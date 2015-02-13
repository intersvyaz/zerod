#include "session.h"

#include "zero.h"
#include "client.h"
#include "router/router.h"

/**
* Destroy session.
* @param[in] sess
*/
void session_destroy(struct zsession *sess)
{
    // update counters
    atomic_fetch_sub_explicit(&zinst()->sessions_cnt, 1, memory_order_relaxed);
    if (0 == sess->client->id) {
        atomic_fetch_sub_explicit(&zinst()->unauth_sessions_cnt, 1, memory_order_relaxed);
    }

    pthread_rwlock_destroy(&sess->lock_client);
    client_session_remove(sess->client, sess);
    client_release(sess->client);

    if (sess->nat) znat_destroy(sess->nat);

    free(sess);
}

/**
* Release session reference.
* @param[in] sess
*/
void session_release(struct zsession *sess)
{
    if (1 == atomic_fetch_sub_explicit(&sess->refcnt, 1, memory_order_relaxed)) {
        session_destroy(sess);
    }
}

/**
* Remove session from storage.
* @param[in] sess
*/
void session_remove(struct zsession *sess)
{
    size_t sidx = STORAGE_IDX(sess->ip);
    pthread_rwlock_wrlock(&zinst()->sessions_lock[sidx]);
    HASH_DELETE(hh, zinst()->sessions[sidx], sess);
    pthread_rwlock_unlock(&zinst()->sessions_lock[sidx]);
    session_release(sess); // release from session hash
}

/**
* Create new empty session.
* @return New session pointer.
*/
struct zsession *session_create()
{
    struct zsession *sess = malloc(sizeof(*sess));

    bzero(sess, sizeof(*sess));
    sess->client = client_create();
    client_session_add(sess->client, sess);
    sess->create_time = ztime(false);

    // set default values
    atomic_init(&sess->refcnt, 1); // caller references this entry
    atomic_init(&sess->last_activity, 0);
    atomic_init(&sess->last_auth, 0);
    atomic_init(&sess->last_acct, 0);
    atomic_init(&sess->delete_flag, false);
    atomic_init(&sess->packets_up, 0);
    atomic_init(&sess->packets_down, 0);
    atomic_init(&sess->traff_up, 0);
    atomic_init(&sess->traff_down, 0);
    pthread_spin_init(&sess->_nat_lock, PTHREAD_PROCESS_PRIVATE);
    pthread_rwlock_init(&sess->lock_client, NULL);

    atomic_fetch_add_explicit(&zinst()->sessions_cnt, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&zinst()->unauth_sessions_cnt, 1, memory_order_relaxed);

    return sess;
}

/**
* Acquire existing session from sotrage or create new one.
* All session MUST be requested through this function.
* @param[in] ip IPv4 address of client.
* @param[in] existing_only Do only existing sssion search.
* @return New client.
*/
struct zsession *session_acquire(uint32_t ip, bool existing_only)
{
    struct zsession *sess = NULL;
    size_t sidx = STORAGE_IDX(ip);

    // search for existing session
    pthread_rwlock_rdlock(&zinst()->sessions_lock[sidx]);
    HASH_FIND(hh, zinst()->sessions[sidx], &ip, sizeof(ip), sess);
    if (NULL != sess) {
        atomic_fetch_add_explicit(&sess->refcnt, 1, memory_order_relaxed);
    }
    pthread_rwlock_unlock(&zinst()->sessions_lock[sidx]);

    // or create new session
    if (!existing_only && NULL == sess) {
        pthread_rwlock_wrlock(&zinst()->sessions_lock[sidx]);

        HASH_FIND(hh, zinst()->sessions[sidx], &ip, sizeof(ip), sess);
        if (NULL != sess) {
            atomic_fetch_add_explicit(&sess->refcnt, 1, memory_order_relaxed);
        } else {
            sess = session_create();
            sess->ip = ip;
            atomic_store_explicit(&sess->last_activity, ztime(false), memory_order_relaxed);
            atomic_fetch_add_explicit(&sess->refcnt, 1, memory_order_relaxed); // sessions storage reference

            HASH_ADD(hh, zinst()->sessions[sidx], ip, sizeof(ip), sess);
        }

        pthread_rwlock_unlock(&zinst()->sessions_lock[sidx]);
    }

    return sess;
}

/**
* Get session nat table.
* @param[in] sess Session.
* @param[in] proto Protocol.
* @param[in] allocate Whether to allocate new table.
* @return
*/
struct znat *session_get_nat(struct zsession *sess, bool allocate)
{
    struct znat *nat;

    pthread_spin_lock(&sess->_nat_lock);
    if (allocate && (NULL == sess->nat)) {
        sess->nat = znat_create();
    }
    nat = sess->nat;
    pthread_spin_unlock(&sess->_nat_lock);

    return nat;
}
