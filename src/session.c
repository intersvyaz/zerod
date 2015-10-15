#include "session.h"
#include "zero.h"
#include "client.h"

/**
 * Destroy session.
 * @param[in] sess
 */
void session_destroy(struct zsession *sess)
{
    // update counters
    atomic_fetch_sub_explicit(&zinst()->sessions_cnt, 1, memory_order_release);
    if (0 == sess->client->id) {
        atomic_fetch_sub_explicit(&zinst()->unauth_sessions_cnt, 1, memory_order_release);
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
    if (1 == atomic_fetch_sub_explicit(&sess->refcnt, 1, memory_order_release)) {
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

    memset(sess, 0, sizeof(*sess));
    sess->client = client_create(&zcfg()->default_client_rules);
    client_session_add(sess->client, sess);
    sess->create_time = ztime(false);

    // set default values
    atomic_init(&sess->refcnt, 1); // caller references this entry
    atomic_init(&sess->dhcp_lease_end, ztime(false) + zcfg()->dhcp_default_lease_time);
    atomic_init(&sess->last_activity, 0);
    atomic_init(&sess->last_auth, 0);
    atomic_init(&sess->last_acct, 0);
    atomic_init(&sess->delete_flag, false);
    atomic_init(&sess->packets_up, 0);
    atomic_init(&sess->packets_down, 0);
    atomic_init(&sess->traff_up, 0);
    atomic_init(&sess->traff_down, 0);
    atomic_init(&sess->max_duration, zcfg()->session_max_duration);
    atomic_init(&sess->acct_interval, zcfg()->session_acct_interval);
    spdm_init(&sess->dns_speed);
    pthread_spin_init(&sess->_nat_lock, PTHREAD_PROCESS_PRIVATE);
    pthread_rwlock_init(&sess->lock_client, NULL);

    atomic_fetch_add_explicit(&zinst()->sessions_cnt, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&zinst()->unauth_sessions_cnt, 1, memory_order_relaxed);

    return sess;
}

/**
 * Acquire existing session from sotrage or create new one.
 * All session MUST be requested through this function.
 * @param[in] ip IPv4 address of client (host order).
 * @param[in] flags SF_* flags.
 * @return New client.
 */
struct zsession *session_acquire(uint32_t ip, uint32_t flags)
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
    if (((flags & SF_EXISTING_ONLY) == 0) && (NULL == sess)) {
        pthread_rwlock_wrlock(&zinst()->sessions_lock[sidx]);

        HASH_FIND(hh, zinst()->sessions[sidx], &ip, sizeof(ip), sess);
        if (NULL != sess) {
            atomic_fetch_add_explicit(&sess->refcnt, 1, memory_order_relaxed);
        } else {
            sess = session_create();
            sess->ip = ip;
            atomic_store_explicit(&sess->last_activity, ztime(false), memory_order_release);
            atomic_fetch_add_explicit(&sess->refcnt, 1, memory_order_relaxed); // sessions storage reference

            // try to restore dhcp binding info
            if ((flags & SF_NO_DHCP_SEARCH) == 0) {
                struct zdhcp_lease lease;
                lease.ip = htonl(ip);
                if (0 == zdhcp_lease_find(zinst()->dhcp, &lease)) {
                    memcpy(sess->hw_addr, lease.mac, sizeof(sess->hw_addr));
                    sess->has_hw_addr = true;
                    sess->dhcp_lease_end = lease.lease_end;
                }
            }

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
