#include <stddef.h>
#include <arpa/inet.h>

#include "session.h"
#include "client.h"
#include "config.h"

#define SESSION_NAT_CLEANUP_INTERVAL 300000000 // msec, =5min

/**
 * Allocate and initialize new session.
 * @param[in] ip IP address (host order).
 * @param[in] cfg Scope configuration.
 * @return New session pointer.
 */
zsession_t *zsession_new(uint32_t ip, const zconfig_scope_t *cfg)
{
    zsession_t *session = malloc(sizeof(*session));

    if (unlikely(!session)) {
        return NULL;
    }

    memset(session, 0, sizeof(*session));

    session->ip = ip;
    uint32_t ip_n = htonl(ip);
    inet_ntop(AF_INET, &ip_n, session->ip_str, sizeof(session->ip_str));
    session->create_time = ztime();
    atomic_init(&session->refcnt, 1); // caller reference
    atomic_init(&session->last_activity, 0);
    atomic_init(&session->last_auth, 0);
    atomic_init(&session->last_acct, 0);
    atomic_init(&session->delete_queued, false);
    atomic_init(&session->packets_up, 0);
    atomic_init(&session->packets_down, 0);
    atomic_init(&session->traff_up, 0);
    atomic_init(&session->traff_down, 0);
    atomic_init(&session->timeout, cfg->session.timeout);
    atomic_init(&session->idle_timeout, cfg->session.idle_timeout);
    atomic_init(&session->acct_interval, cfg->session.acct_interval);
    pthread_spin_init(&session->_lock_nat, PTHREAD_PROCESS_PRIVATE);
    pthread_spin_init(&session->_lock_client, PTHREAD_PROCESS_PRIVATE);
    pthread_rwlock_init(&session->lock, NULL);

    // Create default client and add relation
    session->_client = zclient_new(&cfg->default_client_rules);
    zclient_session_add(session->_client, session->ip);

    return session;
}

/**
 * Destroy session.
 * @param[in] session
 */
void zsession_free(zsession_t *session)
{
    pthread_rwlock_destroy(&session->lock);
    pthread_spin_destroy(&session->_lock_nat);
    pthread_spin_destroy(&session->_lock_client);
    if (session->nat) znat_free(session->nat);
    free(session);
}

/**
 * Release session reference.
 * @param[in] sess
 */
void zsession_release(zsession_t *session)
{
    if (1 == atomic_fetch_sub_release(&session->refcnt, 1)) {
        zclient_session_remove(session->_client, session->ip);
        zclient_release(session->_client);
        zsession_free(session);
    }
}

/**
 * Get session nat table.
 * @param[in] sess Session.
 * @param[in] proto Protocol.
 * @param[in] allocate Whether to allocate new table.
 * @return
 */
znat_t *zsession_get_nat(zsession_t *sess, bool allocate)
{
    znat_t *nat;

    pthread_spin_lock(&sess->_lock_nat);
    if (allocate && !sess->nat) {
        sess->nat = znat_new(SESSION_NAT_CLEANUP_INTERVAL);
    }
    nat = sess->nat;
    pthread_spin_unlock(&sess->_lock_nat);

    return nat;
}

/**
 *
 */
void zsession_nat_cleanup(zsession_t *sess)
{
    zclock_t now = zclock();

    if ((now - sess->last_nat_cleanup) > SESSION_NAT_CLEANUP_INTERVAL) {
        znat_t *nat = zsession_get_nat(sess, false);
        if (NULL != nat) {
            znat_cleanup(nat);
        }
        sess->last_nat_cleanup = now;
    }
}

struct zclient_struct *zsession_get_client(zsession_t *session)
{
    pthread_spin_lock(&session->_lock_client);

    zclient_t *client = session->_client;
    atomic_fetch_add_release(&client->refcnt, 1);

    pthread_spin_unlock(&session->_lock_client);

    return client;
}

void zsession_set_client(zsession_t *session, zclient_t *client)
{
    pthread_spin_lock(&session->_lock_client);

    zclient_t *old_client = session->_client;

    atomic_fetch_add_release(&client->refcnt, 1);
    session->_client = client;

    pthread_spin_unlock(&session->_lock_client);

    zclient_session_add(session->_client, session->ip);
    zclient_session_remove(old_client, session->ip);
    zclient_release(old_client);
}
