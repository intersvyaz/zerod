#include "scope.h"
#include "log.h"
#include "zero.h"
#include "config.h"
#include "client_rules.h"
#include <event2/util.h>
#include <event2/event.h>
#include <assert.h>

/**
 * Blacklist reload callback.
 */
static void zscope_blacklist_reload_cb(evutil_socket_t fd, short events, void *arg)
{
    (void) fd;
    (void) events;

    zclock_refresh();
    ztime_refresh();

    zscope_t *scope = (zscope_t *) arg;
    zblacklist_reload(scope->blacklist, scope->cfg->blacklist.file);
}

/**
 * Blacklist reload callback.
 */
static void zscope_dhcp_cleanup_cb(evutil_socket_t fd, short events, void *arg)
{
    (void) fd;
    (void) events;

    zclock_refresh();
    ztime_refresh();

    zscope_t *scope = (zscope_t *) arg;
    zdhcp_cleanup(scope->dhcp);
}

/**
 * @return Zero on success.
 */
static int zscope_init_storage(zscope_t *scope)
{
    scope->session_db = zsession_db_new();
    if (unlikely(!scope->session_db)) {
        ZLOG(LOG_ERR, "scope:%s: failed to create session db", scope->cfg->name);
        return -1;
    }

    scope->client_db = zclient_db_new();
    if (unlikely(!scope->client_db)) {
        ZLOG(LOG_ERR, "scope:%s: failed to create client db", scope->cfg->name);
        return -1;
    }

    return 0;
}

/**
 * @return Zero on success.
 */
static int zscope_init_radius(zscope_t *scope)
{
    if (!scope->cfg->radius.auth) {
        return 0;
    }

    scope->radh = rc_read_config(scope->cfg->radius.config);
    if (unlikely(!scope->radh)) {
        ZLOG(LOG_ERR, "scope:%s: failed to load radius configuration file", scope->cfg->name);
        return -1;
    }
    if (unlikely(0 != rc_read_dictionary(scope->radh, rc_conf_str(scope->radh, "dictionary")))) {
        ZLOG(LOG_ERR, "scope:%s: failed to read radius dictionary file", scope->cfg->name);
        return -1;
    }

    return 0;
}

/**
 * @return Zero on success.
 */
static int zscope_init_security(zscope_t *scope)
{
    scope->dhcp = zdhcp_new();
    if (unlikely(!scope->dhcp)) {
        ZLOG(LOG_ERR, "scope:%s: Failed to create new zdhcp instance", scope->cfg->name);
        return -1;
    }
    atomic_init(&scope->security.arp_errors, 0);
    atomic_init(&scope->security.ip_errors, 0);

    struct timeval tv = {USEC2SEC(5 * 60), 0};
    scope->dhcp_cleanup_event = event_new(zinst()->master_event_base, -1, EV_PERSIST, zscope_dhcp_cleanup_cb, scope);
    if (!scope->dhcp_cleanup_event) {
        ZLOG(LOG_ERR, "scope:%s: Failed to create dhcp cleanup event handler", scope->cfg->name);
        return -1;
    }
    event_add(scope->dhcp_cleanup_event, &tv);

    return 0;
}

/**
 * @return Zero on success.
 */
static int zscope_init_blacklist(zscope_t *scope)
{
    if (!scope->cfg->blacklist.enabled) {
        return 0;
    }

    scope->blacklist = zblacklist_new();
    if (unlikely(!scope->blacklist)) {
        ZLOG(LOG_ERR, "scope:%s: Failed to create blacklist instance", scope->cfg->name);
        return -1;
    }

    if (!zblacklist_reload(scope->blacklist, scope->cfg->blacklist.file)) {
        return -1;
    }

    if (scope->cfg->blacklist.reload_interval) {
        struct timeval tv = {USEC2SEC(scope->cfg->blacklist.reload_interval), 0};
        scope->blacklist_reload_event =
                event_new(zinst()->master_event_base, -1, EV_PERSIST, zscope_blacklist_reload_cb, scope);
        if (!scope->blacklist_reload_event) {
            ZLOG(LOG_ERR, "scope:%s: Failed to create blacklist reload event handler", scope->cfg->name);
            return -1;
        }
        event_add(scope->blacklist_reload_event, &tv);
        atomic_init(&scope->blacklist_hits, 0);
    }

    return 0;
}

/**
 * @return Zero on success.
 */
zscope_t *zscope_new(zconfig_scope_t *cfg)
{
    zscope_t *scope = malloc(sizeof(*scope));
    memset(scope, 0, sizeof(*scope));
    scope->cfg = cfg;

    int ret =
            zscope_init_radius(scope)
            || zscope_init_storage(scope)
            || zscope_init_security(scope)
            || zscope_init_blacklist(scope);

    if (ret) {
        zscope_free(scope);
        return NULL;
    }

    return scope;
}

void zscope_free(zscope_t *scope)
{
    if (likely(scope->radh)) {
        rc_destroy(scope->radh);
    }

    if (likely(scope->session_db)) {
        zsession_db_free(scope->session_db);
    }

    if (likely(scope->client_db)) {
        zclient_db_free(scope->client_db);
    }

    if (likely(scope->dhcp)) {
        zdhcp_free(scope->dhcp);
    }

    if (likely(scope->blacklist)) {
        zblacklist_free(scope->blacklist);
    }

    if (likely(scope->blacklist_reload_event)) {
        event_free(scope->blacklist_reload_event);
    }

    if (likely(scope->dhcp_cleanup_event)) {
        event_free(scope->dhcp_cleanup_event);
    }

    free(scope);
}

/**
 * Apply rules to scope.
 * @param[in] scope Target scope.
 * @param[in] rules Rules to apply.
 */
void zscope_apply_rules(zscope_t *scope, const zscope_rules_t *rules)
{
    (void) scope;
    (void) rules;
}

/**
 *
 */
zsession_t *zscope_session_acquire(zscope_t *scope, uint32_t ip, uint32_t flags)
{
    zsession_t *session = zsession_db_acquire(scope->session_db, ip, true);

    if (!session && (flags & SF_EXISTING_ONLY) == 0) {
        zsession_db_partial_wrlock(scope->session_db, ip);

        session = zsession_db_acquire(scope->session_db, ip, false);
        if (!session) {
            session = zsession_new(ip, scope->cfg);
            atomic_store_release(&session->last_activity, ztime());

            zsession_db_insert(scope->session_db, session, false);
            zsession_db_partial_unlock(scope->session_db, ip);

            atomic_fetch_add_release(&scope->session_new_count, 1);
            atomic_fetch_add_release(&scope->session_unauth_count, 1);
        } else {
            zsession_db_partial_unlock(scope->session_db, ip);
        }
    }

    return session;
}

/**
 *
 */
void zscope_session_remove(zscope_t *scope, zsession_t *session)
{
    zclient_t *client = zsession_get_client(session);

    pthread_rwlock_rdlock(&session->lock);

    if (!session->deleted) {
        session->deleted = true;
        if (client->id) {
            zclient_db_partial_wrlock(scope->client_db, client->id);

            pthread_spin_lock(&client->lock);
            size_t sess_ref = utarray_len(&client->sessions);
            pthread_spin_unlock(&client->lock);

            if (1 == sess_ref) {
                zclient_db_remove(scope->client_db, client, false);
            }

            zclient_db_partial_unlock(scope->client_db, client->id);
        } else {
            atomic_fetch_sub_release(&scope->session_unauth_count, 1);
            if (!atomic_load_acquire(&session->last_auth)) {
                atomic_fetch_sub_release(&scope->session_new_count, 1);
            }
        }
    }

    pthread_rwlock_unlock(&session->lock);

    zclient_release(client);

    zsession_db_remove(scope->session_db, session);
}

/**
 * Apply rules to session.
 * NB: use only for session auth.
 * @param[in] session Session.
 * @param[in] rules Client rules.
 */
void zscope_session_rules_apply(zscope_t *scope, zsession_t *session, const zclient_rules_t *rules)
{
    zclient_t *old_client = zsession_get_client(session);

    pthread_rwlock_wrlock(&session->lock);

    if (!session->deleted) {
        zclient_db_partial_wrlock(scope->client_db, rules->user_id);

        if (!atomic_load_acquire(&session->delete_queued)) {
            if (!atomic_load_acquire(&old_client->id)) {
                atomic_fetch_sub_release(&scope->session_unauth_count, 1);
            }
            zclient_t *req_client = zclient_db_acquire(scope->client_db, rules->user_id, false);
            if (req_client) {
                zsession_set_client(session, req_client);
                zclient_release(req_client);
            } else {
                old_client->id = rules->user_id;
                zclient_apply_rules(old_client, rules);
                zclient_db_insert(scope->client_db, old_client, false);
            }
        }

        zclient_db_partial_unlock(scope->client_db, rules->user_id);
    }

    pthread_rwlock_unlock(&session->lock);

    zclient_release(old_client);
}

/**
 * Perform inspection of dhcp binding.
 * @param[in] scope Scope.
 * @param[in] mac MAC address.
 * @param[in] ip IP address (host order).
 * @return True if valid.
 */
bool zscope_dhcp_is_valid_mac_ip(zscope_t *scope, const uint8_t *mac, uint32_t ip)
{
    uint64_t now = ztime();
    zdhcp_lease_t lease = {.ip = ip};

    if (zdhcp_lease_find(scope->dhcp, &lease)) {
        if ((now <= lease.lease_end) && (0 == memcmp(lease.mac, mac, sizeof(lease.mac)))) {
            // valid dhcp lease and mac
            return true;
        }
    } else if (now <= (zinst()->start_time + scope->cfg->security.dhcp_default_lease_time)) {
        // learning time
        return true;
    }

    return false;
}

/**
 *
 */
void zscope_dhcp_bind(zscope_t *scope, const uint8_t *mac, uint32_t ip, uint64_t lease_time)
{
    if (!scope->cfg->security.dhcp_snooping) {
        return;
    }

    zdhcp_lease_t lease;
    lease.ip = ip;
    memcpy(lease.mac, mac, sizeof(lease.mac));
    lease.lease_end = ztime() + lease_time;
    zdhcp_lease_bind(scope->dhcp, &lease);
}

/**
 * @param[in] scope scope.
 * @param[in] sess Session.
 * @return True if session is expired.
 */
bool zscope_is_session_dhcp_expired(const zscope_t *scope, const zsession_t *session)
{
    if (!scope->cfg->security.dhcp_snooping) {
        return false;
    }

    uint64_t now = ztime();
    zdhcp_lease_t lease = {.ip = session->ip};
    if (zdhcp_lease_find(scope->dhcp, &lease)) {
        // lease time
        return now > lease.lease_end;
    } else {
        // learning time
        return now > (zinst()->start_time + scope->cfg->security.dhcp_default_lease_time);
    }
}

