#include <unistd.h>

#include "log.h"
#include "radius.h"
#include "zero.h"

/**
 *
 */
static void zlord_auth(zscope_t *scope, zsession_t *session)
{
    ztime_t now = ztime();
    uint64_t last_auth = atomic_load_acquire(&session->last_auth);

    if (now >= (last_auth + scope->cfg->session.auth_interval)) {
        if (0 == last_auth) {
            zsyslog(LOG_INFO, "%s: New session %s", scope->cfg->name, session->ip_str);
            atomic_fetch_sub_release(&scope->session_new_count, 1);
        }
        zradius_session_auth(scope, session);
        atomic_store_release(&session->last_auth, now);
    }
}

/**
 *
 */
static void zlord_acct(zscope_t *scope, zsession_t *session)
{
    ztime_t now = ztime();

    if (now >= (atomic_load_acquire(&session->last_acct) + atomic_load_acquire(&session->acct_interval))) {
        zrad_status_t ret;
        if (session->accounting_alive) {
            ret = zradius_session_acct(scope, session, PW_STATUS_ALIVE, 0);
        } else {
            ret = zradius_session_acct(scope, session, PW_STATUS_START, 0);
            session->accounting_alive = (ZRAD_OK == ret);
        }

        if (ZRAD_REJECT == ret) {
            ZLOG(LOG_INFO, "%s: Accounting rejected for %s, mark for delete", scope->cfg->name, session->ip_str);
            atomic_store_release(&session->delete_queued, true);
        } else {
            atomic_store_release(&session->last_acct, now);
        }
    }
}

/**
 *
 */
static void zlord_session_aaa(zscope_t *scope, zsession_t *session, zclient_t *client)
{
    if (scope->cfg->radius.auth && !client->id) {
        zlord_auth(scope, session);
    } else if (scope->cfg->radius.acct) {
        zlord_acct(scope, session);
    }
}

/**
 *
 */
static uint32_t zlord_session_term_cause(const zscope_t *scope, const zsession_t *session)
{
    if (atomic_load_acquire(&session->delete_queued)) {
        return PW_ADMIN_RESET;

    } else if (zsession_is_timeout(session)) {
        return PW_ACCT_SESSION_TIMEOUT;

    } else if (zsession_is_idle_timeout(session)) {
        return PW_ACCT_IDLE_TIMEOUT;

    } else if (zscope_is_session_dhcp_expired(scope, session)) {
        return PW_USER_REQUEST;

    } else {
        return 0;
    }
}

/**
 *
 */
static int zlord_serve_session(zsession_t *session, void *arg)
{
    zscope_t *scope = (zscope_t *) arg;

    // refresh
    ztime_refresh();
    zclock_refresh();

    uint32_t term_cause = zlord_session_term_cause(scope, session);

    if (term_cause) {
        if (scope->cfg->radius.acct && session->accounting_alive) {
            zradius_session_acct(scope, session, PW_STATUS_STOP, term_cause);
        }
        zscope_session_remove(scope, session);

        zsyslog(LOG_INFO, "%s: Removed session %s: %s",
                scope->cfg->name, session->ip_str, zrad_decode_term_cause(term_cause));
    } else {
        zsession_nat_cleanup(session);

        zclient_t *client = zsession_get_client(session);
        zclient_apply_deferred_rules(client);
        // do it last as it can change client in session
        zlord_session_aaa(scope, session, client);
        zclient_release(client);
    }

    if (unlikely(zinstance_is_abort())) {
        return -1;
    }

    return 0;
}

/**
 * Serve scope.
 * @param[in] scope Scope to serve.
 * @param[in] lord_index Positional index of overlord.
 * @return Zero on success.
 */
static bool zlord_serve_scope(zscope_t *scope, size_t lord_index)
{
    size_t batch_size = zsession_db_get_bucket_count(scope->session_db) / zinst()->cfg->overlord_threads;
    size_t idx_begin = batch_size * lord_index;
    size_t idx_end = idx_begin + batch_size;

    for (size_t i = idx_begin; i < idx_end; i++) {
        if (0 != zsession_db_bucket_map(scope->session_db, i, zlord_serve_session, scope)) {
            return false;
        }
    }

    return true;
}

/**
 * Overlord thread worker.
 * @param[in] arg Pointer to zoverlord_t.
 * @return null
 */
void *zoverlord_proc(void *arg)
{
    zoverlord_t *lord = (zoverlord_t *) arg;

    while (likely(!zinstance_is_abort())) {
        zscope_t *scope, *tmp_scope;
        HASH_ITER(hh, zinst()->scopes, scope, tmp_scope) {
            if (!zlord_serve_scope(scope, lord->idx)) {
                return NULL;
            }
        }
        sleep(1);
    }

    return NULL;
}
