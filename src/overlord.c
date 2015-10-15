#include "zero.h"
#include <arpa/inet.h>
#include <unistd.h>
#include "client.h"
#include "session.h"
#include "log.h"

#define OVERLORD_NAT_CLEANUP_INTERVAL 300000000 // msec, =5min

// own return code for internal error
#define OTHER_RC -3

/**
 * Authenticate and set client info.
 * @param[in] sess Client session.
 * @return Zero on success (or one of *_RC).
 */
static int session_authenticate(struct zsession *sess)
{
    int ret = OTHER_RC;
    VALUE_PAIR *request_attrs = NULL, *response_attrs = NULL, *attrs = NULL;
    char msg[8192]; // WARNING: libfreeradius-client has unsafe working with this buffer.
    rc_handle *rh = zinst()->radh;
    struct in_addr ip_addr;
    char ip_str[INET_ADDRSTRLEN];
    struct zcrules rules;

    crules_init(&rules);

    ip_addr.s_addr = htonl(sess->ip);
    if (unlikely(NULL == inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str)))) {
        goto end;
    }

    if (unlikely(NULL == rc_avpair_add(rh, &request_attrs, PW_USER_NAME, ip_str, -1, 0))) {
        goto end;
    }
    if (unlikely(NULL == rc_avpair_add(rh, &request_attrs, PW_USER_PASSWORD, "", -1, 0))) {
        goto end;
    }
    if (unlikely(NULL == rc_avpair_add(rh, &request_attrs, PW_NAS_IDENTIFIER, zcfg()->radius_nas_identifier, -1, 0))) {
        goto end;
    }
    if (unlikely(NULL == rc_avpair_add(rh, &request_attrs, PW_CALLING_STATION_ID, ip_str, -1, 0))) {
        goto end;
    }

    ret = rc_auth(rh, 0, request_attrs, &response_attrs, msg);
    if (OK_RC != ret) {
        ZERO_LOG(LOG_ERR, "Session authentication failed for %s (code:%d)", ip_str, ret);
        goto end;
    }

    attrs = response_attrs;
    while (likely(NULL != attrs)) {
        switch (attrs->attribute) {
            case PW_FILTER_ID:
                crules_parse(&rules, attrs->strvalue);
                break;
            case PW_SESSION_TIMEOUT:
                atomic_store_explicit(&sess->max_duration, SEC2USEC(attrs->lvalue), memory_order_release);
                break;
            case PW_ACCT_INTERIM_INTERVAL:
                atomic_store_explicit(&sess->acct_interval, SEC2USEC(attrs->lvalue), memory_order_release);
                break;
        }
        attrs = attrs->next;
    }

    if (likely(rules.have.user_id && rules.have.login)) {
        struct zclient *client = sess->client;

        client_db_find_or_set_id(zinst()->client_db, rules.user_id, &client);
        if (client != sess->client) {
            // found
            pthread_rwlock_wrlock(&sess->lock_client);
            atomic_fetch_add_explicit(&client->refcnt, 1, memory_order_relaxed);
            client_release(sess->client);
            sess->client = client;
            client_session_add(sess->client, sess);
            pthread_rwlock_unlock(&sess->lock_client);
        } else {
            client_apply_rules(sess->client, &rules);
        }

        atomic_fetch_sub_explicit(&zinst()->unauth_sessions_cnt, 1, memory_order_release);

        // log successful authentication
        {
            UT_string rules_str;
            utstring_init(&rules_str);
            utstring_reserve(&rules_str, 1024);

            attrs = response_attrs;
            while (likely(NULL != attrs)) {
                switch (attrs->attribute) {
                    case PW_FILTER_ID:
                        utstring_printf(&rules_str, " %s", attrs->strvalue);
                        break;
                    default:
                        break;
                }
                attrs = attrs->next;
            }

            zero_syslog(LOG_INFO, "Authenticated session %s (rules:%s)", ip_str, utstring_body(&rules_str));
            utstring_done(&rules_str);
        }
    } else {
        ret = OTHER_RC;
        ZERO_LOG(LOG_ERR, "Session authentication failed for %s (code:%d)", ip_str, ret);
    }

    end:
    crules_free(&rules);
    if (request_attrs) rc_avpair_free(request_attrs);
    if (response_attrs) rc_avpair_free(response_attrs);

    return ret;
}

/**
 * Send radius accounting packet.
 * @param[in] sess Session
 * @param[in] status Accounting status (PW_STATUS_START, PW_STATUS_STOP, PW_STATUS_ALIVE)
 * @param[in] cause Accounting termination cause (used only in case of PW_STATUS_STOP)
 * @return Zero on success (one of *_RC codes).
 */
static int session_accounting(struct zsession *sess, uint32_t status, uint32_t term_cause)
{
    int ret = OTHER_RC;
    VALUE_PAIR *request_attrs = NULL;
    rc_handle *rh = zinst()->radh;
    struct in_addr ip_addr;
    char ip_str[INET_ADDRSTRLEN];

    uint64_t traff_down = atomic_load_explicit(&sess->traff_down, memory_order_acquire);
    uint64_t traff_up = atomic_load_explicit(&sess->traff_up, memory_order_acquire);
    uint32_t octets_down = (uint32_t) (traff_down % UINT32_MAX);
    uint32_t octets_up = (uint32_t) (traff_up % UINT32_MAX);
    uint32_t packets_down = atomic_load_explicit(&sess->packets_down, memory_order_acquire) % UINT32_MAX;
    uint32_t packets_up = atomic_load_explicit(&sess->packets_up, memory_order_acquire) % UINT32_MAX;
    uint32_t gigawords_down = 0;
    uint32_t gigawords_up = 0;

    char session_id[255];
    snprintf(session_id, sizeof(session_id), "%s-%" PRIu32, sess->client->login, sess->ip);

    ip_addr.s_addr = htonl(sess->ip);
    if (unlikely(NULL == inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str)))) {
        goto end;
    }

    if (unlikely(NULL == rc_avpair_add(rh, &request_attrs, PW_CALLING_STATION_ID, ip_str, -1, 0))) {
        goto end;
    }
    if (unlikely(NULL == rc_avpair_add(rh, &request_attrs, PW_FRAMED_IP_ADDRESS, &sess->ip, -1, 0))) {
        goto end;
    }
    if (unlikely(NULL == rc_avpair_add(rh, &request_attrs, PW_USER_NAME, sess->client->login, -1, 0))) {
        goto end;
    }
    if (unlikely(NULL == rc_avpair_add(rh, &request_attrs, PW_ACCT_SESSION_ID, session_id, -1, 0))) {
        goto end;
    }
    if (unlikely(NULL == rc_avpair_add(rh, &request_attrs, PW_NAS_IDENTIFIER, zcfg()->radius_nas_identifier, -1, 0))) {
        goto end;
    }
    if (PW_STATUS_STOP == status) {
        if (unlikely(NULL == rc_avpair_add(rh, &request_attrs, PW_ACCT_TERMINATE_CAUSE, &term_cause, -1, 0))) {
            goto end;
        }
    }
    if (unlikely(NULL == rc_avpair_add(rh, &request_attrs, PW_ACCT_STATUS_TYPE, &status, -1, 0))) {
        goto end;
    }
    if (unlikely(NULL == rc_avpair_add(rh, &request_attrs, PW_ACCT_INPUT_OCTETS, &octets_down, -1, 0))) {
        goto end;
    }
    if (unlikely(NULL == rc_avpair_add(rh, &request_attrs, PW_ACCT_INPUT_PACKETS, &packets_down, -1, 0))) {
        goto end;
    }
    if (unlikely(NULL == rc_avpair_add(rh, &request_attrs, PW_ACCT_OUTPUT_OCTETS, &octets_up, -1, 0))) {
        goto end;
    }
    if (unlikely(NULL == rc_avpair_add(rh, &request_attrs, PW_ACCT_OUTPUT_PACKETS, &packets_down, -1, 0))) {
        goto end;
    }
    if (unlikely(UINT32_MAX < traff_down)) {
        gigawords_down = (uint32_t) (traff_down / UINT32_MAX);
        if (unlikely(NULL == rc_avpair_add(rh, &request_attrs, PW_ACCT_INPUT_GIGAWORDS, &gigawords_down, -1, 0))) {
            goto end;
        }
    }
    if (unlikely(UINT32_MAX < traff_up)) {
        gigawords_up = (uint32_t) (traff_up / UINT32_MAX);
        if (unlikely(NULL == rc_avpair_add(rh, &request_attrs, PW_ACCT_OUTPUT_GIGAWORDS, &gigawords_up, -1, 0))) {
            goto end;
        }
    }

    ret = rc_acct(rh, 0, request_attrs);
    if (unlikely(OK_RC != ret)) {
        ZERO_LOG(LOG_ERR, "radius accounting failed %s (code:%d)", ip_str, ret);
        goto end;
    }

    atomic_fetch_sub_explicit(&sess->traff_down, traff_down, memory_order_release);
    atomic_fetch_sub_explicit(&sess->traff_up, traff_up, memory_order_release);
    atomic_fetch_sub_explicit(&sess->packets_down, packets_down, memory_order_release);
    atomic_fetch_sub_explicit(&sess->packets_up, packets_up, memory_order_release);

    end:
    if (request_attrs) {
        rc_avpair_free(request_attrs);
    }

    return ret;
}

static void overlord_nat_cleanup(struct zsession *sess)
{
    uint64_t curr_clock = zclock(false);

    if ((curr_clock - sess->last_nat_cleanup) > OVERLORD_NAT_CLEANUP_INTERVAL) {
        struct znat *nat = session_get_nat(sess, false);
        if (NULL != nat) {
            znat_cleanup(nat);
        }
        sess->last_nat_cleanup = curr_clock;
    }
}

static void overlord_apply_deferred_rules(struct zsession *sess)
{
    if (utarray_len(&sess->client->deferred_rules)) {
        struct zcrules parsed_rules;
        uint64_t curr_clock = zclock(false);

        pthread_spin_lock(&sess->client->lock);

        crules_init(&parsed_rules);

        while (utarray_back(&sess->client->deferred_rules)) {
            struct zrule_deferred *rule =
                    *(struct zrule_deferred **) utarray_back(&sess->client->deferred_rules);

            if (rule->when > curr_clock) {
                break;
            }

            if (0 != crules_parse(&parsed_rules, rule->rule)) {
                zero_syslog(LOG_INFO, "Failed to parse deferred rule '%s' for client %s",
                            rule->rule, ipv4_to_str(htonl(sess->ip)));
            } else {
                zero_syslog(LOG_INFO, "Applying deferred rule '%s' for client %s",
                            rule->rule, ipv4_to_str(htonl(sess->ip)));
            }

            free(rule->rule);
            free(rule);
            utarray_pop_back(&sess->client->deferred_rules);
        }

        pthread_spin_unlock(&sess->client->lock);
        client_apply_rules(sess->client, &parsed_rules);
        crules_free(&parsed_rules);
    }
}

static void overlord_auth(struct zsession *sess)
{
    uint64_t last_auth = atomic_load_explicit(&sess->last_auth, memory_order_acquire);
    uint64_t curr_time = ztime(false);
    if ((curr_time - last_auth) > zcfg()->session_auth_interval) {

        if (0 == last_auth) {
            zero_syslog(LOG_INFO, "New session %s", ipv4_to_str(htonl(sess->ip)));
        }
        session_authenticate(sess);
        atomic_store_explicit(&sess->last_auth, curr_time, memory_order_release);
    }
}

static void overlord_acct(struct zsession *sess)
{
    // update accounting
    int ret;

    if (sess->accounting_alive) {
        ret = session_accounting(sess, PW_STATUS_ALIVE, 0);
    } else {
        ret = session_accounting(sess, PW_STATUS_START, 0);
        sess->accounting_alive = (0 == ret);
    }

    if (REJECT_RC == ret) {
        // accounting rejected, mark session for deletion
        atomic_store_explicit(&sess->delete_flag, true, memory_order_release);
    } else {
        atomic_store_explicit(&sess->last_acct, ztime(false), memory_order_release);
    }
}

/**
 * Idle timeout for session reached in:
 * - ARP inspection is ON and DHCP lease is expired.
 * - ARP inspection is OFF and last activity was not earlier than default dhcp lease time.
 * @param[in] sess Session.
 * @param[in] now Current time.
 * @return bool
 */
static inline bool overlord_sess_is_idle_timeout(struct zsession *sess, uint64_t now)
{
    if (atomic_load_explicit(&zinst()->arp.mode, memory_order_acquire)) {
        return now > atomic_load_explicit(&sess->dhcp_lease_end, memory_order_acquire);
    } else {
        return (now - zcfg()->dhcp_default_lease_time) >
               atomic_load_explicit(&sess->last_activity, memory_order_acquire);
    }
}

/**
 * Server session.
 * - Authenticate sessions.
 * - Upload accounting.
 * - Remove inactive sessions.
 */
static void overlord_serve_session(struct zsession *sess)
{
    uint64_t curr_time = ztime(true);
    zclock(true); // refresh

    // remove inactive, long duration or marked for deletion session
    uint32_t term_cause = 0;
    if (atomic_load_explicit(&sess->delete_flag, memory_order_acquire)) {
        term_cause = PW_ADMIN_RESET;
        zero_syslog(LOG_INFO, "Removed marked for deletion session %s", ipv4_to_str(htonl(sess->ip)));
    } else if (overlord_sess_is_idle_timeout(sess, curr_time)) {
        term_cause = PW_IDLE_TIMEOUT;
        zero_syslog(LOG_INFO, "Removed inactive session %s", ipv4_to_str(htonl(sess->ip)));
    } else if ((curr_time - sess->create_time) > atomic_load_explicit(&sess->max_duration, memory_order_acquire)) {
        term_cause = PW_SESSION_TIMEOUT;
        zero_syslog(LOG_INFO, "Removed long duration session %s", ipv4_to_str(htonl(sess->ip)));
    }

    if (term_cause) {
        if (sess->accounting_alive) {
            session_accounting(sess, PW_STATUS_STOP, term_cause);
        }
        session_remove(sess);
    } else {
        overlord_nat_cleanup(sess);
        overlord_apply_deferred_rules(sess);

        // authenticate session
        if (0 == sess->client->id) {
            overlord_auth(sess);

        } else if ((curr_time - atomic_load_explicit(&sess->last_acct, memory_order_acquire)) >
                   atomic_load_explicit(&sess->acct_interval, memory_order_acquire)) {
            overlord_acct(sess);
        }
    }
}

/**
 *
 */
static void overlord_dns_attack_detect(struct zsession *sess)
{
    if (zcfg()->dns_attack_threshold) {
        uint64_t pps = spdm_calc(&sess->dns_speed);
        if (unlikely(pps >= zcfg()->dns_attack_threshold)) {
            if (!sess->is_dns_attack) {
                ZERO_LOG(LOG_WARNING, "DNS amplification attack begin detected: session %s, %" PRIu64 " pps",
                         ipv4_to_str(sess->ip), pps);
                sess->is_dns_attack = true;
            }
        } else if (unlikely(sess->is_dns_attack)) {
            ZERO_LOG(LOG_WARNING, "DNS amplification attack end: session %s", ipv4_to_str(sess->ip));
            sess->is_dns_attack = false;
        }
    }
}

/**
 * Traverse session storage from idx_begin to idx_end.
 */
void overlord_run(size_t idx_begin, size_t idx_end)
{
    for (size_t i = idx_begin; i < idx_end; i++) {
        struct zsession *sess, *tmp_sess;

        pthread_rwlock_rdlock(&zinst()->sessions_lock[i]);
        HASH_ITER(hh, zinst()->sessions[i], sess, tmp_sess) {
            pthread_rwlock_unlock(&zinst()->sessions_lock[i]);

            overlord_dns_attack_detect(sess);

            overlord_serve_session(sess);

            if (unlikely(zero_is_abort())) {
                return;
            }

            pthread_rwlock_rdlock(&zinst()->sessions_lock[i]);
        }
        pthread_rwlock_unlock(&zinst()->sessions_lock[i]);
    }
}

/**
 * Overlord thread worker.
 * @param[in] arg Pointer to zoverlord struct.
 * @return null
 */
void *overlord_worker(void *arg)
{
    struct zoverlord *lord = (struct zoverlord *) arg;

    while (likely(!zero_is_abort())) {
        size_t batch_size = STORAGE_SIZE / zcfg()->overlord_threads;
        size_t idx_begin = batch_size * lord->idx;
        size_t idx_end = idx_begin + batch_size;

        overlord_run(idx_begin, idx_end);
        sleep(1);
    }

    return NULL;
}
