#include "zero.h"

#include <arpa/inet.h>
#include <unistd.h>

#include <uthash/utstring.h>

#include "client.h"
#include "session.h"
#include "log.h"
#include "router/router.h"
#include "crules.h"

#define OVERLORD_NAT_CLEANUP_INTERVAL 300000000 // msec, =5min

// own return code for internal error
#define OTHER_RC -3

/**
* Authenticate and set client info.
* @param[in] sess Client session.
* @return Zero on success (or one of *_RC).
*/
int session_authenticate(struct zsession *sess)
{
    int ret = OTHER_RC;
    VALUE_PAIR *request_attrs = NULL, *response_attrs = NULL;
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
        ZERO_LOG(LOG_ERR, "radius authentication request failed for %s (code:%d)", ip_str, ret);
        goto end;
    }

    VALUE_PAIR *attrs = response_attrs;
    while (likely(NULL != attrs)) {
        switch (attrs->attribute) {
            case PW_FILTER_ID:
                crules_parse(&rules, attrs->strvalue);
                break;
        }
        attrs = attrs->next;
    }

    if (likely(rules.have.user_id && rules.have.login)) {
        struct zclient *client = NULL;
        size_t sidx = STORAGE_IDX(rules.user_id);

        // pessimistic locking, assume that clients with same id is rare situation
        pthread_rwlock_wrlock(&zinst()->clients_lock[sidx]);
        HASH_FIND(hh, zinst()->clients[sidx], &rules.user_id, sizeof(rules.user_id), client);
        if (likely(NULL == client)) {
            client = sess->client;
            client->id = rules.user_id;
            HASH_ADD(hh, zinst()->clients[sidx], id, sizeof(client->id), client);
            pthread_rwlock_unlock(&zinst()->clients_lock[sidx]);
            atomic_fetch_add_explicit(&zinst()->clients_cnt, 1, memory_order_relaxed);
        } else {
            pthread_rwlock_wrlock(&sess->lock_client);
            atomic_fetch_add_explicit(&client->refcnt, 1, memory_order_relaxed);
            pthread_rwlock_unlock(&zinst()->clients_lock[sidx]);
            client_release(sess->client);
            sess->client = client;
            client_session_add(sess->client, sess);
            pthread_rwlock_unlock(&sess->lock_client);
        }

        atomic_fetch_sub_explicit(&zinst()->unauth_sessions_cnt, 1, memory_order_relaxed);
        client_apply_rules(sess->client, &rules);

        // log successful authentication
        {
            UT_string rules_str;
            VALUE_PAIR *attrs = response_attrs;
            utstring_init(&rules_str);
            utstring_reserve(&rules_str, 1024);

            while (likely(NULL != attrs)) {
                switch (attrs->attribute) {
                    case PW_FILTER_ID:
                        utstring_printf(&rules_str, " %s", attrs->strvalue);
                        break;
                }
                attrs = attrs->next;
            }

            zero_syslog(LOG_INFO, "Authenticated session %s (rules:%s)", ip_str, utstring_body(&rules_str));
            utstring_done(&rules_str);
        }
    } else {
        ZERO_LOG(LOG_DEBUG, "Session authentication response does not contains required user information");
        ret = OTHER_RC;
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
* @return Zero on success (one of *_RC codes).
*/
int session_accounting(struct zsession *sess, uint32_t status)
{
    int ret = OTHER_RC;
    VALUE_PAIR *request_attrs = NULL;
    rc_handle *rh = zinst()->radh;
    struct in_addr ip_addr;
    char ip_str[INET_ADDRSTRLEN];
    uint32_t term_cause = PW_USER_REQUEST;

    uint64_t traff_down = atomic_load_explicit(&sess->traff_down, memory_order_relaxed);
    uint64_t traff_up = atomic_load_explicit(&sess->traff_up, memory_order_relaxed);
    uint32_t octets_down = traff_down % UINT32_MAX;
    uint32_t octets_up = traff_up % UINT32_MAX;
    uint32_t packets_down = atomic_load_explicit(&sess->packets_down, memory_order_relaxed) % UINT32_MAX;
    uint32_t packets_up = atomic_load_explicit(&sess->packets_up, memory_order_relaxed) % UINT32_MAX;
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
        gigawords_down = traff_down / UINT32_MAX;
        if (unlikely(NULL == rc_avpair_add(rh, &request_attrs, PW_ACCT_INPUT_GIGAWORDS, &gigawords_down, -1, 0))) {
            goto end;
        }
    }
    if (unlikely(UINT32_MAX < traff_up)) {
        gigawords_up = traff_up / UINT32_MAX;
        if (unlikely(NULL == rc_avpair_add(rh, &request_attrs, PW_ACCT_OUTPUT_GIGAWORDS, &gigawords_up, -1, 0))) {
            goto end;
        }
    }

    ret = rc_acct(rh, 0, request_attrs);
    if (unlikely(OK_RC != ret)) {
        ZERO_LOG(LOG_ERR, "radius accounting failed %s (code:%d)", ip_str, ret);
        goto end;
    }

    atomic_fetch_sub_explicit(&sess->traff_down, traff_down, memory_order_relaxed);
    atomic_fetch_sub_explicit(&sess->traff_up, traff_up, memory_order_relaxed);
    atomic_fetch_sub_explicit(&sess->packets_down, packets_down, memory_order_relaxed);
    atomic_fetch_sub_explicit(&sess->packets_up, packets_up, memory_order_relaxed);

    end:
    if (request_attrs) rc_avpair_free(request_attrs);

    return ret;
}

/**
* Traverse session storages from idx_begin to idx_end.
* - Authenticate sessions.
* - Upload accounting.
* - Remove inactive sessions.
*/
void overlord_run(size_t idx_begin, size_t idx_end)
{
    for (size_t i = idx_begin; i < idx_end; i++) {
        struct zsession *sess, *tmp_sess;

        pthread_rwlock_rdlock(&zinst()->sessions_lock[i]);
        HASH_ITER(hh, zinst()->sessions[i], sess, tmp_sess) {
            pthread_rwlock_unlock(&zinst()->sessions_lock[i]);

            uint64_t curr_time = ztime(true);
            uint64_t curr_clock = zclock(true);

            // remove inactive or marked for deletion session
            bool delete_flag = atomic_load_explicit(&sess->delete_flag, memory_order_relaxed);
            bool inactive_flag = ((curr_time - atomic_load_explicit(&sess->last_activity, memory_order_relaxed)) > zcfg()->session_timeout);
            bool duration_flag = ((curr_time - sess->create_time) > zcfg()->session_max_duration);
            if (delete_flag || inactive_flag || duration_flag) {
                if (delete_flag) {
                    zero_syslog(LOG_INFO, "Removed marked for deletion session %s", ipv4_to_str(htonl(sess->ip)));
                } else if (inactive_flag) {
                    zero_syslog(LOG_INFO, "Removed inactive session %s", ipv4_to_str(htonl(sess->ip)));
                } else if (duration_flag) {
                    zero_syslog(LOG_INFO, "Removed long duration session %s", ipv4_to_str(htonl(sess->ip)));
                }
                if (sess->accounting_alive) {
                    session_accounting(sess, PW_STATUS_STOP);
                }
                session_remove(sess);

            } else {
                // nat cleanup
                if ((curr_clock - sess->last_nat_cleanup) > OVERLORD_NAT_CLEANUP_INTERVAL) {
                    struct znat *nat = session_get_nat(sess, false);
                    if (NULL != nat) {
                        znat_cleanup(nat);
                    }
                    sess->last_nat_cleanup = curr_clock;
                }

                // apply deferred rules
                if (utarray_len(&sess->client->deferred_rules)) {
                    struct zcrules parsed_rules;

                    pthread_spin_lock(&sess->client->lock);

                    crules_init(&parsed_rules);

                    while (utarray_back(&sess->client->deferred_rules)) {
                        struct zrule_deferred *rule = *(struct zrule_deferred **) utarray_back(&sess->client->deferred_rules);

                        if (rule->when > curr_clock) {
                            break;
                        }

                        if (0 != crules_parse(&parsed_rules, rule->rule)) {
                            zero_syslog(LOG_INFO, "Failed to parse deferred rule '%s' for client %s", rule->rule, ipv4_to_str(htonl(sess->ip)));
                        } else {
                            zero_syslog(LOG_INFO, "Applying deferred rule '%s' for client %s", rule->rule, ipv4_to_str(htonl(sess->ip)));
                        }

                        free(rule->rule);
                        free(rule);
                        utarray_pop_back(&sess->client->deferred_rules);
                    }

                    pthread_spin_unlock(&sess->client->lock);
                    client_apply_rules(sess->client, &parsed_rules);
                    crules_free(&parsed_rules);
                }

                // authenticate session
                if (0 == sess->client->id) {
                    uint64_t last_auth = atomic_load_explicit(&sess->last_auth, memory_order_relaxed);
                    if ((curr_time - last_auth) > zcfg()->session_auth_interval) {

                        if (0 == last_auth) {
                            zero_syslog(LOG_INFO, "New session %s", ipv4_to_str(htonl(sess->ip)));
                        }
                        session_authenticate(sess);
                        atomic_store_explicit(&sess->last_auth, curr_time, memory_order_relaxed);
                    }

                } else if ((curr_time - atomic_load_explicit(&sess->last_acct, memory_order_relaxed)) > zcfg()->session_acct_interval) {
                    // update accounting
                    int ret;

                    if (sess->accounting_alive) {
                        ret = session_accounting(sess, PW_STATUS_ALIVE);
                    } else {
                        ret = session_accounting(sess, PW_STATUS_START);
                        sess->accounting_alive = (0 == ret);
                    }

                    if (REJECT_RC == ret) {
                        // accounting rejected, mark session for deletion
                        atomic_store_explicit(&sess->delete_flag, true, memory_order_relaxed);
                    } else {
                        atomic_store_explicit(&sess->last_acct, curr_time, memory_order_relaxed);
                    }
                }
            }

            // this function can execute too long, so check abort flag
            if (unlikely(atomic_load_explicit(&zinst()->abort, memory_order_relaxed))) {
                return;
            }

            pthread_rwlock_rdlock(&zinst()->sessions_lock[i]);
        }
        pthread_rwlock_unlock(&zinst()->sessions_lock[i]);
    }

}

/**
* Overlord thread worker.
* @param[in] arg Pointer to zoverlord struct .
* @return null
*/
void *overlord_worker(void *arg)
{
    struct zoverlord *lord = (struct zoverlord *) arg;

    while (likely(!atomic_load_explicit(&zinst()->abort, memory_order_relaxed))) {
        size_t batch_size = STORAGE_SIZE / zcfg()->overlord_threads;
        size_t idx_begin = batch_size * lord->idx;
        size_t idx_end = idx_begin + batch_size;

        overlord_run(idx_begin, idx_end);
        sleep(1);
    }

    return NULL;
}
