#include "zero.h"

#include <arpa/inet.h>
#include <unistd.h>

#include <freeradius-client.h>
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
            __atomic_add_fetch(&zinst()->clients_cnt, 1, __ATOMIC_RELAXED);
        } else {
            pthread_rwlock_wrlock(&sess->lock_client);
            __atomic_add_fetch(&client->refcnt, 1, __ATOMIC_RELAXED);
            pthread_rwlock_unlock(&zinst()->clients_lock[sidx]);
            client_release(sess->client);
            sess->client = client;
            client_session_add(sess->client, sess);
            pthread_rwlock_unlock(&sess->lock_client);
        }

        __atomic_sub_fetch(&zinst()->unauth_sessions_cnt, 1, __ATOMIC_RELAXED);
        client_apply_rules(sess->client, &rules);

        // log successful authentification
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
 * @param[in] sess
 * @param[in] Accounting status (PW_STATUS_START, PW_STATUS_STOP, PW_STATUS_ALIVE)
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

    u_long traff_down = __atomic_load_n(&sess->traff_down, __ATOMIC_RELAXED);
    u_long traff_up = __atomic_load_n(&sess->traff_up, __ATOMIC_RELAXED);
    uint32_t octets_down = traff_down % UINT32_MAX;
    uint32_t octets_up = traff_up % UINT32_MAX;
    uint32_t packets_down = __atomic_load_n(&sess->packets_down, __ATOMIC_RELAXED) % UINT32_MAX;
    uint32_t packets_up = __atomic_load_n(&sess->packets_up, __ATOMIC_RELAXED) % UINT32_MAX;
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

    __atomic_sub_fetch(&sess->traff_down, traff_down, __ATOMIC_RELAXED);
    __atomic_sub_fetch(&sess->traff_up, traff_up, __ATOMIC_RELAXED);
    __atomic_sub_fetch(&sess->packets_down, packets_down, __ATOMIC_RELAXED);
    __atomic_sub_fetch(&sess->packets_up, packets_up, __ATOMIC_RELAXED);

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

            int delete_flag = __atomic_load_n(&sess->delete_flag, __ATOMIC_RELAXED);
            if (delete_flag || ((curr_time - __atomic_load_n(&sess->last_activity, __ATOMIC_RELAXED)) > zcfg()->session_timeout)) {
                // remove inactive or marked for deletion session
                if (delete_flag) {
                    zero_syslog(LOG_INFO, "Removed marked for deletion session %s", ipv4_to_str(htonl(sess->ip)));
                } else {
                    zero_syslog(LOG_INFO, "Removed inactive session %s", ipv4_to_str(htonl(sess->ip)));
                }
                if (sess->accounting_alive) {
                    // TODO: try to resend if request failed?
                    session_accounting(sess, PW_STATUS_STOP);
                }
                session_remove(sess);

            } else if (0 == sess->client->id) {
                uint64_t last_auth = __atomic_load_n(&sess->last_auth, __ATOMIC_RELAXED);
                if((curr_time - last_auth) > zcfg()->session_auth_interval) {
                    // autheticate session client
                    if (0 == last_auth) {
                        zero_syslog(LOG_INFO, "New session %s", ipv4_to_str(htonl(sess->ip)));
                    }
                    session_authenticate(sess);
                    __atomic_store_n(&sess->last_auth, curr_time, __ATOMIC_RELAXED);
                }

            } else if ((curr_time - __atomic_load_n(&sess->last_acct, __ATOMIC_RELAXED)) > zcfg()->session_acct_interval) {
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
                    __atomic_store_n(&sess->delete_flag, 1, __ATOMIC_RELAXED);
                } else {
                    __atomic_store_n(&sess->last_acct, curr_time, __ATOMIC_RELAXED);
                }

            } else if ((curr_time - sess->last_nat_cleanup) > OVERLORD_NAT_CLEANUP_INTERVAL) {
                // nat cleanup
                struct znat *nat = session_get_nat(sess, false);
                if (NULL != nat) {
                    znat_cleanup(nat);
                }
                sess->last_nat_cleanup = curr_time;
            }

            // this function can execute too long, so check abort flag
            if (unlikely(__atomic_load_n(&zinst()->abort, __ATOMIC_RELAXED))) {
                return;
            }

            pthread_rwlock_rdlock(&zinst()->sessions_lock[i]);
        }
        pthread_rwlock_unlock(&zinst()->sessions_lock[i]);
    }

}

/**
 * Overlord thread worker.
 * @param[in] arg Pointer to ztask.
 * @return null
 */
void *overlord_worker(void *arg)
{
    struct zoverlord *lord = (struct zoverlord *)arg;

    while (likely(!__atomic_load_n(&zinst()->abort, __ATOMIC_RELAXED))) {
        size_t batch_size = STORAGE_SIZE / zcfg()->overlord_threads;
        size_t idx_begin = batch_size * lord->idx;
        size_t idx_end = idx_begin + batch_size;

        overlord_run(idx_begin, idx_end);
        sleep(1);
    }

    return NULL;
}
