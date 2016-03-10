#include "radius.h"
#include "log.h"
#include "util_string.h"
#include "zero.h"

typedef struct zrad_auth_req_struct
{
    const char *username;
    const char *password;
    const char *nas_id;
    const char *calling_station_id;
} zrad_auth_req_t;

typedef struct zrad_acct_req_struct
{
    /*<<! User-Name */
    const char *username;
    /*<<! Calling-Station-Id */
    const char *calling_station_id;
    /*<<! NAS-Identifier */
    const char *nas_id;
    /*<<! Acct-Session-Id */
    char session_id[128];
    /*<<! Acct-Status-Type */
    uint32_t status;
    /*<<! Acct-Terminate-Cause */
    uint32_t term_cause;
    /*<<! Framed-IP-Address */
    uint32_t framed_ip_addr;
    /*<<! Acct-Input-Octets */
    uint32_t octets_down;
    /*<<! Acct-Output-Octets */
    uint32_t octets_up;
    /*<<! Acct-Input-Packets */
    uint32_t packets_down;
    /*<<! Acct-Output-Packets */
    uint32_t packets_up;
    /*<<! Acct-Input-Gigawords */
    uint32_t gigawords_down;
    /*<<! Acct-Output-Gigawords */
    uint32_t gigawords_up;
    /*<<! Acct-Authentic */
    uint32_t authentic;
    /*<<! Acct-Session-Time */
    uint32_t session_time;

    uint64_t traff_down;
    uint64_t traff_up;
} zrad_acct_req_t;

const char *zrad_decode_state(int code)
{
    switch (code) {
        case ZRAD_OTHER:
            return "OTHER";
        case ZRAD_BADRESP:
            return "BADRESP";
        case ZRAD_ERROR:
            return "ERROR";
        case ZRAD_OK:
            return "OK";
        case ZRAD_TIMEOUT:
            return "TIMEOUT";
        case ZRAD_REJECT:
            return "REJECT";
        default:
            return "UNKNOWN";
    }
}

const char *zrad_decode_term_cause(int code)
{
    switch (code) {
        case PW_USER_REQUEST:
            return "user request";
        case PW_LOST_CARRIER:
            return "lost carrier";
        case PW_LOST_SERVICE:
            return "lost service";
        case PW_ACCT_IDLE_TIMEOUT:
            return "idle timeout";
        case PW_ACCT_SESSION_TIMEOUT:
            return "session timeout";
        case PW_ADMIN_RESET:
            return "admin reset";
        case PW_ADMIN_REBOOT:
            return "admin reboot";
        case PW_PORT_ERROR:
            return "port error";
        case PW_NAS_ERROR:
            return "nas error";
        case PW_NAS_REQUEST:
            return "nas request";
        case PW_NAS_REBOOT:
            return "nas reboot";
        case PW_PORT_UNNEEDED:
            return "port unneeded";
        case PW_PORT_PREEMPTED:
            return "port preempted";
        case PW_PORT_SUSPENDED:
            return "port suspended";
        case PW_SERVICE_UNAVAILABLE:
            return "service unavailable";
        case PW_CALLBACK:
            return "callback";
        case PW_USER_ERROR:
            return "user error";
        case PW_HOST_REQUEST:
            return "host request";
        default:
            return "unknown";
    }
}

/**
 * Prepare authentication request data.
 * @param[in] session Session.
 * @param[in,out] req Authentication request data.
 */
static void zrad_auth_prepare(const zscope_t *scope, const zsession_t *session, zrad_auth_req_t *req)
{
    static const char password[] = "";

    req->username = session->ip_str;
    req->password = password;
    req->nas_id = scope->cfg->radius.nas_id;
    req->calling_station_id = session->ip_str;
}

/**
 * Perform authenticate request.
 * @param[in] radh Radius handle.
 * @param[out] reply_attr Reply attributes.
 * @param[in,out] reply_msg Reply message.
 * @return One of ZRAD_* codes.
 */
static zrad_status_t zrad_auth_request(rc_handle *radh, const zrad_auth_req_t *req,
                                       VALUE_PAIR **reply_attrs, char *reply_msg)
{
    zrad_status_t ret = ZRAD_OTHER;
    VALUE_PAIR *request_attrs = NULL;

    int success = rc_avpair_add(radh, &request_attrs, PW_USER_NAME, req->username, -1, 0)
                  && rc_avpair_add(radh, &request_attrs, PW_USER_PASSWORD, req->password, -1, 0)
                  && rc_avpair_add(radh, &request_attrs, PW_NAS_IDENTIFIER, req->nas_id, -1, 0)
                  && rc_avpair_add(radh, &request_attrs, PW_CALLING_STATION_ID, req->calling_station_id, -1, 0);

    if (likely(success)) {
        ret = (zrad_status_t) rc_auth(radh, 0, request_attrs, reply_attrs, reply_msg);
    }

    if (likely(request_attrs)) {
        rc_avpair_free(request_attrs);
    }

    return ret;
}

/**
 * Parse authentication reply radius attributes.
 * @param[in] session Session.
 * @param[in] attrs Radius attributes.
 * @param[in] rules Client rules.
 */
static void zrad_auth_parse(zsession_t *session, const VALUE_PAIR *attrs, zclient_rules_t *rules)
{
    zclient_rules_init(rules);

    for (; likely(NULL != attrs); attrs = attrs->next) {
        switch (attrs->attribute) {
            case PW_FILTER_ID:
                zclient_rule_parse(zinst()->client_rule_parser, rules, attrs->strvalue);
                break;
            case PW_SESSION_TIMEOUT:
                atomic_store_release(&session->timeout, SEC2USEC(attrs->lvalue));
                break;
            case PW_ACCT_INTERIM_INTERVAL:
                atomic_store_release(&session->acct_interval, SEC2USEC(attrs->lvalue));
                break;
            case PW_IDLE_TIMEOUT:
                atomic_store_release(&session->idle_timeout, SEC2USEC(attrs->lvalue));
                break;
            default:
                ZLOG(LOG_DEBUG, "Unknown radius attribute %d", attrs->attribute);
        }
    }
}

/**
 * Log session authorization.
 * @param[in] session Session.
 * @param[in] attrs Authorization reply attributes.
 */
static void zrad_auth_log(const zscope_t *scope, const zsession_t *session, const VALUE_PAIR *attrs)
{
    UT_string rules_str;
    utstring_init(&rules_str);
    utstring_reserve(&rules_str, 1024);

    for (; likely(NULL != attrs); attrs = attrs->next) {
        switch (attrs->attribute) {
            case PW_FILTER_ID:
                utstring_printf(&rules_str, " %s", attrs->strvalue);
                break;
            default:
                break;
        }
    }

    zsyslog(LOG_INFO, "%s: Authenticated session %s (rules:%s)",
            scope->cfg->name, session->ip_str, utstring_body(&rules_str));
    utstring_done(&rules_str);
}

/**
 * Authenticate and set client info.
 * @param[in] session Client session.
 * @return Zero on success.
 */
zrad_status_t zradius_session_auth(zscope_t *scope, zsession_t *session)
{
    zrad_status_t ret;
    VALUE_PAIR *reply_attrs = NULL;
    char reply_msg[PW_MAX_MSG_SIZE] = {0};

    zclient_rules_t rules;
    zclient_rules_init(&rules);

    zrad_auth_req_t req;
    zrad_auth_prepare(scope, session, &req);

    ret = zrad_auth_request(scope->radh, &req, &reply_attrs, reply_msg);
    if (unlikely(ZRAD_OK != ret)) {
        str_rtrim(reply_msg);
        ZLOG(LOG_ERR, "%s: Session authentication failed for %s (code: %s, msg: %s)",
             scope->cfg->name, session->ip_str, zrad_decode_state(ret), reply_msg);
        goto end;
    }

    zrad_auth_parse(session, reply_attrs, &rules);

    if (unlikely(!rules.have.user_id || !rules.have.login)) {
        ZLOG(LOG_ERR, "%s: Session authentication failed for %s (login or user_id not found)",
             scope->cfg->name, session->ip_str);
        ret = ZRAD_OTHER;
        goto end;
    }

    zscope_session_rules_apply(scope, session, &rules);
    zrad_auth_log(scope, session, reply_attrs);

    end:
    zclient_rules_destroy(&rules);
    if (likely(reply_attrs)) rc_avpair_free(reply_attrs);

    return ret;
}

/**
 * Prepare accounting request data.
 * @param[in] session Session.
 * @param[in,out] req Accounting data request.
 */
static void zrad_acct_prepare(zscope_t *scope, zsession_t *session, zrad_acct_req_t *req)
{
    zclient_t *client = zsession_get_client(session);

    pthread_spin_lock(&client->lock);
    req->username = client->login;
    snprintf(req->session_id, sizeof(req->session_id), "%s-%" PRIu32, client->login, session->ip);
    pthread_spin_unlock(&client->lock);

    zclient_release(client);

    req->calling_station_id = session->ip_str;
    req->framed_ip_addr = session->ip;

    req->nas_id = scope->cfg->radius.nas_id;

    req->traff_down = atomic_load_acquire(&session->traff_down);
    req->traff_up = atomic_load_acquire(&session->traff_up);

    req->octets_down = (uint32_t) (req->traff_down % UINT32_MAX);
    req->octets_up = (uint32_t) (req->traff_up % UINT32_MAX);

    req->packets_down = atomic_load_acquire(&session->packets_down) % UINT32_MAX;
    req->packets_up = atomic_load_acquire(&session->packets_up) % UINT32_MAX;

    req->gigawords_down = (uint32_t) (req->traff_down / UINT32_MAX);
    req->gigawords_up = (uint32_t) (req->traff_up / UINT32_MAX);

    req->authentic = PW_RADIUS;

    if (PW_STATUS_STOP == req->status) {
        req->session_time = (uint32_t) USEC2SEC(ztime() - session->create_time);
    }
}

/**
 * @param[in] session Session
 * @param[in] status Accounting status (PW_STATUS_START, PW_STATUS_STOP, PW_STATUS_ALIVE)
 * @param[in] cause Accounting termination cause (used only in case of PW_STATUS_STOP)
 * @param[in] req Accounting request data.
 */
static zrad_status_t zrad_acct_request(rc_handle *radh, const zrad_acct_req_t *req)
{
    zrad_status_t ret;
    VALUE_PAIR *request_attrs = NULL;

    int success = rc_avpair_add(radh, &request_attrs, PW_CALLING_STATION_ID, req->calling_station_id, -1, 0)
                  && rc_avpair_add(radh, &request_attrs, PW_ACCT_AUTHENTIC, &req->authentic, -1, 0)
                  && rc_avpair_add(radh, &request_attrs, PW_FRAMED_IP_ADDRESS, &req->framed_ip_addr, -1, 0)
                  && rc_avpair_add(radh, &request_attrs, PW_USER_NAME, req->username, -1, 0)
                  && rc_avpair_add(radh, &request_attrs, PW_ACCT_SESSION_ID, req->session_id, -1, 0)
                  && rc_avpair_add(radh, &request_attrs, PW_NAS_IDENTIFIER, req->nas_id, -1, 0)
                  && rc_avpair_add(radh, &request_attrs, PW_ACCT_INPUT_OCTETS, &req->octets_down, -1, 0)
                  && rc_avpair_add(radh, &request_attrs, PW_ACCT_INPUT_PACKETS, &req->packets_down, -1, 0)
                  && rc_avpair_add(radh, &request_attrs, PW_ACCT_OUTPUT_OCTETS, &req->octets_up, -1, 0)
                  && rc_avpair_add(radh, &request_attrs, PW_ACCT_OUTPUT_PACKETS, &req->packets_down, -1, 0)
                  && (!req->gigawords_down ||
                      rc_avpair_add(radh, &request_attrs, PW_ACCT_OUTPUT_GIGAWORDS, &req->gigawords_up, -1, 0))
                  && (!req->gigawords_down ||
                      rc_avpair_add(radh, &request_attrs, PW_ACCT_INPUT_GIGAWORDS, &req->gigawords_down, -1, 0))
                  && rc_avpair_add(radh, &request_attrs, PW_ACCT_STATUS_TYPE, &req->status, -1, 0);

    if (success && PW_STATUS_STOP == req->status) {
        success = success
                  && rc_avpair_add(radh, &request_attrs, PW_ACCT_SESSION_TIME, &req->session_time, -1, 0)
                  && rc_avpair_add(radh, &request_attrs, PW_ACCT_TERMINATE_CAUSE, &req->term_cause, -1, 0);
    }

    if (likely(success)) {
        ret = (zrad_status_t) rc_acct(radh, 0, request_attrs);
    } else {
        ret = ZRAD_OTHER;
    }

    if (likely(request_attrs)) rc_avpair_free(request_attrs);

    return ret;
}

/**
 * Send session accounting.
 * @param[in] session Session
 * @param[in] status Accounting status (PW_STATUS_START, PW_STATUS_STOP, PW_STATUS_ALIVE)
 * @param[in] cause Accounting termination cause (used only in case of PW_STATUS_STOP)
 * @return True on success.
 */
zrad_status_t zradius_session_acct(zscope_t *scope, zsession_t *session, uint32_t status, uint32_t term_cause)
{
    zrad_acct_req_t req = {0};
    req.status = status;
    req.term_cause = term_cause;

    zrad_acct_prepare(scope, session, &req);

    zrad_status_t ret = zrad_acct_request(scope->radh, &req);
    if (ZRAD_OK == ret) {
        atomic_fetch_sub_release(&session->traff_down, req.traff_down);
        atomic_fetch_sub_release(&session->traff_up, req.traff_up);
        atomic_fetch_sub_release(&session->packets_down, req.packets_down);
        atomic_fetch_sub_release(&session->packets_up, req.packets_up);
    }

    return ret;
}
