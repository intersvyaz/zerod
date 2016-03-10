#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <bson.h>
#include "remotectl_bson.h"
#include "zero.h"
#include "globals.h"
#include "log.h"
#include "worker.h"
#include "scope.h"

/**
 * BSON request schema:
 * {
 *     "version": int32,
 *     "cookie": int32,
 *     "action": cstring,
 *     ...
 * }
 */

#define ZRC_MSG_SUCCESS             "success"
#define ZRC_MSG_BAD_PACKET          "bad_packet"
#define ZRC_MSG_BAD_FILTER          "bad_filter"
#define ZRC_MSG_BAD_RULE            "bad_rule"
#define ZRC_MSG_SCOPE_NOT_FOUND     "scope_not_found"
#define ZRC_MSG_CLIENT_NOT_FOUND    "client_not_found"
#define ZRC_MSG_SESSION_NOT_FOUND   "session_not_found"

typedef struct
{
    int val;
    const char *label;
} stats_label_t;

struct rc_bson_packet_hdr
{
    uint16_t magic;
    struct
    {
        int32_t len;
        char data[0];
    } doc __attribute__((__packed__));
} __attribute__((__packed__));

static stats_label_t action_labels[] = {
        {ACTION_PASS, "pass"},
        {ACTION_DROP, "drop"},
};

static stats_label_t flow_dir_labels[] = {
        {DIR_UP,   "up"},
        {DIR_DOWN, "down"}
};

static stats_label_t traff_type_labels[] = {
        {TRAFF_CLIENT,     "client"},
        {TRAFF_LOCAL,      "local"},
        {TRAFF_NON_CLIENT, "non_client"},
};


/**
 * Prepare and send BSON packet.
 * @param[in] bev bufferevent instance.
 * @param[in] doc Reply document.
 */
static void zrc_send_bson(struct bufferevent *bev, const bson_t *doc)
{
    const uint16_t rc_bson_magic = htons(RC_BSON_MAGIC);
    bufferevent_write(bev, &rc_bson_magic, sizeof(rc_bson_magic));
    bufferevent_write(bev, bson_get_data(doc), doc->len);
}

/**
 * Send acknowledge packet.
 * @param[in] bev bufferevent instance.
 * @param code
 * @param cookie
 */
static void zrc_send_ack(struct bufferevent *bev, const char *code, int32_t cookie)
{
    bson_t *bson = BCON_NEW(
            "version", BCON_INT32(RC_BSON_VERSION),
            "cookie", BCON_INT32(cookie),
            "code", BCON_UTF8(code)
    );

    zrc_send_bson(bev, bson);
    bson_destroy(bson);
}

static void zrc_append_ring_stats(bson_t *bson, bcon_append_ctx_t *ctx, const char *name,
                                  zworker_stats_t stats[DIR_MAX][TRAFF_MAX][ACTION_MAX])
{
    BCON_APPEND_CTX(bson, ctx, name, "{");

    for (size_t dir_pos = 0; dir_pos < ARRAYSIZE(flow_dir_labels); dir_pos++) {
        zflow_dir_t flow_dir = (zflow_dir_t) flow_dir_labels[dir_pos].val;
        BCON_APPEND_CTX(bson, ctx, flow_dir_labels[dir_pos].label, "{");

        for (size_t type_pos = 0; type_pos < ARRAYSIZE(traff_type_labels); type_pos++) {
            ztraff_type_t traff_type = (ztraff_type_t) traff_type_labels[type_pos].val;
            BCON_APPEND_CTX(bson, ctx, traff_type_labels[type_pos].label, "{");

            for (size_t action_pos = 0; action_pos < ARRAYSIZE(action_labels); action_pos++) {
                zpacket_action_t action = (zpacket_action_t) action_labels[action_pos].val;
                zworker_stats_t *st = &stats[flow_dir][traff_type][action];

                BCON_APPEND_CTX(bson, ctx,
                                action_labels[action_pos].label, "{",
                                "count", BCON_INT64(atomic_load_acquire(&st->count)),
                                "speed", BCON_INT64(spdm_calc(&st->speed))
                );

#ifdef ZEROD_PROFILE
                BCON_APPEND_CTX(bson, ctx, "avg_ppt", BCON_INT64(st->avg_ppt));
#endif

                BCON_APPEND_CTX(bson, ctx, "}");

            }
            BCON_APPEND_CTX(bson, ctx, "}");
        }
        BCON_APPEND_CTX(bson, ctx, "}");
    }
    BCON_APPEND_CTX(bson, ctx, "}");
}

/**
 * Gather and send app statistic.
 * @param[in] bev bufferevent instance.
 * @param[in] doc Request document.
 * @param[in] cookie Unique request id.
 */
static void zrc_process_show_stats(struct bufferevent *bev, const bson_t *doc, int32_t cookie)
{
    (void) doc;
    size_t sessions_counter = 0, unauth_sessions_counter = 0, client_counter = 0;

    zscope_t *scope, *tmp_scope;
    HASH_ITER(hh, zinst()->scopes, scope, tmp_scope) {
        sessions_counter += zsession_db_count(scope->session_db);
        unauth_sessions_counter += atomic_load_acquire(&scope->session_unauth_count);
        client_counter += zclient_db_count(scope->client_db);
    }

    bson_t *bson = BCON_NEW(
            "version", BCON_INT32(RC_BSON_VERSION),
            "cookie", BCON_INT32(cookie),
            "code", BCON_UTF8(ZRC_MSG_SUCCESS),
            "app_ver", BCON_UTF8(ZEROD_VER_STR),
            "start_time", BCON_INT64(USEC2SEC(zinst()->start_time)),
            "sessions", "{",
            "total", BCON_INT64(sessions_counter),
            "unauth", BCON_INT64(unauth_sessions_counter),
            "}",
            "clients", "{",
            "total", BCON_INT64(client_counter),
            "}"
    );

    bson_t bson_rings;
    bson_append_array_begin(bson, "rings", -1, &bson_rings);
    for (uint32_t i = 0; i < utarray_len(&zinst()->workers); i++) {
        zworker_t *worker = *(zworker_t **) utarray_eltptr(&zinst()->workers, i);

        char str[16];
        const char *key;
        bson_uint32_to_string(i, &key, str, sizeof(str));

        bcon_append_ctx_t ctx;
        bcon_append_ctx_init(&ctx);

        BCON_APPEND_CTX(&bson_rings, &ctx, key, "{",
                        "lan", BCON_UTF8(worker->lan->ifname),
                        "wan", BCON_UTF8(worker->wan->ifname),
                        "ring_id", BCON_INT32(worker->ring_id)
        );

        zrc_append_ring_stats(&bson_rings, &ctx, "packets", worker->stats.packets);
        zrc_append_ring_stats(&bson_rings, &ctx, "traffic", worker->stats.traffic);

        BCON_APPEND_CTX(&bson_rings, &ctx, "}");
    }
    bson_append_array_end(bson, &bson_rings);

    zrc_send_bson(bev, bson);
    bson_destroy(bson);
}

/**
 * Show scopes.
 * @param[in] bev bufferevent instance.
 * @param[in] doc Request document.
 * @param[in] cookie Unique request id.
 */
static void zrc_process_show_scopes(struct bufferevent *bev, const bson_t *doc, int32_t cookie)
{
    (void) doc;

    bson_t *bson = BCON_NEW(
            "version", BCON_INT32(RC_BSON_VERSION),
            "cookie", BCON_INT32(cookie),
            "code", BCON_UTF8(ZRC_MSG_SUCCESS)
    );

    bson_t bson_scopes;
    bson_append_array_begin(bson, "scopes", -1, &bson_scopes);

    uint32_t idx = 0;
    zscope_t *scope, *tmp_scope;
    HASH_ITER(hh, zinst()->scopes, scope, tmp_scope) {
        const char *key;
        char key_buf[16];
        bson_uint32_to_string(idx, &key, key_buf, sizeof(key_buf));
        BCON_APPEND(&bson_scopes, key, BCON_UTF8(scope->cfg->name));
        idx++;
    }

    bson_append_array_end(bson, &bson_scopes);

    zrc_send_bson(bev, bson);
    bson_destroy(bson);
}

/**
 *
 * @param[in] bev bufferevent instance.
 * @param[in] doc Request document.
 * @param[in] cookie Unique request id.
 */
static void zrc_process_client_show(struct bufferevent *bev, const bson_t *doc, int32_t cookie)
{
    bson_iter_t iter;
    zscope_t *scope = NULL;
    zclient_t *client = NULL;
    UT_string rules;

    utstring_init(&rules);

    // find scope
    if (bson_iter_init_find(&iter, doc, "scope") && BSON_ITER_HOLDS_UTF8(&iter)) {
        scope = zinstance_get_scope(bson_iter_utf8(&iter, NULL));
    } else {
        zrc_send_ack(bev, ZRC_MSG_BAD_PACKET, cookie);
        goto end;
    }
    if (!scope) {
        zrc_send_ack(bev, ZRC_MSG_SCOPE_NOT_FOUND, cookie);
        goto end;
    }

    // find client
    if (bson_iter_init_find(&iter, doc, "id") && BSON_ITER_HOLDS_INT32(&iter)) {
        uint32_t id = (uint32_t) bson_iter_int32(&iter);
        client = zclient_db_acquire(scope->client_db, id, true);
    } else if (bson_iter_init_find(&iter, doc, "ip") && BSON_ITER_HOLDS_UTF8(&iter)) {
        uint32_t ip = 0;
        if (0 == ipv4_to_u32(bson_iter_utf8(&iter, NULL), &ip)) {
            zsession_t *session = zscope_session_acquire(scope, ip, SF_EXISTING_ONLY);
            if (session) {
                client = zsession_get_client(session);
                zsession_release(session);
            }
        }
    } else {
        zrc_send_ack(bev, ZRC_MSG_BAD_PACKET, cookie);
        goto end;
    }
    if (!client) {
        zrc_send_ack(bev, ZRC_MSG_CLIENT_NOT_FOUND, cookie);
        goto end;
    }

    bson_t *bson = BCON_NEW(
            "version", BCON_INT32(RC_BSON_VERSION),
            "cookie", BCON_INT32(cookie),
            "code", BCON_UTF8(ZRC_MSG_SUCCESS)
    );

    utstring_reserve(&rules, 1024);
    zclient_dump_rules(client, &rules);

    uint32_t i = 0;
    off_t pos = 0;
    bson_t bson_rules;
    bson_append_array_begin(bson, "rules", 5, &bson_rules);
    while (pos < utstring_len(&rules)) {
        char str[16];
        const char *key;
        const char *rule = utstring_body(&rules) + pos;
        bson_uint32_to_string(i, &key, str, sizeof(str));
        BCON_APPEND(&bson_rules, key, BCON_UTF8(rule));
        pos += strlen(rule) + 1;
        i++;
    }
    bson_append_array_end(bson, &bson_rules);

    zrc_send_bson(bev, bson);
    bson_destroy(bson);

    end:
    utstring_done(&rules);
    if (client) {
        zclient_release(client);
    }
}

/**
 * @param[in] bev bufferevent instance.
 * @param[in] doc Request document.
 * @param[in] cookie Unique request id.
 */
static void zrc_process_client_update(struct bufferevent *bev, const bson_t *doc, int32_t cookie)
{
    bson_iter_t iter;
    zscope_t *scope = NULL;
    uint32_t ip = 0;
    zclient_t *client = NULL;
    zclient_rules_t rules;
    UT_string all_rules;

    utstring_init(&all_rules);
    zclient_rules_init(&rules);

    // find scope
    if (bson_iter_init_find(&iter, doc, "scope") && BSON_ITER_HOLDS_UTF8(&iter)) {
        scope = zinstance_get_scope(bson_iter_utf8(&iter, NULL));
    } else {
        zrc_send_ack(bev, ZRC_MSG_BAD_PACKET, cookie);
        goto end;
    }
    if (!scope) {
        zrc_send_ack(bev, ZRC_MSG_SCOPE_NOT_FOUND, cookie);
        goto end;
    }

    // find client
    if (bson_iter_init_find(&iter, doc, "id") && BSON_ITER_HOLDS_INT32(&iter)) {
        client = zclient_db_acquire(scope->client_db, (uint32_t) bson_iter_int32(&iter), true);
    } else if (bson_iter_init_find(&iter, doc, "ip") && BSON_ITER_HOLDS_UTF8(&iter)) {
        if (0 == ipv4_to_u32(bson_iter_utf8(&iter, NULL), &ip)) {
            zsession_t *session = zscope_session_acquire(scope, ip, SF_EXISTING_ONLY);
            if (session) {
                client = zsession_get_client(session);
                zsession_release(session);
            }
        }
    } else {
        zrc_send_ack(bev, ZRC_MSG_BAD_PACKET, cookie);
        goto end;
    }
    if (!client) {
        zrc_send_ack(bev, ZRC_MSG_CLIENT_NOT_FOUND, cookie);
        goto end;
    }

    // find rules
    utstring_reserve(&all_rules, 1024);

    bson_iter_t iter_rules;
    if (!bson_iter_init_find(&iter, doc, "rules") ||
        !BSON_ITER_HOLDS_ARRAY(&iter) ||
        !bson_iter_recurse(&iter, &iter_rules)) {
        zrc_send_ack(bev, ZRC_MSG_BAD_RULE, cookie);
        goto end;
    }

    bool parse_ok = true;
    while (parse_ok && bson_iter_next(&iter_rules)) {
        uint32_t len;
        const char *rule = bson_iter_utf8(&iter_rules, &len);
        parse_ok = zclient_rule_parse(zinst()->client_rule_parser, &rules, rule);
        if (parse_ok) {
            utstring_printf(&all_rules, " %s", rule);
        }
    }

    if (!parse_ok) {
        zrc_send_ack(bev, ZRC_MSG_BAD_RULE, cookie);
        goto end;
    }

    zclient_apply_rules(client, &rules);
    zrc_send_ack(bev, ZRC_MSG_SUCCESS, cookie);

    // log client update
    char peer_ip[INET_ADDRSTRLEN];
    getpeerip(bufferevent_getfd(bev), peer_ip, sizeof(peer_ip));
    if (ip) {
        char ip_str[INET_ADDRSTRLEN];
        ipv4_to_str(ip, ip_str, sizeof(ip_str));
        zsyslog(LOG_INFO, "RC:%s: %s: update session_ip=%s (rules: %s)",
                scope->cfg->name, peer_ip, ip_str, utstring_body(&all_rules));
    } else {
        zsyslog(LOG_INFO, "RC:%s: %s: update client_id=%u (rules: %s)",
                scope->cfg->name, peer_ip, client->id, utstring_body(&all_rules));
    }

    end:
    utstring_done(&all_rules);
    zclient_rules_destroy(&rules);
    if (client) {
        zclient_release(client);
    }
}

/**
 * @param[in] bev bufferevent instance.
 * @param[in] doc Request document.
 * @param[in] cookie Unique request id.
 */
static void zrc_process_client_delete(struct bufferevent *bev, const bson_t *doc, int32_t cookie)
{
    bson_iter_t iter;
    zscope_t *scope = NULL;
    zclient_t *client = NULL;

    // find scope
    if (bson_iter_init_find(&iter, doc, "scope") && BSON_ITER_HOLDS_UTF8(&iter)) {
        scope = zinstance_get_scope(bson_iter_utf8(&iter, NULL));
    } else {
        zrc_send_ack(bev, ZRC_MSG_BAD_PACKET, cookie);
        goto end;
    }
    if (!scope) {
        zrc_send_ack(bev, ZRC_MSG_SCOPE_NOT_FOUND, cookie);
        goto end;
    }

    // find client
    if (bson_iter_init_find(&iter, doc, "id") && BSON_ITER_HOLDS_INT32(&iter)) {
        client = zclient_db_acquire(scope->client_db, (uint32_t) bson_iter_int32(&iter), true);
    } else if (bson_iter_init_find(&iter, doc, "ip") && BSON_ITER_HOLDS_UTF8(&iter)) {
        uint32_t ip = 0;
        if (0 == ipv4_to_u32(bson_iter_utf8(&iter, NULL), &ip)) {
            zsession_t *session = zscope_session_acquire(scope, ip, SF_EXISTING_ONLY);
            if (session) {
                client = zsession_get_client(session);
                zsession_release(session);
            }
        }
    } else {
        zrc_send_ack(bev, ZRC_MSG_BAD_PACKET, cookie);
        goto end;
    }
    if (NULL == client) {
        zrc_send_ack(bev, ZRC_MSG_CLIENT_NOT_FOUND, cookie);
        goto end;
    }

    char peerip[INET_ADDRSTRLEN];
    getpeerip(bufferevent_getfd(bev), peerip, sizeof(peerip));

    zsyslog(LOG_INFO, "RC:%s: %s: remove client user_id=%" PRIu32, scope->cfg->name, peerip, client->id);

    pthread_spin_lock(&client->lock);

    for (size_t i = 0; i < utarray_len(&client->sessions); i++) {
        uint32_t ip = *(uint32_t *) utarray_eltptr(&client->sessions, i);
        // mark session for deletion
        zsession_t *session = zscope_session_acquire(scope, ip, SF_EXISTING_ONLY);
        if (likely(session)) {
            atomic_store_release(&session->delete_queued, true);
            zsession_release(session);
        }
    }

    pthread_spin_unlock(&client->lock);

    zrc_send_ack(bev, ZRC_MSG_SUCCESS, cookie);

    end:
    if (client) {
        zclient_release(client);
    }
}

/**
 * @param[in] bev bufferevent instance.
 * @param[in] doc Request document.
 * @param[in] cookie Unique request id.
 */
static void zrc_process_session_show(struct bufferevent *bev, const bson_t *doc, int32_t cookie)
{
    bson_iter_t iter;
    zscope_t *scope = NULL;
    zsession_t *session = NULL;

    // find scope
    if (bson_iter_init_find(&iter, doc, "scope") && BSON_ITER_HOLDS_UTF8(&iter)) {
        scope = zinstance_get_scope(bson_iter_utf8(&iter, NULL));
    } else {
        zrc_send_ack(bev, ZRC_MSG_BAD_PACKET, cookie);
        goto end;
    }
    if (!scope) {
        zrc_send_ack(bev, ZRC_MSG_SCOPE_NOT_FOUND, cookie);
        goto end;
    }

    // find session
    if (bson_iter_init_find(&iter, doc, "ip") && BSON_ITER_HOLDS_UTF8(&iter)) {
        uint32_t ip = 0;
        if (0 == ipv4_to_u32(bson_iter_utf8(&iter, NULL), &ip)) {
            session = zscope_session_acquire(scope, ip, SF_EXISTING_ONLY);
        }
    } else {
        zrc_send_ack(bev, ZRC_MSG_BAD_PACKET, cookie);
        return;
    }
    if (!session) {
        zrc_send_ack(bev, ZRC_MSG_SESSION_NOT_FOUND, cookie);
        return;
    }

    zclient_t *client = zsession_get_client(session);

    bson_t *bson = BCON_NEW(
            "version", BCON_INT32(RC_BSON_VERSION),
            "cookie", BCON_INT32(cookie),
            "code", BCON_UTF8(ZRC_MSG_SUCCESS),
            "user_id", BCON_INT32(client->id),
            "create_time", BCON_INT64(USEC2SEC(session->create_time)),
            "last_activity", BCON_INT64(USEC2SEC(atomic_load_acquire(&session->last_activity))),
            "last_accounting", BCON_INT64(USEC2SEC(atomic_load_acquire(&session->last_acct))),
            "last_authorization", BCON_INT64(USEC2SEC(atomic_load_acquire(&session->last_auth))),
            "traffic_down", BCON_INT64(atomic_load_acquire(&session->traff_down)),
            "traffic_up", BCON_INT64(atomic_load_acquire(&session->traff_up)),
            "timeout", BCON_INT64(USEC2SEC(atomic_load_acquire(&session->timeout))),
            "idle_timeout", BCON_INT64(USEC2SEC(atomic_load_acquire(&session->idle_timeout))),
            "accounting_interval", BCON_INT64(USEC2SEC(atomic_load_acquire(&session->acct_interval)))
    );

    zdhcp_lease_t lease = {.ip = session->ip, .mac = {0}};
    if (zdhcp_lease_find(scope->dhcp, &lease)) {
        char mac_str[HWADDR_MAC48_STR_LEN] = {0};
        mac48_bin_to_str(lease.mac, mac_str, sizeof(mac_str));
        BCON_APPEND(bson,
                    "dhcp_lease_end", BCON_INT64(USEC2SEC(lease.lease_end)),
                    "mac", BCON_UTF8(mac_str)
        );
    }

    zclient_release(client);

    zrc_send_bson(bev, bson);
    bson_destroy(bson);

    end:
    if (session) {
        zsession_release(session);
    }
}

/**
 * @brief zrc_process_session_delete
 * @param[in] bev bufferevent instance.
 * @param[in] doc Request document.
 * @param[in] cookie Unique request id.
 */
static void zrc_process_session_delete(struct bufferevent *bev, const bson_t *doc, int32_t cookie)
{
    bson_iter_t iter;
    zscope_t *scope = NULL;
    zsession_t *sess = NULL;

    // finds scope
    if (bson_iter_init_find(&iter, doc, "scope") && BSON_ITER_HOLDS_UTF8(&iter)) {
        scope = zinstance_get_scope(bson_iter_utf8(&iter, NULL));
    } else {
        zrc_send_ack(bev, ZRC_MSG_BAD_PACKET, cookie);
        goto end;
    }
    if (!scope) {
        zrc_send_ack(bev, ZRC_MSG_SCOPE_NOT_FOUND, cookie);
        goto end;
    }

    // find session
    if (bson_iter_init_find(&iter, doc, "ip") && BSON_ITER_HOLDS_UTF8(&iter)) {
        uint32_t ip = 0;
        if (0 == ipv4_to_u32(bson_iter_utf8(&iter, NULL), &ip)) {
            sess = zscope_session_acquire(scope, ip, SF_EXISTING_ONLY);
        }
    } else {
        zrc_send_ack(bev, ZRC_MSG_BAD_PACKET, cookie);
        goto end;
    }
    if (!sess) {
        zrc_send_ack(bev, ZRC_MSG_SESSION_NOT_FOUND, cookie);
        goto end;
    }

    char peerip[INET_ADDRSTRLEN];
    getpeerip(bufferevent_getfd(bev), peerip, sizeof(peerip));

    zsyslog(LOG_INFO, "RC:%s: %s: remove session %s", scope->cfg->name, peerip, sess->ip_str);
    // mark session for deletion
    atomic_store_release(&sess->delete_queued, true);

    zrc_send_ack(bev, "success", cookie);

    end:
    if (sess) {
        zsession_release(sess);
    }
}

/**
 * Show runtime configuration.
 * @param[in] bev bufferevent instance.
 * @param[in] doc Request document.
 * @param[in] cookie Unique request id.
 */
static void zrc_process_scope_show(struct bufferevent *bev, const bson_t *doc, int32_t cookie)
{
    bson_iter_t iter;
    zscope_t *scope = NULL;

    if (bson_iter_init_find(&iter, doc, "scope") && BSON_ITER_HOLDS_UTF8(&iter)) {
        scope = zinstance_get_scope(bson_iter_utf8(&iter, NULL));
    } else {
        zrc_send_ack(bev, ZRC_MSG_BAD_PACKET, cookie);
        return;
    }
    if (!scope) {
        zrc_send_ack(bev, ZRC_MSG_SCOPE_NOT_FOUND, cookie);
        return;
    }

    bson_t *bson = BCON_NEW(
            "version", BCON_INT32(RC_BSON_VERSION),
            "cookie", BCON_INT32(cookie),
            "code", BCON_UTF8(ZRC_MSG_SUCCESS),
            "config", "{",
            "sessions_count", BCON_INT64(zsession_db_count(scope->session_db)),
            "sessions_new_count", BCON_INT64(atomic_load_acquire(&scope->session_new_count)),
            "sessions_unauth_count", BCON_INT64(atomic_load_acquire(&scope->session_unauth_count)),
            "clients_count", BCON_INT64(zclient_db_count(scope->client_db)),
            "arp_protect_errors", BCON_INT32(atomic_load_acquire(&scope->security.arp_errors)),
            "ip_protect_errors", BCON_INT32(atomic_load_acquire(&scope->security.ip_errors)),
            "blacklist_hits", BCON_INT32(atomic_load_acquire(&scope->blacklist_hits)),
            "}"
    );

    zrc_send_bson(bev, bson);
    bson_destroy(bson);
}

/**
 * @param[in] bev bufferevent instance.
 * @param[in] doc Request document.
 * @param[in] cookie Unique request id.
 */
static void zrc_process_scope_update(struct bufferevent *bev, const bson_t *doc, int32_t cookie)
{
    bson_iter_t iter;
    zscope_t *scope = NULL;

    // scope name
    if (bson_iter_init_find(&iter, doc, "scope") && BSON_ITER_HOLDS_UTF8(&iter)) {
        scope = zinstance_get_scope(bson_iter_utf8(&iter, NULL));
    } else {
        zrc_send_ack(bev, ZRC_MSG_BAD_PACKET, cookie);
        return;
    }
    if (!scope) {
        zrc_send_ack(bev, ZRC_MSG_SCOPE_NOT_FOUND, cookie);
        return;
    }

    // rules array
    bson_iter_t rule_iter;
    if (unlikely(!bson_iter_init_find(&iter, doc, "rules")
                 || !BSON_ITER_HOLDS_ARRAY(&iter)
                 || !bson_iter_recurse(&iter, &rule_iter))) {
        zrc_send_ack(bev, ZRC_MSG_BAD_PACKET, cookie);
        return;
    }

    zscope_rules_t rules;
    UT_string all_rules;

    utstring_init(&all_rules);
    utstring_reserve(&all_rules, 1024);
    zscope_rules_init(&rules);

    bool parse_ok = true;
    while (bson_iter_next(&rule_iter)) {
        if (!BSON_ITER_HOLDS_UTF8(&rule_iter)) {
            continue;
        }
        uint32_t rule_len = 0;
        const char *rule = bson_iter_utf8(&rule_iter, &rule_len);
        if (0 != zscope_rules_parse(&rules, rule)) {
            parse_ok = false;
            break;
        }
        utstring_printf(&all_rules, " %s", rule);
    }

    if (parse_ok) {
        zscope_apply_rules(scope, &rules);
        zrc_send_ack(bev, ZRC_MSG_SUCCESS, cookie);

        char peerip[INET_ADDRSTRLEN];
        getpeerip(bufferevent_getfd(bev), peerip, sizeof(peerip));
        zsyslog(LOG_INFO, "RC:%s: %s: reconfigure with rules:%s", scope->cfg->name, peerip, utstring_body(&all_rules));
    } else {
        zrc_send_ack(bev, ZRC_MSG_BAD_RULE, cookie);
    }

    utstring_done(&all_rules);
    zscope_rules_destroy(&rules);
}

/**
 * @brief zrc_process_monitor
 * @param[in] bev bufferevent instance.
 * @param[in] doc Request document.
 * @param[in] cookie Unique request id.
 */
static void zrc_process_monitor(struct bufferevent *bev, const bson_t *doc, int32_t cookie)
{
    bson_iter_t iter;

    if (!bson_iter_init_find(&iter, doc, "filter") || !BSON_ITER_HOLDS_UTF8(&iter)) {
        zrc_send_ack(bev, ZRC_MSG_BAD_PACKET, cookie);
        return;
    }
    uint32_t len = 0;
    char const *filter = bson_iter_utf8(&iter, &len);
    zmonitor_conn_t *conn = zmonitor_conn_new(zinst()->cfg->monitor.conn_bandwidth);

    if (zmonitor_conn_set_filter(conn, filter)) {
        zrc_send_ack(bev, ZRC_MSG_SUCCESS, cookie);
        bufferevent_priority_set(bev, PRIO_LOW);
        zmonitor_conn_set_listener(conn, bev);
        zmonitor_conn_activate(conn, zinst()->monitor);

        char peerip[INET_ADDRSTRLEN];
        getpeerip(bufferevent_getfd(bev), peerip, sizeof(peerip));
        zsyslog(LOG_INFO, "RC:%s: monitor traffic (filter: %s)", peerip, filter);
    } else {
        zrc_send_ack(bev, ZRC_MSG_BAD_FILTER, cookie);
        zmonitor_conn_free(conn);
    }
}

#ifndef NDEBUG

/**
 * @brief Dump traffic counters.
 * @param[in] bev bufferevent instance.
 * @param[in] doc Request document.
 * @param[in] cookie Unique request id.
 */
static void zrc_process_dump_counters(struct bufferevent *bev, const bson_t *doc, int32_t cookie)
{
    (void) doc;
    zrc_send_ack(bev, ZRC_MSG_SUCCESS, cookie);
    zsyslog(LOG_INFO, "RC: dump traffic counters");

    const char filename[] = "traff_counters.json";
    FILE *f = fopen(filename, "w+");
    if (!f) {
        ZLOGEX(LOG_ERR, errno, "Failed to open %s for writing", filename);
        return;
    }

    fprintf(f, "{\n");

    for (int proto = PROTO_TCP; proto < PROTO_MAX; proto++) {
        if (PROTO_TCP == proto) {
            fprintf(f, "\t\"tcp\":[\n");
        } else {
            fprintf(f, "\t\"udp\":[\n");
        }
        for (int port = 0; port < 65536; port++) {
            fprintf(f, "\t\t{\"port\": %d, \"packets\": %" PRIu64 ", \"bytes\": %" PRIu64 "},\n",
                    port,
                    zinst()->dbg.traff_counter[proto][port].packets,
                    zinst()->dbg.traff_counter[proto][port].bytes);
        }
        fseek(f, -2, SEEK_CUR);
        fprintf(f, "\n\t],\n");
    }
    fseek(f, -2, SEEK_CUR);
    fprintf(f, "\n");

    fputc('}', f);
    fclose(f);
}

#endif

/**
 * @param bev
 * @param doc
 */
static void zrc_process_command(struct bufferevent *bev, const bson_t *doc)
{
    bson_iter_t iter;
    uint32_t len = 0;

    if (!bson_iter_init_find(&iter, doc, "version") || !BSON_ITER_HOLDS_INT32(&iter)) {
        return;
    }
    int32_t version = bson_iter_int32(&iter);
    (void) version;

    if (!bson_iter_init_find(&iter, doc, "cookie") || !BSON_ITER_HOLDS_INT32(&iter)) {
        return;
    }
    int32_t cookie = bson_iter_int32(&iter);

    if (!bson_iter_init_find(&iter, doc, "action") || !BSON_ITER_HOLDS_UTF8(&iter)) {
        return;
    }
    const char *action = bson_iter_utf8(&iter, &len);

    ztime_refresh();
    zclock_refresh();

    if (0 == strncmp(action, "show_stats", len)) {
        zrc_process_show_stats(bev, doc, cookie);
    } else if (0 == strncmp(action, "show_scopes", len)) {
        zrc_process_show_scopes(bev, doc, cookie);
    } else if (0 == strncmp(action, "client_show", len)) {
        zrc_process_client_show(bev, doc, cookie);
    } else if (0 == strncmp(action, "client_update", len)) {
        zrc_process_client_update(bev, doc, cookie);
    } else if (0 == strncmp(action, "client_delete", len)) {
        zrc_process_client_delete(bev, doc, cookie);
    } else if (0 == strncmp(action, "session_show", len)) {
        zrc_process_session_show(bev, doc, cookie);
    } else if (0 == strncmp(action, "session_delete", len)) {
        zrc_process_session_delete(bev, doc, cookie);
    } else if (0 == strncmp(action, "scope_show", len)) {
        zrc_process_scope_show(bev, doc, cookie);
    } else if (0 == strncmp(action, "scope_update", len)) {
        zrc_process_scope_update(bev, doc, cookie);
    } else if (0 == strncmp(action, "monitor", len)) {
        zrc_process_monitor(bev, doc, cookie);
#ifndef NDEBUG
    } else if (0 == strncmp(action, "dump_counters", len)) {
        zrc_process_dump_counters(bev, doc, cookie);
#endif
    } else {
        ZLOG(LOG_WARNING, "RC: invalid action: %s", action);
        return;
    }
}

/**
 * @param[in] bev Bufferevent handle.
 */
void rc_bson_read(struct bufferevent *bev)
{
    struct evbuffer *input = bufferevent_get_input(bev);
    size_t src_len = evbuffer_get_length(input);
    struct rc_bson_packet_hdr *hdr;

    // wait for header
    if (src_len < sizeof(*hdr)) {
        return;
    }

    hdr = (struct rc_bson_packet_hdr *) evbuffer_pullup(input, sizeof(*hdr));
    size_t doc_len = (size_t) le32toh(hdr->doc.len);
    size_t packet_len = sizeof(hdr->magic) + doc_len;

    // wait for entire packet
    if (src_len < packet_len) {
        return;
    }

    hdr = (struct rc_bson_packet_hdr *) evbuffer_pullup(input, packet_len);

    bson_t doc;
    if (!bson_init_static(&doc, (uint8_t *) &hdr->doc, doc_len)) {
        ZLOG(LOG_WARNING, "RC: received malformed BSON document");
        return;
    }

    zrc_process_command(bev, &doc);
    evbuffer_drain(input, packet_len);
}
