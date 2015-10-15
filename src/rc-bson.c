#include "rc-bson.h"
#include <bson.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include "zero.h"
#include "session.h"
#include "client.h"
#include "crules.h"
#include "srules.h"
#include "monitor.h"
#include "log.h"
#include "config.h"

/**
 * BSON request schema:
 * {
 *     "version": int32,
 *     "cookie": int32,
 *     "action": cstring,
 *     ...
 * }
 */

struct rc_bson_packet_hdr
{
    uint16_t magic;
    struct
    {
        int32_t len;
        char data[0];
    } doc __attribute__((__packed__));
} __attribute__((__packed__));


/**
 * Prepare and send BSON packet.
 * @param[in] bev bufferevent instance.
 * @param[in] doc Reply document.
 */
static void rc_send_bson(struct bufferevent *bev, const bson_t *doc)
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
static void rc_send_ack(struct bufferevent *bev, char const *code, int32_t cookie)
{
    bson_t *bson = BCON_NEW(
            "version", BCON_INT32(RC_BSON_VERSION),
            "cookie", BCON_INT32(cookie),
            "code", BCON_UTF8(code)
    );

    rc_send_bson(bev, bson);
    bson_destroy(bson);
}

/**
 * Gather and send app statistic.
 * @param[in] bev bufferevent instance.
 * @param[in] doc Request document.
 * @param[in] cookie Unique request id.
 */
static void rc_process_stats_show(struct bufferevent *bev, const bson_t *doc, int32_t cookie)
{
    (void) doc;

    bson_t *bson = BCON_NEW(
        "version", BCON_INT32(RC_BSON_VERSION),
        "cookie", BCON_INT32(cookie),
        "code", BCON_UTF8("success"),
        "start_time", BCON_INT64(USEC2SEC(zinst()->start_time)),
        "sessions", "{",
            "total", BCON_INT64(atomic_load_explicit(&zinst()->sessions_cnt, memory_order_acquire)),
            "unauth", BCON_INT64(atomic_load_explicit(&zinst()->unauth_sessions_cnt, memory_order_acquire)),
        "}",
        "clients", "{",
            "total", BCON_INT64(client_db_get_count(zinst()->client_db)),
        "}",
        "non_clients", "{",
            "max_bandwidth", "{",
                "down", BCON_INT64(token_bucket_get_max(&zinst()->non_client.band[DIR_DOWN])),
                "up", BCON_INT64(token_bucket_get_max(&zinst()->non_client.band[DIR_UP])),
            "}",
            "speed", "{",
                "down", BCON_INT64(spdm_calc(&zinst()->non_client.speed[DIR_DOWN])),
                "up", BCON_INT64(spdm_calc(&zinst()->non_client.speed[DIR_UP])),
            "}",
        "}"
    );

    bson_t bson_rings;
    bson_append_array_begin(bson, "rings", 5, &bson_rings);
    for (size_t i = 0; i < utarray_len(&zinst()->rings); i++) {
        struct zring *ring = (struct zring *) utarray_eltptr(&zinst()->rings, i);

        char str[16];
        const char *key;
        bson_uint32_to_string(i, &key, str, sizeof(str));
        BCON_APPEND(&bson_rings, key, "{",
            "lan", BCON_UTF8(ring->if_pair->lan),
            "wan", BCON_UTF8(ring->if_pair->wan),
            "ring_id", BCON_INT32(ring->ring_id),
            "packets", "{",
                "down", "{",
                    "all", "{",
                        "count", BCON_INT64(atomic_load_explicit(&ring->packets[DIR_DOWN].all.count, memory_order_acquire)),
                        "speed", BCON_INT64(spdm_calc(&ring->packets[DIR_DOWN].all.speed)),
                    "}",
                    "passed", "{",
                        "count", BCON_INT64(atomic_load_explicit(&ring->packets[DIR_DOWN].passed.count, memory_order_acquire)),
                        "speed", BCON_INT64(spdm_calc(&ring->packets[DIR_DOWN].passed.speed)),
                    "}",
                    "client", "{",
                        "count", BCON_INT64(atomic_load_explicit(&ring->packets[DIR_DOWN].client.count, memory_order_acquire)),
                        "speed", BCON_INT64(spdm_calc(&ring->packets[DIR_DOWN].client.speed)),
                    "}",
                "}",
                "up", "{",
                    "all", "{",
                        "count", BCON_INT64(atomic_load_explicit(&ring->packets[DIR_UP].all.count, memory_order_acquire)),
                        "speed", BCON_INT64(spdm_calc(&ring->packets[DIR_UP].all.speed)),
                    "}",
                    "passed", "{",
                        "count", BCON_INT64(atomic_load_explicit(&ring->packets[DIR_UP].passed.count, memory_order_acquire)),
                        "speed", BCON_INT64(spdm_calc(&ring->packets[DIR_UP].passed.speed)),
                    "}",
                    "client", "{",
                        "count", BCON_INT64(atomic_load_explicit(&ring->packets[DIR_UP].client.count, memory_order_acquire)),
                        "speed", BCON_INT64(spdm_calc(&ring->packets[DIR_UP].client.speed)),
                    "}",
                "}",
            "}",
            "traffic", "{",
                "down", "{",
                    "all", "{",
                        "count", BCON_INT64(atomic_load_explicit(&ring->traffic[DIR_DOWN].all.count, memory_order_acquire)),
                        "speed", BCON_INT64(spdm_calc(&ring->traffic[DIR_DOWN].all.speed)),
                    "}",
                    "passed", "{",
                        "count", BCON_INT64(atomic_load_explicit(&ring->traffic[DIR_DOWN].passed.count, memory_order_acquire)),
                        "speed", BCON_INT64(spdm_calc(&ring->traffic[DIR_DOWN].passed.speed)),
                    "}",
                    "client", "{",
                        "count", BCON_INT64(atomic_load_explicit(&ring->traffic[DIR_DOWN].client.count, memory_order_acquire)),
                        "speed", BCON_INT64(spdm_calc(&ring->traffic[DIR_DOWN].client.speed)),
                    "}",
                "}",
                "up", "{",
                    "all", "{",
                        "count", BCON_INT64(atomic_load_explicit(&ring->traffic[DIR_UP].all.count, memory_order_acquire)),
                        "speed", BCON_INT64(spdm_calc(&ring->traffic[DIR_UP].all.speed)),
                    "}",
                    "passed", "{",
                        "count", BCON_INT64(atomic_load_explicit(&ring->traffic[DIR_UP].passed.count, memory_order_acquire)),
                        "speed", BCON_INT64(spdm_calc(&ring->traffic[DIR_UP].passed.speed)),
                    "}",
                    "client", "{",
                        "count", BCON_INT64(atomic_load_explicit(&ring->traffic[DIR_UP].client.count, memory_order_acquire)),
                        "speed", BCON_INT64(spdm_calc(&ring->traffic[DIR_UP].client.speed)),
                    "}",
                "}",
            "}",
        "}");
    }
    bson_append_array_end(bson, &bson_rings);

    rc_send_bson(bev, bson);
    bson_destroy(bson);
}

/**
 * @brief rc_process_client_show
 * @param[in] bev bufferevent instance.
 * @param[in] doc Request document.
 * @param[in] cookie Unique request id.
 */
static void rc_process_client_show(struct bufferevent *bev, const bson_t *doc, int32_t cookie)
{
    bson_iter_t iter;
    struct zclient *client = NULL;
    struct zsession *session = NULL;

    if (bson_iter_init_find(&iter, doc, "id") && BSON_ITER_HOLDS_INT32(&iter)) {
        client = client_acquire(zinst()->client_db, bson_iter_int32(&iter));
    } else if (bson_iter_init_find(&iter, doc, "ip") && BSON_ITER_HOLDS_UTF8(&iter)) {
        uint32_t ip = 0, len = 0;
        if (0 == ipv4_to_u32(bson_iter_utf8(&iter, &len), &ip)) {
            session = session_acquire(ip, SF_EXISTING_ONLY);
            if (NULL != session) {
                pthread_rwlock_rdlock(&session->lock_client);
                client = session->client;
            }
        }
    } else {
        rc_send_ack(bev, "invalid_id_or_ip", cookie);
        return;
    }

    if (NULL == client) {
        rc_send_ack(bev, "not_found", cookie);
        return;
    }

    bson_t *bson = BCON_NEW(
        "version", BCON_INT32(RC_BSON_VERSION),
        "cookie", BCON_INT32(cookie),
        "code", BCON_UTF8("success")
    );

    UT_string rules;
    utstring_init(&rules);
    utstring_reserve(&rules, 1024);
    client_dump_rules(client, &rules);

    int i = 0;
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
    utstring_done(&rules);

    if (session) {
        pthread_rwlock_unlock(&session->lock_client);
        session_release(session);
    } else {
        client_release(client);
    }

    rc_send_bson(bev, bson);
    bson_destroy(bson);
}

/**
 * @brief rc_process_client_update
 * @param[in] bev bufferevent instance.
 * @param[in] doc Request document.
 * @param[in] cookie Unique request id.
 */
static void rc_process_client_update(struct bufferevent *bev, const bson_t *doc, int32_t cookie)
{
    bson_iter_t iter;
    struct zclient *client = NULL;
    struct zsession *session = NULL;

    if (bson_iter_init_find(&iter, doc, "id") && BSON_ITER_HOLDS_INT32(&iter)) {
        client = client_acquire(zinst()->client_db, bson_iter_int32(&iter));
    } else if (bson_iter_init_find(&iter, doc, "ip") && BSON_ITER_HOLDS_UTF8(&iter)) {
        uint32_t ip = 0, len = 0;
        if (0 == ipv4_to_u32(bson_iter_utf8(&iter, &len), &ip)) {
            session = session_acquire(ip, SF_EXISTING_ONLY);
            if (NULL != session) {
                pthread_rwlock_rdlock(&session->lock_client);
                client = session->client;
            }
        }
    } else {
        rc_send_ack(bev, "bad_packet", cookie);
        return;
    }

    if (NULL == client) {
        rc_send_ack(bev, "not_found", cookie);
        return;
    }

    UT_string all_rules;
    struct zcrules rules;
    crules_init(&rules);
    utstring_init(&all_rules);
    utstring_reserve(&all_rules, 1024);

    bson_iter_t child;
    if (!bson_iter_init_find(&iter, doc, "rules") ||
        !BSON_ITER_HOLDS_ARRAY(&iter) ||
        !bson_iter_recurse(&iter, &child)) {
        return;
    }

    bool parse_ok = true;
    while (bson_iter_next(&child)) {
        uint32_t len;
        const char *rule = bson_iter_utf8(&child, &len);
        if (0 != crules_parse(&rules, rule)) {
            parse_ok = false;
            break;
        }
        utstring_printf(&all_rules, " %s", rule);
    }

    if (parse_ok) {
        client_apply_rules(client, &rules);
        rc_send_ack(bev, "success", cookie);

        // log client update
        if (session) {
            zero_syslog(LOG_INFO, "Remote request[%s]: update session_ip=%s (rules: %s)",
                        getpeerip(bufferevent_getfd(bev)), ipv4_to_str(htonl(session->ip)), utstring_body(&all_rules));
        } else {
            zero_syslog(LOG_INFO, "Remote request[%s]: update client_id=%u (rules: %s)",
                        getpeerip(bufferevent_getfd(bev)), client->id, utstring_body(&all_rules));
        }
    } else {
        rc_send_ack(bev, "bad_rule", cookie);
    }

    if (session) {
        pthread_rwlock_unlock(&session->lock_client);
        session_release(session);
    } else {
        client_release(client);
    }

    utstring_done(&all_rules);
    crules_free(&rules);
}

/**
 * @brief rc_process_client_delete
 * @param[in] bev bufferevent instance.
 * @param[in] doc Request document.
 * @param[in] cookie Unique request id.
 */
static void rc_process_client_delete(struct bufferevent *bev, const bson_t *doc, int32_t cookie)
{
    bson_iter_t iter;
    struct zclient *client = NULL;

    if (bson_iter_init_find(&iter, doc, "id") && BSON_ITER_HOLDS_INT32(&iter)) {
        client = client_acquire(zinst()->client_db, bson_iter_int32(&iter));
    } else {
        rc_send_ack(bev, "bad_packet", cookie);
        return;
    }

    if (NULL == client) {
        rc_send_ack(bev, "not_found", cookie);
        return;
    }

    zero_syslog(LOG_INFO, "Remote request[%s]: remove session user_id=%" PRIu32,
                getpeerip(bufferevent_getfd(bev)), client->id);
    pthread_spin_lock(&client->lock);

    for (size_t i = 0; i < utarray_len(&client->sessions); i++) {
        struct zsession *sess = *(struct zsession **) utarray_eltptr(&client->sessions, i);
        // mark session for deletion
        atomic_store_explicit(&sess->delete_flag, true, memory_order_release);
    }

    pthread_spin_unlock(&client->lock);
    client_release(client);
    rc_send_ack(bev, "success", cookie);
}

/**
 * @brief rc_process_session_show
 * @param[in] bev bufferevent instance.
 * @param[in] doc Request document.
 * @param[in] cookie Unique request id.
 */
static void rc_process_session_show(struct bufferevent *bev, const bson_t *doc, int32_t cookie)
{
    bson_iter_t iter;
    struct zsession *sess = NULL;

    if (bson_iter_init_find(&iter, doc, "ip") && BSON_ITER_HOLDS_UTF8(&iter)) {
        uint32_t ip = 0, len = 0;
        if (0 == ipv4_to_u32(bson_iter_utf8(&iter, &len), &ip)) {
            sess = session_acquire(ip, SF_EXISTING_ONLY);
        }
    } else {
        rc_send_ack(bev, "bad_packet", cookie);
        return;
    }

    if (NULL == sess) {
        rc_send_ack(bev, "not_found", cookie);
        return;
    }

    pthread_rwlock_rdlock(&sess->lock_client);
    uint32_t user_id = sess->client->id;
    pthread_rwlock_unlock(&sess->lock_client);

    bson_t *bson = BCON_NEW(
            "version", BCON_INT32(RC_BSON_VERSION),
            "cookie", BCON_INT32(cookie),
            "code", BCON_UTF8("success"),
            "user_id", BCON_INT32(user_id),
            "create_time", BCON_INT64(USEC2SEC(sess->create_time)),
            "last_activity", BCON_INT64(USEC2SEC(atomic_load_explicit(&sess->last_activity, memory_order_acquire))),
            "last_accounting", BCON_INT64(USEC2SEC(atomic_load_explicit(&sess->last_acct, memory_order_acquire))),
            "last_authorization", BCON_INT64(USEC2SEC(atomic_load_explicit(&sess->last_auth, memory_order_acquire))),
            "dhcp_lease_end", BCON_INT64(USEC2SEC(sess->dhcp_lease_end)),
            "traffic_down", BCON_INT64(atomic_load_explicit(&sess->traff_down, memory_order_acquire)),
            "traffic_up", BCON_INT64(atomic_load_explicit(&sess->traff_up, memory_order_acquire)),
            "max_duration", BCON_INT64(USEC2SEC(atomic_load_explicit(&sess->max_duration, memory_order_acquire))),
            "accounting_interval", BCON_INT64(USEC2SEC(atomic_load_explicit(&sess->acct_interval, memory_order_acquire))),
            "hw_addr", BCON_UTF8(mac48_bin_to_str(sess->hw_addr))
    );

    session_release(sess);
    rc_send_bson(bev, bson);
    bson_destroy(bson);
}

/**
 * @brief rc_process_session_delete
 * @param[in] bev bufferevent instance.
 * @param[in] doc Request document.
 * @param[in] cookie Unique request id.
 */
static void rc_process_session_delete(struct bufferevent *bev, const bson_t *doc, int32_t cookie)
{
    bson_iter_t iter;
    const char *ip_str = NULL;
    struct zsession *sess = NULL;

    if (bson_iter_init_find(&iter, doc, "ip") && BSON_ITER_HOLDS_UTF8(&iter)) {
        uint32_t ip = 0, len = 0;
        ip_str = bson_iter_utf8(&iter, &len);
        if (0 == ipv4_to_u32(ip_str, &ip)) {
            sess = session_acquire(ip, SF_EXISTING_ONLY);
        }
    } else {
        rc_send_ack(bev, "bad_packet", cookie);
        return;
    }

    if (NULL != sess) {
        zero_syslog(LOG_INFO, "Remote request[%s]: remove session %s", getpeerip(bufferevent_getfd(bev)), ip_str);
        // mark session for deletion
        atomic_store_explicit(&sess->delete_flag, true, memory_order_release);
        session_release(sess);
        rc_send_ack(bev, "success", cookie);
    } else {
        rc_send_ack(bev, "not_found", cookie);
    }
}

/**
 * @brief rc_process_upstream_show
 * @param[in] bev bufferevent instance.
 * @param[in] doc Request document.
 * @param[in] cookie Unique request id.
 */
static void rc_process_upstream_show(struct bufferevent *bev, const bson_t *doc, int32_t cookie)
{
    (void) doc;

    bson_t *bson = BCON_NEW(
        "version", BCON_INT32(RC_BSON_VERSION),
        "cookie", BCON_INT32(cookie),
        "code", BCON_UTF8("success")
    );

    bson_t upstreams;
    bson_append_array_begin(bson, "upstreams", 9, &upstreams);
    for (uint16_t i = 0; i < UPSTREAM_COUNT; i++) {
        char str[16];
        const char *key;
        bson_uint32_to_string(i, &key, str, sizeof(str));

        BCON_APPEND(&upstreams,
            BCON_UTF8(key), "{",
                "speed", "{",
                    "down", BCON_INT64(spdm_calc(&zinst()->upstreams[i].speed[DIR_DOWN])),
                    "up", BCON_INT64(spdm_calc(&zinst()->upstreams[i].speed[DIR_UP])),
                "}",
                "p2p_bw_limit", "{",
                    "down", BCON_INT64(token_bucket_get_max(&zinst()->upstreams[i].band[DIR_DOWN])),
                    "up", BCON_INT64(token_bucket_get_max(&zinst()->upstreams[i].band[DIR_UP])),
                "}",
            "}"
        );
    }
    bson_append_array_end(bson, &upstreams);

    rc_send_bson(bev, bson);
    bson_destroy(bson);
}

/**
 * Show runtime configuration.
 * @param[in] bev bufferevent instance.
 * @param[in] doc Request document.
 * @param[in] cookie Unique request id.
 */
static void rc_process_info_show(struct bufferevent *bev, const bson_t *doc, int32_t cookie)
{
    (void) doc;

    bson_t *bson = BCON_NEW(
            "version", BCON_INT32(RC_BSON_VERSION),
            "cookie", BCON_INT32(cookie),
            "code", BCON_UTF8("success"),
            "config", "{",
                "app_ver", BCON_UTF8(ZEROD_VER_STR),
                "start_time", BCON_INT64(USEC2SEC(zinst()->start_time)),
                "non_client_bw_limit_up", BCON_INT64(token_bucket_get_max(&zinst()->non_client.band[DIR_UP]) * 8),
                "non_client_bw_limit_down", BCON_INT64(token_bucket_get_max(&zinst()->non_client.band[DIR_DOWN]) * 8),
                "arp_inspection", BCON_INT32(atomic_load_explicit(&zinst()->arp.mode, memory_order_acquire)),
                "arp_inspection_errors", BCON_INT32(atomic_load_explicit(&zinst()->arp.arp_errors, memory_order_acquire)),
                "ip_guard_errors", BCON_INT32(atomic_load_explicit(&zinst()->arp.ip_errors, memory_order_acquire)),
                "sessions_count", BCON_INT64(atomic_load_explicit(&zinst()->sessions_cnt, memory_order_acquire)),
                "session_unauth_count", BCON_INT64(atomic_load_explicit(&zinst()->unauth_sessions_cnt, memory_order_acquire)),
                "clients_count", BCON_INT64(client_db_get_count(zinst()->client_db)),
            "}"
    );

    rc_send_bson(bev, bson);
    bson_destroy(bson);
}

/**
 * @param[in] bev bufferevent instance.
 * @param[in] doc Request document.
 * @param[in] cookie Unique request id.
 */
static void rc_process_reconfigure(struct bufferevent *bev, const bson_t *doc, int32_t cookie)
{
    bson_iter_t iter;
    struct zsrules rules;
    UT_string all_rules;

    utstring_init(&all_rules);
    utstring_reserve(&all_rules, 1024);
    srules_init(&rules);

    bson_iter_t child;
    if (!bson_iter_init_find(&iter, doc, "rules") ||
        !BSON_ITER_HOLDS_ARRAY(&iter) ||
        !bson_iter_recurse(&iter, &child)) {
        rc_send_ack(bev, "bad_packet", cookie);
        return;
    }

    bool parse_ok = true;
    while (bson_iter_next(&child)) {
        if (!BSON_ITER_HOLDS_UTF8(&child)) {
            continue;
        }
        uint32_t len = 0;
        char const *rule = bson_iter_utf8(&child, &len);
        if (0 != srules_parse(&rules, rule)) {
            parse_ok = false;
            break;
        }
        utstring_printf(&all_rules, " %s", rule);
    }

    if (parse_ok) {
        zero_apply_rules(&rules);
        rc_send_ack(bev, "success", cookie);
        zero_syslog(LOG_INFO, "Remote request[%s]: reconfigure (rules:%s)",
                    getpeerip(bufferevent_getfd(bev)), utstring_body(&all_rules));
    } else {
        rc_send_ack(bev, "bad_rule", cookie);
    }

    utstring_done(&all_rules);
    srules_free(&rules);
}

/**
 * @brief rc_process_monitor
 * @param[in] bev bufferevent instance.
 * @param[in] doc Request document.
 * @param[in] cookie Unique request id.
 */
static void rc_process_monitor(struct bufferevent *bev, const bson_t *doc, int32_t cookie)
{
    bson_iter_t iter;

    if (!bson_iter_init_find(&iter, doc, "filter") || !BSON_ITER_HOLDS_UTF8(&iter)) {
        rc_send_ack(bev, "bad_packet", cookie);
        return;
    }
    uint32_t len = 0;
    char const *filter = bson_iter_utf8(&iter, &len);
    struct zmonitor_conn *conn = zmonitor_conn_new(zcfg()->monitors_conn_bandwidth);

    if (0 == zmonitor_conn_set_filter(conn, filter)) {
        rc_send_ack(bev, "success", cookie);
        bufferevent_priority_set(bev, PRIO_LOW);
        zmonitor_conn_set_listener(conn, bev);
        zmonitor_conn_activate(conn, zinst()->monitor);
        zero_syslog(LOG_INFO, "Remote request[%s]: monitor traffic (filter: %s)",
                    getpeerip(bufferevent_getfd(bev)), filter);
    } else {
        rc_send_ack(bev, "bad_filter", cookie);
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
static void rc_process_dump_counters(struct bufferevent *bev, const bson_t *doc, int32_t cookie)
{
    (void) doc;
    rc_send_ack(bev, "success", cookie);
    zero_syslog(LOG_INFO, "Remote request: dump traffic counters");

    const char filename[] = "traff_counters.json";
    FILE *f = fopen(filename, "w+");
    if (!f) {
        ZERO_ELOG(LOG_ERR, "Failed to open %s for writing", filename);
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
 * @brief rc_process_command
 * @param bev
 * @param doc
 */
static void rc_process_command(struct bufferevent *bev, const bson_t *doc)
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

    ztime(true);
    zclock(true);

    if (0 == strncmp(action, "show_stats", len)) {
        rc_process_stats_show(bev, doc, cookie);
    } else if (0 == strncmp(action, "client_show", len)) {
        rc_process_client_show(bev, doc, cookie);
    } else if (0 == strncmp(action, "client_update", len)) {
        rc_process_client_update(bev, doc, cookie);
    } else if (0 == strncmp(action, "client_delete", len)) {
        rc_process_client_delete(bev, doc, cookie);
    } else if (0 == strncmp(action, "session_show", len)) {
        rc_process_session_show(bev, doc, cookie);
    } else if (0 == strncmp(action, "session_delete", len)) {
        rc_process_session_delete(bev, doc, cookie);
    } else if (0 == strncmp(action, "upstream_show", len)) {
        rc_process_upstream_show(bev, doc, cookie);
    } else if (0 == strncmp(action, "info_show", len)) {
        rc_process_info_show(bev, doc, cookie);
    } else if (0 == strncmp(action, "reconfigure", len)) {
        rc_process_reconfigure(bev, doc, cookie);
    } else if (0 == strncmp(action, "monitor", len)) {
        rc_process_monitor(bev, doc, cookie);
#ifndef NDEBUG
    } else if (0 == strncmp(action, "dump_counters", len)) {
        rc_process_dump_counters(bev, doc, cookie);
#endif
    } else {
        ZERO_LOG(LOG_WARNING, "RC: invalid bson action: %s", action);
        return;
    }
}

/**
 * @brief rc_bson_read
 * @param bev
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
        ZERO_LOG(LOG_WARNING, "RC: received malformed bson document");
        return;
    }

    rc_process_command(bev, &doc);
    evbuffer_drain(input, packet_len);
}
