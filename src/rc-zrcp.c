#include "rc-zrcp.h"

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "zero.h"
#include "util.h"
#include "log.h"
#include "zrcp.h"
#include "session.h"
#include "client.h"
#include "crules.h"
#include "srules.h"
#include "monitor.h"


/**
* Send typed acknowledge.
* @param[in] bev
* @param[in] type
* @param[in] cookie
*/
static void rc_send_ack(struct bufferevent *bev, uint8_t type, uint32_t cookie)
{
    struct zrc_header response;
    zrc_fill_header(&response);
    response.length = 0;
    response.type = type;
    response.cookie = cookie;
    bufferevent_write(bev, &response, sizeof(response));
}

/**
* Show statistics command.
* @param[in] bev
*/
static void rc_process_stats_show(struct bufferevent *bev, const struct zrc_header *req_packet)
{
    uint32_t data32;

    struct zrc_op_stats_show_resp response;

    struct evbuffer *buf = evbuffer_new();

    zrc_fill_header(&response.header);
    response.header.length = htonl(sizeof(response) - sizeof(response.header));
    response.header.type = ZOP_STATS_SHOW_RESP;
    response.header.cookie = req_packet->cookie;

    data32 = atomic_load_explicit(&zinst()->sessions_cnt, memory_order_relaxed);
    response.sess_count = htonl(data32);

    data32 = atomic_load_explicit(&zinst()->clients_cnt, memory_order_relaxed);
    response.clients_count = htonl(data32);

    data32 = atomic_load_explicit(&zinst()->unauth_sessions_cnt, memory_order_relaxed);
    response.unauth_sess_count = htonl(data32);

    response.non_client_bw_down = htonll(atomic_load_explicit(&zinst()->non_client.bw_bucket[DIR_DOWN].max_tokens, memory_order_relaxed));
    response.non_client_bw_up = htonll(atomic_load_explicit(&zinst()->non_client.bw_bucket[DIR_UP].max_tokens, memory_order_relaxed));
    response.non_client_speed_down = htonll(spdm_calc(&zinst()->non_client.speed[DIR_DOWN]));
    response.non_client_speed_up = htonll(spdm_calc(&zinst()->non_client.speed[DIR_UP]));


    response.rings_count = htons(utarray_len(&zinst()->rings));

    evbuffer_add(buf, &response, sizeof(response));

    for (size_t i = 0; i < utarray_len(&zinst()->rings); i++) {
        uint64_t data64;
        struct zring *ring = (struct zring *) utarray_eltptr(&zinst()->rings, i);
        struct zrc_ring_info info;

        strncpy(info.ifname_lan, ring->if_pair->lan, sizeof(info.ifname_lan));
        strncpy(info.ifname_wan, ring->if_pair->wan, sizeof(info.ifname_wan));
        info.ring_id = htons(ring->ring_id);

        info.packets.down.all.count = htonll(atomic_load_explicit(&ring->packets[DIR_DOWN].all.count, memory_order_relaxed));
        info.packets.up.all.count = htonll(atomic_load_explicit(&ring->packets[DIR_UP].all.count, memory_order_relaxed));
        info.packets.down.passed.count = htonll(atomic_load_explicit(&ring->packets[DIR_DOWN].passed.count, memory_order_relaxed));
        info.packets.up.passed.count = htonll(atomic_load_explicit(&ring->packets[DIR_UP].passed.count, memory_order_relaxed));
        info.packets.down.client.count = htonll(atomic_load_explicit(&ring->packets[DIR_DOWN].client.count, memory_order_relaxed));
        info.packets.up.client.count = htonll(atomic_load_explicit(&ring->packets[DIR_UP].client.count, memory_order_relaxed));

        data64 = spdm_calc(&ring->packets[DIR_DOWN].all.speed);
        info.packets.down.all.speed = htonll(data64);

        data64 = spdm_calc(&ring->packets[DIR_UP].all.speed);
        info.packets.up.all.speed = htonll(data64);

        data64 = spdm_calc(&ring->packets[DIR_DOWN].passed.speed);
        info.packets.down.passed.speed = htonll(data64);

        data64 = spdm_calc(&ring->packets[DIR_UP].passed.speed);
        info.packets.up.passed.speed = htonll(data64);

        data64 = spdm_calc(&ring->packets[DIR_DOWN].client.speed);
        info.packets.down.client.speed = htonll(data64);

        data64 = spdm_calc(&ring->packets[DIR_UP].client.speed);
        info.packets.up.client.speed = htonll(data64);

        info.traffic.down.all.count = htonll(atomic_load_explicit(&ring->traffic[DIR_DOWN].all.count, memory_order_relaxed));
        info.traffic.up.all.count = htonll(atomic_load_explicit(&ring->traffic[DIR_UP].all.count, memory_order_relaxed));
        info.traffic.down.passed.count = htonll(atomic_load_explicit(&ring->traffic[DIR_DOWN].passed.count, memory_order_relaxed));
        info.traffic.up.passed.count = htonll(atomic_load_explicit(&ring->traffic[DIR_UP].passed.count, memory_order_relaxed));
        info.traffic.down.client.count = htonll(atomic_load_explicit(&ring->traffic[DIR_DOWN].client.count, memory_order_relaxed));
        info.traffic.up.client.count = htonll(atomic_load_explicit(&ring->traffic[DIR_UP].client.count, memory_order_relaxed));

        data64 = spdm_calc(&ring->traffic[DIR_DOWN].all.speed);
        info.traffic.down.all.speed = htonll(data64);

        data64 = spdm_calc(&ring->traffic[DIR_UP].all.speed);
        info.traffic.up.all.speed = htonll(data64);

        data64 = spdm_calc(&ring->traffic[DIR_DOWN].passed.speed);
        info.traffic.down.passed.speed = htonll(data64);

        data64 = spdm_calc(&ring->traffic[DIR_UP].passed.speed);
        info.traffic.up.passed.speed = htonll(data64);

        data64 = spdm_calc(&ring->traffic[DIR_DOWN].client.speed);
        info.traffic.down.client.speed = htonll(data64);

        data64 = spdm_calc(&ring->traffic[DIR_UP].client.speed);
        info.traffic.up.client.speed = htonll(data64);

        evbuffer_add(buf, &info, sizeof(info));
    }

    struct zrc_header *hdr = (struct zrc_header *) evbuffer_pullup(buf, sizeof(*hdr));
    hdr->length = htonl(evbuffer_get_length(buf) - sizeof(*hdr));

    bufferevent_write_buffer(bev, buf);
    evbuffer_free(buf);
}

/**
* Show client info command.
* @param[in] bev
* @param[in] req_packet
*/
static void rc_process_client_show(struct bufferevent *bev, const struct zrc_op_client_show *req_packet)
{
    struct zclient *client = NULL;
    struct zsession *session = NULL;

    if (req_packet->ip_flag) {
        session = session_acquire(ntohl(req_packet->ip), true);
        if (NULL != session) {
            pthread_rwlock_rdlock(&session->lock_client);
            client = session->client;
        }
    } else {
        client = client_acquire(ntohl(req_packet->user_id));
    }

    if (NULL == client) {
        rc_send_ack(bev, ZOP_NOT_FOUND, req_packet->header.cookie);
        return;
    }

    struct evbuffer *buf = evbuffer_new();

    struct zrc_header header;
    zrc_fill_header(&header);
    header.length = 0;
    header.type = ZOP_CLIENT_SHOW_RESP;
    header.cookie = req_packet->header.cookie;
    evbuffer_add(buf, &header, sizeof(header));

    UT_string rules;
    utstring_init(&rules);
    utstring_reserve(&rules, 1024);
    client_dump_rules(client, &rules);
    evbuffer_add(buf, utstring_body(&rules), utstring_len(&rules));
    utstring_done(&rules);

    struct zrc_header *hdr = (struct zrc_header *) evbuffer_pullup(buf, sizeof(*hdr));
    hdr->length = htonl(evbuffer_get_length(buf) - sizeof(*hdr));
    bufferevent_write_buffer(bev, buf);

    evbuffer_free(buf);

    if (req_packet->ip_flag) {
        pthread_rwlock_unlock(&session->lock_client);
        session_release(session);
    } else {
        client_release(client);
    }
}

/**
* Update client command.
* @param[in] bev
* @param[in] req_packet
*/
static void rc_process_client_update(struct bufferevent *bev, const struct zrc_op_client_update *req_packet)
{
    struct zclient *client = NULL;
    struct zsession *session = NULL;

    if (req_packet->ip_flag) {
        session = session_acquire(ntohl(req_packet->ip), true);
        if (NULL != session) {
            pthread_rwlock_rdlock(&session->lock_client);
            client = session->client;
        }
    } else {
        client = client_acquire(ntohl(req_packet->user_id));
    }

    if (NULL == client) {
        rc_send_ack(bev, ZOP_NOT_FOUND, req_packet->header.cookie);
        return;
    }

    UT_string all_rules;
    struct zcrules rules;
    crules_init(&rules);
    utstring_init(&all_rules);
    utstring_reserve(&all_rules, 1024);

    const char *packet_end = (const char *) (&req_packet->header + 1) + ntohl(req_packet->header.length);
    const char *rule = req_packet->data;
    bool parse_ok = true;

    while (rule < packet_end) {
        if (0 != crules_parse(&rules, rule)) {
            parse_ok = false;
            break;
        }
        utstring_printf(&all_rules, " %s", rule);
        rule += strlen(rule) + 1;
    }

    if (parse_ok) {
        client_apply_rules(client, &rules);
        rc_send_ack(bev, ZOP_OK, req_packet->header.cookie);

        // log client update
        if (req_packet->ip_flag)
            zero_syslog(LOG_INFO, "Remote request[%s]: update session_ip=%s (rules:%s)", getpeerip(bufferevent_getfd(bev)), ipv4_to_str(htonl(session->ip)), utstring_body(&all_rules));
        else
            zero_syslog(LOG_INFO, "Remote request[%s]: update client_id=%u (rules:%s)", getpeerip(bufferevent_getfd(bev)), client->id, utstring_body(&all_rules));
    } else {
        rc_send_ack(bev, ZOP_BAD_RULE, req_packet->header.cookie);
    }

    if (req_packet->ip_flag) {
        pthread_rwlock_unlock(&session->lock_client);
        session_release(session);
    } else {
        client_release(client);
    }

    utstring_done(&all_rules);
    crules_free(&rules);
}

/**
* Show sesion command.
* @param[in] bev
* @param[in] req_packet
*/
static void rc_process_session_show(struct bufferevent *bev, const struct zrc_op_session_show *req_packet)
{
    uint32_t ip = ntohl(req_packet->session_ip);
    struct zsession *sess = session_acquire(ip, true);
    if (NULL != sess) {
        struct zrc_op_session_show_resp response;
        zrc_fill_header(&response.header);
        response.header.length = htonl(sizeof(response) - sizeof(response.header));
        response.header.type = ZOP_SESSION_SHOW_RESP;
        response.header.cookie = req_packet->header.cookie;
        pthread_rwlock_rdlock(&sess->lock_client);
        response.user_id = htonl(sess->client->id);
        pthread_rwlock_unlock(&sess->lock_client);
        response.last_seen = htonl(atomic_load_explicit(&sess->last_activity, memory_order_relaxed) / 1000000);
        response.last_acct = htonl(atomic_load_explicit(&sess->last_acct, memory_order_relaxed) / 1000000);
        response.last_auth = htonl(atomic_load_explicit(&sess->last_auth, memory_order_relaxed) / 1000000);
        response.traff_down = htonll(atomic_load_explicit(&sess->traff_down, memory_order_relaxed));
        response.traff_up = htonll(atomic_load_explicit(&sess->traff_up, memory_order_relaxed));
        session_release(sess);
        bufferevent_write(bev, &response, sizeof(response));
    } else {
        rc_send_ack(bev, ZOP_NOT_FOUND, req_packet->header.cookie);
    }
}

/**
* Delete session command.
* @param[in] bev
* @param[in] req_packet
*/
static void rc_process_session_delete(struct bufferevent *bev, const struct zrc_op_session_delete *req_packet)
{
    uint32_t ip = ntohl(req_packet->session_ip);
    struct zsession *sess = session_acquire(ip, true);
    if (NULL != sess) {
        zero_syslog(LOG_INFO, "Remote request[%s]: remove session %s", getpeerip(bufferevent_getfd(bev)), ipv4_to_str(htonl(sess->ip)));
        // mark session for deletion
        atomic_store_explicit(&sess->delete_flag, true, memory_order_relaxed);
        session_release(sess);
        rc_send_ack(bev, ZOP_OK, req_packet->header.cookie);
    } else {
        rc_send_ack(bev, ZOP_NOT_FOUND, req_packet->header.cookie);
    }
}

/**
* Show upstream info.
* @param bev
*/
static void rc_process_upstream_show(struct bufferevent *bev, const struct zrc_header *req_packet)
{
    struct evbuffer *buf = evbuffer_new();

    struct zrc_op_upstream_show_resp response;
    zrc_fill_header(&response.header);
    response.header.type = ZOP_UPSTREAM_SHOW_RESP;
    response.header.cookie = req_packet->cookie;
    response.count = htons(UPSTREAM_MAX);

    evbuffer_add(buf, &response, sizeof(response));

    for (uint16_t i = 0; i < UPSTREAM_MAX; i++) {
        struct zrc_upstream_info upstream;
        upstream.speed_down = htonll(spdm_calc(&zinst()->upstreams[i].speed[DIR_DOWN]));
        upstream.speed_up = htonll(spdm_calc(&zinst()->upstreams[i].speed[DIR_UP]));
        upstream.p2p_bw_limit_down = htonll(atomic_load_explicit(&zinst()->upstreams[i].p2p_bw_bucket[DIR_DOWN].max_tokens, memory_order_relaxed));
        upstream.p2p_bw_limit_up = htonll(atomic_load_explicit(&zinst()->upstreams[i].p2p_bw_bucket[DIR_UP].max_tokens, memory_order_relaxed));
        evbuffer_add(buf, &upstream, sizeof(upstream));
    }

    struct zrc_header *hdr = (struct zrc_header *) evbuffer_pullup(buf, sizeof(*hdr));
    hdr->length = htonl(evbuffer_get_length(buf) - sizeof(*hdr));

    bufferevent_write_buffer(bev, buf);
    evbuffer_free(buf);
}

/**
* Update client command.
* @param[in] bev
* @param[in] req_packet
*/
static void rc_process_reconfigure(struct bufferevent *bev, const struct zrc_op_reconfigure *req_packet)
{
    UT_string all_rules;
    struct zsrules rules;
    srules_init(&rules);
    utstring_init(&all_rules);
    utstring_reserve(&all_rules, 1024);

    const char *packet_end = req_packet->data + ntohl(req_packet->header.length);
    const char *rule = req_packet->data;
    bool parse_ok = true;

    while (rule < packet_end) {
        if (0 != srules_parse(&rules, rule)) {
            parse_ok = false;
            break;
        }
        utstring_printf(&all_rules, " %s", rule);
        rule += strlen(rule) + 1;
    }

    if (parse_ok) {
        zero_apply_rules(&rules);
        rc_send_ack(bev, ZOP_OK, req_packet->header.cookie);
        zero_syslog(LOG_INFO, "Remote request[%s]: reconfigure (rules:%s)", getpeerip(bufferevent_getfd(bev)), utstring_body(&all_rules));
    } else {
        rc_send_ack(bev, ZOP_BAD_RULE, req_packet->header.cookie);
    }

    utstring_done(&all_rules);
    srules_free(&rules);
}

/**
* Update client command.
* @param[in] bev
* @param[in] req_packet
*/
static void rc_process_monitor(struct bufferevent *bev, const struct zrc_op_monitor *req_packet)
{
    struct monitor *mon = monitor_new();

    if (('\0' == req_packet->filter[0]) || (0 == monitor_set_filter(mon, req_packet->filter))) {
        rc_send_ack(bev, ZOP_OK, req_packet->header.cookie);
        monitor_set_listener(mon, bev);
        monitor_activate(mon);
        zero_syslog(LOG_INFO, "Remote request[%s]: monitor traffic (filter: %s)", getpeerip(bufferevent_getfd(bev)), req_packet->filter);
    } else {
        rc_send_ack(bev, ZOP_BAD_FILTER, req_packet->header.cookie);
        monitor_free(mon);
    }
}

#ifndef NDEBUG
/**
* Dump counters command.
* @param[in] bev
* @param[in] req_packet
*/
static void rc_process_dump_counters(struct bufferevent *bev, const struct zrc_header *req_packet)
{
    rc_send_ack(bev, ZOP_OK, req_packet->cookie);
    zero_syslog(LOG_INFO, "Remote request: dump traffic counters");

    const char filename[] = "traff_counters.json";
    FILE *f = fopen(filename, "w+");
    if (!f) {
        ZERO_ELOG(LOG_ERR, "Failed to open %s for writing", filename);
        return;
    }

    fprintf(f, "{\n");

    for(int proto = PROTO_TCP; proto < PROTO_MAX; proto++) {
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
* Process remote control command.
* @param[in] bev Bufferevent of current connection.
* @param[in] data Command data.
*/
static void rc_process_command(struct bufferevent *bev, const unsigned char *data)
{
    const struct zrc_header *hdr = (struct zrc_header *) data;

    ztime(true);
    zclock(true);

    switch (hdr->type) {
        case ZOP_STATS_SHOW:
            rc_process_stats_show(bev, (const struct zrc_header *) data);
            break;

        case ZOP_CLIENT_SHOW:
            rc_process_client_show(bev, (const struct zrc_op_client_show *) data);
            break;

        case ZOP_CLIENT_UPDATE:
            rc_process_client_update(bev, (const struct zrc_op_client_update *) data);
            break;

        case ZOP_SESSION_SHOW:
            rc_process_session_show(bev, (const struct zrc_op_session_show *) data);
            break;

        case ZOP_SESSION_DELETE:
            rc_process_session_delete(bev, (const struct zrc_op_session_delete *) data);
            break;

        case ZOP_UPSTREAM_SHOW:
            rc_process_upstream_show(bev, (const struct zrc_header *) data);
            break;

        case ZOP_RECONFIGURE:
            rc_process_reconfigure(bev, (const struct zrc_op_reconfigure *) data);
            break;

        case ZOP_MONITOR:
            rc_process_monitor(bev, (const struct zrc_op_monitor *) data);
            break;

#ifndef NDEBUG
        case ZOP_DUMP_COUNTERS:
            rc_process_dump_counters(bev, (const struct zrc_header *) data);
            break;
#endif

        default:
            ZERO_LOG(LOG_WARNING, "RC: Invalid command (type=0x%X)", hdr->type);
    }
}

/**
 * @brief rc_zrcp_read
 * @param bev
 */
void rc_zrcp_read(struct bufferevent *bev)
{
    struct evbuffer *input = bufferevent_get_input(bev);

    size_t src_len = evbuffer_get_length(input);

    // wait for full packet header
    if (sizeof(struct zrc_header) > src_len) {
        return;
    }

    struct zrc_header *packet = (struct zrc_header *) evbuffer_pullup(input, sizeof(*packet));

    if (ZRCP_VERSION != packet->version) {
        rc_send_ack(bev, ZOP_INVALID_VERSION, 0);
        bufferevent_free(bev);
        return;
    }

    size_t full_len = sizeof(*packet) + ntohl(packet->length);
    if (full_len >= src_len) {
        const unsigned char *data = evbuffer_pullup(input, full_len);
        rc_process_command(bev, data);
        evbuffer_drain(input, full_len);
    }
}
