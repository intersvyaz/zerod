#include <arpa/inet.h>
#include <stdio.h>

#include <event2/util.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <uthash/utstring.h>

#include "zero.h"
#include "zrc_proto.h"
#include "client.h"
#include "session.h"
#include "log.h"
#include "crules.h"
#include "srules.h"

/**
 * Send typed acknowledge.
 * @param bev
 * @param type
 */
static void rc_send_ack(struct bufferevent *bev, uint8_t type)
{
    struct zrc_header response;
    zrc_fill_header(&response);
    response.length = 0;
    response.type = type;
    bufferevent_write(bev, &response, sizeof(response));
}

/**
 * Show statistics command.
 * @param[in] bev
 */
static void rc_process_stats_show(struct bufferevent *bev)
{
    uint32_t data32;

    struct zrc_op_stats_show_resp response;

    struct evbuffer *buf = evbuffer_new();

    zrc_fill_header(&response.header);
    response.header.length = htonl(sizeof(response) - sizeof(response.header));
    response.header.type = ZOP_STATS_SHOW_RESP;

    data32 = __atomic_load_n(&zinst()->sessions_cnt, __ATOMIC_RELAXED);
    response.sess_count = htonl(data32);

    data32 = __atomic_load_n(&zinst()->clients_cnt, __ATOMIC_RELAXED);
    response.clients_count = htonl(data32);

    data32 = __atomic_load_n(&zinst()->unauth_sessions_cnt, __ATOMIC_RELAXED);
    response.unauth_sess_count = htonl(data32);

    response.non_client_bw_down = htonll(__atomic_load_n(&zinst()->non_client.bw_bucket[DIR_DOWN].max_tokens, __ATOMIC_RELAXED));
    response.non_client_bw_up = htonll(__atomic_load_n(&zinst()->non_client.bw_bucket[DIR_UP].max_tokens, __ATOMIC_RELAXED));
    response.non_client_speed_down = htonll(spdm_calc(&zinst()->non_client.speed[DIR_DOWN]));
    response.non_client_speed_up = htonll(spdm_calc(&zinst()->non_client.speed[DIR_UP]));


    response.rings_count = htons(utarray_len(&zinst()->rings));

    evbuffer_add(buf, &response, sizeof(response));

    for (size_t i = 0; i < utarray_len(&zinst()->rings); i++) {
        uint64_t data64;
        struct zring *ring = (struct zring *)utarray_eltptr(&zinst()->rings, i);
        struct zrc_ring_info info;

        strncpy(info.ifname_lan, ring->if_pair->lan, sizeof(info.ifname_lan));
        strncpy(info.ifname_wan, ring->if_pair->wan, sizeof(info.ifname_wan));
        info.ring_id = htons(ring->ring_id);

        info.packets.down.all.count = htonll(__atomic_load_n(&ring->packets[DIR_DOWN].all.count, __ATOMIC_RELAXED));
        info.packets.up.all.count = htonll(__atomic_load_n(&ring->packets[DIR_UP].all.count, __ATOMIC_RELAXED));
        info.packets.down.passed.count = htonll(__atomic_load_n(&ring->packets[DIR_DOWN].passed.count, __ATOMIC_RELAXED));
        info.packets.up.passed.count = htonll(__atomic_load_n(&ring->packets[DIR_UP].passed.count, __ATOMIC_RELAXED));

        data64 = spdm_calc(&ring->packets[DIR_DOWN].all.speed);
        info.packets.down.all.speed = htonll(data64);

        data64 = spdm_calc(&ring->packets[DIR_UP].all.speed);
        info.packets.up.all.speed = htonll(data64);

        data64 = spdm_calc(&ring->packets[DIR_DOWN].passed.speed);
        info.packets.down.passed.speed = htonll(data64);

        data64 = spdm_calc(&ring->packets[DIR_UP].passed.speed);
        info.packets.up.passed.speed = htonll(data64);

        info.traffic.down.all.count = htonll(__atomic_load_n(&ring->traffic[DIR_DOWN].all.count, __ATOMIC_RELAXED));
        info.traffic.up.all.count = htonll(__atomic_load_n(&ring->traffic[DIR_UP].all.count, __ATOMIC_RELAXED));
        info.traffic.down.passed.count = htonll(__atomic_load_n(&ring->traffic[DIR_DOWN].passed.count, __ATOMIC_RELAXED));
        info.traffic.up.passed.count = htonll(__atomic_load_n(&ring->traffic[DIR_UP].passed.count, __ATOMIC_RELAXED));

        data64 = spdm_calc(&ring->traffic[DIR_DOWN].all.speed);
        info.traffic.down.all.speed = htonll(data64);

        data64 = spdm_calc(&ring->traffic[DIR_UP].all.speed);
        info.traffic.up.all.speed = htonll(data64);

        data64 = spdm_calc(&ring->traffic[DIR_DOWN].passed.speed);
        info.traffic.down.passed.speed = htonll(data64);

        data64 = spdm_calc(&ring->traffic[DIR_UP].passed.speed);
        info.traffic.up.passed.speed = htonll(data64);

        evbuffer_add(buf, &info, sizeof(info));
    }

    struct zrc_header *hdr = (struct zrc_header *)evbuffer_pullup(buf, sizeof(*hdr));
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
        rc_send_ack(bev, ZOP_NOT_FOUND);
        return;
    }

    struct evbuffer *buf = evbuffer_new();

    struct zrc_header header;
    zrc_fill_header(&header);
    header.length = 0;
    header.type = ZOP_CLIENT_SHOW_RESP;
    evbuffer_add(buf, &header, sizeof(header));

    UT_string rules;
    utstring_init(&rules);
    utstring_reserve(&rules, 1024);
    client_dump_rules(client, &rules);
    evbuffer_add(buf, utstring_body(&rules), utstring_len(&rules));
    utstring_done(&rules);

    struct zrc_header *hdr = (struct zrc_header *)evbuffer_pullup(buf, sizeof(*hdr));
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
        rc_send_ack(bev, ZOP_NOT_FOUND);
        return;
    }

    UT_string all_rules;
    struct zcrules rules;
    crules_init(&rules);
    utstring_init(&all_rules);
    utstring_reserve(&all_rules, 1024);

    const char *packet_end = (const char *)(&req_packet->header + 1) + ntohl(req_packet->header.length);
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
        rc_send_ack(bev, ZOP_OK);

        // log client update
        if (req_packet->ip_flag)
            zero_syslog(LOG_INFO, "Remote request: update session_ip=%s (rules:%s)", ipv4_to_str(htonl(session->ip)), utstring_body(&all_rules));
        else
            zero_syslog(LOG_INFO, "Remote request: update client_id=%u (rules:%s)", client->id, utstring_body(&all_rules));
    } else {
        rc_send_ack(bev, ZOP_BAD_RULE);
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
    struct zrc_op_session_show_resp response;
    bzero(&response, sizeof(response));

    uint32_t ip = ntohl(req_packet->session_ip);
    struct zsession *sess = session_acquire(ip, true);
    if (NULL != sess) {
        struct zrc_op_session_show_resp response;
        zrc_fill_header(&response.header);
        response.header.length = htonl(sizeof(response) - sizeof(response.header));
        response.header.type = ZOP_SESSION_SHOW_RESP;
        pthread_rwlock_rdlock(&sess->lock_client);
        response.user_id = htonl(sess->client->id);
        pthread_rwlock_unlock(&sess->lock_client);
        response.last_seen = htonl(__atomic_load_n(&sess->last_activity, __ATOMIC_RELAXED) / 1000000);
        response.last_acct = htonl(__atomic_load_n(&sess->last_acct, __ATOMIC_RELAXED) / 1000000);
        response.last_auth = htonl(__atomic_load_n(&sess->last_auth, __ATOMIC_RELAXED) / 1000000);
        response.traff_down = htonll(__atomic_load_n(&sess->traff_down, __ATOMIC_RELAXED));
        response.traff_up = htonll(__atomic_load_n(&sess->traff_up, __ATOMIC_RELAXED));
        session_release(sess);
        bufferevent_write(bev, &response, sizeof(response));
    } else {
        rc_send_ack(bev, ZOP_NOT_FOUND);
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
        zero_syslog(LOG_INFO, "Remote request: remove session %s", ipv4_to_str(htonl(sess->ip)));
        // mark session for deletion
        __atomic_store_n(&sess->delete_flag, 1, __ATOMIC_RELAXED);
        session_release(sess);
        rc_send_ack(bev, ZOP_OK);
    } else {
        rc_send_ack(bev, ZOP_NOT_FOUND);
    }
}

/**
 * Show upstream info.
 * @param bev
 */
static void rc_process_upstream_show(struct bufferevent *bev)
{
    struct evbuffer *buf = evbuffer_new();

    struct zrc_op_upstream_show_resp response;
    zrc_fill_header(&response.header);
    response.header.type = ZOP_UPSTREAM_SHOW_RESP;
    response.count = htons(ZUPSTREAM_MAX);

    evbuffer_add(buf, &response, sizeof(response));

    for (uint16_t i = 0; i < ZUPSTREAM_MAX; i++) {
        struct zrc_upstream_info upstream;
        upstream.speed_down = htonll(spdm_calc(&zinst()->upstreams[i].speed[DIR_DOWN]));
        upstream.speed_up = htonll(spdm_calc(&zinst()->upstreams[i].speed[DIR_UP]));
        upstream.p2p_bw_limit_down = htonll(__atomic_load_n(&zinst()->upstreams[i].p2p_bw_bucket[DIR_DOWN].max_tokens, __ATOMIC_RELAXED));
        upstream.p2p_bw_limit_up = htonll(__atomic_load_n(&zinst()->upstreams[i].p2p_bw_bucket[DIR_UP].max_tokens, __ATOMIC_RELAXED));
        evbuffer_add(buf, &upstream, sizeof(upstream));
    }

    struct zrc_header *hdr = (struct zrc_header *)evbuffer_pullup(buf, sizeof(*hdr));
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
        rc_send_ack(bev, ZOP_OK);
        zero_syslog(LOG_INFO, "Remote request: reconfigure (rules:%s)", utstring_body(&all_rules));
    } else {
        rc_send_ack(bev, ZOP_BAD_RULE);
    }

    utstring_done(&all_rules);
    srules_free(&rules);
}

/**
 * Process remote control command.
 * @param[in] bev Bufferevent of current connection.
 * @param[in] data Command data.
 */
static void rc_process_command(struct bufferevent *bev, const unsigned char *data)
{
    const struct zrc_header *hdr = (struct zrc_header *)data;

    ztime(true);

    switch (hdr->type) {
    case ZOP_STATS_SHOW:
        rc_process_stats_show(bev);
        break;

    case ZOP_CLIENT_SHOW:
        rc_process_client_show(bev, (const struct zrc_op_client_show *)data);
        break;

    case ZOP_CLIENT_UPDATE:
        rc_process_client_update(bev, (const struct zrc_op_client_update *)data);
        break;

    case ZOP_SESSION_SHOW:
        rc_process_session_show(bev, (const struct zrc_op_session_show *)data);
        break;

    case ZOP_SESSION_DELETE:
        rc_process_session_delete(bev, (const struct zrc_op_session_delete *)data);
        break;

    case ZOP_UPSTREAM_SHOW:
        rc_process_upstream_show(bev);
        break;

    case ZOP_RECONFIGURE:
        rc_process_reconfigure(bev, (const struct zrc_op_reconfigure *)data);
        break;

    default:
        ZERO_LOG(LOG_WARNING, "RC: Invalid command (type=0x%X)", hdr->type);
    }
}

/**
 * Data available event for remote control connection.
 * @param[in] bev
 * @param[in] ctx Unused.
 */
static void rc_read_cb(struct bufferevent *bev, void *ctx)
{
    (void)ctx;

    struct evbuffer *input = bufferevent_get_input(bev);
    size_t src_len = evbuffer_get_length(input);

    // wait for full packet header
    if (sizeof(struct zrc_header) > src_len)
        return;

    struct zrc_header *packet = (struct zrc_header *)evbuffer_pullup(input, sizeof(*packet));

    if (htons(ZRC_PROTO_MAGIC) != packet->magic) {
        bufferevent_free(bev);
        return;
    }
    if (ZRC_PROTO_VERSION != packet->version) {
        rc_send_ack(bev, ZOP_INVALID_VERSION);
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

/**
 * Event handler for remote control connection.
 * @param[in] bev
 * @param[in] events
 * @param[in] ctx Unused.
 */
static void rc_event_cb(struct bufferevent *bev, short events, void *ctx)
{
    (void)ctx;

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR) ) {
        if (events & ~BEV_EVENT_EOF)
            ZERO_ELOG(LOG_DEBUG, "RC: connection error");
        bufferevent_free(bev);
    }
}

/**
 * Accept incoming remote control connection.
 * @param[in] listener Unused.
 * @param[in] fd Socket descriptor.
 * @param[in] sa Unused.
 * @param[in] socklen Unused.
 * @param[in] ctx Unused.
 */
static void rc_accept_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *sa, int socklen, void *ctx)
{
    (void)listener;
    (void)sa;
    (void)socklen;
    (void)ctx;

    struct bufferevent *bev = bufferevent_socket_new(
        zinst()->master_event_base, fd, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_THREADSAFE
    );
    bufferevent_setcb(bev, rc_read_cb, NULL, rc_event_cb, NULL);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
}

/**
 * Accept error handler for incoming remote control connections.
 * @param[in] listener Unused.
 * @param[in] ctx Unused.
 */
static void rc_accept_error_cb(struct evconnlistener *listener, void *ctx)
{
    (void)listener;
    (void)ctx;

    int err = EVUTIL_SOCKET_ERROR();
    ZERO_LOG(LOG_ERR, "RC: listener accept error %d (%s)", err, evutil_socket_error_to_string(err));
    zero_instance_stop();
}

/**
 * Initialize remote control listener.
 * @return Zero on success.
 */
int rc_listen()
{
    struct sockaddr_in bind_sa;
    int bind_sa_len;

    bzero(&bind_sa, sizeof(bind_sa));
    bind_sa_len = sizeof(bind_sa);
    if (0 != evutil_parse_sockaddr_port(zcfg()->rc_listen_addr, (struct sockaddr*)&bind_sa, &bind_sa_len)) {
        ZERO_LOG(LOG_ERR, "failed to parse rc_listen_addr '%s'", zcfg()->rc_listen_addr);
        return -1;
    }
    bind_sa.sin_family = AF_INET;

    zinst()->rc_tcp_listener = evconnlistener_new_bind(zinst()->master_event_base,
            rc_accept_cb, NULL, LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE,
            5, (struct sockaddr*)&bind_sa, sizeof(bind_sa));
    if (NULL == zinst()->rc_tcp_listener) {
        int err = EVUTIL_SOCKET_ERROR();
        ZERO_LOG(LOG_ERR, "failed to start listen on %s, last error: %s", zcfg()->rc_listen_addr, evutil_socket_error_to_string(err));
        return -1;
    }

    evconnlistener_set_error_cb(zinst()->rc_tcp_listener, rc_accept_error_cb);

    return 0;
}
