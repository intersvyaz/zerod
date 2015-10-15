#include <arpa/inet.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include "zero.h"
#include "rc-zrcp.h"
#include "rc-bson.h"
#include "log.h"

/**
 * Data available event for remote control connection.
 * @param[in] bev
 * @param[in] ctx Unused.
 */
static void rc_read_cb(struct bufferevent *bev, void *ctx)
{
    (void) ctx;

    struct evbuffer *input = bufferevent_get_input(bev);
    const uint16_t *magic;

    // wait for proto magic
    if (sizeof(*magic) > evbuffer_get_length(input)) {
        return;
    }

    magic = (uint16_t *) evbuffer_pullup(input, sizeof(*magic));

    if (htons(RC_ZRCP_MAGIC) == *magic) {
        rc_zrcp_read(bev);
    } else if (htons(RC_BSON_MAGIC) == *magic) {
        rc_bson_read(bev);
    } else {
        bufferevent_free(bev);
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
    (void) ctx;

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        if (events & ~BEV_EVENT_EOF) {
            ZERO_ELOG(LOG_DEBUG, "RC: connection error");
        }
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
static void rc_accept_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *sa, int socklen,
                         void *ctx)
{
    (void) listener;
    (void) sa;
    (void) socklen;
    (void) ctx;

    struct bufferevent *bev = bufferevent_socket_new(
            zinst()->master_event_base, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE
    );
    bufferevent_priority_set(bev, PRIO_HIGH);
    bufferevent_setcb(bev, rc_read_cb, NULL, rc_event_cb, NULL);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
}

/**
 * Accept error handler for incoming remote control connections.
 * @param[in] listener Unused.
 * @param[in] ctx Unused.
 */
static void rc_accept_error_cb(struct evconnlistener *listener, void *ctx)
{
    (void) listener;
    (void) ctx;

    int err = EVUTIL_SOCKET_ERROR();
    ZERO_LOG(LOG_ERR, "RC: listener accept error %d (%s)", err, evutil_socket_error_to_string(err));
    zero_instance_stop();
}

/**
 * Initialize remote control listener.
 * @return Zero on success.
 */
int rc_listen(void)
{
    struct sockaddr_in bind_sa;
    int bind_sa_len;

    memset(&bind_sa, 0, sizeof(bind_sa));
    bind_sa_len = sizeof(bind_sa);
    if (0 != evutil_parse_sockaddr_port(zcfg()->rc_listen_addr, (struct sockaddr *) &bind_sa, &bind_sa_len)) {
        ZERO_LOG(LOG_ERR, "failed to parse rc_listen_addr '%s'", zcfg()->rc_listen_addr);
        return -1;
    }
    bind_sa.sin_family = AF_INET;

    zinst()->rc_tcp_listener = evconnlistener_new_bind(zinst()->master_event_base,
                                                       rc_accept_cb, NULL, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
                                                       5, (struct sockaddr *) &bind_sa, sizeof(bind_sa));
    if (NULL == zinst()->rc_tcp_listener) {
        int err = EVUTIL_SOCKET_ERROR();
        ZERO_LOG(LOG_ERR, "failed to start listen on %s, last error: %s",
                 zcfg()->rc_listen_addr, evutil_socket_error_to_string(err));
        return -1;
    }

    evconnlistener_set_error_cb(zinst()->rc_tcp_listener, rc_accept_error_cb);

    return 0;
}
