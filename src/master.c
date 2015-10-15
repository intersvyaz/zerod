#include <signal.h>
#include <pthread.h>
#include <event2/event.h>
#include "zero.h"
#include "log.h"
#include "blacklist.h"

/**
 * SIGINT handler.
 * @param[in] fd Unused.
 * @param[in] events Unused.
 * @param[in] evbase Unused.
 */
static void sigint_cb(evutil_socket_t fd, short events, void *evbase)
{
    (void) fd;
    (void) events;
    (void) evbase;

    ZERO_LOG(LOG_INFO, "Caught SIGINT, terminating...");
    zero_instance_stop();
}

static void blacklist_reload_cb(evutil_socket_t fd, short events, void *evbase)
{
    (void) fd;
    (void) events;
    (void) evbase;

    zblacklist_reload(zinst()->blacklist, zcfg()->blacklist_file);
}

/**
 * Master worker.
 */
void master_worker(void)
{
    struct event *sigint_ev = NULL, *blacklist_ev = NULL;

    pthread_setname_np(pthread_self(), "zerod: master");

    if (0 != rc_listen()) {
        return;
    }

    // set SIGINT handler
    sigint_ev = evsignal_new(zinst()->master_event_base, SIGINT, sigint_cb, NULL);
    if (!sigint_ev) {
        ZERO_LOG(LOG_ERR, "Failed to create SIGINT event handler");
        return;
    }
    evsignal_add(sigint_ev, NULL);

    // blacklist reload handler
    if (zinst()->blacklist && zcfg()->blacklist_reload_interval) {
        struct timeval tv = {USEC2SEC(zcfg()->blacklist_reload_interval), 0};
        blacklist_ev = event_new(zinst()->master_event_base, -1, EV_PERSIST, blacklist_reload_cb, NULL);
        if (!blacklist_ev) {
            ZERO_LOG(LOG_ERR, "Failed to create backlist reload event handler");
            return;
        }
        event_add(blacklist_ev, &tv);
    }

    if (event_base_dispatch(zinst()->master_event_base) < 0) {
        ZERO_LOG(LOG_WARNING, "Master event loop finished with error");
    }

    event_free(sigint_ev);
    if (blacklist_ev) {
        event_free(blacklist_ev);
    }
}
