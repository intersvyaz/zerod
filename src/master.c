#include <signal.h>
#include <pthread.h>
#include <event2/event.h>

#include "zero.h"
#include "log.h"

/**
 * SIGINT handler.
 * @param[in] fd Unused.
 * @param[in] events Unused.
 * @param[in] evbase Unused.
 */
static void sigint_cb(evutil_socket_t fd, short events, void *arg)
{
    (void) fd;
    (void) events;
    (void) arg;

    ZLOG(LOG_INFO, "Caught SIGINT, terminating...");
    zinstance_stop();
}

/**
 * Master worker.
 */
void master_worker(void)
{
    struct event *sigint_ev = NULL;

    pthread_setname_np(pthread_self(), "zerod: master");

    if (!zremotectl_listen()) {
        return;
    }

    // set SIGINT handler
    sigint_ev = evsignal_new(zinst()->master_event_base, SIGINT, sigint_cb, NULL);
    if (!sigint_ev) {
        ZLOG(LOG_ERR, "Failed to create SIGINT event handler");
        return;
    }
    evsignal_add(sigint_ev, NULL);

    if (event_base_dispatch(zinst()->master_event_base) < 0) {
        ZLOG(LOG_WARNING, "Master event loop finished with error");
    }

    event_free(sigint_ev);
}
