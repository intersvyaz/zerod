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
static void sigint_cb(evutil_socket_t fd, short events, void *evbase)
{
    (void) fd;
    (void) events;
    (void) evbase;

    ZERO_LOG(LOG_INFO, "Caught SIGINT, terminating...");
    zero_instance_stop();
}

/**
* Master worker.
*/
void master_worker(void)
{
    struct event *sigint_ev;

    pthread_setname_np(pthread_self(), "zerod: master");

    if (0 != rc_listen()) {
        return;
    }

    // set SIGINT handler
    sigint_ev = evsignal_new(zinst()->master_event_base, SIGINT, sigint_cb, NULL);
    evsignal_add(sigint_ev, NULL);

    if (event_base_dispatch(zinst()->master_event_base) < 0) {
        ZERO_LOG(LOG_WARNING, "Master event loop finished with error");
    }

    event_free(sigint_ev);
}
