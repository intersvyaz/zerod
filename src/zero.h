#ifndef ZEROD_ZERO_H
#define ZEROD_ZERO_H

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>
#include <uthash/utarray.h>

#include "speed_meter.h"
#include "token_bucket.h"
#include "netmap.h"
#include "util.h"
#include "netdef.h"
#include "client_rules.h"
#include "scope_rules.h"
#include "config.h"
#include "client.h"
#include "session.h"
#include "monitor.h"
#include "scope.h"

typedef enum zevent_prio_enum
{
    PRIO_HIGH,
    PRIO_LOW,
    PRIO_COUNT
} zevent_prio_t;

struct event_base;
struct evconnlistener;

typedef struct zoverlord_struct
{
    // thread index
    size_t idx;
    // thread handle
    pthread_t thread;
} zoverlord_t;

typedef struct zinstance_struct
{
    /*<<! configuration */
    const zconfig_t *cfg;

    /*<<! abort flag */
    atomic_bool abort;

    /*<<! start timestamp (microseconds) */
    uint64_t start_time;

    /*<<! master thread event base */
    struct event_base *master_event_base;
    /*<<! remote control tcp connection listener */
    struct evconnlistener *rc_tcp_listener;

    /*<<! hash of scopes (lookup by cfg->name) */
    zscope_t *scopes;

    /*<<! netmap interface handles (znetmap_iface_t * array) */
    UT_array interfaces;

    /*<<! overlord workers (zworker_t * array) */
    UT_array workers;

    /*<<! monitoring */
    zmonitor_t *monitor;

    zclient_rule_parser_t *client_rule_parser;

    // non-client info
    struct
    {
        token_bucket_t band[DIR_MAX];
        speed_meter_t speed[DIR_MAX];
    } non_client;

#ifndef NDEBUG
    struct
    {
        struct
        {
            /*<<! packets counter */
            atomic_uint64_t packets;
            /*<<! bytes counter */
            atomic_uint64_t bytes;
        } traff_counter[PROTO_MAX][ZL4_PORT_MAX];
    } dbg;
#endif
} zinstance_t;

// global app instance
extern zinstance_t g_zinst;

/**
* Global access to app instance.
* @return App instance.
*/
static inline zinstance_t *zinst(void)
{
    return &g_zinst;
}

/**
 * @return Abort flag.
 */
static inline bool zinstance_is_abort(void)
{
    return atomic_load_acquire(&g_zinst.abort);
}

bool zinstance_init(const zconfig_t *cfg);

void zinstance_run(void);

void zinstance_stop(void);

void zinstance_destroy(void);

zscope_t *zinstance_get_scope(const char *name);

// master.c
void master_worker(void);

// overlord.c
void *zoverlord_proc(void *arg);

// remotectl.c
bool zremotectl_listen(void);

#endif // ZEROD_ZERO_H
