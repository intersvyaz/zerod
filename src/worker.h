#ifndef ZEROD_WORKER_H
#define ZEROD_WORKER_H

#include <pthread.h>
#include "netdef.h"
#include "netmap.h"
#include "speed_meter.h"
#include "atomic.h"
#include "packet.h"

typedef struct zworker_stats_struct
{
    atomic_uint64_t count;
    speed_meter_t speed;
#ifdef ZEROD_PROFILE
    /*<<! average packet processing time (nanoseconds) */
    atomic_uint64_t avg_ppt;
#endif
} zworker_stats_t;

typedef struct zworker_struct
{
    pthread_t thread;
    u_int affinity;
    znetmap_iface_t *lan;
    znetmap_iface_t *wan;
    uint16_t ring_id;

    struct
    {
        zworker_stats_t packets[DIR_MAX][TRAFF_MAX][ACTION_MAX];
        zworker_stats_t traffic[DIR_MAX][TRAFF_MAX][ACTION_MAX];
    } stats;
} zworker_t;

zworker_t *zworker_new(znetmap_iface_t *lan, znetmap_iface_t *wan, uint16_t ring, uint16_t affinity);

void zworker_free(zworker_t *worker);

void *zworker_proc(void *arg);

#endif // ZEROD_WORKER_H
