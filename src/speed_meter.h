#ifndef ZEROD_SPEED_METER_H
#define ZEROD_SPEED_METER_H

#include <pthread.h>
#include "atomic.h"
#include "util_time.h"

#define SPEED_METER_ATOMIC
#define SPEED_METER_BACKLOG 5u

typedef struct speed_meter_struct
{
#ifndef SPEED_METER_ATOMIC
    pthread_spinlock_t lock;
    size_t i;
    struct
    {
        uint64_t speed;
        zclock_t timestamp;
    } backlog[SPEED_METER_BACKLOG];
    uint64_t speed_aux;
    zclock_t last_update;
#else
    // current index
    atomic_size_t i;
    // calculated speed backlog
    struct
    {
        atomic_uint64_t speed;
        atomic_zclock_t timestamp;
    } backlog[SPEED_METER_BACKLOG];
    // speed aux
    atomic_uint64_t speed_aux;
    // last calculation timestamp
    atomic_zclock_t last_update;
#endif
} speed_meter_t;

void spdm_init(speed_meter_t *speed);

void spdm_destroy(speed_meter_t *speed);

void spdm_update(speed_meter_t *speed, uint64_t count);

uint64_t spdm_calc(speed_meter_t *speed);

#endif // ZEROD_SPEED_METER_H
