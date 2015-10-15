#ifndef ZEROD_SPEED_METER_H
#define ZEROD_SPEED_METER_H

#include "atomic.h"

#define SPEED_METER_BACKLOG 5u

struct speed_meter
{
    // current index
    atomic_size_t i;
    // last calculated speeds
    struct
    {
        atomic_uint64_t speed;
        atomic_uint64_t timestamp;
    } backlog[SPEED_METER_BACKLOG];
    // speed aux
    atomic_uint64_t speed_aux;
    // last calculation speed
    atomic_uint64_t last_update;
};

void spdm_init(struct speed_meter *speed);

void spdm_destroy(struct speed_meter *speed);

void spdm_update(struct speed_meter *speed, uint64_t count);

uint64_t spdm_calc(const struct speed_meter *speed);

#endif // ZEROD_SPEED_METER_H