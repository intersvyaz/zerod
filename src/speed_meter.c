#include "speed_meter.h"
#include "util.h"

/**
 * Initialize speed meter.
 * @param[in] speed
 */
void spdm_init(struct speed_meter *speed)
{
    atomic_init(&speed->i, 0);
    atomic_init(&speed->speed_aux, 0);
    atomic_init(&speed->last_update, 0);
    for (size_t i = 0; i < ARRAYSIZE(speed->backlog); i++) {
        atomic_init(&speed->backlog[i].speed, 0);
        atomic_init(&speed->backlog[i].timestamp, 0);
    }
}

/**
 * Destroy speed meter.
 * @param[in] speed
 */
void spdm_destroy(struct speed_meter *speed)
{
    (void) speed;
}

/**
 * Update speed meter.
 * @param[in] speed
 * @param[in] count
 */
void spdm_update(struct speed_meter *speed, uint64_t count)
{
    uint64_t curr_time = zclock(false);
    uint64_t last_update = atomic_load_explicit(&speed->last_update, memory_order_acquire);

    if (curr_time - last_update >= SEC2USEC(1)) {
        if (atomic_compare_exchange_strong_explicit(&speed->last_update, &last_update, curr_time, memory_order_release,
                                                    memory_order_relaxed)) {
            size_t i = atomic_load_explicit(&speed->i, memory_order_acquire);
            uint64_t speed_aux = atomic_load_explicit(&speed->speed_aux, memory_order_acquire);
            atomic_store_explicit(&speed->backlog[i].speed, speed_aux, memory_order_release);
            atomic_fetch_sub_explicit(&speed->speed_aux, speed_aux, memory_order_release);
            atomic_store_explicit(&speed->backlog[i].timestamp, last_update, memory_order_release);
            i++;
            if (SPEED_METER_BACKLOG == i) {
                i = 0;
            }
            atomic_store_explicit(&speed->i, i, memory_order_release);
        }
    }

    atomic_fetch_add_explicit(&speed->speed_aux, count, memory_order_release);
}

/**
 * Calculate speed.
 * @param[in] speed
 * @return Calculated speed.
 */
uint64_t spdm_calc(const struct speed_meter *speed)
{
    uint64_t aux = 0;
    uint64_t curr_time = zclock(false);

    for (size_t i = 0; i < SPEED_METER_BACKLOG; i++) {
        uint64_t diff = USEC2SEC(curr_time - atomic_load_explicit(&speed->backlog[i].timestamp, memory_order_acquire));
        if (diff <= SPEED_METER_BACKLOG) {
            aux += atomic_load_explicit(&speed->backlog[i].speed, memory_order_acquire);
        }
    }

    return aux / SPEED_METER_BACKLOG;
}