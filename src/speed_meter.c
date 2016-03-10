#include "util.h"
#include "speed_meter.h"

/**
 * Initialize speed meter.
 * @param[in] speed
 */
void spdm_init(speed_meter_t *speed)
{
#ifndef SPEED_METER_ATOMIC
    memset(speed, 0, sizeof(*speed));
    pthread_spin_init(&speed->lock, PTHREAD_PROCESS_PRIVATE);
#else
    atomic_init(&speed->i, 0);
    atomic_init(&speed->speed_aux, 0);
    atomic_init(&speed->last_update, 0);
    for (size_t i = 0; i < ARRAYSIZE(speed->backlog); i++) {
        atomic_init(&speed->backlog[i].speed, 0);
        atomic_init(&speed->backlog[i].timestamp, 0);
    }
#endif
}

/**
 * Destroy speed meter.
 * @param[in] speed
 */
void spdm_destroy(speed_meter_t *speed)
{
#ifndef SPEED_METER_ATOMIC
    pthread_spin_destroy(&speed->lock);
#else
    (void) speed;
#endif
}

/**
 * Update speed meter.
 * @param[in] speed
 * @param[in] count
 */
void spdm_update(speed_meter_t *speed, uint64_t count)
{
#ifndef SPEED_METER_ATOMIC
    pthread_spin_lock(&speed->lock);

    zclock_t now = zclock();

    if ((now - speed->last_update) >= SEC2USEC(1)) {
        speed->i++;
        if (SPEED_METER_BACKLOG == speed->i) {
            speed->i = 0;
        }
        speed->backlog[speed->i].speed = speed->speed_aux;
        speed->backlog[speed->i].timestamp = now;
        speed->speed_aux = 0;
        speed->last_update = now;
    }

    speed->speed_aux += count;

    pthread_spin_unlock(&speed->lock);
#else
    zclock_t now = zclock();
    zclock_t last_update = atomic_load_acquire(&speed->last_update);

    // rotate
    if ((now > last_update) && ((now - last_update) >= SEC2USEC(1))) {
        if (atomic_compare_exchange_strong(&speed->last_update, &last_update, now)) {
            size_t i = atomic_load_acquire(&speed->i) + 1;
            if (SPEED_METER_BACKLOG == i) {
                i = 0;
            }
            atomic_store_release(&speed->i, i);

            uint64_t speed_aux = atomic_load_acquire(&speed->speed_aux);
            atomic_fetch_sub_release(&speed->speed_aux, speed_aux);

            atomic_store_release(&speed->backlog[i].speed, speed_aux);
            atomic_store_release(&speed->backlog[i].timestamp, last_update);

        }
    }

    atomic_fetch_add_release(&speed->speed_aux, count);
#endif
}

/**
 * Calculate speed.
 * @param[in] speed
 * @return Calculated speed.
 */
uint64_t spdm_calc(speed_meter_t *speed)
{
#ifndef SPEED_METER_ATOMIC
    uint64_t aux = 0;

    pthread_spin_lock(&speed->lock);

    for (size_t i = 0; i < SPEED_METER_BACKLOG; i++) {
        zclock_t diff = USEC2SEC(zclock() - speed->backlog[i].timestamp);
        if (diff <= SPEED_METER_BACKLOG) {
            aux += speed->backlog[i].speed;
        }
    }

    pthread_spin_unlock(&speed->lock);

    return aux / SPEED_METER_BACKLOG;
#else
    uint64_t aux = 0;
    zclock_t now = zclock();

    for (size_t i = 0; i < SPEED_METER_BACKLOG; i++) {
        zclock_t diff = USEC2SEC(now - atomic_load_acquire(&speed->backlog[i].timestamp));
        if (diff <= SPEED_METER_BACKLOG) {
            aux += atomic_load_acquire(&speed->backlog[i].speed);
        }
    }

    return aux / SPEED_METER_BACKLOG;
#endif
}
