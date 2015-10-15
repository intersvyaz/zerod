#include "router.h"
#include <pthread.h>
#include <uthash/utarray.h>
#include "../util.h"

struct zfirewall
{
    // array of ports
    UT_array rules[PROTO_MAX][PORT_MAX];
    pthread_spinlock_t lock;
};

/**
 * Create firewall instance.
 * @return New instance.
 */
struct zfirewall *zfwall_create(void)
{
    struct zfirewall *fire = malloc(sizeof(*fire));
    pthread_spin_init(&fire->lock, PTHREAD_PROCESS_PRIVATE);
    for (int proto = 0; proto < PROTO_MAX; proto++) {
        for (int rule = 0; rule < PORT_MAX; rule++) {
            utarray_init(&fire->rules[proto][rule], &ut_uint16_icd);
        }
    }

    return fire;
}

/**
 * Destroy firewall instance.
 * @param[in] fwd Firewall handle.
 */
void zfwall_destroy(struct zfirewall *fire)
{
    pthread_spin_destroy(&fire->lock);

    for (int proto = 0; proto < PROTO_MAX; proto++) {
        for (int rule = 0; rule < PORT_MAX; rule++) {
            utarray_done(&fire->rules[proto][rule]);
        }
    }

    free(fire);
}

/**
 * Add firewall rule.
 * @param[in] fire Firewall handle.
 * @param[in] proto Protocol.
 * @param[in] rule Rule type.
 * @param[in] port Port number (network order).
 */
void zfwall_add_rule(struct zfirewall *fire, enum ipproto proto, enum port_rule rule, uint16_t port)
{
    pthread_spin_lock(&fire->lock);

    if (NULL == utarray_find(&fire->rules[proto][rule], &port, uint16_cmp)) {
        utarray_push_back(&fire->rules[proto][rule], &port);
        utarray_sort(&fire->rules[proto][rule], uint16_cmp);
    }

    pthread_spin_unlock(&fire->lock);
}

/**
 * Delete firewall rule.
 * @param[in] fire Firewall handle.
 * @param[in] proto Protocol.
 * @param[in] rule Rule type.
 * @param[in] port Port number (network order).
 */
void zfwall_del_rule(struct zfirewall *fire, enum ipproto proto, enum port_rule rule, uint16_t port)
{
    pthread_spin_lock(&fire->lock);

    uint16_t *ptr = utarray_find(&fire->rules[proto][rule], &port, uint16_cmp);
    if (NULL != ptr) {
        ssize_t idx = utarray_eltidx(&fire->rules[proto][rule], ptr);
        if (-1 != idx) {
            utarray_erase(&fire->rules[proto][rule], idx, 1);
        }
    }

    pthread_spin_unlock(&fire->lock);
}

/**
 * Check whether port is allowed.
 * @param[in] fire Firewall handle.
 * @param[in] proto Protocol.
 * @param[in] port Port to check (network order).
 * @return Zero on allow.
 */
int zfwall_is_allowed(struct zfirewall *fire, enum ipproto proto, uint16_t port)
{
    int ret = -1;

    pthread_spin_lock(&fire->lock);

    UT_array *prules = fire->rules[proto];
    if ((!utarray_len(&prules[PORT_ALLOW]) || utarray_find(&prules[PORT_ALLOW], &port, uint16_cmp)) &&
        (!utarray_len(&prules[PORT_DENY]) || !utarray_find(&prules[PORT_DENY], &port, uint16_cmp))) {
        ret = 0;
    }

    pthread_spin_unlock(&fire->lock);

    return ret;
}

/**
 * Dump firewall rules with specified protocol and rule type.
 * @param[in] fire Firewall handle.
 * @param[in] proto Protocol.
 * @param[in] rule Rule type.
 * @param[out] ports Array of ports. Must be freed by user. (network order)
 * @param[out] count Length of array.
 */
void zfwall_dump_ports(struct zfirewall *fire, enum ipproto proto, enum port_rule rule, uint16_t **ports, size_t *count)
{
    pthread_spin_lock(&fire->lock);

    *count = utarray_len(&fire->rules[proto][rule]);
    if (0 == *count) {
        *ports = NULL;
    } else {
        *ports = malloc((*count) * sizeof(uint16_t));
        memcpy(*ports, fire->rules[proto][rule].d, *count * sizeof(uint16_t));
    }

    pthread_spin_unlock(&fire->lock);
}
