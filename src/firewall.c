#include <pthread.h>
#include <uthash/utarray.h>
#include "firewall.h"
#include "util.h"

struct zfirewall_struct
{
    // array of ports
    UT_array rules[PROTO_MAX][ACCESS_MAX];
    pthread_spinlock_t lock;
};

/**
 * Create firewall instance.
 * @return New instance.
 */
zfirewall_t *zfwall_new(void)
{
    zfirewall_t *fwall = malloc(sizeof(*fwall));

    if (unlikely(NULL == fwall)) {
        return NULL;
    }

    if (unlikely(0 != pthread_spin_init(&fwall->lock, PTHREAD_PROCESS_PRIVATE))) {
        free(fwall);
        return NULL;
    }

    for (int proto = 0; proto < PROTO_MAX; proto++) {
        for (int policy = 0; policy < ACCESS_MAX; policy++) {
            utarray_init(&fwall->rules[proto][policy], &ut_uint16_icd);
        }
    }

    return fwall;
}

/**
 * Free firewall instance.
 * @param[in] fwall Firewall handle.
 */
void zfwall_free(zfirewall_t *fwall)
{
    pthread_spin_destroy(&fwall->lock);

    for (int proto = 0; proto < PROTO_MAX; proto++) {
        for (int policy = 0; policy < ACCESS_MAX; policy++) {
            utarray_done(&fwall->rules[proto][policy]);
        }
    }

    free(fwall);
}

/**
 * Add firewall rule.
 * @param[in] fwall Firewall handle.
 * @param[in] proto Protocol.
 * @param[in] policy Access policy type.
 * @param[in] port Port number (network order).
 */
void zfwall_add_rule(zfirewall_t *fwall, zip_proto_t proto, zfwall_policy_t policy, uint16_t port)
{
    pthread_spin_lock(&fwall->lock);

    if (NULL == utarray_find(&fwall->rules[proto][policy], &port, uint16_cmp)) {
        utarray_push_back(&fwall->rules[proto][policy], &port);
        utarray_sort(&fwall->rules[proto][policy], uint16_cmp);
    }

    pthread_spin_unlock(&fwall->lock);
}

/**
 * Delete firewall rule.
 * @param[in] fwall Firewall handle.
 * @param[in] proto Protocol.
 * @param[in] policy Access policy type.
 * @param[in] port Port number (network order).
 */
void zfwall_del_rule(zfirewall_t *fwall, zip_proto_t proto, zfwall_policy_t policy, uint16_t port)
{
    pthread_spin_lock(&fwall->lock);

    uint16_t *ptr = utarray_find(&fwall->rules[proto][policy], &port, uint16_cmp);
    if (NULL != ptr) {
        ssize_t idx = utarray_eltidx(&fwall->rules[proto][policy], ptr);
        if (-1 != idx) {
            utarray_erase(&fwall->rules[proto][policy], idx, 1);
        }
    }

    pthread_spin_unlock(&fwall->lock);
}

/**
 * Check whether port is allowed.
 * @param[in] fwall Firewall handle.
 * @param[in] proto Protocol.
 * @param[in] port Port to check (network order).
 * @return True if allowed.
 */
bool zfwall_is_allowed(zfirewall_t *fwall, zip_proto_t proto, uint16_t port)
{
    bool allowed = false;

    pthread_spin_lock(&fwall->lock);

    UT_array *prules = fwall->rules[proto];
    if ((!utarray_len(&prules[ACCESS_ALLOW]) || utarray_find(&prules[ACCESS_ALLOW], &port, uint16_cmp)) &&
        (!utarray_len(&prules[ACCESS_DENY]) || !utarray_find(&prules[ACCESS_DENY], &port, uint16_cmp))) {
        allowed = true;
    }

    pthread_spin_unlock(&fwall->lock);

    return allowed;
}

/**
 * Dump firewall rules with specified protocol and policy.
 * @param[in] fwall Firewall handle.
 * @param[in] proto Protocol.
 * @param[in] policy Access policy type.
 * @param[out] ports Array of ports. Must be freed by user. (network order)
 * @param[out] count Length of array.
 */
void zfwall_dump_ports(zfirewall_t *fwall, zip_proto_t proto, zfwall_policy_t policy, uint16_t **ports, size_t *count)
{
    pthread_spin_lock(&fwall->lock);

    *count = utarray_len(&fwall->rules[proto][policy]);
    if (0 == *count) {
        *ports = NULL;
    } else {
        *ports = malloc((*count) * sizeof(uint16_t));
        memcpy(*ports, fwall->rules[proto][policy].d, *count * sizeof(uint16_t));
    }

    pthread_spin_unlock(&fwall->lock);
}
