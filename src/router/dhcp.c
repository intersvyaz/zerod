#include "router.h"
#include <pthread.h>
#include <netinet/in.h>
#include <uthash/uthash.h>
#include "../util.h"

#define BUCKET_MASK 0b1111u
#define BUCKET_COUNT ((BUCKET_MASK) + 1)
#define BUCKET_IDX(x) ((x) & BUCKET_MASK)
#define BUCKET_GET(db, idx) (&(db)->bucket[(idx)])

struct zdhcp_lease_int
{
    struct zdhcp_lease lease;
    UT_hash_handle hh;
};

struct zdhcp_bucket
{
    pthread_rwlock_t lock;
    // lease hash (lookup by ip)
    struct zdhcp_lease_int *leases;
};

struct zdhcp
{
    struct zdhcp_bucket bucket[BUCKET_COUNT];
};

/**
 * Create new instance.
 * @return New instance.
 */
struct zdhcp *zdhcp_new(void)
{
    struct zdhcp *dhcp = malloc(sizeof(*dhcp));

    if (unlikely(NULL == dhcp)) {
        return NULL;
    }

    memset(dhcp, 0, sizeof(*dhcp));
    for (size_t i = 0; i < ARRAYSIZE(dhcp->bucket); i++) {
        struct zdhcp_bucket *bucket = BUCKET_GET(dhcp, i);
        if (unlikely(0 != pthread_rwlock_init(&bucket->lock, NULL))) {
            goto err;
        }
    }

    return dhcp;

    err:
    free(dhcp);
    return NULL;
}

/**
 * Destroy and free instance.
 * @param[in] dhcp Instance.
 */
void zdhcp_free(struct zdhcp *dhcp)
{
    for (size_t i = 0; i < ARRAYSIZE(dhcp->bucket); i++) {
        struct zdhcp_bucket *bucket = BUCKET_GET(dhcp, i);
        pthread_rwlock_destroy(&bucket->lock);
        struct zdhcp_lease_int *lease, *tmp;
        HASH_ITER(hh, bucket->leases, lease, tmp) {
            HASH_DELETE(hh, bucket->leases, lease);
            free(lease);
        }
    }
    free(dhcp);
}

/**
 * Insert or update lease record.
 * @param[in] dhcp Instance.
 * @param[in] lease Lease record.
 */
void zdhcp_lease_bind(struct zdhcp *dhcp, const struct zdhcp_lease *lease)
{
    struct zdhcp_lease_int *lease_int = NULL;
    struct zdhcp_bucket *bucket = BUCKET_GET(dhcp, BUCKET_IDX(ntohl(lease->ip)));

    pthread_rwlock_wrlock(&bucket->lock);

    HASH_FIND(hh, bucket->leases, &lease->ip, sizeof(lease->ip), lease_int);
    if (lease_int) {
        lease_int->lease = *lease;
    } else {
        lease_int = malloc(sizeof(*lease_int));
        if (likely(lease_int)) {
            lease_int->lease = *lease;
            HASH_ADD(hh, bucket->leases, lease.ip, sizeof(lease->ip), lease_int);
        }
    }

    pthread_rwlock_unlock(&bucket->lock);
}

/**
 * Find a lease record.
 * Fill lease->ip with searched value. If record was found other fields will be filled.
 * @param[in] dhcp Instance.
 * @param[in,out] lease Lease record.
 * @return Zero on success.
 */
int zdhcp_lease_find(struct zdhcp *dhcp, struct zdhcp_lease *lease)
{
    struct zdhcp_lease_int *lease_int = NULL;
    struct zdhcp_bucket *bucket = BUCKET_GET(dhcp, BUCKET_IDX(ntohl(lease->ip)));

    pthread_rwlock_rdlock(&bucket->lock);

    HASH_FIND(hh, bucket->leases, &lease->ip, sizeof(lease->ip), lease_int);
    if (lease_int) {
        *lease = lease_int->lease;
    }

    pthread_rwlock_unlock(&bucket->lock);

    return lease_int ? 0 : 1;
}