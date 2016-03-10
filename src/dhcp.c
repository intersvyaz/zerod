#include <pthread.h>
#include <uthash/uthash.h>
#include "dhcp.h"
#include "util.h"
#include "util_time.h"

#define DHCP_LEASE_TTL      MIN2USEC(10) // 10 minutes

#define BUCKET_MASK (0b1111u)
#define BUCKET_COUNT (BUCKET_MASK + 1)
#define BUCKET_IDX(x) ((x) & BUCKET_MASK)
#define BUCKET_GET(db, idx) (&(db)->bucket[(idx)])

typedef struct zdhcp_lease_int_struct
{
    zdhcp_lease_t lease;
    UT_hash_handle hh;
} zdhcp_lease_int_t;

typedef struct zdhcp_bucket_struct
{
    /*<<! hash (lookup by ip) */
    zdhcp_lease_int_t *leases;
    /*<<! access lock */
    pthread_rwlock_t lock;


} zdhcp_bucket_t;

struct zdhcp_struct
{
    zdhcp_bucket_t bucket[BUCKET_COUNT];
};

/**
 * Create new instance.
 * @return New instance.
 */
zdhcp_t *zdhcp_new(void)
{
    zdhcp_t *dhcp = malloc(sizeof(*dhcp));
    if (unlikely(NULL == dhcp)) {
        return NULL;
    }

    memset(dhcp, 0, sizeof(*dhcp));

    for (size_t i = 0; i < ARRAYSIZE(dhcp->bucket); i++) {
        zdhcp_bucket_t *bucket = BUCKET_GET(dhcp, i);
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
void zdhcp_free(zdhcp_t *dhcp)
{
    for (size_t i = 0; i < ARRAYSIZE(dhcp->bucket); i++) {
        zdhcp_bucket_t *bucket = BUCKET_GET(dhcp, i);
        pthread_rwlock_destroy(&bucket->lock);
        zdhcp_lease_int_t *lease, *tmp;
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
 * @return True on success.
 */
bool zdhcp_lease_bind(zdhcp_t *dhcp, const zdhcp_lease_t *lease)
{
    zdhcp_lease_int_t *lease_int = NULL;
    zdhcp_bucket_t *bucket = BUCKET_GET(dhcp, BUCKET_IDX(lease->ip));
    bool ok = false;

    pthread_rwlock_wrlock(&bucket->lock);

    HASH_FIND(hh, bucket->leases, &lease->ip, sizeof(lease->ip), lease_int);
    if (lease_int) {
        lease_int->lease = *lease;
    } else {
        lease_int = malloc(sizeof(*lease_int));
        if (likely(lease_int)) {
            lease_int->lease = *lease;
            HASH_ADD(hh, bucket->leases, lease.ip, sizeof(lease->ip), lease_int);
            ok = true;
        }
    }

    pthread_rwlock_unlock(&bucket->lock);

    return ok;
}

/**
 * Find a lease record.
 * Fill lease->ip with searched value. If record was found other fields will be filled.
 * @param[in] dhcp Instance.
 * @param[in,out] lease Lease record.
 * @return True if found.
 */
bool zdhcp_lease_find(zdhcp_t *dhcp, zdhcp_lease_t *lease)
{
    const zdhcp_lease_int_t *lease_int = NULL;
    zdhcp_bucket_t *bucket = BUCKET_GET(dhcp, BUCKET_IDX(lease->ip));

    pthread_rwlock_rdlock(&bucket->lock);

    HASH_FIND(hh, bucket->leases, &lease->ip, sizeof(lease->ip), lease_int);
    if (lease_int) {
        *lease = lease_int->lease;
    }

    pthread_rwlock_unlock(&bucket->lock);

    return lease_int != NULL;
}

/**
 * Cleanup dhcp lease database.
 * @param[in] dhcp Database instance.
 */
void zdhcp_cleanup(zdhcp_t *dhcp)
{
    for (size_t i = 0; i < ARRAYSIZE(dhcp->bucket); i++) {
        zdhcp_bucket_t *bucket = BUCKET_GET(dhcp, i);
        zdhcp_lease_int_t *lease, *tmp;

        pthread_rwlock_wrlock(&bucket->lock);
        HASH_ITER(hh, bucket->leases, lease, tmp) {
            if (ztime() > (lease->lease.lease_end + DHCP_LEASE_TTL)) {
                HASH_DELETE(hh, bucket->leases, lease);
                free(lease);
            }
        }
        pthread_rwlock_unlock(&bucket->lock);
    }
}
