#include <stddef.h> // fix clion bug
#include <assert.h>

#include "client_db.h"

#define BUCKET_MASK (0b1111u)
#define BUCKET_COUNT (BUCKET_MASK + 1)
#define BUCKET_IDX(x) ((x) & BUCKET_MASK)
#define BUCKET_GET(db, idx) (&(db)->bucket[(idx)])

typedef struct zclient_db_bucket_struct
{
    /*<<! hash (lookup by user_id) */
    zclient_t *hash;
    /*<<! access lock */
    pthread_rwlock_t lock;
} zclient_db_bucket_t;

struct zclient_db_struct
{
    /*<<! size counter */
    atomic_size_t count;
    /*<<! Database buckets */
    zclient_db_bucket_t bucket[BUCKET_COUNT];
};

/**
 * Create client database instance.
 * @return New client database instance.
 */
zclient_db_t *zclient_db_new(void)
{
    zclient_db_t *db = malloc(sizeof(*db));
    if (unlikely(NULL == db)) {
        return NULL;
    }

    memset(db, 0, sizeof(*db));

    atomic_init(&db->count, 0);

    for (size_t i = 0; i < ARRAYSIZE(db->bucket); i++) {
        zclient_db_bucket_t *bucket = BUCKET_GET(db, i);
        pthread_rwlock_init(&bucket->lock, NULL);
    }

    return db;
}

/**
 * Destroy and free client database instance.
 * @param[in] db Database instance.
 */
void zclient_db_free(zclient_db_t *db)
{
    for (size_t i = 0; i < ARRAYSIZE(db->bucket); i++) {
        zclient_db_bucket_t *bucket = BUCKET_GET(db, i);
        pthread_rwlock_destroy(&bucket->lock);

        zclient_t *client, *tmp_client;
        HASH_ITER(hh, bucket->hash, client, tmp_client) {
            HASH_DELETE(hh, bucket->hash, client);
            assert(1 == client->refcnt);
            zclient_free(client);
        }
    }
    free(db);
}

/**
 * Get database size.
 * @param[in] Database instance.
 * @return Clients count in database.
 */
inline size_t zclient_db_count(const zclient_db_t *db)
{
    return atomic_load_acquire(&db->count);
}

/**
 * Acquire client from database.
 * @param[in] db Database instance.
 * @param[in] id User id.
 * @return Client instance.
 */
zclient_t *zclient_db_acquire(zclient_db_t *db, uint32_t id, bool lock)
{
    zclient_t *client = NULL;
    zclient_db_bucket_t *bucket = BUCKET_GET(db, BUCKET_IDX(id));

    if (lock) pthread_rwlock_rdlock(&bucket->lock);

    HASH_FIND(hh, bucket->hash, &id, sizeof(id), client);
    if (NULL != client) {
        atomic_fetch_add_release(&client->refcnt, 1);
    }

    if (lock) pthread_rwlock_unlock(&bucket->lock);

    return client;
}

/**
 * Insert client.
 * @param[in] db Database instance.
 * @param[in] client.
 * @param[in,out] client Client instance.
 */
void zclient_db_insert(zclient_db_t *db, zclient_t *client, bool lock)
{
    zclient_db_bucket_t *bucket = BUCKET_GET(db, BUCKET_IDX(client->id));

    if (lock) pthread_rwlock_wrlock(&bucket->lock);

    atomic_fetch_add_release(&db->count, 1);
    atomic_fetch_add_release(&client->refcnt, 1);
    HASH_ADD_KEYPTR(hh, bucket->hash, &client->id, sizeof(client->id), client);

    if (lock) pthread_rwlock_unlock(&bucket->lock);
}

/**
 * Remove client from db only with no references.
 * @return Zero on success.
 */
void zclient_db_remove(zclient_db_t *db, zclient_t *client, bool lock)
{
    zclient_db_bucket_t *bucket = BUCKET_GET(db, BUCKET_IDX(client->id));

    if (lock) pthread_rwlock_wrlock(&bucket->lock);

    HASH_DELETE(hh, bucket->hash, client);
    atomic_fetch_sub_release(&client->refcnt, 1);
    atomic_fetch_sub_release(&db->count, 1);

    if (lock) pthread_rwlock_unlock(&bucket->lock);
}

/**
 *
 */
inline bool zclient_db_partial_rdlock(zclient_db_t *db, uint32_t id)
{
    return 0 == pthread_rwlock_rdlock(&BUCKET_GET(db, BUCKET_IDX(id))->lock);
}

/**
 *
 */
inline bool zclient_db_partial_wrlock(zclient_db_t *db, uint32_t id)
{
    return 0 == pthread_rwlock_wrlock(&BUCKET_GET(db, BUCKET_IDX(id))->lock);
}

/**
 *
 */
inline bool zclient_db_partial_unlock(zclient_db_t *db, uint32_t id)
{
    return 0 == pthread_rwlock_unlock(&BUCKET_GET(db, BUCKET_IDX(id))->lock);
}
