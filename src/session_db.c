#include <stddef.h> // fix annoying bug in clion
#include <uthash/uthash.h>
#include <assert.h>

#include "session_db.h"

#define BUCKET_MASK (0b11111u)
#define BUCKET_COUNT (BUCKET_MASK + 1)
#define BUCKET_IDX(x) ((x) & BUCKET_MASK)
#define BUCKET_GET(db, idx) (&(db)->bucket[(idx)])

typedef struct zsession_db_bucket_struct
{
    /*<<! hash (lookup by ip) */
    zsession_t *hash;
    /*<<! access lock */
    pthread_rwlock_t lock;
} zsession_db_bucket_t;

struct zsession_db_struct
{
    /*<<! Session count */
    atomic_size_t count;
    /*<<! Bucket */
    zsession_db_bucket_t bucket[BUCKET_COUNT];
};

/**
 * Create database instance.
 * @return New instance.
 */
zsession_db_t *zsession_db_new(void)
{
    zsession_db_t *db = malloc(sizeof(*db));
    if (unlikely(NULL == db)) {
        return NULL;
    }

    memset(db, 0, sizeof(*db));
    atomic_init(&db->count, 0);

    for (size_t i = 0; i < ARRAYSIZE(db->bucket); i++) {
        zsession_db_bucket_t *bucket = BUCKET_GET(db, i);
        pthread_rwlock_init(&bucket->lock, NULL);
    }

    return db;
}

/**
 * Free database instance.
 */
void zsession_db_free(zsession_db_t *db)
{
    for (size_t i = 0; i < ARRAYSIZE(db->bucket); i++) {
        zsession_db_bucket_t *bucket = BUCKET_GET(db, i);
        pthread_rwlock_destroy(&bucket->lock);

        zsession_t *sess, *tmp_sess;
        HASH_ITER(hh, bucket->hash, sess, tmp_sess) {
            HASH_DELETE(hh, bucket->hash, sess);
            assert(1 == sess->refcnt);
            zsession_release(sess);
        }
    }
    free(db);
}

/**
 *
 */
inline bool zsession_db_partial_rdlock(zsession_db_t *db, uint32_t ip)
{
    return 0 == pthread_rwlock_rdlock(&BUCKET_GET(db, BUCKET_IDX(ip))->lock);
}

/**
 *
 */
inline bool zsession_db_partial_wrlock(zsession_db_t *db, uint32_t ip)
{
    return 0 == pthread_rwlock_wrlock(&BUCKET_GET(db, BUCKET_IDX(ip))->lock);
}

/**
 *
 */
inline bool zsession_db_partial_unlock(zsession_db_t *db, uint32_t ip)
{
    return 0 == pthread_rwlock_unlock(&BUCKET_GET(db, BUCKET_IDX(ip))->lock);
}

/**
 * @param[in] db Database instance.
 * @return Bucket count in database instance.
 */
inline size_t zsession_db_get_bucket_count(const zsession_db_t *db)
{
    return ARRAYSIZE(db->bucket);
}

/**
 * @return Zero on success or value returned from callback.
 */
int zsession_db_bucket_map(zsession_db_t *db, size_t index, zsession_db_bucket_cb callback, void *arg)
{
    zsession_db_bucket_t *bucket = BUCKET_GET(db, index);
    zsession_t *sess, *tmp_sess;

    pthread_rwlock_rdlock(&bucket->lock);
    HASH_ITER(hh, bucket->hash, sess, tmp_sess) {
        atomic_fetch_add_release(&sess->refcnt, 1);
        pthread_rwlock_unlock(&bucket->lock);

        int ret = callback(sess, arg);

        zsession_release(sess);

        if (ret) {
            return ret;
        }

        pthread_rwlock_rdlock(&bucket->lock);
    }
    pthread_rwlock_unlock(&bucket->lock);

    return 0;
}

/**
 * @return Null or session pointer if found.
 */
zsession_t *zsession_db_acquire(zsession_db_t *db, uint32_t ip, bool lock)
{
    zsession_t *session = NULL;
    zsession_db_bucket_t *bucket = BUCKET_GET(db, BUCKET_IDX(ip));

    if (lock) pthread_rwlock_rdlock(&bucket->lock);

    HASH_FIND(hh, bucket->hash, &ip, sizeof(ip), session);
    if (session) {
        atomic_fetch_add_release(&session->refcnt, 1);
    }

    if (lock) pthread_rwlock_unlock(&bucket->lock);

    return session;
}

/**
 *
 */
void zsession_db_insert(zsession_db_t *db, zsession_t *session, bool lock)
{
    zsession_db_bucket_t *bucket = BUCKET_GET(db, BUCKET_IDX(session->ip));

    if (lock) pthread_rwlock_wrlock(&bucket->lock);
    atomic_fetch_add_release(&session->refcnt, 1); // database reference
    HASH_ADD(hh, bucket->hash, ip, sizeof(session->ip), session);
    if (lock) pthread_rwlock_unlock(&bucket->lock);

    atomic_fetch_add_release(&db->count, 1);
}

/**
 * Remove session from storage.
 * @param[in] session Session.
 */
void zsession_db_remove(zsession_db_t *db, zsession_t *session)
{
    zsession_db_bucket_t *bucket = BUCKET_GET(db, BUCKET_IDX(session->ip));

    pthread_rwlock_wrlock(&bucket->lock);
    HASH_DELETE(hh, bucket->hash, session);
    atomic_fetch_sub_release(&session->refcnt, 1); // database reference
    pthread_rwlock_unlock(&bucket->lock);

    atomic_fetch_sub_release(&db->count, 1);
}

/**
 * @param[in] db Database instance.
 * @return Size of database.
 */
inline size_t zsession_db_count(const zsession_db_t *db)
{
    return atomic_load_acquire(&db->count);
}
