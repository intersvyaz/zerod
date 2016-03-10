#ifndef ZEROD_TOKEN_BUCKET_H
#define ZEROD_TOKEN_BUCKET_H

#include <stdbool.h>
#include <pthread.h>
#include "atomic.h"
#include "util_time.h"

#define TOKEN_BUCKET_ATOMIC

typedef struct
{
#ifndef TOKEN_BUCKET_ATOMIC
    pthread_spinlock_t lock;
    uint64_t capacity;
    uint64_t tokens;
    zclock_t last_update;
#else
    // max tokens in bucket
    atomic_uint64_t capacity;
    // available tokens
    atomic_uint64_t tokens;
    // last update
    atomic_zclock_t last_update;
#endif
} token_bucket_t;

void token_bucket_init(token_bucket_t *bucket, uint64_t capacity);

void token_bucket_destroy(token_bucket_t *bucket);

bool token_bucket_update(token_bucket_t *bucket, uint64_t tokens);

/**
 * Get bucket capacity.
 * @param[in] bucket Bucket.
 * @return Maximum tokens in bucket.
 */
static inline uint64_t token_bucket_capacity(token_bucket_t *bucket)
{
#ifndef TOKEN_BUCKET_ATOMIC
    pthread_spin_lock(&bucket->lock);
    uint64_t capacity = bucket->capacity;
    pthread_spin_unlock(&bucket->lock);
    return capacity;
#else
    return atomic_load_acquire(&bucket->capacity);
#endif
}

/**
 * Set bucket capacity.
 * @param[in] bucket Bucket.
 * @param[in] capacity New bucket capacity.
 */
static inline void token_bucket_set_capacity(token_bucket_t *bucket, uint64_t capacity)
{
#ifndef TOKEN_BUCKET_ATOMIC
    pthread_spin_lock(&bucket->lock);
    bucket->capacity = capacity;
    pthread_spin_unlock(&bucket->lock);
#else
    atomic_store_release(&bucket->capacity, capacity);
#endif
}

/**
 * Set current token count int bucket.
 * @param[in] bucket Bucket.
 * @param[in] tokens .
 */
static inline void token_bucket_set_tokens(token_bucket_t *bucket, uint64_t tokens)
{
#ifndef TOKEN_BUCKET_ATOMIC
    pthread_spin_lock(&bucket->lock);
    bucket->tokens = tokens;
    pthread_spin_unlock(&bucket->lock);
#else
    atomic_store_release(&bucket->tokens, tokens);
#endif
}

/**
 * Rollback bucket update.
 * @param[in] bucket Bucket.
 * @param[in] tokens Tokens amount to return.
 */
static inline void token_bucket_rollback(token_bucket_t *bucket, uint64_t tokens)
{
#ifndef TOKEN_BUCKET_ATOMIC
    pthread_spin_lock(&bucket->lock);
    bucket->tokens += tokens;
    pthread_spin_unlock(&bucket->lock);
#else
    atomic_fetch_add_release(&bucket->tokens, tokens);
#endif
}

#endif // ZEROD_TOKEN_BUCKET_H
