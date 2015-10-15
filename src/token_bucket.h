#ifndef ZEROD_TOKEN_BUCKET_H
#define ZEROD_TOKEN_BUCKET_H

#include "atomic.h"

struct token_bucket
{
    // max tokens in bucket
    atomic_uint64_t max_tokens;
    // available tokens count
    atomic_uint64_t tokens;
    // last update time in microseconds
    atomic_uint64_t last_update;
};

void token_bucket_init(struct token_bucket *bucket, uint64_t max_tokens);

void token_bucket_destroy(struct token_bucket *bucket);

int token_bucket_update(struct token_bucket *bucket, uint64_t tokens);

void token_bucket_rollback(struct token_bucket *bucket, uint64_t tokens);

/**
 * Get maximum tokens in bucket.
 * @param[in] bucket Bucket.
 * @return Maximum tokens in bucket.
 */
static inline uint64_t token_bucket_get_max(struct token_bucket *bucket)
{
    return atomic_load_explicit(&bucket->max_tokens, memory_order_acquire);
}

/**
 * Set maximum tokens in bucket.
 * @param[in] bucket Bucket.
 * @param[in] max Maximum tokens in bucket.
 */
static inline void token_bucket_set_max(struct token_bucket *bucket, uint64_t max)
{
    atomic_store_explicit(&bucket->max_tokens, max, memory_order_release);
}

#endif // ZEROD_TOKEN_BUCKET_H