#include "util.h"
#include "token_bucket.h"

/**
 * Init token bucket.
 * @param[in,out] bucket Bucket for init.
 * @param[in] capacity Bucket capacity.
 */
void token_bucket_init(token_bucket_t *bucket, uint64_t capacity)
{
#ifndef TOKEN_BUCKET_ATOMIC
    memset(bucket, 0, sizeof(*bucket));
    pthread_spin_init(&bucket->lock, PTHREAD_PROCESS_PRIVATE);
    bucket->capacity = capacity;
#else
    atomic_init(&bucket->last_update, 0);
    atomic_init(&bucket->capacity, capacity);
    atomic_init(&bucket->tokens, 0);
#endif
}

void token_bucket_destroy(token_bucket_t *bucket)
{
#ifndef TOKEN_BUCKET_ATOMIC
    pthread_spin_destroy(&bucket->lock);
#else
    (void) bucket;
#endif
}

/**
 * Update bucket and remove some tokens if enough.
 * Full bucket refill interval is one second.
 * @param[in] bucket Bucket to process.
 * @param[in] tokens Tokens to remove.
 * @return True on success.
 */
bool token_bucket_update(token_bucket_t *bucket, uint64_t tokens)
{
#ifndef TOKEN_BUCKET_ATOMIC
    bool ok = true;

    pthread_spin_lock(&bucket->lock);

    uint64_t now = zclock();

    if (now > bucket->last_update) {
        uint64_t diff = now - bucket->last_update;
        bucket->last_update = now;
        uint64_t inc = bucket->capacity;
        if (diff < SEC2USEC(1)) {
            inc = (uint64_t) ((double) bucket->capacity * ((double) diff / (double) SEC2USEC(1)));
        }

        bucket->tokens += inc;
        if (bucket->tokens > bucket->capacity) {
            bucket->tokens = bucket->capacity;
        }
    }

    if (bucket->tokens >= tokens) {
        bucket->tokens -= tokens;
    } else {
        ok = false;
    }

    pthread_spin_unlock(&bucket->lock);
    return ok;
#else
    uint64_t real_tokens;
    uint64_t capacity = atomic_load_acquire(&bucket->capacity);

    if (!capacity) {
        return false;
    }

    zclock_t now = zclock();
    zclock_t last_update = atomic_load_acquire(&bucket->last_update);

    if (now > last_update) {
        if (atomic_compare_exchange_strong(&bucket->last_update, &last_update, now)) {
            uint64_t diff = now - last_update;
            uint64_t inc = capacity;
            if (diff < SEC2USEC(1)) {
                inc = (uint64_t) ((double) capacity * ((double) diff / (double) SEC2USEC(1)));
            }

            uint64_t real_tokens = atomic_load_acquire(&bucket->tokens);
            uint64_t new_tokens;
            do {
                new_tokens = real_tokens + inc;
                if (new_tokens > capacity) {
                    new_tokens = capacity;
                }
            } while (!atomic_compare_exchange_strong(&bucket->tokens, &real_tokens, new_tokens));
        }
    }

    bool ok = true;
    real_tokens = atomic_load_acquire(&bucket->tokens);
    do {
        if (tokens > real_tokens) {
            ok = false;
            break;
        }
    } while (!atomic_compare_exchange_strong(&bucket->tokens, &real_tokens, real_tokens - tokens));

    return ok;
#endif
}
