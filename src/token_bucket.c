#include "token_bucket.h"
#include "util.h"

/**
 * Init token bucket structure.
 * @param[in,out] bucket Bucket for init.
 * @param[in] max_tokens Max tokens in bucket.
 */
void token_bucket_init(struct token_bucket *bucket, uint64_t max_tokens)
{
    atomic_init(&bucket->last_update, zclock(false));
    atomic_init(&bucket->max_tokens, max_tokens);
    atomic_init(&bucket->tokens, max_tokens);
}

void token_bucket_destroy(struct token_bucket *bucket)
{
    (void) bucket;
}

/**
 * Update bucket and remove some tokens if enough.
 * Full bucket refill interval is one second.
 * @param[in,out] bucket Bucket to process.
 * @param[in] tokens Tokens to remove.
 * @param[in] max_tokens Max tokens in bucket.
 * @return Zero on success.
 */
int token_bucket_update(struct token_bucket *bucket, uint64_t tokens)
{
    uint64_t cur_time = zclock(false);

    uint64_t last_update = atomic_load_explicit(&bucket->last_update, memory_order_acquire);
    uint64_t real_tokens;

    if (atomic_compare_exchange_strong_explicit(&bucket->last_update, &last_update, cur_time, memory_order_release,
                                                memory_order_relaxed)) {
        uint64_t max_tokens = atomic_load_explicit(&bucket->max_tokens, memory_order_acquire);
        uint64_t inc = max_tokens;
        if (cur_time - last_update < 1000000) {
            inc = max_tokens * (cur_time - last_update) / 1000000;
        }

        do {
            real_tokens = atomic_load_explicit(&bucket->tokens, memory_order_acquire);

            if (real_tokens + inc >= max_tokens) {
                if (real_tokens > max_tokens) {
                    break;
                }
                inc = max_tokens - real_tokens;
            }
        } while (!atomic_compare_exchange_strong_explicit(&bucket->tokens, &real_tokens, real_tokens + inc,
                                                          memory_order_release, memory_order_relaxed));
    }

    int ret = 0;

    do {
        real_tokens = atomic_load_explicit(&bucket->tokens, memory_order_acquire);
        if (real_tokens < tokens) {
            ret = -1;
            break;
        }
    } while (!atomic_compare_exchange_strong_explicit(&bucket->tokens, &real_tokens, real_tokens - tokens,
                                                      memory_order_release, memory_order_relaxed));

    return ret;
}

void token_bucket_rollback(struct token_bucket *bucket, uint64_t tokens)
{
    atomic_fetch_add_explicit(&bucket->tokens, tokens, memory_order_acq_rel);
}