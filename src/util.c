#include "util.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>
#include <sys/time.h>
#include <arpa/inet.h>

const UT_icd ut_uint16_icd _UNUSED_ = {sizeof(uint16_t),NULL,NULL,NULL};
const UT_icd ut_ip_range_icd _UNUSED_ = {sizeof(struct ip_range),NULL,NULL,NULL};

// cached time
static __thread uint64_t g_ztime_cached = 0;

/**
 * Thread-cached version of gettimeofday() and conversion to microseconds.
 * @param[in] refresh Whether to update cached value.
 * @return Current cached time in microseconds.
 */
uint64_t ztime(bool refresh)
{
    if (ZTIME_NO_CACHE || refresh || (0 == g_ztime_cached)) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        g_ztime_cached = tv.tv_usec + tv.tv_sec * 1000000;
    }

    return g_ztime_cached;
}

/**
 * Init token bucket structure.
 * @param[in,out] bucket Bucket for init.
 * @param[in] max_tokens Max tokens in bucket.
 */
void token_bucket_init(struct token_bucket *bucket, uint64_t max_tokens)
{
    bucket->last_update = ztime(false);
    bucket->max_tokens = bucket->tokens = max_tokens;
#ifndef ATOMIC_TOKEN_BUCKET
    pthread_spin_init(&bucket->lock, PTHREAD_PROCESS_PRIVATE);
#endif
}

void token_bucket_destroy(struct token_bucket *bucket)
{
#ifdef ATOMIC_TOKEN_BUCKET
    (void)bucket;
#else
    pthread_spin_destroy(&bucket->lock);
#endif
}

/**
 * Update bucket and remove some tokens if enough.
 * Full bucket refill interval is one second.
 * @param[in,out] bucket Bucket to process.
 * @param[in] tokens Tokens to remove.
 * @param[in] max_tokens Max tokens in bucket.
 * @return Zero on succes.
 */
int token_bucket_update(struct token_bucket *bucket, uint64_t tokens)
{
#ifdef ATOMIC_TOKEN_BUCKET
    uint64_t cur_time = ztime(false);

    uint64_t last_update = __atomic_load_n(&bucket->last_update, __ATOMIC_ACQUIRE);
    uint64_t real_tokens;

    if (__atomic_compare_exchange_n(&bucket->last_update, &last_update, cur_time, true, __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
        uint64_t max_tokens = __atomic_load_n(&bucket->max_tokens, __ATOMIC_RELAXED);
        uint64_t inc = max_tokens / 2;
        if (cur_time - last_update < 1000000) {
            inc = max_tokens * (cur_time - last_update) / 1000000;
        }

        do {
            real_tokens = __atomic_load_n(&bucket->tokens, __ATOMIC_ACQUIRE);

            if (real_tokens + inc >= max_tokens) {
                if (real_tokens > max_tokens) {
                    break;
                }
                inc = max_tokens - real_tokens;
            }
        } while (!__atomic_compare_exchange_n(&bucket->tokens, &real_tokens, real_tokens + inc, true, __ATOMIC_RELEASE, __ATOMIC_RELAXED));
    }

    int ret = 0;

    do {
        real_tokens = __atomic_load_n(&bucket->tokens, __ATOMIC_ACQUIRE);
        if (real_tokens < tokens) {
            ret = -1;
            break;
        }
    } while (!__atomic_compare_exchange_n(&bucket->tokens, &real_tokens, real_tokens - tokens, true, __ATOMIC_RELEASE, __ATOMIC_RELAXED));

    return ret;
#else
    uint64_t cur_time = ztime(false);

    pthread_spin_lock(&bucket->lock);

    uint64_t max_tokens = __atomic_load_n(&bucket->max_tokens, __ATOMIC_RELAXED);

    bucket->tokens += max_tokens * (cur_time - bucket->last_update) / 1000000;
    if (bucket->tokens > max_tokens) {
        bucket->tokens = max_tokens;
    }

    bucket->last_update = cur_time;

    int ret = 0;

    if (bucket->tokens >= tokens) {
        bucket->tokens -= tokens;
    } else {
        ret = -1;
    }

    pthread_spin_unlock(&bucket->lock);

    return ret;
#endif
}

void token_bucket_rollback(struct token_bucket *bucket, uint64_t tokens)
{
#ifdef ATOMIC_TOKEN_BUCKET
    __atomic_fetch_add(&bucket->tokens, tokens, __ATOMIC_ACQ_REL);
#else
    pthread_spin_lock(&bucket->lock);

    bucket->tokens += tokens;

    pthread_spin_unlock(&bucket->lock);
#endif
}

/**
 * Create hex dump of buffer to user-supplied buffer or internal static buffer.
 * Static buffer is thread-safe.
 * The destination buffer must be at least 30+4*len.
 * @param[in] p Source buffer.
 * @param[in] len Bufer length.
 * @param[in,out] dst User suppiled buffer.
 * @return String with hexidecimal dump.
 */
const char *hex_dump(const char *p, u_int len, u_int lim, char *dst)
{
    static __thread char _dst[8192];
    u_int i, j, i0;
    static char hex[] = "0123456789abcdef";
    char *o; // output position

    if (!dst)
            dst = _dst;
    if (lim <= 0 || lim > len)
            lim = len;
    o = dst;
    sprintf(o, "buf 0x%p len %d lim %d\n", p, len, lim);
    o += strlen(o);
    // hexdump routine
    for (i = 0; i < lim; ) {
            sprintf(o, "%5d: ", i);
            o += strlen(o);
            memset(o, ' ', 48);
            i0 = i;
            for (j=0; j < 16 && i < lim; i++, j++) {
                    o[j*3] = hex[(p[i] & 0xf0)>>4];
                    o[j*3+1] = hex[(p[i] & 0xf)];
            }
            i = i0;
            for (j=0; j < 16 && i < lim; i++, j++)
                    o[j + 48] = (p[i] >= 0x20 && p[i] <= 0x7e) ? p[i] : '.';
            o[j+48] = '\n';
            o += j+49;
    }
    *o = '\0';

    return dst;
}

/**
 * IP range comparator.
 * @param[in] arg1
 * @param[in] arg2
 * @return Same as strcmp.
 */
__attribute__((pure)) int ip_range_cmp(const void *arg1, const void *arg2)
{
    const struct ip_range *ip1 = arg1, *ip2 = arg2;

    if (ip1->ip_end < ip2->ip_start) return -1;
    if (ip1->ip_start > ip2->ip_end) return 1;
    return 0;
}

/**
 * uint16_t  comparator.
 * @param[in] arg1
 * @param[in] arg2
 * @return Same as strcmp.
 */
__attribute__((pure)) int uint16_cmp(const void *arg1, const void *arg2)
{
    const uint16_t *num1 = arg1, *num2 = arg2;

    if (*num1 < *num2) return -1;
    if (*num1 > *num2) return 1;
    return 0;
}

/**
 * Check whether string ends with suffix.
 * @param[in] str
 * @param[in] suffix
 * @return Non zero on success.
 */
__attribute__((pure)) int str_ends_with(const char *str, const char *suffix)
{
    if (!str || !suffix)
        return 0;

    size_t lenstr = strlen(str);
    size_t lensuffix = strlen(suffix);
    if (lensuffix > lenstr)
        return 0;

    return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}

/**
 * Convert string to lower case.
 * @param[in, out] str String to be converted.
 */
__attribute__((pure)) void strtolower(char *str)
{
    for (size_t i = 0; str[i]; i++){
      str[i] = tolower(str[i]);
    }
}

/**
 * Convert string to upper case.
 * @param str
 */
__attribute__((pure)) void strtoupper(char *str)
{
    for (size_t i = 0; str[i]; i++){
      str[i] = toupper(str[i]);
    }
}

/**
 * @brief ipv4_to_str
 * @param[in,out] buf Destination buffer.
 * @param[in] len Buffer size.
 * @param[in] ip
 * @return Zero on success.
 */
const char *ipv4_to_str(uint32_t ip)
{
    static __thread char buf[INET_ADDRSTRLEN];

    if (NULL == inet_ntop(AF_INET, &ip, buf, sizeof(buf))) {
        snprintf(buf, sizeof(buf), "(invalid)");
    }

    return buf;
}

/**
 * Convert IPv4 address from string to uint32_t host order.
 * @param[in] src Source IPv4 string.
 * @param[out] dst Destination buffer.
 * @return Zero on success.
 */
int ipv4_to_u32(const char *src, uint32_t *dst)
{
    struct in_addr addr;
    if (0 < inet_pton(AF_INET, src, &addr)) {
        *dst = ntohl(addr.s_addr);
        return 0;
    } else {
        *dst = 0;
        return -1;
    }
}

/**
 * Initialize speed meter.
 * @param[in] speed
 */
void spdm_init(struct speed_meter *speed)
{
    bzero(speed, sizeof(*speed));
#ifndef ATOMIC_SPEED_METER
    pthread_spin_init(&speed->lock, PTHREAD_PROCESS_PRIVATE);
#endif
}

/**
 * Destriy speed meter.
 * @param[in] speed
 */
void spdm_destroy(struct speed_meter *speed)
{
#ifdef ATOMIC_SPEED_METER
    (void)speed;
#else
    pthread_spin_destroy(&speed->lock);
#endif
}

/**
 * Update speed meter.
 * @param[in] speed
 * @param[in] count
 */
void spdm_update(struct speed_meter *speed, uint64_t count)
{
#ifdef ATOMIC_SPEED_METER
    uint64_t curr_time = ztime(false);
    uint64_t last_update = __atomic_load_n(&speed->last_update, __ATOMIC_ACQUIRE);

    if (curr_time - speed->last_update >= 1000000) {
        if (__atomic_compare_exchange_n(&speed->last_update, &last_update, curr_time, true, __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
            size_t i = __atomic_load_n(&speed->i, __ATOMIC_ACQUIRE);
            uint64_t speed_aux = __atomic_load_n(&speed->speed_aux, __ATOMIC_ACQUIRE);
            __atomic_store_n(&speed->backlog[i].speed, speed_aux, __ATOMIC_RELEASE);
            __atomic_sub_fetch(&speed->speed_aux, speed_aux, __ATOMIC_RELEASE);
            __atomic_store_n(&speed->backlog[i].timestamp, last_update, __ATOMIC_RELEASE);
            i++;
            if (SPEED_METER_BACKLOG == i) {
                i = 0;
            }
            __atomic_store_n(&speed->i, i, __ATOMIC_RELEASE);
        }
    }

    __atomic_add_fetch(&speed->speed_aux, count, __ATOMIC_RELEASE);
#else
    uint64_t curr_time = ztime(false);

    pthread_spin_lock(&speed->lock);

    if (curr_time - speed->last_update >= 1000000) {
        speed->backlog[speed->i].speed = speed->speed_aux;
        speed->backlog[speed->i].timestamp = curr_time;
        speed->i++;
        if (SPEED_METER_BACKLOG == speed->i) {
            speed->i = 0;
        }
        speed->speed_aux = 0;
        speed->last_update = curr_time;
    }
    speed->speed_aux += count;

    pthread_spin_unlock(&speed->lock);
#endif
}

/**
 * Calculate speed.
 * @param[in] speed
 * @return Calculated speed.
 */
uint64_t spdm_calc(struct speed_meter *speed)
{
#ifdef ATOMIC_SPEED_METER
    uint64_t aux = 0;
    uint64_t curr_time = ztime(false);

    for (size_t i = 0; i < SPEED_METER_BACKLOG; i++) {
        if (((curr_time - __atomic_load_n(&speed->backlog[i].timestamp, __ATOMIC_ACQUIRE)) / 1000000) <= SPEED_METER_BACKLOG) {
            aux += __atomic_load_n(&speed->backlog[i].speed, __ATOMIC_ACQUIRE);
        }
    }

    return aux / SPEED_METER_BACKLOG;
#else
    uint64_t aux = 0;
    uint64_t curr_time = ztime(false);

    pthread_spin_lock(&speed->lock);

    for (size_t i = 0; i < SPEED_METER_BACKLOG; i++) {
        if (((curr_time - speed->backlog[i].timestamp) / 1000000) <= SPEED_METER_BACKLOG) {
            aux += speed->backlog[i].speed;
        }
    }

    pthread_spin_unlock(&speed->lock);

    return aux / SPEED_METER_BACKLOG;
#endif
}
