#include "util.h"

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <arpa/inet.h>


const UT_icd ut_uint16_icd _UNUSED_ = {sizeof(uint16_t), NULL, NULL, NULL};
const UT_icd ut_ip_range_icd _UNUSED_ = {sizeof(struct ip_range), NULL, NULL, NULL};

// cached time
static _Thread_local uint64_t g_ztime_cached = 0;
static _Thread_local uint64_t g_zclock_cached = 0;

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
* Thread-cached version of clock_gettime(CLOCK_MONOTONIC) and conversion to microseconds.
* @param[in] refresh Whether to update cached value.
* @return Current cached hardware clock in microseconds.
*/
uint64_t zclock(bool refresh)
{
    if (ZTIME_NO_CACHE || refresh || (0 == g_zclock_cached)) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        g_zclock_cached = ts.tv_nsec / 1000 + ts.tv_sec * 1000000;
    }

    return g_zclock_cached;
}

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

    if (atomic_compare_exchange_strong_explicit(&bucket->last_update, &last_update, cur_time, memory_order_release, memory_order_relaxed)) {
        uint64_t max_tokens = atomic_load_explicit(&bucket->max_tokens, memory_order_relaxed);
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
        } while (!atomic_compare_exchange_strong_explicit(&bucket->tokens, &real_tokens, real_tokens + inc, memory_order_release, memory_order_relaxed));
    }

    int ret = 0;

    do {
        real_tokens = atomic_load_explicit(&bucket->tokens, memory_order_acquire);
        if (real_tokens < tokens) {
            ret = -1;
            break;
        }
    } while (!atomic_compare_exchange_strong_explicit(&bucket->tokens, &real_tokens, real_tokens - tokens, memory_order_release, memory_order_relaxed));

    return ret;
}

void token_bucket_rollback(struct token_bucket *bucket, uint64_t tokens)
{
    atomic_fetch_add_explicit(&bucket->tokens, tokens, memory_order_acq_rel);
}

/**
* Create hex dump of buffer to user-supplied buffer or internal static buffer.
* Static buffer is thread-safe.
* The destination buffer must be at least 30+4*len.
* @param[in] p Source buffer.
* @param[in] len Buffer length.
* @param[in] lim
* @param[in,out] dst User supplied buffer (optional).
* @return String with hexadecimal dump.
*/
const char *hex_dump(unsigned const char *p, u_int len, u_int lim, char *dst)
{
    static __thread char _dst[8192];
    u_int i, j, i0;
    static char hex[] = "0123456789abcdef";
    char *o; // output position

    if (!dst) {
        dst = _dst;
    }
    if (lim <= 0 || lim > len) {
        lim = len;
    }
    o = dst;
    sprintf(o, "buf 0x%p len %d lim %d\n", p, len, lim);
    o += strlen(o);
    for (i = 0; i < lim;) {
        sprintf(o, "%5d: ", i);
        o += strlen(o);
        memset(o, ' ', 48);
        i0 = i;
        for (j = 0; j < 16 && i < lim; i++, j++) {
            o[j * 3] = hex[(p[i] & 0xf0) >> 4];
            o[j * 3 + 1] = hex[(p[i] & 0xf)];
        }
        i = i0;
        for (j = 0; j < 16 && i < lim; i++, j++)
            o[j + 48] = (p[i] >= 0x20 && p[i] <= 0x7e) ? p[i] : '.';
        o[j + 48] = '\n';
        o += j + 49;
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
int ip_range_cmp(const void *arg1, const void *arg2)
{
    const struct ip_range *ip1 = arg1, *ip2 = arg2;

    if (ip1->ip_end < ip2->ip_start) return -1;
    if (ip1->ip_start > ip2->ip_end) return 1;
    return 0;
}

/**
* Pointer comparator.
* @param[in] arg1
* @param[in] arg2
* @return Same as strcmp.
*/
int ptr_cmp(const void **arg1, const void **arg2)
{
    if (*arg1 < *arg2) return -1;
    if (*arg1 > *arg2) return 1;
    return 0;
}

/**
* uint16_t comparator.
* @param[in] arg1
* @param[in] arg2
* @return Same as strcmp.
*/
int uint16_cmp(const void *arg1, const void *arg2)
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
int str_ends_with(const char *str, const char *suffix)
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
void strtolower(char *str)
{
    for (size_t i = 0; str[i]; i++) {
        str[i] = tolower(str[i]);
    }
}

/**
* Convert string to upper case.
* @param str
*/
void strtoupper(char *str)
{
    for (size_t i = 0; str[i]; i++) {
        str[i] = toupper(str[i]);
    }
}

/**
* Convert machine ipv4 to string.
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
    atomic_init(&speed->i, 0);
    atomic_init(&speed->speed_aux, 0);
    atomic_init(&speed->last_update, 0);
    for (size_t i = 0; i < ARRAYSIZE(speed->backlog); i++) {
        atomic_init(&speed->backlog[i].speed, 0);
        atomic_init(&speed->backlog[i].timestamp, 0);
    }
}

/**
* Destroy speed meter.
* @param[in] speed
*/
void spdm_destroy(struct speed_meter *speed)
{
    (void) speed;
}

/**
* Update speed meter.
* @param[in] speed
* @param[in] count
*/
void spdm_update(struct speed_meter *speed, uint64_t count)
{
    uint64_t curr_time = zclock(false);
    uint64_t last_update = atomic_load_explicit(&speed->last_update, memory_order_acquire);

    if (curr_time - last_update >= 1000000) {
        if (atomic_compare_exchange_strong_explicit(&speed->last_update, &last_update, curr_time, memory_order_release, memory_order_relaxed)) {
            size_t i = atomic_load_explicit(&speed->i, memory_order_acquire);
            uint64_t speed_aux = atomic_load_explicit(&speed->speed_aux, memory_order_acquire);
            atomic_store_explicit(&speed->backlog[i].speed, speed_aux, memory_order_release);
            atomic_fetch_sub_explicit(&speed->speed_aux, speed_aux, memory_order_release);
            atomic_store_explicit(&speed->backlog[i].timestamp, last_update, memory_order_release);
            i++;
            if (SPEED_METER_BACKLOG == i) {
                i = 0;
            }
            atomic_store_explicit(&speed->i, i, memory_order_release);
        }
    }

    atomic_fetch_add_explicit(&speed->speed_aux, count, memory_order_release);
}

/**
* Calculate speed.
* @param[in] speed
* @return Calculated speed.
*/
uint64_t spdm_calc(struct speed_meter *speed)
{
    uint64_t aux = 0;
    uint64_t curr_time = zclock(false);

    for (size_t i = 0; i < SPEED_METER_BACKLOG; i++) {
        if (((curr_time - atomic_load_explicit(&speed->backlog[i].timestamp, memory_order_acquire)) / 1000000) <= SPEED_METER_BACKLOG) {
            aux += atomic_load_explicit(&speed->backlog[i].speed, memory_order_acquire);
        }
    }

    return aux / SPEED_METER_BACKLOG;
}

/**
* @param[in] str
* @param[out] val
* @return Zero on success.
*/
int str_to_u64(const char *str, uint64_t *val)
{
    char *end = NULL;
    u_long v;
    errno = 0;
    v = strtoul(str, &end, 10);
    if ((ERANGE == errno) || (end == str) || ((end != NULL) && isdigit(*end)) || (v > UINT64_MAX)) {
        return -1;
    }
    *val = (uint64_t) v;
    return 0;
}

/**
* @param[in] str
* @param[out] val
* @return Zero on success.
*/
int str_to_u32(const char *str, uint32_t *val)
{
    uint64_t v;
    if (0 != str_to_u64(str, &v) || v > UINT32_MAX) {
        return -1;
    }
    *val = (uint32_t) v;
    return 0;
}

/**
* @param[in] str
* @param[out] val
* @return Zero on success.
*/
int str_to_u16(const char *str, uint16_t *val)
{
    uint64_t v;
    if (0 != str_to_u64(str, &v) || v > UINT16_MAX) {
        return -1;
    }
    *val = (uint16_t) v;
    return 0;
}

/**
* @param[in] str
* @param[out] val
* @return Zero on success.
*/
int str_to_u8(const char *str, uint8_t *val)
{
    uint64_t v;
    if (0 != str_to_u64(str, &v) || v > UINT8_MAX) {
        return -1;
    }
    *val = (uint8_t) v;
    return 0;
}

/**
* Enable core dump file.
* @return Zero on success.
*/
int enable_coredump(void)
{
    if (-1 == prctl(PR_SET_DUMPABLE, 1, 0, 0, 0)) {
        return -1;
    }

    struct rlimit lim = {.rlim_max = RLIM_INFINITY, .rlim_cur = RLIM_INFINITY};
    if (setrlimit(RLIMIT_CORE, &lim) == 0) {
        return 0;
    } else {
        return -1;
    }
}

const char *getpeerip(int socket)
{
    struct sockaddr_storage sa;
    socklen_t len = sizeof(sa);
    struct sockaddr_in *sa4 = (struct sockaddr_in *)&sa;

    if (0 != getpeername(socket, (struct sockaddr *)&sa, &len)) {
        return "0.0.0.0";
    }

    return ipv4_to_str(sa4->sin_addr.s_addr);
}
