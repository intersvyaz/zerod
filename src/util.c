#include "util.h"
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include "router/netproto.h"

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
        g_ztime_cached = SEC2USEC(tv.tv_sec) + tv.tv_usec;
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
        g_zclock_cached = SEC2USEC(ts.tv_sec) + NSEC2USEC(ts.tv_nsec);
    }

    return g_zclock_cached;
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
    static _Thread_local char _dst[8192];
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
 * Convert string to upper case.
 * @param[in,out] str
 */
void strtoupper(char *str)
{
    for (size_t i = 0; str[i]; i++) {
        str[i] = (char)toupper(str[i]);
    }
}

/**
 * Convert string to lower case.
 * @param[in,out] str
 */
void strtolower(char *str)
{
    for (size_t i = 0; str[i]; i++) {
        str[i] = (char)tolower(str[i]);
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
    static _Thread_local char buf[INET_ADDRSTRLEN];

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
 * Get socket peer address string.
 * @param[in] socket Socket descriptor.
 * @return String address representation.
 */
const char *getpeerip(int socket)
{
    struct sockaddr_storage sa;
    socklen_t len = sizeof(sa);
    struct sockaddr_in *sa4 = (struct sockaddr_in *) &sa;

    if (0 != getpeername(socket, (struct sockaddr *) &sa, &len)) {
        return "0.0.0.0";
    }

    return ipv4_to_str(sa4->sin_addr.s_addr);
}

/**
 *
 */
const char *mac48_bin_to_str(const uint8_t *mac)
{
    static _Thread_local char buf[HWADDR_MAC48_STR_LEN];

    for (size_t i = 0; i < HWADDR_MAC48_LEN; i++) {
        snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }

    return buf;
}

/**
 *
 */
void mac48_str_to_bin(uint8_t *mac, const char *str)
{
    for (size_t i = 0; i < HWADDR_MAC48_LEN; i++) {
        mac[i] = (uint8_t)strtol(&str[i*3], NULL, 16);
    }
}

/**
 * Update internet checksum.
 * Only for updating data aligned to word boundary.
 * @see rfc1624 for details.
 * @param old_csum Old checksum.
 * @param len Data length in words.
 * @param old_data Old data.
 * @param new_data New data.
 * @return New checksum.
 */
uint16_t in_csum_update(uint16_t old_csum, uint16_t len, const uint16_t *old_data, const uint16_t *new_data)
{
    uint32_t csum = (uint16_t) ~old_csum;

    while (len--) {
        csum += (uint16_t) ~*old_data + *new_data;
        old_data++;
        new_data++;
    }

    while (csum >> 16) {
        csum = (csum & 0xffff) + (csum >> 16);
    }

    return (uint16_t) ~csum;
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
