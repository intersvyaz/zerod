#ifndef ZEROD_UTIL_H
#define ZEROD_UTIL_H

#include <inttypes.h>
#include <stdbool.h>
#include <uthash/utarray.h>

#ifndef likely
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#endif /* likely and unlikely */

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ntohll(x)    __bswap_64 (x)
#define htonll(x)    __bswap_64 (x)
#else
#define ntohll(x)    (x)
#define htonll(x)    (x)
#endif

#define ARRAYSIZE(x) sizeof(x)/sizeof((x)[0])
#define STRLEN_STATIC(x) (sizeof(x) - 1)

#define USEC2SEC(x) ((x) / 1000000u)
#define SEC2USEC(x) ((x) * 1000000u)
#define NSEC2USEC(x) ((x) / 1000u)

#define min(x, y) ((x) < (y) ? (x) : (y))

/**
 * Time routines.
 */

// comment this to enable time caching
#define ZTIME_NO_CACHE 1

uint64_t ztime(bool refresh);

uint64_t zclock(bool refresh);

/**
 * String manipulation routines.
 */

const char *hex_dump(unsigned const char *p, u_int len, u_int lim, char *dst);

int str_ends_with(const char *str, const char *suffix);

void strtoupper(char *str);

void strtolower(char *str);

int str_to_u64(const char *str, uint64_t *val);

int str_to_u32(const char *str, uint32_t *val);

int str_to_u16(const char *str, uint16_t *val);

int str_to_u8(const char *str, uint8_t *val);

/**
 * Network manipulation routines.
 */

// get from IP address and CIDR ending address in subnet
#define IP_RANGE_END(ip, cidr) (cidr == 32u ? (ip) : (ip) | (((uint32_t)~0u) >> (cidr)))

struct ip_range
{
    uint32_t ip_start;
    uint32_t ip_end;
};

extern const UT_icd ut_ip_range_icd;

int ip_range_cmp(const void *arg1, const void *arg2);

const char *ipv4_to_str(uint32_t ip);

int ipv4_to_u32(const char *src, uint32_t *dst);

const char *getpeerip(int socket);

const char *mac48_bin_to_str(const uint8_t *mac);

void mac48_str_to_bin(uint8_t *mac, const char *str);

uint16_t in_csum_update(uint16_t old_csum, uint16_t len, const uint16_t *old_data, const uint16_t *new_data);

/**
 * Other routines.
 */

extern const UT_icd ut_uint16_icd;

int uint16_cmp(const void *arg1, const void *arg2);

int enable_coredump(void);

#endif // ZEROD_UTIL_H
