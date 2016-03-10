#ifndef ZEROD_UTIL_H
#define ZEROD_UTIL_H

#include <inttypes.h>
#include <stdbool.h>
#include <uthash/utarray.h>

#ifndef likely
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#endif /* likely and unlikely */

#define ARRAYSIZE(x) (sizeof(x)/sizeof((x)[0]))

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) > (y) ? (x) : (y))

/**
 * Network manipulation routines.
 */

// get from IP address and CIDR ending address in subnet
#define IP_RANGE_END(ip, cidr) ((cidr == 32u ? (ip) : (ip) | (((uint32_t)~0u) >> (cidr))))

typedef struct
{
    uint32_t ip_start;
    uint32_t ip_end;
} ip_range_t;

extern const UT_icd ut_ip_range_icd;

int ip_range_cmp(const void *arg1, const void *arg2);

int ipv4_to_str(uint32_t ip, char *buf, uint32_t buf_len);

int ipv4_to_u32(const char *src, uint32_t *dst);

int getpeerip(int socket, char *buf, uint32_t buf_len);

int mac48_bin_to_str(const uint8_t *mac, char *buf, size_t buf_len);

void mac48_str_to_bin(uint8_t *mac, const char *str);

uint16_t in_csum_update(uint16_t old_csum, uint16_t len, const uint16_t *old_data, const uint16_t *new_data);

/**
 * Other routines.
 */

extern const UT_icd ut_uint16_icd;
extern const UT_icd ut_uint32_icd;

int uint16_cmp(const void *arg1, const void *arg2);

int util_enable_coredump(void);

#endif // ZEROD_UTIL_H
