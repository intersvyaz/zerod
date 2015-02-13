#ifndef UTIL_H
#define UTIL_H

#include <inttypes.h>
#include <sys/types.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <pthread.h>

#include <uthash/utarray.h>

#include "atomic.h"

#define ZTIME_NO_CACHE 1

#ifndef likely
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#endif /* likely and unlikely */

#if __BYTE_ORDER == __LITTLE_ENDIAN
#   define ntohll(x)    __bswap_64 (x)
#   define htonll(x)    __bswap_64 (x)
#endif

// get from IP address and CIDR ending address in subnet
#define IP_RANGE_END(ip, cidr) (cidr == 32u ? (ip) : (ip) | (((uint32_t)~0u) >> (cidr)))

#define ARRAYSIZE(x) sizeof(x)/sizeof((x)[0])

struct token_bucket {
    // max tokens in bucket
    atomic_uint64_t max_tokens;
    // available tokens count
    atomic_uint64_t tokens;
    // last update time in microseconds
    atomic_uint64_t last_update;
};

struct ip_range {
    uint32_t ip_start;
    uint32_t ip_end;
};

enum flow_dir {
    DIR_UP = 0,
    DIR_DOWN = 1,
    DIR_MAX = 2
};

#define SPEED_METER_BACKLOG 5

struct speed_meter {
    // current index
    atomic_size_t i;
    // last calculated speeds
    struct {
        atomic_uint64_t speed;
        atomic_uint64_t timestamp;
    } backlog[SPEED_METER_BACKLOG];
    // speed aux
    atomic_uint64_t speed_aux;
    // last calculation speed
    atomic_uint64_t last_update;
};

extern const UT_icd ut_uint16_icd;
extern const UT_icd ut_ip_range_icd;

uint64_t ztime(bool refresh);
uint64_t zclock(bool refresh);

void token_bucket_init(struct token_bucket *bucket, uint64_t max_tokens);

void token_bucket_destroy(struct token_bucket *bucket);

int token_bucket_update(struct token_bucket *bucket, uint64_t tokens);

void token_bucket_rollback(struct token_bucket *bucket, uint64_t tokens);

const char *hex_dump(unsigned const char *p, u_int len, u_int lim, char *dst);

int ip_range_cmp(const void *arg1, const void *arg2);

int ptr_cmp(const void **arg1, const void **arg2);

int uint16_cmp(const void *arg1, const void *arg2);

int str_ends_with(const char *str, const char *suffix);

void strtolower(char *str);

void strtoupper(char *str);

const char *ipv4_to_str(uint32_t ip);

int ipv4_to_u32(const char *src, uint32_t *dst);

/**
* Speed meter functions
*/

void spdm_init(struct speed_meter *speed);

void spdm_destroy(struct speed_meter *speed);

void spdm_update(struct speed_meter *speed, uint64_t count);

uint64_t spdm_calc(struct speed_meter *speed);

/**
* Safe string to integer convert functions
*/

int str_to_u64(const char *str, uint64_t *val);

int str_to_u32(const char *str, uint32_t *val);

int str_to_u16(const char *str, uint16_t *val);

int str_to_u8(const char *str, uint8_t *val);

int enable_coredump(void);

#endif // UTIL_H
