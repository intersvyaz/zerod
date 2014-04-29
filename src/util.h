#ifndef UTIL_H
#define UTIL_H

#include <inttypes.h>
#include <sys/types.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <pthread.h>

#include <uthash/utarray.h>

#define ATOMIC_TOKEN_BUCKET
#define ATOMIC_SPEED_METER
#define ZTIME_NO_CACHE 1

#ifndef likely
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#endif /* likely and unlikely */

#if __BYTE_ORDER == __LITTLE_ENDIAN
#   define ntohll(x)    __bswap_64 (x)
#   define htonll(x)    __bswap_64 (x)
#endif

// get from ip and cidr ending address in subnet
#define IP_RANGE_END(ip, cidr) (ip) | (((uint32_t)~0) >> (cidr))

#define ARRAYSIZE(x) sizeof(x)/sizeof((x)[0])

struct token_bucket {
    // max tokens in bucket (atomic)
    uint64_t max_tokens;
    // available tokens count (atomic)
    uint64_t tokens;
    // last update time in microseconds (atomic)
    uint64_t last_update;
#ifndef ATOMIC_TOKEN_BUCKET
    // lock
    pthread_spinlock_t lock;
#endif
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
    unsigned i;
    // last calculated speeds
    struct {
        uint64_t speed;
        uint64_t timestamp;
    } backlog[SPEED_METER_BACKLOG];
    // speed aux
    uint64_t speed_aux;
    // last calculation speed
    uint64_t last_update;
#ifndef ATOMIC_SPEED_METER
    // lock
    pthread_spinlock_t lock;
#endif
};

extern const UT_icd ut_uint16_icd;
extern const UT_icd ut_ip_range_icd;

uint64_t ztime(bool refresh);

void token_bucket_init(struct token_bucket *bucket, uint64_t max_tokens);
void token_bucket_destroy(struct token_bucket *bucket);
int token_bucket_update(struct token_bucket *bucket, uint64_t tokens);
void token_bucket_rollback(struct token_bucket *bucket, uint64_t tokens);

const char *hex_dump(const char *p, u_int len, u_int lim, char *dst);

int ip_range_cmp(const void *arg1, const void *arg2);
int uint16_cmp(const void *arg1, const void *arg2);

int str_ends_with(const char *str, const char *suffix);
void strtolower(char *str);
void strtoupper(char *str);

const char *ipv4_to_str(uint32_t ip);
int ipv4_to_u32(const char *src, uint32_t *dst);

void spdm_init(struct speed_meter *speed);
void spdm_destroy(struct speed_meter *speed);
void spdm_update(struct speed_meter *speed, uint64_t count);
uint64_t spdm_calc(struct speed_meter *speed);

#endif // UTIL_H
