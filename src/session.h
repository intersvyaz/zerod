#ifndef ZEROD_SESSION_H
#define ZEROD_SESSION_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <uthash/uthash.h>
#include "atomic.h"
#include "router/netproto.h"
#include "speed_meter.h"

struct znat;
struct zclient;

enum {
    SF_EXISTING_ONLY  = 1, /**<! acquire only existing session */
    SF_NO_DHCP_SEARCH = 2  /**<! skip dhcp binding search      */
};

/**
 * Session.
 */
struct zsession
{
    // session ip (host order)
    uint32_t ip;
    // assigned client for this session
    struct zclient *client;

    // hardware address
    uint8_t hw_addr[HWADDR_MAC48_LEN];
    // hardware address availability flag
    bool has_hw_addr;
    // DHCP lease end time
    atomic_uint64_t dhcp_lease_end;

    // create time
    uint64_t create_time;
    // last activity time
    atomic_uint64_t last_activity;
    // last authentication time
    atomic_uint64_t last_auth;
    // last accounting update time
    atomic_uint64_t last_acct;

    // accounting alive flag
    bool accounting_alive;
    // delete flag (for overlord)
    atomic_bool delete_flag;

    // packet counters
    atomic_uint32_t packets_up;
    atomic_uint32_t packets_down;
    // traffic counters in bytes
    atomic_uint64_t traff_up;
    atomic_uint64_t traff_down;

    // reference count
    atomic_size_t refcnt;

    // last NAT cleanup time (clock)
    uint64_t last_nat_cleanup;
    // lock for NAT allocating
    pthread_spinlock_t _nat_lock;
    // NAT handle
    struct znat *nat;

    // rwlock
    pthread_rwlock_t lock_client;
    // hash handle (lookup by ip)
    UT_hash_handle hh;

    // maximum session duration (microseconds)
    atomic_uint64_t max_duration;
    // interval between accounting update (microseconds)
    atomic_uint64_t acct_interval;

    // DNS Amplification attack detecting
    struct speed_meter dns_speed;
    bool is_dns_attack;
};

struct zsession *session_acquire(uint32_t ip, uint32_t flags);

void session_release(struct zsession *sess);

void session_remove(struct zsession *sess);

void session_destroy(struct zsession *sess);

struct znat *session_get_nat(struct zsession *sess, bool allocate);

#endif // ZEROD_SESSION_H
