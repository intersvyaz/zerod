#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <uthash/uthash.h>

#include "atomic.h"

struct znat;
struct zclient;

/**
* Session.
*/
struct zsession {
    // session ip (host order)
    uint32_t ip;
    // assigned client for this session
    struct zclient *client;

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
};

struct zsession *session_acquire(uint32_t ip, bool existing_only);

void session_release(struct zsession *sess);

void session_remove(struct zsession *sess);

void session_destroy(struct zsession *sess);

struct znat *session_get_nat(struct zsession *sess, bool allocate);

#endif // SESSION_H
