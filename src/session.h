#ifndef ZEROD_SESSION_H
#define ZEROD_SESSION_H

#include <stdbool.h>
#include <netinet/in.h>
#include <pthread.h>

#include <uthash/uthash.h>

#include "atomic.h"
#include "speed_meter.h"
#include "netdef.h"
#include "config.h"

/**
 * Typedefs.
 */
typedef struct zsession_struct zsession_t;

struct zsession_struct
{
    /*<<! session IP (host order) */
    uint32_t ip;
    /*<<! session ip string */
    char ip_str[INET_ADDRSTRLEN];

    /*<<! assigned client for this session */
    struct zclient_struct *_client;
    /*<<! client access lock */
    pthread_spinlock_t _lock_client;

    /*<<! create timestamp */
    ztime_t create_time;
    /*<<! last activity timestamp */
    atomic_ztime_t last_activity;
    /*<<! last authentication timestamp */
    atomic_ztime_t last_auth;
    /*<<! last accounting update timestamp */
    atomic_ztime_t last_acct;

    /*<<! accounting alive flag */
    bool accounting_alive;
    /*<<! is delete queued (for overlord) */
    atomic_bool delete_queued;
    /*<<! is session already deleted */
    bool deleted;

    /*<<! packet counters */
    atomic_uint32_t packets_up;
    atomic_uint32_t packets_down;
    /*<<! traffic counters (in bytes) */
    atomic_uint64_t traff_up;
    atomic_uint64_t traff_down;

    /*<<! reference count */
    atomic_size_t refcnt;

    /*<<! last NAT cleanup timestamp (clock) */
    uint64_t last_nat_cleanup;
    /*<<! lock for NAT allocating */
    pthread_spinlock_t _lock_nat;
    /*<<! NAT handle */
    znat_t *nat;

    /*<<! access lock */
    pthread_rwlock_t lock;

    /*<<! hash handle (lookup by ip) */
    UT_hash_handle hh;

    /*<<! session timeout (microseconds) */
    atomic_uint64_t timeout;
    /*<<! session idle timeout (microseconds) */
    atomic_uint64_t idle_timeout;
    /*<<! accounting update interval (microseconds) */
    atomic_uint64_t acct_interval;
};

zsession_t *zsession_new(uint32_t ip, const zconfig_scope_t *cfg);

void zsession_release(zsession_t *session);

void zsession_free(zsession_t *session);

znat_t *zsession_get_nat(zsession_t *sess, bool allocate);

void zsession_nat_cleanup(zsession_t *sess);

struct zclient_struct *zsession_get_client(zsession_t *session);

void zsession_set_client(zsession_t *session, struct zclient_struct *client);

inline static bool zsession_is_timeout(const zsession_t *session)
{
    uint64_t timeout = atomic_load_acquire(&session->timeout);
    if (timeout) {
        return ztime() > (session->create_time + timeout);
    } else {
        return false;
    }
}

inline static bool zsession_is_idle_timeout(const zsession_t *session)
{
    uint64_t idle_timeout = atomic_load_acquire(&session->idle_timeout);
    if (idle_timeout) {
        return ztime() > (atomic_load_acquire(&session->last_activity) + idle_timeout);
    } else {
        return false;
    }
}

#endif // ZEROD_SESSION_H
