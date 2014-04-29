#ifndef CLIENT_H
#define CLIENT_H

#include <stdint.h>
#include <pthread.h>
#include <stdio.h>

#include <uthash/uthash.h>
#include <uthash/utarray.h>
#include <uthash/utstring.h>

#include "util.h"

struct zforwarder;
struct zfirewall;
struct zcrules;
struct zsession;

/**
 * Client.
 */
struct zclient {
    // user id
    uint32_t id;
    // user login
    char* login;

    // traffic bandwith buckets
    struct token_bucket bw_bucket[DIR_MAX];

    // p2p policer flag
    uint8_t p2p_policer;

    // forwarder handle
    struct zforwarder *forwarder;
    // firewall handle
    struct zfirewall *firewall;

    // current speed
    struct speed_meter speed[DIR_MAX];

    // last p2p throttling activation
    uint64_t last_p2p_throttle;

    // reference count (atomic)
    u_int refcnt;
    // lock
    pthread_spinlock_t lock;
    // hash handle (lookup by id)
    UT_hash_handle hh;

    // related session pointers
    UT_array sessions;
};

struct zclient *client_create();
struct zclient *client_acquire(uint32_t id);
void client_destroy(struct zclient *client);
void client_release(struct zclient *client);

void client_session_add(struct zclient *client, const struct zsession *sess);
void client_session_remove(struct zclient *client, const struct zsession *sess);

struct zforwarder *client_get_forwarder(struct zclient *client, bool allocate);
struct zfirewall *client_get_firewall(struct zclient *client, bool allocate);

void client_apply_rules(struct zclient *client, struct zcrules *rules);
void client_dump_rules(struct zclient *client, UT_string *rules);

#endif // CLIENT_H
