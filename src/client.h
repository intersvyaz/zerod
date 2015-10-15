#ifndef ZEROD_CLIENT_H
#define ZEROD_CLIENT_H

#include <stdint.h>
#include <pthread.h>
#include <stdio.h>

#include <uthash/uthash.h>
#include <uthash/utarray.h>
#include <uthash/utstring.h>

#include "util.h"
#include "token_bucket.h"
#include "speed_meter.h"
#include "router/router.h"

struct zforwarder;
struct zfirewall;
struct zcrules;
struct zsession;
struct zclient_db;

/**
 * Client.
 */
struct zclient
{
    // user id
    uint32_t id;
    // user login
    char *login;
    // create time
    uint64_t create_time;
    struct zclient_db *db;

    // band buckets
    struct token_bucket band[DIR_MAX];

    // p2p policy flag
    uint8_t p2p_policy;

    // forwarder handle
    struct zforwarder *forwarder;
    // firewall handle
    struct zfirewall *firewall;

    // current speed
    struct speed_meter speed[DIR_MAX];

    // last p2p throttling activation (clock)
    atomic_uint64_t last_p2p_throttle;

    // reference count
    atomic_size_t refcnt;
    // lock
    pthread_spinlock_t lock;
    // hash handle (lookup by id)
    UT_hash_handle hh;

    // related sessions array
    UT_array sessions;

    // deferred rules array (sorted in desc order by time field)
    UT_array deferred_rules;
};

struct zclient_db *client_db_new(void);

void client_db_free(struct zclient_db *db);

void client_db_find_or_set_id(struct zclient_db *db, uint32_t id, struct zclient **client);

uint32_t client_db_get_count(struct zclient_db *db);

struct zclient *client_create(const struct zcrules *default_rules);

struct zclient *client_acquire(struct zclient_db *db, uint32_t id);

void client_destroy(struct zclient *client);

void client_release(struct zclient *client);

void client_session_add(struct zclient *client, const struct zsession *sess);

void client_session_remove(struct zclient *client, const struct zsession *sess);

struct zforwarder *client_get_forwarder(struct zclient *client, bool allocate);

struct zfirewall *client_get_firewall(struct zclient *client, bool allocate);

void client_apply_rules(struct zclient *client, const struct zcrules *rules);

void client_dump_rules(struct zclient *client, UT_string *rules);

#endif // ZEROD_CLIENT_H
