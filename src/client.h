#ifndef ZEROD_CLIENT_H
#define ZEROD_CLIENT_H

#include <stdint.h>
#include <pthread.h>
#include <stdio.h>

#include <uthash/uthash.h>
#include <uthash/utarray.h>
#include <uthash/utstring.h>

#include "token_bucket.h"
#include "speed_meter.h"
#include "client_rules.h"

/**
 * Typedefs.
 */
struct zclient_db_struct;
typedef struct zclient_struct zclient_t;

/**
 * Client declarations.
 */
struct zclient_struct
{
    /*<<! user id */
    atomic_uint32_t id;
    /*<<! user login */
    char *login;

    /*<<! create timestamp */
    ztime_t create_time;

    /*<<! bandwidth buckets */
    token_bucket_t band[DIR_MAX];

    /*<<! forwarder handle */
    zforwarder_t *forwarder;
    /*<<! firewall handle */
    zfirewall_t *firewall;

    /*<<! current speed */
    speed_meter_t speed[DIR_MAX];

    /*<<! reference counter */
    atomic_size_t refcnt;
    /*<<! access lock */
    pthread_spinlock_t lock;

    /*<<! hash handle (lookup by id) */
    UT_hash_handle hh;

    /*<<! array of related sessions IP (host order) */
    UT_array sessions;

    /*<<! deferred rules array (sorted in desc order by time field) */
    UT_array deferred_rules;
};

zclient_t *zclient_new(const zclient_rules_t *default_rules);

void zclient_free(zclient_t *client);

void zclient_release(zclient_t *client);

void zclient_session_add(zclient_t *client, uint32_t ip);

void zclient_session_remove(zclient_t *client, uint32_t ip);

zforwarder_t *zclient_forwarder(zclient_t *client, bool allocate);

zfirewall_t *zclient_firewall(zclient_t *client, bool allocate);

void zclient_apply_rules(zclient_t *client, const zclient_rules_t *rules);

void zclient_dump_rules(zclient_t *client, UT_string *rules);

void zclient_apply_deferred_rules(zclient_t *client);

#endif // ZEROD_CLIENT_H
