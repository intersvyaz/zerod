#ifndef ZEROD_CRULES_H
#define ZEROD_CRULES_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <uthash/utarray.h>
#include <uthash/utstring.h>
#include "router/router.h"
#include "util.h"

struct zclient;
struct zsession;

struct zrule_port
{
    enum ipproto proto;
    enum port_rule type;
    // (network order)
    uint16_t port;
    bool add;
};

struct zrule_fwd
{
    enum ipproto proto;
    // (network order)
    uint16_t port;
    // (network order)
    uint32_t fwd_ip;
    // (network order)
    uint16_t fwd_port;
    bool add;
};

struct zrule_deferred
{
    // clock
    uint64_t when;
    // rule to apply
    char *rule;
};

struct zcrules
{
    struct
    {
        unsigned user_id:1;
        unsigned login:1;
        unsigned bw_up:1;
        unsigned bw_down:1;
        unsigned p2p_policy:1;
        unsigned port_rules:1;
        unsigned fwd_rules:1;
        unsigned deferred_rules:1;
        unsigned rmdeferred:1;
    } have;

    // user id
    uint32_t user_id;
    // user login
    char *login;
    // max upload bandwidth
    uint32_t bw_up;
    // max download bandwidth
    uint32_t bw_down;
    // p2p policy flag
    uint8_t p2p_policy;

    UT_array fwd_rules;
    UT_array port_rules;
    UT_array deferred_rules;
};

void crules_init(struct zcrules *rules);

int crules_parse(struct zcrules *rules, const char *rule);

void crules_free(struct zcrules *rules);

void crules_make_identity(UT_string *string, uint32_t user_id, const char *login);

void crules_make_bw(UT_string *string, uint64_t bw, enum flow_dir flow_dir);

void crules_make_p2p_policy(UT_string *string, uint8_t p2p_policy);

void crules_make_ports(UT_string *string, enum ipproto proto, enum port_rule type, const uint16_t *ports, size_t count);

void crules_make_fwd(UT_string *string, enum ipproto proto, const struct zfwd_rule *fwd_rule);

void crules_make_speed(UT_string *string, uint64_t speed, enum flow_dir flow_dir);

void crules_make_session(UT_string *string, const struct zsession *sess);

void crules_make_deferred(UT_string *string, const struct zrule_deferred *def_rule);

int zrule_deferred_cmp(const void *arg1, const void *arg2);

struct zrule_deferred *zrule_deferred_dup(const struct zrule_deferred *src);

#endif // ZEROD_CRULES_H
