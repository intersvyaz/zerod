#ifndef ZEROD_CLIENT_RULES_H
#define ZEROD_CLIENT_RULES_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <uthash/utarray.h>
#include <uthash/utstring.h>
#include "firewall.h"
#include "forwarder.h"
#include "util.h"
#include "util_time.h"

/**
 * Client rules declarations.
 */

typedef struct zcr_port_struct zcr_port_t;
typedef struct zcr_forward_struct zcr_forward_t;
typedef struct zcr_deferred_struct zcr_deferred_t;
typedef struct zclient_rules_struct zclient_rules_t;
typedef struct zclient_rule_parser_struct zclient_rule_parser_t;

/**
 * @brief Port firewall rule.
 */
struct zcr_port_struct
{
    /*<<! IP Protocol */
    zip_proto_t proto;
    /*<<! Access policy */
    zfwall_policy_t policy;
    /*<<! Destination port (network order) */
    uint16_t port;
    /*<<! Add flag */
    bool add;
} ;

/**
 * @brief Forwarding rule.
 */
struct zcr_forward_struct
{
    /*<<! IP Protocol */
    zip_proto_t proto;
    /*<<! Destination port (network order) */
    uint16_t port;
    /*<<! IP forward to (network order) */
    uint32_t fwd_ip;
    /*<<! Optional new destination port (network order) */
    uint16_t fwd_port;
    /*<<! Add flag */
    bool add;
};

/**
 * @brief Deferred rule.
 */
struct zcr_deferred_struct
{
    /*<<! Microseconds timestamp when this rule must be applied (use monotonic clock) */
    zclock_t when;
    /*<<! rule to apply */
    char *rule;
};

struct zclient_rules_struct
{
    struct
    {
        unsigned user_id:1;
        unsigned login:1;
        unsigned bw_up:1;
        unsigned bw_down:1;
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
    uint64_t bw_up;
    // max download bandwidth
    uint64_t bw_down;

    UT_array fwd_rules;
    UT_array port_rules;
    UT_array deferred_rules;
};

zclient_rule_parser_t *zclient_rule_parser_new(void);

void zclient_rule_parser_free(zclient_rule_parser_t *parser);

bool zclient_rule_parse(const zclient_rule_parser_t *parser, zclient_rules_t *rules, const char *rule);

void zclient_rules_init(zclient_rules_t *rules);

void zclient_rules_destroy(zclient_rules_t *rules);

void zclient_rules_make_identity(UT_string *string, uint32_t user_id, const char *login);

void zclient_rules_make_bw(UT_string *string, uint64_t bw, zflow_dir_t flow_dir);

void zclient_rules_make_ports(UT_string *string, zip_proto_t proto, zfwall_policy_t policy, const uint16_t *ports,
                              size_t count);

void zclient_rules_make_fwd(UT_string *string, zip_proto_t proto, const zfwd_rule_t *fwd_rule);

void zclient_rules_make_speed(UT_string *string, uint64_t speed, zflow_dir_t flow_dir);

void zclient_rules_make_session(UT_string *string, const char *ip);

void zclient_rules_make_deferred(UT_string *string, const zcr_deferred_t *def_rule);

int zcr_deferred_cmp(const void *arg1, const void *arg2);

zcr_deferred_t *zcr_deferred_dup(const zcr_deferred_t *src);

#endif // ZEROD_CLIENT_RULES_H
