#ifndef ZEROD_SCOPE_H
#define ZEROD_SCOPE_H

#include <pcap/pcap.h>
#include <freeradius-client.h>
#include "config.h"
#include "session_db.h"
#include "client_db.h"
#include "speed_meter.h"
#include "token_bucket.h"
#include "blacklist.h"
#include "scope_rules.h"
#include "dhcp.h"

struct event;

enum
{
    SF_EXISTING_ONLY = 1, /*<<! acquire only existing session */
};

typedef struct zscope_struct
{
    /*<<! scope config */
    const zconfig_scope_t *cfg;

    /*<<! radius handle */
    rc_handle *radh;

    /*<<! Session database */
    zsession_db_t *session_db;
    /*<<! Client database handle */
    zclient_db_t *client_db;

    /*<<! Never authenticated session counter */
    atomic_size_t session_new_count;
    /*<<! Authenticated session counter */
    atomic_size_t session_unauth_count;

    /*<<! blacklist handle */
    zblacklist_t *blacklist;
    /*<<! blacklist reload event handle */
    struct event *blacklist_reload_event;
    /*<<! blocked requests counter */
    atomic_uint64_t blacklist_hits;

    /*<<! dhcp handle */
    zdhcp_t *dhcp;
    /*<<! dhcp cleanup event handle */
    struct event *dhcp_cleanup_event;

    /*<<! security */
    struct
    {
        /*<<! arp errors counter */
        atomic_uint64_t arp_errors;
        /*<<! ip errors counter */
        atomic_uint64_t ip_errors;
    } security;

    /*<<! hash handle (lookup by cfg->name) */
    UT_hash_handle hh;
} zscope_t;

/*
 *
 */

zscope_t *zscope_new(zconfig_scope_t *cfg);
void zscope_free(zscope_t *scope);
void zscope_apply_rules(zscope_t *scope, const zscope_rules_t *rules);

/*
 * SESSION/CLIENT
 */

zsession_t *zscope_session_acquire(zscope_t *scope, uint32_t ip, uint32_t flags);
void zscope_session_remove(zscope_t *scope, zsession_t *session);
void zscope_session_rules_apply(zscope_t *scope, zsession_t *session, const zclient_rules_t *rules);
bool zscope_is_session_dhcp_expired(const zscope_t *scope, const zsession_t *session);

/*
 * DHCP
 */

void zscope_dhcp_bind(zscope_t *scope, const uint8_t *mac, uint32_t ip, uint64_t lease_time);
bool zscope_dhcp_is_valid_mac_ip(zscope_t *scope, const uint8_t *mac, uint32_t ip);

#endif // ZEROD_SCOPE_H
