#ifndef ZEROD_CONFIG_H
#define ZEROD_CONFIG_H

#include <stdint.h>
#include <net/if.h>
#include <uthash/utarray.h>
#include <uthash/uthash.h>
#include "client_rules.h"

typedef UT_array zsubnet_group_t;

typedef struct zifpair_struct
{
    /*<<! LAN interface name */
    char lan[IFNAMSIZ];
    /*<<! WAN interface name */
    char wan[IFNAMSIZ];
    /*<<! affinity */
    uint16_t affinity;
} zifpair_t;

typedef struct zconfig_scope_struct
{
    /*<<! scope name */
    char *name;

    /*<<! client subnets */
    zsubnet_group_t client_subnets;
    /*<<! local subnets */
    zsubnet_group_t local_subnets;
    /*<<! local subnets exclusions */
    zsubnet_group_t local_subnets_exclusions;

    /*<<! default client rules */
    zclient_rules_t default_client_rules;

    struct
    {
        /*<<! perform authentication */
        bool auth;
        /*<<! perform accounting */
        bool acct;
        /*<<! configuration file path */
        char *config;
        /*<<! NAS identifier */
        char *nas_id;
    } radius;

    struct
    {
        /*<<! accounting update interval (microseconds) */
        uint64_t acct_interval;
        /*<<! authentication interval (microseconds) */
        uint64_t auth_interval;
        /*<<! session timeout (microseconds) */
        uint64_t timeout;
        /*<<! session idle timeout (microseconds) */
        uint64_t idle_timeout;
    } session;

    /*<<! ports whitelist (uint16_t array) */
    UT_array ports_whitelist;

    struct {
        /*<<! DHCP snooping */
        bool dhcp_snooping;
        /*<<! DHCP default lease time (microseconds) */
        uint64_t dhcp_default_lease_time;
        /*<<! dynamic ARP inspection mode */
        bool arp_protect;
        /*<<! IP source guard */
        bool ip_protect;
    } security;

    struct
    {
        /*<<! flag */
        bool enabled;
        /*<<! file path */
        char *file;
        /*<<! reload interval (microseconds) */
        uint64_t reload_interval;
    } blacklist;
} zconfig_scope_t;

typedef struct zconfig_struct
{
    /*<<! array of interface pairs */
    UT_array interfaces;

    /*<<! wait time before start running operations on interfaces (seconds) */
    u_int iface_wait_time;

    /*<<! overlord threads count */
    u_int overlord_threads;

    /*<<! remote control listen address and port */
    char *remotectl_listen;

    struct
    {
        /*<<! total bandwidth (bytes) */
        uint64_t total_bandwidth;

        /*<<! bandwidth per connection (bytes) */
        uint64_t conn_bandwidth;
    } monitor;

    /*<<! non-client bandwidth (bytes) */
    uint64_t non_client_bandwidth[DIR_MAX];

    struct {
        bool lldp_pass_in;
        bool lldp_pass_out;
    } sw;

    /*<<! enable coredump */
    bool enable_coredump;

    /*<<! array of zconfig_scope_t */
    UT_array scopes;

#ifndef NDEBUG
    struct
    {
        /*<<! print all packets in hex to stdout */
        bool hexdump;
    } dbg;
#endif
} zconfig_t;

extern const UT_icd ut_zifpair_t_icd;

bool zconfig_load(const char *path, zconfig_t *zconf);

void zconfig_destroy(zconfig_t *zconf);

bool zsubnet_group_ip_belongs(const zsubnet_group_t *group, uint32_t ip);

#endif // ZEROD_CONFIG_H
