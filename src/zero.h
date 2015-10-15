#ifndef ZEROD_ZERO_H
#define ZEROD_ZERO_H

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>
#include <freeradius-client.h>
#include <uthash/utarray.h>
#include "speed_meter.h"
#include "token_bucket.h"
#include "netmap.h"
#include "util.h"
#include "router/router.h"
#include "crules.h"

/**
* For decreasing storage access concurrency used storage split to many buckets.
* For example, session storage uses lookup by ip and we use for buckets lower bits of ip address.
*/

// storage mask
#define STORAGE_MASK 0b1111u
// number of storage buckets
#define STORAGE_SIZE ((STORAGE_MASK) + 1)
// retrieve storage index
#define STORAGE_IDX(x) ((x) & STORAGE_MASK)

#define UPSTREAM_COUNT 64u

// 2 minutes (microseconds)
#define P2P_THROTTLE_TIME 120000000u

enum event_prio
{
    PRIO_HIGH,
    PRIO_LOW,
    PRIO_COUNT
};

enum arp_insp_mode
{
    AIM_OFF = 0,
    AIM_LOOSE = 1,
    AIM_STRICT = 2
};

struct ip_range;
struct event_base;
struct evconnlistener;
struct zsrules;
struct zmonitor;
struct zclient_db;
struct zblacklist;

struct zif_pair
{
    // LAN interface name
    char lan[IFNAMSIZ];
    // WAN interface name
    char wan[IFNAMSIZ];
    // affinity
    uint16_t affinity;
};

struct zoverlord
{
    // thread index
    u_int idx;
    // thread handle
    pthread_t thread;
};

struct zring
{
    // interfaces info
    struct zif_pair *if_pair;
    // thread handle
    pthread_t thread;
    // ring index
    uint16_t ring_id;
    // netmap rings
    struct znm_ring ring_lan;
    struct znm_ring ring_wan;
    // statistics
    struct
    {
        struct
        {
            atomic_uint64_t count;
            struct speed_meter speed;
        } all, passed, client;
    } packets[DIR_MAX], traffic[DIR_MAX];
};

struct zupstream
{
    struct token_bucket band[DIR_MAX];
    struct speed_meter speed[DIR_MAX];
};

struct zconfig
{
    // array of interface pairs
    UT_array interfaces;
    // wait time before start running operations on interfaces (seconds)
    u_int iface_wait_time;

    // overlord threads count
    u_int overlord_threads;

    struct zcrules default_client_rules;

    // client net list
    UT_array client_net;

    // home net list
    UT_array home_net;

    // home net exclude list
    UT_array home_net_exclude;

    // path to radius configuration file
    char *radius_config_file;
    // radius NAS identifier
    char *radius_nas_identifier;

    // DHCP default lease time (microseconds)
    uint64_t dhcp_default_lease_time;

    // session accounting update interval (microseconds)
    uint64_t session_acct_interval;
    // session authentication interval (microseconds)
    uint64_t session_auth_interval;
    // session maximum duration (microseconds)
    uint64_t session_max_duration;

    // remote control address and port
    char *rc_listen_addr;

    // default upstream p2p bandwidth (bytes)
    uint64_t upstream_p2p_bandwidth[DIR_MAX];

    // non-p2p ports (uint16_t array)
    UT_array p2p_ports_whitelist;

    // p2p ports (uint16_t array)
    UT_array p2p_ports_blacklist;

    // non-client bandwidth (bytes)
    uint64_t non_client_bandwidth[DIR_MAX];

    // initial client bucket size (bytes)
    uint64_t initial_client_bucket_size;

    // total monitoring bandwidth (bytes)
    uint64_t monitors_total_bandwidth;

    // monitoring bandwidth per connection (bytes)
    uint64_t monitors_conn_bandwidth;

    // dynamic ARP inspection mode
    u_int arp_inspection;

    // enable coredump
    u_int enable_coredump;

    // blacklist file path
    char *blacklist_file;

    // blacklist reload interval
    uint64_t blacklist_reload_interval;

    // DNS Amplification attack threshold detection
    uint64_t dns_attack_threshold;

#ifndef NDEBUG
    struct
    {
        // print all packets in hex to stdout
        bool hexdump;
    } dbg;
#endif
};

struct zinstance
{
    // configuration, must not be used directly
    const struct zconfig *_cfg;
    // execution abort flag
    atomic_bool abort;

    // start time (microseconds)
    uint64_t start_time;

    // active session count
    atomic_size_t sessions_cnt;
    // unauthed sessions count
    atomic_size_t unauth_sessions_cnt;

    struct zclient_db *client_db;

    // hash ip->session
    struct zsession *sessions[STORAGE_SIZE];
    // global lock for s_sessions hash
    pthread_rwlock_t sessions_lock[STORAGE_SIZE];


    // radius handle
    rc_handle *radh;

    // master thread event base
    struct event_base *master_event_base;
    // remote control tcp connection listener
    struct evconnlistener *rc_tcp_listener;

    // rings information (zring array)
    UT_array rings;

    // upstreams
    struct zupstream upstreams[UPSTREAM_COUNT];

    // non-client info
    struct
    {
        struct token_bucket band[DIR_MAX];
        struct speed_meter speed[DIR_MAX];
    } non_client;

    // monitoring stuff
    struct zmonitor *monitor;

    // dhcp binding
    struct zdhcp *dhcp;

    // blacklist
    struct zblacklist *blacklist;

    // arp inspection
    struct
    {
        atomic_uint mode;
        atomic_uint64_t arp_errors;
        atomic_uint64_t ip_errors;
    } arp;

#ifndef NDEBUG
    struct
    {
        struct
        {
            atomic_uint64_t packets;
            atomic_uint64_t bytes;
        } traff_counter[PROTO_MAX][L4_PORT_MAX];
    } dbg;
#endif
};

extern const UT_icd ut_zif_pair_icd;
extern const UT_icd ut_zring_icd;

// global app instance
extern struct zinstance g_zinst;

/**
* Global access to app instance.
* @return App instance.
*/
static inline struct zinstance *zinst(void)
{
    return &g_zinst;
}

/**
* Global access to app configuration.
* @return App config.
*/
static inline const struct zconfig *zcfg(void)
{
    return g_zinst._cfg;
}

static inline bool zero_is_abort(void)
{
    return (bool)atomic_load_explicit(&g_zinst.abort, memory_order_acquire);
}

int zero_instance_init(const struct zconfig *zconf);

void zero_instance_run(void);

void zero_instance_free(void);

void zero_instance_stop(void);

void zero_apply_rules(struct zsrules *rules);

// master.c
void master_worker(void);

// overlord.c
void *overlord_worker(void *arg);

// remotectl.c
int rc_listen(void);

#endif // ZEROD_ZERO_H
