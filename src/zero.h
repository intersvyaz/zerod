#ifndef ZERO_H
#define ZERO_H

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>

#include <freeradius-client.h>
#include <uthash/utarray.h>

#include "netmap.h"
#include "util.h"
#include "router/router.h"

#define MAX_THREAD_NAME 16

/**
* For decreasing storage access concurrency used dividing one type of storage to many substorages.
* For example session storage uses lookup by ip and we use for substorage selection lower bits of ip address.
*/

// storage mask
#define STORAGE_MASK 0b1111u
// number of storages
#define STORAGE_SIZE ((STORAGE_MASK) + 1)
// retrieve storage index
#define STORAGE_IDX(x) ((x) & STORAGE_MASK)

#define UPSTREAM_MAX 64

// 2 mins
#define P2P_THROTTLE_TIME 120000000

enum event_prio {
    HIGH_PRIO,
    LOW_PRIO,
    PRIO_COUNT
};

struct ip_range;
struct event_base;
struct evconnlistener;
struct zsrules;

struct zif_pair {
    // LAN interface name
    char lan[IFNAMSIZ];
    // WAN interface name
    char wan[IFNAMSIZ];
    // affinity
    uint16_t affinity;
};

struct zoverlord {
    // thread index
    u_int idx;
    // thread handle
    pthread_t thread;
};

struct zring {
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
    struct {
        struct {
            // value counter
            atomic_uint64_t count;
            struct speed_meter speed;
        } all, passed, client;
    } packets[DIR_MAX], traffic[DIR_MAX];
};

struct zupstream {
    struct token_bucket p2p_bw_bucket[DIR_MAX];
    struct speed_meter speed[DIR_MAX];
};

struct zconfig {
    // array of interface pairs
    UT_array interfaces;
    // wait time before start running operations on interfaces (seconds)
    u_int iface_wait_time;

    // overlord threads count
    u_int overlord_threads;

    // unauthorized client bandwidth limits (bytes)
    uint64_t unauth_bw_limit[DIR_MAX];

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

    // inactivity timeout (microseconds)
    uint64_t session_inactive_timeout;
    // session accounting update interval (microseconds)
    uint64_t session_acct_interval;
    // session authentication interval (microseconds)
    uint64_t session_auth_interval;
    // session maximum duration (microseconds)
    uint64_t session_max_duration;

    // remote control address and port
    char *rc_listen_addr;

    // default upstream p2p bandwidth limits (bytes)
    uint64_t upstream_p2p_bw[DIR_MAX];

    // non-p2p ports (uint16_t array)
    UT_array p2p_ports_whitelist;

    // p2p ports (uint16_t array)
    UT_array p2p_ports_blacklist;

    // non-client bandwidth limits (bytes)
    uint64_t non_client_bw[DIR_MAX];

    // initial client bucket size (bytes)
    uint64_t initial_client_bucket_size;

    // total monitoring bandwidth limit (bytes)
    uint64_t monitors_total_bw_limit;

    // monitoring bandwidth limit per connection (bytes)
    uint64_t monitors_conn_bw_limit;

    // enable coredumps
    u_int enable_coredump;

#ifndef NDEBUG
    struct {
        // print all packets in hex to stdout
        bool hexdump;
    } dbg;
#endif
};

struct zinstance {
    // configuration, must not be used directly
    const struct zconfig *_cfg;
    // execution abort flag
    atomic_bool abort;

    // active session count
    atomic_size_t sessions_cnt;
    // authed clients count
    atomic_size_t clients_cnt;
    // unauthed sessions count
    atomic_size_t unauth_sessions_cnt;

    // global lock for s_sessions hash
    pthread_rwlock_t sessions_lock[STORAGE_SIZE];
    // global lock for s_clients hash
    pthread_rwlock_t clients_lock[STORAGE_SIZE];

    // hash ip->session
    struct zsession *sessions[STORAGE_SIZE];
    // hash user_id->client
    struct zclient *clients[STORAGE_SIZE];

    // radius handle
    rc_handle *radh;

    // master thread event base
    struct event_base *master_event_base;
    // remote control tcp connection listener
    struct evconnlistener *rc_tcp_listener;

    // rings information (zring array)
    UT_array rings;

    // upstreams
    struct zupstream upstreams[UPSTREAM_MAX];

    // non-client info
    struct {
        struct token_bucket bw_bucket[DIR_MAX];
        struct speed_meter speed[DIR_MAX];
    } non_client;

    // monitoring stuff
    pthread_rwlock_t monitors_lock;
    struct token_bucket monitors_bucket;
    UT_array monitors;

#ifndef NDEBUG
    struct {
        struct {
            atomic_uint64_t packets;
            atomic_uint64_t bytes;
        } traff_counter[PROTO_MAX][65536];
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

int zero_instance_init(const struct zconfig *zconf);

void zero_instance_run(void);

void zero_instance_free(void);

void zero_instance_stop(void);

void zero_apply_rules(struct zsrules *rules);

// config.c
int zero_config_load(const char *path, struct zconfig *zconf);

void zero_config_free(struct zconfig *zconf);

// packet.c
enum traffic_type {
    TRAF_NON_CLIENT,
    TRAF_CLIENT,
    TRAF_HOME
};

int process_packet(unsigned char *packet, u_int len, enum flow_dir flow_dir, enum traffic_type *traf_type);

// master.c
void master_worker(void);

// overlord.c
void *overlord_worker(void *arg);

// remotectl.c
int rc_listen(void);

#endif // ZERO_H
