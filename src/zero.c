#include <stddef.h> // fix annoying bug in clion
#include "zero.h"
#include <arpa/inet.h>
#include <signal.h>
#include <event2/event.h>
#include <event2/thread.h>
#include "log.h"
#include "client.h"
#include "session.h"
#include "srules.h"
#include "monitor.h"
#include "packet.h"
#include "blacklist.h"

// global app instance
struct zinstance g_zinst;

const UT_icd ut_zif_pair_icd _UNUSED_ = {sizeof(struct zif_pair), NULL, NULL, NULL};
const UT_icd ut_zring_icd _UNUSED_ = {sizeof(struct zring), NULL, NULL, NULL};

/**
 * Initialize app instance structure.
 * @param[in] zconf Configuration for instance.
 * @return Zero on success.
 */
int zero_instance_init(const struct zconfig *zconf)
{
    memset(&g_zinst, 0, sizeof(g_zinst));

    // store options in global instance
    g_zinst._cfg = zconf;

    // initialize storage locks.
    for (size_t i = 0; i < STORAGE_SIZE; i++) {
        if (unlikely(0 != pthread_rwlock_init(&g_zinst.sessions_lock[i], NULL))) {
            ZERO_LOG(LOG_ERR, "failed to initialize rwlock");
            return -1;
        }
    }

    g_zinst.client_db = client_db_new();
    if (unlikely(!g_zinst.client_db)) {
        ZERO_LOG(LOG_ERR, "failed to create client db");
        return -1;
    }

    // initialize radius stuff
    g_zinst.radh = rc_read_config(zcfg()->radius_config_file);
    if (unlikely(NULL == g_zinst.radh)) {
        ZERO_LOG(LOG_ERR, "failed to read radius client configuration file");
        return -1;
    }
    if (unlikely(0 != rc_read_dictionary(g_zinst.radh, rc_conf_str(g_zinst.radh, "dictionary")))) {
        ZERO_LOG(LOG_ERR, "failed to read radius client dictionary file");
        return -1;
    }

    // initialize libevent stuff.
    if (unlikely(0 != evutil_secure_rng_init())) {
        ZERO_LOG(LOG_ERR, "failed to seed random number generator");
        return -1;
    }
    if (unlikely(0 != evthread_use_pthreads())) {
        ZERO_LOG(LOG_ERR, "failed to init libevent threading model");
        return -1;
    }

    g_zinst.master_event_base = event_base_new();
    if (unlikely(NULL == g_zinst.master_event_base)) {
        ZERO_LOG(LOG_ERR, "failed to create master event loop");
        return -1;
    }
    event_base_priority_init(g_zinst.master_event_base, PRIO_COUNT);

    // initialize remote control stuff
    struct sockaddr_in rc_addr;
    int sa_len = sizeof(rc_addr);
    int ret = evutil_parse_sockaddr_port(zcfg()->rc_listen_addr, (struct sockaddr *) &rc_addr, &sa_len);
    if (unlikely((0 != ret) || (0 == rc_addr.sin_port))) {
        ZERO_LOG(LOG_ERR, "failed to parse rc_listen addr '%s' or missing port", zcfg()->rc_listen_addr);
        return -1;
    }

    // initialize interfaces
    {
        struct nmreq req;
        void *cached_mmap_memory = NULL;
        utarray_init(&g_zinst.rings, &ut_zring_icd);

        for (u_int i = 0; i < utarray_len(&zcfg()->interfaces); i++) {
            struct zif_pair *if_pair = (struct zif_pair *) utarray_eltptr(&zcfg()->interfaces, i);
            uint16_t lan_rings, wan_rings;

            if (0 != znm_info(if_pair->lan, &req)) {
                return -1;
            }
            lan_rings = req.nr_rx_rings;

            if (0 != znm_info(if_pair->wan, &req)) {
                return -1;
            }
            wan_rings = req.nr_rx_rings;

            if (lan_rings != wan_rings) {
                ZERO_LOG(LOG_ERR, "Interfaces pair %s<->%s has different rx ring count", if_pair->lan, if_pair->wan);
                return -1;
            }

            if (0 != znm_prepare_if(if_pair->lan)) {
                return -1;
            }
            if (0 != znm_prepare_if(if_pair->wan)) {
                return -1;
            }

            // initialize rings
            for (uint16_t j = 0; j < lan_rings; j++) {
                struct zring ring;
                memset(&ring, 0, sizeof(ring));

                ring.if_pair = if_pair;
                ring.ring_id = j;

                if (0 != znm_open(&ring.ring_lan, ring.if_pair->lan, ring.ring_id, cached_mmap_memory)) {
                    return -1;
                }
                // cache mmap'ed memory
                if (NULL == cached_mmap_memory) {
                    cached_mmap_memory = ring.ring_lan.mem;
                }
                if (0 != znm_open(&ring.ring_wan, ring.if_pair->wan, ring.ring_id, cached_mmap_memory)) {
                    return -1;
                }

                for (int dir = 0; dir < DIR_MAX; dir++) {
                    spdm_init(&ring.packets[dir].all.speed);
                    spdm_init(&ring.packets[dir].passed.speed);
                    spdm_init(&ring.traffic[dir].all.speed);
                    spdm_init(&ring.traffic[dir].passed.speed);
                }

                utarray_push_back(&g_zinst.rings, &ring);
            }
        }
    }

    // initialize upstream stuff
    for (size_t i = 0; i < ARRAYSIZE(g_zinst.upstreams); i++) {
        for (int dir = 0; dir < DIR_MAX; dir++) {
            token_bucket_init(&g_zinst.upstreams[i].band[dir], zcfg()->upstream_p2p_bandwidth[dir]);
            spdm_init(&g_zinst.upstreams[i].speed[dir]);
        }
    }

    // initialize non-client limits
    for (int dir = 0; dir < DIR_MAX; dir++) {
        token_bucket_init(&g_zinst.non_client.band[dir], zcfg()->non_client_bandwidth[dir]);
        spdm_init(&g_zinst.non_client.speed[dir]);
    }

    g_zinst.monitor = zmonitor_new(zcfg()->monitors_total_bandwidth);
    if (unlikely(!g_zinst.monitor)) {
        ZERO_LOG(LOG_ERR, "failed to create new zmonitor instance");
        return -1;
    }

    // arp inspection
    g_zinst.dhcp = zdhcp_new();
    if (unlikely(!g_zinst.dhcp)) {
        ZERO_LOG(LOG_ERR, "failed to create new zdhcp instance");
        return -1;
    }
    atomic_init(&g_zinst.arp.mode, zcfg()->arp_inspection);
    atomic_init(&g_zinst.arp.arp_errors, 0);
    atomic_init(&g_zinst.arp.ip_errors, 0);

    // blacklist
    if (zcfg()->blacklist_file) {
        g_zinst.blacklist = zblacklist_new();
        if (unlikely(!g_zinst.blacklist)) {
            ZERO_LOG(LOG_ERR, "failed to create new blacklist instance");
            return -1;
        }
        if (0 != zblacklist_reload(g_zinst.blacklist, zcfg()->blacklist_file)) {
            return -1;
        }
    }

    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);

    g_zinst.start_time = ztime(true);

    return 0;
}

/**
 * Cleanup app instance.
 */
void zero_instance_free(void)
{
    if (g_zinst.radh) rc_destroy(g_zinst.radh);

    // clean storage.
    for (size_t i = 0; i < STORAGE_SIZE; i++) {
        pthread_rwlock_destroy(&g_zinst.sessions_lock[i]);

        struct zsession *sess, *tmp_sess;
        HASH_ITER(hh, g_zinst.sessions[i], sess, tmp_sess) {
            HASH_DELETE(hh, g_zinst.sessions[i], sess);
            session_destroy(sess);
        }
    }

    if (likely(g_zinst.client_db)) {
        client_db_free(g_zinst.client_db);
        g_zinst.client_db = NULL;
    }

    // clean rings.
    for (size_t i = 0; i < utarray_len(&g_zinst.rings); i++) {
        struct zring *ring = (struct zring *) utarray_eltptr(&g_zinst.rings, i);

        znm_close(&ring->ring_lan);
        znm_close(&ring->ring_wan);

        for (int dir = 0; dir < DIR_MAX; dir++) {
            spdm_destroy(&ring->packets[dir].all.speed);
            spdm_destroy(&ring->packets[dir].passed.speed);
            spdm_destroy(&ring->traffic[dir].all.speed);
            spdm_destroy(&ring->traffic[dir].passed.speed);
        }
    }
    utarray_done(&g_zinst.rings);

    // clean upstreams.
    for (size_t i = 0; i < ARRAYSIZE(g_zinst.upstreams); i++) {
        token_bucket_destroy(&g_zinst.upstreams[i].band[DIR_DOWN]);
        token_bucket_destroy(&g_zinst.upstreams[i].band[DIR_UP]);
        spdm_destroy(&g_zinst.upstreams[i].speed[DIR_DOWN]);
        spdm_destroy(&g_zinst.upstreams[i].speed[DIR_UP]);
    }

    if (likely(g_zinst.monitor)) {
        zmonitor_free(g_zinst.monitor);
        g_zinst.monitor = NULL;
    }

    if (likely(g_zinst.master_event_base)) {
        event_base_free(g_zinst.master_event_base);
    }

    if (likely(g_zinst.dhcp)) {
        zdhcp_free(g_zinst.dhcp);
        g_zinst.dhcp = NULL;
    }

    if (likely(g_zinst.blacklist)) {
        zblacklist_free(g_zinst.blacklist);
        g_zinst.blacklist = NULL;
    }
}

/**
 * Stop application instance.
 */
void zero_instance_stop(void)
{
    event_base_loopbreak(zinst()->master_event_base);
    atomic_store_explicit(&zinst()->abort, true, memory_order_release);
}

/**
 * Apply rules to app instance.
 * @param[in] rules Rules.
 */
void zero_apply_rules(struct zsrules *rules)
{
    // upstream rules.
    for (size_t uidx = 0; uidx < UPSTREAM_COUNT; uidx++) {
        for (int dir = 0; dir < DIR_MAX; dir++) {
            if (rules->have.upstream_bandwidth[uidx][dir]) {
                token_bucket_set_max(&zinst()->upstreams[uidx].band[dir], rules->upstream_bandwidth[uidx][dir]);
            }
        }
    }

    // non-client limits.
    for (int dir = 0; dir < DIR_MAX; dir++) {
        if (rules->have.non_client_bandwidth[dir]) {
            token_bucket_set_max(&zinst()->non_client.band[dir], rules->non_client_bandwidth[dir]);
        }
    }

    // ARP inspection
    if (rules->have.arp_inspection) {
        zinst()->arp.mode = rules->arp_inspection;
    }
}
