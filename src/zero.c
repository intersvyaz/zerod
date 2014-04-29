#include "zero.h"

#include <stdlib.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <event2/event.h>
#include <event2/thread.h>

#include "netmap.h"
#include "log.h"
#include "client.h"
#include "session.h"
#include "srules.h"

// global app instance
struct zero_instance g_zinst;

const UT_icd ut_zif_pair_icd _UNUSED_ = {sizeof(struct zif_pair),NULL,NULL,NULL};
const UT_icd ut_zring_icd _UNUSED_ = {sizeof(struct zring),NULL,NULL,NULL};

/**
 * Process ring pair.
 * @param[in] rxring Source ring.
 * @param[in] txring Destination ring.
 * @param[in] flow_dir Flow direction.
 * @return
 */
static u_int process_rings(struct zring *info, enum flow_dir flow_dir)
{
    struct netmap_ring *tx, *rx;
    u_int rxcur, txcur, avail;

    if (DIR_DOWN == flow_dir) {
        rx = info->ring_wan.rx;
        tx = info->ring_lan.tx;
    } else if (DIR_UP == flow_dir) {
        rx = info->ring_lan.rx;
        tx = info->ring_wan.tx;
    } else {
        abort();
    }

    // print a warning if any of the ring flags is set (e.g. NM_REINIT)
    if (unlikely(rx->flags || tx->flags)) {
        ZERO_LOG(LOG_DEBUG, "rxflags %X txflags %X", rx->flags, tx->flags);
    }

    rxcur = rx->cur; // RX
    txcur = tx->cur; // TX

    avail = nm_ring_space(rx);
    if (avail > nm_ring_space(tx))
        avail = nm_ring_space(tx);

    u_int i = avail;
    while (likely(i-- > 0)) {
        struct netmap_slot *rs = &rx->slot[rxcur];
        struct netmap_slot *ts = &tx->slot[txcur];

        if (unlikely(ts->buf_idx < 2 || rs->buf_idx < 2)) {
            ZERO_LOG(LOG_DEBUG, "wrong index rx[%u] = %u  -> tx[%u] = %u", rxcur, rs->buf_idx, txcur, ts->buf_idx);
        }

        if (unlikely(rs->len < 14 || rs->len > 2048)) {
            ZERO_LOG(LOG_ERR, "wrong packet length %u rx slot %u", rs->len, rxcur);
        }

        // refresh current time
        ztime(true);

        __atomic_add_fetch(&info->packets[flow_dir].all.count, 1, __ATOMIC_RELAXED);
        __atomic_add_fetch(&info->traffic[flow_dir].all.count, rs->len, __ATOMIC_RELAXED);
        spdm_update(&info->packets[flow_dir].all.speed, 1);
        spdm_update(&info->traffic[flow_dir].all.speed, rs->len);

        unsigned char *packet = NETMAP_BUF(rx, rs->buf_idx);

        if (0 == process_packet(packet, rs->len, flow_dir)) {

            // refresh current time
            ztime(true);

            __atomic_add_fetch(&info->packets[flow_dir].passed.count, 1, __ATOMIC_RELAXED);
            __atomic_add_fetch(&info->traffic[flow_dir].passed.count, rs->len, __ATOMIC_RELAXED);
            spdm_update(&info->packets[flow_dir].passed.speed, 1);
            spdm_update(&info->traffic[flow_dir].passed.speed, rs->len);

            // swap packets
            uint32_t tmp_idx;
            tmp_idx = ts->buf_idx;
            ts->buf_idx = rs->buf_idx;
            rs->buf_idx = tmp_idx;

            // copy the packet length
            ts->len = rs->len;

            // report the buffer change
            ts->flags |= NS_BUF_CHANGED;
            rs->flags |= NS_BUF_CHANGED;

            // move to next slot
            txcur = nm_ring_next(tx, txcur);
        }

        // move to next slot
        rxcur = nm_ring_next(rx, rxcur);
    }

    // update rings information
    rx->head = rx->cur = rxcur;
    tx->head = tx->cur = txcur;

    return avail;
}

/**
 * Set ring IRQ affinity.
 * @param ifname INterface name.
 * @param ring Ring id.
 * @param affinity Affinity.
 */
static void set_ring_irq_affinity(const char *ifname, u_int ring, u_int affinity)
{
    const char *dir[] = {"tx", "rx", "TxRx"};
    char irq_name[3][IF_NAMESIZE + 10];
    size_t i;
    int irq = -1;

    for (i = 0; i < ARRAYSIZE(irq_name); i++) {
        // e.g. "eth0-TxRx-1"
        snprintf(irq_name[i], sizeof(irq_name[0]), "%s-%s-%u", ifname, dir[i], ring);
    }

    const char *intr_filename = "/proc/interrupts";
    FILE *fintr = fopen(intr_filename, "r");
    if (unlikely(NULL == fintr)) {
        ZERO_ELOG(LOG_ERR, "Failed to open %s", intr_filename);
        return;
    }

    char buf[8192];
    while (likely(fgets(buf, sizeof(buf), fintr))) {
        buf[strlen(buf)-1] = 0;
        for (i = 0; i < ARRAYSIZE(irq_name); i++) {
            if (str_ends_with(buf, irq_name[i])) {
                irq = atoi(buf);
                break;
            }
        }
        if (irq >= 0) break;
    }

    fclose(fintr);

    if (unlikely(irq < 0)) {
        ZERO_LOG(LOG_ERR, "Can't find irq for %u ring of %s interface", ring, ifname);
        return;
    }

    char irq_filename[256];
    snprintf(irq_filename, sizeof(irq_filename), "/proc/irq/%d/smp_affinity", irq);
    FILE *firq = fopen(irq_filename, "w");
    if (unlikely(NULL == firq)) {
        ZERO_ELOG(LOG_ERR, "Failed to open %s", irq_filename);
        return;
    }

    fprintf(firq, "%x", 1u << affinity);
    fclose(firq);

    ZERO_LOG(LOG_DEBUG, "Set ring affinity on %s-ring%u -> irq%u -> %x", ifname, ring, irq, 1u << affinity);
}

/**
 * Ring worker.
 * @param arg zring pointer.
 * @return null
 */
static void *ring_worker(void *arg)
{
    struct pollfd pollfd[2];
    struct zring *ring = (struct zring *)arg;

    // pin thread and ring interrrupts to assigned core
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(ring->if_pair->affinity + ring->ring_id, &cpuset);
    pthread_setaffinity_np(ring->thread, sizeof(cpuset), &cpuset);
    set_ring_irq_affinity(ring->if_pair->lan, ring->ring_id, ring->if_pair->affinity + ring->ring_id);
    set_ring_irq_affinity(ring->if_pair->wan, ring->ring_id, ring->if_pair->affinity + ring->ring_id);

    // setup poll variables
    bzero(pollfd, sizeof(pollfd));
    pollfd[0].fd = ring->ring_lan.fd;
    pollfd[0].events = POLLIN;
    pollfd[1].fd = ring->ring_wan.fd;
    pollfd[1].events = POLLIN;

    if (zcfg()->iface_wait_time) {
        ZERO_LOG(LOG_INFO, "Wait %u secs for link up...", zcfg()->iface_wait_time);
        sleep(zcfg()->iface_wait_time);
    }

    while (likely(!__atomic_load_n(&zinst()->abort, __ATOMIC_RELAXED))) {
        int ret;

        pollfd[0].events = pollfd[1].events = 0;
        pollfd[0].revents = pollfd[1].revents = 0;

        if (nm_ring_space(ring->ring_lan.rx)) {
            pollfd[1].events |= POLLOUT;
        } else {
            pollfd[0].events |= POLLIN;
        }

        if (nm_ring_space(ring->ring_wan.rx)) {
            pollfd[0].events |= POLLOUT;
        } else {
            pollfd[1].events |= POLLIN;
        }

        ret = poll(pollfd, ARRAYSIZE(pollfd), 2500);

        if (unlikely(ret < 0)) {
            ZERO_ELOG(LOG_WARNING, "Poll error");
            continue;
        }

        if (unlikely(pollfd[0].revents & POLLERR)) {
            ZERO_LOG(LOG_WARNING, "poll error (if=%s,ring=%" PRIu16 ",rxcur=%" PRIu32, ring->if_pair->lan, ring->ring_id, ring->ring_lan.rx->cur);
        }
        if (unlikely(pollfd[1].revents & POLLERR)) {
            ZERO_LOG(LOG_WARNING, "poll error (if=%s,ring=%" PRIu16 ",rxcur=%" PRIu32, ring->if_pair->wan, ring->ring_id, ring->ring_wan.rx->cur);
        }

        if (likely(pollfd[0].revents & POLLOUT)) {
            process_rings(ring, DIR_DOWN);
        }
        if (likely(pollfd[1].revents & POLLOUT)) {
            process_rings(ring, DIR_UP);
        }
    }

    return NULL;
}

/**
 * Intialize app instance structure.
 * @param[in] zconf Configuration for instance.
 * @return Zero on success.
 */
int zero_instance_init(const struct zero_config *zconf)
{
    bzero(&g_zinst, sizeof(g_zinst));

    // store options in global instance
    g_zinst._cfg = zconf;

    // initialize storage locks.
    for (size_t i = 0; i < STORAGE_SIZE; i++) {
        if (unlikely(0 != pthread_rwlock_init(&g_zinst.sessions_lock[i], NULL))) {
            ZERO_LOG(LOG_ERR, "failed to initialize rwlock");
            return -1;
        }
        if (unlikely(0 != pthread_rwlock_init(&g_zinst.clients_lock[i], NULL))) {
            ZERO_LOG(LOG_ERR, "failed to initialize rwlock");
            return -1;
        }
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

    // initialize remote control stuff
    struct sockaddr_in rc_addr;
    int sa_len = sizeof(rc_addr);
    int ret = evutil_parse_sockaddr_port(zcfg()->rc_listen_addr, (struct sockaddr *)&rc_addr, &sa_len);
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
            struct zif_pair *if_pair = (struct zif_pair*)utarray_eltptr(&zcfg()->interfaces, i);
            uint16_t lan_rings, wan_rings;

            if (0 != znm_info(if_pair->lan, &req)) {
                return -1;
            }
            lan_rings = req.nr_rx_rings;

            if (0 != znm_info(if_pair->wan, &req)) {
                return -1;
            }
            wan_rings = req.nr_rx_rings;

            if(lan_rings != wan_rings) {
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
                bzero(&ring, sizeof(ring));

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

                for(int dir = 0; dir < DIR_MAX; dir++) {
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
        for(int dir = 0; dir < DIR_MAX; dir++) {
            token_bucket_init(&g_zinst.upstreams[i].p2p_bw_bucket[dir], zcfg()->upstream_p2p_bw[dir]);
            spdm_init(&g_zinst.upstreams[i].speed[dir]);
        }
    }

    // initialize non-client limits
    for(int dir = 0; dir < DIR_MAX; dir++) {
        token_bucket_init(&g_zinst.non_client.bw_bucket[dir], zcfg()->non_client_bw[dir]);
        spdm_init(&g_zinst.non_client.speed[dir]);
    }

    return 0;
}

/**
 * Cleanup app instance.
 */
void zero_instance_free()
{
    if (g_zinst.radh) rc_destroy(g_zinst.radh);

    // clean storages.
    for (size_t i = 0; i < STORAGE_SIZE; i++) {
        pthread_rwlock_destroy(&g_zinst.sessions_lock[i]);
        pthread_rwlock_destroy(&g_zinst.clients_lock[i]);

        struct zsession *sess, *tmp_sess;
        HASH_ITER(hh, g_zinst.sessions[i], sess, tmp_sess) {
            HASH_DELETE(hh, g_zinst.sessions[i], sess);
            session_destroy(sess);
        }
    }

    // clean rings.
    for (size_t i = 0; i < utarray_len(&g_zinst.rings); i++) {
        struct zring *ring = (struct zring *)utarray_eltptr(&g_zinst.rings, i);

        znm_close(&ring->ring_lan);
        znm_close(&ring->ring_wan);

        for(int dir = 0; dir < DIR_MAX; dir++) {
            spdm_destroy(&ring->packets[dir].all.speed);
            spdm_destroy(&ring->packets[dir].passed.speed);
            spdm_destroy(&ring->traffic[dir].all.speed);
            spdm_destroy(&ring->traffic[dir].passed.speed);
        }
    }
    utarray_done(&g_zinst.rings);

    // clean upstreams.
    for (size_t i = 0; i < ARRAYSIZE(g_zinst.upstreams); i++) {
        token_bucket_destroy(&g_zinst.upstreams[i].p2p_bw_bucket[DIR_DOWN]);
        token_bucket_destroy(&g_zinst.upstreams[i].p2p_bw_bucket[DIR_UP]);
        spdm_destroy(&g_zinst.upstreams[i].speed[DIR_DOWN]);
        spdm_destroy(&g_zinst.upstreams[i].speed[DIR_UP]);
    }

    if (g_zinst.master_event_base) event_base_free(g_zinst.master_event_base);
}

/**
 * Run app instance.
 * @param zconf
 */
void zero_instance_run()
{
    struct zoverlord *overlord_threads = calloc(zcfg()->overlord_threads, sizeof(*overlord_threads));

    __atomic_store_n(&zinst()->abort, false, __ATOMIC_RELAXED);

    // start ring threads.
    for (u_int i = 0; i < utarray_len(&zinst()->rings); i++) {
        char thread_name[MAX_THREAD_NAME];
        struct zring *ring = (struct zring *)utarray_eltptr(&zinst()->rings, i);

        if (0 != pthread_create(&ring->thread, NULL, ring_worker, ring)) {
            ZERO_LOG(LOG_ERR, "Failed to start ring thread");
            __atomic_store_n(&zinst()->abort, true, __ATOMIC_RELAXED);
            goto end;
        }

        snprintf(thread_name, sizeof(thread_name), "%s-ring%u", ring->if_pair->lan, i);
        pthread_setname_np(ring->thread, thread_name);
    }

    // start overlod threads.
    for (u_int i = 0; i < zcfg()->overlord_threads; i++) {
        char thread_name[MAX_THREAD_NAME];
        overlord_threads[i].idx = i;

        if (0 != pthread_create(&overlord_threads[i].thread, NULL, overlord_worker, &overlord_threads[i])) {
            ZERO_LOG(LOG_ERR, "Failed to start overlord thread");
            __atomic_store_n(&zinst()->abort, true, __ATOMIC_RELAXED);
            goto end;
        }

        snprintf(thread_name, sizeof(thread_name), "overlord%u", i);
        pthread_setname_np(overlord_threads[i].thread, thread_name);
    }

    // run master thread.
    master_worker();

end:
    // join ring threads.
    for (u_int i = 0; i < utarray_len(&zinst()->rings); i++) {
        struct zring *ring = (struct zring *)utarray_eltptr(&zinst()->rings, i);

        if ((0 != ring->thread) && (0 != pthread_join(ring->thread, NULL))) {
            ZERO_LOG(LOG_ERR, "Failed to join %s-ring%u thread", ring->if_pair->lan, i);
        }
    }

    // join overlord threads.
    for (u_int i = 0; i < zcfg()->overlord_threads; i++) {
        if ((0 != overlord_threads[i].thread) && (0 != pthread_join(overlord_threads[i].thread, NULL))) {
            ZERO_LOG(LOG_ERR, "Failed to join overlord%u thread", i);
        }
    }

    if (overlord_threads) free(overlord_threads);
}

/**
 * Stop application instance.
 */
void zero_instance_stop()
{
    event_base_loopbreak(zinst()->master_event_base);
    __atomic_store_n(&zinst()->abort, true, __ATOMIC_RELAXED);
}

/**
 * Apply rules to app instance.
 * @param[in] rules Rules.
 */
void zero_apply_rules(struct zsrules *rules)
{
    // upstream rules.
    for (size_t uidx = 0; uidx < ZUPSTREAM_MAX; uidx++) {
        for (int dir = 0; dir < DIR_MAX; dir++) {
            if (rules->have.upstream_bw[uidx][dir]) {
                __atomic_store_n(&zinst()->upstreams[uidx].p2p_bw_bucket[dir].max_tokens, rules->upstream_bw[uidx][dir], __ATOMIC_RELAXED);
            }
        }
    }

    // non-client limits.
    for (int dir = 0; dir < DIR_MAX; dir++) {
        if (rules->have.non_client_bw[dir]) {
            __atomic_store_n(&zinst()->non_client.bw_bucket[dir].max_tokens, rules->non_client_bw[dir], __ATOMIC_RELAXED);
        }
    }
}
