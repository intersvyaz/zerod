#include "zero.h"
#include <sys/poll.h>
#include <unistd.h>
#include <pthread.h>
#include "log.h"
#include "packet.h"
#include "monitor.h"

#ifndef PTHREAD_MAX_THREAD_NAME
#define PTHREAD_MAX_THREAD_NAME 16
#endif

/**
 * Set ring IRQ affinity.
 * @param[in] ifname Interface name.
 * @param[in] ring Ring id.
 * @param[in] affinity Affinity.
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
        buf[strlen(buf) - 1] = 0;
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
 * Process ring pair.
 * @param[in] ring Ring pair.
 * @param[in] flow_dir Flow direction.
 * @return
 */
static u_int process_ring(struct zring *ring, enum flow_dir flow_dir)
{
    struct netmap_ring *tx, *rx;
    u_int rxcur, txcur, avail;

    if (DIR_DOWN == flow_dir) {
        rx = ring->ring_wan.rx;
        tx = ring->ring_lan.tx;
    } else if (DIR_UP == flow_dir) {
        rx = ring->ring_lan.rx;
        tx = ring->ring_wan.tx;
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
        zclock(true);

        ring->packets[flow_dir].all.count++;
        ring->traffic[flow_dir].all.count += rs->len;
        spdm_update(&ring->packets[flow_dir].all.speed, 1);
        spdm_update(&ring->traffic[flow_dir].all.speed, rs->len);

        unsigned char *packet = (unsigned char *)NETMAP_BUF(rx, rs->buf_idx);
        enum traffic_type traf_type = TRAFF_NON_CLIENT;

#ifndef NDEBUG
        if (unlikely(zcfg()->dbg.hexdump)) {
            const char *dump = hex_dump(packet, rs->len, 0, NULL);
            puts(dump);
        }
#endif

        if (0 == packet_process(packet, rs->len, flow_dir, &traf_type)) {

            zmonitor_mirror_packet(zinst()->monitor, packet, rs->len);

            // refresh current time
            ztime(true);
            zclock(true);

            ring->packets[flow_dir].passed.count++;
            ring->traffic[flow_dir].passed.count += rs->len;
            spdm_update(&ring->packets[flow_dir].passed.speed, 1);
            spdm_update(&ring->traffic[flow_dir].passed.speed, rs->len);

            if (TRAFF_CLIENT == traf_type) {
                ring->packets[flow_dir].client.count++;
                ring->traffic[flow_dir].client.count += rs->len;
                spdm_update(&ring->packets[flow_dir].client.speed, 1);
                spdm_update(&ring->traffic[flow_dir].client.speed, rs->len);
            }

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
 * Ring worker.
 * @param[in] arg zring pointer.
 * @return null
 */
static void *ring_worker(void *arg)
{
    struct pollfd pollfd[2];
    struct zring *ring = (struct zring *) arg;

    // pin thread and ring interrupts to assigned core
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(ring->if_pair->affinity + ring->ring_id, &cpuset);
    pthread_setaffinity_np(ring->thread, sizeof(cpuset), &cpuset);
    set_ring_irq_affinity(ring->if_pair->lan, ring->ring_id, ring->if_pair->affinity + ring->ring_id);
    set_ring_irq_affinity(ring->if_pair->wan, ring->ring_id, ring->if_pair->affinity + ring->ring_id);

    // setup poll variables
    memset(pollfd, 0, sizeof(pollfd));
    pollfd[0].fd = ring->ring_lan.fd;
    pollfd[0].events = POLLIN;
    pollfd[1].fd = ring->ring_wan.fd;
    pollfd[1].events = POLLIN;

    if (zcfg()->iface_wait_time) {
        ZERO_LOG(LOG_INFO, "Wait %u secs for link up...", zcfg()->iface_wait_time);
        sleep(zcfg()->iface_wait_time);
    }

    while (likely(!zinst()->abort)) {
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
            ZERO_LOG(LOG_WARNING, "poll error (if=%s,ring=%"
            PRIu16
            ",rxcur=%"
            PRIu32, ring->if_pair->lan, ring->ring_id, ring->ring_lan.rx->cur);
        }
        if (unlikely(pollfd[1].revents & POLLERR)) {
            ZERO_LOG(LOG_WARNING, "poll error (if=%s,ring=%"
            PRIu16
            ",rxcur=%"
            PRIu32, ring->if_pair->wan, ring->ring_id, ring->ring_wan.rx->cur);
        }

        if (likely(pollfd[1].revents & POLLOUT)) {
            process_ring(ring, DIR_UP);
        }
        if (likely(pollfd[0].revents & POLLOUT)) {
            process_ring(ring, DIR_DOWN);
        }
    }

    return NULL;
}

/**
 * Run app instance.
 */
void zero_instance_run(void)
{
    struct zoverlord *overlord_threads = calloc(zcfg()->overlord_threads, sizeof(*overlord_threads));

    atomic_init(&zinst()->abort, false);

    // start ring threads.
    for (u_int i = 0; i < utarray_len(&zinst()->rings); i++) {
        char thread_name[PTHREAD_MAX_THREAD_NAME];
        struct zring *ring = (struct zring *) utarray_eltptr(&zinst()->rings, i);

        if (0 != pthread_create(&ring->thread, NULL, ring_worker, ring)) {
            ZERO_LOG(LOG_ERR, "Failed to start ring thread");
            zinst()->abort = true;
            goto end;
        }

        snprintf(thread_name, sizeof(thread_name), "%s-ring%u", ring->if_pair->lan, i);
        pthread_setname_np(ring->thread, thread_name);
    }

    // start overlord threads.
    for (u_int i = 0; i < zcfg()->overlord_threads; i++) {
        char thread_name[PTHREAD_MAX_THREAD_NAME];
        overlord_threads[i].idx = i;

        if (0 != pthread_create(&overlord_threads[i].thread, NULL, overlord_worker, &overlord_threads[i])) {
            ZERO_LOG(LOG_ERR, "Failed to start overlord thread");
            zinst()->abort = true;
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
        struct zring *ring = (struct zring *) utarray_eltptr(&zinst()->rings, i);

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