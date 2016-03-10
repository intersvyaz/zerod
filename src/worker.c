#include <unistd.h>
#include <sys/poll.h>
#include "worker.h"
#include "log.h"
#include "zero.h"
#include "util_string.h"

typedef enum zpoll_type_enum
{
    ZPOLL_LAN = 0,
    ZPOLL_WAN = 1,
    ZPOLL_LAN_SW = 2,
    ZPOLL_WAN_SW = 3,
    ZPOLL_MAX
} zpoll_type_t;

#define ZPOLL_TIMEOUT   (2500)

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
        ZLOGEX(LOG_ERR, errno, "Failed to open %s", intr_filename);
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
        ZLOGEX(LOG_ERR, errno, "Can't find irq for %u ring of %s interface", ring, ifname);
        return;
    }

    char irq_filename[256];
    snprintf(irq_filename, sizeof(irq_filename), "/proc/irq/%d/smp_affinity", irq);
    FILE *firq = fopen(irq_filename, "w");
    if (unlikely(NULL == firq)) {
        ZLOGEX(LOG_ERR, errno, "Failed to open %s", irq_filename);
        return;
    }

    fprintf(firq, "%x", 1u << affinity);
    fclose(firq);

    ZLOG(LOG_DEBUG, "Set ring affinity on %s-ring%u -> irq%u -> %x", ifname, ring, irq, 1u << affinity);
}

static size_t zworker_dispatch_ring_sw(zworker_t *worker, znetmap_ring_t *rx_ring,
                                       znetmap_ring_t *tx_ring, zflow_dir_t flow_dir)
{
    (void)worker;
    struct netmap_ring *rx = rx_ring->rx;
    struct netmap_ring *tx = tx_ring->tx;

    if (unlikely(rx->flags || tx->flags)) {
        ZLOG(LOG_DEBUG, "rxflags %X txflags %X", rx->flags, tx->flags);
    }

    ztime_refresh();
    zclock_refresh();

    size_t processed = 0;
    while (nm_ring_space(rx) && nm_ring_space(tx)) {
        struct netmap_slot *rs = &rx->slot[rx->cur];

        zpacket_t packet = {
                .data = (unsigned char *) NETMAP_BUF(rx, rs->buf_idx),
                .length = rs->len,
                .flow_dir = flow_dir,
                .traff_type = TRAFF_NON_CLIENT
        };

        zpacket_action_t action = zpacket_process_sw(&packet);

        bool write_ok = true;
        if (ACTION_PASS == action) {
            write_ok = znm_ring_write_slot(tx_ring, rs, false);
        }

        if (!write_ok) {
            break;
        }

        // move to next slot
        rx->cur = nm_ring_next(rx, rx->cur);
        processed++;
    }

    rx->head = rx->cur;

    return processed;
}

/**
 * Process ring pair.
 * @param[in] worker Worker instance.
 * @param[in] flow_dir Flow direction.
 * @return Count of processed packets.
 */
static size_t zworker_dispatch_ring(zworker_t *worker, znetmap_ring_t *rx_ring, znetmap_ring_t *tx_ring,
                                    znetmap_ring_t *tx_ring_sw, zflow_dir_t flow_dir)
{
    struct netmap_ring *rx = rx_ring->rx;
    struct netmap_ring *tx = tx_ring->tx;

    if (unlikely(rx->flags || tx->flags)) {
        ZLOG(LOG_DEBUG, "rxflags %X txflags %X", rx->flags, tx->flags);
    }

    size_t processed = 0;
    bool need_tx_sw_sync = false;
    while (nm_ring_space(rx) && nm_ring_space(tx)) {
        struct netmap_slot *rs = &rx->slot[rx->cur];

        zpacket_t packet = {
                .data = (unsigned char *) NETMAP_BUF(rx, rs->buf_idx),
                .length = rs->len,
                .flow_dir = flow_dir,
                .traff_type = TRAFF_NON_CLIENT
        };

#ifndef NDEBUG
        if (unlikely(zinst()->cfg->dbg.hexdump)) {
            const char *dump = hex_dump(packet.data, packet.length, 0, NULL);
            puts(dump);
        }
#endif

        ztime_refresh();
        zclock_refresh();

#ifdef ZEROD_PROFILE
        struct timespec start_ts, end_ts;
        clock_gettime(CLOCK_MONOTONIC, &start_ts);
#endif

        zpacket_action_t action = zpacket_process(&packet);

        // update statistics
        zworker_stats_t *packet_stats = &worker->stats.packets[flow_dir][packet.traff_type][action];
        zworker_stats_t *traff_stats = &worker->stats.traffic[flow_dir][packet.traff_type][action];
        atomic_fetch_add_release(&packet_stats->count, 1);
        atomic_fetch_add_release(&traff_stats->count, rs->len);
        spdm_update(&packet_stats->speed, 1);
        spdm_update(&traff_stats->speed, rs->len);

#ifdef ZEROD_PROFILE
        clock_gettime(CLOCK_MONOTONIC, &end_ts);
        packet_stats->avg_ppt = (packet_stats->avg_ppt + (end_ts.tv_nsec - start_ts.tv_nsec)) / 2;
#endif

        bool write_ok = true;
        if (ACTION_PASS == action) {
            zmonitor_mirror_packet(zinst()->monitor, packet.data, packet.length);
            write_ok = znm_ring_write_slot(tx_ring, rs, false);
        } else if (ACTION_CONSUME == action) {
            write_ok = znm_ring_write_slot(tx_ring_sw, rs, true);
            need_tx_sw_sync |= write_ok;
        }

        if (!write_ok) {
            break;
        }

        // move to next slot
        rx->cur = nm_ring_next(rx, rx->cur);
        processed++;
    }

    rx->head = rx->cur;
    if (need_tx_sw_sync) {
        znm_ring_try_sync_tx(tx_ring_sw, true);
    }

    return processed;
}

static void zworker_pin_affinity(const zworker_t *worker)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(worker->affinity, &cpuset);
    pthread_setaffinity_np(worker->thread, sizeof(cpuset), &cpuset);
    set_ring_irq_affinity(worker->lan->ifname, worker->ring_id, worker->affinity);
    set_ring_irq_affinity(worker->wan->ifname, worker->ring_id, worker->affinity);
}

/**
 * Ring worker.
 * @param[in] arg zworker_t pointer.
 * @return null
 */
void *zworker_proc(void *arg)
{
    zworker_t *worker = (zworker_t *) arg;
    bool dispatch_sw = (worker->ring_id == 0);

    znetmap_ring_t *ring_lan = ZNM_RING(worker->lan, worker->ring_id);
    znetmap_ring_t *ring_wan = ZNM_RING(worker->wan, worker->ring_id);
    znetmap_ring_t *ring_lan_sw = ZNM_SW_RING(worker->lan);
    znetmap_ring_t *ring_wan_sw = ZNM_SW_RING(worker->wan);

    zworker_pin_affinity(worker);

    // setup poll variables
    size_t poll_cnt = dispatch_sw ? ZPOLL_MAX : (ZPOLL_WAN + 1);
    struct pollfd pollfd[poll_cnt];
    memset(pollfd, 0, sizeof(pollfd));
    pollfd[ZPOLL_LAN].fd = ring_lan->fd;
    pollfd[ZPOLL_WAN].fd = ring_wan->fd;
    if (dispatch_sw) {
        pollfd[ZPOLL_LAN_SW].fd = ring_lan_sw->fd;
        pollfd[ZPOLL_WAN_SW].fd = ring_wan_sw->fd;
    }

    while (likely(!zinstance_is_abort())) {
        pollfd[ZPOLL_LAN].events = pollfd[ZPOLL_WAN].events = 0;
        pollfd[ZPOLL_LAN].revents = pollfd[ZPOLL_WAN].revents = 0;

        if (nm_ring_space(ring_lan->rx))
            pollfd[ZPOLL_WAN].events |= POLLOUT;
        else
            pollfd[ZPOLL_LAN].events |= POLLIN;
        if (nm_ring_space(ring_wan->rx))
            pollfd[ZPOLL_LAN].events |= POLLOUT;
        else
            pollfd[ZPOLL_WAN].events |= POLLIN;

        if (dispatch_sw) {
            pollfd[ZPOLL_LAN_SW].events = pollfd[ZPOLL_WAN_SW].events = 0;
            pollfd[ZPOLL_LAN_SW].revents = pollfd[ZPOLL_WAN_SW].revents = 0;

            if (nm_ring_space(ring_lan_sw->rx))
                pollfd[ZPOLL_LAN].events |= POLLOUT;
            else
                pollfd[ZPOLL_LAN_SW].events |= POLLIN;
            if (nm_ring_space(ring_wan_sw->rx))
                pollfd[ZPOLL_WAN].events |= POLLOUT;
            else
                pollfd[ZPOLL_WAN_SW].events |= POLLIN;
        }

        int ret = (int) TEMP_FAILURE_RETRY(poll(pollfd, ARRAYSIZE(pollfd), ZPOLL_TIMEOUT));
        if (unlikely(ret < 0)) {
            ZLOGEX(LOG_WARNING, errno, "Poll error");
            continue;
        }

        if (unlikely(pollfd[ZPOLL_LAN].revents & POLLERR)) {
            ZLOG(LOG_WARNING, "Poll error (if=%s,ring=%" PRIu16 ",rxcur=%" PRIu32,
                 worker->lan->ifname, worker->ring_id, ring_lan->rx->cur);
        }
        if (unlikely(pollfd[ZPOLL_WAN].revents & POLLERR)) {
            ZLOG(LOG_WARNING, "Poll error (if=%s,ring=%" PRIu16 ",rxcur=%" PRIu32,
                 worker->wan->ifname, worker->ring_id, ring_wan->rx->cur);
        }

        if (dispatch_sw) {
            if (unlikely(pollfd[ZPOLL_LAN_SW].revents & POLLERR)) {
                ZLOG(LOG_WARNING, "Poll error (if=%s,ring_sw,rxcur=%" PRIu32,
                     worker->lan->ifname, ring_lan_sw->rx->cur);
            }
            if (unlikely(pollfd[ZPOLL_WAN_SW].revents & POLLERR)) {
                ZLOG(LOG_WARNING, "Poll error (if=%s, ring_sw, rxcur=%" PRIu32,
                     worker->wan->ifname, ring_wan_sw->rx->cur);
            }

            if (likely(pollfd[ZPOLL_LAN].revents & POLLOUT)) {
                zworker_dispatch_ring_sw(worker, ring_lan_sw, ring_lan, DIR_UP);
            }
            if (likely(pollfd[ZPOLL_WAN].revents & POLLOUT)) {
                zworker_dispatch_ring_sw(worker, ring_wan_sw, ring_wan, DIR_DOWN);
            }
        }

        if (likely(pollfd[ZPOLL_LAN].revents & POLLOUT)) {
            zworker_dispatch_ring(worker, ring_wan, ring_lan, ring_wan_sw, DIR_DOWN);
        }
        if (likely(pollfd[ZPOLL_WAN].revents & POLLOUT)) {
            zworker_dispatch_ring(worker, ring_lan, ring_wan, ring_lan_sw, DIR_UP);
        }
    }

    return NULL;
}

zworker_t *zworker_new(znetmap_iface_t *lan, znetmap_iface_t *wan, uint16_t ring, uint16_t affinity)
{
    zworker_t *worker = malloc(sizeof(*worker));
    if (unlikely(NULL == worker)) {
        return NULL;
    }

    memset(worker, 0, sizeof(*worker));

    worker->lan = lan;
    worker->wan = wan;
    worker->ring_id = ring;
    worker->affinity = affinity;

    for (int dir = 0; dir < DIR_MAX; dir++) {
        for (int traff = 0; traff < TRAFF_MAX; traff++) {
            for (int action = 0; action < ACTION_MAX; action++) {
                spdm_init(&worker->stats.packets[dir][traff][action].speed);
                spdm_init(&worker->stats.traffic[dir][traff][action].speed);
            }
        }
    }

    return worker;
}

void zworker_free(zworker_t *worker)
{
    for (int dir = 0; dir < DIR_MAX; dir++) {
        for (int traff = 0; traff < TRAFF_MAX; traff++) {
            for (int action = 0; action < ACTION_MAX; action++) {
                spdm_destroy(&worker->stats.packets[dir][traff][action].speed);
                spdm_destroy(&worker->stats.traffic[dir][traff][action].speed);
            }
        }
    }

    free(worker);
}
