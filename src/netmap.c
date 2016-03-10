#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <pthread.h>


#include "log.h"
#include "util.h"
#include "netmap.h"

static const char znetmap_device[] = "/dev/netmap";

/**
 * Prepare interface for operation in netmap mode.
 * @param[in] ifname Interface name.
 * @return Zero on success.
 */
static int znetmap_prepare(const char *ifname)
{
    struct ifreq ifr;
    int fd, ret = -1;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        ZLOGEX(LOG_ERR, errno, "Can not create device control socket");
        goto end;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    // check and set interface flags
    if (0 != ioctl(fd, SIOCGIFFLAGS, &ifr)) {
        ZLOGEX(LOG_ERR, errno, "%s: Failed to get interface flags", ifname);
        goto end;
    }
    if (0 == (ifr.ifr_flags & IFF_UP)) {
        ZLOG(LOG_INFO, "%s: Interface is down, set up...", ifname);
        ifr.ifr_flags |= IFF_UP;
    }
    if (0 == (ifr.ifr_flags & IFF_PROMISC)) {
        ZLOG(LOG_DEBUG, "%s: promisc mode enabled", ifname);
        ifr.ifr_flags |= IFF_PROMISC;
    }
    if (0 != ioctl(fd, SIOCSIFFLAGS, &ifr)) {
        ZLOGEX(LOG_ERR, errno, "%s: Failed to set interface flags", ifname);
        goto end;
    }

    struct ethtool_value ethval;
    ifr.ifr_data = (caddr_t) &ethval;

    // disable generic-segmentation-offload
    ethval.cmd = ETHTOOL_SGSO;
    ethval.data = 0;
    if (0 != ioctl(fd, SIOCETHTOOL, &ifr)) {
        ZLOGEX(LOG_ERR, errno, "%s: Failed to disable GSO", ifname);
        goto end;
    }

    // disable generic-receive-offload
    ethval.cmd = ETHTOOL_SGRO;
    ethval.data = 0;
    if (0 != ioctl(fd, SIOCETHTOOL, &ifr)) {
        ZLOGEX(LOG_ERR, errno, "%s: Failed to disable GRO", ifname);
        goto end;
    }

    // disable tcp-segmentation-offload
    ethval.cmd = ETHTOOL_STSO;
    ethval.data = 0;
    if (0 != ioctl(fd, SIOCETHTOOL, &ifr)) {
        ZLOGEX(LOG_ERR, errno, "%s: Failed to disable TSO", ifname);
        goto end;
    }

    // disable hw rx-checksum
    ethval.cmd = ETHTOOL_SRXCSUM;
    ethval.data = 0;
    if (0 != ioctl(fd, SIOCETHTOOL, &ifr)) {
        ZLOGEX(LOG_ERR, errno, "%s: Failed to disable rx checksum", ifname);
        goto end;
    }

    // disable hw tx-checksum
    ethval.cmd = ETHTOOL_STXCSUM;
    ethval.data = 0;
    if (0 != ioctl(fd, SIOCETHTOOL, &ifr)) {
        ZLOGEX(LOG_ERR, errno, "%s: Failed to disable tx checksum", ifname);
        goto end;
    }

    // disable ntuple, rx/tx VLAN offload, large-receive-offload
    ethval.cmd = ETHTOOL_SFLAGS;
    ethval.data = 0;
    if (0 != ioctl(fd, SIOCETHTOOL, &ifr)) {
        ZLOGEX(LOG_ERR, errno, "%s: Failed to disable ntuple, VLAN offload, LRO", ifname);
        goto end;
    }

    ret = 0;

    end:
    if (fd >= 0) {
        close(fd);
    }
    return ret;
}

/**
 * @param[in] ifname Interface name.
 * @param[in] parent Already opened handle for mmap reuse.
 * @return Handle pointer.
 */
znetmap_iface_t *znetmap_new(const char *ifname, znetmap_iface_t *parent)
{
    if (0 != znetmap_prepare(ifname)) {
        return NULL;
    }

    znetmap_iface_t *dev = malloc(sizeof(*dev));
    if (unlikely(NULL == dev)) {
        return NULL;
    }
    memset(dev, 0, sizeof(*dev));

    /* open netmap */
    int fd = (int) TEMP_FAILURE_RETRY(open(znetmap_device, O_RDWR));
    if (fd == -1) {
        ZLOGEX(LOG_ERR, errno, "Failed to open netmap device %s", znetmap_device);
        goto error_malloc;
    }

    /* query netmap info */
    struct nmreq nm_req;
    memset(&nm_req, 0, sizeof(nm_req));
    strncpy(nm_req.nr_name, ifname, sizeof(nm_req.nr_name));
    nm_req.nr_version = NETMAP_API;

    if (0 != ioctl(fd, NIOCGINFO, &nm_req)) {
        ZLOGEX(LOG_ERR, errno, "%s: netmap information query failed", ifname);
        goto error_fd;
    }

    if (parent) {
        dev->memsize = 0;
        dev->mem = parent->mem;
    } else {
        dev->memsize = nm_req.nr_memsize;
    }
    dev->rx_rings_count = nm_req.nr_rx_rings;
    dev->tx_rings_count = nm_req.nr_tx_rings;
    dev->rings_count = max(dev->rx_rings_count, dev->tx_rings_count);

    /* hw rings + sw ring */
    size_t rings_storage_size = sizeof(*dev->rings) * (dev->rings_count + 1);
    dev->rings = malloc(rings_storage_size);
    if (unlikely(NULL == dev->rings)) {
        ZLOGEX(LOG_ERR, errno, "Failed to allocate memory");
        goto error_fd;
    }
    memset(dev->rings, 0, rings_storage_size);

    /* open individual instance for each ring (+sw ring) */
    uint16_t success_cnt = 0;
    for (uint16_t i = 0; i <= dev->rings_count; i++) {
        znetmap_ring_t *pring = &dev->rings[i];
        pring->fd = (int) TEMP_FAILURE_RETRY(open(znetmap_device, O_RDWR));
        if (pring->fd == -1) {
            ZLOGEX(LOG_ERR, errno, "Failed to open netmap device %s", znetmap_device);
            break;
        }

        if (i < dev->rings_count) {
            nm_req.nr_flags = NR_REG_ONE_NIC;
            nm_req.nr_ringid = i;
        } else {
            nm_req.nr_flags = NR_REG_SW;
            nm_req.nr_ringid = NETMAP_NO_TX_POLL;
        }

        if (ioctl(pring->fd, NIOCREGIF, &nm_req) != 0) {
            ZLOGEX(LOG_ERR, errno, "%s: Failed to register ring %" PRIu16 " with netmap", ifname, i);
            break;
        }

        if (dev->mem == NULL) {
            dev->mem = mmap(0, dev->memsize, PROT_WRITE | PROT_READ, MAP_SHARED, pring->fd, 0);
            if (dev->mem == MAP_FAILED) {
                dev->mem = NULL;
                ZLOGEX(LOG_ERR, errno, "%s: Failed to mmap netmap", ifname);
                break;
            }
        }

        pring->nif = NETMAP_IF(dev->mem, nm_req.nr_offset);

        if (i < dev->rx_rings_count || (i == dev->rings_count)) {
            pring->rx = NETMAP_RXRING(pring->nif, i);
        }
        if (i < dev->tx_rings_count || (i == dev->rings_count)) {
            pring->tx = NETMAP_TXRING(pring->nif, i);
        }
        if (0 != pthread_spin_init(&pring->tx_lock, PTHREAD_PROCESS_PRIVATE)) {
            ZLOGEX(LOG_ERR, errno, "Failed to init spin lock");
            close(pring->fd);
            break;
        }
        success_cnt++;
    }

    if (success_cnt != (dev->rings_count + 1)) {
        for (uint16_t i = 0; i < success_cnt; i++) {
            close(dev->rings[i].fd);
            pthread_spin_destroy(&dev->rings[i].tx_lock);
        }
        // we own mem only if memsize is set
        if (dev->mem && dev->memsize) {
            munmap(dev->mem, dev->memsize);
        }
        free(dev->rings);
        goto error_malloc;
    }

    strncpy(dev->ifname, ifname, sizeof(dev->ifname));

    close(fd);
    ZLOG(LOG_DEBUG, "successfully opened %s", ifname);
    return dev;

    error_malloc:
    free(dev);
    error_fd:
    close(fd);

    return NULL;
}

/**
 * Close netmap interface handle.
 * @param[in] dev Interface handle.
 */
void znetmap_free(znetmap_iface_t *dev)
{
    assert(dev);

    for (uint16_t i = 0; i <= dev->rings_count; i++) {
        close(dev->rings[i].fd);
        pthread_spin_destroy(&dev->rings[i].tx_lock);
    }
    free(dev->rings);

    // we own mem only if memsize is set
    if (dev->memsize) {
        munmap(dev->mem, dev->memsize);
    }
    free(dev);
}

/**
 * Query netmap for interface capabilities.
 * @param[in] ifname Interface name.
 * @param[in,out] info Query result.
 * @return True on success.
 */
bool znetmap_info(const char *ifname, struct nmreq *info)
{
    assert(info);

    int ret;
    int fd;

    // set up interface for internal resource allocation
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        ZLOGEX(LOG_ERR, errno, "Can not create device control socket");
        return false;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    if (0 != ioctl(fd, SIOCGIFFLAGS, &ifr)) {
        ZLOGEX(LOG_ERR, errno, "Failed to get '%s' interface flags", ifname);
        close(fd);
        return false;
    }
    if (0 == (ifr.ifr_flags & IFF_UP)) {
        ifr.ifr_flags |= IFF_UP;
        if (0 != ioctl(fd, SIOCSIFFLAGS, &ifr)) {
            ZLOGEX(LOG_ERR, errno, "Failed to bring up '%s' interface", ifname);
            close(fd);
            return false;
        }
    }
    close(fd);

    // query netmap for device info
    fd = (int) TEMP_FAILURE_RETRY(open(znetmap_device, O_RDWR));
    if (fd < 0) {
        ZLOGEX(LOG_ERR, errno, "Failed to open '%s'", znetmap_device);
        return false;
    }

    memset(info, 0, sizeof(*info));
    strncpy(info->nr_name, ifname, sizeof(info->nr_name));
    info->nr_version = NETMAP_API;

    ret = ioctl(fd, NIOCGINFO, info);
    close(fd);

    if (ret) {
        ZLOGEX(LOG_ERR, errno, "Unable to query netmap for interface '%s' info", ifname);
        return false;
    }

    return true;
}

inline int znm_ring_sync_rx(znetmap_ring_t *ring)
{
    return ioctl(ring->fd, NIOCRXSYNC);
}

inline int znm_ring_try_sync_tx(znetmap_ring_t *ring, bool lock)
{
    if (lock) {
        if (0 != pthread_spin_trylock(&ring->tx_lock)) return -1;
    }
    int ret = ioctl(ring->fd, NIOCTXSYNC);
    if (lock) pthread_spin_unlock(&ring->tx_lock);
    return ret;
}

bool znm_ring_write_slot(znetmap_ring_t *ring, struct netmap_slot *slot, bool lock)
{
    struct netmap_ring *tx = ring->tx;

    if (lock) pthread_spin_lock(&ring->tx_lock);

    if (!nm_ring_space(tx)) {
        if (lock) pthread_spin_unlock(&ring->tx_lock);
        return false;
    }

    struct netmap_slot *ts = &tx->slot[tx->cur];
    znm_slot_swap(ts, slot);
    tx->head = tx->cur = nm_ring_next(tx, tx->cur);

    if (lock) pthread_spin_unlock(&ring->tx_lock);

    return true;
}
