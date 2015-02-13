#include "netmap.h"

#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#include "log.h"

/**
Preapre interface for operation in netmap mode.
* @param[in] ifname Interface name.
* @return Zero on success.
*/
int znm_prepare_if(const char *ifname)
{
    struct ifreq ifr;
    struct ethtool_value ethval;
    int fd, ret = -1;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        ZERO_ELOG(LOG_ERR, "Can not create device control socket");
        goto end;
    }

    bzero(&ifr, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    // check and set interface flags
    if (0 != ioctl(fd, SIOCGIFFLAGS, &ifr)) {
        ZERO_ELOG(LOG_ERR, "Failed to get '%s' interface flags", ifname);
        goto end;
    }
    if (0 == (ifr.ifr_flags & IFF_UP)) {
        ZERO_LOG(LOG_INFO, "'%s' is down, bringing up...", ifname);
        ifr.ifr_flags |= IFF_UP;
    }
    if (0 == (ifr.ifr_flags & IFF_PROMISC)) {
        ZERO_LOG(LOG_DEBUG, "Set '%s' to promisc mode", ifname);
        ifr.ifr_flags |= IFF_PROMISC;
    }
    if (0 != ioctl(fd, SIOCSIFFLAGS, &ifr)) {
        ZERO_ELOG(LOG_ERR, "Failed to set '%s' interface flags", ifname);
        goto end;
    }

    ifr.ifr_data = (caddr_t) &ethval;

    // disable generic-segmentation-offload
    ethval.cmd = ETHTOOL_SGSO;
    ethval.data = 0;
    if (0 != ioctl(fd, SIOCETHTOOL, &ifr)) {
        ZERO_ELOG(LOG_ERR, "Failed to disable GSO feature on '%s' interface", ifname);
        goto end;
    }

    // disable generic-receive-offload
    ethval.cmd = ETHTOOL_SGRO;
    ethval.data = 0;
    if (0 != ioctl(fd, SIOCETHTOOL, &ifr)) {
        ZERO_ELOG(LOG_ERR, "Failed to disable GRO feature on '%s' interface", ifname);
        goto end;
    }

    // disable tcp-segmentation-offload
    ethval.cmd = ETHTOOL_STSO;
    ethval.data = 0;
    if (0 != ioctl(fd, SIOCETHTOOL, &ifr)) {
        ZERO_ELOG(LOG_ERR, "Failed to disable TSO feature on '%s' interface", ifname);
        goto end;
    }

    // disable hw rx-checksumming
    ethval.cmd = ETHTOOL_SRXCSUM;
    ethval.data = 0;
    if (0 != ioctl(fd, SIOCETHTOOL, &ifr)) {
        ZERO_ELOG(LOG_ERR, "Failed to disable rx-checksum feature on '%s' interface", ifname);
        goto end;
    }

    // disable hw tx-checksumming
    ethval.cmd = ETHTOOL_STXCSUM;
    ethval.data = 0;
    if (0 != ioctl(fd, SIOCETHTOOL, &ifr)) {
        ZERO_ELOG(LOG_ERR, "Failed to disable tx-checksum feature on '%s' interface", ifname);
        goto end;
    }

    // disable ntuple, rx/tx VLAN offload, large-receive-offload
    ethval.cmd = ETHTOOL_SFLAGS;
    ethval.data = 0;
    if (0 != ioctl(fd, SIOCETHTOOL, &ifr)) {
        ZERO_ELOG(LOG_ERR, "Failed to disable ntuple, VLAN offload, LRO features on '%s' interface", ifname);
        goto end;
    }

    ret = 0;

end:
    if (fd >= 0) close(fd);
    return ret;
}

/**
* Open netmap ring.
* @param[in,out] ring
* @param[in] ringid Ring ID.
* @param[in] cached_mmap_mem Pointer to already mmapped shared netmap memory.
*/
int znm_open(struct znm_ring *ring, const char *ifname, uint16_t ringid, void *cached_mmap_mem)
{
    struct nmreq req;

    ring->fd = open(ZNM_DEVICE, O_RDWR);
    if (ring->fd < 0) {
        ZERO_ELOG(LOG_ERR, "Unable to open %s", ZNM_DEVICE);
        return -1;
    }

    bzero(&req, sizeof(req));
    req.nr_version = NETMAP_API;
    strncpy(req.nr_name, ifname, sizeof(req.nr_name));
    req.nr_ringid = ringid;
    req.nr_flags = NR_REG_ONE_NIC;

    if (0 == ioctl(ring->fd, NIOCGINFO, &req)) {
        ring->memsize = req.nr_memsize;
        if (0 == ioctl(ring->fd, NIOCREGIF, &req)) {
            if (NULL != cached_mmap_mem) {
                ring->mem = cached_mmap_mem;
            } else {
                ring->mem = mmap(0, ring->memsize, PROT_WRITE | PROT_READ, MAP_SHARED, ring->fd, 0);
                ring->own_mmap = 1;
            }

            if (MAP_FAILED != ring->mem) {
                ZERO_LOG(LOG_DEBUG, "Attached to %s HW ring %u", ifname, ringid);
                ring->nifp = NETMAP_IF(ring->mem, req.nr_offset);
                ring->tx = NETMAP_TXRING(ring->nifp, ringid);
                ring->rx = NETMAP_RXRING(ring->nifp, ringid);
                // Success.
                return 0;
            } else {
                ring->mem = NULL;
                ZERO_ELOG(LOG_ERR, "Unable to mmap netmap shared memory");
            }
        } else {
            ZERO_ELOG(LOG_ERR, "Unable to register %s with netmap", ifname);
        }
    } else {
        ZERO_ELOG(LOG_ERR, "Unable to query netmap for '%s' info", ifname);
    }

    close(ring->fd);
    return -1;
}

/**
* Close netmap ring.
* @param[in] ring Ring to close.
*/
void znm_close(struct znm_ring *ring)
{
    if (ring->mem && ring->own_mmap) {
        munmap(ring->mem, ring->memsize);
        ring->mem = NULL;
        ring->memsize = 0;
    }
    if (ring->fd >= 0)
        close(ring->fd);
}

/**
* Query netmap for interface capabilities.
*
* @param[in] ifname Interface name.
* @param[in,out] nm_req Pointer for holding result.
* @return Zero on success.
*/
int znm_info(const char *ifname, struct nmreq *nm_req)
{
    int ret;
    int fd;

    // XXX: bring up for internal resource allocation
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        ZERO_ELOG(LOG_ERR, "Can not create device control socket");
        return -1;
    }
    struct ifreq ifr;
    bzero(&ifr, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    if (0 != ioctl(fd, SIOCGIFFLAGS, &ifr)) {
        ZERO_ELOG(LOG_ERR, "Failed to get '%s' interface flags", ifname);
        return -1;
    }
    if (0 == (ifr.ifr_flags & IFF_UP)) {
        ifr.ifr_flags |= IFF_UP;
        if (0 != ioctl(fd, SIOCSIFFLAGS, &ifr)) {
            ZERO_ELOG(LOG_ERR, "Failed to bring up '%s' interface", ifname);
            return -1;
        }
    }
    close(fd);

    // query netmap for device info
    fd = open(ZNM_DEVICE, O_RDWR);
    if (fd < 0) {
        ZERO_ELOG(LOG_ERR, "Unable to open '%s'", ZNM_DEVICE);
        return -1;
    }

    bzero(nm_req, sizeof(*nm_req));
    strncpy(nm_req->nr_name, ifname, sizeof(nm_req->nr_name));
    nm_req->nr_version = NETMAP_API;

    ret = ioctl(fd, NIOCGINFO, nm_req);
    close(fd);

    if (ret) {
        ZERO_ELOG(LOG_ERR, "Unable to query netmap for interface '%s' info", ifname);
        return -1;
    }

    return 0;
}
