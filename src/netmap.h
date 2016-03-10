#ifndef ZEROD_NETMAP_H
#define ZEROD_NETMAP_H

#include <sys/types.h>
#include <stdbool.h>

#include <net/netmap_user.h>

typedef struct znetmap_ring_struct
{
    /*<<! file descriptor for ioctl commands */
    int fd;
    /*<<! netmap interface info */
    const struct netmap_if *nif;
    /*<<! receive ring */
    struct netmap_ring *rx;
    /*<<! transmit ring */
    struct netmap_ring *tx;
    /*<<! lock handle */
    pthread_spinlock_t tx_lock;
} znetmap_ring_t;

typedef struct znetmap_iface_struct
{
    char ifname[IFNAMSIZ];
    /*<<! netmap NIC memory address */
    void *mem;
    /*<<! netmap NIC memory size */
    size_t memsize;
    /*<<! receive rings count */
    uint16_t rx_rings_count;
    /*<<! transmit rings count */
    uint16_t tx_rings_count;
    /*<<! maximum value of rx_rings_count and tx_rings_count */
    uint16_t rings_count;
    /*<<! rings array + sw ring */
    znetmap_ring_t *rings;
} znetmap_iface_t;

#define ZNM_RING(iface, idx) (&(iface)->rings[(idx)])
#define ZNM_SW_RING(iface) (&(iface)->rings[(iface)->rings_count])

znetmap_iface_t *znetmap_new(const char *ifname, znetmap_iface_t *parent);

void znetmap_free(znetmap_iface_t *dev);

bool znetmap_info(const char *ifname, struct nmreq *info);

int znm_ring_sync_rx(znetmap_ring_t *ring);

int znm_ring_try_sync_tx(znetmap_ring_t *ring, bool lock);

/**
 * @brief Swap slot buffers.
 * @param[in] s1 Netmap slot.
 * @param[in] s2 Netmap slot.
 */
static inline void znm_slot_swap(struct netmap_slot *s1, struct netmap_slot *s2)
{
    uint32_t tmp_idx;
    tmp_idx = s1->buf_idx;
    s1->buf_idx = s2->buf_idx;
    s2->buf_idx = tmp_idx;

    // copy the packet length
    uint16_t tmp_len = s1->len;
    s1->len = s2->len;
    s2->len = tmp_len;

    // report the buffer change
    s1->flags |= NS_BUF_CHANGED;
    s2->flags |= NS_BUF_CHANGED;
}

bool znm_ring_write_slot(znetmap_ring_t *ring, struct netmap_slot *slot, bool lock);

#endif // ZEROD_NETMAP_H
