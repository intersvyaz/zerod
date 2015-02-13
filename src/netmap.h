#ifndef NETMAP_H
#define NETMAP_H

#include <sys/types.h>

#include <net/netmap_user.h>

#define ZNM_DEVICE "/dev/netmap"

struct znm_ring {
    // netmap userspace descriptor
    int fd;
    // userspace mmap'ed memory address
    void *mem;
    // size of mmap'ed area
    size_t memsize;
    // mmap memory is owned by this handle flag
    unsigned own_mmap:1;
    // netmap interface
    struct netmap_if *nifp;
    // ring shortcuts
    struct netmap_ring *tx, *rx;
};

int znm_prepare_if(const char *ifname);

int znm_open(struct znm_ring *ring, const char *ifname, uint16_t ringid, void *mmap_mem);

void znm_close(struct znm_ring *ring);

int znm_info(const char *ifname, struct nmreq *nm_req);

#endif // NETMAP_H
