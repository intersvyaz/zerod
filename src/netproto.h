#ifndef NETPROTO_H
#define NETPROTO_H

#include <inttypes.h>

#define ETHERTYPE_VLAN_STAG    0x88A8          /* 802.1ad Service VLAN         */

struct vlan_header {
    uint16_t tci;
    // payload type
    uint16_t type;
};

uint16_t in_csum_update(uint16_t old_csum, uint16_t len, const uint16_t *old_data, const uint16_t *new_data);

#endif // NETPROTO_H
