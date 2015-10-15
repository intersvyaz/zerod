#ifndef ZEROD_NETPROTO_H
#define ZEROD_NETPROTO_H

#include <stdint.h>

/**
 * Ethrenet
 */

#define HWADDR_MAC48_LEN 6
#define HWADDR_MAC48_STR_LEN 18

#define ETHERTYPE_VLAN_STAG 0x88A8 // 802.1ad Service VLAN

/**
 * VLAN
 */

struct vlan_header
{
    uint16_t tci;
    uint16_t type;
} __attribute__((__packed__));

/**
 * DHCP
 */

#define BOOTREPLY 2
#define DHCPACK 5

#define DHCP_OPT_LEASE_TIME 51
#define DHCP_OPT_MESSAGE    53

struct dhcp_opt
{
    uint8_t code;
    uint8_t len;
    union {
        uint8_t u8[0];
        uint16_t u16[0];
        uint32_t u32[0];
        uint64_t u64[0];
    } data;
} __attribute__((__packed__));

struct dhcphdr
{
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint8_t magic[4];
} __attribute__((__packed__));

/**
 * ARP
 */

#define ARP_REQ 1
#define ARP_REP 2

struct arphdr
{
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    union
    {
        struct
        {
            uint8_t sha[6];
            uint32_t spa;
            uint8_t tha[6];
            uint32_t tpa;
        } __attribute__((__packed__)) mac48_ipv4;
    };
} __attribute__((__packed__));

#endif // ZEROD_NETPROTO_H
