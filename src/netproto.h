#ifndef ZEROD_NETPROTO_H
#define ZEROD_NETPROTO_H

#include <stdint.h>

/**
 * Ethernet declarations.
 */

#define HWADDR_MAC48_LEN        6 /*<<! MAC48 length */
#define HWADDR_MAC48_STR_LEN    18 /*<<! MAC48 string length */

#define ETHERTYPE_VLAN_STAG     0x88A8 /*<<! 802.1ad Service VLAN */
#define ETHERTYPE_LLDP          0x88CC /*<<! 802.1ab Link Layer Discovery Protocol */

/**
 * VLAN declarations.
 */

#define VLAN_VID_MASK       0x0fff /* VLAN Identifier */

/**
 * @brief VLAN header.
 */
struct vlan_header
{
    /*<<! */
    uint16_t tci;
    /*<<! payload type */
    uint16_t type;
} __attribute__((__packed__));

/**
 * DHCP declarations.
 */

#define DHCP_CLIENT_PORT   68
#define DHCP_SERVER_PORT   67

#define BOOTREPLY   2
#define DHCPACK     5

#define DHCP_OPT_LEASE_TIME     51
#define DHCP_OPT_MESSAGE        53

/**
 * @brief DHCP option.
 */
struct dhcp_opt
{
    /*<<! option code */
    uint8_t code;
    /*<<! data length */
    uint8_t len;
    /*<<! data */
    union
    {
        uint8_t u8[0];
        uint16_t u16[0];
        uint32_t u32[0];
        uint64_t u64[0];
    } data;
} __attribute__((__packed__));

/**
 * @brief DHCP header.
 */
struct dhcp_header
{
    uint8_t op;
    /*<<! hardware address type */
    uint8_t htype;
    /*<<! hardware address length */
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    /*<<! client hardware address */
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint8_t magic[4];
    struct dhcp_opt opts[0];
} __attribute__((__packed__));

#define DHCP_OPT_SIZE(x) (sizeof(*x) + (x)->len)
#define DHCP_OPT_NEXT(x) (struct dhcp_opt *) ((unsigned char *) (x) + sizeof(*(x)) + (x)->len)

/**
 * ARP declarations.
 */

#define ARP_HTYPE_ETHERNET 1

#define ARP_REQ 1 /*<<! ARP request */
#define ARP_REP 2 /*<<! ARP response */

/**
 * @brief ARP header.
 */
struct arp_header
{
    /*<<! hardware address type */
    uint16_t htype;
    /*<<! protocol address type */
    uint16_t ptype;
    /*<<! hardware address length */
    uint8_t hlen;
    /*<<! protocol address length */
    uint8_t plen;
    /*<<! operation */
    uint16_t oper;
    union
    {
        struct
        {
            /*<<! source hardware address */
            uint8_t sha[HWADDR_MAC48_LEN];
            /*<<! source protocol address */
            uint32_t spa;
            /*<<! target hardware address */
            uint8_t tha[HWADDR_MAC48_LEN];
            /*<<! target protocol address */
            uint32_t tpa;
        } __attribute__((__packed__)) mac48_ipv4;
    };
} __attribute__((__packed__));

/**
 * HTTP declarations.
 */

#define HTTP_PORT       80

/**
 * IPv4 declarations.
 */

// is ipv4 address belongs to D or E class
#define IPV4_IS_DE_CLASS(x) (((x) >> 29) == 0b111u)

#endif // ZEROD_NETPROTO_H
