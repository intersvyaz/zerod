#ifndef ZEROD_PACKET_H
#define ZEROD_PACKET_H

#include <stddef.h>
#include "netdef.h"
#include "util.h"
#include "scope.h"

typedef enum ztraff_type_enum
{
    TRAFF_CLIENT,
    TRAFF_LOCAL,
    TRAFF_NON_CLIENT,
    TRAFF_MAX
} ztraff_type_t;

typedef enum zpacket_action_enum
{
    ACTION_PASS,
    ACTION_DROP,
    ACTION_CONSUME,
    ACTION_MAX
} zpacket_action_t;

typedef struct zpacket_struct {
    /*<<! packet payload */
    uint8_t *data;
    /*<<! packet length */
    size_t length;
    /*<<! flow direction */
    zflow_dir_t flow_dir;
    /*<<! traffic type */
    ztraff_type_t traff_type;
    /*<<! hybrid traffic flag */
    bool hybrid_traffic;

    /*<<! source IP address, if available (host order) */
    uint32_t src_ip;
    /*<<! destination IP address, if available (host order) */
    uint32_t dst_ip;
} zpacket_t;

zscope_t *zpacket_guess_scope(const zpacket_t *packet);

zpacket_action_t zpacket_process(zpacket_t *packet);

zpacket_action_t zpacket_process_sw(zpacket_t *packet);

zpacket_action_t zpacket_process_ports(const zl4_data_t *l4, zclient_t *client);

zpacket_action_t zpacket_process_bw(const zpacket_t *packet, zsession_t *sess, zclient_t *client);

void zpacket_rollback_bw(const zpacket_t *packet, zsession_t *sess, zclient_t *client);

zpacket_action_t zpacket_process_non_client(zpacket_t *packet);

/*
 * ARP
 */

zpacket_action_t zpacket_process_arp(zpacket_t *packet, const struct arp_header *arph);

/*
 * IPv4
 */

zpacket_action_t zpacket_process_ipv4(zpacket_t *packet, struct ip *iph);

/*
 * DHCP
 */

void zpacket_process_dhcp(zpacket_t *packet, struct dhcp_header *dhcph, size_t len);

#endif //ZEROD_PACKET_H
