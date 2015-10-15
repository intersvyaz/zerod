#ifndef ZEROD_PACKET_ARP_H
#define ZEROD_PACKET_ARP_H

#include <stddef.h>
#include "packet.h"
#include "util.h"

struct arphdr;
struct ether_header;

int packet_process_arp(struct ether_header *eth, size_t packet_len, struct arphdr *arph, enum flow_dir flow_dir,
                       enum traffic_type *traf_type);

#endif //ZEROD_PACKET_ARP_H
