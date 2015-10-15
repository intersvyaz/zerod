#ifndef ZEROD_PACKET_IPV4_H
#define ZEROD_PACKET_IPV4_H

#include <stddef.h>
#include "router/router.h"

struct ip;
struct ether_header;
enum traffic_type;

int packet_process_ipv4(struct ether_header *eth, size_t packet_len, struct ip *iph, enum flow_dir flow_dir,
                        enum traffic_type *traff_type);

#endif // ZEROD_PACKET_IPV4_H
