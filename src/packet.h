#ifndef ZEROD_PACKET_H
#define ZEROD_PACKET_H

#include <stddef.h>
#include "router/router.h"
#include "util.h"

struct l4_data;
struct zsession;

enum traffic_type
{
    TRAFF_NON_CLIENT,
    TRAFF_CLIENT,
    TRAFF_HOME
};

int packet_process(unsigned char *packet, size_t len, enum flow_dir flow_dir, enum traffic_type *traf_type);

int packet_process_ports(struct zsession *sess, const struct l4_data *l4);

int packet_process_bw(struct zsession *sess, size_t packet_len, enum flow_dir flow_dir);

void packet_rollback_bw(struct zsession *sess, size_t packet_len, enum flow_dir flow_dir);

int packet_process_non_client(size_t packet_len, enum flow_dir flow_dir);

int packet_inspect_mac_ip(const uint8_t *mac, uint32_t ip);

#endif //ZEROD_PACKET_H
