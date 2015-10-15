#include <net/ethernet.h>
#include "packet_arp.h"
#include "router/netproto.h"
#include "session.h"
#include "zero.h"
#include "log.h"

/**
 * Process ARP packets.
 * @param[in] packet_len Packet length.
 * @param[in] arph ARP packet.
 * @param[in] flow_dir Flow direction.
 * @param[in,out] traf_type Traffic type.
 * @return Zero on pass.
 */
int packet_process_arp(struct ether_header *eth, size_t packet_len, struct arphdr *arph, enum flow_dir flow_dir,
                       enum traffic_type *traf_type)
{
    (void) eth;
    (void) packet_len;
    (void) traf_type;

    if ((zinst()->arp.mode >= AIM_LOOSE) && (DIR_UP == flow_dir)) {
        if (htons(ETHERTYPE_IP) == arph->ptype && sizeof(uint32_t) == arph->plen && HWADDR_MAC48_LEN == arph->hlen) {
            if (0 != packet_inspect_mac_ip(arph->mac48_ipv4.sha, arph->mac48_ipv4.spa)) {
                atomic_fetch_add_explicit(&zinst()->arp.arp_errors, 1, memory_order_release);
                ZERO_LOG(LOG_DEBUG, "DROP: %s: ARP MAC violation %s",
                         ipv4_to_str(arph->mac48_ipv4.spa), mac48_bin_to_str(arph->mac48_ipv4.sha));
                return 1;
            }
        }
    }

    return 0;
}
