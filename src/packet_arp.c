#include <net/ethernet.h>
#include "packet.h"
#include "log.h"
#include "config.h"
#include "scope.h"

static zpacket_action_t zpkt_process_arp_ipv4(zpacket_t *packet, const struct arp_header *arph)
{
    packet->src_ip = ntohl(arph->mac48_ipv4.spa);
    packet->dst_ip = ntohl(arph->mac48_ipv4.tpa);

    zscope_t *scope = zpacket_guess_scope(packet);
    if (!scope) {
        return ACTION_DROP;
    }

    if (scope->cfg->security.arp_protect) {
        if (unlikely((htons(ARP_HTYPE_ETHERNET) != arph->htype) || (HWADDR_MAC48_LEN != arph->hlen))) {
            return ACTION_DROP;
        }

        // drop 0.0.0.0, 255.255.255.255, D,E class
        if (arph->mac48_ipv4.spa == INADDR_ANY || arph->mac48_ipv4.tpa == INADDR_ANY
            || arph->mac48_ipv4.spa == INADDR_BROADCAST || arph->mac48_ipv4.tpa == INADDR_BROADCAST
            || IPV4_IS_DE_CLASS(ntohl(arph->mac48_ipv4.spa)) || IPV4_IS_DE_CLASS(ntohl(arph->mac48_ipv4.tpa))) {
            return ACTION_DROP;
        }

        // src ethernet mac == src arp mac
        const struct ether_header *eth = (struct ether_header *) packet->data;
        if (0 != memcmp(eth->ether_shost, arph->mac48_ipv4.sha, HWADDR_MAC48_LEN)) {
            atomic_fetch_add_release(&scope->security.arp_errors, 1);
            return ACTION_DROP;
        }

        if (!zscope_dhcp_is_valid_mac_ip(scope, arph->mac48_ipv4.sha, packet->src_ip)) {
            if (unlikely(g_log_verbosity >= LOG_DEBUG)) {
                char ip_str[INET_ADDRSTRLEN];
                ipv4_to_str(arph->mac48_ipv4.spa, ip_str, sizeof(ip_str));

                char mac_str[HWADDR_MAC48_STR_LEN];
                mac48_bin_to_str(arph->mac48_ipv4.sha, mac_str, sizeof(mac_str));

                ZLOG(LOG_DEBUG, "%s: DROP: %s: ARP MAC violation %s", scope->cfg->name, ip_str, mac_str);
            }
            atomic_fetch_add_release(&scope->security.arp_errors, 1);
            return ACTION_DROP;
        }
    }

    return ACTION_PASS;
}

/**
 * Process ARP packets.
 * @param[in] packet Packet.
 * @param[in] arph ARP header.
 * @return Zero on pass.
 */
zpacket_action_t zpacket_process_arp(zpacket_t *packet, const struct arp_header *arph)
{
    packet->traff_type = TRAFF_LOCAL;

    // always trusted
    if (DIR_DOWN == packet->flow_dir) {
        return ACTION_PASS;
    }

    switch (ntohs(arph->ptype)) {
        case ETHERTYPE_IP:
            return zpkt_process_arp_ipv4(packet, arph);
        default:
            // skip others
            return ACTION_PASS;
    }
}
