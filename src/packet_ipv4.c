#include "packet.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include "log.h"
#include "client.h"
#include "session.h"
#include "zero.h"
#include "packet.h"
#include "blacklist.h"
#include "config.h"
#include "scope.h"

static void l4d_fill(struct ip *iph, zl4_data_t *l4)
{
    memset(l4, 0, sizeof(*l4));

    if (IPPROTO_TCP == iph->ip_p) {
        l4->tcph = (struct tcphdr *) ((uint32_t *) iph + iph->ip_hl);
        l4->src_port = &l4->tcph->source;
        l4->dst_port = &l4->tcph->dest;
        l4->csum = &l4->tcph->check;
        l4->proto = PROTO_TCP;


        size_t hlen = (iph->ip_hl + l4->tcph->th_off) * 4;
        uint16_t ip_len = ntohs(iph->ip_len);
        if (ip_len > hlen) {
            l4->data = (unsigned char *) iph + hlen;
            l4->data_len = ip_len - hlen;
        }
    } else if (IPPROTO_UDP == iph->ip_p) {
        l4->udph = (struct udphdr *) ((uint32_t *) iph + iph->ip_hl);
        l4->src_port = &l4->udph->source;
        l4->dst_port = &l4->udph->dest;
        l4->csum = &l4->udph->check;
        l4->proto = PROTO_UDP;

        uint16_t udp_len = ntohs(l4->udph->len);
        if (udp_len > sizeof(*l4->udph)) {
            l4->data = (unsigned char *) l4->udph + sizeof(*l4->udph);
            l4->data_len = udp_len - sizeof(*l4->udph);
        }
    } else {
        l4->proto = PROTO_MAX;
    }
}

/**
 * Apply forwarding rules.
 *
 * @param[in] sess Session.
 * @param[in] iph IPv4 header.
 * @param[in] l4 Layer 4 data.
 * @param[in] flow_dir Flow direction.
 * @return Zero on success.
 */
static void packet_process_forwarding_ipv4(zpacket_t *packet, struct ip *iph, zl4_data_t *l4,
                                           zsession_t *sess, zclient_t *client)
{
    if (PROTO_MAX == l4->proto) {
        return;
    }

    if (DIR_UP == packet->flow_dir) {
        zforwarder_t *fwdr = zclient_forwarder(client, false);
        if (fwdr) {
            zfwd_rule_t rule;
            if (zfwd_find_rule(fwdr, l4->proto, *l4->dst_port, &rule)) {
                znat_t *nat = zsession_get_nat(sess, true);
                zfwd_forward_ipv4(nat, iph, l4, rule.fwd_ip, rule.fwd_port);
            }
        }
    } else {
        znat_t *nat = zsession_get_nat(sess, false);
        if (NULL != nat) {
            zfwd_unforward_ipv4(nat, iph, l4);
        }
    }
}

/**
 *
 */
static void zpkt_guess_traffic_type(zpacket_t *packet, const zscope_t *scope)
{
    uint32_t peer_ip = DIR_UP == packet->flow_dir ? packet->dst_ip : packet->src_ip;

    if (zsubnet_group_ip_belongs(&scope->cfg->local_subnets_exclusions, peer_ip)) {
        packet->traff_type = TRAFF_CLIENT;
        packet->hybrid_traffic = true;
    } else if (zsubnet_group_ip_belongs(&scope->cfg->local_subnets, peer_ip)) {
        packet->traff_type = TRAFF_LOCAL;
    } else {
        packet->traff_type = TRAFF_CLIENT;
    }
}

/**
 *
 */
static bool zpkt_ip_protect(zpacket_t *packet, zscope_t *scope, const zl4_data_t *l4)
{
    if ((DIR_DOWN == packet->flow_dir) || !scope->cfg->security.ip_protect) {
        return true;
    }

    // pass all traffic that looks like DHCP (for weird hardware)
    if ((TRAFF_LOCAL == packet->traff_type)
        && (PROTO_UDP == l4->proto)
        && (htons(DHCP_CLIENT_PORT) == *l4->src_port)
        && (htons(DHCP_SERVER_PORT) == *l4->dst_port)) {
        return true;
    }

    const struct ether_header *eth = (struct ether_header *) packet->data;
    if (!zscope_dhcp_is_valid_mac_ip(scope, (const uint8_t *) eth->ether_shost, packet->src_ip)) {
        if (unlikely(g_log_verbosity >= LOG_DEBUG)) {
            char ip_str[INET_ADDRSTRLEN];
            ipv4_to_str(htonl(packet->src_ip), ip_str, sizeof(ip_str));

            char mac_str[HWADDR_MAC48_STR_LEN];
            mac48_bin_to_str((const uint8_t *) eth->ether_shost, mac_str, sizeof(mac_str));

            ZLOG(LOG_DEBUG, "DROP: %s: IP guard violation with %s", ip_str, mac_str);
        }
        atomic_fetch_add_release(&scope->security.ip_errors, 1);
        return false;
    }

    return true;
}

/**
 * IPv4 packet analyzer.
 *
 * @param[in] packet Packet.
 * @param[in] iph IPv4 header.
 * @return Zero on pass.
 */
zpacket_action_t zpacket_process_ipv4(zpacket_t *packet, struct ip *iph)
{
    zl4_data_t l4;
    l4d_fill(iph, &l4);

    // DHCP snooping
    if ((DIR_DOWN == packet->flow_dir)
        && (IPPROTO_UDP == iph->ip_p)
        && (htons(DHCP_CLIENT_PORT) == *l4.dst_port)
        && (htons(DHCP_SERVER_PORT) == *l4.src_port)
        && (l4.data_len >= sizeof(struct dhcp_header))) {
        zpacket_process_dhcp(packet, (struct dhcp_header *) l4.data, l4.data_len);
    }

    // anycast, broadcast
    if ((INADDR_ANY == iph->ip_src.s_addr) || (INADDR_BROADCAST == iph->ip_dst.s_addr)) {
        packet->traff_type = TRAFF_LOCAL;
        return ACTION_PASS;
    }

    packet->src_ip = ntohl(iph->ip_src.s_addr);
    packet->dst_ip = ntohl(iph->ip_dst.s_addr);

    zscope_t *scope = zpacket_guess_scope(packet);
    if (!scope) {
        return zpacket_process_non_client(packet);
    }

    zpkt_guess_traffic_type(packet, scope);

    // ip guard
    if (!zpkt_ip_protect(packet, scope, &l4)) {
        return ACTION_DROP;
    }

    uint32_t client_ip = DIR_UP == packet->flow_dir ? packet->src_ip : packet->dst_ip;

    // acquire session for this ip
    // create new session only for outgoing packets
    uint32_t sess_flags = (DIR_DOWN == packet->flow_dir) ? SF_EXISTING_ONLY : 0;
    zsession_t *sess = zscope_session_acquire(scope, client_ip, sess_flags);

    if (NULL == sess) {
        if ((TRAFF_LOCAL == packet->traff_type) || packet->hybrid_traffic) {
            return ACTION_PASS;
        } else {
            return zpacket_process_non_client(packet);
        }
    }

    zclient_t *client = zsession_get_client(sess);

    // update last activity time only for outgoing packets
    if ((DIR_UP == packet->flow_dir) && (TRAFF_CLIENT == packet->traff_type)) {
        sess->last_activity = ztime();
    }

    zpacket_action_t drop = ACTION_PASS;

    if (TRAFF_CLIENT == packet->traff_type && !packet->hybrid_traffic) {
        // check and update bandwidth
        if (zpacket_process_bw(packet, sess, client)) {
            drop = ACTION_DROP;
            goto end;
        }

        if (DIR_UP == packet->flow_dir) {
            if (zpacket_process_ports(&l4, client)) {
                drop = ACTION_DROP;
                goto end;
            }

            if (scope->blacklist && (l4.proto == PROTO_TCP) && l4.data_len && (htons(HTTP_PORT) == *l4.dst_port)) {
                if (zblacklist_check(scope->blacklist, (char *) l4.data, l4.data_len)) {
                    atomic_fetch_add_release(&scope->blacklist_hits, 1);
                    drop = ACTION_DROP;
                    goto end;
                }
            }
        }

        spdm_update(&client->speed[packet->flow_dir], packet->length);
    }

    // preform packet forwarding
    // forward only client or incoming home traffic
    if ((TRAFF_CLIENT == packet->traff_type) || (DIR_DOWN == packet->flow_dir)) {
        packet_process_forwarding_ipv4(packet, iph, &l4, sess, client);
    }

    end:
    zclient_release(client);
    zsession_release(sess);

#ifndef NDEBUG
    {
        if (PROTO_MAX != l4.proto) {
            uint16_t port = (packet->flow_dir == DIR_UP) ? ntohs(*l4.dst_port) : ntohs(*l4.src_port);
            zinst()->dbg.traff_counter[l4.proto][port].packets++;
            zinst()->dbg.traff_counter[l4.proto][port].bytes += packet->length;
        }
    }
#endif

    // pass/drop packet
    return drop;
}
