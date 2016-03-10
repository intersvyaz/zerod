#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <byteswap.h>

#include "packet.h"
#include "zero.h"
#include "log.h"
#include "config.h"

/**
 * Check port rules.
 * @param[in] sess Session.
 * @param[in] l4 Level 4 protocol data.
 * @return Zero on pass.
 */
zpacket_action_t zpacket_process_ports(const zl4_data_t *l4, zclient_t *client)
{
    if (PROTO_MAX == l4->proto) {
        return ACTION_PASS;
    }

    zpacket_action_t action = ACTION_PASS;
    zfirewall_t *fwall = zclient_firewall(client, false);
    if (fwall && !zfwall_is_allowed(fwall, l4->proto, *l4->dst_port)) {
        action = ACTION_DROP;
        //ZLOG(LOG_DEBUG, "DROP: session %s: restricted port %s %" PRIu16,
        //     sess->ip_str, (PROTO_TCP == l4->proto ? "tcp" : "udp"), ntohs(*l4->dst_port));
    }

    return action;
}

/**
 * Update bandwidth and traffic counters.
 *
 * @param[in] sess Session
 * @param[in] packet_len Packet length.
 * @param[in] flow_dir Packet flow direction.
 * @return Zero if packet is passed.
 */
zpacket_action_t zpacket_process_bw(const zpacket_t *packet, zsession_t *sess, zclient_t *client)
{
    // check bw limits
    zpacket_action_t pass = token_bucket_update(&client->band[packet->flow_dir], packet->length)
                            ? ACTION_PASS
                            : ACTION_DROP;

    if (0 == pass) {
        // update packet and traffic counters
        atomic_uint32_t *packets_ptr;
        atomic_uint64_t *sess_traff_ptr;

        if (DIR_UP == packet->flow_dir) {
            packets_ptr = &sess->packets_up;
            sess_traff_ptr = &sess->traff_up;
        } else {
            packets_ptr = &sess->packets_down;
            sess_traff_ptr = &sess->traff_down;
        }

        atomic_fetch_add_release(packets_ptr, 1);
        atomic_fetch_add_release(sess_traff_ptr, packet->length);
    }

    return pass;
}

/**
 * Rollback bandwidth and traffic update.
 *
 * @param[in] sess Session.
 * @param[in] packet_len Packet length.
 * @param[in] flow_dir Flow direction.
 */
void zpacket_rollback_bw(const zpacket_t *packet, zsession_t *sess, zclient_t *client)
{
    token_bucket_rollback(&client->band[packet->flow_dir], packet->length);

    // update packet and traffic counters
    atomic_uint32_t *packets_ptr;
    atomic_uint64_t *sess_traff_ptr;

    if (DIR_UP == packet->flow_dir) {
        packets_ptr = &sess->packets_up;
        sess_traff_ptr = &sess->traff_up;
    } else {
        packets_ptr = &sess->packets_down;
        sess_traff_ptr = &sess->traff_down;
    }

    atomic_fetch_sub_release(packets_ptr, 1);
    atomic_fetch_sub_release(sess_traff_ptr, packet->length);

    zclient_release(client);
}

/**
 * Process non-client traffic.
 * @param[in] packet Packet.
 * @return Zero on pass.
*/
zpacket_action_t zpacket_process_non_client(zpacket_t *packet)
{
    packet->traff_type = TRAFF_NON_CLIENT;

    if (token_bucket_update(&zinst()->non_client.band[packet->flow_dir], packet->length)) {
        spdm_update(&zinst()->non_client.speed[packet->flow_dir], packet->length);
        // pass packet
        return ACTION_PASS;
    } else {
        // drop packet
        return ACTION_DROP;
    }
}

/**
 *
 */
zscope_t *zpacket_guess_scope(const zpacket_t *packet)
{
    uint32_t client_ip = packet->flow_dir == DIR_UP ? packet->src_ip : packet->dst_ip;

    zscope_t *scope, *tmp_scope;
    HASH_ITER(hh, zinst()->scopes, scope, tmp_scope) {
        if (zsubnet_group_ip_belongs(&scope->cfg->client_subnets, client_ip)) {
            return scope;
        }
    }

    return NULL;
}

/**
 * Packet analyzer.
 * @param[in] packet Packet to analyze.
 * @param[in] len Packet length.
 * @param[in] flow_dir Packet flow direction.
 * @param[out] traf_type Traffic type.
 * @return Action for this packet.
 */
zpacket_action_t zpacket_process(zpacket_t *packet)
{
    struct ether_header *eth = (struct ether_header *) packet->data;
    uint16_t type = (uint16_t) eth->ether_type;
    unsigned char *payload = (unsigned char *) (eth + 1);

    if (htons(ETHERTYPE_LLDP) == type) {
        packet->traff_type = TRAFF_LOCAL;
        return zinst()->cfg->sw.lldp_pass_in ? ACTION_CONSUME : ACTION_PASS;
    }

    for (; ;) {
        if ((htons(ETHERTYPE_VLAN) == type) || (htons(ETHERTYPE_VLAN_STAG) == type)) {
            struct vlan_header *vlanh = (struct vlan_header *) payload;
            type = vlanh->type;
            payload = (unsigned char *) (vlanh + 1);
        }

        else if (htons(ETHERTYPE_IP) == type) {
            return zpacket_process_ipv4(packet, (struct ip *) payload);
        }

        else if (htons(ETHERTYPE_ARP) == type) {
            return zpacket_process_arp(packet, (struct arp_header *) payload);
        }

        else {
            packet->traff_type = TRAFF_LOCAL;
            // pass packet
            return ACTION_PASS;
        }
    }
}

/**
 * Packet analyzer.
 * @param[in] packet Packet to analyze.
 * @param[in] len Packet length.
 * @param[in] flow_dir Packet flow direction.
 * @param[out] traf_type Traffic type.
 * @return Action for this packet.
 */
zpacket_action_t zpacket_process_sw(zpacket_t *packet)
{
    struct ether_header *eth = (struct ether_header *) packet->data;
    uint16_t type = (uint16_t) eth->ether_type;

    packet->traff_type = TRAFF_LOCAL;

    if (htons(ETHERTYPE_LLDP) == type) {
        return zinst()->cfg->sw.lldp_pass_out ? ACTION_PASS : ACTION_DROP;
    }

    return ACTION_DROP;
}
