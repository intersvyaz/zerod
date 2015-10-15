#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <byteswap.h>
#include "packet.h"
#include "packet_ipv4.h"
#include "packet_arp.h"
#include "client.h"
#include "session.h"
#include "zero.h"
#include "log.h"

/**
 * Check port rules.
 * @param[in] sess Session.
 * @param[in] l4 Level 4 protocol data.
 * @return Zero on pass.
 */
int packet_process_ports(struct zsession *sess, const struct l4_data *l4)
{
    if (PROTO_MAX == l4->proto) {
        return 0;
    }

    pthread_rwlock_rdlock(&sess->lock_client);

    int ret = -1;
    struct zfirewall *fire = client_get_firewall(sess->client, false);
    if (!fire || (0 == zfwall_is_allowed(fire, l4->proto, *l4->dst_port))) {
        ret = 0;
    } else {
        ZERO_LOG(LOG_DEBUG, "DROP: session %s: restricted port %s %" PRIu16,
                 ipv4_to_str(htonl(sess->ip)), (PROTO_TCP == l4->proto ? "tcp" : "udp"), ntohs(*l4->dst_port));
    }

    pthread_rwlock_unlock(&sess->lock_client);

    return ret;
}

/**
 * Update bandwidth and traffic counters.
 *
 * @param[in] sess Session
 * @param[in] packet_len Packet length.
 * @param[in] flow_dir Packet flow direction.
 * @return Zero if packet is passed.
 */
int packet_process_bw(struct zsession *sess, size_t packet_len, enum flow_dir flow_dir)
{
    pthread_rwlock_rdlock(&sess->lock_client);

    struct zclient *client = sess->client;

    // check bw limits
    int pass = token_bucket_update(&client->band[flow_dir], packet_len);

    if (0 == pass) {
        // update packet and traffic counters
        atomic_uint32_t *packets_ptr;
        atomic_uint64_t *sess_traff_ptr;

        if (DIR_UP == flow_dir) {
            packets_ptr = &sess->packets_up;
            sess_traff_ptr = &sess->traff_up;
        } else {
            packets_ptr = &sess->packets_down;
            sess_traff_ptr = &sess->traff_down;
        }

        atomic_fetch_add_explicit(packets_ptr, 1, memory_order_release);
        atomic_fetch_add_explicit(sess_traff_ptr, packet_len, memory_order_release);
    }

    pthread_rwlock_unlock(&sess->lock_client);

    return pass;
}

/**
 * Rollback bandwidth and traffic update.
 *
 * @param[in] sess Session.
 * @param[in] packet_len Packet length.
 * @param[in] flow_dir Flow direction.
 */
void packet_rollback_bw(struct zsession *sess, size_t packet_len, enum flow_dir flow_dir)
{
    pthread_rwlock_rdlock(&sess->lock_client);

    struct zclient *client = sess->client;

    token_bucket_rollback(&client->band[flow_dir], packet_len);

    // update packet and traffic counters
    atomic_uint32_t *packets_ptr;
    atomic_uint64_t *sess_traff_ptr;

    if (DIR_UP == flow_dir) {
        packets_ptr = &sess->packets_up;
        sess_traff_ptr = &sess->traff_up;
    } else {
        packets_ptr = &sess->packets_down;
        sess_traff_ptr = &sess->traff_down;
    }

    atomic_fetch_sub_explicit(packets_ptr, 1, memory_order_release);
    atomic_fetch_sub_explicit(sess_traff_ptr, packet_len, memory_order_release);

    pthread_rwlock_unlock(&sess->lock_client);
}

/**
 * Process non-client traffic.
 * @param[in] packet_len Packet length.
 * @param[in] flow_dir Flow direction
 * @return Zero on pass.
*/
int packet_process_non_client(size_t packet_len, enum flow_dir flow_dir)
{
    if (0 == token_bucket_update(&zinst()->non_client.band[flow_dir], packet_len)) {
        spdm_update(&zinst()->non_client.speed[flow_dir], packet_len);
        // pass packet
        return 0;
    } else {
        // drop packet
        return -1;
    }
}

/**
 * Perform inspection of dhcp binding.
 * @param[in] mac MAC address.
 * @param[in] ip IP address (network order).
 * @return Zero on pass.
 */
int packet_inspect_mac_ip(const uint8_t *mac, uint32_t ip)
{
    struct zdhcp_lease lease = {.ip = ip};

    if (0 == zdhcp_lease_find(zinst()->dhcp, &lease)) {
        if ((ztime(false) > lease.lease_end) || (0 != memcmp(lease.mac, mac, sizeof(lease.mac)))) {
            return 1;
        }
    } else if ((ztime(false) - zinst()->start_time) > zcfg()->dhcp_default_lease_time) {
        return 1;
    }

    return 0;
}

/**
 * Packet analyzer.
 * @param[in] packet Packet to analyze.
 * @param[in] len Packet length.
 * @param[in] flow_dir Packet flow direction.
 * @param[out] traf_type Traffic type.
 * @return Zero on pass.
 */
int packet_process(unsigned char *packet, size_t len, enum flow_dir flow_dir, enum traffic_type *traf_type)
{
    struct ether_header *eth = (struct ether_header *) packet;
    uint16_t type = eth->ether_type;
    unsigned char *ptr = (unsigned char *) (eth + 1);

    for (; ;) {
        if ((htons(ETHERTYPE_VLAN) == type) || (htons(ETHERTYPE_VLAN_STAG) == type)) {
            struct vlan_header *vlh = (struct vlan_header *) ptr;
            type = vlh->type;
            ptr = (unsigned char *) (vlh + 1);
        }
        else if (htons(ETHERTYPE_IP) == type) {
            return packet_process_ipv4(eth, len, (struct ip *) ptr, flow_dir, traf_type);
        }
        else if (htons(ETHERTYPE_ARP) == type) {
            return packet_process_arp(eth, len, (struct arphdr *) ptr, flow_dir, traf_type);
        }
        else {
            // pass packet
            return 0;
        }
    }
}
