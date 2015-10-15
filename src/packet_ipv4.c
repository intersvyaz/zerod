#include "packet_ipv4.h"
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

static void l4d_fill(struct ip *iph, struct l4_data *l4)
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
static void packet_process_forwarding_ipv4(struct zsession *sess, struct ip *iph, struct l4_data *l4,
                                           enum flow_dir flow_dir)
{
    if (PROTO_MAX == l4->proto) {
        return;
    }

    pthread_rwlock_rdlock(&sess->lock_client);

    if (DIR_UP == flow_dir) {
        struct zforwarder *fwdr = client_get_forwarder(sess->client, false);
        if (fwdr) {
            struct zfwd_rule rule;
            if (0 == zfwd_find_rule(fwdr, l4->proto, *l4->dst_port, &rule)) {
                struct znat *nat = session_get_nat(sess, true);
                zfwd_forward_ipv4(nat, iph, l4, rule.fwd_ip, rule.fwd_port);
            }
        }
    } else {
        struct znat *nat = session_get_nat(sess, false);
        if (NULL != nat) {
            zfwd_unforward_ipv4(nat, iph, l4);
        }
    }

    pthread_rwlock_unlock(&sess->lock_client);
}

/**
 * Process upstream p2p bandwidth limits.
 *
 * @param[in] sess Session.
 * @param[in] packet_len Packet length.
 * @param[in] iph IP header.
 * @param[in] flow_dir Flow direction.
 * @return Zero on pass.
 */
static int packet_process_p2p_ipv4(struct zsession *sess, size_t packet_len, struct ip *iph, struct l4_data *l4,
                                   enum flow_dir flow_dir)
{
    if (PROTO_MAX == l4->proto) {
        return 0;
    }

    uint16_t port = ntohs((DIR_UP == flow_dir) ? *l4->dst_port : *l4->src_port);

    pthread_rwlock_rdlock(&sess->lock_client);

    // p2p police enabled and port greater than 1024 and not whitelisted
    if (sess->client->p2p_policy && (port >= 1024) && !utarray_find(&zcfg()->p2p_ports_whitelist, &port, uint16_cmp)) {
        uint64_t speed = spdm_calc(&sess->client->speed[flow_dir]);
        // 1/4 of bw limit
        uint64_t throttle_speed = token_bucket_get_max(&sess->client->band[flow_dir]) / 4;

        uint64_t diff = zclock(false) - sess->client->last_p2p_throttle;
        if ((speed > throttle_speed) || (diff < P2P_THROTTLE_TIME)) {
            unsigned upstream_id = IPTOS_DSCP(iph->ip_tos) >> 2;
            struct token_bucket *bucket = &zinst()->upstreams[upstream_id].band[flow_dir];
            if (0 != token_bucket_update(bucket, packet_len)) {
                return -1;
            }

            struct speed_meter *spd = &zinst()->upstreams[upstream_id].speed[flow_dir];
            spdm_update(spd, packet_len);

            diff = zclock(false) - atomic_load_explicit(&sess->client->last_p2p_throttle, memory_order_acquire);
            if (diff > P2P_THROTTLE_TIME) {
                atomic_store_explicit(&sess->client->last_p2p_throttle, zclock(false), memory_order_release);
            }
        }
    }

    pthread_rwlock_unlock(&sess->lock_client);

    return 0;
}

/**
 * Process DHCP packets.
 *
 * @param[in] dhcph DHCP packet.
 * @return Zero on success.
 */
static int process_dhcp(struct dhcphdr *dhcph, size_t len)
{
    len -= sizeof(*dhcph);
    if (len && (BOOTREPLY == dhcph->op) && (HWADDR_MAC48_LEN == dhcph->hlen)) {
        bool is_ack = false;
        uint64_t lease_time = 0;
        struct dhcp_opt *opt = (struct dhcp_opt *) (dhcph + 1);

        while (len >= (sizeof(*opt) + opt->len)) {
            switch (opt->code) {
                case DHCP_OPT_MESSAGE:
                    if ((1 == opt->len) && (DHCPACK == opt->data.u8[0])) {
                        is_ack = true;
                    } else {
                        // skip all non-ack packets
                        break;
                    }
                    break;
                case DHCP_OPT_LEASE_TIME:
                    if (4 == opt->len) {
                        lease_time = ztime(false) + SEC2USEC(ntohl(opt->data.u32[0]));
                    }
                    break;
            }

            len -= sizeof(*opt) + opt->len;
            opt = (struct dhcp_opt *) ((unsigned char *) opt + sizeof(*opt) + opt->len);
        }

        if (is_ack) {
            // store dhcp binding
            struct zdhcp_lease lease;
            lease.ip = dhcph->yiaddr;
            memcpy(lease.mac, dhcph->chaddr, sizeof(lease.mac));
            lease.lease_end = lease_time;
            zdhcp_lease_bind(zinst()->dhcp, &lease);

            // also create session for client ip and save info
            bool is_client_ip = false;
            uint32_t client_ip = ntohl(dhcph->yiaddr);
            if (utarray_len(&zcfg()->client_net)) {
                struct ip_range ipr_dummy;
                ipr_dummy.ip_start = ipr_dummy.ip_end = client_ip;
                const struct ip_range *ipr_search = utarray_find(&zcfg()->client_net, &ipr_dummy, ip_range_cmp);
                is_client_ip = (ipr_search != NULL);
            } else {
                is_client_ip = true;
            }
            if (is_client_ip) {
                struct zsession *sess = session_acquire(client_ip, SF_NO_DHCP_SEARCH);
                memcpy(sess->hw_addr, dhcph->chaddr, sizeof(sess->hw_addr));
                sess->has_hw_addr = true;
                sess->dhcp_lease_end = lease_time;
                session_release(sess);
            }
        }
    }

    return 0;
}

/**
 * IPv4 packet analyzer.
 *
 * @param[in] packet_len Packet length.
 * @param[in] iph IPv4 header.
 * @param[in] flow_dir Flow direction
 * @param[out] traff_type Traffic type.
 * @return Zero on pass.
 */
int packet_process_ipv4(struct ether_header *eth, size_t packet_len, struct ip *iph, enum flow_dir flow_dir,
                        enum traffic_type *traff_type)
{
    struct l4_data l4;
    l4d_fill(iph, &l4);

    uint32_t client_ip = ntohl(DIR_UP == flow_dir ? iph->ip_src.s_addr : iph->ip_dst.s_addr);

    // DHCP
    if (DIR_DOWN == flow_dir && IPPROTO_UDP == iph->ip_p) {
        if ((htons(68) == *l4.dst_port) && (l4.data_len >= sizeof(struct dhcphdr))) {
            process_dhcp((struct dhcphdr *) l4.data, l4.data_len);
        }
    }

    // special cases
    if ((INADDR_ANY == iph->ip_src.s_addr) || (INADDR_BROADCAST == iph->ip_dst.s_addr)) {
        *traff_type = TRAFF_HOME;
        return 0;
    }

    /**
     * GUESS TRAFFIC TYPE
     */

    bool hybrid_traffic = false;
    *traff_type = TRAFF_NON_CLIENT;

    if (utarray_len(&zcfg()->client_net)) {
        struct ip_range ipr_dummy;
        const struct ip_range *ipr_search;

        ipr_dummy.ip_start = ipr_dummy.ip_end = client_ip;
        ipr_search = utarray_find(&zcfg()->client_net, &ipr_dummy, ip_range_cmp);
        if (ipr_search) {
            *traff_type = TRAFF_CLIENT;
        }
    } else {
        *traff_type = TRAFF_CLIENT;
    }

    if ((TRAFF_CLIENT == *traff_type) && utarray_len(&zcfg()->home_net)) {
        struct ip_range ipr_dummy;
        const struct ip_range *ipr_search;
        uint32_t peer_ip = ntohl(DIR_DOWN == flow_dir ? iph->ip_src.s_addr : iph->ip_dst.s_addr);

        ipr_dummy.ip_start = ipr_dummy.ip_end = peer_ip;
        ipr_search = utarray_find(&zcfg()->home_net, &ipr_dummy, ip_range_cmp);
        if (ipr_search) {
            // excluded from home (hybrid) ?
            ipr_search = utarray_find(&zcfg()->home_net_exclude, &ipr_dummy, ip_range_cmp);
            if (ipr_search) {
                hybrid_traffic = true;
            } else {
                *traff_type = TRAFF_HOME;
            }
        }
    }

    /**
     * PERFORM ACTIONS
     */

    // ip guard
    if ((AIM_STRICT == zinst()->arp.mode) && (DIR_UP == flow_dir)) {
        // exclude DHCP
        if (!((TRAFF_HOME == *traff_type) && (IPPROTO_UDP == iph->ip_p) &&
              (htons(68) == *l4.src_port) && (htons(67) == *l4.dst_port)
        )) {
            if (0 != packet_inspect_mac_ip(eth->ether_shost, iph->ip_src.s_addr)) {
                atomic_fetch_add_explicit(&zinst()->arp.ip_errors, 1, memory_order_release);
                ZERO_LOG(LOG_DEBUG, "DROP: %s: IP guard violation with %s",
                         ipv4_to_str(iph->ip_src.s_addr), mac48_bin_to_str(eth->ether_shost));
                return 1;
            }
        }
    }

    if (TRAFF_NON_CLIENT == *traff_type) {
        return packet_process_non_client(packet_len, flow_dir);
    }

    // acquire session for this ip
    // create new session only for outgoing packets
    uint32_t sess_flags = (DIR_DOWN == flow_dir) ? SF_EXISTING_ONLY : 0;
    struct zsession *sess = session_acquire(client_ip, sess_flags);

    if (NULL == sess) {
        if (TRAFF_HOME == *traff_type) {
            return 0;
        } else {
            *traff_type = TRAFF_NON_CLIENT;
            return packet_process_non_client(packet_len, flow_dir);
        }
    }

    // update last activity time only for outgoing packets
    if ((DIR_UP == flow_dir) && (TRAFF_CLIENT == *traff_type)) {
        sess->last_activity = ztime(false);
    }

    // DNS Amplification attack detector
    if ((DIR_DOWN == flow_dir) && (IPPROTO_UDP == iph->ip_p) && (htons(53) == *l4.src_port)) {
        spdm_update(&sess->dns_speed, 1);
    }

    // prevent changing client in session
    pthread_rwlock_rdlock(&sess->lock_client);

    int drop = 0;

    if (TRAFF_CLIENT == *traff_type && !hybrid_traffic) {
        // check ports on outgoing packets
        if (DIR_UP == flow_dir) {
            if (packet_process_ports(sess, &l4)) {
                drop = 1;
                goto end;
            }
        }

        // check and update bandwidth
        if (packet_process_bw(sess, packet_len, flow_dir)) {
            drop = 1;
            goto end;
        }
        if (packet_process_p2p_ipv4(sess, packet_len, iph, &l4, flow_dir)) {
            packet_rollback_bw(sess, packet_len, flow_dir);
            drop = 1;
            goto end;
        }
    }

    // preform packet forwarding
    // forward only client or incoming home traffic
    if ((TRAFF_CLIENT == *traff_type) || (DIR_DOWN == flow_dir)) {
        packet_process_forwarding_ipv4(sess, iph, &l4, flow_dir);
    }

    // check blacklist
    if (zinst()->blacklist && (TRAFF_CLIENT == *traff_type) && (DIR_UP == flow_dir)) {
        if ((IPPROTO_TCP == iph->ip_p) && l4.data_len && (htons(80) == *l4.dst_port)) {
            if (zblacklist_process(zinst()->blacklist, sess, (char *) l4.data, l4.data_len)) {
                drop = 1;
                goto end;
            }
        }
    }

    if ((TRAFF_CLIENT == *traff_type) && !hybrid_traffic) {
        spdm_update(&sess->client->speed[flow_dir], packet_len);
    }

    end:
    pthread_rwlock_unlock(&sess->lock_client);
    session_release(sess);

#ifndef NDEBUG
    {
        if (PROTO_MAX != l4.proto) {
            uint16_t port = (flow_dir == DIR_UP) ? ntohs(*l4.dst_port) : ntohs(*l4.src_port);
            zinst()->dbg.traff_counter[l4.proto][port].packets++;
            zinst()->dbg.traff_counter[l4.proto][port].bytes += packet_len;
        }
    }
#endif

    // pass/drop packet
    return drop;
}
