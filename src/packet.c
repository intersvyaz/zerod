#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

#include "client.h"
#include "session.h"
#include "zero.h"
#include "netproto.h"
#include "router/router.h"
#include "log.h"

/**
* Check port rules.
* @param[in] sess Session.
* @param[in] iph IP header.
* @return Zero on pass.
*/
static int process_ports(struct zsession *sess, struct ip *iph)
{
    uint16_t port = 0;
    enum ipproto proto = PROTO_TCP;

    if (IPPROTO_TCP == iph->ip_p) {
        struct tcphdr *tcph = (struct tcphdr *) ((uint32_t *) iph + iph->ip_hl);
        port = tcph->dest;
        proto = PROTO_TCP;
    } else if (IPPROTO_UDP == iph->ip_p) {
        struct udphdr *udph = (struct udphdr *) ((uint32_t *) iph + iph->ip_hl);
        port = udph->dest;
        proto = PROTO_UDP;
    }

    if (0 == port) {
        return 0;
    }

    struct zfirewall *fire = client_get_firewall(sess->client, false);
    if (NULL == fire) {
        return 0;
    }

    if (0 == zfwall_is_allowed(fire, proto, port)) {
        return 0;
    } else {
        return -1;
    }
}

/**
* Update traffic counters.
* @param[in] sess Session
* @param[in] packet_len Packet length.
* @param[in] flow_dir Packet flow direction.
* @return Zero if packet is passed.
*/
static int process_bw(struct zsession *sess, u_int packet_len, enum flow_dir flow_dir)
{
    struct zclient *client = sess->client;

    // check bw limits
    int pass = token_bucket_update(&client->bw_bucket[flow_dir], packet_len);

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

        atomic_fetch_add_explicit(packets_ptr, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(sess_traff_ptr, packet_len, memory_order_relaxed);
    }

    return pass;
}

/**
* Apply forwarding rules.
* @param[in] sess Session.
* @param[in] iph IPv4 header.
* @param[in] flow_dir Flow direction.
* @return Zero on success.
*/
static int process_forwarding(struct zsession *sess, struct ip *iph, enum flow_dir flow_dir)
{
    struct zfwd_rule rule;
    enum ipproto proto;
    uint16_t *dst_port;
    void *l4hdr;

    if (IPPROTO_TCP == iph->ip_p) {
        struct tcphdr *tcph = (struct tcphdr *) ((uint32_t *) iph + iph->ip_hl);
        l4hdr = tcph;
        dst_port = &tcph->dest;
        proto = PROTO_TCP;
    } else if (IPPROTO_UDP == iph->ip_p) {
        struct udphdr *udph = (struct udphdr *) ((uint32_t *) iph + iph->ip_hl);
        l4hdr = udph;
        dst_port = &udph->dest;
        proto = PROTO_UDP;
    } else {
        return 0;
    }

    if (DIR_UP == flow_dir) {
        struct zforwarder *fwdr = client_get_forwarder(sess->client, false);
        if (NULL == fwdr) {
            return 0;
        }

        if (0 != zfwd_find_rule(fwdr, proto, *dst_port, &rule)) {
            return 0;
        }
        struct znat *nat = session_get_nat(sess, true);
        zfwd_forward(nat, iph, proto, l4hdr, rule.fwd_ip, rule.fwd_port);
    } else {
        struct znat *nat = session_get_nat(sess, false);
        if (NULL != nat) {
            zfwd_unforward(nat, iph, proto, l4hdr);
        }
    }

    return 0;
}

/**
* Rollback client bandwidth update.
* @param[in] sess Session.
* @param[in] packet_len Packet length.
* @param[in] flow_dir Flow direction.
*/
void rollback_bw(struct zsession *sess, u_int packet_len, enum flow_dir flow_dir)
{
    struct zclient *client = sess->client;

    token_bucket_rollback(&client->bw_bucket[flow_dir], packet_len);

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

    atomic_fetch_sub_explicit(packets_ptr, 1, memory_order_relaxed);
    atomic_fetch_sub_explicit(sess_traff_ptr, packet_len, memory_order_relaxed);
}

/**
* Process upstream p2p bandwidth limits.
* @param[in] sess Session.
* @param[in] packet_len Packet length.
* @param[in] iph IP header.
* @param[in] flow_dir Flow direction.
* @return Zero on pass.
*/
int process_p2p(struct zsession *sess, u_int packet_len, struct ip *iph, enum flow_dir flow_dir)
{
    uint16_t port = 0;

    if (IPPROTO_TCP == iph->ip_p) {
        struct tcphdr *tcph = (struct tcphdr *) ((uint32_t *) iph + iph->ip_hl);
        port = ntohs((DIR_UP == flow_dir) ? tcph->dest : tcph->source);
    } else if (IPPROTO_UDP == iph->ip_p) {
        struct udphdr *udph = (struct udphdr *) ((uint32_t *) iph + iph->ip_hl);
        port = ntohs((DIR_UP == flow_dir) ? udph->dest : udph->source);
    }

    // p2p policer enabled and port greater than 1024 and not whitelisted
    if (sess->client->p2p_policer
            && (port >= 1024)
            && !utarray_find(&zcfg()->p2p_ports_whitelist, &port, uint16_cmp)
            ) {
        uint64_t speed = spdm_calc(&sess->client->speed[flow_dir]);
        // 1/4 of bw limit
        uint64_t throttle_speed = atomic_load_explicit(&sess->client->bw_bucket[flow_dir].max_tokens, memory_order_relaxed) / 4;

        if ((speed > throttle_speed) || (zclock(false) - atomic_load_explicit(&sess->client->last_p2p_throttle, memory_order_acquire) < P2P_THROTTLE_TIME)) {
            unsigned upstream_id = IPTOS_DSCP(iph->ip_tos) >> 2;
            struct token_bucket *bucket = &zinst()->upstreams[upstream_id].p2p_bw_bucket[flow_dir];
            if (0 != token_bucket_update(bucket, packet_len)) {
                return -1;
            }

            struct speed_meter *spd = &zinst()->upstreams[upstream_id].speed[flow_dir];
            spdm_update(spd, packet_len);

            if (zclock(false) - atomic_load_explicit(&sess->client->last_p2p_throttle, memory_order_acquire) > P2P_THROTTLE_TIME) {
                atomic_store_explicit(&sess->client->last_p2p_throttle, zclock(false), memory_order_release);
            }
        }
    }

    return 0;
}

/**
* Process non-client traffic.
* @param[in] len
* @param[in] flow_dir Flow direction
* @return Zero on pass.
*/
int process_non_client_traffic(u_int len, struct ip *iph, enum flow_dir flow_dir)
{
    // pass DHCP
    if (IPPROTO_UDP == iph->ip_p) {
        struct udphdr *udph = (struct udphdr *) ((uint32_t *) iph + iph->ip_hl);
        if (htons(67) == udph->dest || htons(68) == udph->dest) {
            return 0;
        }
    }

    if (0 == token_bucket_update(&zinst()->non_client.bw_bucket[flow_dir], len)) {
        spdm_update(&zinst()->non_client.speed[flow_dir], len);
        // pass packet
        return 0;
    } else {
        // drop packet
        return -1;
    }
}

struct ip *ip_header_seek(unsigned char *packet)
{
    struct ether_header *eth = (struct ether_header *) packet;
    uint16_t type = eth->ether_type;
    unsigned char *ptr = (unsigned char *)(eth + 1);

    for(;;) {
        if (htons(ETHERTYPE_IP) == type) {
            return (struct ip *)ptr;
        }
        else if ((htons(ETHERTYPE_VLAN) == type) || (htons(ETHERTYPE_VLAN_STAG) == type)) {
            struct vlan_header *vlh = (struct vlan_header *)ptr;
            type = vlh->type;
            ptr = (unsigned char *)(vlh + 1);
        }
        else {
            return NULL;
        }
    }
}

/**
* Packet analyzer.
* @param[in] packet Packet to analyze.
* @param[in] len Packet length.
* @param[in] flow_dir Packet flow direction.
* @param[out] traf_type Traffic type.
* @return Zero on pass.
*/
int process_packet(unsigned char *packet, u_int len, enum flow_dir flow_dir, enum traffic_type *traf_type)
{
    struct ip_range ipr_dummy;
    const struct ip_range *ipr_search;

    struct ip *iph = ip_header_seek(packet);

    // pass non ip packets
    if (NULL == iph) {
        return 0;
    }

    uint32_t client_ip = ntohl(DIR_UP == flow_dir ? iph->ip_src.s_addr : iph->ip_dst.s_addr);

    // pass non-client
    if (utarray_len(&zcfg()->client_net)) {
        ipr_dummy.ip_start = ipr_dummy.ip_end = client_ip;
        ipr_search = utarray_find(&zcfg()->client_net, &ipr_dummy, ip_range_cmp);
        if (!ipr_search) {
            *traf_type = TRAF_NON_CLIENT;
            return process_non_client_traffic(len, iph, flow_dir);
        }
    }

    // home excluded traffic (port and bandwidth rules does not apply)
    bool hybrid_traffic = false;
    // home traffic?
    uint32_t peer_ip = ntohl(DIR_UP != flow_dir ? iph->ip_src.s_addr : iph->ip_dst.s_addr);
    ipr_dummy.ip_start = ipr_dummy.ip_end = peer_ip;
    ipr_search = utarray_find(&zcfg()->home_net, &ipr_dummy, ip_range_cmp);
    if (ipr_search) {
        // excluded from home?
        ipr_search = utarray_find(&zcfg()->home_net_exclude, &ipr_dummy, ip_range_cmp);
        if (ipr_search) {
            *traf_type = TRAF_CLIENT;
            hybrid_traffic = true;
        } else {
            *traf_type = TRAF_HOME;
        }
    } else {
        *traf_type = TRAF_CLIENT;
    }

    // acquire session for this ip
    // create new session only for outgoing packets
    struct zsession *sess = session_acquire(client_ip, DIR_DOWN == flow_dir);

    if (NULL == sess) {
        if (TRAF_HOME == *traf_type) {
            return 0;
        } else {
            *traf_type = TRAF_NON_CLIENT;
            return process_non_client_traffic(len, iph, flow_dir);
        }
    }

    // update last activity time only for outgoing packets
    if ((DIR_UP == flow_dir) && (TRAF_CLIENT == *traf_type)) {
        atomic_store_explicit(&sess->last_activity, ztime(false), memory_order_relaxed);
    }

    // prevent changing client in session
    pthread_rwlock_rdlock(&sess->lock_client);

    int pass = 0;

    if (TRAF_CLIENT == *traf_type && !hybrid_traffic) {
        // check ports on outgoing packets
        if (DIR_UP == flow_dir) {
            pass = process_ports(sess, iph);
        }

        // check and update bandwidth
        if (0 == pass) {
            pass = process_bw(sess, len, flow_dir);
            if (0 == pass) {
                pass = process_p2p(sess, len, iph, flow_dir);
                if (0 != pass) {
                    rollback_bw(sess, len, flow_dir);
                }
            }
        }
    }

    // preform packet forwarding
    // forward only client or incoming home traffic
    if ((0 == pass) && ((TRAF_CLIENT == *traf_type) || (DIR_DOWN == flow_dir))) {
        pass = process_forwarding(sess, iph, flow_dir);
    }

    if (TRAF_CLIENT == *traf_type && !hybrid_traffic) {
        if (0 == pass) {
            spdm_update(&sess->client->speed[flow_dir], len);
        }
    }

    pthread_rwlock_unlock(&sess->lock_client);
    session_release(sess);

#ifndef NDEBUG
    {
        if (IPPROTO_TCP == iph->ip_p) {
            struct tcphdr *tcph = (struct tcphdr *) ((uint32_t *) iph + iph->ip_hl);
            uint16_t port = (flow_dir == DIR_UP) ? ntohs(tcph->th_dport) : ntohs(tcph->th_sport);
            zinst()->dbg.traff_counter[PROTO_TCP][port].packets++;
            zinst()->dbg.traff_counter[PROTO_TCP][port].bytes += len;
        } else if (IPPROTO_UDP == iph->ip_p) {
            struct udphdr *udph = (struct udphdr *) ((uint32_t *) iph + iph->ip_hl);
            uint16_t port = (flow_dir == DIR_UP) ? ntohs(udph->uh_dport) : ntohs(udph->uh_sport);
            zinst()->dbg.traff_counter[PROTO_UDP][port].packets++;
            zinst()->dbg.traff_counter[PROTO_UDP][port].bytes += len;
        }
    }
#endif

    // pass/drop packet
    return pass;
}
