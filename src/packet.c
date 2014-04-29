#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

#include "client.h"
#include "session.h"
#include "util.h"
#include "log.h"
#include "zero.h"
#include "netproto.h"
#include "router/router.h"

/**
 * Check port rules.
 * @param[in] sess Session.
 * @param[in] iph IP header.
 * @return Zero on pass.
 */
static int process_ports(struct zsession *sess, struct ip *iph)
{
    uint16_t port = 0;
    enum ipproto proto;

    if (IPPROTO_TCP == iph->ip_p) {
        struct tcphdr *tcph = (struct tcphdr *)((uint32_t *)iph + iph->ip_hl);
        port = tcph->dest;
        proto = PROTO_TCP;
    } else if (IPPROTO_UDP == iph->ip_p) {
        struct udphdr *udph = (struct udphdr *)((uint32_t *)iph + iph->ip_hl);
        port = udph->dest;
        proto = PROTO_UDP;
    } else {
        port = 0;
    }

    if (0 == port) {
        return 0;
    }

    struct zfirewall *fire = client_get_firewall(sess->client, false);
    if (NULL == fire) {
        return 0;
    }

    if (0 == zfwall_allowed(fire, proto, port)) {
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
         uint32_t *packets_ptr;
         uint64_t *sess_traff_ptr;

        if (DIR_UP == flow_dir) {
            packets_ptr = &sess->packets_up;
            sess_traff_ptr = &sess->traff_up;
        } else {
            packets_ptr = &sess->packets_down;
            sess_traff_ptr = &sess->traff_down;
        }

        (void)__atomic_add_fetch(packets_ptr, 1, __ATOMIC_RELAXED);
        (void)__atomic_add_fetch(sess_traff_ptr, packet_len, __ATOMIC_RELAXED);
    }

    return pass;
}

/**
 * Apply forwading rules.
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
        struct tcphdr *tcph = (struct tcphdr *)((uint32_t *)iph + iph->ip_hl);
        l4hdr = tcph;
        dst_port = &tcph->dest;
        proto = PROTO_TCP;
    } else if (IPPROTO_UDP == iph->ip_p) {
        struct udphdr *udph = (struct udphdr *)((uint32_t *)iph + iph->ip_hl);
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
     uint32_t *packets_ptr;
     uint64_t *sess_traff_ptr;

    if (DIR_UP == flow_dir) {
        packets_ptr = &sess->packets_up;
        sess_traff_ptr = &sess->traff_up;
    } else {
        packets_ptr = &sess->packets_down;
        sess_traff_ptr = &sess->traff_down;
    }

    (void)__atomic_sub_fetch(packets_ptr, 1, __ATOMIC_RELAXED);
    (void)__atomic_sub_fetch(sess_traff_ptr, packet_len, __ATOMIC_RELAXED);
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
    uint16_t port;

    if (IPPROTO_TCP == iph->ip_p) {
        struct tcphdr *tcph = (struct tcphdr *)((uint32_t *)iph + iph->ip_hl);
        port = ntohs((DIR_UP == flow_dir) ? tcph->dest : tcph->source);
    } else if (IPPROTO_UDP == iph->ip_p) {
        struct udphdr *udph = (struct udphdr *)((uint32_t *)iph + iph->ip_hl);
        port = ntohs((DIR_UP == flow_dir) ? udph->dest : udph->source);
    } else {
        port = 0;
    }

    // p2p policer enabled and port greater than 1024 and not whitelisted
    if (sess->client->p2p_policer
        && (port >= 1024)
        && !utarray_find(&zcfg()->p2p_ports_whitelist, &port, uint16_cmp)
    ) {
        uint64_t speed = spdm_calc(&sess->client->speed[flow_dir]);
        // 1/4 of bw limit
        uint64_t throttle_speed = __atomic_load_n(&sess->client->bw_bucket[flow_dir].max_tokens, __ATOMIC_RELAXED) / 4;

        if ((speed > throttle_speed) || (ztime(false) - __atomic_load_n(&sess->client->last_p2p_throttle, __ATOMIC_ACQUIRE) < ZP2P_THROTTLE_TIME)) {
            // TODO: uncomment me when DSCP is ready!
            //unsigned upstream_id = IPTOS_DSCP(iph->ip_tos) >> 2;
            unsigned upstream_id = 0;
            struct token_bucket *bucket = &zinst()->upstreams[upstream_id].p2p_bw_bucket[flow_dir];
            if (0 != token_bucket_update(bucket, packet_len)) {
                return -1;
            }

            struct speed_meter *spd = &zinst()->upstreams[upstream_id].speed[flow_dir];
            spdm_update(spd, packet_len);

            // 120 secs
            if (ztime(false) - __atomic_load_n(&sess->client->last_p2p_throttle, __ATOMIC_ACQUIRE) > ZP2P_THROTTLE_TIME) {
                __atomic_store_n(&sess->client->last_p2p_throttle, ztime(false), __ATOMIC_RELEASE);
            }
        }
    }

    return 0;
}

/**
 * Process non-client traffic.
 * @param[in] len
 * @param[in] flow_dir
 * @return Zero on pass.
 */
int process_non_client_traffic(u_int len, enum flow_dir flow_dir)
{
    if (0 == token_bucket_update(&zinst()->non_client.bw_bucket[flow_dir], len)) {
        spdm_update(&zinst()->non_client.speed[flow_dir], len);
        // pass packet
        return 0;
    } else {
        // drop packet
        return -1;
    }
}

/**
 * Packet analyazer.
 * @param[in] packet Packet to analyze.
 * @param[in] len Packet length.
 * @param[in] flow_dir Packet flow direction.
 * @return Zero on pass.
 */
int process_packet(unsigned char *packet, u_int len, enum flow_dir flow_dir)
{
    struct ether_header *eth = (struct ether_header *)packet;
    struct ip *iph;

    if (htons(ETHERTYPE_IP) == eth->ether_type) {
        iph = (struct ip *)(eth + 1);
    } else if (htons(ETHERTYPE_VLAN) == eth->ether_type) {
        struct vlan_header *vlh = (struct vlan_header *)(eth + 1);
        if (htons(ETHERTYPE_IP) == vlh->type) {
            iph = (struct ip *)(vlh + 1);
        } else {
            return 0;
        }
    } else {
        // pass non ethernet-ip packet
        return 0;
    }

    uint32_t client_ip = ntohl(DIR_UP == flow_dir ? iph->ip_src.s_addr : iph->ip_dst.s_addr);

    // pass packets not in ip whitelist
    if (utarray_len(&zcfg()->ip_whitelist)) {
        struct ip_range ipr_dummy;
        ipr_dummy.ip_start = ipr_dummy.ip_end = client_ip;
        const struct ip_range *ipr_result = utarray_find(&zcfg()->ip_whitelist, &ipr_dummy, ip_range_cmp);
        if (!ipr_result) {
            return process_non_client_traffic(len, flow_dir);
        }
    }

    // acquire session for this ip
    // create new sesion only for outgoing packets
    struct zsession *sess = session_acquire(client_ip, DIR_DOWN == flow_dir);

    if (unlikely(NULL == sess)) {
        return process_non_client_traffic(len, flow_dir);
    }

    // update last activity time only for outgoing packets
    if (DIR_UP == flow_dir) {
        __atomic_store_n(&sess->last_activity, ztime(false), __ATOMIC_RELAXED);
    }

    // prevent changing client in session
    pthread_rwlock_rdlock(&sess->lock_client);

    int pass = 0;

    // check ports on outgoing packets
    if ((0 == pass) && (DIR_UP == flow_dir)) {
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

    // preform packet forwarding
    if (0 == pass) {
        pass = process_forwarding(sess, iph, flow_dir);
    }

    if (0 == pass) {
        spdm_update(&sess->client->speed[flow_dir], len);
    }

    pthread_rwlock_unlock(&sess->lock_client);
    session_release(sess);

    // pass/drop packet
    return pass;
}
