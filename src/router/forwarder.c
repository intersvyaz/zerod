#include "router.h"
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <uthash/uthash.h>
#include "../netproto.h"

struct zforwarder {
    // hash of rules for each proto
    struct zfwd_entry *rules[PROTO_MAX];
    pthread_spinlock_t lock;
};

struct zfwd_entry {
    struct zfwd_rule rule;
    // hash handle (lookup by port)
    UT_hash_handle hh;
};

/**
 * Create forwarder instance.
 * @return New instance.
 */
struct zforwarder * zfwd_create()
{
    struct zforwarder *fwd = malloc(sizeof(*fwd));
    bzero(fwd, sizeof(*fwd));
    pthread_spin_init(&fwd->lock, PTHREAD_PROCESS_PRIVATE);

    return fwd;
}

/**
 * Destroy forwarder instance.
 * @param[in] fwd Forwarder handle.
 */
void zfwd_destroy(struct zforwarder *fwd)
{
    pthread_spin_destroy(&fwd->lock);

    for(int i = 0; i < PROTO_MAX; i++) {
        if (fwd->rules[i]) {
            struct zfwd_entry *entry, *tmp;

            HASH_ITER(hh, fwd->rules[i], entry, tmp) {
                HASH_DELETE(hh, fwd->rules[i], entry);
                free(entry);
            }
        }
    }

    free(fwd);
}

/**
 * Add new or rewrite existing forwaring rule.
 * @param[in] fwd Forwarder handle.
 * @param[in] proto Protocol.
 * @param[in] port (network order).
 * @param[in] fwd_ip (network order).
 * @param[in] fwd_port (network order).
 */
void zfwd_add_rule(struct zforwarder *fwd, enum ipproto proto, uint16_t port, uint32_t fwd_ip, uint16_t fwd_port)
{
    pthread_spin_lock(&fwd->lock);

    struct zfwd_entry *entry = NULL;
    HASH_FIND(hh, fwd->rules[proto], &port, sizeof(port), entry);
    if (NULL == entry) {
        entry = malloc(sizeof(*entry));
        entry->rule.port = port;
        HASH_ADD(hh, fwd->rules[proto], rule.port, sizeof(entry->rule.port), entry);
    }

    entry->rule.fwd_ip = fwd_ip;
    entry->rule.fwd_port = fwd_port;

    pthread_spin_unlock(&fwd->lock);
}

/**
 * Delete forwarding rule.
 * @param[in] fwd Forwarder handle.
 * @param[in] proto Protocol.
 * @param[in] port (network order).
 */
void zfwd_del_rule(struct zforwarder *fwd, enum ipproto proto, uint16_t port)
{
    pthread_spin_lock(&fwd->lock);

    struct zfwd_entry *entry = NULL;
    HASH_FIND(hh, fwd->rules[proto], &port, sizeof(port), entry);
    if (NULL != entry) {
        HASH_DELETE(hh, fwd->rules[proto], entry);
        free(entry);
    }

    pthread_spin_unlock(&fwd->lock);
}

/**
 * Search and return forwarding rule for specified protocol and port.
 * @param[in] fwd Forwarder handle.
 * @param[in] proto Protocol.
 * @param[in] port (network order)
 * @param[in,out] rule Buiffer for search result.
 * @return Zero on success.
 */
int zfwd_find_rule(struct zforwarder *fwd, enum ipproto proto, uint16_t port, struct zfwd_rule *rule)
{
    int ret = -1;

    pthread_spin_lock(&fwd->lock);

    struct zfwd_entry *entry = NULL;
    HASH_FIND(hh, fwd->rules[proto], &port, sizeof(port), entry);
    if (NULL != entry) {
        *rule = entry->rule;
        ret = 0;
    }

    pthread_spin_unlock(&fwd->lock);

    return ret;
}

/**
 * Forward packet.
 * @param[in] nat Nat handle.
 * @param[in] iph ip header.
 * @param[in] proto Protocol.
 * @param[in] l4hdr level 4 header.
 * @param[in] fwd_ip
 * @param[in] fwd_port
 */
void zfwd_forward(struct znat *nat, struct ip *iph, enum ipproto proto, void *l4hdr, uint32_t fwd_ip, uint32_t fwd_port)
{
    uint16_t *dst_port, *src_port, *csum, *ip_csum;

    if (PROTO_TCP == proto) {
        struct tcphdr *tcph = (struct tcphdr *)l4hdr;
        dst_port = &tcph->dest;
        src_port = &tcph->source;
        csum = &tcph->check;
    } else if (PROTO_UDP == proto) {
        struct udphdr *udph = (struct udphdr *)l4hdr;
        proto = PROTO_UDP;
        dst_port = &udph->dest;
        src_port = &udph->source;
        csum = &udph->check;
    } else {
        return;
    }

    ip_csum = &iph->ip_sum;

    struct znat_origin origin;

    // assemble origin
    origin.dst_port = fwd_port ? *dst_port : 0;
    origin.src_port = *src_port;
    origin.addr = iph->ip_dst.s_addr;

    *src_port = znat_translate(nat, proto, &origin);

    // update csums and fields
    if (fwd_port) {
        *dst_port = fwd_port;
        *csum = in_csum_update(*csum, 1, (uint16_t *)&origin.dst_port, (uint16_t *)dst_port);
    }
    iph->ip_dst.s_addr = fwd_ip;
    *ip_csum = in_csum_update(*ip_csum, 2, (uint16_t *)&origin.addr, (uint16_t *)&iph->ip_dst.s_addr);
    *csum = in_csum_update(*csum, 2, (uint16_t *)&origin.addr, (uint16_t *)&iph->ip_dst.s_addr);
    *csum = in_csum_update(*csum, 1, (uint16_t *)&origin.src_port, (uint16_t *)src_port);
}

/**
 * Unforward packet.
 * @param[in] nat Nat handle.
 * @param[in] iph ip header.
 * @param[in] proto Protocol.
 * @param[in] l4hdr level 4 header.
 */
void zfwd_unforward(struct znat *nat, struct ip *iph, enum ipproto proto, void *l4hdr)
{
    uint16_t *dst_port, *src_port, *csum, *ip_csum;

    if (PROTO_TCP == proto) {
        struct tcphdr *tcph = (struct tcphdr *)l4hdr;
        dst_port = &tcph->dest;
        src_port = &tcph->source;
        csum = &tcph->check;
    } else if (PROTO_UDP == proto) {
        struct udphdr *udph = (struct udphdr *)l4hdr;
        dst_port = &udph->dest;
        src_port = &udph->source;
        csum = &udph->check;
    } else {
        return;
    }

    ip_csum = &iph->ip_sum;

    struct znat_origin origin;
    if (0 == znat_lookup(nat, proto, *dst_port, &origin)) {
        *ip_csum = in_csum_update(*ip_csum, 2, (uint16_t *)&iph->ip_src.s_addr, (uint16_t *)&origin.addr);
        if (origin.dst_port) {
            *csum = in_csum_update(*csum, 1, (uint16_t *)src_port, (uint16_t *)&origin.dst_port);
        }
        *csum = in_csum_update(*csum, 2, (uint16_t *)&iph->ip_src.s_addr, (uint16_t *)&origin.addr);
        *csum = in_csum_update(*csum, 1, (uint16_t *)dst_port, (uint16_t *)&origin.src_port);
        *dst_port = origin.src_port;
        if (origin.dst_port) {
            *src_port = origin.dst_port;
        }
        iph->ip_src.s_addr = origin.addr;
    }
}

/**
 * Dump forwaring rules for specified protocol.
 * @param[in] fwd
 * @param[in] proto
 * @param[in,out] rules
 * @param[in,out] count
 */
void zfwd_dump_rules(struct zforwarder *fwd, enum ipproto proto, struct zfwd_rule **rules, size_t *count)
{
    pthread_spin_lock(&fwd->lock);

    if (fwd->rules[proto]) {
        *count = HASH_CNT(hh, fwd->rules[proto]);
        *rules = malloc((*count) * sizeof(**rules));

        size_t i = 0;
        struct zfwd_entry *entry, *tmp;
        HASH_ITER(hh, fwd->rules[proto], entry, tmp) {
            (*rules)[i] = entry->rule;
            i++;
        }
    } else {
        *rules = NULL;
        *count = 0;
    }

    pthread_spin_unlock(&fwd->lock);
}
