#include <pthread.h>
#include <netinet/ip.h>
#include <uthash/uthash.h>
#include "forwarder.h"
#include "util.h"

typedef struct zfwd_entry_struct
{
    zfwd_rule_t rule;
    // hash handle (lookup by port)
    UT_hash_handle hh;
} zfwd_entry_t;

struct zforwarder_struct
{
    // hash of rules for each proto
    zfwd_entry_t *rules[PROTO_MAX];
    pthread_spinlock_t lock;
};

/**
 * Create forwarder instance.
 * @return New instance.
 */
zforwarder_t *zfwd_new(void)
{
    zforwarder_t *fwd = malloc(sizeof(*fwd));

    if (unlikely(NULL == fwd)) {
        return NULL;
    }

    memset(fwd, 0, sizeof(*fwd));
    if (unlikely(0 != pthread_spin_init(&fwd->lock, PTHREAD_PROCESS_PRIVATE))) {
        goto err;
    }

    return fwd;

    err:
        free(fwd);
    return NULL;
}

/**
 * Destroy forwarder instance.
 * @param[in] fwd Forwarder handle.
 */
void zfwd_free(zforwarder_t *fwd)
{
    pthread_spin_destroy(&fwd->lock);

    for (int i = 0; i < PROTO_MAX; i++) {
        if (fwd->rules[i]) {
            zfwd_entry_t *entry, *tmp;

            HASH_ITER(hh, fwd->rules[i], entry, tmp) {
                HASH_DELETE(hh, fwd->rules[i], entry);
                free(entry);
            }
        }
    }

    free(fwd);
}

/**
 * Add new or rewrite existing forwarding rule.
 * @param[in] fwd Forwarder handle.
 * @param[in] proto Protocol.
 * @param[in] port (network order).
 * @param[in] fwd_ip (network order).
 * @param[in] fwd_port (network order).
 */
void zfwd_add_rule(zforwarder_t *fwd, zip_proto_t proto, uint16_t port, uint32_t fwd_ip, uint16_t fwd_port)
{
    pthread_spin_lock(&fwd->lock);

    zfwd_entry_t *entry = NULL;
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
void zfwd_del_rule(zforwarder_t *fwd, zip_proto_t proto, uint16_t port)
{
    pthread_spin_lock(&fwd->lock);

    zfwd_entry_t *entry = NULL;
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
 * @param[in,out] rule Buffer for search result.
 * @return True on success.
 */
bool zfwd_find_rule(zforwarder_t *fwd, zip_proto_t proto, uint16_t port, zfwd_rule_t *rule)
{
    zfwd_entry_t *entry = NULL;
    bool ok = false;

    pthread_spin_lock(&fwd->lock);

    HASH_FIND(hh, fwd->rules[proto], &port, sizeof(port), entry);
    if (NULL != entry) {
        *rule = entry->rule;
        ok = true;
    }

    pthread_spin_unlock(&fwd->lock);

    return ok;
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
void zfwd_forward_ipv4(znat_t *nat, struct ip *iph, zl4_data_t *l4, uint32_t fwd_ip, uint16_t fwd_port)
{
    znat_origin_t origin;
    uint16_t *ip_csum = &iph->ip_sum;

    // assemble origin
    origin.dst_port = fwd_port ? *l4->dst_port : (uint16_t) 0u;
    origin.src_port = *l4->src_port;
    origin.addr = iph->ip_dst.s_addr;

    *l4->src_port = znat_translate(nat, l4->proto, &origin);

    // update csums and fields
    if (fwd_port) {
        *l4->dst_port = fwd_port;
        *l4->csum = in_csum_update(*l4->csum, 1, &origin.dst_port, l4->dst_port);
    }
    iph->ip_dst.s_addr = fwd_ip;
    *ip_csum = in_csum_update(*ip_csum, 2, (uint16_t *) &origin.addr, (uint16_t *) &iph->ip_dst.s_addr);
    *l4->csum = in_csum_update(*l4->csum, 2, (uint16_t *) &origin.addr, (uint16_t *) &iph->ip_dst.s_addr);
    *l4->csum = in_csum_update(*l4->csum, 1, &origin.src_port, l4->src_port);
}

/**
 * Unforward packet.
 * @param[in] nat Nat handle.
 * @param[in] iph ip header.
 * @param[in] proto Protocol.
 * @param[in] l4hdr level 4 header.
 * @return True if unforwared.
 */
bool zfwd_unforward_ipv4(znat_t *nat, struct ip *iph, zl4_data_t *l4)
{
    znat_origin_t origin;
    uint16_t *ip_csum = &iph->ip_sum;

    if (znat_lookup(nat, l4->proto, *l4->dst_port, &origin)) {
        *ip_csum = in_csum_update(*ip_csum, 2, (uint16_t *) &iph->ip_src.s_addr, (uint16_t *) &origin.addr);
        if (origin.dst_port) {
            *l4->csum = in_csum_update(*l4->csum, 1, l4->src_port, &origin.dst_port);
        }
        *l4->csum = in_csum_update(*l4->csum, 2, (uint16_t *) &iph->ip_src.s_addr, (uint16_t *) &origin.addr);
        *l4->csum = in_csum_update(*l4->csum, 1, l4->dst_port, &origin.src_port);
        *l4->dst_port = origin.src_port;
        if (origin.dst_port) {
            *l4->src_port = origin.dst_port;
        }
        iph->ip_src.s_addr = origin.addr;

        return true;
    }

    return false;
}

/**
 * Dump forwarding rules for specified protocol.
 * @param[in] fwd
 * @param[in] proto
 * @param[in,out] rules
 * @param[in,out] count
 */
void zfwd_dump_rules(zforwarder_t *fwd, zip_proto_t proto, zfwd_rule_t **rules, size_t *count)
{
    pthread_spin_lock(&fwd->lock);

    if (fwd->rules[proto]) {
        *count = HASH_CNT(hh, fwd->rules[proto]);
        *rules = malloc((*count) * sizeof(**rules));

        size_t i = 0;
        zfwd_entry_t *entry, *tmp;
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
