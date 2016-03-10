#ifndef ZEROD_FORWARDER_H
#define ZEROD_FORWARDER_H

#include <stdint.h>
#include <stdbool.h>
#include "nat.h"

typedef struct zforwarder_struct zforwarder_t;
typedef struct zfwd_rule_struct zfwd_rule_t;

/**
 * @brief Forwarding rule.
 */
struct zfwd_rule_struct
{
    /*<<! original port (network order) */
    uint16_t port;
    /*<<! forward address (network order) */
    uint32_t fwd_ip;
    /*<<! forward port, optional (network order) */
    uint16_t fwd_port;
};

zforwarder_t *zfwd_new(void);

void zfwd_free(zforwarder_t *fwd);

void zfwd_del_rule(zforwarder_t *fwd, zip_proto_t proto, uint16_t port);

void zfwd_add_rule(zforwarder_t *fwd, zip_proto_t proto, uint16_t port, uint32_t fwd_ip, uint16_t fwd_port);

bool zfwd_find_rule(zforwarder_t *fwd, zip_proto_t proto, uint16_t port, zfwd_rule_t *rule);

void zfwd_forward_ipv4(znat_t *nat, struct ip *iph, zl4_data_t *l4, uint32_t fwd_ip, uint16_t fwd_port);

bool zfwd_unforward_ipv4(znat_t *nat, struct ip *iph, zl4_data_t *l4);

void zfwd_dump_rules(zforwarder_t *fwd, zip_proto_t proto, zfwd_rule_t **rules, size_t *count);

#endif // ZEROD_FORWARDER_H
