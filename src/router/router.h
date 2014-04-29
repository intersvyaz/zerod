#ifndef ROUTER_H
#define ROUTER_H

#include <stdint.h>
#include <stdlib.h>

enum ipproto {
    PROTO_TCP = 0,
    PROTO_UDP,
    PROTO_MAX
};

struct ip;

/*
 * NAT
 */

struct znat;

struct znat_origin {
    // source port (network order)
    uint16_t src_port;
    // destination port (nerwork order)
    uint16_t dst_port;
    // destination address (network order)
    uint32_t addr;
};

struct znat_rule {
    // source data
    struct znat_origin origin;
    // port assigned by nat (network order)
    uint16_t nat_port;
};

struct znat *znat_create();
void znat_destroy(struct znat *nat);
uint16_t znat_translate(struct znat *nat, enum ipproto proto, const struct znat_origin *origin);
int znat_lookup(struct znat *nat, enum ipproto proto, uint16_t nat_port, struct znat_origin *origin);
void znat_cleanup(struct znat *nat);

/*
 * Forwarder
 */

struct zforwarder;

struct zfwd_rule {
    // original port (network order)
    uint16_t port;
    // forward address (network order)
    uint32_t fwd_ip;
    // forward port, optional (network order)
    uint16_t fwd_port;
};

struct zforwarder * zfwd_create();
void zfwd_destroy(struct zforwarder *fwd);
void zfwd_del_rule(struct zforwarder *fwd, enum ipproto proto, uint16_t port);
void zfwd_add_rule(struct zforwarder *fwd, enum ipproto proto, uint16_t port, uint32_t fwd_ip, uint16_t fwd_port);
int zfwd_find_rule(struct zforwarder *fwd, enum ipproto proto, uint16_t port, struct zfwd_rule *rule);
void zfwd_forward(struct znat *nat, struct ip *iph, enum ipproto proto, void *l4hdr, uint32_t fwd_ip, uint32_t fwd_port);
void zfwd_unforward(struct znat *nat, struct ip *iph, enum ipproto proto, void *l4hdr);
void zfwd_dump_rules(struct zforwarder *fwd, enum ipproto proto, struct zfwd_rule **rules, size_t *count);

/*
 * Firewall
 */

enum port_rule {
    PORT_ALLOW = 0,
    PORT_DENY,
    PORT_MAX
};

struct zfirewall;

struct zfirewall *zfwall_create();
void zfwall_destroy(struct zfirewall *fire);
void zfwall_add_rule(struct zfirewall *fire, enum ipproto proto, enum port_rule rule, uint16_t port);
void zfwall_del_rule(struct zfirewall *fire, enum ipproto proto, enum port_rule rule, uint16_t port);
int zfwall_allowed(struct zfirewall *fire, enum ipproto proto, uint16_t port);
void zfwall_dump_ports(struct zfirewall *fire, enum ipproto proto, enum port_rule rule, uint16_t **ports, size_t *count);

#endif // ROUTER_H
