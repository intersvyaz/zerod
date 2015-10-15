#ifndef ZEROD_ROUTER_H
#define ZEROD_ROUTER_H

#include <stdint.h>
#include <stddef.h>
#include "netproto.h"

struct ip;
struct tcphdr;
struct udphdr;

#define L4_PORT_MAX 65536

enum flow_dir
{
    DIR_UP = 0,
    DIR_DOWN = 1,
    DIR_MAX = 2
};

enum ipproto
{
    PROTO_TCP = 0,
    PROTO_UDP,
    PROTO_MAX
};

struct l4_data
{
    union {
        struct tcphdr *tcph;
        struct udphdr *udph;
    };
    // protocol
    enum ipproto proto;
    // source port (network order)
    uint16_t *src_port;
    // destination port (network order)
    uint16_t *dst_port;
    // internet checksum
    uint16_t *csum;
    // data pointer
    unsigned char *data;
    // data length
    size_t data_len;
};

/**
 * NAT
 */

struct znat;

struct znat_origin
{
    // source port (network order)
    uint16_t src_port;
    // destination port (network order)
    uint16_t dst_port;
    // destination address (network order)
    uint32_t addr;
};

struct znat_rule
{
    // source data
    struct znat_origin origin;
    // port assigned by nat (network order)
    uint16_t nat_port;
};

struct znat *znat_create(void);

void znat_destroy(struct znat *nat);

uint16_t znat_translate(struct znat *nat, enum ipproto proto, const struct znat_origin *origin);

int znat_lookup(struct znat *nat, enum ipproto proto, uint16_t nat_port, struct znat_origin *origin);

void znat_cleanup(struct znat *nat);

/**
 * Forwarder
 */

struct zforwarder;

struct zfwd_rule
{
    // original port (network order)
    uint16_t port;
    // forward address (network order)
    uint32_t fwd_ip;
    // forward port, optional (network order)
    uint16_t fwd_port;
};

struct zforwarder *zfwd_create(void);

void zfwd_destroy(struct zforwarder *fwd);

void zfwd_del_rule(struct zforwarder *fwd, enum ipproto proto, uint16_t port);

void zfwd_add_rule(struct zforwarder *fwd, enum ipproto proto, uint16_t port, uint32_t fwd_ip, uint16_t fwd_port);

int zfwd_find_rule(struct zforwarder *fwd, enum ipproto proto, uint16_t port, struct zfwd_rule *rule);

void zfwd_forward_ipv4(struct znat *nat, struct ip *iph, struct l4_data *l4, uint32_t fwd_ip, uint16_t fwd_port);

int zfwd_unforward_ipv4(struct znat *nat, struct ip *iph, struct l4_data *l4);

void zfwd_dump_rules(struct zforwarder *fwd, enum ipproto proto, struct zfwd_rule **rules, size_t *count);

/**
 * Firewall
 */
enum port_rule
{
    PORT_ALLOW = 0,
    PORT_DENY,
    PORT_MAX
};

struct zfirewall;

struct zfirewall *zfwall_create(void);

void zfwall_destroy(struct zfirewall *fire);

void zfwall_add_rule(struct zfirewall *fire, enum ipproto proto, enum port_rule rule, uint16_t port);

void zfwall_del_rule(struct zfirewall *fire, enum ipproto proto, enum port_rule rule, uint16_t port);

int zfwall_is_allowed(struct zfirewall *fire, enum ipproto proto, uint16_t port);

void zfwall_dump_ports(struct zfirewall *fire, enum ipproto proto, enum port_rule rule, uint16_t **ports,
                       size_t *count);

/**
 * DHCP
 */

struct zdhcp;

struct zdhcp_lease {
    uint32_t ip; // ip address (network order)
    uint8_t mac[HWADDR_MAC48_LEN];
    uint64_t lease_end; // microseconds
};

struct zdhcp *zdhcp_new(void);

void zdhcp_free(struct zdhcp *dhcp);

void zdhcp_lease_bind(struct zdhcp *dhcp, const struct zdhcp_lease *lease);

int zdhcp_lease_find(struct zdhcp *dhcp, struct zdhcp_lease *);

#endif // ZEROD_ROUTER_H
