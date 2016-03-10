#ifndef ZEROD_NAT_H
#define ZEROD_NAT_H

#include <stdint.h>
#include <stdbool.h>
#include "netdef.h"

typedef struct znat_struct znat_t;
typedef struct znat_origin_struct znat_origin_t;
typedef struct znat_rule_struct znat_rule_t;

/**
 * TODO: rename
 */
struct znat_origin_struct
{
    /*<<! source port (network order) */
    uint16_t src_port;
    /*<<! destination port (network order) */
    uint16_t dst_port;
    /*<<! destination address (network order) */
    uint32_t addr;
};

/**
 * TODO: rename
 */
struct znat_rule_struct
{
    /*<<! source data */
    znat_origin_t origin;
    /*<<!  port assigned by NAT (network order) */
    uint16_t nat_port;
};

znat_t *znat_new(uint64_t entry_ttl);

void znat_free(znat_t *nat);

uint16_t znat_translate(znat_t *nat, zip_proto_t proto, const znat_origin_t *origin);

bool znat_lookup(znat_t *nat, zip_proto_t proto, uint16_t nat_port, znat_origin_t *origin);

void znat_cleanup(znat_t *nat);

#endif // ZEROD_NAT_H
