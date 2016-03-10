#ifndef ZEROD_FIREWALL_H
#define ZEROD_FIREWALL_H

#include <stdint.h>
#include <stdbool.h>
#include "netdef.h"

typedef struct zfirewall_struct zfirewall_t;

/**
 * @brief Firewall access policy.
 */
typedef enum zfwall_policy_enum
{
    ACCESS_ALLOW = 0,
    ACCESS_DENY,
    ACCESS_MAX
} zfwall_policy_t;

zfirewall_t *zfwall_new(void);

void zfwall_free(zfirewall_t *fwall);

void zfwall_add_rule(zfirewall_t *fwall, zip_proto_t proto, zfwall_policy_t policy, uint16_t port);

void zfwall_del_rule(zfirewall_t *fwall, zip_proto_t proto, zfwall_policy_t policy, uint16_t port);

bool zfwall_is_allowed(zfirewall_t *fwall, zip_proto_t proto, uint16_t port);

void zfwall_dump_ports(zfirewall_t *fwall, zip_proto_t proto, zfwall_policy_t policy, uint16_t **ports, size_t *count);

#endif // ZEROD_FIREWALL_H
