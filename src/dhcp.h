#ifndef ZEROD_DHCP_H
#define ZEROD_DHCP_H

#include <stdbool.h>
#include <stdint.h>
#include "netproto.h"
#include "util_time.h"

typedef struct zdhcp_struct zdhcp_t;
typedef struct zdhcp_lease_struct zdhcp_lease_t;

/**
 * @brief DHCP lease record.
 */
struct zdhcp_lease_struct
{
    /*<<! ip address (host order) */
    uint32_t ip;
    /*<<! MAC address */
    uint8_t mac[HWADDR_MAC48_LEN];
    /*<<! lease end timestamp */
    ztime_t lease_end;
};

zdhcp_t *zdhcp_new(void);

void zdhcp_free(zdhcp_t *dhcp);

bool zdhcp_lease_bind(zdhcp_t *dhcp, const zdhcp_lease_t *lease);

bool zdhcp_lease_find(zdhcp_t *dhcp, zdhcp_lease_t *lease);

void zdhcp_cleanup(zdhcp_t *dhcp);

#endif // ZEROD_DHCP_H
