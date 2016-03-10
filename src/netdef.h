#ifndef ZEROD_NETDEF_H
#define ZEROD_NETDEF_H

#include <stddef.h>
#include <stdbool.h>
#include "netproto.h"
#include "util_time.h"

struct ip;
struct tcphdr;
struct udphdr;

#define ZL4_PORT_MAX 65536u /*<<! Transport layer max port value. */

/**
 * @brief Flow directions.
 */
typedef enum zflow_dir_enum
{
    DIR_UP = 0,
    DIR_DOWN = 1,
    DIR_MAX = 2
} zflow_dir_t;

/**
 * @brief IP protocols.
 */
typedef enum zip_proto_enum
{
    PROTO_TCP = 0,
    PROTO_UDP,
    PROTO_MAX
} zip_proto_t;

/**
 * @brief Aggregated transport packet information.
 */
typedef struct zl4_data_struct
{
    union
    {
        /*<<! TCP header pointer */
        struct tcphdr *tcph;
        /*<<! UDP header pointer */
        struct udphdr *udph;
    };
    /*<<! IP protocol */
    zip_proto_t proto;
    /*<<! source port (network order) */
    uint16_t *src_port;
    /*<<! destination port (network order) */
    uint16_t *dst_port;
    /*<<! checksum pointer */
    uint16_t *csum;
    /*<<! data pointer, can be NULL if were no payload in packet */
    unsigned char *data;
    /*<<! data length */
    size_t data_len;
} zl4_data_t;

#endif // ZEROD_NETDEF_H
