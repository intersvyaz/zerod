#ifndef ZEROD_ZRCP_H
#define ZEROD_ZRCP_H

#include <stdint.h>
#include <arpa/inet.h>

#define ZRCP_VERSION   7

enum zrc_opcode
{
    ZOP_INVALID_VERSION = 0xBF,
    ZOP_OK = 0xC0,
    ZOP_NOT_FOUND = 0xC1,
    ZOP_STATS_SHOW = 0xC2,
    ZOP_STATS_SHOW_RESP = 0xC3,
    ZOP_CLIENT_SHOW = 0xC4,
    ZOP_CLIENT_SHOW_RESP = 0xC5,
    ZOP_CLIENT_UPDATE = 0xC6,
    ZOP_SESSION_SHOW = 0xC7,
    ZOP_SESSION_SHOW_RESP = 0xC8,
    ZOP_SESSION_DELETE = 0xC9,
    ZOP_BAD_RULE = 0xCA,
    ZOP_UPSTREAM_SHOW = 0xCD,
    ZOP_UPSTREAM_SHOW_RESP = 0xCE,
    ZOP_RECONFIGURE = 0xCE,
    ZOP_MONITOR = 0xCF,
    ZOP_BAD_FILTER = 0xD0,
#ifndef NDEBUG
    ZOP_DUMP_COUNTERS = 0x20,
#endif
};

struct zrc_header
{
    uint16_t magic;
    uint8_t version;
    uint8_t type;
    uint32_t length;
    uint32_t cookie;
} __attribute__((__packed__));

struct zrc_ring_info
{
    char ifname_lan[16];
    char ifname_wan[16];
    uint16_t ring_id;
    struct
    {
        struct
        {
            struct
            {
                struct
                {
                    uint64_t count;
                    uint64_t speed;
                };
            } all, passed, client;
        } down, up;
    } packets, traffic;
} __attribute__((__packed__));

struct zrc_op_stats_show_resp
{
    struct zrc_header header;
    uint32_t clients_count;
    uint32_t sess_count;
    uint32_t unauth_sess_count;
    uint64_t non_client_speed_down;
    uint64_t non_client_speed_up;
    uint64_t non_client_bw_down;
    uint64_t non_client_bw_up;
    uint16_t rings_count;
    struct zrc_ring_info rings[0];
} __attribute__((__packed__));

struct zrc_op_client_show
{
    struct zrc_header header;
    uint8_t ip_flag;
    union
    {
        uint32_t user_id;
        uint32_t ip;
    };
} __attribute__((__packed__));

struct zrc_op_client_show_resp
{
    struct zrc_header header;
    char data[]; // null terminated strings
} __attribute__((__packed__));

struct zrc_op_client_update
{
    struct zrc_header header;
    uint8_t ip_flag;
    union
    {
        uint32_t user_id;
        uint32_t ip;
    };
    char data[]; // null terminated strings
} __attribute__((__packed__));

struct zrc_op_session_show
{
    struct zrc_header header;
    uint32_t session_ip;
} __attribute__((__packed__));

struct zrc_op_session_show_resp
{
    struct zrc_header header;
    uint32_t user_id;
    uint64_t traff_down;
    uint64_t traff_up;
    uint32_t last_seen;
    uint32_t last_acct;
    uint32_t last_auth;
} __attribute__((__packed__));

struct zrc_op_session_delete
{
    struct zrc_header header;
    uint32_t session_ip;
} __attribute__((__packed__));

struct zrc_upstream_info
{
    uint64_t speed_down;
    uint64_t speed_up;
    uint64_t p2p_bw_limit_down;
    uint64_t p2p_bw_limit_up;
} __attribute__((__packed__));

struct zrc_op_upstream_show_resp
{
    struct zrc_header header;
    uint16_t count;
    struct zrc_upstream_info upstream[0];
} __attribute__((__packed__));

struct zrc_op_reconfigure
{
    struct zrc_header header;
    char data[]; // null terminated strings
} __attribute__((__packed__));

struct zrc_op_monitor
{
    struct zrc_header header;
    char filter[]; // null terminated string
} __attribute__((__packed__));

/**
* Fill packet header with default values.
* @param[in] header
*/
static inline void zrc_fill_header(struct zrc_header *header)
{
    header->magic = htons(RC_ZRCP_MAGIC);
    header->version = ZRCP_VERSION;
}

#endif // ZEROD_ZRCP_H
