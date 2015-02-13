#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <inttypes.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>

#include <uthash/utstring.h>

#include "config.h"
#include "zrc_proto.h"
#include "util.h"

#define DEFAULT_SERVER "localhost:1050"
#define MINITOR_BUFFER_SIZE 32768

enum opt_keys {
    // actions
    OPT_NONE,
    OPT_SHOW_STATS,
    OPT_CLIENT_SHOW,
    OPT_CLIENT_UPDATE,
    OPT_RULES,
    OPT_SESSION_SHOW,
    OPT_SESSION_DELETE,
    OPT_UPSTREAM_SHOW,
    OPT_RECONFIGURE,
    OPT_MONITOR,
#ifdef DEBUG
    OPT_DUMP_COUNTERS,
#endif
};

// current action
static int g_action = 0;

// client rules
static const char *g_rules[128];

// client rules count
static size_t g_rules_cnt = 0;

// target server (host:port)
static const char *g_server = NULL;

// session ip address
static uint32_t g_sess_ip = 0;

// user id
static uint32_t g_user_id = 0;

// supplied ip instead of client id
static unsigned g_ip_flag = 0;

// human readable flag
static unsigned g_human_readable = 0;

// verbosity level
static unsigned g_verbosity = 0;

// monitor filter (empty string is default filter)
static const char *g_monitor_filter = "\0";

// command line options
static const char *opt_string = "Vhs:Hv";
static const struct option long_opts[] = {
        // params
        {"version", no_argument, NULL, 'V'},
        {"help", no_argument, NULL, 'h'},
        {"server", required_argument, NULL, 's'},
        {"human", no_argument, NULL, 'H'},
        // actions
        {"show-stats", no_argument, NULL, OPT_SHOW_STATS},
        {"show-client", required_argument, NULL, OPT_CLIENT_SHOW},
        {"show-upstreams", no_argument, NULL, OPT_UPSTREAM_SHOW},
        {"update-client", required_argument, NULL, OPT_CLIENT_UPDATE},
        {"rules", required_argument, NULL, OPT_RULES},
        {"show-session", required_argument, NULL, OPT_SESSION_SHOW},
        {"delete-session", required_argument, NULL, OPT_SESSION_DELETE},
        {"reconfigure", no_argument, NULL, OPT_RECONFIGURE},
        {"monitor", optional_argument, NULL, OPT_MONITOR},
#ifdef DEBUG
        {"dump-counters", no_argument, NULL, OPT_DUMP_COUNTERS},
#endif
        {NULL, no_argument, NULL, 0}
};

static const char *format_number(char *buf, size_t len, uint64_t size, double div)
{
    static const char *prefix = " KMGTPEZ";

    if (g_human_readable) {
        size_t i = 0;
        long double size_f = size;

        while (size_f >= div) {
            i++;
            size_f /= div;
        }

        snprintf(buf, len, "%7.2Lf %c", size_f, prefix[i]);
    } else {
        snprintf(buf, len, "%" PRIu64 " ", size);
    }

    return buf;
}

static void display_version(void)
{
    puts(
            "zeroctl v" ZEROD_VER_STR " (c) Intersvyaz 2013-\n"
                    "Build: "
#ifdef DEBUG
                    "DEBUG "
#endif
                    "" __DATE__ " " __TIME__ "\n"
    );
}

static void display_usage(void)
{
    puts(
            "Usage: zeroctl [-VhH] [-s <host:port>]\n"
                    "Common options:\n"
                    "\t-v,\t\t\t\tincrease verbosity\n"
                    "\t-h, --help\t\t\tshow this help\n"
                    "\t-V, --version\t\t\tprint version\n"
                    "\t-s, --server <host:port>\ttarget server, defaults to 127.0.0.1:1050\n"
                    "\t-H, --human\t\t\thuman readable numbers and headers\n"
                    "Actions:\n"
                    "\t--show-stats\t\t\tshow server info\n"
                    "\t--show-upstreams\t\tshow upstreams info\n"
                    "\t--show-session <ip_addr>\tshow session info\n"
                    "\t--delete-session <ip_addr>\tdelete session\n"
                    "\t--show-client <user_id|ip>\tshow client info\n"
                    "\t--update-client <user_id|ip>\tupdate client\n"
                    "\t--reconfigure\t\t\tmodify server configuration\n"
                    "\t--rules <rule1> [rule2] ...\tdefine rule for client or server\n"
                    "\t--monitor [filter]\t\ttraffic monitoring with optional bpf-like filter (ex. vlan or ip)\n"
#ifdef DEBUG
                    "\t--dump-counters\t\tDump traffic counters to file\n"
#endif
                    "Client rules:\n"
                    "\tbw.<speed>KBit.<up|down> - bandwidth limit\n"
                    "\tp2p_policer.<0|1> - p2p policer\n"
                    "\tports.<allow|deny>.<tcp|udp>.<port1>[.<port2>] - add port rule\n"
                    "\trmports.<allow|deny>.<tcp|udp>.<port1>[.<port2>] - remove port rule\n"
                    "\tfwd.<tcp|udp>.<port>.<ip>[:<port>] - add forwading rule\n"
                    "\trmfwd.<tcp|udp>.<port> - remove forwarding rule\n"
                    "\tdeferred.<seconds>.<rule> - apply deferred rule after given timeout\n"
                    "Server rules:\n"
                    "\tupstream_bw.<id>.<speed>Kbit.<up|down> - upstream p2p bandwidth limit\n"
                    "\tnon_client_bw.<speed>Kbit.<up|down> - non-client bandwidth limit\n"
    );
}

/**
* Connects to target server.
* @param[in] server Server and port string.
* @return Socket descriptor.
*/
static int server_connect(const char *server)
{
    if (NULL == server) {
        fprintf(stderr, "Server not specified\n");
        exit(EXIT_FAILURE);
    }

    int ret = 0;
    char *port_str, *host_str = strdupa(server);
    if (NULL == (port_str = strchr(host_str, ':'))) {
        fprintf(stderr, "Port not specified\n");
        exit(EXIT_FAILURE);
    }
    *port_str = 0;
    port_str++;

    struct addrinfo ai_hint, *ai_addr;
    bzero(&ai_hint, sizeof(ai_hint));
    ai_hint.ai_family = PF_INET;
    ai_hint.ai_socktype = SOCK_STREAM;
    ai_hint.ai_protocol = IPPROTO_TCP;

    if (0 != (ret = getaddrinfo(host_str, port_str, &ai_hint, &ai_addr))) {
        if (EAI_SYSTEM == ret) {
            perror("Invalid server address or port");
        } else {
            fprintf(stderr, "Invalid server address or port: %s\n", gai_strerror(ret));
        }
        exit(EXIT_FAILURE);
    }

    int fd = socket(PF_INET, SOCK_STREAM, 0);
    if (-1 == fd) {
        perror("Failed to create socket");
        exit(EXIT_FAILURE);
    }

    if (0 != connect(fd, ai_addr->ai_addr, ai_addr->ai_addrlen)) {
        perror("Failed connect to server");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(ai_addr);

    return fd;
}

/**
* Read packet from stream.
* @param[in] fd Socket descriptor.
* @param[in,out] buf Buffer for packet.
* @param[in] cookie Required cookie.
*/
static void read_packet(int fd, UT_string *buf, uint32_t cookie)
{
    size_t req_len = sizeof(struct zrc_header);
    bool has_header = false;

    while (utstring_len(buf) < req_len) {
        char tmp_buf[2048];
        ssize_t ret = recv(fd, tmp_buf, sizeof(tmp_buf), 0);
        if (ret <= 0) {
            perror("Error reading socket stream");
            exit(EXIT_FAILURE);
        }
        utstring_bincpy(buf, tmp_buf, (size_t) ret);

        if ((utstring_len(buf) >= req_len) && !has_header) {
            struct zrc_header *packet = (struct zrc_header *) utstring_body(buf);
            if ((htons(ZRC_PROTO_MAGIC) != packet->magic) || (ZRC_PROTO_VERSION != packet->version)) {
                fprintf(stderr, "Invalid server response: invalid proto magic or version\n");
                exit(EXIT_FAILURE);
            }
            if (packet->cookie != cookie) {
                fprintf(stderr, "Invalid cookie (0x%X != 0x%X)\n", cookie, packet->cookie);
                exit(EXIT_FAILURE);
            }
            has_header = true;
            req_len += ntohl(packet->length);
        }
    }
}

static void print_ring_stats(struct zrc_ring_info *ring)
{
    char buf[4][32];

    format_number(buf[0], sizeof(buf[0]), ring->packets.down.all.count, 1000);
    format_number(buf[1], sizeof(buf[1]), ring->packets.down.all.speed, 1000);
    format_number(buf[2], sizeof(buf[2]), ring->traffic.down.all.count, 1000);
    format_number(buf[3], sizeof(buf[3]), ring->traffic.down.all.speed * 8, 1024);
    fprintf(stdout, " down\t\t%spkt\t%spps\t%sB\t%sbps\n", buf[0], buf[1], buf[2], buf[3]);

    format_number(buf[0], sizeof(buf[0]), ring->packets.down.passed.count, 1000);
    format_number(buf[1], sizeof(buf[1]), ring->packets.down.passed.speed, 1000);
    format_number(buf[2], sizeof(buf[2]), ring->traffic.down.passed.count, 1000);
    format_number(buf[3], sizeof(buf[3]), ring->traffic.down.passed.speed * 8, 1024);
    fprintf(stdout, " down passed\t%spkt\t%spps\t%sB\t%sbps\n", buf[0], buf[1], buf[2], buf[3]);

    format_number(buf[0], sizeof(buf[0]), ring->packets.down.client.count, 1000);
    format_number(buf[1], sizeof(buf[1]), ring->packets.down.client.speed, 1000);
    format_number(buf[2], sizeof(buf[2]), ring->traffic.down.client.count, 1000);
    format_number(buf[3], sizeof(buf[3]), ring->traffic.down.client.speed * 8, 1024);
    fprintf(stdout, " down client\t%spkt\t%spps\t%sB\t%sbps\n", buf[0], buf[1], buf[2], buf[3]);

    format_number(buf[0], sizeof(buf[0]), ring->packets.up.all.count, 1000);
    format_number(buf[1], sizeof(buf[1]), ring->packets.up.all.speed, 1000);
    format_number(buf[2], sizeof(buf[2]), ring->traffic.up.all.count, 1000);
    format_number(buf[3], sizeof(buf[3]), ring->traffic.up.all.speed * 8, 1024);
    fprintf(stdout, " up\t\t%spkt\t%spps\t%sB\t%sbps\n", buf[0], buf[1], buf[2], buf[3]);

    format_number(buf[0], sizeof(buf[0]), ring->packets.up.passed.count, 1000);
    format_number(buf[1], sizeof(buf[1]), ring->packets.up.passed.speed, 1000);
    format_number(buf[2], sizeof(buf[2]), ring->traffic.up.passed.count, 1000);
    format_number(buf[3], sizeof(buf[3]), ring->traffic.up.passed.speed * 8, 1024);
    fprintf(stdout, " up passed\t%spkt\t%spps\t%sB\t%sbps\n", buf[0], buf[1], buf[2], buf[3]);

    format_number(buf[0], sizeof(buf[0]), ring->packets.up.client.count, 1000);
    format_number(buf[1], sizeof(buf[1]), ring->packets.up.client.speed, 1000);
    format_number(buf[2], sizeof(buf[2]), ring->traffic.up.client.count, 1000);
    format_number(buf[3], sizeof(buf[3]), ring->traffic.up.client.speed * 8, 1024);
    fprintf(stdout, " up client\t%spkt\t%spps\t%sB\t%sbps\n", buf[0], buf[1], buf[2], buf[3]);
}

static void ring_info_n2h(struct zrc_ring_info *ring)
{
    ring->packets.down.all.count = ntohll(ring->packets.down.all.count);
    ring->packets.down.all.speed = ntohll(ring->packets.down.all.speed);
    ring->packets.down.passed.count = ntohll(ring->packets.down.passed.count);
    ring->packets.down.passed.speed = ntohll(ring->packets.down.passed.speed);
    ring->packets.down.client.count = ntohll(ring->packets.down.client.count);
    ring->packets.down.client.speed = ntohll(ring->packets.down.client.speed);

    ring->packets.up.all.count = ntohll(ring->packets.up.all.count);
    ring->packets.up.all.speed = ntohll(ring->packets.up.all.speed);
    ring->packets.up.passed.count = ntohll(ring->packets.up.passed.count);
    ring->packets.up.passed.speed = ntohll(ring->packets.up.passed.speed);
    ring->packets.up.client.count = ntohll(ring->packets.up.client.count);
    ring->packets.up.client.speed = ntohll(ring->packets.up.client.speed);

    ring->traffic.down.all.count = ntohll(ring->traffic.down.all.count);
    ring->traffic.down.all.speed = ntohll(ring->traffic.down.all.speed);
    ring->traffic.down.passed.count = ntohll(ring->traffic.down.passed.count);
    ring->traffic.down.passed.speed = ntohll(ring->traffic.down.passed.speed);
    ring->traffic.down.client.count = ntohll(ring->traffic.down.client.count);
    ring->traffic.down.client.speed = ntohll(ring->traffic.down.client.speed);

    ring->traffic.up.all.count = ntohll(ring->traffic.up.all.count);
    ring->traffic.up.all.speed = ntohll(ring->traffic.up.all.speed);
    ring->traffic.up.passed.count = ntohll(ring->traffic.up.passed.count);
    ring->traffic.up.passed.speed = ntohll(ring->traffic.up.passed.speed);
    ring->traffic.up.client.count = ntohll(ring->traffic.up.client.count);
    ring->traffic.up.client.speed = ntohll(ring->traffic.up.client.speed);
}

static void ring_info_add(struct zrc_ring_info *to, struct zrc_ring_info *from)
{
    to->packets.down.all.count += from->packets.down.all.count;
    to->packets.down.all.speed += from->packets.down.all.speed;
    to->packets.down.passed.count += from->packets.down.passed.count;
    to->packets.down.passed.speed += from->packets.down.passed.speed;
    to->packets.down.client.count += from->packets.down.client.count;
    to->packets.down.client.speed += from->packets.down.client.speed;

    to->packets.up.all.count += from->packets.up.all.count;
    to->packets.up.all.speed += from->packets.up.all.speed;
    to->packets.up.passed.count += from->packets.up.passed.count;
    to->packets.up.passed.speed += from->packets.up.passed.speed;
    to->packets.up.client.count += from->packets.up.client.count;
    to->packets.up.client.speed += from->packets.up.client.speed;

    to->traffic.down.all.count += from->traffic.down.all.count;
    to->traffic.down.all.speed += from->traffic.down.all.speed;
    to->traffic.down.passed.count += from->traffic.down.passed.count;
    to->traffic.down.passed.speed += from->traffic.down.passed.speed;
    to->traffic.down.client.count += from->traffic.down.client.count;
    to->traffic.down.client.speed += from->traffic.down.client.speed;

    to->traffic.up.all.count += from->traffic.up.all.count;
    to->traffic.up.all.speed += from->traffic.up.all.speed;
    to->traffic.up.passed.count += from->traffic.up.passed.count;
    to->traffic.up.passed.speed += from->traffic.up.passed.speed;
    to->traffic.up.client.count += from->traffic.up.client.count;
    to->traffic.up.client.speed += from->traffic.up.client.speed;
}

/**
* Show server statistics.
*/
static void cmd_show_stats()
{
    int fd = server_connect(g_server);

    struct zrc_header request_packet;
    zrc_fill_header(&request_packet);
    request_packet.length = 0;
    request_packet.type = ZOP_STATS_SHOW;
    request_packet.cookie = (uint32_t) rand();
    send(fd, &request_packet, sizeof(request_packet), 0);

    UT_string packet;
    utstring_init(&packet);
    read_packet(fd, &packet, request_packet.cookie);
    struct zrc_op_stats_show_resp *response_packet = (struct zrc_op_stats_show_resp *) utstring_body(&packet);

    if (unlikely(ZOP_STATS_SHOW_RESP != response_packet->header.type)) {
        fprintf(stderr, "Invalid response type (0x%X)\n", response_packet->header.type);
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "Server stats:\n");
    fprintf(stdout, "Sessions count: %" PRIu32 "\n", ntohl(response_packet->sess_count));
    fprintf(stdout, "Unauth sessions count: %" PRIu32 "\n", ntohl(response_packet->unauth_sess_count));
    fprintf(stdout, "Clients count: %" PRIu32 "\n", ntohl(response_packet->clients_count));

    char buf[2][32];
    format_number(buf[0], sizeof(buf[0]), ntohll(response_packet->non_client_speed_down) * 8, 1024);
    format_number(buf[1], sizeof(buf[1]), ntohll(response_packet->non_client_bw_down) * 8, 1024);
    fprintf(stdout, "Non-client speed down: %sbps (limit: %sbps)\n", buf[0], buf[1]);
    format_number(buf[0], sizeof(buf[0]), ntohll(response_packet->non_client_speed_up) * 8, 1024);
    format_number(buf[1], sizeof(buf[1]), ntohll(response_packet->non_client_bw_up) * 8, 1024);
    fprintf(stdout, "Non-client speed up: %sbps (limit: %sbps)\n\n", buf[0], buf[1]);

    struct zrc_ring_info total, total_if;
    bzero(&total, sizeof(total));
    bzero(&total_if, sizeof(total_if));
    uint16_t ring_id = 0;

    if (g_human_readable) {
        fprintf(stdout, "\t\tPkt\t\tPkt speed\tTraffic\t\tTraffic speed\n");
    }

    uint16_t rings_count = ntohs(response_packet->rings_count);
    for (uint16_t i = 0; i < rings_count; i++) {
        struct zrc_ring_info *ring = &response_packet->rings[i];

        if ('\0' == total_if.ifname_lan[0]) {
            bzero(&total_if, sizeof(total_if));
            strncpy(total_if.ifname_lan, ring->ifname_lan, sizeof(total_if.ifname_lan));
            strncpy(total_if.ifname_wan, ring->ifname_wan, sizeof(total_if.ifname_wan));
            ring_id = 0;
        }

        ring_info_n2h(ring);
        ring_info_add(&total, ring);
        ring_info_add(&total_if, ring);

        if (g_verbosity >= 2) {
            fprintf(stdout, "%s-%s ring%" PRIu16 "\n", total_if.ifname_lan, total_if.ifname_wan, ring_id);
            print_ring_stats(ring);
        }

        if (g_verbosity >= 1) {
            // interface pair changed or last in list
            if ((i + 1 == rings_count) || 0 != strncmp(total_if.ifname_lan, response_packet->rings[i + 1].ifname_lan, sizeof(total_if.ifname_lan))) {
                fprintf(stdout, "%s-%s total:\n", total_if.ifname_lan, total_if.ifname_wan);
                print_ring_stats(&total_if);
                // mark as empty
                total_if.ifname_lan[0] = '\0';
            }
        }

        ring_id++;
    }

    if (g_human_readable) {
        fprintf(stdout, "Total:\n");
    }
    print_ring_stats(&total);

    utstring_done(&packet);
    shutdown(fd, SHUT_RDWR);
    close(fd);
}

/**
* Show user info.
*/
static void cmd_client_show(void)
{
    int fd = server_connect(g_server);

    struct zrc_op_client_show request_packet;
    zrc_fill_header(&request_packet.header);
    request_packet.header.length = htonl(sizeof(request_packet) - sizeof(request_packet.header));
    request_packet.header.type = ZOP_CLIENT_SHOW;
    request_packet.header.cookie = (uint32_t) rand();
    request_packet.ip_flag = g_ip_flag;
    if (request_packet.ip_flag) {
        request_packet.ip = htonl(g_sess_ip);
    } else {
        request_packet.user_id = htonl(g_user_id);
    }

    send(fd, &request_packet, sizeof(request_packet), 0);

    UT_string packet;
    utstring_init(&packet);
    read_packet(fd, &packet, request_packet.header.cookie);
    struct zrc_op_client_show_resp *response_packet = (struct zrc_op_client_show_resp *) utstring_body(&packet);

    if (unlikely(ZOP_NOT_FOUND == response_packet->header.type)) {
        fprintf(stderr, "User not found\n");
        exit(EXIT_FAILURE);
    } else if (unlikely(ZOP_CLIENT_SHOW_RESP != response_packet->header.type)) {
        fprintf(stderr, "Invalid response type (0x%X)\n", response_packet->header.type);
        exit(EXIT_FAILURE);
    }

    const char *rule = response_packet->data;
    const char *packet_end = response_packet->data + ntohl(response_packet->header.length);

    if (g_human_readable) {
        fprintf(stdout, "Client config:\n");
    }

    while (rule < packet_end) {
        fprintf(stdout, "%s\n", rule);
        rule += strlen(rule) + 1;
    }

    utstring_done(&packet);
    shutdown(fd, SHUT_RDWR);
    close(fd);
}

/**
* Updater user.
*/
static void cmd_client_update(void)
{
    if (0 == g_rules_cnt) {
        fprintf(stderr, "Rules not specified\n");
        exit(EXIT_FAILURE);
    }

    int fd = server_connect(g_server);

    UT_string packet;
    utstring_init(&packet);

    struct zrc_op_client_update request_packet;
    zrc_fill_header(&request_packet.header);
    request_packet.header.type = ZOP_CLIENT_UPDATE;
    request_packet.header.cookie = (uint32_t) rand();
    request_packet.ip_flag = g_ip_flag;
    if (request_packet.ip_flag) {
        request_packet.ip = htonl(g_sess_ip);
    } else {
        request_packet.user_id = htonl(g_user_id);
    }

    utstring_bincpy(&packet, &request_packet, sizeof(request_packet));

    for (size_t i = 0; i < g_rules_cnt; i++) {
        size_t rule_len = strlen(g_rules[i]) + 1;
        utstring_bincpy(&packet, g_rules[i], rule_len);
    }

    size_t packet_len = utstring_len(&packet);
    struct zrc_header *hdr = (struct zrc_header *) utstring_body(&packet);
    hdr->length = htonl(packet_len - sizeof(*hdr));
    send(fd, hdr, packet_len, 0);

    utstring_clear(&packet);
    read_packet(fd, &packet, request_packet.header.cookie);
    struct zrc_header *response_packet = (struct zrc_header *) utstring_body(&packet);

    if (ZOP_NOT_FOUND == response_packet->type) {
        fprintf(stderr, "User not found\n");
        exit(EXIT_FAILURE);
    } else if (ZOP_BAD_RULE == response_packet->type) {
        fprintf(stdout, "Bad rule\n");
    } else if (ZOP_OK == response_packet->type) {
        fprintf(stdout, "Success\n");
    } else {
        fprintf(stderr, "Invalid response type (0x%X)\n", response_packet->type);
        exit(EXIT_FAILURE);
    }

    utstring_done(&packet);
    shutdown(fd, SHUT_RDWR);
    close(fd);
}

/**
* Show session info command.
*/
static void cmd_session_show(void)
{
    int fd = server_connect(g_server);

    struct zrc_op_session_show request_packet;
    zrc_fill_header(&request_packet.header);
    request_packet.header.length = htonl(sizeof(request_packet) - sizeof(request_packet.header));
    request_packet.header.type = ZOP_SESSION_SHOW;
    request_packet.header.cookie = (uint32_t) rand();
    request_packet.session_ip = htonl(g_sess_ip);
    send(fd, &request_packet, sizeof(request_packet), 0);

    UT_string packet;
    utstring_init(&packet);
    read_packet(fd, &packet, request_packet.header.cookie);
    struct zrc_op_session_show_resp *response_packet = (struct zrc_op_session_show_resp *) utstring_body(&packet);

    if (ZOP_NOT_FOUND == response_packet->header.type) {
        fprintf(stderr, "Session not found\n");
        exit(EXIT_FAILURE);
    } else if (ZOP_SESSION_SHOW_RESP != response_packet->header.type) {
        fprintf(stderr, "Invalid response type (0x%X)\n", response_packet->header.type);
        exit(EXIT_FAILURE);
    }

    struct tm *timeinfo;
    char time_str[64];
    time_t time;

    time = ntohl(response_packet->last_seen);
    timeinfo = localtime(&time);
    strftime(time_str, sizeof(time_str), "%Y.%m.%d %H:%M:%S", timeinfo);
    fprintf(stdout, "Last activity: %s\n", time_str);

    time = ntohl(response_packet->last_auth);
    timeinfo = localtime(&time);
    strftime(time_str, sizeof(time_str), "%Y.%m.%d %H:%M:%S", timeinfo);
    fprintf(stdout, "Last authorization: %s\n", time_str);

    time = ntohl(response_packet->last_acct);
    timeinfo = localtime(&time);
    strftime(time_str, sizeof(time_str), "%Y.%m.%d %H:%M:%S", timeinfo);
    fprintf(stdout, "Last accounting: %s\n", time_str);

    fprintf(stdout, "User id: %" PRIu32 "\n", ntohl(response_packet->user_id));

    char buf[128];
    format_number(buf, sizeof(buf), ntohll(response_packet->traff_down), 1024);
    fprintf(stdout, "Download traffic: %sB\n", buf);
    format_number(buf, sizeof(buf), ntohll(response_packet->traff_up), 1024);
    fprintf(stdout, "Upload traffic: %sB\n", buf);

    utstring_done(&packet);
    shutdown(fd, SHUT_RDWR);
    close(fd);
}

/**
* Delete session command.
*/
static void cmd_session_delete(void)
{
    int fd = server_connect(g_server);

    struct zrc_op_session_delete request_packet;
    bzero(&request_packet, sizeof(request_packet));
    zrc_fill_header(&request_packet.header);
    request_packet.header.length = htonl(sizeof(request_packet) - sizeof(request_packet.header));
    request_packet.header.type = ZOP_SESSION_DELETE;
    request_packet.header.cookie = (uint32_t) rand();
    request_packet.session_ip = htonl(g_sess_ip);

    send(fd, &request_packet, sizeof(request_packet), 0);

    UT_string packet;
    utstring_init(&packet);
    read_packet(fd, &packet, request_packet.header.cookie);
    struct zrc_header *response_packet = (struct zrc_header *) utstring_body(&packet);

    if (ZOP_NOT_FOUND == response_packet->type) {
        fprintf(stderr, "Session not found\n");
        exit(EXIT_FAILURE);
    } else if (ZOP_OK == response_packet->type) {
        fprintf(stdout, "Success\n");
    } else {
        fprintf(stderr, "Invalid response type (0x%X)\n", response_packet->type);
        exit(EXIT_FAILURE);
    }

    utstring_done(&packet);
    shutdown(fd, SHUT_RDWR);
    close(fd);
}

/**
* Show server statistics.
*/
static void cmd_upstream_show(void)
{
    int fd = server_connect(g_server);

    struct zrc_header request_packet;
    zrc_fill_header(&request_packet);
    request_packet.length = 0;
    request_packet.type = ZOP_UPSTREAM_SHOW;
    request_packet.cookie = (uint32_t) rand();
    send(fd, &request_packet, sizeof(request_packet), 0);

    UT_string packet;
    utstring_init(&packet);
    read_packet(fd, &packet, request_packet.cookie);
    struct zrc_op_upstream_show_resp *response_packet = (struct zrc_op_upstream_show_resp *) utstring_body(&packet);

    if (unlikely(ZOP_UPSTREAM_SHOW_RESP != response_packet->header.type)) {
        fprintf(stderr, "Invalid response type (0x%X)\n", response_packet->header.type);
        exit(EXIT_FAILURE);
    }

    if (g_human_readable) {
        fprintf(stdout, "Upstream stats:\n");
        fprintf(stdout, "Upstream\tSpeed down\tSpeed up\tP2P limit down\tP2P limit up\n");
    }

    uint16_t upstream_count = ntohs(response_packet->count);
    for (uint16_t i = 0; i < upstream_count; i++) {
        char buf[64];

        format_number(buf, sizeof(buf), ntohll(response_packet->upstream[i].speed_down) * 8, 1024);
        fprintf(stdout, "%u\t\t%sbps", i, buf);
        format_number(buf, sizeof(buf), ntohll(response_packet->upstream[i].speed_up) * 8, 1024);
        fprintf(stdout, "\t%sbps", buf);
        format_number(buf, sizeof(buf), ntohll(response_packet->upstream[i].p2p_bw_limit_down) * 8, 1024);
        fprintf(stdout, "\t%sbps", buf);
        format_number(buf, sizeof(buf), ntohll(response_packet->upstream[i].p2p_bw_limit_up) * 8, 1024);
        fprintf(stdout, "\t%sbps\n", buf);
    }

    fprintf(stdout, "\n");

    utstring_done(&packet);
    shutdown(fd, SHUT_RDWR);
    close(fd);
}

/**
* Reconfigure server.
*/
static void cmd_reconfigure(void)
{
    if (0 == g_rules_cnt) {
        fprintf(stderr, "Rules not specified\n");
        exit(EXIT_FAILURE);
    }

    int fd = server_connect(g_server);

    UT_string packet;
    utstring_init(&packet);

    struct zrc_op_reconfigure request_packet;
    zrc_fill_header(&request_packet.header);
    request_packet.header.type = ZOP_RECONFIGURE;
    request_packet.header.cookie = (uint32_t) rand();
    utstring_bincpy(&packet, &request_packet, sizeof(request_packet));

    for (size_t i = 0; i < g_rules_cnt; i++) {
        size_t rule_len = strlen(g_rules[i]) + 1;
        utstring_bincpy(&packet, g_rules[i], rule_len);
    }

    size_t packet_len = utstring_len(&packet);
    struct zrc_header *hdr = (struct zrc_header *) utstring_body(&packet);
    hdr->length = htonl(packet_len - sizeof(*hdr));
    send(fd, hdr, packet_len, 0);

    utstring_clear(&packet);
    read_packet(fd, &packet, request_packet.header.cookie);
    struct zrc_header *response_packet = (struct zrc_header *) utstring_body(&packet);

    if (unlikely(ZOP_BAD_RULE == response_packet->type)) {
        fprintf(stdout, "Bad rule\n");
    } else if (likely(ZOP_OK == response_packet->type)) {
        fprintf(stdout, "Success\n");
    } else {
        fprintf(stderr, "Invalid response type (0x%X)\n", response_packet->type);
        exit(EXIT_FAILURE);
    }

    utstring_done(&packet);
    shutdown(fd, SHUT_RDWR);
    close(fd);
}

/**
* Monitor traffic.
*/
static void cmd_monitor(void)
{
    if (0 == g_monitor_filter) {
        fprintf(stderr, "Filter not specified\n");
        exit(EXIT_FAILURE);
    }

    int fd = server_connect(g_server);

    UT_string packet;
    utstring_init(&packet);

    struct zrc_op_reconfigure request_packet;
    zrc_fill_header(&request_packet.header);
    request_packet.header.type = ZOP_MONITOR;
    request_packet.header.cookie = (uint32_t) rand();
    utstring_bincpy(&packet, &request_packet, sizeof(request_packet));
    utstring_bincpy(&packet, g_monitor_filter, strlen(g_monitor_filter) + 1);

    size_t packet_len = utstring_len(&packet);
    struct zrc_header *hdr = (struct zrc_header *) utstring_body(&packet);
    hdr->length = htonl(packet_len - sizeof(*hdr));
    send(fd, hdr, packet_len, 0);

    utstring_clear(&packet);
    read_packet(fd, &packet, request_packet.header.cookie);
    struct zrc_header *response_packet = (struct zrc_header *) utstring_body(&packet);

    if (unlikely(ZOP_BAD_FILTER == response_packet->type)) {
        fprintf(stderr, "Bad filter\n");
        exit(EXIT_FAILURE);
    } else if (likely(ZOP_OK == response_packet->type)) {
        fprintf(stderr, "Monitoring traffic...\n");
    } else {
        fprintf(stderr, "Invalid response type (0x%X)\n", response_packet->type);
        exit(EXIT_FAILURE);
    }

    char *pkt_buf = malloc(MINITOR_BUFFER_SIZE);
    for (; ;) {
        ssize_t ret = recv(fd, pkt_buf, MINITOR_BUFFER_SIZE, 0);
        if (ret <= 0) {
            perror("Error reading socket stream");
            exit(EXIT_FAILURE);
        }
        (void)write(fileno(stdout), pkt_buf, (size_t) ret);
    }
}

#ifdef DEBUG
/**
* Dump traffic counters.
*/
static void cmd_dump_counters(void)
{
    int fd = server_connect(g_server);

    struct zrc_header header;
    zrc_fill_header(&header);
    header.type = ZOP_DUMP_COUNTERS;
    header.cookie = (uint32_t) rand();
    header.length = 0;
    send(fd, &header, sizeof(header), 0);

    UT_string packet;
    utstring_init(&packet);

    read_packet(fd, &packet, header.cookie);
    struct zrc_header *response_packet = (struct zrc_header *) utstring_body(&packet);

    if (likely(ZOP_OK == response_packet->type)) {
        fprintf(stderr, "Success\n");
        exit(EXIT_SUCCESS);
    } else {
        fprintf(stderr, "Failed\n");
        exit(EXIT_FAILURE);
    }
}
#endif

/**
* Set action.
* @param[in] action
*/
static void set_action(int action)
{
    if (0 != g_action) {
        fprintf(stderr, "Only one action allowed!\n");
        exit(EXIT_FAILURE);
    }

    g_action = action;
}

/**
* App entry point.
* @param[in] argc
* @param[in] argv
* @return Zero on success.
*/
int main(int argc, char *argv[])
{
    // parse command line arguments
    int opt, long_index = 0;
    opt = getopt_long(argc, argv, opt_string, long_opts, &long_index);
    while (-1 != opt) {
        switch (opt) {
            case 'V':
                display_version();
                return EXIT_SUCCESS;

            case 'h':
                display_usage();
                return EXIT_SUCCESS;

            case 's':
                g_server = optarg;
                break;

            case 'H':
                g_human_readable = 1;
                break;

            case 'v':
                g_verbosity++;
                break;

            case OPT_RECONFIGURE:
            case OPT_SHOW_STATS:
            case OPT_UPSTREAM_SHOW:
#ifdef DEBUG
            case OPT_DUMP_COUNTERS:
#endif
                set_action(opt);
                break;

            case OPT_CLIENT_SHOW:
            case OPT_CLIENT_UPDATE:
                set_action(opt);
                if (0 == ipv4_to_u32(optarg, &g_sess_ip)) {
                    g_ip_flag = 1;
                } else if (0 != str_to_u32(optarg, &g_user_id)) {
                    fprintf(stderr, "Invalid user id or session ip address\n");
                    exit(EXIT_FAILURE);
                }
                break;

            case OPT_SESSION_SHOW:
            case OPT_SESSION_DELETE:
                set_action(opt);
                if (0 != ipv4_to_u32(optarg, &g_sess_ip)) {
                    fprintf(stderr, "Invalid session ip address\n");
                    exit(EXIT_FAILURE);
                }
                break;

            case OPT_RULES:
                optind--;
                while ((optind < argc) && ('-' != argv[optind][0])) {
                    g_rules[g_rules_cnt++] = argv[optind];
                    optind++;
                }
                break;

            case OPT_MONITOR:
                set_action(opt);
                if ((NULL != argv[optind]) && ('-' != *argv[optind])) {
                    g_monitor_filter = argv[optind];
                }
                break;

            default:
                return EXIT_FAILURE;
        }

        opt = getopt_long(argc, argv, opt_string, long_opts, &long_index);
    }

    if (NULL == g_server) {
        g_server = DEFAULT_SERVER;
    }

    srand(time(NULL));

    switch (g_action) {
        case OPT_SHOW_STATS:
            cmd_show_stats();
            break;

        case OPT_CLIENT_SHOW:
            cmd_client_show();
            break;

        case OPT_CLIENT_UPDATE:
            cmd_client_update();
            break;

        case OPT_SESSION_SHOW:
            cmd_session_show();
            break;

        case OPT_SESSION_DELETE:
            cmd_session_delete();
            break;

        case OPT_UPSTREAM_SHOW:
            cmd_upstream_show();
            break;

        case OPT_RECONFIGURE:
            cmd_reconfigure();
            break;

        case OPT_MONITOR:
            cmd_monitor();
            break;

#ifdef DEBUG
        case OPT_DUMP_COUNTERS:
            cmd_dump_counters();
            break;
#endif

        default:
            fprintf(stderr, "Invalid action\n");
            display_usage();
            exit(EXIT_FAILURE);
    }

    return EXIT_SUCCESS;
}
