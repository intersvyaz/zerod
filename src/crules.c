#include "crules.h"

#include <arpa/inet.h>
#include <assert.h>

#include <event2/util.h>

#include "session.h"
#include "client.h"

// predefined strings for rule identification
#define CLIENT_RULE_IDENTITY "identity."
#define CLIENT_RULE_BW "bw."
#define CLIENT_RULE_P2P_POLICER "p2p_policer."
#define CLIENT_RULE_PORTS "ports."
#define CLIENT_RULE_RMPORTS "rmports."
#define CLIENT_RULE_FWD "fwd."
#define CLIENT_RULE_RMFWD "rmfwd."
#define CLIENT_RULE_DEFERRED "deferred."

// deprecated rules
#define CLIENT_RULE_SHAPE "shape."
#define CLIENT_RULE_LOGIN "login."
#define CLIENT_RULE_MARK_POLICER "mark_policer"
#define CLIENT_RULE_NO_SMTP "no_smtp"
#define CLIENT_RULE_DNS_FILTER_TYPE "dns_filter_type."

// predefined string parts
#define STR_IN "in"
#define STR_OUT "out"
#define STR_ALLOW "allow"
#define STR_DENY "deny"
#define STR_TCP "tcp"
#define STR_UDP "udp"
#define STR_SPEED "speed"
#define STR_SESSION "session"
#define STR_DOWN "down"
#define STR_UP "up"

/**
* Parse bandwidth rule.
* @param[in] rules
* @param[in] str
* @return Zero on success.
*/
static int parse_bw(struct zcrules *rules, const char *str)
{
    int i = 0;
    uint32_t speed = 0;

    while ((NULL != (str = strchr(str, '.'))) && (i < 2)) {
        str++;

        switch (i) {
            case 0: // speed
                if (0 != str_to_u32(str, &speed)) {
                    return -1;
                }
                break;

            case 1: // direction
                if (0 == strncmp(STR_DOWN, str, sizeof(STR_DOWN) - 1)) {
                    rules->bw_down = speed * 1024 / 8;
                    rules->have.bw_down = 1;
                } else if (0 == strncmp(STR_UP, str, sizeof(STR_UP) - 1)) {
                    rules->bw_up = speed * 1024 / 8;
                    rules->have.bw_up = 1;
                } else {
                    return -1;
                }
                return 0;

            default:
                assert(false);
                return -1;
        }
        i++;
    }

    return -1;
}

/**
* Parse p2p policer rule.
* @param[in] rules
* @param[in] str
* @return Zero on success.
*/
static int parse_p2p_policer(struct zcrules *rules, const char *str)
{
    str = strchr(str, '.') + 1;
    if (0 == str_to_u8(str, &rules->p2p_policer)) {
        rules->have.p2p_policer = 1;
        return 0;
    } else {
        return -1;
    }
}

/*
* Parse identity rule.
* @param[in] rules
* @param[in] str
* @return Zero on success.
*/
static int parse_identity(struct zcrules *rules, const char *str)
{
    int i = 0;
    while ((NULL != (str = strchr(str, '.'))) && (i < 2)) {
        str++;
        switch (i) {
            case 0: // user id
                if ((0 != str_to_u32(str, &rules->user_id)) || (0 == rules->user_id)) {
                    return -1;
                }
                break;

            case 1: // login
                rules->login = strdup(str);
                strtoupper(rules->login);
                rules->have.user_id = 1;
                rules->have.login = 1;
                return 0;

            default:
                assert(false);
                return -1;
        }
        i++;
    }

    return -1;
}

/**
* Parse ports rule.
* @param[in] rules
* @param[in] str
* @return Zero on success.
*/
static int parse_ports(struct zcrules *rules, const char *str, bool add)
{
    enum port_rule type;
    enum ipproto proto;

    str = strchr(str, '.') + 1;

    if (0 == strncmp(STR_ALLOW, str, sizeof(STR_ALLOW) - 1)) {
        type = PORT_ALLOW;
    } else if (0 == strncmp(STR_DENY, str, sizeof(STR_DENY) - 1)) {
        type = PORT_DENY;
    } else {
        return -1;
    }

    str = strchr(str, '.');
    if (NULL == str) return -1;
    str++;

    if (0 == strncmp(STR_TCP, str, sizeof(STR_TCP) - 1)) {
        proto = PROTO_TCP;
    } else if (0 == strncmp(STR_UDP, str, sizeof(STR_UDP) - 1)) {
        proto = PROTO_UDP;
    } else {
        return -1;
    }

    size_t pushed_cnt = 0;
    while (NULL != (str = strchr(str, '.'))) {
        str++;
        struct zrule_port *item = malloc(sizeof(*item));
        item->proto = proto;
        item->type = type;
        if (0 != str_to_u16(str, &item->port)) {
            free(item);
            while (pushed_cnt--) {
                free(*(struct zrule_port **)utarray_back(&rules->port_rules));
                utarray_pop_back(&rules->port_rules);
            }
            return -1;
        }
        item->port = htons(item->port);
        item->add = add;
        utarray_push_back(&rules->port_rules, &item);
        pushed_cnt++;
    }

    rules->have.port_rules = 1;

    return 0;
}

/**
* Parse forwarding rule.
* @param[in] rules
* @param[in] str
* @return Zero on success.
*/
static int parse_fwd(struct zcrules *rules, const char *str, bool add)
{
    int i = 0;
    enum ipproto proto = PROTO_TCP;
    uint16_t port = 0;
    struct sockaddr_in sa;

    while ((NULL != (str = strchr(str, '.'))) && (i < 3)) {
        str++;

        switch (i) {
            case 0: // proto
                if (0 == strncmp(STR_TCP, str, sizeof(STR_TCP) - 1)) {
                    proto = PROTO_TCP;
                } else if (0 == strncmp(STR_UDP, str, sizeof(STR_UDP) - 1)) {
                    proto = PROTO_UDP;
                } else {
                    return -1;
                }
                break;

            case 1: // port
                if (0 != str_to_u16(str, &port)) {
                    return -1;
                }
                if (0 == port) {
                    return -1;
                }
                port = htons(port);
                break;

            case 2: { // server
                int sa_len = sizeof(sa);
                if (0 != evutil_parse_sockaddr_port(str, (struct sockaddr *) &sa, &sa_len)) {
                    return -1;
                }
                break;
            }

            default:
                assert(false);
                return -1;
        }

        i++;
    }

    if ((add && 3 == i) || (!add && 2 == i)) {
        struct zrule_fwd *item = malloc(sizeof(*item));
        item->add = add;
        item->proto = proto;
        item->port = port;
        if (add) {
            item->fwd_ip = sa.sin_addr.s_addr;
            item->fwd_port = sa.sin_port;
        } else {
            item->fwd_ip = 0;
            item->fwd_port = 0;
        }
        utarray_push_back(&rules->fwd_rules, &item);
        rules->have.fwd_rules = 1;
        return 0;
    } else {
        return -1;
    }
}

/**
* Parse deferred rule.
* @param[in] rules
* @param[in] str
* @return Zero on success.
*/
static int parse_deferred(struct zcrules *rules, const char *str)
{
    int i = 0;
    uint64_t when = 0;
    struct zrule_deferred *def_rule = NULL;

    while ((NULL != (str = strchr(str, '.'))) && (i < 2)) {
        str++;
        switch (i) {
            case 0: // seconds
                if (0 != str_to_u64(str, &when)) {
                    return -1;
                }
                break;

            case 1: // rule
                def_rule = malloc(sizeof(*def_rule));
                def_rule->when = when;
                def_rule->rule = strdup(str);
                utarray_push_back(&rules->deferred_rules, &def_rule);
                rules->have.deferred_rules = 1;
                return 0;

            default:
                assert(false);
                return -1;
        }

        i++;
    }

    return -1;
}

/**
* Parse shape rule.
* @deprecated Remove after migrating to new rules.
* @param[in] rules
* @param[in] str
* @return Zero on success.
*/
static int parse_shape(struct zcrules *rules, const char *str)
{
    int i = 0;
    uint32_t speed = 0;

    while ((NULL != (str = strchr(str, '.'))) && (i < 3)) {
        str++;
        switch (i) {
            case 0: // user_id
                if ((0 != str_to_u32(str, &rules->user_id)) || (0 == rules->user_id)) {
                    return -1;
                }
                break;

            case 1: // speed
                if (0 != str_to_u32(str, &speed)) {
                    return -1;
                }
                break;

            case 2: // direction with inverse logic!
                if (0 == strncmp(STR_IN, str, sizeof(STR_IN) - 1)) {
                    rules->bw_up = speed * 1024 / 8;
                    rules->have.bw_up = 1;
                } else if (0 == strncmp(STR_OUT, str, sizeof(STR_OUT) - 1)) {
                    rules->bw_down = speed * 1024 / 8;
                    rules->have.bw_down = 1;
                } else {
                    return -1;
                }

                rules->have.user_id = 1;
                return 0;

            default:
                assert(false);
                return -1;
        }

        i++;
    }

    return -1;
}

/**
* Parse login rule.
* @deprecated Remove after migrating to new rules.
* @param[in] rules
* @param[in] str
* @return Zero on success.
*/
static int parse_login(struct zcrules *rules, const char *str)
{
    str = strchr(str, '.') + 1;
    rules->login = strdup(str);
    strtoupper(rules->login);
    rules->have.login = 1;
    return 0;
}

/**
* Parse mark policer rule.
* @deprecated Remove after migrating to new rules.
* @param[in] rules
* @param[in] str
* @return Zero on success.
*/
static int parse_mark_policer(struct zcrules *rules, const char *str)
{
    (void) str;
    rules->p2p_policer = 1;
    rules->have.p2p_policer = 1;
    return 0;
}

/**
* Parse no smtp rule.
* @deprecated Remove after migrating to new rules.
* @param[in] cfg
* @param[in] rule
* @return Zero on success.
*/
static int parse_no_smtp(struct zcrules *rules, const char *str)
{
    (void) str;
    return parse_ports(rules, "ports.deny.tcp.25", true);
}

/**
* Parse dns filter type rule.
* @deprecated Remove after migrating to new rules.
* @param[in] cfg
* @param[in] rule
* @return Zero on success.
*/
static int parse_dns_filter_type(struct zcrules *rules, const char *str)
{
    str = strchr(str, '.') + 1;
    long dns_type = strtol(str, NULL, 10);

    int ret = 0;

    ret = ret || parse_ports(rules, "rmports.allow.udp.53", false);
    ret = ret || parse_ports(rules, "rmports.allow.tcp.53", false);
    ret = ret || parse_ports(rules, "rmports.allow.tcp.80.443", false);

    switch (dns_type) {
        case 0: // no filtering
            ret = ret || parse_fwd(rules, "rmfwd.udp.53", false);
            ret = ret || parse_fwd(rules, "rmfwd.tcp.53", false);
            return ret;

        case 1: // junior
            ret = ret || parse_fwd(rules, "fwd.udp.53.78.29.2.26", true);
            ret = ret || parse_fwd(rules, "fwd.tcp.53.78.29.2.26", true);
            return ret;

        case 3: // government
            ret = ret || parse_fwd(rules, "fwd.udp.53.78.29.2.27", true);
            ret = ret || parse_fwd(rules, "fwd.tcp.53.78.29.2.27", true);
            ret = ret || parse_ports(rules, "ports.allow.udp.53", true);
            ret = ret || parse_ports(rules, "ports.allow.tcp.53.80.443", true);
            return ret;

        default:
            return -1;
    }
}

/**
* Initialize client rules.
* @param[in,out] rules
*/
void crules_init(struct zcrules *rules)
{
    bzero(rules, sizeof(*rules));
    utarray_init(&rules->fwd_rules, &ut_ptr_icd);
    utarray_init(&rules->port_rules, &ut_ptr_icd);
    utarray_init(&rules->deferred_rules, &ut_ptr_icd);
}

/**
* Parse client rule.
* @param[in] rules
* @param[in] str
* @return Zero on success.
*/
int crules_parse(struct zcrules *rules, const char *str)
{
    // identity.<userid>.<login>
    if (0 == strncmp(str, CLIENT_RULE_IDENTITY, sizeof(CLIENT_RULE_IDENTITY) - 1))
        return parse_identity(rules, str);

    // bw.<speed>KBit.<up|down>
    if (0 == strncmp(str, CLIENT_RULE_BW, sizeof(CLIENT_RULE_BW) - 1))
        return parse_bw(rules, str);

    // p2p_policer.<0|1>
    if (0 == strncmp(str, CLIENT_RULE_P2P_POLICER, sizeof(CLIENT_RULE_P2P_POLICER) - 1))
        return parse_p2p_policer(rules, str);

    // ports.<allow|deny>.<tcp|udp>.<port1>[.<port2>]
    if (0 == strncmp(str, CLIENT_RULE_PORTS, sizeof(CLIENT_RULE_PORTS) - 1))
        return parse_ports(rules, str, true);

    // rmports.<allow|deny>.<tcp|udp>.<port1>[.<port2>]
    if (0 == strncmp(str, CLIENT_RULE_RMPORTS, sizeof(CLIENT_RULE_RMPORTS) - 1))
        return parse_ports(rules, str, false);

    // fwd.<tcp|udp>.<port>.<ip>[:<port>]
    if (0 == strncmp(str, CLIENT_RULE_FWD, sizeof(CLIENT_RULE_FWD) - 1))
        return parse_fwd(rules, str, true);

    // rmfwd.<tcp|udp>.<port>
    if (0 == strncmp(str, CLIENT_RULE_RMFWD, sizeof(CLIENT_RULE_RMFWD) - 1))
        return parse_fwd(rules, str, false);

    // deferred.<seconds>.<rule>
    if (0 == strncmp(str, CLIENT_RULE_DEFERRED, sizeof(CLIENT_RULE_DEFERRED) - 1))
        return parse_deferred(rules, str);

    // deprecated rules

    // shape.<user_id>.<speed>KBit.<in|out>
    if (0 == strncmp(str, CLIENT_RULE_SHAPE, sizeof(CLIENT_RULE_SHAPE) - 1))
        return parse_shape(rules, str);

    // mark_policer
    if (0 == strncmp(str, CLIENT_RULE_MARK_POLICER, sizeof(CLIENT_RULE_MARK_POLICER) - 1))
        return parse_mark_policer(rules, str);

    // no_smtp
    if (0 == strncmp(str, CLIENT_RULE_NO_SMTP, sizeof(CLIENT_RULE_NO_SMTP) - 1))
        return parse_no_smtp(rules, str);

    // login.<login>
    if (0 == strncmp(str, CLIENT_RULE_LOGIN, sizeof(CLIENT_RULE_LOGIN) - 1))
        return parse_login(rules, str);

    // dns_filter_type.<type>
    if (0 == strncmp(str, CLIENT_RULE_DNS_FILTER_TYPE, sizeof(CLIENT_RULE_DNS_FILTER_TYPE) - 1))
        return parse_dns_filter_type(rules, str);

    return -1;
}

/**
* Free internally allocated memory for client config.
* @param[in] cfg
*/
void crules_free(struct zcrules *rules)
{
    if (rules->login) free(rules->login);

    for (size_t i = 0; i < utarray_len(&rules->port_rules); i++) {
        struct zrule_port *rule = *(struct zrule_port **) utarray_eltptr(&rules->port_rules, i);
        free(rule);
    }
    utarray_done(&rules->port_rules);

    for (size_t i = 0; i < utarray_len(&rules->fwd_rules); i++) {
        struct zrule_fwd *rule = *(struct zrule_fwd **) utarray_eltptr(&rules->fwd_rules, i);
        free(rule);
    }
    utarray_done(&rules->fwd_rules);

    for (size_t i = 0; i < utarray_len(&rules->deferred_rules); i++) {
        struct zrule_deferred *rule = *(struct zrule_deferred **) utarray_eltptr(&rules->deferred_rules, i);
        free(rule->rule);
        free(rule);
    }
    utarray_done(&rules->deferred_rules);
}

/**
* Make rule "identity".
* @param[in,out] string Output buffer.
* @param[in] user_id User id.
* @param[in] login Login.
*/
void crules_make_identity(UT_string *string, uint32_t user_id, const char *login)
{
    // identity.<user_id>.<login>
    utstring_printf(string, "%s%" PRIu32 ".%s", CLIENT_RULE_IDENTITY, user_id, login);
}

/**
* Make rule "bw".
* @param[in,out] string Output buffer.
* @param[in] speed Speed limit.
* @param[in] flow_dir Flow direction.
*/
void crules_make_bw(UT_string *string, uint32_t speed, enum flow_dir flow_dir)
{
    // bw.<speed>KBit.<up|down>
    speed = speed * 8 / 1024;
    const char *dir = (DIR_UP == flow_dir) ? STR_UP : STR_DOWN;
    utstring_printf(string, "%s%" PRIu32 "KBit.%s", CLIENT_RULE_BW, speed, dir);
}

/**
* Make rule "p2p_policer".
* @param[in,out] string Output buffer.
* @param[in] p2p_policer Policer state.
*/
void crules_make_p2p_policer(UT_string *string, uint8_t p2p_policer)
{
    // p2p_policer.<value>
    utstring_printf(string, "%s%" PRIu8, CLIENT_RULE_P2P_POLICER, p2p_policer);
}

/**
* Make rule "ports".
* @param[in,out] string Output buffer.
* @param[in] proto Protocol.
* @param[in] type Rule type.
* @param[in] ports Array of ports (network order).
* @param[in] count Number of elements in ports array.
*/
void crules_make_ports(UT_string *string, enum ipproto proto, enum port_rule type, const uint16_t *ports, size_t count)
{
    // ports.<allow|deny>.<tcp|udp>.<port1>[.<port2>]

    const char *proto_str = PROTO_TCP == proto ? STR_TCP : STR_UDP;
    const char *rule_str = PORT_ALLOW == type ? STR_ALLOW : STR_DENY;

    utstring_printf(string, "%s%s.%s", CLIENT_RULE_PORTS, rule_str, proto_str);

    for (size_t i = 0; i < count; i++) {
        utstring_printf(string, ".%" PRIu16, ntohs(ports[i]));
    }
}

/**
* Make rule "forward".
* @param[in,out] string Output buffer.
* @param[in] proto Protocol.
* @param[in] fwd_rule Forwarding rule.
*/
void crules_make_fwd(UT_string *string, enum ipproto proto, const struct zfwd_rule *fwd_rule)
{
    // forward.<tcp|udp>.<port>.<ip>[:<port>]

    const char *proto_str = PROTO_TCP == proto ? STR_TCP : STR_UDP;

    utstring_printf(string, "%s%s.%" PRIu16 ".%s",
            CLIENT_RULE_FWD,
            proto_str,
            ntohs(fwd_rule->port),
            ipv4_to_str(fwd_rule->fwd_ip)
    );

    if (fwd_rule->fwd_port) {
        utstring_printf(string, ":%" PRIu16, ntohs(fwd_rule->fwd_port));
    }
}

/**
* Make rule "speed".
* @param[in,out] string Output buffer.
* @param speed Speed.
* @param flow_dir Flow direction.
*/
void crules_make_speed(UT_string *string, uint64_t speed, enum flow_dir flow_dir)
{
    static const char *prefixes[] = {"bps", "Kbps", "Mbps", "Gbps", "Tbps", "Pbps", "Ebps", "Zbps"};
    const char *dir = (DIR_UP == flow_dir) ? STR_UP : STR_DOWN;

    size_t i = 0;

    while (speed >= 1024) {
        i++;
        speed /= 1024;
    }

    utstring_printf(string, "%s.%" PRIu64 ".%s.%s", STR_SPEED, speed, prefixes[i], dir);
}

/**
* Make rule "session".
* @param[in,out] string Output buffer.
* @param[in] sess Session.
*/
void crules_make_session(UT_string *string, const struct zsession *sess)
{
    utstring_printf(string, "%s.%s", STR_SESSION, ipv4_to_str(htonl(sess->ip)));
}

/**
* Make deferred rule.
* @param[in,out] string Output buffer.
* @param[in] def_rule Deferred rule.
*/
void crules_make_deferred(UT_string *string, const struct zrule_deferred *def_rule)
{
    uint64_t cur_clock = zclock(false);
    uint64_t when = (def_rule->when > cur_clock) ? ((def_rule->when - cur_clock) / 1000000) : 0;

    utstring_printf(string, "%s%" PRIu64 ".%s", CLIENT_RULE_DEFERRED, when, def_rule->rule);
}

/**
* Deferred rule time comparator.
* @param[in] arg1
* @param[in] arg2
* @return Same as strcmp with inversion.
*/
int zrule_deferred_cmp(const void *arg1, const void *arg2)
{
    const struct zrule_deferred *rule1 = *(const struct zrule_deferred **) arg1, *rule2 = *(const struct zrule_deferred **) arg2;

    if (rule1->when > rule2->when) return -1;
    if (rule1->when < rule2->when) return 1;
    return 0;
}
