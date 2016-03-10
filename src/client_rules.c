#include <assert.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <event2/util.h>
#include "client_rules.h"
#include "util_string.h"
#include "util_pcre.h"

// predefined strings for rule identification
#define CLIENT_RULE_IDENTITY "identity."
#define CLIENT_RULE_BW "bw."
#define CLIENT_RULE_PORTS "ports."
#define CLIENT_RULE_RMPORTS "rmports."
#define CLIENT_RULE_FWD "fwd."
#define CLIENT_RULE_RMFWD "rmfwd."
#define CLIENT_RULE_DEFERRED "deferred."
#define CLIENT_RULE_RMDEFERRED "rmdeferred"

// predefined string parts
#define STR_ALLOW "allow"
#define STR_DENY "deny"
#define STR_TCP "tcp"
#define STR_UDP "udp"
#define STR_SPEED "speed"
#define STR_SESSION "session"
#define STR_DOWN "down"
#define STR_UP "up"
#define STR_BOTH "both"

struct zclient_rule_parser_struct
{
    pcre *re_bw;
    pcre_extra *re_bw_extra;
    pcre *re_identity;
    pcre_extra *re_identity_extra;
    pcre *re_ports;
    pcre_extra *re_ports_extra;
    pcre *re_fwd;
    pcre_extra *re_fwd_extra;
    pcre *re_deferred;
    pcre_extra *re_deferred_extra;
};

/**
 *
 */
zclient_rule_parser_t *zclient_rule_parser_new(void)
{
    zclient_rule_parser_t *parser = malloc(sizeof(*parser));
    if (unlikely(!parser)) {
        return NULL;
    }

    memset(parser, 0, sizeof(*parser));

    int erroffset;
    const char *errptr;

    parser->re_bw = pcre_compile("^bw\\.(\\d+)([kmgtpe])?bit\\.(up|down)$", PCRE_CASELESS, &errptr, &erroffset, NULL);
    if (unlikely(!parser->re_bw)) {
        assert(false);
        goto error;
    }
    parser->re_bw_extra = pcre_study(parser->re_bw, 0, &errptr);

    parser->re_identity = pcre_compile("^identity\\.(\\d+)\\.([^\\s]+)$", PCRE_CASELESS, &errptr, &erroffset, NULL);
    if (unlikely(!parser->re_identity)) {
        assert(false);
        goto error;
    }
    parser->re_identity_extra = pcre_study(parser->re_identity, 0, &errptr);

    parser->re_ports = pcre_compile("^(rm)?ports\\.(allow|deny).(tcp|udp)(?:\\.\\d+)+$", PCRE_CASELESS, &errptr, &erroffset, NULL);
    if (unlikely(!parser->re_ports)) {
        assert(false);
        goto error;
    }
    parser->re_ports_extra = pcre_study(parser->re_ports, 0, &errptr);

    parser->re_fwd = pcre_compile("^(rm)?fwd\\.(tcp|udp).(\\d+)(?:\\.((?:\\d{1,3}.){3}\\d{1,3}(?::\\d+)?))?$", PCRE_CASELESS, &errptr, &erroffset, NULL);
    if (unlikely(!parser->re_fwd)) {
        assert(false);
        goto error;
    }
    parser->re_fwd_extra = pcre_study(parser->re_fwd, 0, &errptr);

    parser->re_deferred = pcre_compile("^deferred\\.(\\d+)\\.([^\\s]+)$", PCRE_CASELESS, &errptr, &erroffset, NULL);
    if (unlikely(!parser->re_deferred)) {
        assert(false);
        goto error;
    }
    parser->re_deferred_extra = pcre_study(parser->re_deferred, 0, &errptr);

    return parser;

error:
    zclient_rule_parser_free(parser);
    return NULL;
}

/**
 *
 */
void zclient_rule_parser_free(zclient_rule_parser_t *parser)
{
    assert(parser);

    if (parser->re_bw_extra) pcre_free_study(parser->re_bw_extra);
    if (parser->re_bw) pcre_free(parser->re_bw);
    if (parser->re_identity_extra) pcre_free_study(parser->re_identity_extra);
    if (parser->re_identity) pcre_free(parser->re_identity);
    if (parser->re_ports_extra) pcre_free_study(parser->re_ports_extra);
    if (parser->re_ports) pcre_free(parser->re_ports);
    if (parser->re_fwd_extra) pcre_free_study(parser->re_fwd_extra);
    if (parser->re_fwd) pcre_free(parser->re_fwd);
    if (parser->re_deferred_extra) pcre_free_study(parser->re_deferred_extra);
    if (parser->re_deferred) pcre_free(parser->re_deferred);
    free(parser);
}

/**
 * Parse bandwidth rule.
 * @param[in] rules
 * @param[in] str
 * @return Zero on success.
 */
static bool parse_bw(const zclient_rule_parser_t *parser, zclient_rules_t *rules, const char *str)
{
    int ovec[ZPCRE_DECL_SIZE(1+3)];

    int rc = pcre_exec(parser->re_bw, parser->re_bw_extra, str, (int)strlen(str), 0, 0, ovec, ARRAYSIZE(ovec));
    if (unlikely(rc < 0)) {
        return false;
    }

    const char *speed_str = str + ZPCRE_SO(ovec, 1);
    const char *prefix_str = (ZPCRE_SO(ovec, 2) != -1) ? (str + ZPCRE_SO(ovec, 2)) : NULL;
    const char *dir_str = str + ZPCRE_SO(ovec, 3);

    uint64_t speed = 0;
    if (0 != str_to_u64(speed_str, &speed)) {
        return false;
    }

    uint64_t mul = 1;
    if (prefix_str) {
        mul = str_parse_si_unit(*prefix_str, 1024);
    }

    if ('U' == toupper(*dir_str)) {
        rules->bw_up = speed * mul / 8;
        rules->have.bw_up = 1;
    } else {
        rules->bw_down = speed * mul / 8;
        rules->have.bw_down = 1;
    }

    return true;
}

/*
 * Parse identity rule.
 * @param[in] rules
 * @param[in] str
 * @return Zero on success.
 */
static bool parse_identity(const zclient_rule_parser_t *parser, zclient_rules_t *rules, const char *str)
{
    int ovec[ZPCRE_DECL_SIZE(1+2)];

    int rc = pcre_exec(parser->re_identity, parser->re_identity_extra, str, (int)strlen(str), 0, 0, ovec, ARRAYSIZE(ovec));
    if (unlikely(rc < 0)) {
        return false;
    }

    const char *id_str = str + ZPCRE_SO(ovec, 1);
    const char *login_str = str + ZPCRE_SO(ovec, 2);

    uint32_t user_id = 0;
    if (0 != str_to_u32(id_str, &user_id)) {
        return false;
    }
    if (!user_id) {
        return false;
    }

    rules->user_id = user_id;
    rules->have.user_id = 1;
    rules->login = strdup(login_str);
    strtoupper(rules->login);
    rules->have.login = 1;

    return true;
}

/**
 * Parse ports rule.
 * @param[in] rules
 * @param[in] str
 * @return Zero on success.
 */
static bool parse_ports(const zclient_rule_parser_t *parser, zclient_rules_t *rules, const char *str)
{
    int ovec[ZPCRE_DECL_SIZE(1+3)];

    int rc = pcre_exec(parser->re_ports, parser->re_ports_extra, str, (int)strlen(str), 0, 0, ovec, ARRAYSIZE(ovec));
    if (unlikely(rc < 0)) {
        return false;
    }

    bool add = true;
    if (ZPCRE_SO(ovec, 1) != -1) { // "rm" prefix
        add = false;
    }

    const char *policy_str = str + ZPCRE_SO(ovec, 2);
    const char *proto_str = str + ZPCRE_SO(ovec, 3);

    zfwall_policy_t policy = ('A' == toupper(*policy_str)) ? ACCESS_ALLOW : ACCESS_DENY;
    zip_proto_t proto = ('T' == toupper(*proto_str)) ? PROTO_TCP : PROTO_UDP ;

    str += ZPCRE_EO(ovec, 3);
    size_t pushed_cnt = 0;
    while (NULL != (str = strchr(str, '.'))) {
        str++;
        zcr_port_t *item = malloc(sizeof(*item));
        item->proto = proto;
        item->policy = policy;
        if (0 != str_to_u16(str, &item->port)) {
            free(item);
            goto error;
        }
        item->port = htons(item->port);
        item->add = add;
        utarray_push_back(&rules->port_rules, &item);
        pushed_cnt++;
    }

    rules->have.port_rules = 1;

    return true;

error:
    while (pushed_cnt--) {
        free(*(struct zcr_port **) utarray_back(&rules->port_rules));
        utarray_pop_back(&rules->port_rules);
    }

    return false;
}

/**
 * Parse forwarding rule.
 * @param[in] rules
 * @param[in] str
 * @return Zero on success.
 */
static bool parse_fwd(const zclient_rule_parser_t *parser, zclient_rules_t *rules, const char *str)
{
    int ovec[ZPCRE_DECL_SIZE(1+4)];

    int rc = pcre_exec(parser->re_fwd, parser->re_fwd_extra, str, (int)strlen(str), 0, 0, ovec, ARRAYSIZE(ovec));
    if (unlikely(rc < 0)) {
        return false;
    }

    bool add = true;
    if (ZPCRE_SO(ovec, 1) != -1) { // "rm" prefix
        add = false;
    }

    const char *proto_str = str + ZPCRE_SO(ovec, 2);
    const char *port_str = str + ZPCRE_SO(ovec, 3);
    const char *ipport_str = (-1 != ZPCRE_SO(ovec, 4)) ? (str + ZPCRE_SO(ovec, 4)) : NULL;

    zip_proto_t proto = ('T' == toupper(*proto_str)) ? PROTO_TCP : PROTO_UDP;

    uint16_t port = 0;
    if (0 != str_to_u16(port_str, &port)) {
        return false;
    }
    port = htons(port);

    struct sockaddr_in sa;
    if (add) {
        if (!ipport_str) {
            return false;
        }
        int sa_len = sizeof(sa);
        if (0 != evutil_parse_sockaddr_port(ipport_str, (struct sockaddr *) &sa, &sa_len)) {
            return false;
        }
    } else if (ipport_str) {
        return false;
    }

    zcr_forward_t *item = malloc(sizeof(*item));
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
    return true;
}

/**
 * Parse deferred rule.
 * @param[in] rules
 * @param[in] str
 * @return Zero on success.
 */
static bool parse_deferred(const zclient_rule_parser_t *parser, zclient_rules_t *rules, const char *str)
{
    int ovec[ZPCRE_DECL_SIZE(1+2)];

    int rc = pcre_exec(parser->re_deferred, parser->re_deferred_extra, str, (int)strlen(str), 0, 0, ovec, ARRAYSIZE(ovec));
    if (unlikely(rc < 0)) {
        return false;
    }

    const char *when_str = str + ZPCRE_SO(ovec, 1);
    const char *rule_str = str + ZPCRE_SO(ovec, 2);

    uint64_t when = 0;
    if (0 != str_to_u64(when_str, &when)) {
        return false;
    }

    zcr_deferred_t *def_rule = NULL;
    def_rule = malloc(sizeof(*def_rule));
    def_rule->when = when;
    def_rule->rule = strdup(rule_str);
    utarray_push_back(&rules->deferred_rules, &def_rule);
    rules->have.deferred_rules = 1;
    return true;
}

/**
 * Parse rmdeferred rule.
 * @param[in] rules
 * @param[in] str
 * @return Zero on success.
 */
static bool parse_rmdeferred(const zclient_rule_parser_t *parser, zclient_rules_t *rules, const char *str)
{
    (void)parser;
    (void)str;
    rules->have.rmdeferred = 1;
    return true;
}

/**
 * Parse client rule.
 * @param[in] rules
 * @param[in] str
 * @return Zero on success.
 */
bool zclient_rule_parse(const zclient_rule_parser_t *parser, zclient_rules_t *rules, const char *str)
{
    bool ok = false;

    // identity.<userid>.<login>
    if (0 == strncmp(str, CLIENT_RULE_IDENTITY, STRLEN_STATIC(CLIENT_RULE_IDENTITY))) {
        ok = parse_identity(parser, rules, str);
    }

        // bw.<speed>KBit.<up|down>
    else if (0 == strncmp(str, CLIENT_RULE_BW, STRLEN_STATIC(CLIENT_RULE_BW))) {
        ok = parse_bw(parser, rules, str);
    }

        // ports.<allow|deny>.<tcp|udp>.<port1>[.<port2>]
    else if (0 == strncmp(str, CLIENT_RULE_PORTS, STRLEN_STATIC(CLIENT_RULE_PORTS))) {
        ok = parse_ports(parser, rules, str);
    }

        // rmports.<allow|deny>.<tcp|udp>.<port1>[.<port2>]
    else if (0 == strncmp(str, CLIENT_RULE_RMPORTS, STRLEN_STATIC(CLIENT_RULE_RMPORTS))) {
        ok = parse_ports(parser, rules, str);
    }

        // fwd.<tcp|udp>.<port>.<ip>[:<port>]
    else if (0 == strncmp(str, CLIENT_RULE_FWD, STRLEN_STATIC(CLIENT_RULE_FWD))) {
        ok = parse_fwd(parser, rules, str);
    }

        // rmfwd.<tcp|udp>.<port>
    else if (0 == strncmp(str, CLIENT_RULE_RMFWD, STRLEN_STATIC(CLIENT_RULE_RMFWD))) {
        ok = parse_fwd(parser, rules, str);
    }

        // deferred.<seconds>.<rule>
    else if (0 == strncmp(str, CLIENT_RULE_DEFERRED, STRLEN_STATIC(CLIENT_RULE_DEFERRED))) {
        ok = parse_deferred(parser, rules, str);
    }

        // rmdeferred
    else if (0 == strcmp(str, CLIENT_RULE_RMDEFERRED)) {
        ok = parse_rmdeferred(parser, rules, str);
    }

    return ok;
}

/**
 * Initialize client rules.
 * @param[in,out] rules
 */
void zclient_rules_init(zclient_rules_t *rules)
{
    memset(rules, 0, sizeof(*rules));
    utarray_init(&rules->fwd_rules, &ut_ptr_icd);
    utarray_init(&rules->port_rules, &ut_ptr_icd);
    utarray_init(&rules->deferred_rules, &ut_ptr_icd);
}

/**
 * Free internally allocated memory for client config.
 * @param[in] cfg
 */
void zclient_rules_destroy(zclient_rules_t *rules)
{
    if (rules->login) free(rules->login);

    for (size_t i = 0; i < utarray_len(&rules->port_rules); i++) {
        zcr_port_t *rule = *(zcr_port_t **) utarray_eltptr(&rules->port_rules, i);
        free(rule);
    }
    utarray_done(&rules->port_rules);

    for (size_t i = 0; i < utarray_len(&rules->fwd_rules); i++) {
        zcr_forward_t *rule = *(zcr_forward_t **) utarray_eltptr(&rules->fwd_rules, i);
        free(rule);
    }
    utarray_done(&rules->fwd_rules);

    for (size_t i = 0; i < utarray_len(&rules->deferred_rules); i++) {
        zcr_deferred_t *rule = *(zcr_deferred_t **) utarray_eltptr(&rules->deferred_rules, i);
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
void zclient_rules_make_identity(UT_string *string, uint32_t user_id, const char *login)
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
void zclient_rules_make_bw(UT_string *string, uint64_t bw, zflow_dir_t flow_dir)
{
    // bw.<bw>KBit.<up|down>
    bw = bw * 8 / 1024;
    const char *dir = (DIR_UP == flow_dir) ? STR_UP : STR_DOWN;
    utstring_printf(string, "%s%" PRIu64 "KBit.%s", CLIENT_RULE_BW, bw, dir);
}

/**
 * Make rule "ports".
 * @param[in,out] string Output buffer.
 * @param[in] proto Protocol.
 * @param[in] type Rule type.
 * @param[in] ports Array of ports (network order).
 * @param[in] count Number of elements in ports array.
 */
void zclient_rules_make_ports(UT_string *string, zip_proto_t proto, zfwall_policy_t policy, const uint16_t *ports,
                              size_t count)
{
    // ports.<allow|deny>.<tcp|udp>.<port1>[.<port2>]

    const char *proto_str = PROTO_TCP == proto ? STR_TCP : STR_UDP;
    const char *rule_str = ACCESS_ALLOW == policy ? STR_ALLOW : STR_DENY;

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
void zclient_rules_make_fwd(UT_string *string, zip_proto_t proto, const zfwd_rule_t *fwd_rule)
{
    // forward.<tcp|udp>.<port>.<ip>[:<port>]
    char fwd_ip_str[INET_ADDRSTRLEN];
    const char *proto_str = PROTO_TCP == proto ? STR_TCP : STR_UDP;

    ipv4_to_str(fwd_rule->fwd_ip, fwd_ip_str, sizeof(fwd_ip_str));

    utstring_printf(string, "%s%s.%" PRIu16 ".%s", CLIENT_RULE_FWD, proto_str, ntohs(fwd_rule->port), fwd_ip_str);

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
void zclient_rules_make_speed(UT_string *string, uint64_t speed, zflow_dir_t flow_dir)
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
 * @param[in] ip Session IP address.
 */
void zclient_rules_make_session(UT_string *string, const char *ip)
{
    utstring_printf(string, "%s.%s", STR_SESSION, ip);
}

/**
 * Make deferred rule.
 * @param[in,out] string Output buffer.
 * @param[in] def_rule Deferred rule.
 */
void zclient_rules_make_deferred(UT_string *string, const zcr_deferred_t *def_rule)
{
    zclock_t cur_clock = zclock();
    uint64_t when = (def_rule->when > cur_clock) ? USEC2SEC(def_rule->when - cur_clock) : 0;

    utstring_printf(string, "%s%" PRIu64 ".%s", CLIENT_RULE_DEFERRED, when, def_rule->rule);
}

/**
 * Deferred rule time comparator.
 * @param[in] arg1
 * @param[in] arg2
 * @return Same as strcmp with inversion.
 */
int zcr_deferred_cmp(const void *arg1, const void *arg2)
{
    const zcr_deferred_t *rule1 = *(const zcr_deferred_t **) arg1, *rule2 = *(const zcr_deferred_t **) arg2;

    if (rule1->when > rule2->when) return -1;
    if (rule1->when < rule2->when) return 1;
    return 0;
}

/**
 * Duplicate deferred rule.
 * @param[in] Source deferred rules.
 * @return Duplicate.
 */
zcr_deferred_t *zcr_deferred_dup(const zcr_deferred_t *src)
{
    zcr_deferred_t *dup = malloc(sizeof(*src));

    if (!dup) {
        return NULL;
    }

    dup->when = src->when;
    dup->rule = strdup(src->rule);

    return dup;
}
