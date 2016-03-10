#include <stddef.h>
#include <ctype.h>
#include <limits.h>
#include <arpa/inet.h>

#include <libconfig.h>
#include <uthash/uthash.h>

#include "log.h"
#include "config.h"
#include "util_string.h"

#define ZCFG_SECTION_GLOBAL "global"

#define ZCFG_GLOBAL_INTERFACES                  "interfaces"
#define ZCFG_GLOBAL_IFACE_WAIT_TIME             "interfaces_wait_time"
#define ZCFG_GLOBAL_OVERLORD_THREADS            "overlord_threads"
#define ZCFG_GLOBAL_REMOTECTL_LISTEN            "remote_control_listen"
#define ZCFG_GLOBAL_MONITORS_TOTAL_BW           "monitors_total_bandwidth"
#define ZCFG_GLOBAL_MONITORS_CONN_BW            "monitors_connection_bandwidth"
#define ZCFG_GLOBAL_NON_CLIENT_BW_DOWN          "non_client_bandwidth_down"
#define ZCFG_GLOBAL_NON_CLIENT_BW_UP            "non_client_bandwidth_up"
#define ZCFG_GLOBAL_SW_LLDP_PASS_IN             "lldp_pass_in"
#define ZCFG_GLOBAL_SW_LLDP_PASS_OUT            "lldp_pass_out"
#define ZCFG_GLOBAL_ENABLE_COREDUMP             "enable_coredump"

#define ZCFG_SCOPE_SUBNETS_CLIENT               "subnets_client"
#define ZCFG_SCOPE_SUBNETS_LOCAL                "subnets_local"
#define ZCFG_SCOPE_SUBNETS_LOCAL_EXCLUDE        "subnets_local_exclude"
#define ZCFG_SCOPE_DEFAULT_CLIENT_RULES         "default_client_rules"
#define ZCFG_SCOPE_RADIUS_AUTH                  "radius_auth"
#define ZCFG_SCOPE_RADIUS_ACCT                  "radius_accounting"
#define ZCFG_SCOPE_RADIUS_CONFIG                "radius_config"
#define ZCFG_SCOPE_RADIUS_NAS_ID                "radius_nas_identifier"
#define ZCFG_SCOPE_SESSION_ACCT_INTERVAL        "session_accounting_interval"
#define ZCFG_SCOPE_SESSION_AUTH_INTERVAL        "session_authentication_interval"
#define ZCFG_SCOPE_SESSION_TIMEOUT              "session_timeout"
#define ZCFG_SCOPE_SESSION_IDLE_TIMEOUT         "session_idle_timeout"
#define ZCFG_SCOPE_PORTS_WHITELIST              "ports_whitelist"
#define ZCFG_SCOPE_DHCP_SNOOPING                "dhcp_snooping"
#define ZCFG_SCOPE_DHCP_DEFAULT_LEASE_TIME      "dhcp_default_lease_time"
#define ZCFG_SCOPE_DYNAMIC_ARP_PROTECTION       "dynamic_arp_protection"
#define ZCFG_SCOPE_IP_VERIFY_SOURCE             "ip_verify_source"
#define ZCFG_SCOPE_BLACKLIST_ENABLED            "blacklist_enabled"
#define ZCFG_SCOPE_BLACKLIST_FILE               "blacklist_file"
#define ZCFG_SCOPE_BLACKLIST_RELOAD_INTERVAL    "blacklist_reload_interval"

#define ZCFG_LAN        "lan"
#define ZCFG_WAN        "wan"
#define ZCFG_AFFINITY   "affinity"

#define CIDR_MAX 32

const UT_icd ut_zif_pair_icd _UNUSED_ = {sizeof(zifpair_t), NULL, NULL, NULL};

/**
 * Load client rules list.
 * @param[in] option Configuration option.
 * @param[in,out] rules Resulting rules.
 * @return <0 - error. 0 - success. >0 - not found.
 */
static int zcfg_load_client_rules(const config_setting_t *option, zclient_rules_t *rules)
{
    zclient_rules_init(rules);

    if (!option) {
        return 1;
    }

    if (CONFIG_TYPE_LIST != option->type) {
        return -1;
    }

    int count = config_setting_length(option);

    zclient_rule_parser_t *rule_parser = zclient_rule_parser_new();

    for (int i = 0; i < count; i++) {
        const char *str = config_setting_get_string_elem(option, i);
        if (!zclient_rule_parse(rule_parser, rules, str)) {
            ZLOG(LOG_ERR, "config:%s:%s: invalid client rule: %s", option->parent->name, option->name, str);
            zclient_rule_parser_free(rule_parser);
            return -1;
        }
    }

    zclient_rule_parser_free(rule_parser);
    return 0;
}

/**
 * Load uint16 array.
 * @param[in] option Configuration option.
 * @param[in,out] array Resulting array.
 * @return <0 - error. 0 - success. >0 - not found.
 */
static int zcfg_load_uint16_array(const config_setting_t *option, UT_array *array)
{
    utarray_init(array, &ut_uint16_icd);

    if (!option) {
        return 1;
    }

    if (CONFIG_TYPE_ARRAY != option->type) {
        return -1;
    }

    int count = config_setting_length(option);

    for (int i = 0; i < count; i++) {
        int item = config_setting_get_int_elem(option, i);

        if ((item < 0) || (item > UINT16_MAX)) {
            ZLOG(LOG_ERR, "config:%s:%s: invalid port: %d", option->parent->name, option->name, item);
            utarray_done(array);
            return -1;
        }

        uint16_t port = (uint16_t) item;
        utarray_push_back(array, &port);
    }

    if (utarray_len(array)) {
        utarray_sort(array, uint16_cmp);
    }

    return 0;
}

/**
 * Load subnet array.
 * @param[in] cfg Config section.
 * @param[in] option Option name.
 * @param[in,out] array Resulting array.
 * @return <0 - error. 0 - success. >0 - not found.
 */
static int zcfg_load_subnet_list(const config_setting_t *option, zsubnet_group_t *array)
{
    utarray_init(array, &ut_ip_range_icd);

    if (!option) {
        return 1;
    }

    if (CONFIG_TYPE_LIST != option->type) {
        return -1;
    }

    int count = config_setting_length(option);

    for (int i = 0; i < count; i++) {
        ip_range_t range;
        char ip_str[INET_ADDRSTRLEN];
        const char *item = config_setting_get_string_elem(option, i);
        const char *cidr_pos = strchr(item, '/');

        // search CIDR, and make sure, that ip part is not bigger than buffer size
        if (cidr_pos && (((size_t) (cidr_pos - item) < sizeof(ip_str)))) {
            strncpy(ip_str, item, cidr_pos - item);
            ip_str[cidr_pos - item] = '\0';

            struct in_addr ip_addr;
            if (0 < inet_pton(AF_INET, ip_str, &ip_addr)) {
                uint8_t cidr = 0;
                if ((0 == str_to_u8(cidr_pos + 1, &cidr)) && (cidr <= CIDR_MAX)) {
                    range.ip_start = ntohl(ip_addr.s_addr);
                    range.ip_end = IP_RANGE_END(range.ip_start, cidr);
                    utarray_push_back(array, &range);
                    continue;
                }
            }
        }

        // error handler
        ZLOG(LOG_ERR, "config:%s:%s: invalid subnet: %s", option->parent->name, option->name, item);
        utarray_done(array);
        return -1;
    }

    if (count) {
        utarray_sort(array, ip_range_cmp);
    }

    return 0;
}

/**
 * Load string value from config.
 * @param[in] section Config section.
 * @param[in] option Option name.
 * @param[out] pvalue Value pointer.
 * @return <0 - error. 0 - success. >0 - not found.
 */
static int zcfg_load_string(const config_setting_t *option, char **pvalue)
{
    *pvalue = NULL;

    if (!option) {
        return 1;
    }

    if (CONFIG_TYPE_STRING != option->type) {
        return -1;
    }

    const char *str_val = config_setting_get_string(option);
    if (NULL == str_val) {
        return -1;
    }

    *pvalue = strdup(str_val);

    return 0;
}

/**
 * Load boolean value from config.
 * @param[in] section Config section.
 * @param[in] option Option name.
 * @param[out] pvalue Value pointer.
 * @return <0 - error. 0 - success. >0 - not found.
 */
static int zcfg_load_bool(const config_setting_t *option, bool *pvalue)
{
    *pvalue = false;

    if (!option) {
        return 1;
    }

    if (CONFIG_TYPE_BOOL != option->type) {
        return -1;
    }

    *pvalue = (bool) config_setting_get_bool(option);

    return 0;
}

/**
 * Load int from config.
 * @param[in] option Option name.
 * @param[out] value Value pointer.
 * @return <0 - error. 0 - success. >0 - not found.
 */
static int zcfg_load_int(const config_setting_t *option, int *value)
{
    *value = 0;

    if (!option) {
        return 1;
    }

    if (CONFIG_TYPE_INT != option->type) {
        return -1;
    }

    *value = config_setting_get_int(option);

    return 0;
}

/**
 * Load unsigned int from config.
 * @param[in] option Option name.
 * @param[out] value Value pointer.
 * @return <0 - error. 0 - success. >0 - not found.
 */
static int zcfg_load_uint(const config_setting_t *option, u_int *value)
{
    *value = 0u;

    if (!option) {
        return 1;
    }

    if ((CONFIG_TYPE_INT != option->type) && (CONFIG_TYPE_INT64 != option->type)) {
        return -1;
    }

    int64_t tmp = config_setting_get_int64(option);

    if ((UINT_MAX < tmp) || (0 > tmp)) {
        return -1;
    }

    *value = (u_int) tmp;

    return 0;
}

#if 0
/**
 * Load int64 from config.
 * @param[in] option Option name.
 * @param[out] value Value pointer.
 * @return <0 - error. 0 - success. >0 - not found.
 */
static int zcfg_load_int64(const config_setting_t *option, int64_t *value)
{
    *value = 0;

    if (!option) {
        return 1;
    }

    if (CONFIG_TYPE_INT64 != option->type) {
        return -1;
    }

    *value = config_setting_get_int64(option);

    return 0;
}
#endif

/**
 * Load size with SI prefix.
 * @param opt Option name.
 * @param val Value pointer.
 * @param base Value base (e.g. 1000, 1024, etc.).
 * @return <0 - error. 0 - success. >0 - not found.
 */
static int zcfg_load_kmgt(const config_setting_t *option, uint64_t *val, uint64_t base)
{
    *val = 0ull;

    if (!option) {
        return 1;
    }

    if ((CONFIG_TYPE_INT == option->type) || (CONFIG_TYPE_INT64 == option->type)) {
        int64_t ival64 = config_setting_get_int64(option);
        if (ival64 < 0) {
            return -1;
        }
        return 0;
    } else if (CONFIG_TYPE_STRING == option->type) {
        const char *str = config_setting_get_string(option);
        if (0 != str_to_u64(str, val)) {
            return -1;
        }
        char prefix = str[strlen(str) - 1];
        *val *= str_parse_si_unit(prefix, base);
        return 0;
    }

    return -1;
}

/**
 * Load interfaces section.
 * @param[in] option Option name.
 * @param[in,out] array Resulting array.
 * @return <0 - error. 0 - success. >0 - not found.
 */
int zcfg_load_interfaces(const config_setting_t *option, UT_array *array)
{
    utarray_init(array, &ut_zif_pair_icd);

    if (!option) {
        return 1;
    }

    if (CONFIG_TYPE_LIST != option->type) {
        return -1;
    }

    u_int count = (u_int) config_setting_length(option);

    for (u_int i = 0; i < count; i++) {
        zifpair_t if_pair;
        const char *str;
        config_setting_t *entry = config_setting_get_elem(option, i);

        if (!config_setting_lookup_string(entry, ZCFG_LAN, &str)) {
            ZLOG(LOG_ERR, "config:%s:%s: invalid or missing 'lan' property", option->parent->name, option->name);
            goto fail;
        }
        strncpy(if_pair.lan, str, sizeof(if_pair.lan));

        if (!config_setting_lookup_string(entry, ZCFG_WAN, &str)) {
            ZLOG(LOG_ERR, "config:%s:%s: invalid or missing 'wan' property", option->parent->name, option->name);
            goto fail;
        }
        strncpy(if_pair.wan, str, sizeof(if_pair.wan));

        int affinity = 0;
        if (!config_setting_lookup_int(entry, ZCFG_AFFINITY, &affinity)) {
            ZLOG(LOG_ERR, "config:%s:%s: invalid or missing 'affinity' property", option->parent->name, option->name);
            goto fail;
        }
        if ((affinity < 0) || affinity >= UINT16_MAX) {
            ZLOG(LOG_ERR, "config:%s:%s: invalid 'affinity' value", option->parent->name, option->name);
            goto fail;
        }
        if_pair.affinity = (uint16_t) affinity;

        utarray_push_back(array, &if_pair);
    }

    return 0;

    fail:
    utarray_done(array);
    return -1;
}

/**
 * @param[in] section Config section.
 * @param[in,out] scope Config scope.
 */
int zconfig_scope_load(const config_setting_t *section, zconfig_scope_t *scope)
{
    u_int uival = 0;
    const config_setting_t *option = NULL;

    memset(scope, 0, sizeof(*scope));

    scope->name = strdup(section->name);

    option = config_setting_get_member(section, ZCFG_SCOPE_DEFAULT_CLIENT_RULES);
    if (0 != zcfg_load_client_rules(option, &scope->default_client_rules)) {
        ZLOG(LOG_ERR, "config:%s: failed to load %s option", scope->name, ZCFG_SCOPE_DEFAULT_CLIENT_RULES);
        return -1;
    }

    option = config_setting_get_member(section, ZCFG_SCOPE_RADIUS_AUTH);
    if (0 != zcfg_load_bool(option, &scope->radius.auth)) {
        ZLOG(LOG_ERR, "config:%s: failed to load %s option", scope->name, ZCFG_SCOPE_RADIUS_AUTH);
        return -1;
    }

    if (scope->radius.auth) {
        option = config_setting_get_member(section, ZCFG_SCOPE_RADIUS_ACCT);
        if (0 != zcfg_load_bool(option, &scope->radius.acct)) {
            ZLOG(LOG_ERR, "config:%s: failed to load %s option", scope->name, ZCFG_SCOPE_RADIUS_ACCT);
            return -1;
        }

        option = config_setting_get_member(section, ZCFG_SCOPE_RADIUS_CONFIG);
        if (0 != zcfg_load_string(option, &scope->radius.config)) {
            ZLOG(LOG_ERR, "config:%s: failed to load %s option", scope->name, ZCFG_SCOPE_RADIUS_CONFIG);
            return -1;
        }

        option = config_setting_get_member(section, ZCFG_SCOPE_RADIUS_NAS_ID);
        if (0 != zcfg_load_string(option, &scope->radius.nas_id)) {
            ZLOG(LOG_ERR, "config:%s: failed to load %s option", scope->name, ZCFG_SCOPE_RADIUS_NAS_ID);
            return -1;
        }
    }

    option = config_setting_get_member(section, ZCFG_SCOPE_SESSION_ACCT_INTERVAL);
    if (0 != zcfg_load_uint(option, &uival)) {
        ZLOG(LOG_ERR, "config:%s: failed to load %s option", scope->name, ZCFG_SCOPE_SESSION_ACCT_INTERVAL);
        return -1;
    } else {
        scope->session.acct_interval = SEC2USEC(uival);
    }

    option = config_setting_get_member(section, ZCFG_SCOPE_SESSION_AUTH_INTERVAL);
    if (0 != zcfg_load_uint(option, &uival)) {
        ZLOG(LOG_ERR, "config:%s: failed to load %s option", scope->name, ZCFG_SCOPE_SESSION_AUTH_INTERVAL);
        return -1;
    } else {
        scope->session.auth_interval = SEC2USEC(uival);
    }

    option = config_setting_get_member(section, ZCFG_SCOPE_SESSION_TIMEOUT);
    if (0 != zcfg_load_uint(option, &uival)) {
        ZLOG(LOG_ERR, "config:%s: failed to load %s option", scope->name, ZCFG_SCOPE_SESSION_TIMEOUT);
        return -1;
    } else {
        scope->session.timeout = SEC2USEC(uival);
    }

    option = config_setting_get_member(section, ZCFG_SCOPE_SESSION_IDLE_TIMEOUT);
    if (0 != zcfg_load_uint(option, &uival)) {
        ZLOG(LOG_ERR, "config:%s: failed to load %s option", scope->name, ZCFG_SCOPE_SESSION_IDLE_TIMEOUT);
        return -1;
    } else {
        scope->session.idle_timeout = SEC2USEC(uival);
    }

    option = config_setting_get_member(section, ZCFG_SCOPE_SUBNETS_CLIENT);
    if (0 != zcfg_load_subnet_list(option, &scope->client_subnets)) {
        ZLOG(LOG_ERR, "config:%s: failed to load %s option", scope->name, ZCFG_SCOPE_SUBNETS_CLIENT);
        return -1;
    }

    option = config_setting_get_member(section, ZCFG_SCOPE_SUBNETS_LOCAL);
    if (0 != zcfg_load_subnet_list(option, &scope->local_subnets)) {
        ZLOG(LOG_ERR, "config:%s: failed to load %s option", scope->name, ZCFG_SCOPE_SUBNETS_LOCAL);
        return -1;
    }

    option = config_setting_get_member(section, ZCFG_SCOPE_SUBNETS_LOCAL_EXCLUDE);
    if (0 != zcfg_load_subnet_list(option, &scope->local_subnets_exclusions)) {
        ZLOG(LOG_ERR, "config:%s: failed to load %s option", scope->name, ZCFG_SCOPE_SUBNETS_LOCAL_EXCLUDE);
        return -1;
    }

    option = config_setting_get_member(section, ZCFG_SCOPE_PORTS_WHITELIST);
    if (0 != zcfg_load_uint16_array(option, &scope->ports_whitelist)) {
        ZLOG(LOG_ERR, "config:%s: failed to load %s option", scope->name, ZCFG_SCOPE_PORTS_WHITELIST);
        return -1;
    }

    option = config_setting_get_member(section, ZCFG_SCOPE_DHCP_SNOOPING);
    if (0 != zcfg_load_bool(option, &scope->security.dhcp_snooping)) {
        ZLOG(LOG_ERR, "config:%s: failed to load %s option", scope->name, ZCFG_SCOPE_DHCP_SNOOPING);
        return -1;
    }

    option = config_setting_get_member(section, ZCFG_SCOPE_DHCP_DEFAULT_LEASE_TIME);
    if (0 != zcfg_load_uint(option, &uival)) {
        ZLOG(LOG_ERR, "config:%s: failed to load %s option", scope->name, ZCFG_SCOPE_DHCP_DEFAULT_LEASE_TIME);
        return -1;
    } else {
        scope->security.dhcp_default_lease_time = SEC2USEC(uival);
    }

    if (scope->security.dhcp_snooping) {
        option = config_setting_get_member(section, ZCFG_SCOPE_DYNAMIC_ARP_PROTECTION);
        if (0 != zcfg_load_bool(option, &scope->security.arp_protect)) {
            ZLOG(LOG_ERR, "config:%s: failed to load %s option", scope->name, ZCFG_SCOPE_DYNAMIC_ARP_PROTECTION);
            return -1;
        }

        option = config_setting_get_member(section, ZCFG_SCOPE_IP_VERIFY_SOURCE);
        if (0 != zcfg_load_bool(option, &scope->security.ip_protect)) {
            ZLOG(LOG_ERR, "config:%s: failed to load %s option", scope->name, ZCFG_SCOPE_IP_VERIFY_SOURCE);
            return -1;
        }
    }

    option = config_setting_get_member(section, ZCFG_SCOPE_BLACKLIST_ENABLED);
    if (0 != zcfg_load_bool(option, &scope->blacklist.enabled)) {
        ZLOG(LOG_ERR, "config:%s: failed to load %s option", scope->name, ZCFG_SCOPE_BLACKLIST_ENABLED);
        return -1;
    }

    if (scope->blacklist.enabled) {
        option = config_setting_get_member(section, ZCFG_SCOPE_BLACKLIST_FILE);
        if (0 != zcfg_load_string(option, &scope->blacklist.file)) {
            ZLOG(LOG_ERR, "config:%s: failed to load %s option", scope->name, ZCFG_SCOPE_BLACKLIST_FILE);
            return -1;
        }

        option = config_setting_get_member(section, ZCFG_SCOPE_BLACKLIST_RELOAD_INTERVAL);
        if (0 != zcfg_load_uint(option, &uival)) {
            ZLOG(LOG_ERR, "config:%s: failed to load %s option", scope->name, ZCFG_SCOPE_BLACKLIST_RELOAD_INTERVAL);
            return -1;
        } else {
            scope->blacklist.reload_interval = SEC2USEC(uival);
        }
    }

    return 0;
}

/**
 * @return Zero on success.
 */
int zconfig_global_load(const config_setting_t *section, zconfig_t *conf)
{
    config_setting_t *option = NULL;

    option = config_setting_get_member(section, ZCFG_GLOBAL_INTERFACES);
    if (0 != zcfg_load_interfaces(option, &conf->interfaces)) {
        ZLOG(LOG_ERR, "config:%s: invalid or missing %s option", section->name, ZCFG_GLOBAL_INTERFACES);
        return -1;
    }

    option = config_setting_get_member(section, ZCFG_GLOBAL_IFACE_WAIT_TIME);
    if (0 != zcfg_load_uint(option, &conf->iface_wait_time)) {
        ZLOG(LOG_ERR, "config:%s: invalid or missing %s option", section->name, ZCFG_GLOBAL_IFACE_WAIT_TIME);
        return -1;
    }

    option = config_setting_get_member(section, ZCFG_GLOBAL_OVERLORD_THREADS);
    if (0 != zcfg_load_uint(option, &conf->overlord_threads)) {
        ZLOG(LOG_ERR, "config:%s: invalid or missing %s option", section->name, ZCFG_GLOBAL_OVERLORD_THREADS);
        return -1;
    }

    option = config_setting_get_member(section, ZCFG_GLOBAL_REMOTECTL_LISTEN);
    if (0 != zcfg_load_string(option, &conf->remotectl_listen)) {
        ZLOG(LOG_ERR, "config:%s: invalid or missing %s option", section->name, ZCFG_GLOBAL_REMOTECTL_LISTEN);
        return -1;
    }

    option = config_setting_get_member(section, ZCFG_GLOBAL_MONITORS_TOTAL_BW);
    if (0 != zcfg_load_kmgt(option, &conf->monitor.total_bandwidth, 1024)) {
        ZLOG(LOG_ERR, "config:%s: invalid or missing %s option", section->name, ZCFG_GLOBAL_MONITORS_TOTAL_BW);
        return -1;
    } else {
        // convert from bits to bytes
        conf->monitor.total_bandwidth /= 8;
    }

    option = config_setting_get_member(section, ZCFG_GLOBAL_MONITORS_CONN_BW);
    if (0 != zcfg_load_kmgt(option, &conf->monitor.conn_bandwidth, 1024)) {
        ZLOG(LOG_ERR, "config:%s: invalid or missing %s option", section->name, ZCFG_GLOBAL_MONITORS_CONN_BW);
        return -1;
    } else {
        // convert from bits to bytes
        conf->monitor.conn_bandwidth /= 8;
    }

    option = config_setting_get_member(section, ZCFG_GLOBAL_NON_CLIENT_BW_DOWN);
    if (0 != zcfg_load_kmgt(option, &conf->non_client_bandwidth[DIR_DOWN], 1024)) {
        ZLOG(LOG_ERR, "config:%s: failed to load %s option", section->name, ZCFG_GLOBAL_NON_CLIENT_BW_DOWN);
        return -1;
    } else {
        conf->non_client_bandwidth[DIR_DOWN] /= 8;
    }

    option = config_setting_get_member(section, ZCFG_GLOBAL_NON_CLIENT_BW_UP);
    if (0 != zcfg_load_kmgt(option, &conf->non_client_bandwidth[DIR_UP], 1024)) {
        ZLOG(LOG_ERR, "config:%s: failed to load %s option", section->name, ZCFG_GLOBAL_NON_CLIENT_BW_UP);
        return -1;
    } else {
        conf->non_client_bandwidth[DIR_UP] /= 8;
    }

    option = config_setting_get_member(section, ZCFG_GLOBAL_SW_LLDP_PASS_IN);
    if (0 != zcfg_load_bool(option, &conf->sw.lldp_pass_in)) {
        ZLOG(LOG_ERR, "config:%s: failed to load %s option", section->name, ZCFG_GLOBAL_SW_LLDP_PASS_IN);
        return -1;
    }

    option = config_setting_get_member(section, ZCFG_GLOBAL_SW_LLDP_PASS_OUT);
    if (0 != zcfg_load_bool(option, &conf->sw.lldp_pass_out)) {
        ZLOG(LOG_ERR, "config:%s: failed to load %s option", section->name, ZCFG_GLOBAL_SW_LLDP_PASS_OUT);
        return -1;
    }

    option = config_setting_get_member(section, ZCFG_GLOBAL_ENABLE_COREDUMP);
    if (0 != zcfg_load_bool(option, &conf->enable_coredump)) {
        ZLOG(LOG_ERR, "config:%s: invalid or missing %s option", ZCFG_SECTION_GLOBAL, ZCFG_GLOBAL_ENABLE_COREDUMP);
        return -1;
    }

    return 0;
}

/**
 *
 */
void zconfig_scope_destroy(zconfig_scope_t *scope)
{
    if (scope->name) free(scope->name);
    if (scope->radius.config) free(scope->radius.config);
    if (scope->radius.nas_id) free(scope->radius.nas_id);
    if (scope->blacklist.file) free(scope->blacklist.file);

    utarray_done(&scope->ports_whitelist);
    utarray_done(&scope->client_subnets);
    utarray_done(&scope->local_subnets);
    utarray_done(&scope->local_subnets_exclusions);
    zclient_rules_destroy(&scope->default_client_rules);
}

/**
 * @param[in] root Root section of config.
 * @param[in] zconf Config handle.
 * @return True on success.
 */
bool zconfig_load_sections(const config_setting_t *root, zconfig_t *zconf)
{
    // global section
    config_setting_t *section = config_setting_get_member(root, ZCFG_SECTION_GLOBAL);
    if (!section) {
        ZLOG(LOG_ERR, "config: %s section not found", ZCFG_SECTION_GLOBAL);
        return false;
    }
    if (0 != zconfig_global_load(section, zconf)) {
        ZLOG(LOG_ERR, "config: failed to load %s section", ZCFG_SECTION_GLOBAL);
        return false;
    }

    // all other sections parse as scopes
    u_int sections_count = (u_int) config_setting_length(root);

    // global section + minimum one scope section
    if (sections_count < 2) {
        ZLOG(LOG_ERR, "config: no scopes found");
        return false;
    }

    utarray_init(&zconf->scopes, &ut_ptr_icd);
    for (u_int i = 0; i < sections_count; i++) {
        section = config_setting_get_elem(root, i);

        if (!config_setting_is_group(section)) {
            continue;
        }
        if (0 == strcmp(section->name, ZCFG_SECTION_GLOBAL)) {
            continue;
        }

        for (size_t j = 0; j < utarray_len(&zconf->scopes); j++) {
            zconfig_scope_t *sc = *(zconfig_scope_t **) utarray_eltptr(&zconf->scopes, j);
            if (0 == strcasecmp(sc->name, section->name)) {
                ZLOG(LOG_ERR, "config: duplicate scope %s", section->name);
                return false;
            }
        }

        zconfig_scope_t *scope = malloc(sizeof(*scope));
        if (0 == zconfig_scope_load(section, scope)) {
            utarray_push_back(&zconf->scopes, &scope);
            ZLOG(LOG_DEBUG, "config: loaded scope %s", scope->name);
        } else {
            zconfig_scope_destroy(scope);
            free(scope);
            ZLOG(LOG_ERR, "config: failed to load scope %s", section->name);
            return false;
        }
    }

    return true;
}

/**
 * Free internally allocated memory in config.
 * @param[in] zconf
 */
void zconfig_destroy(zconfig_t *zconf)
{
    utarray_done(&zconf->interfaces);
    if (zconf->remotectl_listen) free(zconf->remotectl_listen);

    for (size_t i = 0; i < utarray_len(&zconf->scopes); i++) {
        zconfig_scope_t *scope = *(zconfig_scope_t **) utarray_eltptr(&zconf->scopes, i);
        zconfig_scope_destroy(scope);
        free(scope);
    }
    utarray_done(&zconf->scopes);
}

/**
 * Load configuration file.
 * @param[in] path Configuration file location.
 * @param[in,out] zconf Parsed configuration storage.
 * @return True on success.
 */
bool zconfig_load(const char *path, zconfig_t *zconf)
{
    if (NULL == path) {
        ZLOG(LOG_ERR, "config: configuration file not specified");
        return false;
    }

    bool loaded = false;
    config_t config;
    config_init(&config);

    if (!config_read_file(&config, path)) {
        ZLOG(LOG_ERR, "config: failed to parse %s (error: %s at %d line)",
             path, config_error_text(&config), config_error_line(&config));
        goto end;
    }

    const config_setting_t *root = config_root_setting(&config);

    if (!zconfig_load_sections(root, zconf)) {
        zconfig_destroy(zconf);
    } else {
        loaded = true;
    }

    end:
    config_destroy(&config);

    return loaded;
}

bool zsubnet_group_ip_belongs(const zsubnet_group_t *group, uint32_t ip)
{
    if (!utarray_len(group)) {
        return false;
    }

    ip_range_t ipr_dummy;
    ipr_dummy.ip_start = ipr_dummy.ip_end = ip;
    const struct ip_range *ipr_search = utarray_find(group, &ipr_dummy, ip_range_cmp);
    return (ipr_search != NULL);
}
