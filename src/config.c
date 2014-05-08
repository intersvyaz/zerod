#include "zero.h"

#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <math.h>
#include <limits.h>
#include <ctype.h>

#include <libconfig.h>

#include "log.h"
#include "util.h"

#define ZCFG_DEFAULT_PATH "zerod.conf"

#define ZCFG_INTERFACES                  "interfaces"
#define ZCFG_IFACE_WAIT_TIME             "iface_wait_time"
#define ZCFG_OVERLORD_THREADS            "overlord_threads"
#define ZCFG_UNAUTH_BW_LIMIT_DOWN        "unauth_bw_limit_down"
#define ZCFG_UNAUTH_BW_LIMIT_UP          "unauth_bw_limit_up"
#define ZCFG_IP_WHITELIST                "ip_whitelist"
#define ZCFG_RADIUS_CONFIG_FILE          "radius_config_file"
#define ZCFG_RADIUS_NAS_IDENTIFIER       "radius_nas_identifier"
#define ZCFG_SESSION_TIMEOUT             "session_timeout"
#define ZCFG_SESSION_ACCT_INTERVAL       "session_accounting_interval"
#define ZCFG_SESSION_AUTH_INTERVAL       "session_auth_interval"
#define ZCFG_RC_LISTEN_ADDR              "rc_listen_addr"
#define ZCFG_UPSTREAM_P2P_BW_DOWN        "upstream_p2p_bw_down"
#define ZCFG_UPSTREAM_P2P_BW_UP          "upstream_p2p_bw_up"
#define ZCFG_P2P_PORTS_WHITELIST         "p2p_ports_whitelist"
#define ZCFG_P2P_PORTS_BLACKLIST         "p2p_ports_blacklist"
#define ZCFG_NON_CLIENT_BW_DOWN          "non_client_bw_down"
#define ZCFG_NON_CLIENT_BW_UP            "non_client_bw_up"
#define ZCFG_INITIAL_CLIENT_BUCKET_SIZE  "initial_client_bucket_size"

#define ZCFG_LAN        "lan"
#define ZCFG_WAN        "wan"
#define ZCFG_AFFINITY   "affinity"

/**
 * Load uint16 array from config.
 * @param[in] cfg Configuration option.
 * @param[in] option Option name.
 * @param[in,out] array Resulting array.
 * @return Zero on success.
 */
static int load_uint16_list(const config_setting_t *cfg, const char *option, UT_array *array)
{
    config_setting_t *cfg_list = config_setting_get_member(cfg, option);

    if (!cfg_list) {
        ZERO_LOG(LOG_ERR, "config: missing %s entry", option);
        return 0;
    }

    if (config_setting_type(cfg_list) != CONFIG_TYPE_LIST) {
        ZERO_LOG(LOG_ERR, "config: invalid %s entry", option);
        return -1;
    }

    int count = config_setting_length(cfg_list);

    if (0 >= count) {
        return 0;
    }

    utarray_init(array, &ut_uint16_icd);

    for (int i = 0; i < count; i++) {
        int entry = config_setting_get_int_elem(cfg_list, i);

        if (!entry) {
            ZERO_LOG(LOG_ERR, "config: failed to get next %s record", option);
            continue;
        }

        if (entry < UINT16_MAX) {
            uint16_t port = entry;
            utarray_push_back(array, &port);
            continue;
        }

        // if we here, then entry is invalid
        ZERO_LOG(LOG_ERR, "config: invalid %s item: %d", option, entry);
        utarray_done(array);
        return -1;
    }

    utarray_sort(array, uint16_cmp);

    return 0;
}

/**
 * Load ip-mask array.
 * @param[in] cfg Config section.
 * @param[in] option Option name.
 * @param[in,out] array Resulting array.
 * @return Zero on success.
 */
static int load_ip_mask_list(const config_setting_t *cfg, const char *option, UT_array *array)
{
    config_setting_t *cfg_list = config_setting_get_member(cfg, option);

    if (!cfg_list) {
        ZERO_LOG(LOG_ERR, "config: missing %s entry", option);
        return 0;
    }

    if (config_setting_type(cfg_list) != CONFIG_TYPE_LIST) {
        ZERO_LOG(LOG_ERR, "config: invalid %s entry", option);
        return -1;
    }

    int count = config_setting_length(cfg_list);

    if (0 >= count) {
        return 0;
    }

    utarray_init(array, &ut_ip_range_icd);

    for (int i = 0; i < count; i++) {
        struct ip_range range;
        const char *entry = config_setting_get_string_elem(cfg_list, i);

        if (!entry) {
            ZERO_LOG(LOG_ERR, "config: failed to get next %s record", option);
            continue;
        }

        char ip_str[INET_ADDRSTRLEN];
        const char *cidr_pos = strchr(entry, '/');

        // we search for CIDR, and make sure, that ip part is not bigger than allowed size
        if (cidr_pos && ((size_t)(cidr_pos - entry) < sizeof(ip_str))) {
            strncpy(ip_str, entry, cidr_pos - entry);
            ip_str[cidr_pos - entry] = '\0';

            struct in_addr ip_addr;
            if (0 < inet_pton(AF_INET, ip_str, &ip_addr)) {
                u_long cidr = strtoul(cidr_pos + 1, NULL, 10);
                if (cidr != ULONG_MAX && cidr <= 32) {
                    range.ip_start = ntohl(ip_addr.s_addr);
                    range.ip_end = IP_RANGE_END(range.ip_start, cidr);
                    utarray_push_back(array, &range);
                    continue;
                }
            }
        }

        // if we here, then entry is invalid
        ZERO_LOG(LOG_ERR, "config: invalid %s item: %s", option, entry);
        utarray_done(array);
        return -1;
    }

    utarray_sort(array, ip_range_cmp);

    return 0;
}

/**
 * Load required string value from config.
 * @param[in] cfg Config section.
 * @param[in] opt Option name.
 * @param[out] val Value pointer.
 * @return Zero on success.
 */
static int load_string_req(const config_setting_t *cfg, const char *opt, char **val)
{
    const char *str_val;
    if (config_setting_lookup_string(cfg, opt, &str_val)) {
        *val = strdup(str_val);
        return 0;
    } else {
        ZERO_LOG(LOG_ERR, "config: '%s' missing", opt);
        return -1;
    }
}

/**
 * Load required int value from config.
 * @param[in] cfg Config section.
 * @param[in] opt Option name.
 * @param[out] val Value pointer.
 * @return Zero on success.
 */
static int load_int_req(const config_setting_t *cfg, const char *opt, int *val)
{
    int int_val;
    if (config_setting_lookup_int(cfg, opt, &int_val)) {
        *val = int_val;
        return 0;
    } else {
        ZERO_LOG(LOG_ERR, "config: '%s' missing", opt);
        return -1;
    }
}

/**
 * Load required unsigned int value from config.
 * @param[in] cfg Config section.
 * @param[in] opt Option name.
 * @param[out] val Value pointer.
 * @return Zero on success.
 */
static int load_uint_req(const config_setting_t *cfg, const char *opt, u_int *val)
{
    int int_val;

    if (!load_int_req(cfg, opt, &int_val)) {
        if (int_val < 0) {
            ZERO_LOG(LOG_ERR, "config: '%s' must be greater than zero", opt);
        } else {
            *val = (u_int)int_val;
            return 0;
        }
    }

    return -1;
}

/**
 * Load required int value from config.
 * @param[in] cfg Config section.
 * @param[in] opt Option name.
 * @param[out] val Value pointer.
 * @return Zero on success.
 */
static int load_int64_req(const config_setting_t *cfg, const char *opt, int64_t *val)
{
    long long int int64_val;
    if (config_setting_lookup_int64(cfg, opt, &int64_val)) {
        *val = int64_val;
        return 0;
    } else {
        ZERO_LOG(LOG_ERR, "config: '%s' missing", opt);
        return -1;
    }
}

/**
 * Load required unsigned int value from config.
 * @param[in] cfg Config section.
 * @param[in] opt Option name.
 * @param[out] val Value pointer.
 * @return Zero on success.
 */
static int load_uint64_req(const config_setting_t *cfg, const char *opt, uint64_t *val)
{
    int64_t int64_val;

    if (!load_int64_req(cfg, opt, &int64_val)) {
        if (int64_val < 0) {
            ZERO_LOG(LOG_ERR, "config: '%s' must be greater than zero", opt);
        } else {
            *val = (u_int)int64_val;
            return 0;
        }
    }

    return -1;
}

/**
 * Load size with SI prefix.
 * @param cfg Config section.
 * @param opt Option name.
 * @param val Value pointer.
 * @param base Value base (e.g. 1000, 1024, etc.).
 * @return Zero on success.
 */
static int load_kmgt(const config_setting_t *cfg, const char *opt, uint64_t *val, u_int base)
{
    const char *str_val;
    if (config_setting_lookup_string(cfg, opt, &str_val)) {
        *val = strtoul(str_val, NULL, 10);
        char prefix = str_val[strlen(str_val)-1];
        if (!isdigit(prefix)) {
            switch (str_val[strlen(str_val)-1]) {
            // no prefix
            case 0:
                break;
            // tera
            case 'T':
            case 't':
                *val *= base;
            // giga
            case 'G':
            case 'g':
                *val *= base;
            // mega
            case 'M':
            case 'm':
                *val *= base;
            // kilo
            case 'K':
            case 'k':
                *val *= base;
                break;
            default:
                ZERO_LOG(LOG_ERR, "config: '%s' invalid value", opt);
                return -1;
            }
        }

        return 0;
    } else {
        ZERO_LOG(LOG_ERR, "config: '%s' missing", opt);
        return -1;
    }
}

/**
   Load interfaces section.
 * @param[in] cfg Config section.
 * @param[in] option Option name.
 * @param[in,out] array Resulting array.
 * @return Zero on success.
 */
int load_interfaces(const config_setting_t *cfg, const char *option, UT_array *array)
{
    config_setting_t *cfg_list = config_setting_get_member(cfg, option);

    if (!cfg_list) {
        ZERO_LOG(LOG_ERR, "config: missing %s entry", option);
        return -1;
    }

    if (config_setting_type(cfg_list) != CONFIG_TYPE_LIST) {
        ZERO_LOG(LOG_ERR, "config: invalid %s entry", option);
        return -1;
    }

    int count = config_setting_length(cfg_list);

    if (0 >= count) {
        ZERO_LOG(LOG_ERR, "config: empty %s entry", option);
        return -1;
    }

    utarray_init(array, &ut_zif_pair_icd);

    for (int i = 0; i < count; i++) {
        struct zif_pair if_pair;
        const char *str;
        config_setting_t *entry = config_setting_get_elem(cfg_list, i);

        if (NULL == entry) {
            ZERO_LOG(LOG_ERR, "config: failed to read %u-th group of %s entry", i, option);
            goto fail;
        }

        if (!config_setting_lookup_string(entry, ZCFG_LAN, &str)) {
            ZERO_LOG(LOG_ERR, "config: failed to read '%s' property of %u-th group of %s entry", ZCFG_LAN, i, option);
            goto fail;
        }
        strncpy(if_pair.lan, str, sizeof(if_pair.lan));

        if (!config_setting_lookup_string(entry, ZCFG_WAN, &str)) {
            ZERO_LOG(LOG_ERR, "config: failed to read '%s' property of %u-th group of %s entry", ZCFG_WAN, i, option);
            goto fail;
        }
        strncpy(if_pair.wan, str, sizeof(if_pair.wan));

        int affinity = 0;
        if (!config_setting_lookup_int(entry, ZCFG_AFFINITY, &affinity)) {
            ZERO_LOG(LOG_ERR, "config: failed to read '%s' property of %u-th group of %s entry", ZCFG_AFFINITY, i, option);
            goto fail;
        }
        if ((affinity < 0) || affinity >= UINT16_MAX) {
            ZERO_LOG(LOG_ERR, "config: invalid value in '%s' property of %u-th group of %s entry", ZCFG_AFFINITY, i, option);
            goto fail;
        }
        if_pair.affinity = (uint16_t)affinity;

        utarray_push_back(array, &if_pair);
    }

    return 0;

fail:
    utarray_done(array);
    return -1;
}

/**
 * Load configuration file.
 * @param[in] path Location of configuration file.
 * @param[in,out] zconf Loaded options will be stored here.
 * @return Zero on success.
 */
int zero_config_load(const char *path, struct zero_config *zconf)
{
    int ret = 0;
    config_t config;
    config_init(&config);

    if (NULL == path) {
        path = ZCFG_DEFAULT_PATH;
    }

     if (config_read_file(&config, path)) {
        const config_setting_t *root = config_root_setting(&config);

        ret = ret
            || load_interfaces(root, ZCFG_INTERFACES, &zconf->interfaces)
            || load_uint_req(root, ZCFG_IFACE_WAIT_TIME, &zconf->iface_wait_time)
            || load_uint_req(root, ZCFG_OVERLORD_THREADS, &zconf->overlord_threads)
            || load_kmgt(root, ZCFG_UNAUTH_BW_LIMIT_DOWN, &zconf->unauth_bw_limit[DIR_DOWN], 1024)
            || load_kmgt(root, ZCFG_UNAUTH_BW_LIMIT_UP, &zconf->unauth_bw_limit[DIR_UP], 1024)
            || load_string_req(root, ZCFG_RADIUS_CONFIG_FILE, &zconf->radius_config_file)
            || load_string_req(root, ZCFG_RADIUS_NAS_IDENTIFIER, &zconf->radius_nas_identifier)
            || load_uint64_req(root, ZCFG_SESSION_TIMEOUT, &zconf->session_timeout)
            || load_uint64_req(root, ZCFG_SESSION_ACCT_INTERVAL, &zconf->session_acct_interval)
            || load_uint64_req(root, ZCFG_SESSION_AUTH_INTERVAL, &zconf->session_auth_interval)
            || load_string_req(root, ZCFG_RC_LISTEN_ADDR, &zconf->rc_listen_addr)
            || load_kmgt(root, ZCFG_UPSTREAM_P2P_BW_DOWN, &zconf->upstream_p2p_bw[DIR_DOWN], 1024)
            || load_kmgt(root, ZCFG_UPSTREAM_P2P_BW_UP, &zconf->upstream_p2p_bw[DIR_UP], 1024)
            || load_ip_mask_list(root, ZCFG_IP_WHITELIST, &zconf->ip_whitelist)
            || load_uint16_list(root, ZCFG_P2P_PORTS_WHITELIST, &zconf->p2p_ports_whitelist)
            || load_uint16_list(root, ZCFG_P2P_PORTS_BLACKLIST, &zconf->p2p_ports_blacklist)
            || load_kmgt(root, ZCFG_NON_CLIENT_BW_DOWN, &zconf->non_client_bw[DIR_DOWN], 1024)
            || load_kmgt(root, ZCFG_NON_CLIENT_BW_UP, &zconf->non_client_bw[DIR_UP], 1024)
            || load_kmgt(root, ZCFG_INITIAL_CLIENT_BUCKET_SIZE, &zconf->initial_client_bucket_size, 1024)
        ;

        // convert from bits to bytes
        zconf->unauth_bw_limit[DIR_DOWN] /= 8;
        zconf->unauth_bw_limit[DIR_UP] /= 8;
        zconf->upstream_p2p_bw[DIR_DOWN] /= 8;
        zconf->upstream_p2p_bw[DIR_UP] /= 8;
        zconf->non_client_bw[DIR_DOWN] /= 8;
        zconf->non_client_bw[DIR_UP] /= 8;

        // convert from seconds to microseconds
        zconf->session_timeout *= 1000000;
        zconf->session_acct_interval *= 1000000;
        zconf->session_auth_interval *= 1000000;
    } else {
        ZERO_LOG(LOG_ERR, "config: failed to parse %s (error:%s at %d line)", path, config_error_text(&config), config_error_line(&config));
        ret = -1;
    }

    config_destroy(&config);

    return ret;
}

/**
 * Free internally allocated memory in config.
 * @param[in] zconf
 */
void zero_config_free(struct zero_config *zconf)
{
    if (zconf->radius_config_file) free(zconf->radius_config_file);
    if (zconf->radius_nas_identifier) free(zconf->radius_nas_identifier);
    if (zconf->rc_listen_addr) free(zconf->rc_listen_addr);
    utarray_done(&zconf->ip_whitelist);
    utarray_done(&zconf->interfaces);
}

