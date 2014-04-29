#include "srules.h"

#define SERVER_RULE_UPSTREAM_BW "upstream_bw."
#define SERVER_RULE_NON_CLIENT_BW "non_client_bw."

#define STR_UP "up"
#define STR_DOWN "down"


/**
 * Initialize server rules structure.
 * @param[in] rules
 */
void srules_init(struct zsrules *rules)
{
    bzero(rules, sizeof(*rules));
}

/**
 * Free internally allocated memory.
 * @param[in] rules
 */
void srules_free(struct zsrules *rules)
{
    (void)rules;
}

/**
 * Parse upstream bandwidth rule.
 * @param rules
 * @param str
 * @return
 */
int parse_upstream_bw(struct zsrules *rules, const char *str)
{
    int i = 0;
    uint32_t uidx = 0;
    uint32_t speed = 0;

    while ((NULL != (str = strchr(str, '.'))) && (i < 3)) {
        str++;

        switch (i) {
        case 0: // upstream id
            uidx = strtoul(str, NULL, 10);
            if (uidx >= ZUPSTREAM_MAX) return -1;
            break;

        case 1: // speed
            speed = strtoul(str, NULL, 10);
            break;

        case 2: // direction
            if (0 == strncmp(STR_DOWN, str, sizeof(STR_DOWN) - 1)) {
                rules->upstream_bw[uidx][DIR_DOWN] = speed * 1024 / 8;
                rules->have.upstream_bw[uidx][DIR_DOWN] = 1;
            } else if (0 == strncmp(STR_UP, str, sizeof(STR_UP) - 1)) {
                rules->upstream_bw[uidx][DIR_UP] = speed * 1024 / 8 ;
                rules->have.upstream_bw[uidx][DIR_UP] = 1;
            } else {
                return -1;
            }

            return 0;
        }
        i++;
    }

    return -1;
}

/**
 * Parse non-client bandwidth rule.
 * @param[in,out] rules
 * @param[in] str Rule string.
 * @return Zero on success.
 */
int parse_non_client_bw(struct zsrules *rules, const char *str)
{
    int i = 0;
    uint32_t speed = 0;

    while ((NULL != (str = strchr(str, '.'))) && (i < 3)) {
        str++;

        switch (i) {
        case 0: // speed
            speed = strtoul(str, NULL, 10);
            break;

        case 1: // direction
            if (0 == strncmp(STR_DOWN, str, sizeof(STR_DOWN) - 1)) {
                rules->non_client_bw[DIR_DOWN] = speed * 1024 / 8;
                rules->have.non_client_bw[DIR_DOWN] = 1;
            } else if (0 == strncmp(STR_UP, str, sizeof(STR_UP) - 1)) {
                rules->non_client_bw[DIR_UP] = speed * 1024 / 8 ;
                rules->have.non_client_bw[DIR_UP] = 1;
            } else {
                return -1;
            }

            return 0;
        }
        i++;
    }

    return -1;
}

/**
 * Parse rule.
 * @param[in] rules
 * @param[in] str
 */
int srules_parse(struct zsrules *rules, const char *str)
{
    // upstream_bw.<id>.<speed>Kbit.<up|down>
    if (0 == strncmp(str, SERVER_RULE_UPSTREAM_BW, sizeof(SERVER_RULE_UPSTREAM_BW) - 1))
        return parse_upstream_bw(rules, str);

    // non_client_bw.<speed>Kbit.<up|down>
    if (0 == strncmp(str, SERVER_RULE_NON_CLIENT_BW, sizeof(SERVER_RULE_NON_CLIENT_BW) - 1))
        return parse_non_client_bw(rules, str);

    return -1;
}
