#include "scope_rules.h"
#include <assert.h>
#include <string.h>
#include "util.h"

/**
 * Initialize scope rules structure.
 * @param[in] rules
 */
void zscope_rules_init(zscope_rules_t *rules)
{
    memset(rules, 0, sizeof(*rules));
}

/**
 * Free internally allocated memory.
 * @param[in] rules
 */
void zscope_rules_destroy(zscope_rules_t *rules)
{
    (void) rules;
}

/**
 * Parse scope rule.
 * @param[in,out] rules
 * @param[in] str Rule string.
 */
int zscope_rules_parse(zscope_rules_t *rules, const char *str)
{
    (void) rules;
    (void) str;

    return -1;
}
