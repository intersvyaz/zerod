#ifndef ZEROD_SCOPE_RULES_H
#define ZEROD_SCOPE_RULES_H

#include <stdbool.h>

typedef struct
{
    struct
    {
        unsigned dhcp_snooping;
        unsigned arp_protection;
        unsigned ip_protection;
    } have;
    bool dhcp_snooping;
    bool arp_protection;
    bool ip_protection;
} zscope_rules_t;

void zscope_rules_init(zscope_rules_t *rules);

void zscope_rules_destroy(zscope_rules_t *rules);

int zscope_rules_parse(zscope_rules_t *rules, const char *str);

#endif // ZEROD_SCOPE_RULES_H
