#ifndef ZEROD_SRULES_H
#define ZEROD_SRULES_H

#include "zero.h"

struct zsrules
{
    struct
    {
        unsigned upstream_bandwidth[UPSTREAM_COUNT][DIR_MAX];
        unsigned non_client_bandwidth[DIR_MAX];
        unsigned arp_inspection;
    } have;
    uint32_t upstream_bandwidth[UPSTREAM_COUNT][DIR_MAX];
    uint32_t non_client_bandwidth[DIR_MAX];
    uint8_t arp_inspection;

};

void srules_init(struct zsrules *rules);

void srules_free(struct zsrules *rules);

int srules_parse(struct zsrules *rules, const char *str);

#endif // ZEROD_SRULES_H
