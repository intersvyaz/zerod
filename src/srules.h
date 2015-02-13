#ifndef SRULES_H
#define SRULES_H

#include "zero.h"

struct zsrules {
    struct {
        unsigned upstream_bw[UPSTREAM_MAX][DIR_MAX];
        unsigned non_client_bw[DIR_MAX];
    } have;
    uint32_t upstream_bw[UPSTREAM_MAX][DIR_MAX];
    uint32_t non_client_bw[DIR_MAX];

};

void srules_init(struct zsrules *rules);

void srules_free(struct zsrules *rules);

int srules_parse(struct zsrules *rules, const char *str);

#endif // SRULES_H
