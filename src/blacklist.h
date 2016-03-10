#ifndef ZEROD_BLACKLIST_H
#define ZEROD_BLACKLIST_H

#include <stddef.h>
#include <stdbool.h>

/**
 * Typedefs.
 */
typedef struct zblacklist zblacklist_t;

/**
 * Blacklist declarations.
 */
zblacklist_t *zblacklist_new(void);

void zblacklist_free(zblacklist_t *bl);

bool zblacklist_reload(zblacklist_t *bl, const char *file);

bool zblacklist_check(zblacklist_t *bl, const char *data, size_t data_len);

#endif // ZEROD_BLACKLIST_H
