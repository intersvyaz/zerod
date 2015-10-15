#ifndef ZEROD_BLACKLIST_H
#define ZEROD_BLACKLIST_H

#include <stddef.h>

struct zsession;
struct zblacklist;

struct zblacklist *zblacklist_new(void);

void zblacklist_free(struct zblacklist *bl);

int zblacklist_reload(struct zblacklist *bl, const char *file);

int zblacklist_process(struct zblacklist *bl, struct zsession *sess, char *data, size_t len);

#endif // ZEROD_BLACKLIST_H
