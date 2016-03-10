#ifndef ZEROD_CLIENT_DB_H
#define ZEROD_CLIENT_DB_H

#include <stdint.h>
#include "client.h"

/**
 * Typedefs.
 */
typedef struct zclient_db_struct zclient_db_t;

/**
 * NEW/FREE DATABASE
 */

zclient_db_t *zclient_db_new(void);
void zclient_db_free(zclient_db_t *db);

/**
 * LOCKS
 */

bool zclient_db_partial_rdlock(zclient_db_t *db, uint32_t id);
bool zclient_db_partial_wrlock(zclient_db_t *db, uint32_t id);
bool zclient_db_partial_unlock(zclient_db_t *db, uint32_t id);

/**
 * ADD/REMOVE CLIENT
 */
zclient_t *zclient_db_acquire(zclient_db_t *db, uint32_t id, bool lock);
void zclient_db_insert(zclient_db_t *db, zclient_t *client, bool lock);
void zclient_db_remove(zclient_db_t *db, zclient_t *client, bool lock);

/**
 * OTHER
 */

size_t zclient_db_count(const zclient_db_t *db);

#endif // ZEROD_CLIENT_DB_H
