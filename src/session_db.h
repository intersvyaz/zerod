#ifndef ZEROD_SESSION_DB_H
#define ZEROD_SESSION_DB_H

#include <pthread.h>
#include <stdint.h>
#include "session.h"

typedef struct zsession_db_struct zsession_db_t;
typedef struct zsession_struct zsession_t;

/**
 * NEW/FREE DATABASE
 */

zsession_db_t *zsession_db_new(void);
void zsession_db_free(zsession_db_t *db);

/**
 * LOCKS
 */

bool zsession_db_partial_rdlock(zsession_db_t *db, uint32_t ip);
bool zsession_db_partial_wrlock(zsession_db_t *db, uint32_t ip);
bool zsession_db_partial_unlock(zsession_db_t *db, uint32_t ip);

/**
 * ADD/REMOVE SESSION
 */

zsession_t *zsession_db_acquire(zsession_db_t *db, uint32_t ip, bool lock);
void zsession_db_insert(zsession_db_t *db, zsession_t *session, bool lock);
void zsession_db_remove(zsession_db_t *db, zsession_t *session);


/**
 * BUCKETS
 */

typedef int (*zsession_db_bucket_cb)(zsession_t *, void *);
size_t zsession_db_get_bucket_count(const zsession_db_t *db);
int zsession_db_bucket_map(zsession_db_t *db, size_t index, zsession_db_bucket_cb callback, void *arg);

/**
 * OTHER
 */

size_t zsession_db_count(const zsession_db_t *db);

#endif // ZEROD_SESSION_DB_H
