#include "router.h"
#include <pthread.h>
#include <netinet/in.h>
#include <uthash/uthash.h>
#include "../util.h"

#define ZNAT_MIN_PORT 1500
#define ZNAT_MAX_PORT 65535
#define ZNAT_ENTRY_TTL 300000000 // in microseconds (=5min)

struct znat_entry {
    struct znat_rule rule;
    // last use time
    uint64_t last_use;
    // hash by rule.origin
    UT_hash_handle hh_origin;
    // hash by nat rule.port
    UT_hash_handle hh_port;
};

struct znat_table {
    // next port used for translation
    uint16_t next_port;

    // hash handle, lookup by origin
    struct znat_entry *tbl_origin;
    // hash handle, lookup by port
    struct znat_entry *tbl_port;
};

struct znat {
    struct znat_table table[PROTO_MAX];
    pthread_spinlock_t lock;
};

/**
 * Create nat.
 * @return
 */
struct znat *znat_create()
{
    struct znat *nat = malloc(sizeof(*nat));
    bzero(nat, sizeof(*nat));
    pthread_spin_init(&nat->lock, PTHREAD_PROCESS_PRIVATE);

    for (int i = 0; i < PROTO_MAX; i++) {
        nat->table[i].next_port = ZNAT_MIN_PORT;
    }

    return nat;
}

/**
 * Destroy nat.
 * @param[in] nat
 */
void znat_destroy(struct znat *nat)
{
    pthread_spin_destroy(&nat->lock);

    for (int i = 0; i < PROTO_MAX; i++) {
        struct znat_entry *entry, *tmp;

        HASH_CLEAR(hh_port, nat->table[i].tbl_port);
        HASH_ITER(hh_origin, nat->table[i].tbl_origin, entry, tmp) {
            HASH_DELETE(hh_origin, nat->table[i].tbl_origin, entry);
            free(entry);
        }
    }
    free(nat);
}

/**
 * Translate port and addr.
 * @param[in] nat
 * @param[in] src
 * @return Translated port in netowrk byte-order.
 */
uint16_t znat_translate(struct znat *nat, enum ipproto proto, const struct znat_origin *origin)
{
    uint16_t nat_port;
    struct znat_entry *entry = NULL;

    pthread_spin_lock(&nat->lock);

    struct znat_table *table = &nat->table[proto];

    HASH_FIND(hh_origin, table->tbl_origin, origin, sizeof(*origin), entry);
    if (NULL == entry) {
        entry = malloc(sizeof(*entry));
        entry->rule.origin = *origin;
        entry->rule.nat_port = htons(table->next_port);
        table->next_port++;
        if (table->next_port >= ZNAT_MAX_PORT) {
            table->next_port = ZNAT_MIN_PORT;
        }

        HASH_ADD(hh_origin, table->tbl_origin, rule.origin, sizeof(entry->rule.origin), entry);
        HASH_ADD(hh_port, table->tbl_port, rule.nat_port, sizeof(entry->rule.nat_port), entry);
    }

    nat_port = entry->rule.nat_port;
    entry->last_use = ztime(false);

    pthread_spin_unlock(&nat->lock);

    return nat_port;
}

/**
 * Lookup nat translation entry.
 * @param[in] nat
 * @param[in] nat_port Port in network byte-order.
 * @param[in,out] src Translation entry.
 * @return Zero on success.
 */
int znat_lookup(struct znat *nat, enum ipproto proto, uint16_t nat_port, struct znat_origin *origin)
{
    int ret = -1;

    pthread_spin_lock(&nat->lock);

    struct znat_entry *entry = NULL;
    HASH_FIND(hh_port, nat->table[proto].tbl_port, &nat_port, sizeof(nat_port), entry);
    if (NULL != entry) {
        entry->last_use = ztime(false);
        *origin = entry->rule.origin;
        ret = 0;
    }

    pthread_spin_unlock(&nat->lock);

    return ret;
}

/**
 * Clean up nat translation table.
 * @param[in] nat
 */
void znat_cleanup(struct znat *nat)
{
    uint64_t curr_time = ztime(false);

    pthread_spin_lock(&nat->lock);

    for(int i = 0; i < PROTO_MAX; i++) {
        struct znat_table *table = &nat->table[i];

        struct znat_entry *entry, *tmp;
        HASH_ITER(hh_port, table->tbl_port, entry, tmp) {
            if ((curr_time - entry->last_use) > ZNAT_ENTRY_TTL) {
                HASH_DELETE(hh_origin, table->tbl_origin, entry);
                HASH_DELETE(hh_port, table->tbl_port, entry);
                free(entry);
            }
        }
    }

    pthread_spin_unlock(&nat->lock);
}
