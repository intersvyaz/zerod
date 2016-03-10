#include <pthread.h>
#include <netinet/in.h>
#include <uthash/uthash.h>
#include "nat.h"
#include "util.h"

#define ZNAT_MIN_PORT 1500u
#define ZNAT_MAX_PORT UINT16_MAX // 65535

typedef struct znat_entry_struct
{
    znat_rule_t rule;
    // last use time
    zclock_t last_use;
    // hash by rule.origin
    UT_hash_handle hh_origin;
    // hash by nat rule.port
    UT_hash_handle hh_port;
} znat_entry_t;

typedef struct znat_table_struct
{
    // next port used for translation
    uint16_t next_port;
    // hash handle, lookup by origin
    znat_entry_t *tbl_origin;
    // hash handle, lookup by port
    znat_entry_t *tbl_port;
} znat_table_t;

struct znat_struct
{
    /*<<! nat table for each protocol */
    znat_table_t table[PROTO_MAX];
    /*<<! trandlation entry ttl (microseconds) */
    uint64_t entry_ttl;
    /*<<! access lock */
    pthread_spinlock_t lock;
};

/**
 * Create nat.
 * @param[in] entry_ttl Translation entry ttl.
 * @return New instance.
 */
znat_t *znat_new(uint64_t entry_ttl)
{
    znat_t *nat = malloc(sizeof(*nat));

    if (unlikely(NULL == nat)) {
        return NULL;
    }

    memset(nat, 0, sizeof(*nat));
    if (unlikely(0 != pthread_spin_init(&nat->lock, PTHREAD_PROCESS_PRIVATE))) {
        goto err;
    }

    for (int i = 0; i < PROTO_MAX; i++) {
        nat->table[i].next_port = ZNAT_MIN_PORT;
    }

    nat->entry_ttl = entry_ttl;

    return nat;

    err:
    free(nat);
    return NULL;
}

/**
 * Destroy nat.
 * @param[in] nat
 */
void znat_free(znat_t *nat)
{
    pthread_spin_destroy(&nat->lock);

    for (int i = 0; i < PROTO_MAX; i++) {
        znat_entry_t *entry, *tmp;

        HASH_CLEAR(hh_port, nat->table[i].tbl_port);
        HASH_ITER(hh_origin, nat->table[i].tbl_origin, entry, tmp) {
            HASH_DELETE(hh_origin, nat->table[i].tbl_origin, entry);
            free(entry);
        }
    }

    free(nat);
}

/**
 * Translate port and address.
 * @param[in] nat NAT handle.
 * @param[in] proto
 * @param[in] origin
 * @return Translated port in network byte-order.
 */
uint16_t znat_translate(znat_t *nat, zip_proto_t proto, const znat_origin_t *origin)
{
    uint16_t nat_port;
    znat_entry_t *entry = NULL;

    pthread_spin_lock(&nat->lock);

    znat_table_t *table = &nat->table[proto];

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
    entry->last_use = zclock();

    pthread_spin_unlock(&nat->lock);

    return nat_port;
}

/**
 * Lookup nat translation entry.
 * @param[in] nat
 * @param[in] nat_port Port in network byte-order.
 * @param[in,out] origin Translation entry.
 * @return Zero on success.
 */
bool znat_lookup(znat_t *nat, zip_proto_t proto, uint16_t nat_port, znat_origin_t *origin)
{
    znat_entry_t *entry = NULL;
    bool ok = false;

    pthread_spin_lock(&nat->lock);

    HASH_FIND(hh_port, nat->table[proto].tbl_port, &nat_port, sizeof(nat_port), entry);
    if (NULL != entry) {
        entry->last_use = zclock();
        *origin = entry->rule.origin;
        ok = true;
    }

    pthread_spin_unlock(&nat->lock);

    return ok;
}

/**
 * Clean up nat translation table.
 * @param[in] nat NAT instance.
 */
void znat_cleanup(znat_t *nat)
{
    zclock_t now = zclock();

    pthread_spin_lock(&nat->lock);

    for (int i = 0; i < PROTO_MAX; i++) {
        znat_table_t *table = &nat->table[i];

        znat_entry_t *entry, *tmp;
        HASH_ITER(hh_port, table->tbl_port, entry, tmp) {
            if ((now - entry->last_use) > nat->entry_ttl) {
                HASH_DELETE(hh_origin, table->tbl_origin, entry);
                HASH_DELETE(hh_port, table->tbl_port, entry);
                free(entry);
            }
        }
    }

    pthread_spin_unlock(&nat->lock);
}
