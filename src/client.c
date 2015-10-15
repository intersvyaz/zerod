#include <stddef.h> // fix annoying bug in clion
#include <assert.h>
#include "client.h"
#include "zero.h"
#include "crules.h"

#define BUCKET_MASK 0b1111u
#define BUCKET_COUNT ((BUCKET_MASK) + 1)
#define BUCKET_IDX(x) ((x) & BUCKET_MASK)
#define BUCKET_GET(db, idx) (&(db)->bucket[(idx)])

struct zclient_db_bucket
{
    // hash (lookup by user_id)
    struct zclient *hash;
    // access lock
    pthread_rwlock_t lock;
};

struct zclient_db
{
    atomic_uint32_t count;
    struct zclient_db_bucket bucket[BUCKET_COUNT];
};

/**
 * Create client database instance.
 * @return New instance.
 */
struct zclient_db *client_db_new(void)
{
    struct zclient_db *db = malloc(sizeof(*db));
    if (unlikely(NULL == db)) {
        return NULL;
    }

    memset(db, 0, sizeof(*db));
    atomic_init(&db->count, 0);

    for (size_t i = 0; i < ARRAYSIZE(db->bucket); i++) {
        struct zclient_db_bucket *bucket = BUCKET_GET(db, i);
        pthread_rwlock_init(&bucket->lock, NULL);
    }

    return db;
}

/**
 * Destroy and free client database instance.
 * @param[in] db Database instance.
 */
void client_db_free(struct zclient_db *db)
{
    for (size_t i = 0; i < ARRAYSIZE(db->bucket); i++) {
        struct zclient_db_bucket *bucket = BUCKET_GET(db, i);
        pthread_rwlock_destroy(&bucket->lock);
        assert(HASH_COUNT(bucket->hash) == 0);
    }
    free(db);
}

/**
 * Find client with id or add client to db.
 * At first we will try to find client with given \a id and put result to \a client.
 * If nothing is found then add \a client to storage.
 * @param[in] db Database.
 * @param[in] id Client id to find.
 * @param[in,out] Client instance.
 */
void client_db_find_or_set_id(struct zclient_db *db, uint32_t id, struct zclient **client)
{
    struct zclient_db_bucket *bucket = BUCKET_GET(db, BUCKET_IDX(id));
    pthread_rwlock_wrlock(&bucket->lock);

    struct zclient *tmp = *client;
    HASH_FIND(hh, bucket->hash, &id, sizeof(id), tmp);
    if (NULL == tmp) {
        (*client)->id = id;
        (*client)->db = db;
        HASH_ADD(hh, bucket->hash, id, sizeof((*client)->id), *client);
        atomic_fetch_add_explicit(&db->count, 1, memory_order_release);
    } else {
        *client = tmp;
    }

    pthread_rwlock_unlock(&bucket->lock);
}

inline uint32_t client_db_get_count(struct zclient_db *db)
{
    return atomic_load_explicit(&db->count, memory_order_acquire);
}

/**
 * Create new client with default values.
 * @return New client instance.
 */
struct zclient *client_create(const struct zcrules *default_rules)
{
    struct zclient *client = malloc(sizeof(*client));
    memset(client, 0, sizeof(*client));
    client->create_time = ztime(false);
    atomic_init(&client->refcnt, 1); // caller references this entry
    atomic_init(&client->last_p2p_throttle, 0);
    pthread_spin_init(&client->lock, PTHREAD_PROCESS_PRIVATE);
    for (int dir = 0; dir < DIR_MAX; dir++) {
        client->band[dir].tokens = zcfg()->initial_client_bucket_size;
        spdm_init(&client->speed[dir]);
    }
    utarray_init(&client->sessions, &ut_ptr_icd);
    utarray_init(&client->deferred_rules, &ut_ptr_icd);

    client_apply_rules(client, default_rules);

    return client;
}

/**
 * Destroy client.
 * @param[in] client
 */
void client_destroy(struct zclient *client)
{
    pthread_spin_destroy(&client->lock);

    if (client->login) free(client->login);
    if (client->firewall) zfwall_destroy(client->firewall);
    if (client->forwarder) zfwd_destroy(client->forwarder);

    for (int dir = 0; dir < DIR_MAX; dir++) {
        token_bucket_destroy(&client->band[dir]);
        spdm_destroy(&client->speed[dir]);
    }

    for (size_t i = 0; i < utarray_len(&client->deferred_rules); i++) {
        struct zrule_deferred *rule = *(struct zrule_deferred **) utarray_eltptr(&client->deferred_rules, i);
        free(rule->rule);
        free(rule);
    }
    utarray_done(&client->deferred_rules);
    utarray_done(&client->sessions);

    free(client);
}

/**
 * Release client.
 * @param[in] client
 */
void client_release(struct zclient *client)
{
    if (1 == atomic_fetch_sub_explicit(&client->refcnt, 1, memory_order_release)) {
        if (0 == client->id) {
            client_destroy(client);
        } else {
            assert(client->db != NULL);
            struct zclient_db_bucket *bucket = BUCKET_GET(client->db, BUCKET_IDX(client->id));
            pthread_rwlock_wrlock(&bucket->lock);
            if (0 == atomic_load_explicit(&client->refcnt, memory_order_acquire)) {
                HASH_DELETE(hh, bucket->hash, client);
                atomic_fetch_sub_explicit(&client->db->count, 1, memory_order_release);
                client_destroy(client);
            }
            pthread_rwlock_unlock(&bucket->lock);
        }
    }
}

/**
 * Acquire client from storage.
 * @param[in] id User id.
 * @return Client instance.
 */
struct zclient *client_acquire(struct zclient_db *db, uint32_t id)
{
    struct zclient *client = NULL;
    struct zclient_db_bucket *bucket = BUCKET_GET(db, BUCKET_IDX(id));

    pthread_rwlock_rdlock(&bucket->lock);
    HASH_FIND(hh, bucket->hash, &id, sizeof(id), client);
    if (NULL != client) {
        atomic_fetch_add_explicit(&client->refcnt, 1, memory_order_relaxed);
    }
    pthread_rwlock_unlock(&bucket->lock);

    return client;
}

/**
 * Add related session to client.
 * @param[in] client Target client.
 * @param[in] sess Related session.
 */
void client_session_add(struct zclient *client, const struct zsession *sess)
{
    pthread_spin_lock(&client->lock);

    utarray_push_back(&client->sessions, &sess);

    pthread_spin_unlock(&client->lock);
}

/**
 * Remove related session.
 * @param[in] client Target client.
 * @param[in] sess Related session.
 */
void client_session_remove(struct zclient *client, const struct zsession *sess)
{
    pthread_spin_lock(&client->lock);

    for (size_t i = 0; i < utarray_len(&client->sessions); i++) {
        const struct zsession *_sess = *(struct zsession **) utarray_eltptr(&client->sessions, i);
        if (_sess == sess) {
            utarray_erase(&client->sessions, i, 1);
        }
    }

    pthread_spin_unlock(&client->lock);
}

/**
 * Get forwarder instance.
 * @param[in] client Target client.
 * @param[in] allocate Allocate if forwarded not created.
 * @return Forwarder instance.
 */
struct zforwarder *client_get_forwarder(struct zclient *client, bool allocate)
{
    struct zforwarder *fwdr;

    pthread_spin_lock(&client->lock);

    if (allocate && (NULL == client->forwarder)) {
        client->forwarder = zfwd_create();
    }
    fwdr = client->forwarder;

    pthread_spin_unlock(&client->lock);

    return fwdr;
}

/**
 * Get firewall instance.
 * @param[in] client Target client.
 * @param[in] allocate Allocate if firewall not created.
 * @return Firewall instance.
 */
struct zfirewall *client_get_firewall(struct zclient *client, bool allocate)
{
    struct zfirewall *fire;

    pthread_spin_lock(&client->lock);

    if (allocate && (NULL == client->firewall)) {
        client->firewall = zfwall_create();
    }
    fire = client->firewall;

    pthread_spin_unlock(&client->lock);

    return fire;
}

/**
 * Apply config to client.
 * @param[in] client
 * @param[in] rules
 */
void client_apply_rules(struct zclient *client, const struct zcrules *rules)
{
    pthread_spin_lock(&client->lock);

    if (rules->have.bw_down) {
        token_bucket_set_max(&client->band[DIR_DOWN], rules->bw_down);
    }
    if (rules->have.bw_up) {
        token_bucket_set_max(&client->band[DIR_UP], rules->bw_up);
    }

    if (rules->have.p2p_policy) {
        client->p2p_policy = rules->p2p_policy;
    }

    if (rules->have.login) {
        if (client->login) free(client->login);
        client->login = strdup(rules->login);
    }

    if (rules->have.rmdeferred) {
        while (utarray_len(&client->deferred_rules)) {
            struct zrule_deferred *def_rule = *(struct zrule_deferred **) utarray_back(&client->deferred_rules);
            free(def_rule);
            utarray_pop_back(&client->deferred_rules);
        }
    }

    if (rules->have.deferred_rules) {
        uint64_t curr_clock = zclock(false);
        for (size_t i = 0; i < utarray_len(&rules->deferred_rules); i++) {
            struct zrule_deferred *def_rule = *(struct zrule_deferred **) utarray_eltptr(&rules->deferred_rules, i);
            def_rule = zrule_deferred_dup(def_rule);
            def_rule->when = curr_clock + SEC2USEC(def_rule->when);
            utarray_push_back(&client->deferred_rules, &def_rule);
        }
        utarray_sort(&client->deferred_rules, zrule_deferred_cmp);
    }

    pthread_spin_unlock(&client->lock);

    if (rules->have.port_rules) {
        struct zfirewall *fwall = client_get_firewall(client, true);
        for (size_t i = 0; i < utarray_len(&rules->port_rules); i++) {
            struct zrule_port *rule = *(struct zrule_port **) utarray_eltptr(&rules->port_rules, i);
            if (rule->add) {
                zfwall_add_rule(fwall, rule->proto, rule->type, rule->port);
            } else {
                zfwall_del_rule(fwall, rule->proto, rule->type, rule->port);
            }
        }
    }

    if (rules->have.fwd_rules) {
        struct zforwarder *fwdr = client_get_forwarder(client, true);
        for (size_t i = 0; i < utarray_len(&rules->fwd_rules); i++) {
            struct zrule_fwd *rule = *(struct zrule_fwd **) utarray_eltptr(&rules->fwd_rules, i);
            if (rule->add) {
                zfwd_add_rule(fwdr, rule->proto, rule->port, rule->fwd_ip, rule->fwd_port);
            } else {
                zfwd_del_rule(fwdr, rule->proto, rule->port);
            }
        }
    }
}

/**
 * Dump client rules.
 * @param[in] client Target client.
 * @param[in] rules Buffer.
 */
void client_dump_rules(struct zclient *client, UT_string *rules)
{
    pthread_spin_lock(&client->lock);

    crules_make_identity(rules, client->id, client->login);
    utstring_bincpy(rules, "\0", 1);

    for (int dir = 0; dir < DIR_MAX; dir++) {
        uint64_t bw = token_bucket_get_max(&client->band[dir]);
        crules_make_bw(rules, bw, dir);
        utstring_bincpy(rules, "\0", 1);
    }

    crules_make_p2p_policy(rules, client->p2p_policy);
    utstring_bincpy(rules, "\0", 1);

    for (size_t i = 0; i < utarray_len(&client->sessions); i++) {
        struct zsession *sess = *(struct zsession **) utarray_eltptr(&client->sessions, i);
        crules_make_session(rules, sess);
        utstring_bincpy(rules, "\0", 1);
    }

    for (size_t i = 0; i < utarray_len(&client->deferred_rules); i++) {
        struct zrule_deferred *deff = *(struct zrule_deferred **) utarray_eltptr(&client->deferred_rules, i);
        crules_make_deferred(rules, deff);
        utstring_bincpy(rules, "\0", 1);
    }

    pthread_spin_unlock(&client->lock);

    struct zfirewall *fire = client_get_firewall(client, false);
    if (fire) {
        for (size_t proto = 0; proto < PROTO_MAX; proto++) {
            for (size_t type = 0; type < PORT_MAX; type++) {
                uint16_t *ports;
                size_t count;
                zfwall_dump_ports(fire, proto, type, &ports, &count);
                if (count) {
                    crules_make_ports(rules, proto, type, ports, count);
                    utstring_bincpy(rules, "\0", 1);
                    free(ports);
                }
            }
        }
    }

    struct zforwarder *fwdr = client_get_forwarder(client, false);
    if (fwdr) {
        for (size_t proto = 0; proto < PROTO_MAX; proto++) {
            struct zfwd_rule *fwd_rules;
            size_t count;
            zfwd_dump_rules(fwdr, proto, &fwd_rules, &count);
            if (count) {
                for (size_t i = 0; i < count; i++) {
                    crules_make_fwd(rules, proto, &fwd_rules[i]);
                    utstring_bincpy(rules, "\0", 1);
                }
                free(fwd_rules);
            }
        }
    }

    for (int dir = 0; dir < DIR_MAX; dir++) {
        uint64_t speed = spdm_calc(&client->speed[dir]);
        crules_make_speed(rules, speed * 8, dir);
        utstring_bincpy(rules, "\0", 1);
    }

    uint64_t diff = zclock(false) - atomic_load_explicit(&client->last_p2p_throttle, memory_order_acquire);
    if (diff < P2P_THROTTLE_TIME) {
        utstring_printf(rules, "p2p_throttling_active");
        utstring_bincpy(rules, "\0", 1);
    }
}
