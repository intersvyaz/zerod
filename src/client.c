#include "client.h"

#include "zero.h"
#include "log.h"
#include "router/router.h"
#include "crules.h"

/**
* Create new client with default values.
* @return New client instance.
*/
struct zclient *client_create(void)
{
    struct zclient *client = malloc(sizeof(*client));
    bzero(client, sizeof(*client));
    client->create_time = ztime(false);
    atomic_init(&client->refcnt, 1); // caller references this entry
    atomic_init(&client->last_p2p_throttle, 0);
    pthread_spin_init(&client->lock, PTHREAD_PROCESS_PRIVATE);
    for (int dir = 0; dir < DIR_MAX; dir++) {
        token_bucket_init(&client->bw_bucket[dir], zcfg()->unauth_bw_limit[dir]);
        client->bw_bucket[dir].tokens = zcfg()->initial_client_bucket_size;
        spdm_init(&client->speed[dir]);
    }
    utarray_init(&client->sessions, &ut_ptr_icd);
    utarray_init(&client->deferred_rules, &ut_ptr_icd);

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
        token_bucket_destroy(&client->bw_bucket[dir]);
        spdm_destroy(&client->speed[dir]);
    }

    for (size_t i = 0; i < utarray_len(&client->deferred_rules); i++) {
        struct zrule_deferred *rule = *(struct zrule_deferred **) utarray_eltptr(&client->deferred_rules, i);
        free(rule->rule);
        free(rule);
    }
    utarray_done(&client->deferred_rules);

    free(client);
}

/**
* Release client.
* @param[in] client
*/
void client_release(struct zclient *client)
{
    if (1 == atomic_fetch_sub_explicit(&client->refcnt, 1, memory_order_relaxed)) {
        if (0 == client->id) {
            client_destroy(client);
        } else {
            size_t sidx = STORAGE_IDX(client->id);
            pthread_rwlock_wrlock(&zinst()->clients_lock[sidx]);
            if (0 == atomic_load_explicit(&client->refcnt, memory_order_relaxed)) {
                HASH_DELETE(hh, zinst()->clients[sidx], client);
                client_destroy(client);
            }
            pthread_rwlock_unlock(&zinst()->clients_lock[sidx]);
            atomic_fetch_sub_explicit(&zinst()->clients_cnt, 1, memory_order_relaxed);
        }
    }
}

/**
* Acquire client from storage.
* @param[in] id User id.
* @return
*/
struct zclient *client_acquire(uint32_t id)
{
    struct zclient *client = NULL;
    size_t sidx = STORAGE_IDX(id);

    pthread_rwlock_rdlock(&zinst()->clients_lock[sidx]);
    HASH_FIND(hh, zinst()->clients[sidx], &id, sizeof(id), client);
    if (NULL != client) {
        atomic_fetch_add_explicit(&client->refcnt, 1, memory_order_relaxed);
    }
    pthread_rwlock_unlock(&zinst()->clients_lock[sidx]);

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
* @param sess Related session.
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
* @param[in] allocate Allocate if forwared not created.
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
void client_apply_rules(struct zclient *client, struct zcrules *rules)
{
    pthread_spin_lock(&client->lock);

    if (rules->have.bw_down) {
        atomic_store_explicit(&client->bw_bucket[DIR_DOWN].max_tokens, rules->bw_down, memory_order_relaxed);
    }
    if (rules->have.bw_up) {
        atomic_store_explicit(&client->bw_bucket[DIR_UP].max_tokens, rules->bw_up, memory_order_relaxed);
    }
    if (rules->have.p2p_policer) client->p2p_policer = rules->p2p_policer;

    if (rules->have.login) {
        if (client->login) free(client->login);
        client->login = rules->login;
        rules->login = NULL;
    }

    if (rules->have.deferred_rules) {
        uint64_t curr_clock = zclock(false);
        struct zrule_deferred *def_rule = NULL;
        while (utarray_back(&rules->deferred_rules)) {
            def_rule = *(struct zrule_deferred **) utarray_back(&rules->deferred_rules);
            def_rule->when = curr_clock + def_rule->when * 1000000;
            utarray_push_back(&client->deferred_rules, &def_rule);
            utarray_pop_back(&rules->deferred_rules);
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
        uint32_t speed = atomic_load_explicit(&client->bw_bucket[dir].max_tokens, memory_order_relaxed);
        crules_make_bw(rules, speed, dir);
        utstring_bincpy(rules, "\0", 1);
    }

    crules_make_p2p_policer(rules, client->p2p_policer);
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

    if (zclock(false) - atomic_load_explicit(&client->last_p2p_throttle, memory_order_acquire) < P2P_THROTTLE_TIME) {
        utstring_printf(rules, "p2p_throttling_active");
        utstring_bincpy(rules, "\0", 1);
    }
}
