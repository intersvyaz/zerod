#include <stddef.h> // fix annoying bug in clion
#include "client.h"
#include "session.h"
#include "zero.h"
#include "log.h"

/**
 * Create new client with default values.
 * @return New client instance.
 */
zclient_t *zclient_new(const zclient_rules_t *default_rules)
{
    zclient_t *client = malloc(sizeof(*client));
    if (unlikely(NULL == client)) {
        return NULL;
    }

    memset(client, 0, sizeof(*client));

    if (0 != pthread_spin_init(&client->lock, PTHREAD_PROCESS_PRIVATE)) {
        free(client);
        return NULL;
    }

    atomic_init(&client->refcnt, 1); // caller reference
    utarray_init(&client->sessions, &ut_uint32_icd);
    utarray_init(&client->deferred_rules, &ut_ptr_icd);
    client->create_time = ztime();

    for (int dir = 0; dir < DIR_MAX; dir++) {
        token_bucket_init(&client->band[dir], 0);
        spdm_init(&client->speed[dir]);
    }

    zclient_apply_rules(client, default_rules);

    return client;
}

/**
 * Destroy client.
 * @param[in] client
 */
void zclient_free(zclient_t *client)
{
    pthread_spin_destroy(&client->lock);

    if (likely(client->login)) free(client->login);
    if (client->firewall) zfwall_free(client->firewall);
    if (client->forwarder) zfwd_free(client->forwarder);

    for (int dir = 0; dir < DIR_MAX; dir++) {
        token_bucket_destroy(&client->band[dir]);
        spdm_destroy(&client->speed[dir]);
    }

    for (size_t i = 0; i < utarray_len(&client->deferred_rules); i++) {
        zcr_deferred_t *rule = *(zcr_deferred_t **) utarray_eltptr(&client->deferred_rules, i);
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
void zclient_release(zclient_t *client)
{
    if (1 == atomic_fetch_sub_release(&client->refcnt, 1)) {
        zclient_free(client);
    }
}

/**
 * Add related session to client.
 * @param[in] client Target client.
 * @param[in] ip IP address (host order).
 */
void zclient_session_add(zclient_t *client, uint32_t ip)
{
    pthread_spin_lock(&client->lock);

    utarray_push_back(&client->sessions, &ip);

    pthread_spin_unlock(&client->lock);
}

/**
 * Remove related session.
 * @param[in] client Target client.
 * @param[in] ip IP address (host order).
 */
void zclient_session_remove(zclient_t *client, uint32_t ip)
{
    pthread_spin_lock(&client->lock);

    for (size_t i = 0; i < utarray_len(&client->sessions); i++) {
        uint32_t _ip = *(uint32_t *) utarray_eltptr(&client->sessions, i);
        if (_ip == ip) {
            utarray_erase(&client->sessions, i, 1);
            break;
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
zforwarder_t *zclient_forwarder(zclient_t *client, bool allocate)
{
    zforwarder_t *fwdr;

    pthread_spin_lock(&client->lock);

    if (allocate && (NULL == client->forwarder)) {
        client->forwarder = zfwd_new();
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
zfirewall_t *zclient_firewall(zclient_t *client, bool allocate)
{
    zfirewall_t *fwall;

    pthread_spin_lock(&client->lock);

    if (allocate && (NULL == client->firewall)) {
        client->firewall = zfwall_new();
    }
    fwall = client->firewall;

    pthread_spin_unlock(&client->lock);

    return fwall;
}

/**
 * Apply config to client.
 * @param[in] client
 * @param[in] rules
 */
void zclient_apply_rules(zclient_t *client, const zclient_rules_t *rules)
{
    pthread_spin_lock(&client->lock);

    if (rules->have.bw_down) {
        token_bucket_set_capacity(&client->band[DIR_DOWN], rules->bw_down);
    }
    if (rules->have.bw_up) {
        token_bucket_set_capacity(&client->band[DIR_UP], rules->bw_up);
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
        for (size_t i = 0; i < utarray_len(&rules->deferred_rules); i++) {
            zcr_deferred_t *def_rule = *(zcr_deferred_t **) utarray_eltptr(&rules->deferred_rules, i);
            def_rule = zcr_deferred_dup(def_rule);
            def_rule->when = zclock() + SEC2USEC(def_rule->when);
            utarray_push_back(&client->deferred_rules, &def_rule);
        }
        utarray_sort(&client->deferred_rules, zcr_deferred_cmp);
    }

    pthread_spin_unlock(&client->lock);

    if (rules->have.port_rules) {
        zfirewall_t *fwall = zclient_firewall(client, true);
        for (size_t i = 0; i < utarray_len(&rules->port_rules); i++) {
            zcr_port_t *rule = *(zcr_port_t **) utarray_eltptr(&rules->port_rules, i);
            if (rule->add) {
                zfwall_add_rule(fwall, rule->proto, rule->policy, rule->port);
            } else {
                zfwall_del_rule(fwall, rule->proto, rule->policy, rule->port);
            }
        }
    }

    if (rules->have.fwd_rules) {
        zforwarder_t *fwdr = zclient_forwarder(client, true);
        for (size_t i = 0; i < utarray_len(&rules->fwd_rules); i++) {
            zcr_forward_t *rule = *(zcr_forward_t **) utarray_eltptr(&rules->fwd_rules, i);
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
void zclient_dump_rules(zclient_t *client, UT_string *rules)
{
    pthread_spin_lock(&client->lock);

    zclient_rules_make_identity(rules, client->id, client->login);
    utstring_bincpy(rules, "\0", 1);

    for (int dir = 0; dir < DIR_MAX; dir++) {
        uint64_t bw = token_bucket_capacity(&client->band[dir]);
        zclient_rules_make_bw(rules, bw, dir);
        utstring_bincpy(rules, "\0", 1);
    }

    for (size_t i = 0; i < utarray_len(&client->sessions); i++) {
        uint32_t ip = *(uint32_t *) utarray_eltptr(&client->sessions, i);
        char ip_str[INET_ADDRSTRLEN];
        ipv4_to_str(htonl(ip), ip_str, sizeof(ip_str));
        zclient_rules_make_session(rules, ip_str);
        utstring_bincpy(rules, "\0", 1);
    }

    for (size_t i = 0; i < utarray_len(&client->deferred_rules); i++) {
        zcr_deferred_t *deff = *(zcr_deferred_t **) utarray_eltptr(&client->deferred_rules, i);
        zclient_rules_make_deferred(rules, deff);
        utstring_bincpy(rules, "\0", 1);
    }

    pthread_spin_unlock(&client->lock);

    zfirewall_t *wall = zclient_firewall(client, false);
    if (wall) {
        for (size_t proto = 0; proto < PROTO_MAX; proto++) {
            for (size_t policy = 0; policy < ACCESS_MAX; policy++) {
                uint16_t *ports;
                size_t count;
                zfwall_dump_ports(wall, proto, policy, &ports, &count);
                if (count) {
                    zclient_rules_make_ports(rules, proto, policy, ports, count);
                    utstring_bincpy(rules, "\0", 1);
                    free(ports);
                }
            }
        }
    }

    zforwarder_t *fwdr = zclient_forwarder(client, false);
    if (fwdr) {
        for (int proto = 0; proto < PROTO_MAX; proto++) {
            zfwd_rule_t *fwd_rules;
            size_t count;
            zfwd_dump_rules(fwdr, proto, &fwd_rules, &count);
            if (count) {
                for (size_t i = 0; i < count; i++) {
                    zclient_rules_make_fwd(rules, proto, &fwd_rules[i]);
                    utstring_bincpy(rules, "\0", 1);
                }
                free(fwd_rules);
            }
        }
    }

    for (int dir = 0; dir < DIR_MAX; dir++) {
        uint64_t speed = spdm_calc(&client->speed[dir]);
        zclient_rules_make_speed(rules, speed * 8, dir);
        utstring_bincpy(rules, "\0", 1);
    }
}

/**
 *
 */
void zclient_apply_deferred_rules(zclient_t *client)
{
    if (utarray_len(&client->deferred_rules)) {
        zclient_rules_t parsed_rules;
        zclient_rules_init(&parsed_rules);

        pthread_spin_lock(&client->lock);

        while (utarray_back(&client->deferred_rules)) {
            zcr_deferred_t *rule = *(zcr_deferred_t **) utarray_back(&client->deferred_rules);

            if (rule->when >= zclock()) {
                break;
            }

            if (zclient_rule_parse(zinst()->client_rule_parser, &parsed_rules, rule->rule)) {
                zsyslog(LOG_INFO, "Applied deferred rule '%s' for client %s", rule->rule, client->login);
            } else {
                zsyslog(LOG_INFO, "Failed to parse deferred rule '%s' for client %s", rule->rule, client->login);
            }

            free(rule->rule);
            free(rule);
            utarray_pop_back(&client->deferred_rules);
        }

        pthread_spin_unlock(&client->lock);

        zclient_apply_rules(client, &parsed_rules);
        zclient_rules_destroy(&parsed_rules);
    }
}
