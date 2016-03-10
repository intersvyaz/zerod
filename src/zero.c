#include <stddef.h> // fix clion bug
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>

#include <event2/event.h>
#include <event2/thread.h>

#include "zero.h"
#include "log.h"
#include "worker.h"

#ifndef PTHREAD_MAX_THREAD_NAME
#define PTHREAD_MAX_THREAD_NAME 16
#endif

// global app instance
zinstance_t g_zinst;

/**
 * @return True on success.
 */
static bool zinst_init_events(zinstance_t *inst)
{
    if (unlikely(0 != evutil_secure_rng_init())) {
        ZLOG(LOG_ERR, "failed to seed random number generator");
        return false;
    }
    if (unlikely(0 != evthread_use_pthreads())) {
        ZLOG(LOG_ERR, "failed to init libevent threading model");
        return false;
    }

    inst->master_event_base = event_base_new();
    if (unlikely(NULL == inst->master_event_base)) {
        ZLOG(LOG_ERR, "failed to create master event loop");
        return false;
    }
    event_base_priority_init(inst->master_event_base, PRIO_COUNT);

    return true;
}

static bool zinst_init_client_rule_parser(zinstance_t *inst)
{
    zclient_rule_parser_t *parser = zclient_rule_parser_new();
    if (unlikely(!parser)) {
        ZLOG(LOG_ERR, "failed to create client rule parser");
        return false;
    }

    inst->client_rule_parser = parser;
    return true;
}

/**
 * @return True on success.
 */
static bool zinst_init_remotectl(zinstance_t *inst)
{
    struct sockaddr_in rc_addr;
    int sa_len = sizeof(rc_addr);
    bool ok = evutil_parse_sockaddr_port(inst->cfg->remotectl_listen, (struct sockaddr *) &rc_addr, &sa_len) == 0;
    if (unlikely(!ok || !rc_addr.sin_port)) {
        ZLOG(LOG_ERR, "Failed to parse remote control listen address '%s' or missing port", inst->cfg->remotectl_listen);
        return false;
    }

    return true;
}

/**
 * @return True on success.
 */
static bool zinst_init_interfaces(zinstance_t *inst)
{
    znetmap_iface_t * if_first = NULL;
    utarray_init(&inst->interfaces, &ut_ptr_icd);
    utarray_init(&inst->workers, &ut_ptr_icd);

    for (u_int i = 0; i < utarray_len(&inst->cfg->interfaces); i++) {
        zifpair_t *if_pair = (zifpair_t *) utarray_eltptr(&inst->cfg->interfaces, i);
        znetmap_iface_t *if_lan, *if_wan;

        if_lan = znetmap_new(if_pair->lan, if_first);
        if (unlikely(!if_lan)) {
            ZLOG(LOG_ERR, "Failed to open interface %s in netmap mode", if_pair->lan);
            return false;
        }
        // save first opened netmap handle for mmap caching
        if (!if_first) {
            if_first = if_lan;
        }

        if_wan = znetmap_new(if_pair->wan, if_first);
        if (unlikely(0 == if_wan)) {
            ZLOG(LOG_ERR, "Failed to open interface %s in netmap mode", if_pair->wan);
            znetmap_free(if_lan);
            return false;
        }

        // We support only 1:1 ring mapping
        if (if_lan->rx_rings_count != if_wan->tx_rings_count
            || if_wan->rx_rings_count != if_lan->tx_rings_count
            || if_lan->rx_rings_count != if_wan->rx_rings_count
                ) {
            ZLOG(LOG_ERR, "Incompatible rings count for %s<->%s", if_pair->lan, if_pair->wan);
            znetmap_free(if_lan);
            znetmap_free(if_wan);
            return false;
        }

        utarray_push_back(&inst->interfaces, &if_lan);
        utarray_push_back(&inst->interfaces, &if_wan);

        // initialize rings
        for (uint16_t ring_id = 0; ring_id < if_lan->rings_count; ring_id++) {
            zworker_t *worker = zworker_new(if_lan, if_wan, ring_id, if_pair->affinity + ring_id);
            utarray_push_back(&inst->workers, &worker);
        }
    }

    return true;
}

/**
 * @return True on success.
 */
static bool zinst_init_monitor(zinstance_t *inst)
{
    inst->monitor = zmonitor_new(inst->cfg->monitor.total_bandwidth);
    if (unlikely(!inst->monitor)) {
        ZLOG(LOG_ERR, "Failed to create zmonitor instance");
        return false;
    }

    return true;
}

/**
 * @return True on success.
 */
static int zinst_init_limits(zinstance_t *inst)
{
    for (int dir = 0; dir < DIR_MAX; dir++) {
        token_bucket_init(&inst->non_client.band[dir], inst->cfg->non_client_bandwidth[dir]);
        spdm_init(&inst->non_client.speed[dir]);
    }

    return true;
}

/**
 * @return True on success.
 */
static bool zinst_init_scopes(zinstance_t *inst)
{
    for (size_t i = 0; i < utarray_len(&inst->cfg->scopes); i++) {
        zconfig_scope_t *cfg = *(zconfig_scope_t **) utarray_eltptr(&inst->cfg->scopes, i);

        zscope_t *scope = zscope_new(cfg);
        if (!scope) {
            ZLOG(LOG_ERR, "Failed to initialize %s scope", cfg->name);
            return false;
        }

        HASH_ADD_KEYPTR(hh, inst->scopes, scope->cfg->name, strlen(scope->cfg->name), scope);
    }

    return true;
}

/**
 * Initialize app instance structure.
 * @param[in] zconf Configuration for instance.
 * @return True on success.
 */
bool zinstance_init(const zconfig_t *cfg)
{
    memset(&g_zinst, 0, sizeof(g_zinst));

    ztime_refresh();

    g_zinst.cfg = cfg;
    g_zinst.start_time = ztime();

    bool ok =
            zinst_init_events(&g_zinst)
            && zinst_init_client_rule_parser(&g_zinst)
            && zinst_init_remotectl(&g_zinst)
            && zinst_init_interfaces(&g_zinst)
            && zinst_init_monitor(&g_zinst)
            && zinst_init_limits(&g_zinst)
            && zinst_init_scopes(&g_zinst);

    if (!ok) {
        return false;
    }

    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);

    return true;
}

/**
 * Cleanup app instance.
 */
void zinstance_destroy(void)
{
    // clean workers
    for (size_t i = 0; i < utarray_len(&g_zinst.workers); i++) {
        zworker_t *worker = *(zworker_t **) utarray_eltptr(&g_zinst.workers, i);
        zworker_free(worker);

    }
    utarray_done(&g_zinst.workers);

    // clean scopes
    zscope_t *scope, *tmp_scope;
    HASH_ITER(hh, g_zinst.scopes, scope, tmp_scope) {
        HASH_DELETE(hh, g_zinst.scopes, scope);
        zscope_free(scope);
    }

    // close netmap interfaces
    for (size_t i = 0; i < utarray_len(&g_zinst.interfaces); i++) {
        znetmap_iface_t *iface = *(znetmap_iface_t **) utarray_eltptr(&g_zinst.interfaces, i);
        znetmap_free(iface);
    }
    utarray_done(&g_zinst.interfaces);

    if (likely(g_zinst.monitor)) {
        zmonitor_free(g_zinst.monitor);
        g_zinst.monitor = NULL;
    }

    if (likely(g_zinst.client_rule_parser)) {
        zclient_rule_parser_free(g_zinst.client_rule_parser);
        g_zinst.client_rule_parser = NULL;
    }

    if (likely(g_zinst.master_event_base)) {
        event_base_free(g_zinst.master_event_base);
        g_zinst.master_event_base = NULL;
    }
}

/**
 * Stop application instance.
 */
void zinstance_stop(void)
{
    event_base_loopbreak(zinst()->master_event_base);
    atomic_store_release(&zinst()->abort, true);
}

/**
 * Run app instance.
 */
void zinstance_run(void)
{
    zoverlord_t *overlord_threads = calloc(zinst()->cfg->overlord_threads, sizeof(*overlord_threads));

    atomic_init(&zinst()->abort, false);

    if (zinst()->cfg->iface_wait_time) {
        ZLOG(LOG_INFO, "Wait %u secs for link up...", zinst()->cfg->iface_wait_time);
        sleep(zinst()->cfg->iface_wait_time);
    }

    // start worker threads.
    for (size_t i = 0; i < utarray_len(&zinst()->workers); i++) {
        char thread_name[PTHREAD_MAX_THREAD_NAME];
        zworker_t *worker = *(zworker_t **) utarray_eltptr(&zinst()->workers, i);

        if (0 != pthread_create(&worker->thread, NULL, zworker_proc, worker)) {
            ZLOG(LOG_ERR, "Failed to start ring thread");
            atomic_store_release(&zinst()->abort, true);
            goto end;
        }

        snprintf(thread_name, sizeof(thread_name), "%s-ring%zu", worker->lan->ifname, i);
        pthread_setname_np(worker->thread, thread_name);
        ZLOG(LOG_DEBUG, "Start thread %s", thread_name);
    }

    // start overlord threads.
    for (size_t i = 0; i < zinst()->cfg->overlord_threads; i++) {
        char thread_name[PTHREAD_MAX_THREAD_NAME];
        overlord_threads[i].idx = i;

        if (0 != pthread_create(&overlord_threads[i].thread, NULL, zoverlord_proc, &overlord_threads[i])) {
            ZLOG(LOG_ERR, "Failed to start overlord thread");
            atomic_store_release(&zinst()->abort, true);
            goto end;
        }

        snprintf(thread_name, sizeof(thread_name), "overlord%zu", i);
        pthread_setname_np(overlord_threads[i].thread, thread_name);
        ZLOG(LOG_DEBUG, "Start thread %s", thread_name);
    }

    // run master thread.
    master_worker();

    end:
    // join ring threads.
    for (size_t i = 0; i < utarray_len(&zinst()->workers); i++) {
        zworker_t *worker = *(zworker_t **) utarray_eltptr(&zinst()->workers, i);

        if ((0 != worker->thread) && (0 != pthread_join(worker->thread, NULL))) {
            ZLOG(LOG_ERR, "Failed to join %s-ring%zu thread", worker->lan->ifname, i);
        }
    }

    // join overlord threads.
    for (size_t i = 0; i < zinst()->cfg->overlord_threads; i++) {
        if ((0 != overlord_threads[i].thread) && (0 != pthread_join(overlord_threads[i].thread, NULL))) {
            ZLOG(LOG_ERR, "Failed to join overlord%zu thread", i);
        }
    }

    if (overlord_threads) free(overlord_threads);
}

/**
 * Find scope by name.
 * @param[in] name Scope name.
 * @return Scope or null if not found.
 */
zscope_t *zinstance_get_scope(const char *name)
{
    zscope_t *scope = NULL;
    HASH_FIND(hh, g_zinst.scopes, name, strlen(name), scope);
    return scope;
}
