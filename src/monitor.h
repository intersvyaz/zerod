#ifndef ZEROD_MONITOR_H
#define ZEROD_MONITOR_H

#include <stdint.h>
#include <stdbool.h>

struct bufferevent;

typedef struct zmonitor_struct zmonitor_t;
typedef struct zmonitor_conn_struct zmonitor_conn_t;

zmonitor_t *zmonitor_new(uint64_t max_bandwidth);

void zmonitor_free(zmonitor_t *mon);

void zmonitor_mirror_packet(zmonitor_t *mon, void *packet, size_t len);

zmonitor_conn_t *zmonitor_conn_new(uint64_t max_bandwidth);

void zmonitor_conn_free(zmonitor_conn_t *mon);

void zmonitor_conn_activate(zmonitor_conn_t *conn, zmonitor_t *mon);

void zmonitor_conn_deactivate(zmonitor_conn_t *conn);

bool zmonitor_conn_set_filter(zmonitor_conn_t *mon, const char *filter);

void zmonitor_conn_set_listener(zmonitor_conn_t *mon, struct bufferevent *bev);

#endif // ZEROD_MONITOR_H
