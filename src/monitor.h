#ifndef ZEROD_MONITOR_H
#define ZEROD_MONITOR_H

#include <stddef.h>
#include <stdint.h>

struct bufferevent;
struct zmonitor;
struct zmonitor_conn;

struct zmonitor *zmonitor_new(uint64_t max_bandwidth);

void zmonitor_free(struct zmonitor *mon);

void zmonitor_mirror_packet(struct zmonitor *mon, unsigned const char *packet, size_t len);

struct zmonitor_conn *zmonitor_conn_new(uint64_t max_bandwidth);

void zmonitor_conn_free(struct zmonitor_conn *mon);

void zmonitor_conn_activate(struct zmonitor_conn *conn, struct zmonitor *mon);

void zmonitor_conn_deactivate(struct zmonitor_conn *conn);

int zmonitor_conn_set_filter(struct zmonitor_conn *mon, const char *filter);

void zmonitor_conn_set_listener(struct zmonitor_conn *mon, struct bufferevent *bev);



#endif // ZEROD_MONITOR_H
