#ifndef MONITOR_H
#define MONITOR_H

#include <stddef.h>

struct monitor;
struct bufferevent;

struct monitor *monitor_new(void);

void monitor_free(struct monitor *mon);

void monitor_activate(struct monitor *mon);

void monitor_deactivate(struct monitor *mon);

int monitor_set_filter(struct monitor *mon, const char *filter);

void monitor_set_listener(struct monitor *mon, struct bufferevent *bev);

void monitor_mirror_packet(unsigned const char *packet, size_t len);

#endif // MONITOR_H
