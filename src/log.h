#ifndef ZEROD_LOG_H
#define ZEROD_LOG_H

#include <string.h>
#include <errno.h>
#include <syslog.h>

extern unsigned g_log_verbosity;
extern unsigned g_log_stderr;

void zopenlog(void);

void zcloselog(void);

void zsyslog(int lvl, const char *fmt, ...)
        __attribute__ ((format (printf, 2, 3)));

void _zlog(int lvl, const char *fmt, ...)
        __attribute__ ((format (printf, 2, 3)));

#define ZLOG(lvl, msg, ...) \
    if (unlikely(g_log_verbosity >= (lvl))) _zlog(lvl, "%s(): " msg "\n", __FUNCTION__, ##__VA_ARGS__)

#define ZLOGEX(lvl, err, msg, ...) \
    if (unlikely(g_log_verbosity >= (lvl))) _zlog(lvl, "%s(): " msg ": %s\n", __FUNCTION__,  ##__VA_ARGS__, strerror(err))

#endif // ZEROD_LOG_H
