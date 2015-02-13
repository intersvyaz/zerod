#ifndef LOG_H
#define LOG_H

#include <string.h>
#include <errno.h>
#include <syslog.h>

extern unsigned g_verbosity;

void zero_openlog(void);

void zero_closelog(void);

void zero_syslog(int lvl, const char *fmt, ...)
        __attribute__ ((format (printf, 2, 3)));

void _zero_log(int lvl, const char *fmt, ...)
        __attribute__ ((format (printf, 2, 3)));

#define ZERO_LOG(lvl, msg, ...) \
    if (unlikely(g_verbosity >= (lvl))) _zero_log(lvl, "%s(): " msg "\n", __FUNCTION__, ##__VA_ARGS__)

#define ZERO_ELOG(lvl, msg, ...) \
    if (unlikely(g_verbosity >= (lvl))) _zero_log(lvl, "%s(): " msg ": %s\n", __FUNCTION__,  ##__VA_ARGS__, strerror(errno))

#endif // LOG_H
