#include <stdio.h>
#include <stdarg.h>

#include "globals.h"
#include "log.h"
#include "util.h"

#define ZLOG_INDENT "zerod"

unsigned g_log_verbosity = ZEROD_DEFAULT_LOG_LEVEL;
unsigned g_log_stderr = 1;

/**
 * Open log.
 */
void zopenlog(void)
{
    openlog(ZLOG_INDENT, LOG_NDELAY, LOG_DAEMON);
}

void zcloselog(void)
{
    closelog();
}

/**
 * Log directly to syslog.
 * @param[in] lvl Log level.
 * @param[in] fmt Massage (printf-like).
 */
void zsyslog(int lvl, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsyslog(lvl, fmt, ap);
    va_end(ap);
}

/**
 * Log to stderr and syslog.
 * @param[in] lvl Log level.
 * @param[in] fmt Message.
 */
void _zlog(int lvl, const char *fmt, ...)
{
    va_list ap;

    if (unlikely(g_log_stderr)) {
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
    }

    va_start(ap, fmt);
    vsyslog(lvl, fmt, ap);
    va_end(ap);
}
