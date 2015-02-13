#include "log.h"

#include <stdio.h>
#include <stdarg.h>

#include "config.h"

#define ZERO_LOG_INDENT "zerod"

unsigned g_verbosity = ZERO_DEFAULT_LOG_LEVEL;

/**
* Open log.
*/
void zero_openlog(void)
{
    openlog(ZERO_LOG_INDENT, LOG_NDELAY, LOG_DAEMON);
}

void zero_closelog(void)
{
    closelog();
}

/**
Log directly to syslog.
* @param[in] lvl Log level.
* @param[in] fmt Massage (printf-like).
*/
void zero_syslog(int lvl, const char *fmt, ...)
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
void _zero_log(int lvl, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);

    va_start(ap, fmt);
    vsyslog(lvl, fmt, ap);

    va_end(ap);
}
