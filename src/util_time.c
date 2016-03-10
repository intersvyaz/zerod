#include <time.h>
#include <sys/time.h>
#include "util_time.h"

// cached time
static _Thread_local ztime_t
g_ztime_cached = 0;
static _Thread_local zclock_t
g_zclock_cached = 0;

/**
 * @return Cached timestamp in microseconds.
 */
inline ztime_t ztime()
{
    return g_ztime_cached;
}

/**
 * @return Cached monotonic clock timestamp in microseconds.
 */
inline zclock_t zclock()
{
    return g_zclock_cached;
}

/**
 * Cache current timestamp in microseconds.
 */
inline void ztime_refresh()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    g_ztime_cached = SEC2USEC(tv.tv_sec) + tv.tv_usec;
}

/**
 * Cache current monotonic clock timestamp in microseconds.
 */
inline void zclock_refresh()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    g_zclock_cached = SEC2USEC(ts.tv_sec) + NSEC2USEC(ts.tv_nsec);
}
