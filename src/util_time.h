#ifndef ZEROD_UTIL_TIME_H
#define ZEROD_UTIL_TIME_H

#include <stdint.h>

typedef uint64_t zclock_t;
typedef uint64_t ztime_t;

typedef _Atomic uint64_t atomic_zclock_t;;
typedef _Atomic uint64_t atomic_ztime_t;;

#define USEC2SEC(x) (((uint64_t)(x)) / 1000000u)
#define NSEC2USEC(x) (((uint64_t)(x)) / 1000u)
#define SEC2USEC(x) (((uint64_t)(x)) * 1000000u)
#define MIN2USEC(x) (SEC2USEC(x)*60)

ztime_t ztime();
zclock_t zclock();

void ztime_refresh();
void zclock_refresh();

#endif // ZEROD_UTIL_TIME_H
