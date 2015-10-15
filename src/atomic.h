#ifndef ZEROD_ATOMIC_H
#define ZEROD_ATOMIC_H

#include <stdint.h>
#include <stdatomic.h>

typedef _Atomic uint8_t atomic_uint8_t;
typedef _Atomic uint16_t atomic_uint16_t;
typedef _Atomic uint32_t atomic_uint32_t;
typedef _Atomic uint64_t atomic_uint64_t;

#endif // ZEROD_ATOMIC_H
