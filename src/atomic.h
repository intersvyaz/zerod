#ifndef ZEROD_ATOMIC_H
#define ZEROD_ATOMIC_H

#include <stdint.h>
#include <stdatomic.h>

typedef _Atomic uint8_t atomic_uint8_t;;
typedef _Atomic uint16_t atomic_uint16_t;;
typedef _Atomic uint32_t atomic_uint32_t;;
typedef _Atomic uint64_t atomic_uint64_t;;

#define atomic_load_acquire(PTR)                atomic_load_explicit(PTR, memory_order_acquire)
#define atomic_store_release(PTR, VAL)          atomic_store_explicit(PTR, VAL, memory_order_release)
#define atomic_fetch_add_release(PTR, VAL)      atomic_fetch_add_explicit(PTR, VAL, memory_order_release)
#define atomic_fetch_sub_release(PTR, VAL)      atomic_fetch_sub_explicit(PTR, VAL, memory_order_release)

#endif // ZEROD_ATOMIC_H
