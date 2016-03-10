#ifndef ZEROD_UTIL_STRING_H
#define ZEROD_UTIL_STRING_H

#include <stddef.h>
#include <stdint.h>

#define STRLEN_STATIC(x) (sizeof(x) - 1)

const char *hex_dump(unsigned const char *p, size_t len, size_t lim, char *dst);

int str_ends_with(const char *str, const char *suffix);

void str_rtrim(char *str);

void strtoupper(char *str);

void strtolower(char *str);

int str_to_i64(const char *str, int64_t *val);

int str_to_u64(const char *str, uint64_t *val);

int str_to_u32(const char *str, uint32_t *val);

int str_to_u16(const char *str, uint16_t *val);

int str_to_u8(const char *str, uint8_t *val);

uint64_t str_parse_si_unit(char prefix, uint64_t base);

#endif // ZEROD_UTIL_STRING_H
