#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include "util_string.h"

/**
 * Create hex dump of buffer to user-supplied buffer or internal static buffer.
 * Static buffer is thread-safe.
 * The destination buffer must be at least 30+4*len.
 * @param[in] p Source buffer.
 * @param[in] len Buffer length.
 * @param[in] lim
 * @param[in,out] dst User supplied buffer (optional).
 * @return String with hexadecimal dump.
 */
const char *hex_dump(unsigned const char *p, size_t len, size_t lim, char *dst)
{
    static _Thread_local char _dst[8192];
    u_int i, j, i0;
    static char hex[] = "0123456789abcdef";
    char *o; // output position

    if (!dst) {
        dst = _dst;
    }
    if (!lim || lim > len) {
        lim = len;
    }
    o = dst;
    sprintf(o, "buf 0x%p len %zu lim %zu\n", p, len, lim);
    o += strlen(o);
    for (i = 0; i < lim;) {
        sprintf(o, "%5d: ", i);
        o += strlen(o);
        memset(o, ' ', 48);
        i0 = i;
        for (j = 0; j < 16 && i < lim; i++, j++) {
            o[j * 3] = hex[(p[i] & 0xf0) >> 4];
            o[j * 3 + 1] = hex[(p[i] & 0xf)];
        }
        i = i0;
        for (j = 0; j < 16 && i < lim; i++, j++)
            o[j + 48] = (p[i] >= 0x20 && p[i] <= 0x7e) ? p[i] : '.';
        o[j + 48] = '\n';
        o += j + 49;
    }
    *o = '\0';

    return dst;
}

/**
 * Check whether string ends with suffix.
 * @param[in] str
 * @param[in] suffix
 * @return Non zero on success.
 */
int str_ends_with(const char *str, const char *suffix)
{
    if (!str || !suffix)
        return 0;

    size_t lenstr = strlen(str);
    size_t lensuffix = strlen(suffix);
    if (lensuffix > lenstr)
        return 0;

    return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}

/**
 * Trim trailing whitespaces.
 * @param[in] str String to trim.
 */
void str_rtrim(char *str)
{
    char *end = str + strlen(str) - 1;
    while(end > str && isspace(*end)) end--;
    *(end+1) = 0;
}

/**
 * Convert string to upper case.
 * @param[in,out] str
 */
void strtoupper(char *str)
{
    for (size_t i = 0; str[i]; i++) {
        str[i] = (char) toupper(str[i]);
    }
}

/**
 * Convert string to lower case.
 * @param[in,out] str
 */
void strtolower(char *str)
{
    for (size_t i = 0; str[i]; i++) {
        str[i] = (char) tolower(str[i]);
    }
}

/**
 * @param[in] str
 * @param[out] val
 * @return Zero on success.
 */
int str_to_u64(const char *str, uint64_t *val)
{
    char *end = NULL;
    u_long v;
    errno = 0;
    v = strtoul(str, &end, 10);
    if ((ERANGE == errno) || (end == str) || ((end != NULL) && isdigit(*end)) || (v > UINT64_MAX)) {
        return -1;
    }
    *val = (uint64_t) v;
    return 0;
}

/**
 * @param[in] str
 * @param[out] val
 * @return Zero on success.
 */
int str_to_u32(const char *str, uint32_t *val)
{
    uint64_t v;
    if (0 != str_to_u64(str, &v) || v > UINT32_MAX) {
        return -1;
    }
    *val = (uint32_t) v;
    return 0;
}

/**
 * @param[in] str
 * @param[out] val
 * @return Zero on success.
 */
int str_to_u16(const char *str, uint16_t *val)
{
    uint64_t v;
    if (0 != str_to_u64(str, &v) || v > UINT16_MAX) {
        return -1;
    }
    *val = (uint16_t) v;
    return 0;
}

/**
 * @param[in] str
 * @param[out] val
 * @return Zero on success.
 */
int str_to_u8(const char *str, uint8_t *val)
{
    uint64_t v;
    if (0 != str_to_u64(str, &v) || v > UINT8_MAX) {
        return -1;
    }
    *val = (uint8_t) v;
    return 0;
}

uint64_t str_parse_si_unit(char prefix, uint64_t base)
{
    uint64_t mul = 1;
    switch (toupper(prefix)) {
        case 'E':
            mul *= base;
        case 'P':
            mul *= base;
        case 'T':
            mul *= base;
        case 'G':
            mul *= base;
        case 'M':
            mul *= base;
        case 'K':
            mul *= base;
        default:
            return mul;
    }
}
