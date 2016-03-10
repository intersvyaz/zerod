#ifndef ZEROD_UTIL_PCRE_H
#define ZEROD_UTIL_PCRE_H

#include <pcre.h>

#define ZPCRE_DECL_SIZE(n) ((n)*3)

// get match start offset
#define ZPCRE_SO(ovec, i) ((ovec)[(i)*2])
// get match end offset
#define ZPCRE_EO(ovec, i) ((ovec)[(i)*2+1])
// get match length
#define ZPCRE_LEN(ovec, i) (ZPCRE_EO(ovec, i) - ZPCRE_SO(ovec, i))

#endif // ZEROD_UTIL_PCRE_H
