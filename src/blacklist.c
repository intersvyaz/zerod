#include <stddef.h> // fix annoying bug in clion
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <netinet/in.h>
#include <uthash/uthash.h>

#include "blacklist.h"
#include "util.h"
#include "util_string.h"
#include "util_pcre.h"
#include "log.h"

#define ZBL_MAX_URL_LEN 32767

// TODO: use suffix tree?

typedef struct zbl_path
{
    /*<<! path */
    char *path;
    /*<<! path_len */
    size_t path_len;
    /*<<! hash handle (lookup by path) */
    UT_hash_handle hh;
} zbl_path_t;

typedef struct zbl_domain
{
    /*<<! domain */
    char *domain;
    /*<<! domain length */
    size_t domain_len;
    /*<<! block whole domain */
    bool whole;
    /*<<! path hash (lookup by path) */
    zbl_path_t *hpath;
    /*<<! hash handle (lookup by domain) */
    UT_hash_handle hh;
} zbl_domain_t;

struct zblacklist
{
    /*<<! URL regexp, for input file parsing */
    pcre *re_url;
    pcre_extra *re_url_extra;
    /*<<! HTTP path regexp */
    pcre *re_path;
    pcre_extra *re_path_extra;
    /*<<! HTTP domain regexp */
    pcre *re_domain;
    pcre_extra *re_domain_extra;
    /*<<! access lock */
    pthread_rwlock_t lock;
    /*<<! domain hash (lookup by domain) */
    zbl_domain_t *hdomain;
};

typedef struct zbl_url_struct
{
    /*<<! domain */
    char *domain;
    /*<<! domain length */
    size_t domain_len;
    /*<<! path */
    char *path;
    /*<<! path length */
    size_t path_len;
} zbl_url_t;

typedef struct zbl_url_const_struct
{
    /*<<! domain */
    const char *domain;
    /*<<! domain length */
    size_t domain_len;
    /*<<! path */
    const char *path;
    /*<<! path length */
    size_t path_len;
} zbl_url_const_t;

typedef enum zbl_url_type_enum
{
    ZBL_URL_INVALID = -1,
    ZBL_URL_OK = 0,
    ZBL_URL_DOMAIN = 1,
    ZBL_URL_DUPLICATE = 2,
} zbl_url_type_t;

/**
 * Create new blacklist instance.
 * @return Allocated and initialized instance.
 */
zblacklist_t *zblacklist_new(void)
{
    zblacklist_t *bl = malloc(sizeof(*bl));
    if (unlikely(!bl)) {
        return NULL;
    }

    memset(bl, 0, sizeof(*bl));

    if (unlikely(0 != pthread_rwlock_init(&bl->lock, NULL))) {
        goto error;
    }

    int erroffset;
    const char *errptr;

    bl->re_url = pcre_compile("https?://([^/]+)(/.*)?", PCRE_CASELESS | PCRE_NEWLINE_CRLF, &errptr, &erroffset, NULL);
    if (unlikely(!bl->re_url)) {
        goto error;
    }
    bl->re_url_extra = pcre_study(bl->re_url, 0, &errptr);

    bl->re_path = pcre_compile("^(?:OPTIONS|GET|HEAD|POST|PUT|PATCH|DELETE|TRACE|CONNECT)\\s+(.+)\\s+HTTP", PCRE_CASELESS | PCRE_NEWLINE_CRLF, &errptr, &erroffset, NULL);
    if (unlikely(!bl->re_path)) {
        goto error;
    }
    bl->re_path_extra = pcre_study(bl->re_path, 0, &errptr);

    bl->re_domain = pcre_compile("\nHost:\\s+(.+)\r", PCRE_CASELESS | PCRE_NEWLINE_CRLF, &errptr, &erroffset, NULL);
    if (unlikely(!bl->re_domain)) {
        goto error;
    }

    return bl;

    error:
    zblacklist_free(bl);
    return NULL;
}

/**
 * Free domain hash.
 * @param[in] hdomain Domain hash.
 */
static void zblacklist_hdomain_free(zbl_domain_t *hdomain)
{
    zbl_domain_t *domain, *tmp_domain;
    HASH_ITER(hh, hdomain, domain, tmp_domain) {
        zbl_path_t *path, *tmp_path;
        HASH_ITER(hh, domain->hpath, path, tmp_path) {
            HASH_DELETE(hh, domain->hpath, path);
            free(path->path);
            free(path);
        }
        HASH_DELETE(hh, hdomain, domain);
        free(domain->domain);
        free(domain);
    }
}

/**
 * Free blacklist instance.
 * @param[in] bl Instance.
 */
void zblacklist_free(zblacklist_t *bl)
{
    assert(bl);

    if (bl->re_url_extra) pcre_free_study(bl->re_url_extra);
    if (bl->re_url) pcre_free(bl->re_url);
    if (bl->re_path_extra) pcre_free_study(bl->re_path_extra);
    if (bl->re_path) pcre_free(bl->re_path);
    if (bl->re_domain_extra) pcre_free_study(bl->re_domain_extra);
    if (bl->re_domain) pcre_free(bl->re_domain);
    pthread_rwlock_destroy(&bl->lock);
    zblacklist_hdomain_free(bl->hdomain);
    free(bl);
}

/**
 * Parse URL.
 * @param[in] Blacklist instance.
 * @param[in] string String to parse.
 * @param[in, out] url
 * @return Zero on success.
 */
static bool zbl_url_parse(zblacklist_t *bl, const char *string, zbl_url_t *url)
{
    int ovec[ZPCRE_DECL_SIZE(1+2)];

    int rc = pcre_exec(bl->re_url, bl->re_url_extra, string, (int)strlen(string), 0, 0, ovec, ARRAYSIZE(ovec));
    if (unlikely(rc < 0)) {
        return false;
    }

    url->domain_len = (size_t) ZPCRE_LEN(ovec, 1);
    url->domain = strndup(string + ZPCRE_SO(ovec, 1), url->domain_len);

    if (-1 != ZPCRE_SO(ovec, 2)) {
        url->path_len = (size_t) ZPCRE_LEN(ovec, 2);
        url->path = strndup(string + ZPCRE_SO(ovec, 2), url->path_len);
    } else {
        url->path = NULL;
        url->path_len = 0;
    }

    return true;
}

/**
 * Load URL.
 * @param[in] bl
 * @param[in,out] hdomain
 * @param[in] url
 * @return URL type.
 */
static zbl_url_type_t zbl_load_url(zblacklist_t *bl, zbl_domain_t **hdomain, const char *url)
{
    zbl_url_t match = {0};

    if (unlikely(!zbl_url_parse(bl, url, &match))) {
        return ZBL_URL_INVALID;
    }

    zbl_domain_t *domain_rec = NULL;
    HASH_FIND(hh, *hdomain, match.domain, match.domain_len, domain_rec);
    if (!domain_rec) {
        domain_rec = malloc(sizeof(*domain_rec));
        memset(domain_rec, 0, sizeof(*domain_rec));
        domain_rec->domain = match.domain;
        domain_rec->domain_len = match.domain_len;
        HASH_ADD_KEYPTR(hh, *hdomain, domain_rec->domain, domain_rec->domain_len, domain_rec);
    } else {
        free(match.domain);
    }

    if (0 == match.path_len) {
        if (!domain_rec->whole) {
            domain_rec->whole = true;
            return ZBL_URL_DOMAIN;
        } else {
            return ZBL_URL_DUPLICATE;
        }
    } else if (!domain_rec->whole) {
        zbl_path_t *path_rec = NULL;
        HASH_FIND(hh, domain_rec->hpath, match.path, match.path_len, path_rec);
        if (unlikely(!path_rec)) {
            path_rec = malloc(sizeof(*path_rec));
            memset(path_rec, 0, sizeof(*path_rec));
            path_rec->path = match.path;
            path_rec->path_len = match.path_len;
            HASH_ADD_KEYPTR(hh, domain_rec->hpath, path_rec->path, path_rec->path_len, path_rec);
            return ZBL_URL_OK;
        } else {
            free(match.path);
            return ZBL_URL_DUPLICATE;
        }
    } else {
        free(match.path);
        return ZBL_URL_DUPLICATE;
    }
}

/**
 * Reload blacklist from file.
 * @param[in] bl Blacklist instance.
 * @param[in] file File path.
 * @return Zero no success.
 */
bool zblacklist_reload(zblacklist_t *bl, const char *file)
{
    size_t domain_count = 0, url_count = 0, invalid_count = 0, duplicate_count = 0;

    FILE *f = fopen(file, "r");
    if (unlikely(!f)) {
        ZLOGEX(LOG_ERR, errno, "Failed to open %s for reading", file);
        return false;
    }

    char line[ZBL_MAX_URL_LEN];
    zbl_domain_t *new_hdomain = NULL;

    while (likely(fgets(line, sizeof(line), f))) {
        str_rtrim(line);
        zbl_url_type_t type = zbl_load_url(bl, &new_hdomain, line);
        switch (type) {
            case ZBL_URL_INVALID:
                invalid_count++;
                ZLOG(LOG_DEBUG, "Invalid URL in blacklist file: %s", line);
                break;
            case ZBL_URL_OK:
                url_count++;
                break;
            case ZBL_URL_DOMAIN:
                domain_count++;
                break;
            case ZBL_URL_DUPLICATE:
                duplicate_count++;
                break;
            default:
                break;
        }
    }

    pthread_rwlock_wrlock(&bl->lock);
    zbl_domain_t *old_hdomain = bl->hdomain;
    bl->hdomain = new_hdomain;
    pthread_rwlock_unlock(&bl->lock);

    if (likely(old_hdomain)) {
        zblacklist_hdomain_free(old_hdomain);
    }

    ZLOG(LOG_INFO, "Loaded blacklist (%zu domains, %zu urls, %zu invalid, duplicate %zu)",
            domain_count, url_count, invalid_count, duplicate_count);

    fclose(f);
    return true;
}

/**
 *
 */
static bool zbl_url_is_blocked(zblacklist_t *bl, const zbl_url_const_t *url)
{
    bool blocked = false;

    pthread_rwlock_rdlock(&bl->lock);

    zbl_domain_t *domain_rec = NULL;
    HASH_FIND(hh, bl->hdomain, url->domain, url->domain_len, domain_rec);
    if (domain_rec) {
        if (domain_rec->whole) {
            blocked = true;
        } else {
            zbl_path_t *path_rec = NULL;
            HASH_FIND(hh, domain_rec->hpath, url->path, url->path_len, path_rec);
            if (path_rec) {
                blocked = true;
            }
        }
    }

    pthread_rwlock_unlock(&bl->lock);

    return blocked;
}

/**
 * Extract URL from packet.
 * @param[in] bl Blacklist handle.
 * @param[in] data Packet (must be null-terminated).
 * @param[in,out] url Where to place extracted information.
 * @return Zero on success.
 */
static bool zbl_url_extract(zblacklist_t *bl, const char *data, size_t data_len, zbl_url_const_t *url)
{
    int ovec[ZPCRE_DECL_SIZE(1+1)];
    int rc = 0;

    // path
    rc = pcre_exec(bl->re_path, bl->re_path_extra, data, (int)data_len, 0, 0, ovec, ARRAYSIZE(ovec));
    if (rc < 0) {
        return false;
    }
    url->path_len = (size_t) ZPCRE_LEN(ovec, 1);
    url->path = data + ZPCRE_SO(ovec, 1);

    // domain
    rc = pcre_exec(bl->re_domain, bl->re_domain_extra, data, (int)data_len, 0, 0, ovec, ARRAYSIZE(ovec));
    if (rc < 0) {
        return false;
    }
    url->domain_len = (size_t) ZPCRE_LEN(ovec, 1);
    url->domain = data + ZPCRE_SO(ovec, 1);

    return true;
}

/**
 * Process packet data for blacklisted requests.
 * @param[in] bl Blacklist instance.
 * @param[in] data Packet data.
 * @param[in] len Data length.
 * @return True if contains forbidden request.
 */
bool zblacklist_check(zblacklist_t *bl, const char *data, size_t data_len)
{
    zbl_url_const_t url;

    if (!zbl_url_extract(bl, data, data_len, &url)) {
        return false;
    }

    if (zbl_url_is_blocked(bl, &url)) {
        if(unlikely(g_log_verbosity >= LOG_DEBUG)) {
            char *domain = strndup(url.domain, url.domain_len);
            char *path = strndup(url.path, url.path_len);
            ZLOG(LOG_DEBUG, "Blocked URL: %s%s", domain, path);
            free(domain);
            free(path);
        }
        return true;
    }

    return false;
}
