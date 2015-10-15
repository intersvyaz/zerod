#include "blacklist.h"
#include <string.h>
#include <regex.h>
#include <assert.h>
#include <stdio.h>
#include <netinet/in.h>
#include <uthash/uthash.h>
#include "util.h"
#include "session.h"
#include "log.h"

#define MAX_URL_LEN 32767
#define MAX_DOMAIN_LEN 256
#define MAX_PATH_LEN 8192

struct zbl_path
{
    char *path;
    size_t path_len;
    UT_hash_handle hh;
};

struct zbl_domain
{
    char *domain;
    size_t domain_len;
    bool whole;
    struct zbl_path *hpath;
    UT_hash_handle hh;
};

struct zblacklist
{
    /*<<! URL regexp, for input file parsing */
    regex_t re_url;
    /*<<! HTTP path regexp */
    regex_t re_path;
    /*<<! HTTP domain regexp */
    regex_t re_domain;
    /*<<! instance lock */
    pthread_rwlock_t lock;
    /*<<! domain hash, lookup by hdomain->domain */
    struct zbl_domain *hdomain;
};

/**
 * Create new blacklist instance.
 * @return Allocated and initialized instance.
 */
struct zblacklist *zblacklist_new(void)
{
    struct zblacklist *bl = malloc(sizeof(*bl));
    if (unlikely(!bl)) {
        return NULL;
    }

    memset(bl, 0, sizeof(*bl));

    if (unlikely(0 != pthread_rwlock_init(&bl->lock, NULL))) {
        goto end;
    }

    if (unlikely(0 != regcomp(&bl->re_url, "https?://([^/]+)(/.*)?", REG_EXTENDED | REG_NEWLINE | REG_ICASE))) {
        goto end;
    }

    if (unlikely(0 != regcomp(&bl->re_path, "^(GET|POST|HEAD)\\s+(.+)\\s+HTTP", REG_EXTENDED | REG_NEWLINE | REG_ICASE))) {
        goto end;
    }

    if (unlikely(0 != regcomp(&bl->re_domain, "\nHost:\\s+(.+)\r", REG_EXTENDED | REG_NEWLINE | REG_ICASE))) {
        goto end;
    }

    return bl;

    end:
    regfree(&bl->re_url);
    regfree(&bl->re_domain);
    regfree(&bl->re_path);
    pthread_rwlock_destroy(&bl->lock);
    free(bl);
    return NULL;
}

/**
 * Free domain hash.
 * @param[in] hdomain Domain hash.
 */
static void zblacklist_hdomain_free(struct zbl_domain *hdomain)
{
    struct zbl_domain *domain, *tmp_domain;
    HASH_ITER(hh, hdomain, domain, tmp_domain) {
        struct zbl_path *path, *tmp_path;
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
void zblacklist_free(struct zblacklist *bl)
{
    assert(bl);
    regfree(&bl->re_url);
    regfree(&bl->re_path);
    regfree(&bl->re_domain);
    pthread_rwlock_destroy(&bl->lock);
    zblacklist_hdomain_free(bl->hdomain);
    free(bl);
}

/**
 * Reload blacklist from file.
 * @param[in] bl Blacklist instance.
 * @param[in] file File path.
 * @return Zero no success.
 */
int zblacklist_reload(struct zblacklist *bl, const char *file)
{
    size_t domain_count = 0, url_count = 0, invalid_count = 0;

    FILE *f = fopen(file, "r");
    if (unlikely(!f)) {
        ZERO_ELOG(LOG_ERR, "Failed to open %s for reading", file);
        return -1;
    }

    regmatch_t matches[3];
    char line[MAX_URL_LEN];
    struct zbl_domain *new_hdomain = NULL;

    while (likely(fgets(line, sizeof(line), f))) {
        if (0 != regexec(&bl->re_url, line, ARRAYSIZE(matches), matches, 0)) {
            invalid_count++;
            ZERO_LOG(LOG_DEBUG, "Invalid line in blacklist file: %s", line);
            continue;
        }

        size_t domain_len = (size_t) (matches[1].rm_eo - matches[1].rm_so);
        char *domain = strndup(line + matches[1].rm_so, domain_len);

        size_t path_len = 0;
        char *path = NULL;
        if (-1 != matches[2].rm_eo) {
            path_len = (size_t) (matches[2].rm_eo - matches[2].rm_so);
            path = strndup(line + matches[2].rm_so, path_len);
        } else {
            path_len = 0;
        }

        struct zbl_domain *domain_rec = NULL;
        HASH_FIND(hh, new_hdomain, domain, domain_len, domain_rec);
        if (!domain_rec) {
            domain_rec = malloc(sizeof(*domain_rec));
            memset(domain_rec, 0, sizeof(*domain_rec));
            domain_rec->domain = domain;
            domain_rec->domain_len = domain_len;
            HASH_ADD_KEYPTR(hh, new_hdomain, domain_rec->domain, domain_rec->domain_len, domain_rec);
        } else {
            free(domain);
        }

        if (0 == path_len) {
            if (!domain_rec->whole) {
                domain_rec->whole = true;
                domain_count++;
            }
        } else if (!domain_rec->whole) {
            struct zbl_path *path_rec = NULL;
            HASH_FIND(hh, domain_rec->hpath, path, path_len, path_rec);
            if (unlikely(!path_rec)) {
                path_rec = malloc(sizeof(*path_rec));
                memset(path_rec, 0, sizeof(*path_rec));
                path_rec->path = path;
                path_rec->path_len = path_len;
                HASH_ADD_KEYPTR(hh, domain_rec->hpath, path_rec->path, path_rec->path_len, path_rec);
                url_count++;
            } else {
                free(path);
                continue;
            }
        } else {
            free(path);
        }
    }

    pthread_rwlock_wrlock(&bl->lock);
    struct zbl_domain *old_hdomain = bl->hdomain;
    bl->hdomain = new_hdomain;
    pthread_rwlock_unlock(&bl->lock);

    if (likely(old_hdomain)) {
        zblacklist_hdomain_free(old_hdomain);
    }

    zero_syslog(LOG_INFO, "Loaded blacklist (%zu domains, %zu urls, %zu invalid)",
                domain_count, url_count, invalid_count);

    fclose(f);
    return 0;
}

/**
 * Process packet data for blacklisted requests.
 * @param[in] bl Blacklist instance.
 * @param[in] sess Session.
 * @param[in] data Packet data.
 * @param[in] len Data length.
 * @return Zero on pass
 */
int zblacklist_process(struct zblacklist *bl, struct zsession *sess, char *data, size_t len)
{
    (void) sess;

    int drop = 0;
    regmatch_t match[3];
    char domain[MAX_DOMAIN_LEN];
    char path[MAX_PATH_LEN];

    // safe data end
    char old_end = data[len - 1];
    data[len - 1] = '\0';

    // path
    if (0 != regexec(&bl->re_path, data, ARRAYSIZE(match), match, 0)) {
        goto end;
    }
    size_t path_len = (size_t) (match[2].rm_eo - match[2].rm_so);
    char *path_ptr = data + match[2].rm_so;
    if (path_len >= sizeof(path)) {
        goto end;
    }

    // domain
    if (0 != regexec(&bl->re_domain, data, ARRAYSIZE(match), match, 0)) {
        goto end;
    }
    size_t domain_len = (size_t) (match[1].rm_eo - match[1].rm_so);
    char *domain_ptr = data + match[1].rm_so;
    if (domain_len >= sizeof(domain)) {
        goto end;
    }
    memcpy(domain, domain_ptr, domain_len);
    domain[domain_len] = '\0';

    pthread_rwlock_rdlock(&bl->lock);

    struct zbl_domain *domain_rec = NULL;
    HASH_FIND(hh, bl->hdomain, domain, domain_len, domain_rec);
    if (domain_rec) {
        if (domain_rec->whole) {
            drop = 1;
        } else {
            struct zbl_path *path_rec = NULL;
            memcpy(path, path_ptr, path_len);
            path[path_len] = '\0';
            HASH_FIND(hh, domain_rec->hpath, path, path_len, path_rec);
            if (path_rec) {
                drop = 1;
            }
        }
    }

    pthread_rwlock_unlock(&bl->lock);

    end:
#ifndef NDEBUG
    if (drop) {
        ZERO_LOG(LOG_DEBUG, "DROP: session %s: blacklisted URL: %s%s", ipv4_to_str(ntohl(sess->ip)), domain, path);
    }
#endif
    // restore data end
    data[len - 1] = old_end;

    return drop;
}
