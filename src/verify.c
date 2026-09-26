#define _POSIX_C_SOURCE 200809L
#include "verify.h"
#include "config.h"
#include "package.h"

#include <archive.h>
#include <archive_entry.h>
#include <errno.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct payload {
    char *path;
    unsigned char hash[32];
    long long size;
    unsigned int mode;
    long long uid, gid;
    int matched;
};

static int compare(const void *a, const void *b)
{
    const struct payload *x = a, *y = b;
    return strcmp(x->path, y->path);
}

static int number(const char *s, int base, unsigned long long *out)
{
    char *end;
    errno = 0;
    *out = strtoull(s, &end, base);
    return s[0] && s[0] != '-' && !errno && !*end;
}

static int validate_manifest(const char *path, char *text, size_t size,
                             struct payload *files, size_t count)
{
    size_t start = 0, i, line = 0, seen = 0;
    char *error = NULL;
    for (i = 0; i <= size; ++i) {
        char **v = NULL;
        size_t n = 0;
        struct payload key, *found;
        unsigned long long mode, uid, gid, length;
        size_t j;
        if (i < size && text[i] != '\n') continue;
        ++line;
        if (memchr(text + start, '\0', i - start) ||
            !holy_lex(text + start, i - start, &v, &n, path, line, &error)) {
            fprintf(stderr, "%s: HOLY/files:%zu: %s\n", path, line,
                    error ? error : "NUL or invalid record");
            free(error);
            return 0;
        }
        start = i + 1;
        if (!n) { holy_tokens_free(v, n); continue; }
        if (n != 12 || strcmp(v[0], "file") ||
            !number(v[2], 8, &mode) || !number(v[5], 10, &uid) ||
            !number(v[6], 10, &gid) || !number(v[7], 10, &length) ||
            strlen(v[8]) != 64 || strcmp(v[9], "none") ||
            strcmp(v[10], "-") || strcmp(v[11], "-") ||
            mode > 07777 || uid > 0x7fffffff || gid > 0x7fffffff ||
            length > 0x7fffffffffffffffULL) {
            fprintf(stderr, "%s: HOLY/files:%zu: unsupported or invalid record\n", path, line);
            holy_tokens_free(v, n);
            return 0;
        }
        key.path = v[1];
        found = count ? bsearch(&key, files, count, sizeof *files, compare) : NULL;
        if (!found || found->matched || (unsigned long long)found->size != length ||
            found->mode != mode || (unsigned long long)found->uid != uid ||
            (unsigned long long)found->gid != gid) {
            fprintf(stderr, "%s: HOLY/files:%zu: payload or attributes mismatch\n", path, line);
            holy_tokens_free(v, n);
            return 0;
        }
        for (j = 0; j < 32; ++j) {
            char byte[3] = {v[8][j * 2], v[8][j * 2 + 1], 0};
            unsigned long long hex;
            if (!number(byte, 16, &hex) || hex != found->hash[j]) break;
        }
        if (j != 32) {
            fprintf(stderr, "%s: HOLY/files:%zu: payload SHA-256 mismatch\n", path, line);
            holy_tokens_free(v, n);
            return 0;
        }
        found->matched = 1;
        ++seen;
        holy_tokens_free(v, n);
    }
    if (seen != count) {
        fprintf(stderr, "%s: unlisted payload file\n", path);
        return 0;
    }
    return 1;
}

int holy_verify(const char *path)
{
    struct archive *a = NULL;
    struct archive_entry *entry;
    struct payload *files = NULL;
    size_t count = 0, i, manifest_size = 0;
    char *manifest = NULL;
    char buffer[8192];
    int status, seen = 0, ok = 0;
    if (!holy_package_info(path)) return 0;
    a = archive_read_new();
    if (!a || archive_read_support_filter_lz4(a) != ARCHIVE_OK ||
        archive_read_support_format_tar(a) != ARCHIVE_OK ||
        archive_read_open_filename(a, path, 8192) != ARCHIVE_OK) {
        fprintf(stderr, "%s: archive open failed\n", path);
        goto done;
    }
    while ((status = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        const char *name = archive_entry_pathname(entry);
        int is_manifest = name && !strcmp(name, "HOLY/files");
        int is_data = name && !strncmp(name, "DATA/", 5) &&
                      archive_entry_filetype(entry) != AE_IFDIR;
        EVP_MD_CTX *hash = NULL;
        la_ssize_t got;
        unsigned int digest_size;
        unsigned long long actual = 0;
        if (!holy_safe_archive_path(name)) {
            fprintf(stderr, "%s: unsafe archive path\n", path);
            goto done;
        }
        if (is_manifest) {
            if (seen++ || archive_entry_filetype(entry) != AE_IFREG ||
                archive_entry_size(entry) < 0 || archive_entry_size(entry) > 16 * 1024 * 1024) {
                fprintf(stderr, "%s: invalid HOLY/files\n", path);
                goto done;
            }
        }
        if (is_data) {
            struct payload *next;
            if (!name[5] || archive_entry_filetype(entry) != AE_IFREG ||
                archive_entry_size(entry) < 0 || count == (size_t)-1 / sizeof *files) {
                fprintf(stderr, "%s: unsupported payload type\n", path);
                goto done;
            }
            next = realloc(files, (count + 1) * sizeof *files);
            if (!next) goto done;
            files = next;
            files[count].path = strdup(name + 5);
            if (!files[count].path) goto done;
            files[count].size = archive_entry_size(entry);
            files[count].mode = archive_entry_perm(entry);
            files[count].uid = archive_entry_uid(entry);
            files[count].gid = archive_entry_gid(entry);
            files[count].matched = 0;
            hash = EVP_MD_CTX_new();
            if (!hash || EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1) {
                EVP_MD_CTX_free(hash);
                free(files[count].path);
                goto done;
            }
        }
        while ((got = archive_read_data(a, buffer, sizeof buffer)) > 0) {
            if (hash) actual += (unsigned long long)got;
            if (hash && EVP_DigestUpdate(hash, buffer, (size_t)got) != 1) break;
            if (is_manifest) {
                char *next;
                if ((size_t)got > 16 * 1024 * 1024 - manifest_size) break;
                next = realloc(manifest, manifest_size + (size_t)got + 1);
                if (!next) break;
                manifest = next;
                memcpy(manifest + manifest_size, buffer, (size_t)got);
                manifest_size += (size_t)got;
                manifest[manifest_size] = '\0';
            }
        }
        if (got < 0 || got > 0 ||
            (hash && actual != (unsigned long long)files[count].size) ||
            (hash && (EVP_DigestFinal_ex(hash, files[count].hash, &digest_size) != 1 ||
                      digest_size != 32))) {
            EVP_MD_CTX_free(hash);
            if (hash) free(files[count].path);
            fprintf(stderr, "%s: invalid archive data\n", path);
            goto done;
        }
        if (hash) ++count;
        EVP_MD_CTX_free(hash);
    }
    if (status != ARCHIVE_EOF || !seen) {
        fprintf(stderr, "%s: missing HOLY/files or truncated archive\n", path);
        goto done;
    }
    qsort(files, count, sizeof *files, compare);
    for (i = 1; i < count; ++i)
        if (!strcmp(files[i - 1].path, files[i].path)) {
            fprintf(stderr, "%s: duplicate payload path\n", path);
            goto done;
        }
    ok = validate_manifest(path, manifest ? manifest : "", manifest_size, files, count);
    if (ok) printf("verified %zu regular files\n", count);
done:
    for (i = 0; i < count; ++i) free(files[i].path);
    free(files);
    free(manifest);
    if (a) archive_read_free(a);
    return ok;
}
