#define _POSIX_C_SOURCE 200809L
#include "package.h"
#include "config.h"

#include <archive.h>
#include <archive_entry.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define META_LIMIT (1024u * 1024u)

static const char *const fields[] = {
    "format", "name", "version", "release", "os", "arch", "libc"
};

static const char *const members[] = {
    "HOLY/meta", "HOLY/files", "HOLY/deps", "HOLY/provides",
    "HOLY/hooks", "HOLY/origin", "HOLY/transform"
};

static int safe_value(const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    if (!*p) return 0;
    while (*p) {
        if (*p < 32 || *p == 127) return 0;
        ++p;
    }
    return 1;
}

int holy_safe_archive_path(const char *name)
{
    const char *part, *end;
    size_t n;
    if (!name || !*name || name[0] == '/' ||
        (strcmp(name, "HOLY") && strcmp(name, "DATA") &&
         strncmp(name, "HOLY/", 5) && strncmp(name, "DATA/", 5))) return 0;
    part = name;
    while (*part) {
        end = strchr(part, '/');
        n = end ? (size_t)(end - part) : strlen(part);
        if (!n || (n == 1 && part[0] == '.') ||
            (n == 2 && part[0] == '.' && part[1] == '.')) return 0;
        if (!end) break;
        part = end + 1;
        if (!*part) return 1;
    }
    return 1;
}

static int meta_line(char *line, size_t len, const char *path, size_t number,
                     char **values, char **error)
{
    char **v = NULL;
    size_t count = 0, i;
    if (memchr(line, '\0', len)) {
        fprintf(stderr, "%s: HOLY/meta:%zu: NUL byte\n", path, number);
        return 0;
    }
    if (!holy_lex(line, len, &v, &count, path, number, error)) {
        fprintf(stderr, "%s\n", *error ? *error : "out of memory");
        holy_tokens_free(v, count);
        return 0;
    }
    if (!count) { holy_tokens_free(v, count); return 1; }
    if (count != 2 || !safe_value(v[0]) || !safe_value(v[1])) {
        fprintf(stderr, "%s: HOLY/meta:%zu: invalid field\n", path, number);
        holy_tokens_free(v, count);
        return 0;
    }
    if (!strcmp(v[0], "requires-feature")) {
        fprintf(stderr, "%s: HOLY/meta:%zu: unsupported feature\n", path, number);
        holy_tokens_free(v, count);
        return 0;
    }
    for (i = 0; i < sizeof fields / sizeof *fields; ++i) {
        if (strcmp(fields[i], v[0])) continue;
        if (values[i]) {
            fprintf(stderr, "%s: HOLY/meta:%zu: duplicate %s\n", path, number, v[0]);
            holy_tokens_free(v, count);
            return 0;
        }
        values[i] = v[1];
        v[1] = NULL;
        break;
    }
    holy_tokens_free(v, count);
    return 1;
}

static int read_meta(const char *path, const char *data, size_t length)
{
    size_t i, start = 0, line = 1;
    char *values[sizeof fields / sizeof *fields] = {0};
    char *error = NULL;
    int ok = 1;
    for (i = 0; i <= length; ++i) {
        if (i != length && data[i] != '\n') continue;
        if (!meta_line((char *)data + start, i - start, path, line++, values, &error)) {
            ok = 0;
            break;
        }
        start = i + 1;
    }
    if (ok) for (i = 0; i < sizeof fields / sizeof *fields; ++i) {
        if (!values[i]) {
            fprintf(stderr, "%s: HOLY/meta: missing %s\n", path, fields[i]);
            ok = 0;
        }
    }
    if (ok && strcmp(values[0], "holy-package-1")) {
        fprintf(stderr, "%s: unsupported format %s\n", path, values[0]);
        ok = 0;
    }
    if (ok) for (i = 0; i < sizeof fields / sizeof *fields; ++i)
        printf("%s %s\n", fields[i], values[i]);
    for (i = 0; i < sizeof fields / sizeof *fields; ++i) free(values[i]);
    free(error);
    return ok;
}

int holy_package_info(const char *path)
{
    static const unsigned char magic[] = {0x04, 0x22, 0x4d, 0x18};
    unsigned char head[4];
    char buffer[8192], *meta = NULL;
    struct archive *a = NULL;
    struct archive_entry *entry;
    EVP_MD_CTX *digest_ctx = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_size = 0;
    FILE *fp;
    size_t meta_size = 0, n, i;
    int status, ok = 0;
    unsigned char seen[sizeof members / sizeof *members] = {0};
    fp = fopen(path, "rb");
    if (!fp) { perror(path); return 0; }
    if (fread(head, 1, sizeof head, fp) != sizeof head ||
        memcmp(head, magic, sizeof head)) {
        fprintf(stderr, "%s: expected LZ4 frame\n", path);
        goto done;
    }
    digest_ctx = EVP_MD_CTX_new();
    if (!digest_ctx || EVP_DigestInit_ex(digest_ctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "%s: SHA-256 initialization failed\n", path);
        goto done;
    }
    if (fseek(fp, 0, SEEK_SET)) goto done;
    while ((n = fread(buffer, 1, sizeof buffer, fp)) > 0)
        if (EVP_DigestUpdate(digest_ctx, buffer, n) != 1) goto done;
    if (ferror(fp) || EVP_DigestFinal_ex(digest_ctx, digest, &digest_size) != 1 ||
        digest_size != 32) {
        fprintf(stderr, "%s: SHA-256 read failed\n", path);
        goto done;
    }
    if (fseek(fp, 0, SEEK_SET)) {
        fprintf(stderr, "%s: rewind failed\n", path);
        goto done;
    }
    a = archive_read_new();
    if (!a || archive_read_support_filter_lz4(a) != ARCHIVE_OK ||
        archive_read_support_format_tar(a) != ARCHIVE_OK ||
        archive_read_open_FILE(a, fp) != ARCHIVE_OK) {
        fprintf(stderr, "%s: archive open: %s\n", path,
                a ? archive_error_string(a) : "out of memory");
        goto done;
    }
    while ((status = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        const char *name = archive_entry_pathname(entry);
        int is_meta = name && !strcmp(name, "HOLY/meta");
        la_ssize_t got;
        if (!holy_safe_archive_path(name)) {
            fprintf(stderr, "%s: unsafe or unexpected archive path\n", path);
            goto done;
        }
        if ((!strcmp(name, "HOLY") || !strcmp(name, "HOLY/") ||
             !strcmp(name, "DATA") || !strcmp(name, "DATA/")) &&
            archive_entry_filetype(entry) != AE_IFDIR) {
            fprintf(stderr, "%s: archive root marker is not a directory\n", path);
            goto done;
        }
        for (i = 0; i < sizeof members / sizeof *members; ++i) {
            if (strcmp(name, members[i])) continue;
            if (seen[i]++ || archive_entry_filetype(entry) != AE_IFREG ||
                archive_entry_hardlink(entry) || archive_entry_size(entry) < 0 ||
                (is_meta && archive_entry_size(entry) > META_LIMIT)) {
                fprintf(stderr, "%s: invalid or repeated %s\n", path, members[i]);
                goto done;
            }
            break;
        }
        while ((got = archive_read_data(a, buffer, sizeof buffer)) > 0) {
            if (is_meta) {
                if ((size_t)got > META_LIMIT - meta_size) {
                    fprintf(stderr, "%s: oversized HOLY/meta\n", path);
                    goto done;
                }
                {
                    char *next = realloc(meta, meta_size + (size_t)got + 1);
                    if (!next) { fprintf(stderr, "%s: out of memory\n", path); goto done; }
                    meta = next;
                }
                memcpy(meta + meta_size, buffer, (size_t)got);
                meta_size += (size_t)got;
                meta[meta_size] = '\0';
            }
        }
        if (got < 0) { fprintf(stderr, "%s: archive data: %s\n", path, archive_error_string(a)); goto done; }
    }
    if (status != ARCHIVE_EOF) {
        fprintf(stderr, "%s: archive header: %s\n", path, archive_error_string(a));
        goto done;
    }
    for (i = 0; i < sizeof members / sizeof *members; ++i)
        if (!seen[i]) {
            fprintf(stderr, "%s: missing %s\n", path, members[i]);
            goto done;
        }
    ok = read_meta(path, meta ? meta : "", meta_size);
    if (ok) {
        fputs("sha256 ", stdout);
        for (i = 0; i < digest_size; ++i) printf("%02x", digest[i]);
        putchar('\n');
    }
done:
    if (a) archive_read_free(a);
    fclose(fp);
    free(meta);
    EVP_MD_CTX_free(digest_ctx);
    return ok;
}
