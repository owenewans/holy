#define _POSIX_C_SOURCE 200809L
#include "package.h"
#include "config.h"
#include "version.h"

#include <archive.h>
#include <archive_entry.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define META_LIMIT (1024u * 1024u)

static const char *const fields[] = {
    "format", "name", "version", "release", "os", "arch", "libc", "x-version-family"
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

static int one_of(const char *value, const char *a, const char *b,
                  const char *c)
{
    return !strcmp(value, a) || !strcmp(value, b) ||
           (c && !strcmp(value, c));
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

static int read_meta(const char *path, const char *data, size_t length, int emit,
                     char **arch, char **libc, struct holy_package_identity *identity)
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
    if (ok) for (i = 0; i < 7; ++i) {
        if (!values[i]) {
            fprintf(stderr, "%s: HOLY/meta: missing %s\n", path, fields[i]);
            ok = 0;
        }
    }
    if (ok && strcmp(values[0], "holy-package-1")) {
        fprintf(stderr, "%s: unsupported format %s\n", path, values[0]);
        ok = 0;
    }
    if (ok && !one_of(values[4], "linux", "windows", NULL)) {
        fprintf(stderr, "%s: unsupported os in HOLY/meta\n", path);
        ok = 0;
    }
    if (ok && !one_of(values[5], "x86", "x86_64", "noarch")) {
        fprintf(stderr, "%s: unsupported arch in HOLY/meta\n", path);
        ok = 0;
    }
    if (ok && !one_of(values[6], "glibc", "musl", "nolibc")) {
        fprintf(stderr, "%s: unsupported libc in HOLY/meta\n", path);
        ok = 0;
    }
    if (ok && !strcmp(values[5], "noarch") && strcmp(values[6], "nolibc")) {
        fprintf(stderr, "%s: noarch requires nolibc in HOLY/meta\n", path);
        ok = 0;
    }
    if (ok && values[7] && !strcmp(values[7], "holy")) {
        int order;
        if (!holy_version_compare(values[2], values[2], &order) ||
            !holy_version_compare(values[3], values[3], &order)) {
            fprintf(stderr, "%s: invalid Holy native version or release in HOLY/meta\n", path);
            ok = 0;
        }
    }
    if (ok && emit) for (i = 0; i < sizeof fields / sizeof *fields; ++i)
        if (values[i]) printf("%s %s\n", fields[i], values[i]);
    if (ok && arch && libc) {
        *arch = strdup(values[5]);
        *libc = strdup(values[6]);
        if (!*arch || !*libc) {
            free(*arch);
            free(*libc);
            *arch = *libc = NULL;
            ok = 0;
        }
    }
    if (ok && identity) {
        identity->version_family = values[7]; values[7] = NULL;
        identity->name = values[1]; values[1] = NULL;
        identity->version = values[2]; values[2] = NULL;
        identity->release = values[3]; values[3] = NULL;
        identity->os = values[4]; values[4] = NULL;
        identity->arch = values[5]; values[5] = NULL;
        identity->libc = values[6]; values[6] = NULL;
    }
    for (i = 0; i < sizeof fields / sizeof *fields; ++i) free(values[i]);
    free(error);
    return ok;
}

static int inspect(const char *path, int emit, char **arch, char **libc,
                   struct holy_package_identity *identity)
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
    struct stat input_stat;
    fp = fopen(path, "rb");
    if (!fp) { perror(path); return 0; }
    if (identity && (fstat(fileno(fp), &input_stat) || !S_ISREG(input_stat.st_mode) ||
                     input_stat.st_size < 0)) goto done;
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
    ok = read_meta(path, meta ? meta : "", meta_size, emit, arch, libc, identity);
    if (ok && identity) {
        for (i = 0; i < digest_size; ++i)
            snprintf(identity->digest + i * 2, 3, "%02x", digest[i]);
        identity->digest[64] = '\0';
        identity->size = (uint64_t)input_stat.st_size;
    }
    if (ok && emit) {
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

int holy_package_inspect(const char *path, int emit)
{
    return inspect(path, emit, NULL, NULL, NULL);
}

int holy_package_tags(const char *path, char **arch, char **libc)
{
    *arch = *libc = NULL;
    return inspect(path, 0, arch, libc, NULL);
}

int holy_package_identity(const char *path, struct holy_package_identity *out)
{
    memset(out, 0, sizeof *out);
    return inspect(path, 0, NULL, NULL, out);
}

void holy_package_identity_free(struct holy_package_identity *info)
{
    free(info->name);
    free(info->version);
    free(info->release);
    free(info->version_family);
    free(info->os);
    free(info->arch);
    free(info->libc);
    memset(info, 0, sizeof *info);
}

int holy_package_info(const char *path)
{
    return holy_package_inspect(path, 1);
}
