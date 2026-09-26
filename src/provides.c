#define _POSIX_C_SOURCE 200809L
#include "provides.h"
#include "config.h"
#include "stage.h"
#include "verify.h"

#include <archive.h>
#include <archive_entry.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PROVIDES_LIMIT (1024u * 1024u)

struct capability { char **fields; };

static const char *const capability_kinds[] = {
    "package", "file", "command", "soname", "symbol-version", "build"
};

static int one_of(const char *value, const char *const *options, size_t count)
{
    size_t i;
    for (i = 0; i < count; ++i) if (!strcmp(value, options[i])) return 1;
    return 0;
}

int holy_provides_kind(const char *kind)
{
    return kind && one_of(kind, capability_kinds,
                          sizeof capability_kinds / sizeof *capability_kinds);
}

static int valid(char **v, size_t n)
{
    static const char *const arches[] = {"any", "x86", "x86_64", "noarch"};
    static const char *const libcs[] = {"any", "glibc", "musl", "nolibc"};
    if (n != 7 || strcmp(v[0], "provide")) return 0;
    if (!holy_provides_kind(v[1]) ||
        !one_of(v[3], arches, sizeof arches / sizeof *arches) ||
        !one_of(v[4], libcs, sizeof libcs / sizeof *libcs) ||
        !v[2][0] || !v[5][0] || !v[6][0]) return 0;
    if (!strcmp(v[1], "file") && v[2][0] != '/') return 0;
    if (!strcmp(v[1], "soname") && strchr(v[2], '/')) return 0;
    return 1;
}

static int parse(char *data, size_t size, struct capability **items, size_t *count)
{
    size_t start = 0, pos, line = 0;
    char *error = NULL;
    for (pos = 0; pos <= size; ++pos) {
        char **v = NULL;
        size_t n = 0, i;
        struct capability *next;
        if (pos < size && data[pos] != '\n') continue;
        ++line;
        if (memchr(data + start, '\0', pos - start) || pos - start > 65536 ||
            !holy_lex(data + start, pos - start, &v, &n,
                      "HOLY/provides", line, &error)) {
            fprintf(stderr, "holypkg: HOLY/provides:%zu: %s\n", line,
                    error ? error : "invalid record");
            free(error);
            holy_tokens_free(v, n);
            return 0;
        }
        start = pos + 1;
        if (!n) { holy_tokens_free(v, n); continue; }
        if (!valid(v, n) || *count >= PROVIDES_LIMIT / 7) {
            fprintf(stderr, "holypkg: HOLY/provides:%zu: unsupported capability\n", line);
            holy_tokens_free(v, n);
            return 0;
        }
        for (i = 0; i < *count; ++i) {
            char **existing = (*items)[i].fields;
            if (!strcmp(existing[1], v[1]) && !strcmp(existing[2], v[2]) &&
                !strcmp(existing[3], v[3]) && !strcmp(existing[4], v[4]) &&
                !strcmp(existing[5], v[5])) {
                fprintf(stderr, "holypkg: HOLY/provides:%zu: duplicate capability\n", line);
                holy_tokens_free(v, n);
                return 0;
            }
        }
        next = realloc(*items, (*count + 1) * sizeof **items);
        if (!next) { holy_tokens_free(v, n); return 0; }
        *items = next;
        (*items)[*count].fields = v;
        ++*count;
    }
    return 1;
}

static void print_token(const char *text)
{
    const unsigned char *p = (const unsigned char *)text;
    putchar('"');
    for (; *p; ++p)
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p <= 32 || *p >= 127) printf("\\x%02x", (unsigned int)*p);
        else putchar(*p);
    putchar('"');
}

static void json_string(const char *text)
{
    const unsigned char *p = (const unsigned char *)text;
    putchar('"');
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p >= 32 && *p < 127) putchar(*p);
        else printf("\\u%04x", (unsigned int)*p);
    }
    putchar('"');
}

static int inspect(const char *package, int emit, const char *kind,
                   const char *name, int *matched)
{
    char *snapshot = holy_stage_local(package, "holy-provides");
    char *data = NULL;
    struct archive *archive = NULL;
    struct archive_entry *entry;
    struct capability *items = NULL;
    size_t count = 0, i, j;
    int status, ok = 0, seen = 0;
    if (!snapshot || !holy_verify_with_output(snapshot, 0)) goto done;
    archive = archive_read_new();
    if (!archive || archive_read_support_filter_lz4(archive) != ARCHIVE_OK ||
        archive_read_support_format_tar(archive) != ARCHIVE_OK ||
        archive_read_open_filename(archive, snapshot, 8192) != ARCHIVE_OK) goto done;
    while ((status = archive_read_next_header(archive, &entry)) == ARCHIVE_OK) {
        if (!strcmp(archive_entry_pathname(entry), "HOLY/provides")) {
            la_int64_t size = archive_entry_size(entry);
            size_t used = 0;
            if (seen++ || size < 0 || size > PROVIDES_LIMIT) goto done;
            data = malloc((size_t)size + 1);
            if (!data) goto done;
            while (used < (size_t)size) {
                la_ssize_t got = archive_read_data(archive, data + used,
                                                  (size_t)size - used);
                if (got <= 0) goto done;
                used += (size_t)got;
            }
            data[used] = '\0';
            if (!parse(data, used, &items, &count)) goto done;
        } else if (archive_read_data_skip(archive) != ARCHIVE_OK) goto done;
    }
    if (status != ARCHIVE_EOF || !seen) goto done;
    if (matched) {
        for (i = 0; i < count; ++i)
            if (!strcmp(items[i].fields[1], kind) &&
                !strcmp(items[i].fields[2], name)) *matched = 1;
    }
    if (emit == 1) {
        for (i = 0; i < count; ++i) {
            fputs("provide", stdout);
            for (j = 1; j < 7; ++j) {
                putchar(' ');
                print_token(items[i].fields[j]);
            }
            putchar('\n');
        }
        printf("capabilities %zu\n", count);
    } else if (emit == 2) {
        static const char *const keys[] = {
            "kind", "name", "arch", "libc", "version", "evidence"
        };
        for (i = 0; i < count; ++i) {
            fputs("{\"schema\":\"holy-provides-1\",\"type\":\"capability\"", stdout);
            for (j = 1; j < 7; ++j) {
                printf(",\"%s\":", keys[j - 1]);
                json_string(items[i].fields[j]);
            }
            puts("}");
        }
        printf("{\"schema\":\"holy-provides-1\",\"type\":\"summary\",\"count\":%zu}\n", count);
    }
    ok = 1;
done:
    if (!ok) {
        fprintf(stderr, "holypkg: capabilities inspection failed\n");
        if (emit == 2)
            puts("{\"schema\":\"holy-provides-1\",\"type\":\"error\",\"code\":\"invalid-provides\"}");
    }
    for (i = 0; i < count; ++i) holy_tokens_free(items[i].fields, 7);
    free(items);
    free(data);
    if (archive) archive_read_free(archive);
    if (snapshot) { unlink(snapshot); free(snapshot); }
    return ok;
}

int holy_provides_local(const char *package, int emit)
{
    return inspect(package, emit, NULL, NULL, NULL);
}

int holy_provides_match(const char *package, const char *kind,
                        const char *name, int *matched)
{
    if (!matched || !holy_provides_kind(kind) || !name || !*name) return 0;
    *matched = 0;
    return inspect(package, 0, kind, name, matched);
}
