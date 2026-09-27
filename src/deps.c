#define _POSIX_C_SOURCE 200809L
#include "deps.h"
#include "config.h"
#include "stage.h"
#include "verify.h"

#include <archive.h>
#include <archive_entry.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEPS_LIMIT (1024u * 1024u)

struct requirement {
    char **fields;
};

static int one_of(const char *value, const char *const *values, size_t count)
{
    size_t i;
    for (i = 0; i < count; ++i) if (!strcmp(value, values[i])) return 1;
    return 0;
}

static int valid_requirement(char **v, size_t n)
{
    static const char *const kinds[] = {
        "package", "file", "command", "soname", "symbol-version", "build", "foreign"
    };
    static const char *const arches[] = {"any", "x86", "x86_64", "noarch"};
    static const char *const libcs[] = {"any", "glibc", "musl", "nolibc"};
    static const char *const relations[] = {"any", "eq", "ge", "le", "gt", "lt"};
    size_t i;
    if (n != 11 || strcmp(v[0], "require") || !v[1][0] || !v[2][0] ||
        !v[4][0] || !v[9][0] || !v[10][0] ||
        !one_of(v[3], kinds, sizeof kinds / sizeof *kinds) ||
        !one_of(v[5], arches, sizeof arches / sizeof *arches) ||
        !one_of(v[6], libcs, sizeof libcs / sizeof *libcs) ||
        !one_of(v[7], relations, sizeof relations / sizeof *relations) ||
        (!strcmp(v[7], "any") ? strcmp(v[8], "-") :
         !v[8][0] || !strcmp(v[8], "-"))) return 0;
    for (i = 0; v[1][i]; ++i)
        if (!((v[1][i] >= 'a' && v[1][i] <= 'z') ||
              (v[1][i] >= 'A' && v[1][i] <= 'Z') ||
              (v[1][i] >= '0' && v[1][i] <= '9') ||
              v[1][i] == '-' || v[1][i] == '_' || v[1][i] == '.')) return 0;
    return 1;
}

static int parse(char *data, size_t length, struct requirement **items,
                 size_t *count)
{
    size_t start = 0, pos, line = 0;
    char *error = NULL;
    for (pos = 0; pos <= length; ++pos) {
        char **v = NULL;
        size_t n = 0, i;
        struct requirement *next;
        if (pos < length && data[pos] != '\n') continue;
        ++line;
        if (memchr(data + start, '\0', pos - start) || pos - start > 65536 ||
            !holy_lex(data + start, pos - start, &v, &n, "HOLY/deps", line, &error)) {
            fprintf(stderr, "holypkg: HOLY/deps:%zu: %s\n", line,
                    error ? error : "invalid record");
            free(error);
            holy_tokens_free(v, n);
            return 0;
        }
        start = pos + 1;
        if (!n) { holy_tokens_free(v, n); continue; }
        if (!valid_requirement(v, n) || *count >= DEPS_LIMIT / 11) {
            fprintf(stderr, "holypkg: HOLY/deps:%zu: unsupported requirement\n", line);
            holy_tokens_free(v, n);
            return 0;
        }
        for (i = 0; i < *count; ++i)
            if (!strcmp((*items)[i].fields[1], v[1])) {
                fprintf(stderr, "holypkg: HOLY/deps:%zu: duplicate requirement id\n", line);
                holy_tokens_free(v, n);
                return 0;
            }
        next = realloc(*items, (*count + 1) * sizeof **items);
        if (!next) { holy_tokens_free(v, n); return 0; }
        *items = next;
        (*items)[*count].fields = v;
        ++*count;
    }
    return 1;
}

static void print_token(const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    putchar('"');
    for (; *p; ++p)
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p <= 32 || *p >= 127) printf("\\x%02x", (unsigned int)*p);
        else putchar(*p);
    putchar('"');
}

static void json_string(const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    putchar('"');
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p >= 32 && *p < 127) putchar(*p);
        else printf("\\u%04x", (unsigned int)*p);
    }
    putchar('"');
}

static int inspect_local(const char *package, int emit, size_t *result_count,
                         holy_requirement_visit visitor, void *opaque)
{
    char *snapshot = holy_stage_local(package, "holy-deps");
    char *data = NULL;
    struct archive *archive = NULL;
    struct archive_entry *entry;
    struct requirement *items = NULL;
    size_t count = 0, i, j;
    int status, ok = 0, seen = 0;
    if (!snapshot || !holy_verify_with_output(snapshot, 0)) goto done;
    archive = archive_read_new();
    if (!archive || archive_read_support_filter_lz4(archive) != ARCHIVE_OK ||
        archive_read_support_format_tar(archive) != ARCHIVE_OK ||
        archive_read_open_filename(archive, snapshot, 8192) != ARCHIVE_OK) goto done;
    while ((status = archive_read_next_header(archive, &entry)) == ARCHIVE_OK) {
        if (!strcmp(archive_entry_pathname(entry), "HOLY/deps")) {
            la_int64_t size = archive_entry_size(entry);
            size_t used = 0;
            if (seen++ || size < 0 || size > DEPS_LIMIT) goto done;
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
    if (visitor) for (i = 0; i < count; ++i) {
        char **v = items[i].fields;
        if (!visitor(opaque, v[1], v[2], v[3], v[4], v[5], v[6],
                     v[7], v[8], v[9], v[10])) goto done;
    }
    if (result_count) *result_count = count;
    if (emit == 1) {
        for (i = 0; i < count; ++i) {
            fputs("require", stdout);
            for (j = 1; j < 11; ++j) {
                putchar(' ');
                print_token(items[i].fields[j]);
            }
            putchar('\n');
        }
        printf("requirements %zu\n", count);
    } else if (emit == 2) {
        static const char *const keys[] = {
            "id", "consumer", "kind", "name", "arch", "libc",
            "relation", "version", "original", "evidence"
        };
        for (i = 0; i < count; ++i) {
            fputs("{\"schema\":\"holy-requirements-1\",\"type\":\"requirement\"", stdout);
            for (j = 1; j < 11; ++j) {
                printf(",\"%s\":", keys[j - 1]);
                json_string(items[i].fields[j]);
            }
            puts("}");
        }
        printf("{\"schema\":\"holy-requirements-1\",\"type\":\"summary\",\"count\":%zu}\n", count);
    }
    ok = 1;
done:
    if (!ok) {
        fprintf(stderr, "holypkg: requirements inspection failed\n");
        if (emit == 2)
            puts("{\"schema\":\"holy-requirements-1\",\"type\":\"error\",\"code\":\"invalid-requirements\"}");
    }
    for (i = 0; i < count; ++i) holy_tokens_free(items[i].fields, 11);
    free(items);
    free(data);
    if (archive) archive_read_free(archive);
    if (snapshot) { unlink(snapshot); free(snapshot); }
    return ok;
}

int holy_deps_local(const char *package)
{
    return holy_deps_local_with_output(package, 1);
}

int holy_deps_local_with_output(const char *package, int emit)
{
    return inspect_local(package, emit, NULL, NULL, NULL);
}

int holy_deps_count(const char *package, size_t *count)
{
    *count = 0;
    return inspect_local(package, 0, count, NULL, NULL);
}

int holy_deps_visit(const char *package, holy_requirement_visit visitor,
                    void *opaque)
{
    return visitor && inspect_local(package, 0, NULL, visitor, opaque);
}
