#define _POSIX_C_SOURCE 200809L
#include "source.h"
#include "config.h"
#include "state.h"
#include "stage.h"
#include "repo.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct source {
    char id[65];
    char *alias, *definition;
    int active;
};

struct registry {
    struct source *items;
    size_t count;
    unsigned long long revision;
};

static int hash(const char *data, char output[65])
{
    unsigned char bytes[32];
    unsigned int size;
    size_t i;
    if (EVP_Digest(data, strlen(data), bytes, &size, EVP_sha256(), NULL) != 1 || size != 32) return 0;
    for (i = 0; i < 32; ++i) snprintf(output + i * 2, 3, "%02x", bytes[i]);
    return 1;
}

static int valid_hash(const char *text)
{
    return strlen(text) == 64 && strspn(text, "0123456789abcdef") == 64;
}

static void quote(FILE *out, const char *text)
{
    const unsigned char *p = (const unsigned char *)text;
    fputc('"', out);
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') fprintf(out, "\\%c", *p);
        else if (*p < 32 || *p >= 127) fprintf(out, "\\x%02x", *p);
        else fputc(*p, out);
    }
    fputc('"', out);
}

static void clear_registry(struct registry *r)
{
    size_t i;
    for (i = 0; i < r->count; ++i) { free(r->items[i].alias); free(r->items[i].definition); }
    free(r->items);
    memset(r, 0, sizeof *r);
}

static int source_order(const void *a, const void *b)
{
    return strcmp(((const struct source *)a)->id, ((const struct source *)b)->id);
}

static int row_order(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static char *read_fd(int fd)
{
    struct stat st;
    char *data;
    size_t used = 0;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 1 || st.st_size > 32 * 1024 * 1024) return NULL;
    data = malloc((size_t)st.st_size + 1);
    if (!data) return NULL;
    while (used < (size_t)st.st_size) {
        ssize_t n = read(fd, data + used, (size_t)st.st_size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { free(data); return NULL; }
        used += (size_t)n;
    }
    if (memchr(data, 0, used) || data[used - 1] != '\n') { free(data); return NULL; }
    data[used] = 0;
    return data;
}

static int tokens(const char *line, size_t size, char ***v, size_t *n)
{
    char *error = NULL;
    int ok = holy_lex(line, size, v, n, "source registry", 0, &error);
    free(error);
    return ok;
}

static int endpoint_valid(const char *value)
{
    const char *scheme = strstr(value, "://"), *end;
    const unsigned char *p = (const unsigned char *)value;
    if (!scheme || scheme == value || strchr(value, '?') || strchr(value, '#')) return 0;
    for (; *p; ++p) if (*p <= 32 || *p == 127) return 0;
    scheme += 3;
    end = scheme + strcspn(scheme, "/");
    return memchr(scheme, '@', (size_t)(end - scheme)) == NULL;
}

static int definition_valid(const char *text)
{
    const char *line = text;
    unsigned types = 0, urls = 0, repos = 0;
    int ok = 1;
    char *previous = NULL, *repo_name = NULL;
    while (*line && ok) {
        const char *end = strchr(line, '\n');
        char **v = NULL, *canonical = NULL;
        size_t n = 0, size = 0, i;
        ok = end && tokens(line, (size_t)(end - line), &v, &n);
        if (ok && n == 2 && !strcmp(v[0], "type")) ok = v[1][0] && ++types == 1;
        else if (ok && n == 2 && !strcmp(v[0], "url")) ok = ++urls == 1 && endpoint_valid(v[1]);
        else if (ok && n == 3 && !strcmp(v[0], "repo")) {
            ++repos;
            ok = v[1][0] && endpoint_valid(v[2]) && (!repo_name || strcmp(repo_name, v[1]));
            free(repo_name); repo_name = strdup(v[1]);
            if (!repo_name) ok = 0;
        }
        else ok = 0;
        if (ok) {
            FILE *out = open_memstream(&canonical, &size);
            if (!out) ok = 0;
            else {
                fputs(v[0], out);
                for (i = 1; i < n; ++i) { fputc(' ', out); quote(out, v[i]); }
                fputc('\n', out);
                ok = !ferror(out);
                if (fclose(out)) ok = 0;
                if (ok) ok = size == (size_t)(end - line + 1) && !memcmp(line, canonical, size) &&
                             (!previous || strcmp(previous, canonical) < 0);
            }
        }
        free(previous); previous = canonical;
        holy_tokens_free(v, n);
        if (end) line = end + 1;
    }
    free(previous); free(repo_name);
    return ok && types == 1 && (urls || repos);
}

static char *serialize(struct registry *r)
{
    char *data = NULL;
    size_t size = 0, i;
    FILE *out = open_memstream(&data, &size);
    int ok;
    if (!out) return NULL;
    if (r->count) qsort(r->items, r->count, sizeof *r->items, source_order);
    fprintf(out, "format holy-sources-1\nrevision %llu\n", r->revision);
    for (i = 0; i < r->count; ++i) {
        struct source *s = &r->items[i];
        fprintf(out, "source %s ", s->id); quote(out, s->alias);
        fprintf(out, " %s ", s->active ? "active" : "inactive"); quote(out, s->definition);
        fputc('\n', out);
    }
    ok = !ferror(out);
    if (fclose(out)) ok = 0;
    if (!ok || size > 16 * 1024 * 1024) { free(data); return NULL; }
    return data;
}

static int parse_registry(const char *data, struct registry *r)
{
    const char *line = data;
    size_t number = 0;
    if (!*data) return 1;
    while (*line) {
        const char *end = strchr(line, '\n');
        char **v = NULL;
        size_t n = 0, i;
        int ok = end && tokens(line, (size_t)(end - line), &v, &n);
        if (ok && number == 0) ok = n == 2 && !strcmp(v[0], "format") && !strcmp(v[1], "holy-sources-1");
        else if (ok && number == 1) {
            char *last = NULL;
            errno = 0;
            if (n != 2 || strcmp(v[0], "revision") || !v[1][0] || strspn(v[1], "0123456789") != strlen(v[1])) ok = 0;
            else { r->revision = strtoull(v[1], &last, 10); ok = !errno && !*last; }
        } else if (ok && n == 5 && !strcmp(v[0], "source") && valid_hash(v[1]) &&
                   v[2][0] && strcmp(v[2], "local") &&
                   (!strcmp(v[3], "active") || !strcmp(v[3], "inactive")) && definition_valid(v[4])) {
            struct source *grown;
            char id[65];
            int active = !strcmp(v[3], "active");
            ok = hash(v[4], id) && !strcmp(id, v[1]) && r->count < 10000;
            for (i = 0; ok && i < r->count; ++i)
                if (!strcmp(r->items[i].id, id) || (active && r->items[i].active && !strcmp(r->items[i].alias, v[2]))) ok = 0;
            grown = ok ? realloc(r->items, (r->count + 1) * sizeof *grown) : NULL;
            if (!grown) ok = 0;
            else {
                struct source *s;
                r->items = grown; s = &grown[r->count++]; memset(s, 0, sizeof *s);
                memcpy(s->id, id, 65); s->alias = strdup(v[2]); s->definition = strdup(v[4]); s->active = active;
                ok = s->alias && s->definition;
            }
        } else ok = 0;
        holy_tokens_free(v, n);
        if (!ok) return 0;
        ++number;
        line = end + 1;
    }
    return number >= 2;
}

static char *load_registry(int dir, struct registry *r)
{
    struct stat st;
    int fd = openat(dir, "sources", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    char *data;
    if (fd < 0) return errno == ENOENT ? strdup("") : NULL;
    if (fstat(fd, &st) || (st.st_mode & 0022) || (st.st_uid != 0 && st.st_uid != geteuid())) { close(fd); return NULL; }
    data = read_fd(fd);
    close(fd);
    if (data && !parse_registry(data, r)) { free(data); data = NULL; }
    return data;
}

static char *definition(const struct holy_config *config, const char *section)
{
    char **rows = NULL, *data = NULL;
    size_t count = 0, i, j, size = 0;
    FILE *out = NULL;
    int ok = 0;
    rows = calloc(config->count ? config->count : 1, sizeof *rows);
    if (!rows) goto done;
    for (i = 0; i < config->count; ++i) {
        const struct holy_entry *e = &config->entries[i];
        if (strcmp(e->section, section) || (strcmp(e->key, "type") && strcmp(e->key, "url") && strcmp(e->key, "repo"))) continue;
        out = open_memstream(&rows[count], &size);
        if (!out) goto done;
        ++count;
        fputs(e->key, out);
        for (j = 0; j < e->count; ++j) { fputc(' ', out); quote(out, e->values[j]); }
        fputc('\n', out);
        ok = !ferror(out);
        if (fclose(out)) ok = 0;
        out = NULL;
        if (!ok) goto done;
    }
    qsort(rows, count, sizeof *rows, row_order);
    out = open_memstream(&data, &size);
    if (!out) { ok = 0; goto done; }
    for (i = 0; i < count; ++i) fputs(rows[i], out);
    ok = !ferror(out);
    if (fclose(out)) ok = 0;
    out = NULL;
    if (ok) ok = size <= 1024 * 1024 && definition_valid(data);
done:
    if (out) fclose(out);
    for (i = 0; i < count; ++i) free(rows[i]);
    free(rows);
    if (!ok) { free(data); data = NULL; }
    return data;
}

static void describe_changes(const struct registry *before, const struct registry *after)
{
    size_t i, j, k;
    for (i = 0; i < after->count; ++i) {
        const struct source *next = &after->items[i];
        if (!next->active) continue;
        for (j = 0; j < before->count; ++j) if (!strcmp(next->id, before->items[j].id)) break;
        if (j < before->count && before->items[j].active && !strcmp(next->alias, before->items[j].alias)) continue;
        for (k = 0; k < before->count; ++k)
            if (before->items[k].active && !strcmp(next->alias, before->items[k].alias) && strcmp(next->id, before->items[k].id)) break;
        if (k < before->count) {
            fputs("origin-change ", stderr); quote(stderr, next->alias);
            fprintf(stderr, " %s -> %s\n", before->items[k].id, next->id);
        } else if (j < before->count) {
            fprintf(stderr, "%s %s ", before->items[j].active ? "alias-change" : "reactivate", next->id);
            quote(stderr, before->items[j].alias); fputs(" -> ", stderr); quote(stderr, next->alias); fputc('\n', stderr);
        } else {
            fprintf(stderr, "add-source %s ", next->id); quote(stderr, next->alias); fputc('\n', stderr);
        }
    }
    for (i = 0; i < before->count; ++i) if (before->items[i].active) {
        for (j = 0; j < after->count; ++j)
            if (!strcmp(before->items[i].id, after->items[j].id) && after->items[j].active) break;
        if (j == after->count) {
            fprintf(stderr, "deactivate %s ", before->items[i].id);
            quote(stderr, before->items[i].alias); fputc('\n', stderr);
        }
    }
}

int holy_source_plan(const char *path, const char *root)
{
    struct holy_config config = {0};
    struct registry r = {0}, before = {0};
    struct stat st;
    char *error = NULL, *old = NULL, *next = NULL, base[65];
    int dir = -1, result = 1;
    unsigned long long generation;
    size_t i, j;
    if (!holy_config_load(path, &config, &error)) { fprintf(stderr, "holypkg: %s\n", error ? error : "invalid config"); result = 2; goto done; }
    dir = holy_state_lock(root, 0, &generation, &result);
    if (dir < 0) goto done;
    result = 1;
    old = load_registry(dir, &r);
    if (!old || !parse_registry(old, &before) || fstat(dir, &st) || !hash(old, base)) goto done;
    for (i = 0; i < r.count; ++i) r.items[i].active = 0;
    for (i = 0; i < config.count; ++i) {
        const struct holy_entry *e = &config.entries[i];
        char *text, id[65], *alias;
        if (strncmp(e->section, "source ", 7) || strcmp(e->key, "type")) continue;
        text = definition(&config, e->section);
        if (!text) {
            fputs("holypkg: invalid source endpoints for ", stderr); quote(stderr, e->section + 7);
            fputs("; omit credentials, query and fragment\n", stderr);
            result = 2; goto done;
        }
        if (!hash(text, id)) { free(text); goto done; }
        for (j = 0; j < r.count; ++j) if (!strcmp(r.items[j].id, id)) break;
        if (j < r.count && r.items[j].active) {
            fprintf(stderr, "holypkg: decision-required source-definition-%s: duplicate aliases\n", id);
            free(text); result = 3; goto done;
        }
        alias = strdup(e->section + 7);
        if (!alias) { free(text); goto done; }
        if (j == r.count) {
            struct source *grown = r.count < 10000 ? realloc(r.items, (r.count + 1) * sizeof *grown) : NULL;
            if (!grown) { free(text); free(alias); goto done; }
            r.items = grown; memset(&grown[r.count++], 0, sizeof *grown);
            memcpy(r.items[j].id, id, 65);
            r.items[j].definition = text;
        } else free(text);
        free(r.items[j].alias); r.items[j].alias = alias; r.items[j].active = 1;
    }
    next = serialize(&r);
    if (!next) goto done;
    if (strcmp(next, old)) {
        if (r.revision == ULLONG_MAX) { result = 6; goto done; }
        ++r.revision; free(next); next = serialize(&r);
        if (!next) goto done;
    }
    describe_changes(&before, &r);
    printf("format holy-source-plan-1\nbase %s\ngeneration %llu\ndatabase %ju:%ju\n%s", base,
           generation, (uintmax_t)st.st_dev, (uintmax_t)st.st_ino, next);
    result = ferror(stdout) ? 1 : 0;
done:
    if (result) fprintf(stderr, "holypkg: source plan failed (status %d)\n", result);
    if (dir >= 0) close(dir);
    free(error); free(old); free(next);
    clear_registry(&r); clear_registry(&before); holy_config_free(&config);
    return result;
}

int holy_source_apply(const char *path, const char *approved, const char *root)
{
    struct registry old_registry = {0}, next_registry = {0};
    struct stat st;
    char *snapshot = NULL, *data = NULL, *old = NULL, *header_end, *next, *canonical = NULL;
    char actual[65], base[65], prefix[256], temp_name[43] = {0};
    size_t i, j, used = 0, size;
    int dir = -1, input = -1, temp = -1, result = 1;
    unsigned long long generation;
    if (!valid_hash(approved)) return 2;
    snapshot = holy_stage_local(path, "holy-source-plan");
    input = snapshot ? open(snapshot, O_RDONLY | O_NOFOLLOW | O_CLOEXEC) : -1;
    if (input < 0 || !(data = read_fd(input)) || !hash(data, actual)) goto done;
    if (strcmp(actual, approved)) { result = 3; goto done; }
    dir = holy_state_lock(root, 1, &generation, &result);
    if (dir < 0) goto done;
    result = 1;
    old = load_registry(dir, &old_registry);
    if (!old || !hash(old, base) || fstat(dir, &st)) goto done;
    snprintf(prefix, sizeof prefix, "format holy-source-plan-1\nbase %s\ngeneration %llu\ndatabase %ju:%ju\n", base,
             generation, (uintmax_t)st.st_dev, (uintmax_t)st.st_ino);
    if (strncmp(data, prefix, strlen(prefix))) { result = 3; goto done; }
    header_end = data + strlen(prefix); next = header_end;
    if (!parse_registry(next, &next_registry) || !(canonical = serialize(&next_registry)) || strcmp(next, canonical)) { result = 2; goto done; }
    if (!strcmp(old, next)) { result = 0; goto done; }
    if (old_registry.revision == ULLONG_MAX || next_registry.revision != old_registry.revision + 1) { result = 3; goto done; }
    for (i = 0; i < old_registry.count; ++i) {
        for (j = 0; j < next_registry.count; ++j) if (!strcmp(old_registry.items[i].id, next_registry.items[j].id)) break;
        if (j == next_registry.count || strcmp(old_registry.items[i].definition, next_registry.items[j].definition)) { result = 3; goto done; }
    }
    temp = holy_temporary_at(dir, temp_name);
    if (temp < 0) goto done;
    size = strlen(next);
    while (used < size) {
        ssize_t n = write(temp, next + used, size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto done;
        used += (size_t)n;
    }
    if (fsync(temp) || renameat(dir, temp_name, dir, "sources") || fsync(dir)) goto done;
    result = 0;
done:
    if (temp >= 0) close(temp);
    if (dir >= 0) { if (temp_name[0]) unlinkat(dir, temp_name, 0); close(dir); }
    if (input >= 0) close(input);
    if (snapshot) { unlink(snapshot); free(snapshot); }
    if (result) fprintf(stderr, "holypkg: source apply failed (status %d)\n", result);
    else printf("source-registry revision %llu\n", next_registry.revision);
    free(data); free(old); free(canonical);
    clear_registry(&old_registry); clear_registry(&next_registry);
    return result;
}

int holy_source_list(const char *root)
{
    struct registry r = {0};
    char *data = NULL;
    size_t i;
    unsigned long long generation;
    int result, dir = holy_state_lock(root, 0, &generation, &result);
    if (dir < 0) { fprintf(stderr, "holypkg: source registry unavailable (status %d)\n", result); return result; }
    data = load_registry(dir, &r);
    result = data ? 0 : 1;
    if (data) {
        if (r.count) qsort(r.items, r.count, sizeof *r.items, source_order);
        for (i = 0; i < r.count; ++i) {
            printf("source %s ", r.items[i].id); quote(stdout, r.items[i].alias);
            printf(" %s\n", r.items[i].active ? "active" : "inactive");
        }
        printf("revision %llu sources %zu\n", r.revision, r.count);
        if (ferror(stdout)) result = 1;
    }
    if (result) fprintf(stderr, "holypkg: source registry unavailable (status %d)\n", result);
    close(dir); free(data); clear_registry(&r);
    return result;
}

static char *native_endpoint(const char *definition)
{
    const char *line = definition;
    char *url = NULL;
    int native = 0, unsupported = 0;
    while (*line) {
        const char *end = strchr(line, '\n');
        char **v = NULL;
        size_t n = 0;
        if (!end || !tokens(line, (size_t)(end - line), &v, &n)) {
            holy_tokens_free(v, n);
            free(url);
            return NULL;
        }
        if (n == 2 && !strcmp(v[0], "type")) native = !strcmp(v[1], "holy-http");
        else if (n == 2 && !strcmp(v[0], "url")) {
            free(url);
            url = strdup(v[1]);
            if (!url) { holy_tokens_free(v, n); return NULL; }
        } else if (n == 3 && !strcmp(v[0], "repo")) unsupported = 1;
        holy_tokens_free(v, n);
        line = end + 1;
    }
    if (!native || unsupported) { free(url); return NULL; }
    return url;
}

int holy_source_sync(const char *alias, const char *root, const char *digest,
                     const char *output, const char *ca_file)
{
    struct registry registry = {0};
    char *data = NULL, *url = NULL;
    char source_id[65] = {0};
    unsigned long long generation;
    int dir, result = 1;
    size_t i;
    if (!alias || !*alias || !strcmp(alias, "local") || !digest || !valid_hash(digest) ||
        !output || !*output) return 2;
    dir = holy_state_lock(root, 0, &generation, &result);
    if (dir < 0) return result;
    result = 1;
    data = load_registry(dir, &registry);
    if (!data) goto done;
    result = 6;
    for (i = 0; i < registry.count; ++i)
        if (registry.items[i].active && !strcmp(registry.items[i].alias, alias)) break;
    if (i == registry.count) {
        fputs("holypkg: active source unavailable: ", stderr);
        quote(stderr, alias); fputc('\n', stderr);
        goto done;
    }
    url = native_endpoint(registry.items[i].definition);
    if (!url) {
        fputs("holypkg: source ", stderr);
        quote(stderr, alias); fputs(" requires a single holy-http URL\n", stderr);
        goto done;
    }
    memcpy(source_id, registry.items[i].id, sizeof source_id);
    close(dir); dir = -1;
    result = holy_repo_mirror_source(url, digest, output, ca_file, source_id);
    if (!result) printf("synced source %s index %s\n", source_id, digest);
done:
    if (dir >= 0) close(dir);
    free(data); free(url); clear_registry(&registry);
    return result;
}

int holy_source_record(int database, const char *id, char **record, char registry[65])
{
    struct registry r = {0};
    char *data = load_registry(database, &r), *result = NULL;
    size_t i, size = 0;
    int status = 1;
    FILE *out = NULL;
    *record = NULL;
    if (!data || !hash(data, registry)) goto done;
    status = 6;
    for (i = 0; i < r.count; ++i) if (!strcmp(r.items[i].id, id)) break;
    if (i == r.count || !r.items[i].active) goto done;
    status = 1;
    out = open_memstream(&result, &size);
    if (!out) goto done;
    fprintf(out, "source %s ", id); quote(out, r.items[i].alias); fputc('\n', out);
    status = ferror(out) ? 1 : 0;
    if (fclose(out)) status = 1;
    if (size > 16 * 1024 * 1024) status = 1;
done:
    if (!status) *record = result; else free(result);
    free(data); clear_registry(&r);
    return status;
}

int holy_source_instance(int instance, char id[65], char digest[65])
{
    struct stat st;
    char *data = NULL, **v = NULL;
    size_t count = 0;
    int fd = openat(instance, "source", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC), ok = 0;
    if (fd < 0 || fstat(fd, &st) || (st.st_mode & 0022) ||
        (st.st_uid != 0 && st.st_uid != geteuid())) goto done;
    data = read_fd(fd);
    if (!data || !tokens(data, strlen(data), &v, &count) || count != 3 ||
        strcmp(v[0], "source") || !valid_hash(v[1]) || !v[2][0] ||
        !strcmp(v[2], "local") || !hash(data, digest)) goto done;
    memcpy(id, v[1], 65);
    ok = 1;
done:
    if (fd >= 0) close(fd);
    free(data); holy_tokens_free(v, count);
    return ok;
}
