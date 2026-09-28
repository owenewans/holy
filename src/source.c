#define _XOPEN_SOURCE 700
#include "source.h"
#include "config.h"
#include "state.h"
#include "stage.h"
#include "repo.h"
#include "fetch.h"
#include "sign.h"
#include "git.h"
#include "../backends/apk.h"
#include "../backends/apt-release.h"
#include "../backends/xbps.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

struct source {
    char id[65];
    char *alias, *definition, *trust, *family;
    char key[65], parent[65];
    int active, priority;
};

struct registry {
    struct source *items;
    size_t count;
    unsigned long long revision;
};

static const char *source_public_key(const struct source *source, char spec[69])
{
    if (!source->key[0]) return NULL;
    memcpy(spec, "raw:", 4);
    memcpy(spec + 4, source->key, 65);
    return spec;
}

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
    for (i = 0; i < r->count; ++i) {
        free(r->items[i].alias); free(r->items[i].definition);
        free(r->items[i].trust); free(r->items[i].family);
    }
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
    fprintf(out, "format holy-sources-3\nrevision %llu\n", r->revision);
    for (i = 0; i < r->count; ++i) {
        struct source *s = &r->items[i];
        fprintf(out, "source %s ", s->id); quote(out, s->alias);
        fprintf(out, " %s ", s->active ? "active" : "inactive"); quote(out, s->definition);
        fprintf(out, " %s %s %s ", s->trust, s->key[0] ? s->key : "-",
                s->parent[0] ? s->parent : "-");
        quote(out, s->family ? s->family : "-");
        fprintf(out, " %d\n", s->priority);
    }
    ok = !ferror(out);
    if (fclose(out)) ok = 0;
    if (!ok || size > 16 * 1024 * 1024) { free(data); return NULL; }
    return data;
}

static int parse_registry(const char *data, struct registry *r)
{
    const char *line = data;
    size_t number = 0, i;
    int version = 0;
    if (!*data) return 1;
    while (*line) {
        const char *end = strchr(line, '\n');
        char **v = NULL;
        size_t n = 0;
        int ok = end && tokens(line, (size_t)(end - line), &v, &n);
        if (ok && number == 0) {
            version = n == 2 && !strcmp(v[0], "format") && !strcmp(v[1], "holy-sources-1") ? 1 :
                      n == 2 && !strcmp(v[0], "format") && !strcmp(v[1], "holy-sources-2") ? 2 :
                      n == 2 && !strcmp(v[0], "format") && !strcmp(v[1], "holy-sources-3") ? 3 : 0;
            ok = version != 0;
        }
        else if (ok && number == 1) {
            char *last = NULL;
            errno = 0;
            if (n != 2 || strcmp(v[0], "revision") || !v[1][0] || strspn(v[1], "0123456789") != strlen(v[1])) ok = 0;
            else { r->revision = strtoull(v[1], &last, 10); ok = !errno && !*last; }
        } else if (ok && ((version == 1 && n >= 5 && n <= 7) ||
                          (version == 2 && n == 8) ||
                          (version == 3 && n == 10)) &&
                   !strcmp(v[0], "source") && valid_hash(v[1]) &&
                   v[2][0] && strcmp(v[2], "local") &&
                   (!strcmp(v[3], "active") || !strcmp(v[3], "inactive")) &&
                   definition_valid(v[4]) &&
                   (n == 5 || !strcmp(v[5], "warn") || !strcmp(v[5], "require") ||
                    !strcmp(v[5], "ignore")) &&
                   (version == 1 ? n < 7 || valid_hash(v[6]) :
                    (!strcmp(v[6], "-") || valid_hash(v[6])) &&
                    (!strcmp(v[7], "-") || valid_hash(v[7]))) &&
                   (version != 3 || (!strcmp(v[8], "-") ||
                     (v[8][0] && strlen(v[8]) <= 128)))) {
            struct source *grown;
            char id[65];
            int active = !strcmp(v[3], "active");
            long priority = 0;
            char *end_priority = NULL;
            if (version == 3) {
                errno = 0;
                priority = strtol(v[9], &end_priority, 10);
                if (errno || !v[9][0] || *end_priority || priority < INT_MIN ||
                    priority > INT_MAX) ok = 0;
            }
            ok = ok && hash(v[4], id) && !strcmp(id, v[1]) && r->count < 10000 &&
                 !(((version == 1 && n == 6) ||
                    (version >= 2 && !strcmp(v[6], "-"))) &&
                   !strcmp(v[5], "require") &&
                   (strstr(v[4], "type \"holy-http\"\n") ||
                    strstr(v[4], "type \"holy-git\"\n") ||
                    strstr(v[4], "type \"apk\"\n") ||
                    strstr(v[4], "type \"apt\"\n") ||
                    strstr(v[4], "type \"xbps\"\n")));
            for (i = 0; ok && i < r->count; ++i)
                if (!strcmp(r->items[i].id, id) || (active && r->items[i].active && !strcmp(r->items[i].alias, v[2]))) ok = 0;
            grown = ok ? realloc(r->items, (r->count + 1) * sizeof *grown) : NULL;
            if (!grown) ok = 0;
            else {
                struct source *s;
                r->items = grown; s = &grown[r->count++]; memset(s, 0, sizeof *s);
                memcpy(s->id, id, 65); s->alias = strdup(v[2]);
                s->definition = strdup(v[4]); s->trust = strdup(n >= 6 ? v[5] : "warn");
                if ((version == 1 && n == 7) || (version >= 2 && strcmp(v[6], "-")))
                    memcpy(s->key, v[6], 65);
                if (version >= 2 && strcmp(v[7], "-")) memcpy(s->parent, v[7], 65);
                if (version == 3 && strcmp(v[8], "-")) s->family = strdup(v[8]);
                s->priority = (int)priority;
                s->active = active;
                ok = s->alias && s->definition && s->trust &&
                     (version != 3 || !strcmp(v[8], "-") || s->family);
            }
        } else ok = 0;
        holy_tokens_free(v, n);
        if (!ok) return 0;
        ++number;
        line = end + 1;
    }
    if (number < 2) return 0;
    for (number = 0; number < r->count; ++number) if (r->items[number].parent[0]) {
        size_t depth = 0, current = number;
        while (r->items[current].parent[0]) {
            for (i = 0; i < r->count; ++i)
                if (!strcmp(r->items[i].id, r->items[current].parent)) break;
            if (i == r->count || i == number || ++depth > r->count) return 0;
            current = i;
        }
    }
    return 1;
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

static const struct holy_entry *config_field(const struct holy_config *config,
                                              const char *section, const char *key)
{
    size_t i;
    for (i = 0; i < config->count; ++i)
        if (!strcmp(config->entries[i].section, section) &&
            !strcmp(config->entries[i].key, key)) return &config->entries[i];
    return NULL;
}

static char *source_key_path(const struct holy_entry *entry)
{
    const char *name = entry->values[0], *slash;
    char *path, *resolved;
    size_t a, b;
    if (name[0] == '/') return realpath(name, NULL);
    slash = strrchr(entry->file, '/');
    a = slash ? (size_t)(slash - entry->file + 1) : 0;
    b = strlen(name);
    if (a > (size_t)-1 - b - 1) return NULL;
    path = malloc(a + b + 1);
    if (!path) return NULL;
    memcpy(path, entry->file, a);
    memcpy(path + a, name, b + 1);
    resolved = realpath(path, NULL);
    free(path);
    return resolved;
}

static void describe_changes(const struct registry *before, const struct registry *after)
{
    size_t i, j, k;
    for (i = 0; i < after->count; ++i) {
        const struct source *next = &after->items[i];
        if (!next->active) continue;
        for (j = 0; j < before->count; ++j) if (!strcmp(next->id, before->items[j].id)) break;
        if (j < before->count && before->items[j].active) {
            const struct source *old = &before->items[j];
            if (strcmp(old->trust, next->trust) || strcmp(old->key, next->key) ||
                strcmp(old->parent, next->parent) ||
                strcmp(old->family ? old->family : "", next->family ? next->family : "") ||
                old->priority != next->priority) {
                fprintf(stderr, "policy-change %s ", next->id);
                quote(stderr, next->alias);
                fprintf(stderr, " trust=%s parent=%s family=", next->trust,
                        next->parent[0] ? next->parent : "-");
                quote(stderr, next->family ? next->family : "-");
                fprintf(stderr, " priority=%d key=%s\n", next->priority,
                        next->key[0] ? next->key : "-");
            }
            if (!strcmp(next->alias, old->alias)) continue;
        }
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
        const struct holy_entry *trust_entry, *key_entry, *raw_entry;
        char *text, id[65], *alias, *trust, *key_path = NULL;
        char key[65] = {0};
        if (strncmp(e->section, "source ", 7) || strcmp(e->key, "type")) continue;
        trust_entry = config_field(&config, e->section, "trust");
        if (!trust_entry) trust_entry = config_field(&config, "general", "trust");
        key_entry = config_field(&config, e->section, "public-key");
        raw_entry = config_field(&config, e->section, "public-key-ed25519");
        trust = strdup(trust_entry ? trust_entry->values[0] : "warn");
        if (!trust) goto done;
        if (key_entry && raw_entry) {
            fputs("holypkg: source accepts one public key form\n", stderr);
            free(trust); result = 2; goto done;
        }
        if (key_entry) {
            key_path = source_key_path(key_entry);
            if (!key_path ||
                (!strcmp(e->values[0], "apk") ?
                 !holy_apk_key_fingerprint(key_path, key) :
                 !strcmp(e->values[0], "apt") ?
                 !holy_apt_key_fingerprint(key_path, key) :
                 !strcmp(e->values[0], "xbps") ?
                 !holy_xbps_key_fingerprint(key_path, key) :
                 !holy_public_key_hex(key_path, key))) {
                fprintf(stderr, "holypkg: invalid %s public key at %s:%zu\n",
                        !strcmp(e->values[0], "apk") ? "APK RSA" :
                        !strcmp(e->values[0], "apt") ? "APT keyring" :
                        !strcmp(e->values[0], "xbps") ? "XBPS RSA" : "Ed25519",
                        key_entry->file, key_entry->line);
                free(key_path); free(trust); result = 2; goto done;
            }
            free(key_path);
        } else if (raw_entry) {
            if (!strcmp(e->values[0], "apk") || !strcmp(e->values[0], "apt") ||
                !strcmp(e->values[0], "xbps") ||
                !valid_hash(raw_entry->values[0])) {
                fprintf(stderr, "holypkg: invalid Ed25519 raw key at %s:%zu\n",
                        raw_entry->file, raw_entry->line);
                free(trust); result = 2; goto done;
            }
            memcpy(key, raw_entry->values[0], 65);
        }
        if ((!strcmp(e->values[0], "holy-http") ||
             !strcmp(e->values[0], "holy-git") ||
             !strcmp(e->values[0], "apk") ||
             !strcmp(e->values[0], "apt") ||
             !strcmp(e->values[0], "xbps")) &&
            !strcmp(trust, "require") && !key[0]) {
            fprintf(stderr, "holypkg: [%s] trust require needs public-key\n", e->section);
            free(trust); result = 2; goto done;
        }
        if (!strcmp(e->values[0], "apt") || !strcmp(e->values[0], "xbps")) {
            const struct holy_entry *endpoint = config_field(&config, e->section, "url");
            char *probe = endpoint ? holy_fetch_child_url(endpoint->values[0], "probe") : NULL;
            int repos = 0;
            for (j = 0; j < config.count; ++j)
                if (!strcmp(config.entries[j].section, e->section) &&
                    !strcmp(config.entries[j].key, "repo")) repos = 1;
            if (!probe || repos) {
                fprintf(stderr, "holypkg: [%s] %s requires one HTTPS url and no repo entries\n",
                        e->section, e->values[0]);
                free(probe); free(trust); result = 2; goto done;
            }
            free(probe);
        }
        text = definition(&config, e->section);
        if (!text) {
            fputs("holypkg: invalid source endpoints for ", stderr); quote(stderr, e->section + 7);
            fputs("; omit credentials, query and fragment\n", stderr);
            free(trust);
            result = 2; goto done;
        }
        if (!hash(text, id)) { free(text); free(trust); goto done; }
        for (j = 0; j < r.count; ++j) if (!strcmp(r.items[j].id, id)) break;
        if (j < r.count && r.items[j].active) {
            fprintf(stderr, "holypkg: decision-required source-definition-%s: duplicate aliases\n", id);
            free(text); free(trust); result = 3; goto done;
        }
        alias = strdup(e->section + 7);
        if (!alias) { free(text); free(trust); goto done; }
        if (j == r.count) {
            struct source *grown = r.count < 10000 ? realloc(r.items, (r.count + 1) * sizeof *grown) : NULL;
            if (!grown) { free(text); free(alias); free(trust); goto done; }
            r.items = grown; memset(&grown[r.count++], 0, sizeof *grown);
            memcpy(r.items[j].id, id, 65);
            r.items[j].definition = text;
        } else free(text);
        free(r.items[j].trust); r.items[j].trust = trust;
        memcpy(r.items[j].key, key, 65);
        free(r.items[j].alias); r.items[j].alias = alias; r.items[j].active = 1;
    }
    for (i = 0; i < r.count; ++i) if (r.items[i].active) {
        const struct holy_entry *parent, *family, *priority;
        char *section;
        size_t length = strlen(r.items[i].alias);
        if (length > SIZE_MAX - sizeof "source ") { result = 2; goto done; }
        section = malloc(length + sizeof "source ");
        if (!section) goto done;
        snprintf(section, length + sizeof "source ", "source %s", r.items[i].alias);
        parent = config_field(&config, section, "parent");
        family = config_field(&config, section, "family");
        priority = config_field(&config, section, "priority");
        free(section);
        free(r.items[i].family); r.items[i].family = NULL;
        r.items[i].priority = 0;
        if (family) {
            if (!family->values[0][0] || !strcmp(family->values[0], "-") ||
                strlen(family->values[0]) > 128 ||
                !(r.items[i].family = strdup(family->values[0]))) {
                result = 2; goto done;
            }
        }
        if (priority) {
            char *end = NULL;
            long value;
            errno = 0;
            value = strtol(priority->values[0], &end, 10);
            if (errno || !priority->values[0][0] || *end ||
                value < INT_MIN || value > INT_MAX) { result = 2; goto done; }
            r.items[i].priority = (int)value;
        }
        r.items[i].parent[0] = 0;
        if (!parent) continue;
        for (j = 0; j < r.count; ++j)
            if (r.items[j].active && !strcmp(r.items[j].alias, parent->values[0])) break;
        if (j == r.count) { result = 2; goto done; }
        memcpy(r.items[i].parent, r.items[j].id, 65);
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

int holy_source_show(const char *root, const char *alias)
{
    struct registry r = {0};
    unsigned long long generation;
    char *data = NULL;
    size_t i;
    int dir, result = 1;
    if (!root || !alias || !*alias) return 2;
    dir = holy_state_lock(root, 0, &generation, &result);
    if (dir < 0) return result;
    data = load_registry(dir, &r);
    if (!data) goto done;
    result = 6;
    for (i = 0; i < r.count; ++i) if (r.items[i].active && !strcmp(r.items[i].alias, alias)) {
        const struct source *s = &r.items[i];
        printf("source-id %s\nalias ", s->id); quote(stdout, s->alias);
        fputs("\ndefinition\n", stdout);
        fputs(s->definition, stdout);
        printf("trust %s\npublic-key-sha256 %s\nparent-id %s\nfamily ",
               s->trust, s->key[0] ? s->key : "-", s->parent[0] ? s->parent : "-");
        quote(stdout, s->family ? s->family : "-");
        printf("\npriority %d\nrevision %llu\n", s->priority, r.revision);
        result = ferror(stdout) ? 1 : 0;
        break;
    }
done:
    if (result) fprintf(stderr, "holypkg: source %s unavailable (status %d)\n", alias, result);
    free(data); clear_registry(&r); close(dir);
    return result;
}

static int alias_order(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

int holy_source_active_aliases(const char *root, char ***aliases, size_t *count)
{
    struct registry r = {0};
    unsigned long long generation;
    char *data = NULL;
    char **items = NULL;
    size_t i, used = 0;
    int dir, result = 1;
    if (!aliases || !count) return 2;
    *aliases = NULL;
    *count = 0;
    dir = holy_state_lock(root, 0, &generation, &result);
    if (dir < 0) return result;
    data = load_registry(dir, &r);
    if (!data) goto done;
    items = calloc(r.count ? r.count : 1, sizeof *items);
    if (!items) goto done;
    for (i = 0; i < r.count; ++i) if (r.items[i].active) {
        items[used] = strdup(r.items[i].alias);
        if (!items[used]) goto done;
        ++used;
    }
    qsort(items, used, sizeof *items, alias_order);
    *aliases = items;
    *count = used;
    items = NULL;
    result = 0;
done:
    if (items) {
        for (i = 0; i < used; ++i) free(items[i]);
        free(items);
    }
    free(data); clear_registry(&r); close(dir);
    return result;
}

int holy_source_active_id(const char *root, const char *alias, char output[65])
{
    struct registry registry = {0};
    unsigned long long generation;
    char *data = NULL;
    size_t i;
    int dir, result = 1;
    output[0] = 0;
    if (!alias || !*alias || !strcmp(alias, "local")) return 2;
    dir = holy_state_lock(root, 0, &generation, &result);
    if (dir < 0) return result;
    result = 1;
    data = load_registry(dir, &registry);
    if (!data) goto done;
    result = 6;
    for (i = 0; i < registry.count; ++i)
        if (registry.items[i].active && !strcmp(registry.items[i].alias, alias)) {
            memcpy(output, registry.items[i].id, 65);
            result = 0;
            break;
        }
done:
    if (result) {
        fputs("holypkg: active source unavailable: ", stderr);
        quote(stderr, alias); fputc('\n', stderr);
    }
    free(data); clear_registry(&registry); close(dir);
    return result;
}

int holy_source_type(const char *root, const char *alias, char **type)
{
    struct registry registry = {0};
    unsigned long long generation;
    char *data = NULL;
    size_t i;
    int dir, result = 1;
    if (!root || !alias || !*alias || !type) return 2;
    *type = NULL;
    dir = holy_state_lock(root, 0, &generation, &result);
    if (dir < 0) return result;
    data = load_registry(dir, &registry);
    if (!data) goto done;
    result = 6;
    for (i = 0; i < registry.count; ++i)
        if (registry.items[i].active && !strcmp(registry.items[i].alias, alias)) {
            const char *line = registry.items[i].definition;
            while (*line) {
                const char *end = strchr(line, '\n');
                char **v = NULL;
                size_t n = 0;
                if (!end || !tokens(line, (size_t)(end - line), &v, &n)) {
                    holy_tokens_free(v, n); result = 2; goto done;
                }
                if (n == 2 && !strcmp(v[0], "type")) {
                    *type = strdup(v[1]);
                    holy_tokens_free(v, n);
                    result = *type ? 0 : 1;
                    goto done;
                }
                holy_tokens_free(v, n);
                line = end + 1;
            }
            result = 2;
            break;
        }
done:
    free(data); clear_registry(&registry); close(dir);
    return result;
}

int holy_source_parent_id(const char *root, const char *id, char output[65])
{
    struct registry registry = {0};
    unsigned long long generation;
    char *data = NULL;
    size_t i;
    int dir, result = 1;
    if (!root || !id || !valid_hash(id) || !output) return 2;
    output[0] = 0;
    dir = holy_state_lock(root, 0, &generation, &result);
    if (dir < 0) return result;
    data = load_registry(dir, &registry);
    if (!data) goto done;
    result = 6;
    for (i = 0; i < registry.count; ++i)
        if (!strcmp(registry.items[i].id, id)) {
            memcpy(output, registry.items[i].parent, 65);
            result = 0; break;
        }
done:
    free(data); clear_registry(&registry); close(dir);
    return result;
}

int holy_source_rank_info(const char *root, const char *id,
                          char **family, int *priority)
{
    struct registry registry = {0};
    unsigned long long generation;
    char *data = NULL;
    size_t i;
    int dir, result = 1;
    if (!root || !id || !valid_hash(id) || !family || !priority) return 2;
    *family = NULL; *priority = 0;
    dir = holy_state_lock(root, 0, &generation, &result);
    if (dir < 0) return result;
    data = load_registry(dir, &registry);
    if (!data) goto done;
    result = 6;
    for (i = 0; i < registry.count; ++i)
        if (!strcmp(registry.items[i].id, id)) {
            *family = registry.items[i].family ? strdup(registry.items[i].family) : NULL;
            *priority = registry.items[i].priority;
            result = registry.items[i].family && !*family ? 1 : 0;
            break;
        }
done:
    free(data); clear_registry(&registry); close(dir);
    return result;
}

int holy_source_apk_repos(const char *root, const char *alias,
                          char ***repos, size_t *count)
{
    struct registry registry = {0};
    unsigned long long generation;
    char *data = NULL, **items = NULL;
    size_t i, used = 0;
    int dir, result = 1, apk = 0;
    if (!root || !alias || !*alias || !repos || !count) return 2;
    *repos = NULL; *count = 0;
    dir = holy_state_lock(root, 0, &generation, &result);
    if (dir < 0) return result;
    data = load_registry(dir, &registry);
    if (!data) goto done;
    result = 6;
    for (i = 0; i < registry.count; ++i)
        if (registry.items[i].active && !strcmp(registry.items[i].alias, alias)) break;
    if (i == registry.count) goto done;
    {
        const char *line = registry.items[i].definition;
        while (*line) {
            const char *end = strchr(line, '\n');
            char **v = NULL;
            size_t n = 0;
            char **grown;
            if (!end || !tokens(line, (size_t)(end - line), &v, &n)) {
                holy_tokens_free(v, n); result = 2; goto done;
            }
            if (n == 2 && !strcmp(v[0], "type")) apk = !strcmp(v[1], "apk");
            if (n == 3 && !strcmp(v[0], "repo")) {
                grown = realloc(items, (used + 1) * sizeof *items);
                if (!grown) { holy_tokens_free(v, n); result = 1; goto done; }
                items = grown;
                items[used] = strdup(v[1]);
                if (!items[used]) { holy_tokens_free(v, n); result = 1; goto done; }
                ++used;
            }
            holy_tokens_free(v, n);
            line = end + 1;
        }
    }
    if (!apk || !used) goto done;
    qsort(items, used, sizeof *items, alias_order);
    *repos = items; *count = used;
    items = NULL; result = 0;
done:
    if (items) {
        for (i = 0; i < used; ++i) free(items[i]);
        free(items);
    }
    free(data); clear_registry(&registry); close(dir);
    return result;
}

int holy_source_known_id(const char *root, const char *alias, char output[65])
{
    struct registry registry = {0};
    unsigned long long generation;
    char *data = NULL;
    size_t i, matches = 0;
    int dir, result = 1, active = 0;
    output[0] = 0;
    if (!alias || !*alias || !strcmp(alias, "local")) return 2;
    dir = holy_state_lock(root, 0, &generation, &result);
    if (dir < 0) return result;
    data = load_registry(dir, &registry);
    if (!data) goto done;
    result = 6;
    for (i = 0; i < registry.count; ++i) {
        if (strcmp(registry.items[i].alias, alias)) continue;
        if (registry.items[i].active) {
            memcpy(output, registry.items[i].id, 65);
            active = 1;
            matches = 1;
            break;
        }
        if (++matches == 1) memcpy(output, registry.items[i].id, 65);
    }
    if (active || matches == 1) result = 0;
    else if (matches > 1) result = 3;
done:
    if (result) fprintf(stderr, "holypkg: source alias %s for installed package: %s\n",
                        result == 3 ? "ambiguous" : "unavailable", alias);
    free(data); clear_registry(&registry); close(dir);
    return result;
}

static char *native_endpoint(const char *definition, int *git)
{
    const char *line = definition;
    char *url = NULL;
    int native = 0, unsupported = 0;
    if (git) *git = 0;
    while (*line) {
        const char *end = strchr(line, '\n');
        char **v = NULL;
        size_t n = 0;
        if (!end || !tokens(line, (size_t)(end - line), &v, &n)) {
            holy_tokens_free(v, n);
            free(url);
            return NULL;
        }
        if (n == 2 && !strcmp(v[0], "type")) {
            native = !strcmp(v[1], "holy-http") || !strcmp(v[1], "holy-git");
            if (git) *git = !strcmp(v[1], "holy-git");
        }
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

int holy_source_apk_repo(const char *root, const char *alias, const char *repo,
                         char id[65], char **url, char **trust, char key[65])
{
    struct registry registry = {0};
    char *data = NULL, *selected = NULL;
    const char *line;
    unsigned long long generation;
    size_t i;
    int dir, result = 1, apk = 0;
    id[0] = 0;
    if (key) key[0] = 0;
    *url = NULL;
    *trust = NULL;
    if (!alias || !*alias || !strcmp(alias, "local") || !repo || !*repo) return 2;
    dir = holy_state_lock(root, 0, &generation, &result);
    if (dir < 0) return result;
    data = load_registry(dir, &registry);
    if (!data) goto done;
    result = 6;
    for (i = 0; i < registry.count; ++i)
        if (registry.items[i].active && !strcmp(registry.items[i].alias, alias)) break;
    if (i == registry.count) goto done;
    line = registry.items[i].definition;
    while (*line) {
        const char *end = strchr(line, '\n');
        char **v = NULL;
        size_t n = 0;
        if (!end || !tokens(line, (size_t)(end - line), &v, &n)) {
            holy_tokens_free(v, n); result = 2; goto done;
        }
        if (n == 2 && !strcmp(v[0], "type")) apk = !strcmp(v[1], "apk");
        if (n == 3 && !strcmp(v[0], "repo") && !strcmp(v[1], repo)) {
            if (selected) { holy_tokens_free(v, n); result = 2; goto done; }
            selected = strdup(v[2]);
            if (!selected) { holy_tokens_free(v, n); result = 1; goto done; }
        }
        holy_tokens_free(v, n);
        line = end + 1;
    }
    if (!apk || !selected || strncmp(selected, "https://", 8) ||
        selected[strlen(selected) - 1] != '/') goto done;
    *trust = strdup(registry.items[i].trust);
    if (!*trust) { result = 1; goto done; }
    *url = selected; selected = NULL;
    memcpy(id, registry.items[i].id, 65);
    if (key) memcpy(key, registry.items[i].key, 65);
    result = 0;
done:
    if (result) { free(*url); free(*trust); *url = NULL; *trust = NULL; id[0] = 0; if (key) key[0] = 0; }
    free(selected); free(data); clear_registry(&registry); close(dir);
    return result;
}

int holy_source_apt(const char *root, const char *alias,
                    char id[65], char **url, char **trust, char key[65])
{
    struct registry registry = {0};
    char *data = NULL, *selected = NULL;
    const char *line;
    unsigned long long generation;
    size_t i;
    int dir, result = 1, apt = 0, repos = 0;
    id[0] = key[0] = 0;
    *url = *trust = NULL;
    if (!root || !alias || !*alias || !strcmp(alias, "local")) return 2;
    dir = holy_state_lock(root, 0, &generation, &result);
    if (dir < 0) return result;
    data = load_registry(dir, &registry);
    if (!data) goto done;
    result = 6;
    for (i = 0; i < registry.count; ++i)
        if (registry.items[i].active && !strcmp(registry.items[i].alias, alias)) break;
    if (i == registry.count) goto done;
    line = registry.items[i].definition;
    while (*line) {
        const char *end = strchr(line, '\n');
        char **v = NULL;
        size_t n = 0;
        if (!end || !tokens(line, (size_t)(end - line), &v, &n)) {
            holy_tokens_free(v, n); result = 2; goto done;
        }
        if (n == 2 && !strcmp(v[0], "type")) apt = !strcmp(v[1], "apt");
        else if (n == 2 && !strcmp(v[0], "url")) {
            free(selected); selected = strdup(v[1]);
            if (!selected) { holy_tokens_free(v, n); result = 1; goto done; }
        } else if (n == 3 && !strcmp(v[0], "repo")) repos = 1;
        holy_tokens_free(v, n);
        line = end + 1;
    }
    if (!apt || repos || !selected || strncmp(selected, "https://", 8) ||
        selected[strlen(selected) - 1] != '/') goto done;
    *trust = strdup(registry.items[i].trust);
    if (!*trust) { result = 1; goto done; }
    *url = selected; selected = NULL;
    memcpy(id, registry.items[i].id, 65);
    memcpy(key, registry.items[i].key, 65);
    result = 0;
done:
    if (result) {
        free(*url); free(*trust); *url = *trust = NULL;
        id[0] = key[0] = 0;
    }
    free(selected); free(data); clear_registry(&registry); close(dir);
    return result;
}

int holy_source_xbps(const char *root, const char *alias,
                     char id[65], char **url, char **trust, char key[65])
{
    struct registry registry = {0};
    char *data = NULL, *selected = NULL;
    const char *line;
    unsigned long long generation;
    size_t i;
    int dir, result = 1, xbps = 0, repos = 0;
    id[0] = key[0] = 0;
    *url = *trust = NULL;
    if (!root || !alias || !*alias || !strcmp(alias, "local")) return 2;
    dir = holy_state_lock(root, 0, &generation, &result);
    if (dir < 0) return result;
    data = load_registry(dir, &registry);
    if (!data) goto done;
    result = 6;
    for (i = 0; i < registry.count; ++i)
        if (registry.items[i].active && !strcmp(registry.items[i].alias, alias)) break;
    if (i == registry.count) goto done;
    line = registry.items[i].definition;
    while (*line) {
        const char *end = strchr(line, '\n');
        char **v = NULL;
        size_t n = 0;
        if (!end || !tokens(line, (size_t)(end - line), &v, &n)) {
            holy_tokens_free(v, n); result = 2; goto done;
        }
        if (n == 2 && !strcmp(v[0], "type")) xbps = !strcmp(v[1], "xbps");
        else if (n == 2 && !strcmp(v[0], "url")) {
            if (selected) { holy_tokens_free(v, n); result = 2; goto done; }
            selected = strdup(v[1]);
            if (!selected) { holy_tokens_free(v, n); result = 1; goto done; }
        } else if (n == 3 && !strcmp(v[0], "repo")) repos = 1;
        holy_tokens_free(v, n);
        line = end + 1;
    }
    if (!xbps || repos || !selected || strncmp(selected, "https://", 8) ||
        selected[strlen(selected) - 1] != '/') goto done;
    *trust = strdup(registry.items[i].trust);
    if (!*trust) { result = 1; goto done; }
    *url = selected; selected = NULL;
    memcpy(id, registry.items[i].id, 65);
    memcpy(key, registry.items[i].key, 65);
    result = 0;
done:
    if (result) {
        free(*url); free(*trust); *url = *trust = NULL;
        id[0] = key[0] = 0;
    }
    free(selected); free(data); clear_registry(&registry); close(dir);
    return result;
}

int holy_source_catalog(const char *root, const char *alias,
                        const char *catalog, char source_id[65])
{
    struct registry registry = {0};
    unsigned long long generation;
    char *data = NULL, *url = NULL, key_spec[69];
    size_t i;
    int dir, result = 1, git = 0;
    source_id[0] = 0;
    if (!alias || !*alias || !strcmp(alias, "local") || !catalog || !*catalog) return 2;
    dir = holy_state_lock(root, 0, &generation, &result);
    if (dir < 0) return result;
    result = 1;
    data = load_registry(dir, &registry);
    if (!data) goto done;
    result = 6;
    for (i = 0; i < registry.count; ++i)
        if (registry.items[i].active && !strcmp(registry.items[i].alias, alias)) break;
    if (i == registry.count) goto done;
    url = native_endpoint(registry.items[i].definition, &git);
    if (!url) goto done;
    if (!holy_repo_source_catalog(catalog, registry.items[i].id, url,
                                  source_public_key(&registry.items[i], key_spec)) ||
        (git && !holy_git_catalog_commit(catalog, NULL))) goto done;
    memcpy(source_id, registry.items[i].id, 65);
    result = 0;
done:
    if (result) {
        fputs("holypkg: source catalog unavailable for ", stderr);
        quote(stderr, alias); fputc('\n', stderr);
    }
    free(url); free(data); clear_registry(&registry); close(dir);
    return result;
}

static int catalogs_dir(int database, int create)
{
    struct stat st;
    int fd;
    if (create && mkdirat(database, "catalogs", 0700) && errno != EEXIST)
        return -1;
    if (create && fsync(database)) return -1;
    fd = openat(database, "catalogs", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    if (fstat(fd, &st) || !S_ISDIR(st.st_mode) ||
        (st.st_uid != 0 && st.st_uid != geteuid()) || (st.st_mode & 0022)) {
        close(fd); return -1;
    }
    return fd;
}

static int read_catalog_binding(int database, const char *id,
                                char index[65], char **path, int *root_relative)
{
    struct stat st;
    char *data = NULL, *line, **v = NULL;
    size_t n = 0;
    int catalogs = -1, fd = -1, ok = 0;
    *path = NULL;
    *root_relative = 0;
    index[0] = 0;
    catalogs = catalogs_dir(database, 0);
    if (catalogs < 0) goto done;
    fd = openat(catalogs, id, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        (st.st_uid != 0 && st.st_uid != geteuid()) || (st.st_mode & 0022) ||
        st.st_size > 1024 * 1024) goto done;
    data = read_fd(fd);
    if (!data || strncmp(data, "format holy-source-catalog-1\n", 29)) goto done;
    line = data + 29;
    {
        char *end = strchr(line, '\n');
        if (!end || !tokens(line, (size_t)(end - line), &v, &n) ||
            n != 2 || strcmp(v[0], "index") || !valid_hash(v[1])) goto done;
        memcpy(index, v[1], 65);
        holy_tokens_free(v, n); v = NULL; n = 0;
        line = end + 1;
    }
    {
        char *end = strchr(line, '\n');
        if (!end || end[1] || !tokens(line, (size_t)(end - line), &v, &n) ||
            n != 2 || (strcmp(v[0], "path") && strcmp(v[0], "root-path")) ||
            v[1][0] != '/') goto done;
        *root_relative = !strcmp(v[0], "root-path");
        *path = strdup(v[1]);
        ok = *path != NULL;
    }
done:
    holy_tokens_free(v, n);
    free(data);
    if (fd >= 0) close(fd);
    if (catalogs >= 0) close(catalogs);
    if (!ok) { free(*path); *path = NULL; index[0] = 0; }
    return ok;
}

int holy_source_bind_catalog(const char *root, const char *alias,
                             const char *catalog)
{
    struct registry registry = {0};
    char *data = NULL, *url = NULL, *path = NULL, *root_path = NULL, *record = NULL;
    char index[65], key_spec[69], temp_name[43] = {0};
    size_t i, size = 0, used = 0;
    unsigned long long generation;
    FILE *out = NULL;
    int database = -1, catalogs = -1, temp = -1, result = 1, git = 0;
    if (!alias || !*alias || !strcmp(alias, "local") || !catalog || !*catalog)
        return 2;
    database = holy_state_lock(root, 1, &generation, &result);
    if (database < 0) return result;
    data = load_registry(database, &registry);
    if (!data) goto done;
    result = 6;
    for (i = 0; i < registry.count; ++i)
        if (registry.items[i].active && !strcmp(registry.items[i].alias, alias)) break;
    if (i == registry.count) goto done;
    url = native_endpoint(registry.items[i].definition, &git);
    path = realpath(catalog, NULL);
    if (!url || !path || !holy_repo_source_catalog(path, registry.items[i].id, url,
              source_public_key(&registry.items[i], key_spec)) ||
        (git && !holy_git_catalog_commit(path, NULL)) ||
        !holy_repo_catalog_index(path, index)) goto done;
    result = 1;
    out = open_memstream(&record, &size);
    if (!out) goto done;
    root_path = realpath(root, NULL);
    if (!root_path) goto done;
    fprintf(out, "format holy-source-catalog-1\nindex %s\n%s ", index,
            strcmp(root_path, "/") && !strncmp(path, root_path, strlen(root_path)) &&
            path[strlen(root_path)] == '/' ? "root-path" : "path");
    quote(out, strcmp(root_path, "/") && !strncmp(path, root_path, strlen(root_path)) &&
          path[strlen(root_path)] == '/' ? path + strlen(root_path) : path);
    fputc('\n', out);
    {
        int failed = ferror(out);
        if (fclose(out)) failed = 1;
        out = NULL;
        if (failed) goto done;
    }
    catalogs = catalogs_dir(database, 1);
    if (catalogs < 0) goto done;
    temp = holy_temporary_at(catalogs, temp_name);
    if (temp < 0) goto done;
    while (used < size) {
        ssize_t n = write(temp, record + used, size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto done;
        used += (size_t)n;
    }
    if (fsync(temp) || renameat(catalogs, temp_name, catalogs,
                               registry.items[i].id) || fsync(catalogs)) goto done;
    result = 0;
    printf("catalog-bound %s index %s\n", registry.items[i].id, index);
done:
    if (out) fclose(out);
    if (temp >= 0) close(temp);
    if (catalogs >= 0) {
        if (temp_name[0]) unlinkat(catalogs, temp_name, 0);
        close(catalogs);
    }
    if (database >= 0) close(database);
    free(data); free(url); free(path); free(root_path); free(record);
    clear_registry(&registry);
    if (result) fprintf(stderr, "holypkg: source catalog binding failed (status %d)\n", result);
    return result;
}

static int source_catalog_path(const char *root, const char *alias,
                               char **path, int fast)
{
    struct registry registry = {0};
    char *data = NULL, *url = NULL, *saved = NULL, *joined = NULL, *canonical = NULL;
    char expected[65], actual[65], key_spec[69];
    size_t i;
    unsigned long long generation;
    int database = -1, result = 1, root_relative = 0, git = 0;
    *path = NULL;
    if (!alias || !*alias || !strcmp(alias, "local")) return 2;
    database = holy_state_lock(root, 0, &generation, &result);
    if (database < 0) return result;
    data = load_registry(database, &registry);
    if (!data) goto done;
    result = 6;
    for (i = 0; i < registry.count; ++i)
        if (registry.items[i].active && !strcmp(registry.items[i].alias, alias)) break;
    if (i == registry.count) goto done;
    url = native_endpoint(registry.items[i].definition, &git);
    if (!url || !read_catalog_binding(database, registry.items[i].id,
                                      expected, &saved, &root_relative)) goto done;
    if (root_relative) {
        size_t a, b;
        canonical = realpath(root, NULL);
        if (!canonical) goto done;
        a = strlen(canonical); b = strlen(saved);
        if (a > (size_t)-1 - b - 1) goto done;
        joined = malloc(a + b + 1);
        if (!joined) goto done;
        if (!strcmp(canonical, "/")) memcpy(joined, saved, b + 1);
        else {
            memcpy(joined, canonical, a);
            memcpy(joined + a, saved, b + 1);
        }
        free(saved);
        saved = realpath(joined, NULL);
        if (!saved || (strcmp(canonical, "/") &&
                       (strncmp(saved, canonical, a) || saved[a] != '/'))) goto done;
    }
    if (
        !holy_repo_source_catalog(saved, registry.items[i].id, url,
                                  source_public_key(&registry.items[i], key_spec)) ||
        (git && !holy_git_catalog_commit(saved, NULL)) ||
        !(fast ? holy_repo_catalog_index_fast(saved, actual) :
                  holy_repo_catalog_index(saved, actual)) ||
        strcmp(expected, actual)) goto done;
    *path = saved;
    saved = NULL;
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: bound catalog unavailable for source ");
    if (result) { quote(stderr, alias); fputc('\n', stderr); }
    free(saved); free(joined); free(canonical); free(url); free(data);
    clear_registry(&registry);
    if (database >= 0) close(database);
    return result;
}

int holy_source_catalog_path(const char *root, const char *alias, char **path)
{
    return source_catalog_path(root, alias, path, 0);
}

int holy_source_catalog_path_fast(const char *root, const char *alias, char **path)
{
    return source_catalog_path(root, alias, path, 1);
}

static int sync_catalog_parent(const char *root, const char *id, char **path)
{
    static const char *const parts[] = {"var", "cache", "holypkg", "catalogs"};
    char *canonical = NULL, *name = NULL;
    struct stat st;
    size_t i, length;
    int fd = -1;
    *path = NULL;
    canonical = realpath(root, NULL);
    if (!canonical) return -1;
    length = strlen(canonical);
    if (length > (size_t)-1 - strlen(id) - 31) goto done;
    name = malloc(length + strlen(id) + 31);
    if (!name) goto done;
    snprintf(name, length + strlen(id) + 31,
             "%s/var/cache/holypkg/catalogs/%s", canonical, id);
    fd = open(canonical, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) goto done;
    for (i = 0; i <= sizeof parts / sizeof *parts; ++i) {
        int next;
        const char *part = i == sizeof parts / sizeof *parts ? id : parts[i];
        if (fstat(fd, &st) || !S_ISDIR(st.st_mode) ||
            (st.st_uid != geteuid() && st.st_uid != 0) || (st.st_mode & 0022))
            goto done;
        if (mkdirat(fd, part, 0700)) {
            if (errno != EEXIST) goto done;
        } else if (fsync(fd)) goto done;
        next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) goto done;
        close(fd);
        fd = next;
    }
    if (fstat(fd, &st) || !S_ISDIR(st.st_mode) ||
        (st.st_uid != geteuid() && st.st_uid != 0) || (st.st_mode & 0022))
        goto done;
    *path = name;
    name = NULL;
done:
    free(name);
    free(canonical);
    if (!*path && fd >= 0) { close(fd); fd = -1; }
    return fd;
}

static int sync_bound_catalog(const char *alias, const char *root, const char *url,
                              const char *id, const char *digest, const char *ca_file,
                              int current_accepted, const char *public_key,
                              const char *commit)
{
    char *parent_path = NULL, *catalog = NULL, *temporary = NULL;
    char actual[65];
    struct stat st;
    size_t length;
    int parent = -1, result = 1;
    parent = sync_catalog_parent(root, id, &parent_path);
    if (parent < 0 || flock(parent, LOCK_EX)) goto done;
    length = strlen(parent_path);
    if (length > (size_t)-1 - 80) goto done;
    catalog = malloc(length + 66);
    temporary = malloc(length + 20);
    if (!catalog || !temporary) goto done;
    snprintf(catalog, length + 66, "%s/%s", parent_path, digest);
    if (fstatat(parent, digest, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!S_ISDIR(st.st_mode) ||
            !holy_repo_source_catalog(catalog, id, url, public_key) ||
            (commit && !holy_git_catalog_commit(catalog, commit)) ||
            !holy_repo_catalog_index(catalog, actual) || strcmp(actual, digest)) {
            result = 6; goto done;
        }
    } else {
        if (errno != ENOENT) goto done;
        snprintf(temporary, length + 20, "%s/.sync-XXXXXX", parent_path);
        if (!mkdtemp(temporary) || rmdir(temporary)) goto done;
        result = commit ? holy_git_mirror_source(url, commit, digest, temporary,
                                                 id, public_key, ca_file) :
                 public_key ? holy_repo_mirror_source_signed(url, digest, temporary,
                                                              ca_file, id, public_key) :
                 holy_repo_mirror_source(url, digest, temporary, ca_file, id,
                                         current_accepted);
        if (result) {
            fprintf(stderr, "holypkg: incomplete catalog retained at %s\n", temporary);
            goto done;
        }
        result = 1;
        if (renameat(parent, strrchr(temporary, '/') + 1, parent, digest) ||
            fsync(parent)) goto done;
    }
    result = holy_source_bind_catalog(root, alias, catalog);
done:
    if (result) fprintf(stderr, "holypkg: source catalog sync failed (status %d)\n", result);
    if (parent >= 0) close(parent);
    free(parent_path); free(catalog); free(temporary);
    return result;
}

int holy_source_sync(const char *alias, const char *root, const char *digest,
                     const char *accepted_unsigned, const char *output,
                     const char *ca_file, const char *commit)
{
    struct registry registry = {0};
    char *data = NULL, *url = NULL;
    char source_id[65] = {0}, key_spec[69];
    char current[65];
    const char *public_key = NULL;
    unsigned long long generation;
    int dir, result = 1, git = 0;
    size_t i;
    if (!alias || !*alias || !strcmp(alias, "local") ||
        (digest && accepted_unsigned) ||
        (digest && !valid_hash(digest)) ||
        (accepted_unsigned && !valid_hash(accepted_unsigned)) ||
        (commit && ((strlen(commit) != 40 && strlen(commit) != 64) ||
                    strspn(commit, "0123456789abcdef") != strlen(commit))) ||
        (output && !*output)) return 2;
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
    url = native_endpoint(registry.items[i].definition, &git);
    if (!url) {
        fputs("holypkg: source ", stderr);
        quote(stderr, alias); fputs(" requires a single native URL\n", stderr);
        goto done;
    }
    if ((git && (!commit || !digest || accepted_unsigned)) ||
        (!git && commit)) { result = 2; goto done; }
    public_key = source_public_key(&registry.items[i], key_spec);
    if (public_key && accepted_unsigned) {
        fputs("holypkg: signed source cannot accept unsigned current\n", stderr);
        result = 2; goto done;
    }
    if (!public_key && !strcmp(registry.items[i].trust, "require")) {
        fputs("holypkg: source trust require needs a registered public key\n", stderr);
        result = 6; goto done;
    }
    memcpy(source_id, registry.items[i].id, sizeof source_id);
    close(dir); dir = -1;
    if (!digest) {
        result = holy_fetch_https_current(url, ca_file, current);
        if (result) goto done;
        if (!public_key && (!accepted_unsigned || strcmp(accepted_unsigned, current))) {
            fprintf(stderr, "holypkg: decision-required unsigned current source=%s index=%s; --accept-unsigned %s confirms this generation\n",
                    source_id, current, current);
            result = 3; goto done;
        }
        digest = current;
    }
    result = output ? (git ? holy_git_mirror_source(url, commit, digest, output,
                                                  source_id, public_key, ca_file) :
                       public_key ? holy_repo_mirror_source_signed(url, digest,
                                             output, ca_file, source_id, public_key) :
                      holy_repo_mirror_source(url, digest, output, ca_file,
                                             source_id, accepted_unsigned != NULL)) :
        sync_bound_catalog(alias, root, url, source_id, digest, ca_file,
                           accepted_unsigned != NULL, public_key, commit);
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
