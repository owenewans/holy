#define _POSIX_C_SOURCE 200809L
#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

struct frame {
    dev_t dev;
    ino_t ino;
    struct frame *parent;
};

static char *copy(const char *s)
{
    size_t n = strlen(s);
    char *p = malloc(n + 1);
    if (p) memcpy(p, s, n + 1);
    return p;
}

static int fail(char **error, const char *file, size_t line, const char *fmt, ...)
{
    char msg[512];
    int n;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    n = snprintf(NULL, 0, "%s:%zu: %s", file, line, msg);
    if (n >= 0) {
        *error = malloc((size_t)n + 1);
        if (*error) snprintf(*error, (size_t)n + 1, "%s:%zu: %s", file, line, msg);
    }
    return 0;
}

void holy_tokens_free(char **v, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) free(v[i]);
    free(v);
}

static int append(char **buf, size_t *len, size_t *cap, char c)
{
    char *next;
    size_t size;
    if (*len + 1 >= *cap) {
        if (*cap > (size_t)-1 / 2) return 0;
        size = *cap ? *cap * 2 : 32;
        next = realloc(*buf, size);
        if (!next) return 0;
        *buf = next;
        *cap = size;
    }
    (*buf)[(*len)++] = c;
    return 1;
}

static int hex(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int utf8(const unsigned char *s, size_t n)
{
    size_t i = 0, j, count;
    unsigned int code, minimum;
    while (i < n) {
        unsigned char c = s[i++];
        if (c < 0x80) continue;
        if (c >= 0xc2 && c <= 0xdf) { count = 1; code = c & 31; minimum = 0x80; }
        else if (c >= 0xe0 && c <= 0xef) { count = 2; code = c & 15; minimum = 0x800; }
        else if (c >= 0xf0 && c <= 0xf4) { count = 3; code = c & 7; minimum = 0x10000; }
        else return 0;
        if (count > n - i) return 0;
        for (j = 0; j < count; ++j) {
            c = s[i++];
            if ((c & 0xc0) != 0x80) return 0;
            code = (code << 6) | (c & 63);
        }
        if (code < minimum || code > 0x10ffff ||
            (code >= 0xd800 && code <= 0xdfff)) return 0;
    }
    return 1;
}

int holy_lex(const char *s, size_t length, char ***out, size_t *count,
             const char *file, size_t line, char **error)
{
    size_t i = 0, used = 0, cap = 0;
    char **v = NULL;
    if (!utf8((const unsigned char *)s, length))
        return fail(error, file, line, "invalid UTF-8");
    while (i < length) {
        char *word = NULL;
        size_t len = 0, size = 0;
        int quoted = 0, active = 0;
        while (i < length && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r')) ++i;
        if (i == length || s[i] == '\n' || s[i] == '#') break;
        while (i < length && s[i] != '\n') {
            char c = s[i++];
            if (c == '"') { quoted = !quoted; active = 1; continue; }
            if (!quoted && (c == ' ' || c == '\t' || c == '\r')) break;
            if (c == '\\') {
                if (i >= length || s[i] == '\n') goto bad_escape;
                c = s[i++];
                if (c == 'n') c = '\n';
                else if (c == 't') c = '\t';
                else if (c == 'r') c = '\r';
                else if (c == 'x') {
                    int hi, lo;
                    if (i + 1 >= length || (hi = hex(s[i])) < 0 ||
                        (lo = hex(s[i + 1])) < 0) goto bad_escape;
                    c = (char)(hi * 16 + lo);
                    i += 2;
                    if (!c) goto bad_escape;
                } else if (c != '"' && c != '\\') goto bad_escape;
            }
            active = 1;
            if (!append(&word, &len, &size, c)) goto oom;
        }
        if (quoted) {
            free(word);
            holy_tokens_free(v, used);
            return fail(error, file, line, "unterminated quote");
        }
        if (!active) { free(word); continue; }
        if (!append(&word, &len, &size, '\0')) goto oom;
        if (used == cap) {
            size_t next = cap ? cap * 2 : 4;
            if (next < cap || next > (size_t)-1 / sizeof(*v)) goto oom;
            {
                char **newv = realloc(v, next * sizeof(*v));
                if (!newv) goto oom;
                v = newv;
            }
            cap = next;
        }
        v[used++] = word;
        continue;
bad_escape:
        free(word);
        holy_tokens_free(v, used);
        return fail(error, file, line, "invalid escape or NUL");
oom:
        free(word);
        holy_tokens_free(v, used);
        return fail(error, file, line, "out of memory");
    }
    *out = v;
    *count = used;
    return 1;
}

static char *relative(const char *base, const char *name)
{
    const char *slash;
    size_t prefix, n;
    char *path;
    if (name[0] == '/') return copy(name);
    slash = strrchr(base, '/');
    prefix = slash ? (size_t)(slash - base + 1) : 0;
    n = strlen(name);
    if (prefix > (size_t)-1 - n - 1) return NULL;
    path = malloc(prefix + n + 1);
    if (!path) return NULL;
    memcpy(path, base, prefix);
    memcpy(path + prefix, name, n + 1);
    return path;
}

static int valid_section(const char *s)
{
    return !strcmp(s, "general") || !strcmp(s, "resolver") ||
           (!strncmp(s, "source ", 7) && s[7] && strcmp(s + 7, "local")) ||
           (!strncmp(s, "rule ", 5) && s[5]);
}

static int list_key(const char *section, const char *key)
{
    return (!strncmp(section, "source ", 7) && !strcmp(key, "repo")) ||
           (!strcmp(section, "resolver") && !strcmp(key, "prefer"));
}

static int key_arity(const char *section, const char *key)
{
    if (!strcmp(section, "general")) {
        if (!strcmp(key, "arch") || !strcmp(key, "compat-arch") ||
            !strcmp(key, "scripts") || !strcmp(key, "trust")) return 1;
    } else if (!strcmp(section, "resolver")) {
        if (!strcmp(key, "ask-sources") || !strcmp(key, "prefer")) return 1;
    } else if (!strncmp(section, "source ", 7)) {
        if (!strcmp(key, "repo")) return 2;
        if (!strcmp(key, "type") || !strcmp(key, "url") ||
            !strcmp(key, "parent") || !strcmp(key, "trust")) return 1;
    } else if (!strncmp(section, "rule ", 5)) {
        if (!strcmp(key, "consumer") || !strcmp(key, "require") ||
            !strcmp(key, "provider")) return 1;
    }
    return 0;
}

static int known_value(const char *section, const char *key, const char *v)
{
    if (!strcmp(key, "scripts") && !strcmp(section, "general"))
        return !strcmp(v, "ask") || !strcmp(v, "run") || !strcmp(v, "skip");
    if (!strcmp(key, "trust"))
        return !strcmp(v, "warn") || !strcmp(v, "require") || !strcmp(v, "ignore");
    if (!strcmp(key, "ask-sources"))
        return !strcmp(v, "yes") || !strcmp(v, "no");
    if (!strcmp(key, "prefer"))
        return !strcmp(v, "installed") || !strcmp(v, "same-source") ||
               !strcmp(v, "parent") || !strcmp(v, "family");
    return 1;
}

static int url_has_userinfo(const char *url)
{
    const char *scheme = strstr(url, "://"), *authority, *end;
    if (!scheme) return 0;
    authority = scheme + 3;
    end = authority + strcspn(authority, "/?#");
    return memchr(authority, '@', (size_t)(end - authority)) != NULL;
}

static int parse(const char *path, struct holy_config *config,
                 struct frame *parent, char **error)
{
    FILE *fp;
    struct stat st;
    struct frame current, *node;
    char *line = NULL, *section = NULL;
    size_t capacity = 0, lineno = 0;
    ssize_t length;
    int ok = 1;
    size_t depth = 0;
    for (node = parent; node; node = node->parent) ++depth;
    if (depth >= 64) return fail(error, path, 0, "include depth exceeds 64");
    fp = fopen(path, "r");
    if (!fp) return fail(error, path, 0, "open: %s", strerror(errno));
    if (fstat(fileno(fp), &st)) {
        ok = fail(error, path, 0, "stat: %s", strerror(errno));
        goto done;
    }
    for (node = parent; node; node = node->parent)
        if (node->dev == st.st_dev && node->ino == st.st_ino) {
            ok = fail(error, path, 0, "include cycle");
            goto done;
        }
    current.dev = st.st_dev;
    current.ino = st.st_ino;
    current.parent = parent;
    while ((length = getline(&line, &capacity, fp)) != -1) {
        char **v = NULL;
        size_t count = 0, i;
        struct holy_entry entry, *entries;
        ++lineno;
        if (memchr(line, '\0', (size_t)length)) {
            ok = fail(error, path, lineno, "NUL byte");
            break;
        }
        if (!holy_lex(line, (size_t)length, &v, &count, path, lineno, error)) { ok = 0; break; }
        if (!count) { holy_tokens_free(v, count); continue; }
        if (!strcmp(v[0], "include")) {
            char *child;
            if (count != 2) ok = fail(error, path, lineno, "include expects one path");
            else if (!(child = relative(path, v[1]))) ok = fail(error, path, lineno, "out of memory");
            else { ok = parse(child, config, &current, error); free(child); }
        } else if (v[0][0] == '[') {
            size_t n = strlen(v[0]);
            size_t total = n;
            char *joined = NULL;
            if (count == 2 && total <= (size_t)-1 - strlen(v[1]) - 2) {
                total += strlen(v[1]) + 1;
                joined = malloc(total + 1);
                if (joined) {
                    snprintf(joined, total + 1, "%s %s", v[0], v[1]);
                    n = total;
                }
            } else if (count == 1) joined = copy(v[0]);
            if (!joined) ok = fail(error, path, lineno, "invalid section or out of memory");
            else if (count > 2 || n < 3 || joined[n - 1] != ']' ||
                     (joined[n - 1] = '\0', !valid_section(joined + 1)))
                ok = fail(error, path, lineno, "invalid section");
            else {
                char *next = copy(joined + 1);
                if (!next) ok = fail(error, path, lineno, "out of memory");
                else { free(section); section = next; }
            }
            free(joined);
        } else if (!section || count < 2) {
            ok = fail(error, path, lineno, "key outside section or missing value");
        } else {
            int arity = key_arity(section, v[0]);
            if (!arity) ok = fail(error, path, lineno, "unknown key %s in [%s]", v[0], section);
            else if (count - 1 != (size_t)arity)
                ok = fail(error, path, lineno, "%s expects %d argument(s)", v[0], arity);
            else if (!known_value(section, v[0], v[1]))
                ok = fail(error, path, lineno, "invalid %s value", v[0]);
            for (i = 0; i < config->count; ++i)
                if (ok && !list_key(section, v[0]) &&
                    !strcmp(config->entries[i].section, section) &&
                    !strcmp(config->entries[i].key, v[0])) {
                    ok = fail(error, path, lineno, "duplicate %s (first at %s:%zu)",
                              v[0], config->entries[i].file, config->entries[i].line);
                    break;
                }
            if (ok) {
                if (config->count == (size_t)-1 / sizeof(*entries))
                    ok = fail(error, path, lineno, "too many entries");
                else if (!(entries = realloc(config->entries,
                                             (config->count + 1) * sizeof(*entries))))
                    ok = fail(error, path, lineno, "out of memory");
                else {
                    config->entries = entries;
                    entry.section = copy(section);
                    entry.file = copy(path);
                    entry.key = v[0];
                    entry.values = malloc((count - 1) * sizeof(*entry.values));
                    entry.count = count - 1;
                    if (!entry.section || !entry.file || !entry.values) {
                        free(entry.section); free(entry.file); free(entry.values);
                        ok = fail(error, path, lineno, "out of memory");
                    } else {
                        for (i = 1; i < count; ++i) entry.values[i - 1] = v[i];
                        entry.line = lineno;
                        config->entries[config->count++] = entry;
                        free(v);
                        v = NULL;
                    }
                }
            }
        }
        if (v) holy_tokens_free(v, count);
        if (!ok) break;
    }
    if (ok && ferror(fp)) ok = fail(error, path, lineno, "read: %s", strerror(errno));
done:
    free(line);
    free(section);
    fclose(fp);
    return ok;
}

static int validate(struct holy_config *config, char **error)
{
    size_t i, j;
    for (i = 0; i < config->count; ++i) {
        const struct holy_entry *e = &config->entries[i];
        int type = 0, endpoint = 0, consumer = 0, require = 0, provider = 0;
        if (!e->values[0][0] || (e->count == 2 && !e->values[1][0]))
            return fail(error, e->file, e->line, "empty %s value", e->key);
        if ((!strcmp(e->key, "url") || !strcmp(e->key, "repo")) &&
            url_has_userinfo(e->values[e->count - 1]))
            return fail(error, e->file, e->line, "credentials in %s URL", e->key);
        if (!strcmp(e->key, "repo")) {
            for (j = 0; j < i; ++j) {
                const struct holy_entry *other = &config->entries[j];
                if (!strcmp(e->section, other->section) &&
                    !strcmp(other->key, "repo") &&
                    !strcmp(e->values[0], other->values[0]))
                    return fail(error, e->file, e->line,
                                "duplicate repo name (first at %s:%zu)",
                                other->file, other->line);
            }
        }
        if (strncmp(e->section, "source ", 7) && strncmp(e->section, "rule ", 5))
            continue;
        for (j = 0; j < i; ++j)
            if (!strcmp(e->section, config->entries[j].section)) break;
        if (j != i) continue;
        for (j = i; j < config->count; ++j) {
            const struct holy_entry *field = &config->entries[j];
            if (strcmp(field->section, e->section)) continue;
            if (!strcmp(field->key, "type")) type = 1;
            else if (!strcmp(field->key, "url") || !strcmp(field->key, "repo")) endpoint = 1;
            else if (!strcmp(field->key, "consumer")) consumer = 1;
            else if (!strcmp(field->key, "require")) require = 1;
            else if (!strcmp(field->key, "provider")) provider = 1;
        }
        if (!strncmp(e->section, "source ", 7) && (!type || !endpoint))
            return fail(error, e->file, e->line,
                        "[%s] requires type and url or repo", e->section);
        if (!strncmp(e->section, "rule ", 5) &&
            (!consumer || !require || !provider))
            return fail(error, e->file, e->line,
                        "[%s] requires consumer, require and provider", e->section);
    }
    for (i = 0; i < config->count; ++i) {
        const struct holy_entry *start = &config->entries[i], *parent = start;
        size_t hops = 0;
        if (strcmp(start->key, "parent")) continue;
        while (parent) {
            const struct holy_entry *next = NULL;
            size_t n;
            for (n = 0; n < config->count; ++n)
                if (!strcmp(config->entries[n].key, "parent") &&
                    !strncmp(config->entries[n].section, "source ", 7) &&
                    !strcmp(config->entries[n].section + 7, parent->values[0])) {
                    next = &config->entries[n];
                    break;
                }
            if (!next) {
                int found = 0;
                for (n = 0; n < config->count; ++n)
                    if (!strncmp(config->entries[n].section, "source ", 7) &&
                        !strcmp(config->entries[n].section + 7, parent->values[0])) {
                        found = 1;
                        break;
                    }
                if (!found) return fail(error, parent->file, parent->line,
                                        "parent source is not configured");
            }
            parent = next;
            if (++hops > config->count)
                return fail(error, start->file, start->line, "parent source cycle");
        }
    }
    return 1;
}

int holy_config_load(const char *path, struct holy_config *out, char **error)
{
    *error = NULL;
    return parse(path, out, NULL, error) && validate(out, error);
}

void holy_config_free(struct holy_config *config)
{
    size_t i, j;
    for (i = 0; i < config->count; ++i) {
        struct holy_entry *e = &config->entries[i];
        free(e->section);
        free(e->key);
        free(e->file);
        for (j = 0; j < e->count; ++j) free(e->values[j]);
        free(e->values);
    }
    free(config->entries);
    config->entries = NULL;
    config->count = 0;
}
