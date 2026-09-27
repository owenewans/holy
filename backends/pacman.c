#define _POSIX_C_SOURCE 200809L
#include "pacman.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct keyword {
    const char *name;
    enum holy_pacman_field_kind kind;
    int list, empty;
};

static const struct keyword keywords[] = {
    {"pkgname", HOLY_PACMAN_IDENTITY, 0, 0},
    {"pkgbase", HOLY_PACMAN_IDENTITY, 0, 0},
    {"pkgver", HOLY_PACMAN_IDENTITY, 0, 0},
    {"arch", HOLY_PACMAN_IDENTITY, 0, 0},
    {"pkgdesc", HOLY_PACMAN_DISPLAY, 0, 1},
    {"url", HOLY_PACMAN_DISPLAY, 0, 1},
    {"builddate", HOLY_PACMAN_DISPLAY, 0, 0},
    {"packager", HOLY_PACMAN_DISPLAY, 0, 0},
    {"size", HOLY_PACMAN_DISPLAY, 0, 0},
    {"license", HOLY_PACMAN_DISPLAY, 1, 0},
    {"group", HOLY_PACMAN_DISPLAY, 1, 0},
    {"depend", HOLY_PACMAN_DEPEND, 1, 0},
    {"optdepend", HOLY_PACMAN_OPTIONAL, 1, 0},
    {"makedepend", HOLY_PACMAN_BUILD, 1, 0},
    {"checkdepend", HOLY_PACMAN_CHECK, 1, 0},
    {"provides", HOLY_PACMAN_PROVIDE, 1, 0},
    {"conflict", HOLY_PACMAN_CONFLICT, 1, 0},
    {"replaces", HOLY_PACMAN_REPLACE, 1, 0},
    {"backup", HOLY_PACMAN_BACKUP, 1, 0},
    {"xdata", HOLY_PACMAN_EXTRA, 1, 0}
};

static int digit(unsigned char c) { return c >= '0' && c <= '9'; }
static int alpha(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static int package_name(const char *name)
{
    const unsigned char *p = (const unsigned char *)name;
    if (!*p || *p == '-' || *p == '.') return 0;
    for (; *p; ++p)
        if (!alpha(*p) && !digit(*p) && !strchr("@._+-", *p)) return 0;
    return 1;
}

static int text_value(const char *text)
{
    const unsigned char *p = (const unsigned char *)text;
    while (*p) {
        unsigned value, minimum, left;
        if (*p < 0x20 || *p == 0x7f) return 0;
        if (*p < 0x80) { ++p; continue; }
        if (*p >= 0xc2 && *p <= 0xdf) { value = *p & 31; left = 1; minimum = 0x80; }
        else if (*p >= 0xe0 && *p <= 0xef) { value = *p & 15; left = 2; minimum = 0x800; }
        else if (*p >= 0xf0 && *p <= 0xf4) { value = *p & 7; left = 3; minimum = 0x10000; }
        else return 0;
        ++p;
        while (left--) {
            if ((*p & 0xc0) != 0x80) return 0;
            value = (value << 6) | (*p++ & 63);
        }
        if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) return 0;
    }
    return 1;
}

static int version_value(const char *text, int full)
{
    const char *p = text, *colon = strchr(text, ':'), *release;
    if (!*p) return 0;
    if (colon) {
        if (colon == p) return 0;
        while (p < colon) if (!digit((unsigned char)*p++)) return 0;
        if (!*++p) return 0;
    }
    for (text = p; *p; ++p)
        if ((unsigned char)*p <= 32 || (unsigned char)*p >= 127 || strchr("/:<=>", *p)) return 0;
    if (!full) return 1;
    release = strrchr(text, '-');
    if (!release || release == text || !release[1]) return 0;
    for (p = release + 1; *p; ++p)
        if (!digit((unsigned char)*p) && *p != '.') return 0;
    return digit((unsigned char)release[1]) && digit((unsigned char)p[-1]);
}

static int relative_path(const char *path)
{
    const char *p = path;
    if (!*p || *p == '/') return 0;
    while (*p) {
        const char *end = strchr(p, '/');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        if (!n || (n == 1 && *p == '.') || (n == 2 && !memcmp(p, "..", 2))) return 0;
        if (!end) return 1;
        p = end + 1;
    }
    return 0;
}

static int relation_value(struct holy_pacman_field *field)
{
    struct holy_pacman_relation *r = &field->relation;
    char *operator, *description, *colon;
    size_t length;
    r->storage = strdup(field->value);
    if (!r->storage) return 0;
    r->name = r->storage; r->comparison = "any"; r->version = "-";
    if (field->kind == HOLY_PACMAN_OPTIONAL && (description = strstr(r->storage, ": "))) {
        *description = 0; r->description = description + 2;
        if (!*r->description) return 0;
    }
    operator = strpbrk(r->storage, "<=>");
    if (operator) {
        char first = *operator, second = operator[1];
        *operator++ = 0;
        if (first == '=') r->comparison = "eq";
        else if (second == '=') { r->comparison = first == '<' ? "le" : "ge"; ++operator; }
        else r->comparison = first == '<' ? "lt" : "gt";
        r->version = operator;
        if (!version_value(r->version, 0) ||
            (field->kind == HOLY_PACMAN_PROVIDE && strcmp(r->comparison, "eq"))) return 0;
    }
    colon = strchr(r->storage, ':');
    if (colon) {
        if (operator || (field->kind != HOLY_PACMAN_DEPEND && field->kind != HOLY_PACMAN_PROVIDE)) return 0;
        *colon = 0; r->prefix = r->storage; r->name = colon + 1;
        if (!package_name(r->prefix) || !*r->name || strchr(r->name, ':') ||
            strchr(r->name, '/') || strchr(r->name, ' ') || !strstr(r->name, ".so")) return 0;
        r->kind = HOLY_PACMAN_SONAME_V2;
        return 1;
    }
    if (!package_name(r->name)) return 0;
    length = strlen(r->name);
    if (length > 3 && !strcmp(r->name + length - 3, ".so") &&
        (field->kind == HOLY_PACMAN_DEPEND || field->kind == HOLY_PACMAN_PROVIDE)) {
        const char *dash = strrchr(r->version, '-');
        r->kind = HOLY_PACMAN_SONAME_V1;
        if (!operator) return 1;
        if (strcmp(r->comparison, "eq") || !dash || dash == r->version ||
            (strcmp(dash + 1, "32") && strcmp(dash + 1, "64"))) return 0;
        r->elf_class = !strcmp(dash + 1, "32") ? 32 : 64;
    }
    return 1;
}

static int numeric(const char *text)
{
    const unsigned char *p = (const unsigned char *)text;
    uint64_t value = 0;
    if (!*p) return 0;
    for (; *p; ++p) {
        if (!digit(*p) || value > (UINT64_MAX - (*p - '0')) / 10) return 0;
        value = value * 10 + (*p - '0');
    }
    return 1;
}

void holy_pacman_free(struct holy_pacman_metadata *metadata)
{
    size_t i;
    for (i = 0; i < metadata->count; ++i) free(metadata->fields[i].relation.storage);
    free(metadata->fields); free(metadata->storage);
    memset(metadata, 0, sizeof *metadata);
}

int holy_pacman_parse(const char *bytes, size_t size,
                      struct holy_pacman_metadata *out, struct holy_pacman_error *error)
{
    char *line, *end;
    size_t number = 0, capacity = 0, extras = 0, seen[sizeof keywords / sizeof *keywords] = {0};
    memset(out, 0, sizeof *out); memset(error, 0, sizeof *error);
    error->message = "invalid PKGINFO";
    if (!size || size > 1024u * 1024u || memchr(bytes, 0, size)) return 0;
    out->storage = malloc(size + 1);
    if (!out->storage) { error->message = "allocation failed"; return 0; }
    memcpy(out->storage, bytes, size); out->storage[size] = 0;
    for (line = out->storage; line; line = end) {
        char *value, *p;
        size_t i, key_length;
        struct holy_pacman_field *field;
        end = strchr(line, '\n');
        if (end) *end++ = 0;
        error->line = ++number;
        if (strlen(line) > 65536) { error->message = "oversized line"; return 0; }
        while (*line == ' ' || *line == '\t') ++line;
        if (!*line || *line == '#') continue;
        value = strstr(line, " = ");
        if (!value) { error->message = "expected key = value"; return 0; }
        key_length = (size_t)(value - line);
        if (!key_length) return 0;
        for (p = line; p < value; ++p)
            if (!alpha((unsigned char)*p) && !digit((unsigned char)*p) && *p != '_') return 0;
        *value = 0; value += 3;
        if (!text_value(value)) { error->message = "invalid UTF-8 or control byte"; return 0; }
        for (i = 0; i < sizeof keywords / sizeof *keywords; ++i)
            if (!strcmp(line, keywords[i].name)) break;
        if (i < sizeof keywords / sizeof *keywords) {
            if (!keywords[i].list && seen[i]) { error->message = "duplicate scalar"; return 0; }
            if (!keywords[i].empty && !*value) { error->message = "empty value"; return 0; }
            seen[i] = number;
        }
        if (out->count == capacity) {
            size_t next = capacity ? capacity * 2 : 32;
            void *grown;
            if (next < capacity || next > SIZE_MAX / sizeof *out->fields) return 0;
            grown = realloc(out->fields, next * sizeof *out->fields);
            if (!grown) { error->message = "allocation failed"; return 0; }
            out->fields = grown; capacity = next;
        }
        field = &out->fields[out->count++];
        memset(field, 0, sizeof *field);
        field->key = line; field->value = value; field->line = number;
        field->kind = i < sizeof keywords / sizeof *keywords ? keywords[i].kind : HOLY_PACMAN_UNKNOWN;
        if (field->kind == HOLY_PACMAN_UNKNOWN) ++out->unknown_count;
        if (!strcmp(line, "pkgname")) {
            if (!package_name(value)) return 0;
            out->name = value;
        } else if (!strcmp(line, "pkgbase")) {
            if (!package_name(value)) return 0;
            out->base = value;
        } else if (!strcmp(line, "pkgver")) {
            if (!version_value(value, 1)) return 0;
            out->version = value;
        } else if (!strcmp(line, "arch")) {
            for (p = value; *p; ++p) if (!alpha((unsigned char)*p) && !digit((unsigned char)*p) && *p != '_') return 0;
            out->arch = value;
        } else if (!strcmp(line, "builddate") || !strcmp(line, "size")) {
            if (!numeric(value)) return 0;
        } else if (field->kind >= HOLY_PACMAN_DEPEND && field->kind <= HOLY_PACMAN_REPLACE) {
            if (!relation_value(field)) { error->message = "invalid package relation"; return 0; }
        } else if (field->kind == HOLY_PACMAN_BACKUP) {
            if (!relative_path(value)) { error->message = "unsafe backup path"; return 0; }
        } else if (field->kind == HOLY_PACMAN_EXTRA) {
            p = strchr(value, '=');
            ++extras;
            if (!p || p == value || !p[1]) return 0;
            if (!strncmp(value, "pkgtype=", 8)) {
                if (out->package_type) { error->message = "duplicate pkgtype"; return 0; }
                out->package_type = value + 8;
                if (strcmp(out->package_type, "pkg") && strcmp(out->package_type, "split") &&
                    strcmp(out->package_type, "debug") && strcmp(out->package_type, "src")) ++out->unknown_count;
            } else ++out->unknown_count;
        }
    }
    error->line = number;
    if (!out->name || !out->version || !out->arch || (extras && !out->package_type)) {
        error->message = "missing identity or pkgtype"; return 0;
    }
    error->line = 0; error->message = NULL;
    return 1;
}
