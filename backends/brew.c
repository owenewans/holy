/* a Homebrew formula to a holy-recipe(5) manifest; see man/holy-recipe.5 and
   man/holypkg.8. a formula is Ruby: this converter reads the text and never runs
   it. the values a formula states are carried, a depends_on becomes a build or a
   runtime requirement, and a system call inside def install becomes a build step
   that runs the same command with the Homebrew prefix rewritten onto the build
   root. every other statement of that body stays Ruby: the formula is copied
   beside the recipe, the build declares a ruby helper requirement, and the report
   names the file and line, because a shell step that pretended to run Ruby would
   be a lie. a bottle is a prebuilt foreign binary, so the build runs the pinned
   source instead. */

#define _POSIX_C_SOURCE 200809L
#include "brew.h"
#include "shrecipe.h"
#include "../src/image.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BREW_LIMIT (1024 * 1024)

struct brew_line {
    char *text;
    size_t length;
    size_t number;
};

/* one fetched source the formula names beside its own url */
struct brew_source {
    char *label, *url, *digest;
};

struct brew {
    FILE *out;                /* the build steps, buffered until the header is known */
    char *step_text;
    size_t step_size;
    struct recipe_note *note;
    const char *input;
    char *directory;
    char *name, *version, *release, *arch;
    char *license, *homepage, *url, *sha256, *summary;
    struct brew_source *sources;
    size_t source_count, source_limit;
    char **depends;
    size_t depends_count, depends_limit;
    char **build_depends;
    size_t build_count, build_limit;
    size_t preserved, helpers, optional;
    int review;
    int ruby_body;
};

static int brew_note(struct brew *brew, const char *kind, const char *format, ...)
{
    char body[1024];
    va_list arguments;
    va_start(arguments, format);
    if (vsnprintf(body, sizeof body, format, arguments) < 0) { va_end(arguments); return 0; }
    va_end(arguments);
    if (!strcmp(kind, "unknown") || !strcmp(kind, "helper")) brew->review = 1;
    return holy_note_add(brew->note, kind, "%s", body);
}

static char *trim(char *value)
{
    char *at = value;
    size_t length;
    while (*at == ' ' || *at == '\t' || *at == '\r' || *at == '\n') ++at;
    if (at != value) memmove(value, at, strlen(at) + 1);
    length = strlen(value);
    while (length && (value[length - 1] == ' ' || value[length - 1] == '\t' ||
                      value[length - 1] == '\r' || value[length - 1] == '\n')) value[--length] = 0;
    return value;
}

static int name_character(int value)
{
    return isalnum((unsigned char)value) || value == '_' || value == '-' || value == '.' ||
           value == '+';
}

/* a Homebrew name is a class name, so it becomes the lower-case name a package
   record holds */
static char *package_name(const char *class_name)
{
    char *name = strdup(class_name), *at;
    if (!name) return NULL;
    for (at = name; *at; ++at) *at = (char)tolower((unsigned char)*at);
    if (!*name || !isalnum((unsigned char)name[0])) { free(name); return NULL; }
    for (at = name + 1; *at; ++at)
        if (!name_character((unsigned char)*at)) { free(name); return NULL; }
    return name;
}

/* the version a source url states, since a formula records no version of its own
   and the build has to name the release it fetched */
static char *version_from_url(const char *url)
{
    static const char *const suffixes[] = { ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst",
                                            ".tar.lz", ".tar", ".tgz", ".tbz2", ".tbz", ".txz",
                                            ".zip", ".tar.Z", NULL };
    const char *base = strrchr(url, '/');
    const char *at, *component, *stop;
    base = base ? base + 1 : url;
    for (at = base + strlen(base); at > base; --at) {
        if (at[-1] != '-' && at[-1] != '_') continue;
        /* the version is the last component before the archive suffix, and only a
           component that begins with a digit is one */
        if (!isdigit((unsigned char)at[0])) continue;
        component = at;
        for (stop = at; *stop; ++stop) {
            size_t i;
            for (i = 0; suffixes[i]; ++i)
                if (!strncmp(stop, suffixes[i], strlen(suffixes[i]))) break;
            if (suffixes[i]) break;
        }
        {
            size_t length = (size_t)(stop - component);
            char *version;
            if (!length) return NULL;
            version = malloc(length + 1);
            if (!version) return NULL;
            memcpy(version, component, length);
            version[length] = 0;
            return version;
        }
    }
    return NULL;
}

/* one quoted Ruby string, or NULL when the text is not a single closed literal */
static char *literal(const char *value, size_t length)
{
    char quote;
    char *result;
    size_t at;
    if (length < 2) return NULL;
    quote = value[0];
    if (quote != '"' && quote != '\'') return NULL;
    if (value[length - 1] != quote) return NULL;
    for (at = 1; at + 1 < length; ++at)
        if (value[at] == quote && (at == 1 || value[at - 1] != '\\')) return NULL;
    result = malloc(length);
    if (!result) return NULL;
    memcpy(result, value + 1, length - 2);
    result[length - 2] = 0;
    return result;
}

/* how far a quoted literal reaches, or 0 when the line holds none */
static size_t literal_length(const char *text, size_t length)
{
    size_t at = 0;
    if (!length || (text[0] != '"' && text[0] != '\'')) return 0;
    for (at = 1; at < length; ++at) {
        if (text[at] == text[0] && text[at - 1] != '\\') return at + 1;
    }
    return 0;
}

/* the value of a directive, which Homebrew writes as a bare word or a literal */
static char *argument(const char *line, size_t length, const char *key)
{
    size_t key_length = strlen(key);
    const char *rest = line + key_length;
    size_t rest_length = length - key_length;
    char *value;
    while (rest_length && (*rest == ' ' || *rest == '\t')) { ++rest; --rest_length; }
    if (!rest_length) return NULL;
    if (*rest == '"' || *rest == '\'') {
        size_t used = literal_length(rest, rest_length);
        value = used ? literal(rest, used) : NULL;
    } else {
        size_t at = 0;
        while (at < rest_length && !isspace((unsigned char)rest[at])) ++at;
        value = malloc(at + 1);
        if (value) { memcpy(value, rest, at); value[at] = 0; }
    }
    return value ? trim(value) : NULL;
}

/* the relation a depends_on writes after its name, which selects when the
   dependency is needed */
static char *relation(const char *line, size_t length)
{
    const char *arrow = strstr(line, "=>");
    const char *at;
    size_t rest;
    if (!arrow) return NULL;
    at = arrow + 2;
    while (at < line + length && isspace((unsigned char)*at)) ++at;
    rest = (size_t)(line + length - at);
    if (!rest) return strdup("required");
    if (*at == ':') {
        size_t used = 1;
        char *value;
        while (used < rest && (isalnum((unsigned char)at[used]) || at[used] == '_')) ++used;
        value = malloc(used);
        if (!value) return NULL;
        memcpy(value, at + 1, used - 1);
        value[used - 1] = 0;
        return value;
    }
    if (*at == '[') {
        if (strstr(at, ":build")) return strdup("build");
        return strdup("required");
    }
    {
        size_t used = literal_length(at, rest);
        char *value = used ? literal(at, used) : strdup("required");
        return value;
    }
}

static int push_source(struct brew *brew, const char *label, const char *url, const char *digest)
{
    struct brew_source *grown;
    if (brew->source_count == brew->source_limit) {
        size_t next = brew->source_limit ? brew->source_limit * 2 : 8;
        grown = realloc(brew->sources, next * sizeof *grown);
        if (!grown) return 0;
        brew->sources = grown;
        brew->source_limit = next;
    }
    brew->sources[brew->source_count].label = strdup(label);
    brew->sources[brew->source_count].url = strdup(url);
    brew->sources[brew->source_count].digest = strdup(digest);
    if (!brew->sources[brew->source_count].label || !brew->sources[brew->source_count].url ||
        !brew->sources[brew->source_count].digest) return 0;
    ++brew->source_count;
    return 1;
}

static int push(char ***list, size_t *count, size_t *limit, const char *value)
{
    char **grown;
    if (*count == *limit) {
        size_t next = *limit ? *limit * 2 : 16;
        grown = realloc(*list, next * sizeof *grown);
        if (!grown) return 0;
        *list = grown;
        *limit = next;
    }
    (*list)[*count] = strdup(value);
    if (!(*list)[*count]) return 0;
    ++*count;
    return 1;
}

static int push_dependency(struct brew *brew, const char *name, const char *kind)
{
    return !strcmp(kind, "build-depend") ?
           push(&brew->build_depends, &brew->build_count, &brew->build_limit, name) :
           push(&brew->depends, &brew->depends_count, &brew->depends_limit, name);
}

/* the value buffer a rewritten argument is assembled in */
static int append(struct holy_text *out, const char *bytes, size_t length)
{
    if (out->used + length + 1 > out->capacity) {
        size_t next = out->capacity ? out->capacity : 128;
        char *grown;
        while (next < out->used + length + 1) next *= 2;
        grown = realloc(out->data, next);
        if (!grown) return 0;
        out->data = grown;
        out->capacity = next;
    }
    memcpy(out->data + out->used, bytes, length);
    out->used += length;
    out->data[out->used] = 0;
    return 1;
}

/* a Homebrew path is a prefix inside a cellar, and a Holy build root is the
   prefix, so the interpolation becomes the build destination; an interpolation
   this reader does not model keeps its text and is named */
static char *rewrite(const char *text, struct brew *brew, size_t line_number)
{
    static const char *const known[][2] = {
        { "HOMEBREW_PREFIX", "HOLY_DEST" },
        { "HOMEBREW_CELLAR", "HOLY_DEST" },
        { "opt_prefix", "HOLY_DEST/opt" },
        { "buildpath", "HOLY_BUILD" },
        { "libexec", "HOLY_DEST/libexec" },
        { "prefix", "HOLY_DEST" },
        { "etc", "HOLY_DEST/etc" },
        { "var", "HOLY_DEST/var" },
        { "HEAD", "HOLY_SRC" }
    };
    struct holy_text out = {0};
    const char *cursor = text;
    int unknown = 0;
    for (;;) {
        const char *open = strstr(cursor, "#{"), *stop;
        char name[64];
        size_t name_length, i;
        int depth = 0;
        if (!open) break;
        stop = open + 2;
        while (*stop) {
            if (*stop == '{') ++depth;
            else if (*stop == '}' && !depth) break;
            else if (*stop == '}') --depth;
            ++stop;
        }
        if (*stop != '}') break;
        name_length = (size_t)(stop - open - 2);
        if (name_length >= sizeof name) break;
        memcpy(name, open + 2, name_length);
        name[name_length] = 0;
        if (!append(&out, cursor, (size_t)(open - cursor))) {
            holy_text_free(&out);
            return NULL;
        }
        for (i = 0; i < sizeof known / sizeof *known; ++i)
            if (!strcmp(name, known[i][0])) break;
        if (i == sizeof known / sizeof *known) {
            unknown = 1;
            if (!append(&out, open, (size_t)(stop - open + 1))) {
                holy_text_free(&out);
                return NULL;
            }
        } else {
            char *value = malloc(strlen(known[i][1]) + 2);
            if (!value) { holy_text_free(&out); return NULL; }
            sprintf(value, "$%s", known[i][1]);
            if (!append(&out, value, strlen(value))) {
                free(value);
                holy_text_free(&out);
                return NULL;
            }
            free(value);
        }
        cursor = stop + 1;
    }
    if (!append(&out, cursor, strlen(cursor))) { holy_text_free(&out); return NULL; }
    if (unknown)
        brew_note(brew, "unknown", "the interpolation at line %zu names a Homebrew value this "
                  "reader does not model, and the argument is kept as the formula wrote it",
                  line_number);
    return out.data;
}

/* one system call, as the shell that runs the same command */
static int emit_system(struct brew *brew, const char *line, size_t length, size_t line_number)
{
    size_t at = 6, used = 0, arguments = 0;
    char buffer[4096];
    buffer[0] = 0;
    while (at < length) {
        size_t quoted;
        char *rewritten, *argument_text;
        while (at < length && (line[at] == ' ' || line[at] == '\t' || line[at] == ',')) ++at;
        if (at >= length) break;
        quoted = literal_length(line + at, length - at);
        if (!quoted) {
            brew_note(brew, "unknown", "the system call at line %zu passes a value this reader "
                      "does not model, and the install body stays Ruby", line_number);
            ++brew->helpers;
            brew->ruby_body = 1;
            return 0;
        }
        argument_text = malloc(quoted);
        if (!argument_text) return 0;
        memcpy(argument_text, line + at + 1, quoted - 2);
        argument_text[quoted - 2] = 0;
        rewritten = rewrite(argument_text, brew, line_number);
        free(argument_text);
        if (!rewritten) return 0;
        if (used + strlen(rewritten) + 4 >= sizeof buffer) { free(rewritten); return 0; }
        if (arguments) buffer[used++] = ' ';
        /* a rewritten interpolation has to expand, so its word is double quoted
           and every other word is single quoted */
        if (strchr(rewritten, '$')) {
            buffer[used++] = '"';
            memcpy(buffer + used, rewritten, strlen(rewritten));
            used += strlen(rewritten);
            buffer[used++] = '"';
        } else {
            buffer[used++] = '\'';
            memcpy(buffer + used, rewritten, strlen(rewritten));
            used += strlen(rewritten);
            buffer[used++] = '\'';
        }
        buffer[used] = 0;
        free(rewritten);
        ++arguments;
        at += quoted;
        if (at < length && line[at] == ',') ++at;
    }
    if (!arguments) {
        brew_note(brew, "unknown", "the system call at line %zu names no command", line_number);
        ++brew->helpers;
        brew->ruby_body = 1;
        return 0;
    }
    /* a Homebrew system call runs in the formula's working directory, which is the
       source root, while a Holy build step starts in the build directory */
    fprintf(brew->out, "step build /bin/sh <<BUILD\ncd \"$HOLY_SRC\" || exit 1\n%s\nBUILD\n",
            buffer);
    brew_note(brew, "carried", "the system call at line %zu becomes a build step that runs the "
              "same command in the source root with the Homebrew prefix rewritten onto the build "
              "root", line_number);
    return 1;
}

static int skip_comment(const char *line, size_t *length)
{
    size_t at = 0;
    while (at < *length && isspace((unsigned char)line[at])) ++at;
    if (at < *length && line[at] == '#') { *length = 0; return 1; }
    return 0;
}

static int opens_block(const char *line, size_t length)
{
    static const char *const words[] = { "if ", "unless ", "case ", "begin", "while ",
                                         "until ", "class <<", NULL };
    size_t i, used = 0;
    while (used < length && isspace((unsigned char)line[used])) ++used;
    line += used;
    length -= used;
    if (!strncmp(line, "def ", 4) || !strncmp(line, "class <<", 8)) return 1;
    for (i = 0; words[i]; ++i)
        if (!strncmp(line, words[i], strlen(words[i]))) return 1;
    while (length && isspace((unsigned char)line[length - 1])) --length;
    if (length >= 2 && !memcmp(line + length - 2, "do", 2) &&
        (length == 2 || !isalnum((unsigned char)line[length - 3]))) return 1;
    return 0;
}

static int closes_block(const char *line, size_t length)
{
    size_t used = 0;
    while (used < length && isspace((unsigned char)line[used])) ++used;
    if (used >= length) return 0;
    return used + 3 <= length && !strncmp(line + used, "end", 3) &&
           (used + 3 == length || isspace((unsigned char)line[used + 3]) ||
            line[used + 3] == '#');
}

/* the body of a block is every line up to the end that closes it */
static size_t block_body(const struct brew_line *lines, size_t from, size_t to, size_t *first)
{
    size_t depth = 1, i;
    *first = from;
    for (i = from; i < to; ++i) {
        size_t length = lines[i].length;
        skip_comment(lines[i].text, &length);
        if (closes_block(lines[i].text, length)) {
            if (!--depth) return i;
            continue;
        }
        if (opens_block(lines[i].text, length)) ++depth;
    }
    return to;
}

static void emit_body(struct brew *brew, const struct brew_line *lines, size_t from, size_t to,
                      const char *kind)
{
    size_t i;
    for (i = from; i < to; ++i) {
        const char *line = lines[i].text;
        size_t length = lines[i].length, used = 0;
        if (skip_comment(line, &length)) continue;
        while (used < length && isspace((unsigned char)line[used])) ++used;
        if (used >= length) continue;
        if (closes_block(line, length)) continue;
        if (!strncmp(line + used, "system ", 7)) {
            if (emit_system(brew, line + used, length - used, lines[i].number)) continue;
        }
        if (opens_block(line, length)) continue;
        ++brew->ruby_body;
        ++brew->preserved;
        brew_note(brew, "preserved", "the %s statement at line %zu is Ruby, so the formula is "
                  "copied beside the recipe and the build declares a ruby helper", kind,
                  lines[i].number);
    }
}

static void directive(struct brew *brew, const struct brew_line *lines, size_t index, size_t count)
{
    const struct brew_line *entry = &lines[index];
    const char *line = entry->text;
    size_t length = entry->length, used = 0, first = index + 1, body;
    char *value, *kind;
    while (used < length && isspace((unsigned char)line[used])) ++used;
    line += used;
    length -= used;
    body = block_body(lines, index + 1, count, &first);

    if (!strncmp(line, "class ", 6)) {
        const char *parent = strstr(line, "<");
        value = argument(line, length, "class");
        if (parent && strstr(parent, "Cask")) {
            brew_note(brew, "unknown", "the class inherits from a cask, which installs an "
                      "application bundle rather than building a source tree");
            brew->review = 1;
        } else if (parent && !strstr(parent, "Formula")) {
            brew_note(brew, "unknown", "the class inherits from %s, which this converter does "
                      "not read as a formula", trim((char *)parent + 1));
            brew->review = 1;
        } else {
            brew_note(brew, "carried", "the formula class of the file");
        }
        if (value) {
            char *name = package_name(value);
            if (name) {
                free(brew->name);
                brew->name = name;
            } else {
                brew_note(brew, "unknown", "the class name %s is not a package name", value);
                brew->review = 1;
            }
        }
        free(value);
        return;
    }
    if (!strncmp(line, "desc ", 5)) {
        value = argument(line, length, "desc");
        if (value && *value) {
            free(brew->summary);
            brew->summary = value;
            value = NULL;
            brew_note(brew, "carried", "the description at line %zu", entry->number);
        }
        free(value);
        return;
    }
    if (!strncmp(line, "homepage ", 9)) {
        value = argument(line, length, "homepage");
        if (value && strstr(value, "://")) {
            free(brew->homepage);
            brew->homepage = value;
            brew_note(brew, "carried", "the homepage at line %zu", entry->number);
        } else free(value);
        return;
    }
    if (!strncmp(line, "url ", 4) || !strncmp(line, "url(", 4)) {
        value = argument(line, length, "url");
        if (value && *value) {
            if (brew->url) {
                brew_note(brew, "carried", "the additional source url at line %zu", entry->number);
            } else {
                brew->url = value;
                value = NULL;
                brew_note(brew, "carried", "the source url at line %zu", entry->number);
            }
        }
        free(value);
        return;
    }
    if (!strncmp(line, "sha256 ", 7)) {
        value = argument(line, length, "sha256");
        if (value && *value && !brew->sha256) {
            brew->sha256 = value;
            value = NULL;
            brew_note(brew, "carried", "the pinned digest of the source at line %zu", entry->number);
        }
        free(value);
        return;
    }
    if (!strncmp(line, "license ", 8)) {
        value = argument(line, length, "license");
        if (value) {
            free(brew->license);
            brew->license = value;
            brew_note(brew, "carried", "the license %s, which a Holy recipe has no field for, "
                      "so the report names it", value);
            value = NULL;
        }
        free(value);
        return;
    }
    if (!strncmp(line, "revision ", 9)) {
        value = argument(line, length, "revision");
        if (value) {
            free(brew->release);
            brew->release = value;
            brew_note(brew, "carried", "the revision %s becomes the release", value);
            value = NULL;
        }
        free(value);
        return;
    }
    if (!strncmp(line, "version ", 8)) {
        value = argument(line, length, "version");
        if (value) {
            free(brew->version);
            brew->version = value;
            brew_note(brew, "carried", "the version %s of the formula", value);
            value = NULL;
        }
        free(value);
        return;
    }
    if (!strncmp(line, "head ", 5)) {
        ++brew->helpers;
        brew_note(brew, "unknown", "the head at line %zu is a development checkout, and the "
                  "build compiles the pinned source", entry->number);
        return;
    }
    if (!strncmp(line, "depends_on ", 11)) {
        value = argument(line, length, "depends_on");
        kind = relation(line, length);
        if (value && *value) {
            if (kind && !strcmp(kind, "build")) {
                push_dependency(brew, value, "build-depend");
                brew_note(brew, "carried", "the build dependency %s at line %zu becomes a build "
                          "requirement", value, entry->number);
            } else if (kind && strcmp(kind, "required")) {
                ++brew->optional;
                brew->review = 1;
                brew_note(brew, "unknown", "the dependency %s at line %zu is %s, and a build "
                          "cannot promise a feature it did not ask for", value, entry->number,
                          kind);
            } else {
                push_dependency(brew, value, "depend");
                brew_note(brew, "carried", "the dependency %s at line %zu becomes a runtime "
                          "requirement", value, entry->number);
            }
        }
        free(value);
        free(kind);
        return;
    }
    if (!strncmp(line, "uses_from_macos ", 16)) {
        value = argument(line, length, "uses_from_macos");
        brew_note(brew, "unknown", "the macOS framework %s at line %zu has no counterpart in a "
                  "Linux build", value ? value : "?", entry->number);
        ++brew->helpers;
        free(value);
        return;
    }
    if (!strncmp(line, "bottle ", 7)) {
        brew_note(brew, "unknown", "the bottle block at line %zu is a prebuilt foreign binary, "
                  "and the build runs the source the formula pins", entry->number);
        ++brew->helpers;
        return;
    }
    if (!strncmp(line, "resource ", 9)) {
        char *url = NULL, *digest = NULL;
        size_t i;
        value = argument(line, length, "resource");
        for (i = first; i < body; ++i) {
            const char *inner = lines[i].text;
            size_t length2 = lines[i].length, used = 0;
            if (skip_comment(inner, &length2)) continue;
            while (used < length2 && isspace((unsigned char)inner[used])) ++used;
            inner += used;
            length2 -= used;
            if (!strncmp(inner, "url ", 4) || !strncmp(inner, "url(", 4)) {
                free(url);
                url = argument(inner, length2, "url");
            } else if (!strncmp(inner, "sha256 ", 7)) {
                free(digest);
                digest = argument(inner, length2, "sha256");
            }
        }
        if (url && *url && digest && *digest) {
            char label[128];
            snprintf(label, sizeof label, "resource-%s", value ? value : "unnamed");
            if (!push_source(brew, label, url, digest)) goto resource_done;
            brew_note(brew, "carried", "the resource %s at line %zu becomes a fetched source, "
                      "since a build needs it before it runs", value ? value : "?", entry->number);
        } else {
            ++brew->helpers;
            brew->review = 1;
            brew_note(brew, "helper", "the resource %s at line %zu is prepared by a Ruby block "
                      "this converter does not read, so the build has to supply it",
                      value ? value : "?", entry->number);
        }
resource_done:
        free(url);
        free(digest);
        free(value);
        return;
    }
    if (!strncmp(line, "patch ", 6)) {
        int have_url = 0, have_digest = 0;
        size_t i;
        for (i = first; i < body; ++i) {
            const char *inner = lines[i].text;
            size_t length2 = lines[i].length, used = 0;
            if (skip_comment(inner, &length2)) continue;
            while (used < length2 && isspace((unsigned char)inner[used])) ++used;
            inner += used;
            length2 -= used;
            if (!strncmp(inner, "url ", 4) || !strncmp(inner, "url(", 4)) have_url = 1;
            else if (!strncmp(inner, "sha256 ", 7)) have_digest = 1;
        }
        if (have_url && have_digest) {
            char label[64], url[1024], digest[128];
            url[0] = digest[0] = 0;
            snprintf(label, sizeof label, "patch%zu", brew->source_count + 1);
            for (i = first; i < body; ++i) {
                const char *inner = lines[i].text;
                size_t length2 = lines[i].length, used = 0;
                char *value2;
                if (skip_comment(inner, &length2)) continue;
                while (used < length2 && isspace((unsigned char)inner[used])) ++used;
                inner += used;
                length2 -= used;
                if (!strncmp(inner, "url ", 4) || !strncmp(inner, "url(", 4)) {
                    value2 = argument(inner, length2, "url");
                    if (value2) {
                        snprintf(url, sizeof url, "%s", value2);
                        free(value2);
                    }
                } else if (!strncmp(inner, "sha256 ", 7)) {
                    value2 = argument(inner, length2, "sha256");
                    if (value2) {
                        snprintf(digest, sizeof digest, "%s", value2);
                        free(value2);
                    }
                }
            }
            if (!push_source(brew, label, url, digest)) goto patch_done;
            fprintf(brew->out, "step prepare /bin/sh <<PATCH\n"
                               "patch -p1 -i \"$HOLY_SRC/sources/%s\"\nPATCH\n", label);
            brew_note(brew, "carried", "the patch at line %zu is a fetched source that applies "
                      "with -p1 before the build", entry->number);
        } else {
            ++brew->helpers;
            brew->review = 1;
            brew_note(brew, "helper", "the patch block at line %zu applies its change from a "
                      "Ruby expression, which this converter does not evaluate", entry->number);
        }
patch_done:
        return;
    }
    if (!strncmp(line, "def ", 4)) {
        value = argument(line, length, "def ");
        if (value && !strcmp(value, "install")) {
            emit_body(brew, lines, first, body, "install");
            brew_note(brew, "semantic-change", "the def install body at line %zu becomes build "
                      "steps, and the package phase copies the payload, so an install that wrote "
                      "into prefix now writes into the build root", entry->number);
        } else {
            ++brew->helpers;
            brew->review = 1;
            brew_note(brew, "unknown", "the def %s at line %zu runs after a Homebrew build in a "
                      "prefix this converter has no phase for", value ? value : "?", entry->number);
        }
        free(value);
        return;
    }
    if (!strncmp(line, "test ", 5)) {
        ++brew->helpers;
        brew->review = 1;
        brew_note(brew, "helper", "the test block at line %zu is Ruby, and the build has no "
                  "Homebrew test harness to run it in", entry->number);
        return;
    }
    if (!strncmp(line, "service ", 8)) {
        ++brew->helpers;
        brew_note(brew, "unknown", "the service block at line %zu describes a launchd job, and a "
                  "Linux target has no such service", entry->number);
        return;
    }
    if (!strncmp(line, "on_linux ", 9)) {
        emit_body(brew, lines, first, body, "on_linux");
        brew_note(brew, "semantic-change", "the on_linux block at line %zu is carried, since a "
                  "Holy build runs on Linux", entry->number);
        return;
    }
    if (!strncmp(line, "on_macos ", 9) || !strncmp(line, "on_arm ", 7) ||
        !strncmp(line, "on_intel ", 9)) {
        ++brew->helpers;
        brew_note(brew, "unknown", "the %.*s block at line %zu names a platform a Holy build "
                  "does not run on", (int)strcspn(line, " \t\r\n"), line, entry->number);
        return;
    }
    if (!strncmp(line, "if ", 3)) {
        if (strstr(line, "linux?"))
            brew_note(brew, "semantic-change", "the condition at line %zu asks for Linux, so the "
                      "body is carried without a conditional", entry->number);
        else {
            ++brew->helpers;
            brew->review = 1;
            brew_note(brew, "unknown", "the condition at line %zu is %.*s, and this converter "
                      "does not evaluate it", entry->number, (int)length, line);
        }
        return;
    }
    {
        size_t key_length = strcspn(line, " \t\r\n(");
        ++brew->helpers;
        if (key_length > 3 && !strncmp(line + key_length - 1, "!", 1)) {
            brew_note(brew, "unknown", "the directive %.*s at line %zu stops a formula from "
                      "building, and a Holy recipe has no equivalent gate", (int)key_length, line,
                      entry->number);
            return;
        }
        brew_note(brew, "unknown", "the directive %.*s at line %zu is not one this converter "
                  "reads", (int)key_length, line, entry->number);
        brew->review = 1;
    }
}

static int read_lines(const char *input, struct brew_line **out, size_t *count,
                      char **storage)
{
    FILE *stream = fopen(input, "rb");
    struct stat st;
    char *text;
    size_t used = 0, lines = 0, capacity = 64, at = 0;
    struct brew_line *list;
    if (!stream) return 6;
    if (fstat(fileno(stream), &st) || !S_ISREG(st.st_mode) || st.st_size < 1 ||
        st.st_size > BREW_LIMIT) { fclose(stream); return 2; }
    text = malloc((size_t)st.st_size + 1);
    if (!text) { fclose(stream); return 1; }
    while (used < (size_t)st.st_size) {
        size_t got = fread(text + used, 1, (size_t)st.st_size - used, stream);
        if (!got) break;
        used += got;
    }
    fclose(stream);
    if (used != (size_t)st.st_size || memchr(text, 0, used)) { free(text); return 2; }
    text[used] = 0;
    list = malloc(capacity * sizeof *list);
    if (!list) { free(text); return 1; }
    while (at < used) {
        char *stop = memchr(text + at, '\n', used - at);
        size_t length = stop ? (size_t)(stop - (text + at)) : used - at;
        struct brew_line *grown;
        if (lines == capacity) {
            capacity *= 2;
            grown = realloc(list, capacity * sizeof *list);
            if (!grown) { free(list); free(text); return 1; }
            list = grown;
        }
        text[at + length] = 0;
        list[lines].text = text + at;
        list[lines].length = length;
        list[lines].number = lines + 1;
        ++lines;
        at += length + 1;
    }
    *out = list;
    *count = lines;
    *storage = text;
    return 0;
}

int holy_convert_brew(const char *input, const char *source, const char *output)
{
    struct brew brew;
    struct brew_line *lines = NULL;
    struct recipe_note note = {0};
    char *data = NULL, *directory = NULL, *cut, recipe_path[4096], report_path[4096];
    char fragment[4096];
    char *at, *version = NULL, *ruby_digest = NULL, summary[1024];
    size_t count = 0, i, depth = 0;
    int result = 1, read_status;

    memset(&brew, 0, sizeof brew);
    brew.note = &note;
    brew.name = strdup("formula");
    brew.version = strdup("0");
    brew.release = strdup("1");
    brew.arch = strdup("any");
    if (!brew.name || !brew.version || !brew.release || !brew.arch) goto done;

    if (!input || !output || !*output) {
        fputs("usage: holypkg convert NAME.rb --source NAME --output NEW_DIRECTORY\n", stderr);
        result = 2;
        goto done;
    }
    if (!source || !*source || !strcmp(source, "local")) {
        fputs("holypkg: a converted recipe needs the source name it came from\n", stderr);
        result = 2;
        goto done;
    }
    for (i = 0; source[i]; ++i)
        if ((unsigned char)source[i] <= 32 || source[i] == ':' || source[i] == '/' ||
            source[i] == '@') {
            fputs("holypkg: invalid source name for conversion\n", stderr);
            result = 2;
            goto done;
        }
    read_status = read_lines(input, &lines, &count, &data);
    if (read_status == 6) {
        fprintf(stderr, "holypkg: formula unavailable: %s\n", input);
        result = read_status;
        goto done;
    }
    if (read_status) {
        fputs("holypkg: a Homebrew formula is Ruby text, and this converter reads no other form\n",
              stderr);
        result = 2;
        goto done;
    }
    directory = strdup(input);
    if (!directory) goto done;
    cut = strrchr(directory, '/');
    if (cut && cut != directory) *cut = 0;
    else {
        free(directory);
        directory = strdup(".");
        if (!directory) goto done;
    }
    brew.directory = directory;
    brew.input = input;
    brew.out = open_memstream(&brew.step_text, &brew.step_size);
    if (!brew.out) goto done;

    for (i = 0; i < count; ++i) {
        size_t length = lines[i].length, used = 0;
        if (skip_comment(lines[i].text, &length)) continue;
        while (used < length && isspace((unsigned char)lines[i].text[used])) ++used;
        if (used >= length) continue;
        if (closes_block(lines[i].text, length)) { if (depth) --depth; continue; }
        if (depth) {
            if (opens_block(lines[i].text, length)) ++depth;
            continue;
        }
        directive(&brew, lines, i, count);
        if (opens_block(lines[i].text, length)) depth = 1;
    }
    if (depth) {
        fputs("holypkg: the formula has a block that never ends\n", stderr);
        goto done;
    }
    if (brew.url) {
        /* the engine extracts an archive under its own name, while a Homebrew build
           runs in the source root, so one lift puts the tree where the steps expect it */
        fprintf(brew.out,
                "step unpack /bin/sh <<UNPACK\n"
                "for entry in \"$HOLY_SRC\"/*; do\n"
                "  [ -d \"$entry\" ] || continue\n"
                "  for child in \"$entry\"/* \"$entry\"/.[!.]* \"$entry\"/..?*; do\n"
                "    [ -e \"$child\" ] || continue\n"
                "    mv \"$child\" \"$HOLY_SRC/\"\n"
                "  done\n"
                "  rmdir \"$entry\" 2>/dev/null || true\n"
                "done\n"
                "# a distribution tarball keeps one top directory, and a Homebrew build\n"
                "# runs in the source root, so a single remaining directory is lifted\n"
                "set -- \"$HOLY_SRC\"/*\n"
                "if [ \"$#\" = 1 ] && [ -d \"$1\" ]; then\n"
                "  for child in \"$1\"/* \"$1\"/.[!.]* \"$1\"/..?*; do\n"
                "    [ -e \"$child\" ] || continue\n"
                "    mv \"$child\" \"$HOLY_SRC/\"\n"
                "  done\n"
                "  rmdir \"$1\" 2>/dev/null || true\n"
                "fi\n"
                "UNPACK\n");
        brew_note(&brew, "semantic-change", "the engine extracts the archive under its own name, "
                  "and one lift puts the source root where a Homebrew build runs");
    }
    if (fclose(brew.out)) { brew.out = NULL; goto done; }
    brew.out = NULL;
    if (!brew.url) {
        fputs("holypkg: a Homebrew formula states no url, and a build has no source to fetch\n",
              stderr);
        goto done;
    }
    if (!brew.sha256) {
        fputs("holypkg: a Homebrew formula states no sha256, and a network source needs a pinned "
              "digest\n", stderr);
        goto done;
    }
    if (!strcmp(brew.version, "0")) {
        version = version_from_url(brew.url);
        if (version) {
            free(brew.version);
            brew.version = version;
            version = NULL;
            brew_note(&brew, "carried", "the version %s comes from the source url, since a "
                      "formula records no version of its own", brew.version);
        } else {
            brew_note(&brew, "semantic-change", "the formula states no version and its url "
                      "carries none, so the recipe records zero and the build report names it");
        }
    }
    if (mkdir(output, 0700) && errno != EEXIST) {
        fprintf(stderr, "holypkg: conversion directory unavailable: %s\n", output);
        goto done;
    }
    if (brew.ruby_body) {
        /* the Ruby the converter could not translate travels beside the recipe, and
           the build needs an interpreter to run it */
        snprintf(fragment, sizeof fragment, "%s/homebrew-install.rb", output);
        ruby_digest = malloc(65);
        if (!ruby_digest || !holy_copy_and_hash(input, fragment, ruby_digest)) goto done;
        push_dependency(&brew, "ruby", "build-depend");
        brew_note(&brew, "helper", "the install body keeps %zu Ruby statements, so the formula "
                  "is copied beside the recipe as homebrew-install.rb and the build declares a "
                  "ruby build requirement", brew.preserved);
        holy_note_environment(brew.note, "homebrew-ruby");
    }
    snprintf(recipe_path, sizeof recipe_path, "%s/%s.recipe", output, brew.name);
    snprintf(report_path, sizeof report_path, "%s/conversion", output);
    brew.out = fopen(recipe_path, "wb");
    if (!brew.out) {
        fprintf(stderr, "holypkg: recipe unavailable: %s\n", recipe_path);
        goto done;
    }
    fputs("format holy-recipe-1\nname ", brew.out); holy_token(brew.out, brew.name);
    fputs("\nversion ", brew.out); holy_token(brew.out, brew.version);
    fputs("\nrelease ", brew.out); holy_token(brew.out, brew.release);
    fputs("\narch ", brew.out); holy_token(brew.out, brew.arch);
    fputs("\nlibc any\n", brew.out);
    if (brew.summary) {
        fputs("summary ", brew.out); holy_token(brew.out, brew.summary);
        fputc('\n', brew.out);
    }
    if (brew.homepage) {
        fputs("homepage ", brew.out); holy_token(brew.out, brew.homepage);
        fputc('\n', brew.out);
    }
    fputs("x-source-family homebrew\nx-converter homebrew-1\n", brew.out);
    fputs("x-brew-class ", brew.out); holy_token(brew.out, brew.name);
    fputc('\n', brew.out);
    fputs("source source ", brew.out); holy_token(brew.out, brew.url);
    fputc('\n', brew.out);
    fputs("source-sha256 source ", brew.out); holy_token(brew.out, brew.sha256);
    fputc('\n', brew.out);
    for (i = 0; i < brew.source_count; ++i) {
        fputs("source ", brew.out); holy_token(brew.out, brew.sources[i].label);
        fputc(' ', brew.out); holy_token(brew.out, brew.sources[i].url);
        fputc('\n', brew.out);
        fputs("source-sha256 ", brew.out); holy_token(brew.out, brew.sources[i].label);
        fputc(' ', brew.out); holy_token(brew.out, brew.sources[i].digest);
        fputc('\n', brew.out);
    }
    for (i = 0; i < brew.build_count; ++i) {
        fputs("build-depend ", brew.out); holy_token(brew.out, brew.build_depends[i]);
        fputs(" \"any\" \"-\"\n", brew.out);
    }
    for (i = 0; i < brew.depends_count; ++i) {
        fputs("depend ", brew.out); holy_token(brew.out, brew.depends[i]);
        fputs(" \"any\" \"-\"\n", brew.out);
    }
    fputs("output ", brew.out); holy_token(brew.out, brew.name);
    fputs(" runtime\n", brew.out);
    if (brew.step_text && brew.step_size)
        fwrite(brew.step_text, 1, brew.step_size, brew.out);
    holy_note_environment_records(brew.out, &note);
    if (ferror(brew.out) || fclose(brew.out)) { brew.out = NULL; goto done; }
    brew.out = fopen(report_path, "wb");
    if (!brew.out) {
        fprintf(stderr, "holypkg: report unavailable: %s\n", report_path);
        goto done;
    }
    fputs("format holy-recipe-conversion-1\nconverter homebrew-1\n", brew.out);
    fputs("source-name ", brew.out); holy_token(brew.out, source);
    fputc('\n', brew.out);
    at = strrchr(input, '/');
    fputs("source-file ", brew.out); holy_token(brew.out, at ? at + 1 : input);
    fputc('\n', brew.out);
    {
        char digest[65];
        if (holy_hash_file(input, digest)) {
            fputs("source-sha256 ", brew.out); holy_token(brew.out, digest);
            fputc('\n', brew.out);
        }
    }
    fputs("name ", brew.out); holy_token(brew.out, brew.name); fputc('\n', brew.out);
    fputs("version ", brew.out); holy_token(brew.out, brew.version); fputc('\n', brew.out);
    fputs("release ", brew.out); holy_token(brew.out, brew.release); fputc('\n', brew.out);
    fputs("arch ", brew.out); holy_token(brew.out, brew.arch); fputc('\n', brew.out);
    if (brew.license) {
        fputs("license ", brew.out); holy_token(brew.out, brew.license);
        fputc('\n', brew.out);
    }
    if (ruby_digest) {
        fputs("preserved homebrew-install.rb ", brew.out);
        holy_token(brew.out, ruby_digest);
        fputc('\n', brew.out);
    }
    snprintf(summary, sizeof summary, "%s.recipe", brew.name);
    fputs("recipe ", brew.out); holy_token(brew.out, summary);
    fputc('\n', brew.out);
    fprintf(brew.out, "status %s\n", brew.review ? "review-required" : "native");
    holy_note_environments(brew.out, &note);
    for (i = 0; i < note.count; ++i) fprintf(brew.out, "%s\n", note.lines[i]);
    fprintf(brew.out, "summary carried %zu preserved %zu helper %zu unknown %zu changes %zu\n",
            note.carried, note.preserved, note.helper, note.unknown, note.changes);
    fprintf(brew.out, "dependency runtime %zu build %zu optional %zu sources %zu\n",
            brew.depends_count, brew.build_count, brew.optional, brew.source_count + 1);
    if (fclose(brew.out)) { brew.out = NULL; goto done; }
    brew.out = NULL;
    result = brew.review ? 3 : 0;
    printf("converted %s status %s\n", brew.name, result ? "review-required" : "native");
    printf("recipe %s\nreport %s\n", recipe_path, report_path);
    if (result)
        fputs("holypkg: the converted formula needs review before its first build\n", stderr);
done:
    if (brew.out) fclose(brew.out);
    for (i = 0; i < brew.depends_count; ++i) free(brew.depends[i]);
    for (i = 0; i < brew.build_count; ++i) free(brew.build_depends[i]);
    free(brew.depends);
    free(brew.build_depends);
    for (i = 0; i < brew.source_count; ++i) {
        free(brew.sources[i].label);
        free(brew.sources[i].url);
        free(brew.sources[i].digest);
    }
    free(brew.sources);
    free(brew.step_text);
    free(brew.name);
    free(brew.version);
    free(brew.release);
    free(brew.arch);
    free(brew.license);
    free(brew.homepage);
    free(brew.url);
    free(brew.sha256);
    free(ruby_digest);
    free(version);
    free(directory);
    free(lines);
    free(data);
    holy_note_free(&note);
    return result;
}
