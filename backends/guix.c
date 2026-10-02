/* a Guix package definition to a holy-recipe(5) manifest; see man/holy-recipe.5
   and man/holypkg.8. a definition is Scheme, and this converter reads the text and
   never evaluates it. the fields a definition states are carried, an origin becomes
   a pinned source with the base32 digest it writes decoded into the hex digest a
   Holy source needs, a build system becomes the shell that runs the same tools in
   the same order, inputs and native-inputs become runtime and build requirements,
   and an argument list whose entries are literal strings is carried while anything
   else is named, since only the definition's author knows what an expression
   computes. */

#define _POSIX_C_SOURCE 200809L
#include "guix.h"
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

#define GUIX_LIMIT (4 * 1024 * 1024)
#define GUIX_ITEMS 1024

struct guix_item {
    char **entries;
    size_t count, limit;
};

struct guix {
    FILE *out;
    char *step_text;
    size_t step_size;
    struct recipe_note *note;
    char *name, *version, *release, *arch;
    char *synopsis, *homepage, *license, *build_system;
    char *url, *sha256, *snippet;
    /* the literal flag strings an arguments list carries, one buffer per phase */
    struct holy_text configure_flags, make_flags, install_flags;
    struct guix_item inputs, native_inputs;
    int review;
};

static int guix_report(struct guix *guix, const char *kind, const char *format, ...)
{
    char body[1024];
    va_list arguments;
    va_start(arguments, format);
    if (vsnprintf(body, sizeof body, format, arguments) < 0) { va_end(arguments); return 0; }
    va_end(arguments);
    if (!strcmp(kind, "unknown") || !strcmp(kind, "helper")) guix->review = 1;
    return holy_note_add(guix->note, kind, "%s", body);
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

/* the Guix base32 alphabet, which omits the letters a hex digest cannot be confused
   with */
static int base32_value(int value)
{
    const char *alphabet = "0123456789abcdfghijklmnopqrstuvwxyz";
    const char *at = strchr(alphabet, value);
    return at && value ? (int)(at - alphabet) : -1;
}

/* a Guix digest is base32 of 32 bytes, which a Holy source records as hex */
static char *decode_base32(const char *text, size_t length)
{
    char *digest;
    size_t i, used = 0;
    unsigned bits = 0;
    unsigned value = 0;
    if (length != 52) return NULL;
    digest = malloc(65);
    if (!digest) return NULL;
    for (i = 0; i < length; ++i) {
        int digit = base32_value((unsigned char)text[i]);
        if (digit < 0) { free(digest); return NULL; }
        value = (value << 5) | (unsigned)digit;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (used >= 32) { free(digest); return NULL; }
            snprintf(digest + used * 2, 3, "%02x", (unsigned)((value >> bits) & 0xff));
            ++used;
        }
    }
    if (used != 32) { free(digest); return NULL; }
    digest[64] = 0;
    return digest;
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

static void free_item(struct guix_item *item)
{
    size_t i;
    for (i = 0; i < item->count; ++i) free(item->entries[i]);
    free(item->entries);
    memset(item, 0, sizeof *item);
}

/* the text of one field, which a Guix definition writes as a quoted string */
static char *string_field(const char *text, size_t length, const char *field)
{
    const char *at = text;
    size_t field_length = strlen(field);
    while ((at = strstr(at, field)) != NULL) {
        const char *stop = at + field_length;
        while (stop < text + length && (*stop == ' ' || *stop == '\t' || *stop == '\n')) ++stop;
        if (stop < text + length && *stop == '"') {
            const char *end = stop + 1;
            char *value;
            while (end < text + length && *end != '"') {
                if (*end == '\\' && end + 1 < text + length) ++end;
                ++end;
            }
            if (end >= text + length) return NULL;
            value = malloc((size_t)(end - stop));
            if (!value) return NULL;
            memcpy(value, stop + 1, (size_t)(end - stop - 1));
            value[end - stop - 1] = 0;
            return trim(value);
        }
        at += field_length;
    }
    return NULL;
}

/* every string literal in the value of a field, which is how a uri written as a
   string-append and a digest wrapped in base32 are both read */
static int collect_strings(const char *text, size_t length, const char *field,
                           struct guix_item *item)
{
    const char *at = strstr(text, field);
    const char *stop;
    int depth = 0;
    if (!at) return 0;
    at += strlen(field);
    while (at < text + length && isspace((unsigned char)*at)) ++at;
    if (at >= text + length) return 0;
    if (*at == '(') {
        /* the value is a form, so its own text is what the literals are read from */
        stop = at;
        while (stop < text + length) {
            if (*stop == '(') ++depth;
            else if (*stop == ')') { if (!--depth) break; }
            ++stop;
        }
        if (stop >= text + length) return 0;
        ++at;
    } else if (*at == '"') {
        /* the value is the string itself, as a uri is usually written */
        stop = at + 1;
        while (stop < text + length && *stop != '"') {
            if (*stop == '\\' && stop + 1 < text + length) ++stop;
            ++stop;
        }
        if (stop >= text + length) return 0;
        ++stop;
    } else return 0;
    for (; at < stop; ++at) {
        const char *start;
        char *value;
        if (*at != '"') continue;
        start = ++at;
        while (at < stop && *at != '"') {
            if (*at == '\\' && at + 1 < stop) ++at;
            ++at;
        }
        value = malloc((size_t)(at - start) + 1);
        if (!value) return -1;
        memcpy(value, start, (size_t)(at - start));
        value[at - start] = 0;
        if (!push(&item->entries, &item->count, &item->limit, value)) { free(value); return -1; }
        free(value);
    }
    return 1;
}

/* a bare symbol after a field, which is how a definition names its build system */
static char *symbol_field(const char *text, size_t length, const char *field)
{
    const char *at = strstr(text, field);
    const char *start;
    char *value;
    if (!at) return NULL;
    at += strlen(field);
    while (at < text + length && isspace((unsigned char)*at)) ++at;
    if (at >= text + length || *at == '(') return NULL;
    start = at;
    while (at < text + length && *at != ' ' && *at != '\t' && *at != '\n' && *at != ')') ++at;
    value = malloc((size_t)(at - start) + 1);
    if (!value) return NULL;
    memcpy(value, start, (size_t)(at - start));
    value[at - start] = 0;
    return value;
}

/* the first name of a list, which is how a definition names a package, a build
   system or an input */
static char *head_name(const char *text, size_t length, const char *field)
{
    const char *at = text;
    size_t field_length = strlen(field);
    while ((at = strstr(at, field)) != NULL) {
        const char *stop = at + field_length;
        const char *start;
        while (stop < text + length && (*stop == ' ' || *stop == '\t' || *stop == '\n')) ++stop;
        if (stop < text + length && *stop == '(') {
            ++stop;
            while (stop < text + length && (*stop == ' ' || *stop == '\t' || *stop == '\n')) ++stop;
            start = stop;
            while (stop < text + length && *stop != ' ' && *stop != '\t' && *stop != '\n' &&
                   *stop != ')' && *stop != '(') ++stop;
            {
                char *name = malloc((size_t)(stop - start) + 1);
                if (!name) return NULL;
                memcpy(name, start, (size_t)(stop - start));
                name[stop - start] = 0;
                return name;
            }
        }
        at += field_length;
    }
    return NULL;
}

/* every name in a list field, which is how inputs and native-inputs are written */
static int list_field(struct guix *guix, const char *text, size_t length, const char *field,
                      struct guix_item *item, const char *kind)
{
    const char *at = text;
    size_t field_length = strlen(field);
    while ((at = strstr(at, field)) != NULL) {
        const char *stop;
        const char *body;
        int depth = 0;
        at += field_length;
        while (at < text + length && (*at == ' ' || *at == '\t' || *at == '\n')) ++at;
        if (at >= text + length || *at != '(') continue;
        stop = at;
        while (stop < text + length) {
            if (*stop == '(') ++depth;
            else if (*stop == ')') {
                if (!--depth) break;
            }
            ++stop;
        }
        if (stop >= text + length) return 0;
        body = at + 1;
        /* the form is a call to list, so the symbol that heads it names nothing */
        while (body < stop && isspace((unsigned char)*body)) ++body;
        if (body + 4 <= stop && !strncmp(body, "list", 4) &&
            (body + 4 == stop || isspace((unsigned char)body[4]))) body += 4;
        while (body < stop && isspace((unsigned char)*body)) ++body;
        while (body < stop) {
            const char *start;
            char *name;
            if (isspace((unsigned char)*body) || *body == ',' || *body == ')' ||
                *body == '(') {
                /* a list entry is a name with an optional version constraint, and only
                   the name is a requirement */
                if (*body == '(') {
                    /* a versioned entry is a name with a constraint, and only the name
                       is a requirement */
                    const char *entry = body + 1;
                    const char *start = entry;
                    int entry_depth = 1;
                    while (entry < stop && isspace((unsigned char)*entry)) ++entry;
                    if (entry + 4 <= stop && !strncmp(entry, "list", 4) &&
                        (entry + 4 == stop || isspace((unsigned char)entry[4]) ||
                         entry[4] == ')')) entry += 4;
                    while (entry < stop && isspace((unsigned char)*entry)) ++entry;
                    start = entry;
                    while (entry < stop && !isspace((unsigned char)*entry) &&
                           *entry != ')' && *entry != '(') ++entry;
                    size_t name_length = (size_t)(entry - start);
                    int quoted = name_length > 1 && start[0] == '"' && start[name_length - 1] == '"';
                    if (quoted) { ++start; name_length -= 2; }
                    name = malloc(name_length + 1);
                    if (!name) return 0;
                    memcpy(name, start, name_length);
                    name[name_length] = 0;
                    if (!push(&item->entries, &item->count, &item->limit, name)) {
                        free(name);
                        return 0;
                    }
                    guix_report(guix, "carried", "the %s %s in the %s list carries a version "
                                "constraint, and only the name is a requirement",
                                kind, name, field);
                    free(name);
                    while (++body < stop && entry_depth) {
                        if (*body == '(') ++entry_depth;
                        else if (*body == ')') --entry_depth;
                    }
                } else ++body;
                continue;
            }
            start = body;
            while (body < stop && !isspace((unsigned char)*body) && *body != ',' &&
                   *body != ')' && *body != '(') ++body;
            name = malloc((size_t)(body - start) + 1);
            if (!name) return 0;
            memcpy(name, start, (size_t)(body - start));
            name[body - start] = 0;
            if (!push(&item->entries, &item->count, &item->limit, name)) { free(name); return 0; }
            guix_report(guix, "carried", "the %s %s in the %s list becomes a %s requirement",
                        kind, name, field, kind);
            free(name);
        }
        at = stop;
    }
    return 1;
}

/* the literal strings of an argument entry, which is the only form this reader
   carries; anything else is an expression and is named */
static int argument_flags(struct guix *guix, const char *text, size_t length, const char *keyword,
                          struct holy_text *into)
{
    const char *at = strstr(text, keyword);
    if (!at) return 1;
    at += strlen(keyword);
    while (at < text + length && (isspace((unsigned char)*at) || *at == '\'')) ++at;
    if (at >= text + length || *at != '(') {
        guix_report(guix, "unknown", "the %s argument is a Scheme expression, which this converter "
                    "does not evaluate", keyword);
        guix->review = 1;
        return 1;
    }
    {
        const char *stop = at;
        int depth = 0;
        while (stop < text + length) {
            if (*stop == '(') ++depth;
            else if (*stop == ')' && !--depth) break;
            ++stop;
        }
        if (stop >= text + length) return 0;
        ++at;
        while (at < stop && isspace((unsigned char)*at)) ++at;
        /* the argument is wrapped in a list call, and the symbol that heads it names
           nothing */
        if (at + 4 <= stop && !strncmp(at, "list", 4) &&
            (at + 4 == stop || isspace((unsigned char)at[4]) || at[4] == ')')) at += 4;
        for (; at < stop; ++at) {
            const char *start;
            char *value;
            while (at < stop && (isspace((unsigned char)*at) || *at == '\'' || *at == ')' ||
                                 *at == ',')) ++at;
            if (at >= stop) break;
            if (*at == '(') {
                /* a guix argument is either a list of strings or a list of lists of
                   strings, and both carry the same flags */
                int entry_depth = 1, bare = 0;
                while (++at < stop && entry_depth) {
                    if (*at == '(') ++entry_depth;
                    else if (*at == ')') --entry_depth;
                    else if (*at == '"') {
                        const char *piece = ++at;
                        while (at < stop && *at != '"') ++at;
                        value = malloc((size_t)(at - piece) + 1);
                        if (!value) return 0;
                        memcpy(value, piece, (size_t)(at - piece));
                        value[at - piece] = 0;
                        if (!holy_text_add(into, " '") || !holy_text_add(into, value) ||
                            !holy_text_add(into, "'")) {
                            free(value);
                            return 0;
                        }
                        free(value);
                    } else if (!isspace((unsigned char)*at) && *at != '\'' && *at != ',') {
                        /* a bare symbol is a Scheme expression, and its text stays as the
                           definition wrote it */
                        while (at < stop && !isspace((unsigned char)*at) && *at != ')' &&
                               *at != '(') ++at;
                        bare = 1;
                    }
                }
                if (bare) {
                    guix_report(guix, "unknown", "the %s argument holds a value that is not a "
                                "literal string, so it is reported instead of rewritten", keyword);
                    guix->review = 1;
                }
                continue;
            }
            if (*at != '"') {
                guix_report(guix, "unknown", "the %s argument holds a value that is not a literal "
                            "string, so it is reported instead of rewritten", keyword);
                guix->review = 1;
                break;
            }
            start = ++at;
            while (at < stop && *at != '"') ++at;
            value = malloc((size_t)(at - start) + 1);
            if (!value) return 0;
            memcpy(value, start, (size_t)(at - start));
            value[at - start] = 0;
            if (at < stop) ++at;
            if (!holy_text_add(into, " '") || !holy_text_add(into, value) ||
                !holy_text_add(into, "'")) {
                free(value);
                return 0;
            }
            free(value);
        }
    }
    guix_report(guix, "carried", "the %s argument carries literal flag strings, which become "
                "the flags of the phase that takes them", keyword);
    return 1;
}

/* the build system becomes the tools a Guix build system runs, in the order it runs
   them; the guix build environment supplies them, and this reports the fact */
/* the engine extracts an archive under its own name while a Guix build runs in the
   source root, so one lift puts the tree where the steps expect it */
static void emit_lift(struct guix *guix)
{
    fputs("step unpack /bin/sh <<UNPACK\n"
          "for entry in \"$HOLY_SRC\"/*; do\n"
          "  [ -d \"$entry\" ] || continue\n"
          "  for child in \"$entry\"/* \"$entry\"/.[!.]* \"$entry\"/..?*; do\n"
          "    [ -e \"$child\" ] || continue\n"
          "    mv \"$child\" \"$HOLY_SRC/\"\n"
          "  done\n"
          "  rmdir \"$entry\" 2>/dev/null || true\n"
          "done\n"
          "# a distribution tarball keeps one top directory, and a guix build runs in the\n"
          "# source root, so a single remaining directory is lifted\n"
          "set -- \"$HOLY_SRC\"/*\n"
          "if [ \"$#\" = 1 ] && [ -d \"$1\" ]; then\n"
          "  for child in \"$1\"/* \"$1\"/.[!.]* \"$1\"/..?*; do\n"
          "    [ -e \"$child\" ] || continue\n"
          "    mv \"$child\" \"$HOLY_SRC/\"\n"
          "  done\n"
          "  rmdir \"$1\" 2>/dev/null || true\n"
          "fi\n"
          "UNPACK\n", guix->out);
    guix_report(guix, "semantic-change", "the engine extracts the archive under its own name, "
                "and one lift puts the source root where a guix build runs");
}

static int emit_build_system(struct guix *guix, const char *system)
{
    static const char *const gnu = "gnu-build-system";
    static const char *const cmake = "cmake-build-system";
    static const char *const meson = "meson-build-system";
    static const char *const trivial = "trivial-build-system";
    if (!system) {
        guix_report(guix, "unknown", "the definition names no build system, and a build needs "
                    "one to run");
        holy_note_environment(guix->note, "guix-build-system");
        guix->review = 1;
        return 0;
    }
    if (!strcmp(system, gnu)) {
        fputs("step prepare /bin/sh <<PREPARE\n"
              "# a guix gnu-build-system unpacks, configures, builds and installs with the\n"
              "# autotools its build environment supplies, so the same tools run here; a\n"
              "# hand written configure is left as it is\n"
              "cd \"$HOLY_SRC\" || exit 1\n"
              "if [ -f configure.ac ] || [ -f configure.in ]; then\n"
              "  autoreconf -fi\n"
              "fi\n"
              "PREPARE\n", guix->out);
        /* a guix build configures the package prefix and stages the install with
           DESTDIR, so the prefix is the payload prefix and the destination stages it */
        fprintf(guix->out, "step configure /bin/sh <<CONFIGURE\n"
                "cd \"$HOLY_SRC\" || exit 1\n"
                "./configure --prefix=/usr --build=\"$HOLY_BUILD_TARGET\" "
                "--host=\"$HOLY_BUILD_TARGET\"%s\nCONFIGURE\n",
                guix->configure_flags.data ? guix->configure_flags.data : "");
        fprintf(guix->out, "step build /bin/sh <<BUILD\n"
                "cd \"$HOLY_SRC\" || exit 1\n"
                "make -j \"$HOLY_JOBS\"%s\nBUILD\n",
                guix->make_flags.data ? guix->make_flags.data : "");
        fprintf(guix->out, "step package /bin/sh <<PACKAGE\n"
                "cd \"$HOLY_SRC\" || exit 1\n"
                "make install DESTDIR=\"$HOLY_DEST\"%s\nPACKAGE\n",
                guix->install_flags.data ? guix->install_flags.data : "");
        guix_report(guix, "semantic-change", "the guix %s runs autoreconf, configure, make and "
                    "make install inside a build container that owns the autotools, and the same "
                    "tools run here in the declared phases", system);
        return 1;
    }
    if (!strcmp(system, cmake)) {
        fputs("step configure /bin/sh <<CONFIGURE\n"
              "cd \"$HOLY_SRC\" || exit 1\n"
              "cmake -B \"$HOLY_BUILD\" -DCMAKE_INSTALL_PREFIX=\"$HOLY_DEST\"\n"
              "CONFIGURE\n", guix->out);
        fputs("step build /bin/sh <<BUILD\n"
              "cmake --build \"$HOLY_BUILD\" -j \"$HOLY_JOBS\"\n"
              "BUILD\n", guix->out);
        fprintf(guix->out, "step package /bin/sh <<PACKAGE\n"
                "cmake --build \"$HOLY_BUILD\" --target install%s\nPACKAGE\n",
                guix->install_flags.data ? guix->install_flags.data : "");
        guix_report(guix, "semantic-change", "the guix %s runs cmake configure, build and "
                    "install, and the same three commands run here", system);
        return 1;
    }
    if (!strcmp(system, meson)) {
        fputs("step configure /bin/sh <<CONFIGURE\n"
              "cd \"$HOLY_SRC\" || exit 1\n"
              "meson setup \"$HOLY_BUILD\" --prefix=\"$HOLY_DEST\"\n"
              "CONFIGURE\n", guix->out);
        fputs("step build /bin/sh <<BUILD\n"
              "meson compile -C \"$HOLY_BUILD\"\n"
              "BUILD\n", guix->out);
        fputs("step package /bin/sh <<PACKAGE\n"
              "meson install -C \"$HOLY_BUILD\" --destdir \"$HOLY_DEST\"\n"
              "PACKAGE\n", guix->out);
        guix_report(guix, "semantic-change", "the guix %s runs meson setup, compile and install, "
                    "and the same three commands run here", system);
        return 1;
    }
    if (!strcmp(system, trivial)) {
        guix_report(guix, "unknown", "the %s runs a build procedure the definition states as a "
                    "Scheme body, which this converter does not evaluate", system);
        holy_note_environment(guix->note, "guix-build-system");
        guix->review = 1;
        return 0;
    }
    guix_report(guix, "unknown", "the build system %s is not one this converter replaces, so the "
                "definition needs a build phase of its own", system);
    holy_note_environment(guix->note, "guix-build-system");
    guix->review = 1;
    return 0;
}

static int read_text(const char *path, char **out, size_t *length)
{
    FILE *stream = fopen(path, "rb");
    struct stat st;
    char *text;
    size_t used = 0;
    if (!stream) return 6;
    if (fstat(fileno(stream), &st) || !S_ISREG(st.st_mode) || st.st_size < 1 ||
        st.st_size > GUIX_LIMIT) { fclose(stream); return 2; }
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
    *out = text;
    *length = used;
    return 0;
}

int holy_convert_guix(const char *input, const char *source, const char *output)
{
    struct guix guix;
    struct recipe_note note = {0};
    char *text = NULL, *directory = NULL, *cut, recipe_path[4096], report_path[4096];
    char *at, *version = NULL, *license = NULL;
    size_t length = 0, i, read_status;
    int result = 1;

    memset(&guix, 0, sizeof guix);
    guix.note = &note;
    guix.release = strdup("1");
    guix.arch = strdup("any");
    if (!guix.release || !guix.arch) goto done;

    if (!input || !output || !*output) {
        fputs("usage: holypkg convert NAME.scm --source NAME --output NEW_DIRECTORY\n", stderr);
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
    read_status = read_text(input, &text, &length);
    if (read_status == 6) {
        fprintf(stderr, "holypkg: definition unavailable: %s\n", input);
        result = read_status;
        goto done;
    }
    if (read_status) {
        fputs("holypkg: a Guix package definition is Scheme text, and this converter reads no "
              "other form\n", stderr);
        result = 2;
        goto done;
    }
    if (!strstr(text, "(package")) {
        fputs("holypkg: the file states no package definition\n", stderr);
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
    guix.out = open_memstream(&guix.step_text, &guix.step_size);
    if (!guix.out) goto done;

    guix.name = string_field(text, length, "(name");
    if (!guix.name) {
        char *variable = head_name(text, length, "(define-public");
        if (variable) {
            guix.name = variable;
            guix_report(&guix, "semantic-change", "the definition states no name field, so the "
                        "define-public variable %s becomes the package name", variable);
        }
    }
    if (!guix.name || !*guix.name) {
        fputs("holypkg: a package definition states no name this converter can read\n", stderr);
        goto done;
    }
    guix.version = string_field(text, length, "(version");
    if (!guix.version || !*guix.version) {
        free(guix.version);
        guix.version = strdup("0");
        guix_report(&guix, "semantic-change", "the definition states no version, so the recipe "
                    "records zero and the build report names it");
    }
    guix.synopsis = string_field(text, length, "(synopsis");
    guix.homepage = string_field(text, length, "(home-page");
    license = string_field(text, length, "license:");
    if (license) {
        guix.license = license;
        license = NULL;
        guix_report(&guix, "carried", "the license %s, which a Holy recipe has no field for, so "
                    "the report names it", guix.license);
    }
    guix.build_system = symbol_field(text, length, "(build-system");
    if (!list_field(&guix, text, length, "(inputs", &guix.inputs, "runtime") ||
        !list_field(&guix, text, length, "(native-inputs", &guix.native_inputs, "build")) {
        fputs("holypkg: the definition names a dependency list this reader cannot walk\n", stderr);
        goto done;
    }

    /* an origin is a pinned source, and its digest is base32 where a Holy source
       needs hex */
    if (strstr(text, "(origin")) {
        const char *origin = strstr(text, "(origin");
        size_t left = length - (size_t)(origin - text);
        struct guix_item uri, digest;
        int method = strstr(origin, "url-fetch") != NULL;
        memset(&uri, 0, sizeof uri);
        memset(&digest, 0, sizeof digest);
        if (!method) {
            guix_report(&guix, "unknown", "the origin is not a url-fetch, so it is a local or a "
                        "generated source this converter does not fetch");
            guix.review = 1;
        } else if (collect_strings(origin, left, "(uri", &uri) != 1 || !uri.count ||
                   collect_strings(origin, left, "(sha256", &digest) != 1 || !digest.count) {
            fputs("holypkg: the origin states no uri or no sha256, and a Holy source needs "
                  "both\n", stderr);
            free_item(&uri);
            free_item(&digest);
            goto done;
        } else {
            size_t used = 0, k;
            for (k = 0; k < uri.count; ++k) used += strlen(uri.entries[k]) + 1;
            guix.url = malloc(used + 1);
            if (!guix.url) { free_item(&uri); free_item(&digest); goto done; }
            used = 0;
            for (k = 0; k < uri.count; ++k) {
                size_t piece = strlen(uri.entries[k]);
                memcpy(guix.url + used, uri.entries[k], piece);
                used += piece;
            }
            guix.url[used] = 0;
            if (uri.count > 1) {
                guix_report(&guix, "unknown", "the uri is a string-append of %zu literals, so "
                            "the address is their concatenation and the expression is reported",
                            uri.count);
                guix.review = 1;
            } else {
                guix_report(&guix, "carried", "the origin url becomes the pinned source address");
            }
            if (strstr(origin, "(base32")) {
                guix.sha256 = decode_base32(digest.entries[0], strlen(digest.entries[0]));
                if (!guix.sha256) {
                    fputs("holypkg: the origin digest is not a base32 SHA-256 this reader can "
                          "decode\n", stderr);
                    free_item(&uri);
                    free_item(&digest);
                    goto done;
                }
                guix_report(&guix, "carried", "the origin digest is base32 where a Holy source "
                            "records hex, and it is decoded into the hex form");
            } else {
                guix.sha256 = strdup(digest.entries[0]);
                if (!guix.sha256) { free_item(&uri); free_item(&digest); goto done; }
                guix_report(&guix, "carried", "the origin digest is already hex, so it is carried "
                            "as it stands");
            }
        }
        free_item(&uri);
        free_item(&digest);
    } else {
        fputs("holypkg: the definition states no origin, and a build has no source to fetch\n",
              stderr);
        goto done;
    }

    if (strstr(text, "(arguments")) {
        argument_flags(&guix, text, length, "#:configure-flags", &guix.configure_flags);
        argument_flags(&guix, text, length, "#:make-flags", &guix.make_flags);
        argument_flags(&guix, text, length, "#:install-flags", &guix.install_flags);
        if (strstr(text, "#:tests? #f")) {
            guix_report(&guix, "semantic-change", "the definition turns its test suite off, and a "
                        "Holy check phase is written only when the build asks for one");
        }
        if (strstr(text, "#:phases")) {
            guix_report(&guix, "unknown", "the definition states its own phase list, which "
                        "replaces the build system phases this converter writes");
            guix.review = 1;
        }
    }
    if (strstr(text, "(patch-shebang")) {
        guix_report(&guix, "unknown", "the definition patches shebangs, which is a Guix store "
                    "convention a Holy payload has no need for");
    }
    if (strstr(text, "modulo")) {
        guix_report(&guix, "unknown", "the definition computes a value with modulo, and a "
                    "converter that does not evaluate Scheme keeps it as written");
        guix.review = 1;
    }
    /* the build system writes its phases once the flags its arguments carry are
       known, since they belong inside the step that takes them */
    if (guix.url) emit_lift(&guix);
    emit_build_system(&guix, guix.build_system);
    if (fflush(guix.out) || fclose(guix.out)) { guix.out = NULL; goto done; }
    guix.out = NULL;

    if (mkdir(output, 0700) && errno != EEXIST) {
        fprintf(stderr, "holypkg: conversion directory unavailable: %s\n", output);
        goto done;
    }
    snprintf(recipe_path, sizeof recipe_path, "%s/%s.recipe", output, guix.name);
    snprintf(report_path, sizeof report_path, "%s/conversion", output);
    guix.out = fopen(recipe_path, "wb");
    if (!guix.out) {
        fprintf(stderr, "holypkg: recipe unavailable: %s\n", recipe_path);
        goto done;
    }
    fputs("format holy-recipe-1\nname ", guix.out); holy_token(guix.out, guix.name);
    fputs("\nversion ", guix.out); holy_token(guix.out, guix.version);
    fputs("\nrelease ", guix.out); holy_token(guix.out, guix.release);
    fputs("\narch ", guix.out); holy_token(guix.out, guix.arch);
    fputs("\nlibc any\n", guix.out);
    if (guix.synopsis) {
        fputs("summary ", guix.out); holy_token(guix.out, guix.synopsis);
        fputc('\n', guix.out);
    }
    if (guix.homepage) {
        fputs("homepage ", guix.out); holy_token(guix.out, guix.homepage);
        fputc('\n', guix.out);
    }
    fputs("x-source-family guix\nx-converter guix-1\n", guix.out);
    fputs("x-guix-build-system ", guix.out);
    holy_token(guix.out, guix.build_system ? guix.build_system : "-");
    fputc('\n', guix.out);
    /* an origin this reader cannot fetch records no address, and the report says why */
    fputs("source source ", guix.out);
    holy_token(guix.out, guix.url ? guix.url : "-");
    fputc('\n', guix.out);
    fputs("source-sha256 source ", guix.out);
    holy_token(guix.out, guix.sha256 ? guix.sha256 : "-");
    fputc('\n', guix.out);
    for (i = 0; i < guix.native_inputs.count; ++i) {
        fputs("build-depend ", guix.out); holy_token(guix.out, guix.native_inputs.entries[i]);
        fputs(" \"any\" \"-\"\n", guix.out);
    }
    for (i = 0; i < guix.inputs.count; ++i) {
        fputs("depend ", guix.out); holy_token(guix.out, guix.inputs.entries[i]);
        fputs(" \"any\" \"-\"\n", guix.out);
    }
    fputs("output ", guix.out); holy_token(guix.out, guix.name);
    fputs(" runtime\n", guix.out);
    if (guix.step_text && guix.step_size)
        fwrite(guix.step_text, 1, guix.step_size, guix.out);
    holy_note_environment_records(guix.out, &note);
    if (ferror(guix.out) || fclose(guix.out)) { guix.out = NULL; goto done; }
    guix.out = fopen(report_path, "wb");
    if (!guix.out) {
        fprintf(stderr, "holypkg: report unavailable: %s\n", report_path);
        goto done;
    }
    fputs("format holy-recipe-conversion-1\nconverter guix-1\n", guix.out);
    fputs("source-name ", guix.out); holy_token(guix.out, source);
    fputc('\n', guix.out);
    at = strrchr(input, '/');
    fputs("source-file ", guix.out); holy_token(guix.out, at ? at + 1 : input);
    fputc('\n', guix.out);
    {
        char digest[65];
        if (holy_hash_file(input, digest)) {
            fputs("source-sha256 ", guix.out); holy_token(guix.out, digest);
            fputc('\n', guix.out);
        }
    }
    fputs("name ", guix.out); holy_token(guix.out, guix.name); fputc('\n', guix.out);
    fputs("version ", guix.out); holy_token(guix.out, guix.version); fputc('\n', guix.out);
    fputs("release ", guix.out); holy_token(guix.out, guix.release); fputc('\n', guix.out);
    fputs("arch ", guix.out); holy_token(guix.out, guix.arch); fputc('\n', guix.out);
    fputs("build-system ", guix.out);
    holy_token(guix.out, guix.build_system ? guix.build_system : "-");
    fputc('\n', guix.out);
    if (guix.license) {
        fputs("license ", guix.out); holy_token(guix.out, guix.license);
        fputc('\n', guix.out);
    }
    {
        char named[300];
        snprintf(named, sizeof named, "%s.recipe", guix.name);
        fputs("recipe ", guix.out); holy_token(guix.out, named);
        fputc('\n', guix.out);
    }
    fprintf(guix.out, "status %s\n", guix.review ? "review-required" : "native");
    holy_note_environments(guix.out, &note);
    for (i = 0; i < note.count; ++i) fprintf(guix.out, "%s\n", note.lines[i]);
    fprintf(guix.out, "summary carried %zu preserved %zu helper %zu unknown %zu changes %zu\n",
            note.carried, note.preserved, note.helper, note.unknown, note.changes);
    fprintf(guix.out, "dependency runtime %zu build %zu\n", guix.inputs.count,
            guix.native_inputs.count);
    if (fclose(guix.out)) { guix.out = NULL; goto done; }
    guix.out = NULL;
    result = guix.review ? 3 : 0;
    printf("converted %s status %s\n", guix.name, result ? "review-required" : "native");
    printf("recipe %s\nreport %s\n", recipe_path, report_path);
    if (result)
        fputs("holypkg: the converted definition needs review before its first build\\n", stderr);
done:
    if (guix.out) fclose(guix.out);
    free(guix.step_text);
    free(guix.name);
    free(guix.version);
    free(guix.release);
    free(guix.arch);
    free(guix.synopsis);
    free(guix.homepage);
    free(guix.license);
    free(guix.build_system);
    free(guix.url);
    free(guix.sha256);
    free(guix.snippet);
    holy_text_free(&guix.configure_flags);
    holy_text_free(&guix.make_flags);
    holy_text_free(&guix.install_flags);
    free_item(&guix.inputs);
    free_item(&guix.native_inputs);
    free(license);
    free(version);
    free(directory);
    free(text);
    holy_note_free(&note);
    return result;
}
