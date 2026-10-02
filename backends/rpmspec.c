/* RPM spec file to holy-recipe(5) conversion; see man/holy-recipe.5 and
   man/holypkg.8. the spec is read as text and never run. a spec has no phase
   functions, so each section becomes one Holy phase and the shell inside it keeps
   its own words, with the macros this converter can resolve rewritten onto the
   exported Holy paths. */
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1
#include "rpmspec.h"
#include "shrecipe.h"

#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_MACROS 64
#define MAX_PACKAGES 24
#define MAX_SOURCES 32
#define MAX_FIELDS 128

struct spec_macro {
    char name[128];
    char value[512];
    size_t line;
};

struct spec_section {
    char name[64];
    char argument[256];
    size_t marker;
    size_t first;
    size_t last;
    size_t line;
};

struct spec_package {
    char name[256];
    char summary[1024];
    size_t line;
    size_t files_section;
    int has_files;
    int has_body;
};

struct spec_field {
    char key[64];
    char value[1024];
    size_t line;
    int package;
};

struct spec_source {
    char name[512];
    char url[1024];
    size_t line;
    int patch;
};

static int name_char(char c)
{
    return isalnum((unsigned char)c) || c == '_' || c == '-' || c == '+';
}

/* a growing text buffer, used for macro expansion */
struct text {
    char *data;
    size_t used;
    size_t capacity;
};

static int text_add(struct text *out, const char *data, size_t length)
{
    while (out->used + length + 1 > out->capacity) {
        size_t capacity = out->capacity ? out->capacity * 2 : 256;
        char *grown = realloc(out->data, capacity);
        if (!grown) return 0;
        out->data = grown;
        out->capacity = capacity;
    }
    memcpy(out->data + out->used, data, length);
    out->used += length;
    out->data[out->used] = 0;
    return 1;
}

static int text_puts(struct text *out, const char *data)
{
    return text_add(out, data, strlen(data));
}

/* a word a shell can read as an assignment value */
static int is_shell_word(const char *value)
{
    size_t index;
    if (!*value) return 0;
    for (index = 0; value[index]; ++index) {
        char c = value[index];
        if (isalnum((unsigned char)c) || c == '_' || c == '-' || c == '.' || c == '/' ||
            c == '+' || c == ' ' || c == ':')
            continue;
        return 0;
    }
    return 1;
}

/* the literal part of an identity field, which rpm may write with a macro in it.
   the macro is reported rather than evaluated, so the value stays what the spec says */
static void literal_part(const char *field, char *out, size_t size, struct recipe_note *note,
                         int *review, const char *where, size_t line)
{
    size_t length = strlen(field), used = 0;
    while (length && isspace((unsigned char)field[length - 1])) --length;
    while (used < length && field[used] != '%') ++used;
    if (!used && length && field[0] == '%') {
        /* the whole field is one macro, so its name is the only literal text there */
        used = 1;
        while (used < length && name_char(field[used])) ++used;
    }
    if (used >= size) used = size - 1;
    memcpy(out, field, used);
    out[used] = 0;
    if (used < length) {
        *review = 1;
        holy_note_add(note, "unknown", "%s carries the macro %s, so the Holy value is the "
                      "literal part only", where, field + used);
        (void)line;
    }
}

static const char *base_name(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static char *join_path(const char *directory, const char *name)
{
    char path[4096];
    if (!name || !*name || strlen(name) > 400 || strchr(name, '/') || strchr(name, '$') ||
        !strcmp(name, ".") || !strcmp(name, "..")) return NULL;
    if (snprintf(path, sizeof path, "%s/%s", directory, name) >= (int)sizeof path) return NULL;
    return strdup(path);
}


/* the text of a line without its newline and trailing blanks */
static char *clean_line(const char *start, size_t length)
{
    char *value;
    while (length && isspace((unsigned char)start[length - 1])) --length;
    while (length && isspace((unsigned char)*start)) { ++start; --length; }
    value = holy_shell_copy(start, length);
    return value;
}

/* one record per line, with the blanks around it removed and a wrapped line
   joined onto the next, the way an rpm list is written */
static char **holy_shell_lines(const char *text, size_t *count)
{
    char **list = NULL;
    size_t used = 0;
    const char *cursor = text;
    *count = 0;
    while (cursor && *cursor) {
        const char *newline = strchr(cursor, '\n');
        size_t length = newline ? (size_t)(newline - cursor) : strlen(cursor);
        char *entry = clean_line(cursor, length);
        char **grown;
        if (!entry) goto failed;
        if (!*entry) { free(entry); cursor = newline ? newline + 1 : NULL; continue; }
        /* a trailing backslash continues the record onto the next line */
        while (entry[strlen(entry) - 1] == '\\' && newline) {
            char *next = clean_line(newline + 1, strcspn(newline + 1, "\n"));
            char *joined;
            if (!next) { free(entry); goto failed; }
            entry[strlen(entry) - 1] = 0;
            joined = malloc(strlen(entry) + strlen(next) + 2);
            if (!joined) { free(entry); free(next); goto failed; }
            sprintf(joined, "%s %s", entry, next);
            free(entry);
            free(next);
            entry = joined;
            newline = strchr(newline + 1, '\n');
        }
        grown = realloc(list, (used + 2) * sizeof *grown);
        if (!grown) { free(entry); goto failed; }
        list = grown;
        list[used++] = entry;
        list[used] = NULL;
        cursor = newline ? newline + 1 : NULL;
    }
    if (!list) {
        list = malloc(sizeof *list);
        if (!list) return NULL;
        list[0] = NULL;
    }
    *count = used;
    return list;
failed:
    {
        size_t index;
        for (index = 0; index < used; ++index) free(list[index]);
        free(list);
    }
    return NULL;
}

static void holy_shell_lines_free(char **list)
{
    size_t index;
    if (!list) return;
    for (index = 0; list[index]; ++index) free(list[index]);
    free(list);
}

static const char *const phases[] = { "prepare", "build", "check", "package", NULL };

/* the phase a spec section becomes, or NULL when it is not one */
static const char *phase_of(const char *section)
{
    static const struct { const char *section; const char *phase; } mapping[] = {
        { "prep", "prepare" }, { "build", "build" }, { "check", "check" },
        { "install", "package" }, { "post", "package" }, { NULL, NULL }
    };
    size_t index;
    for (index = 0; mapping[index].section; ++index)
        if (!strcmp(section, mapping[index].section)) return mapping[index].phase;
    for (index = 0; phases[index]; ++index)
        if (!strcmp(section, phases[index])) return phases[index];
    return NULL;
}

/* the macros an rpm build environment supplies that map onto the exported paths */
static const struct { const char *macro; const char *value; } builtins[] = {
    { "_sourcedir", "$HOLY_SRC" },
    { "_srcrpmdir", "$HOLY_SRC" },
    { "_builddir", "$HOLY_BUILD" },
    { "_builddir_platform", "$HOLY_BUILD" },
    { "_topdir", "$HOLY_WORK" },
    { "buildroot", "$HOLY_DEST" },
    { "_bindir", "/usr/bin" },
    { "_sbindir", "/usr/sbin" },
    { "_libdir", "/usr/lib" },
    { "_libexecdir", "/usr/libexec" },
    { "_datadir", "/usr/share" },
    { "_includedir", "/usr/include" },
    { "_mandir", "/usr/share/man" },
    { "_sysconfdir", "/etc" },
    { "_localstatedir", "/var" },
    { "_sharedstatedir", "/var/lib" },
    { "_runstatedir", "/var/run" },
    { "_unitdir", "/usr/lib/systemd/system" },
    { "_prefix", "/usr" },
    { "_exec_prefix", "/usr" },
    { "nil", "" },
    { "dist", "" },
    { "nil", "" },
    { "_isa", "" },
    { "_arch", "" },
    { "_buildarch", "" },
    { "__brp_mangle_shebangs", "" }
};

/* expands the macros a spec body may use that this converter can resolve. a macro
   left over is reported, so an unresolved %define never reaches a step silently. */
static char *expand_macros(const char *body, size_t length, const char *name,
                           const char *version, const char *release,
                           const struct spec_macro *macros, size_t macro_count,
                           struct recipe_note *note, int *review, const char *where)
{
    struct text out = {NULL, 0, 0};
    size_t index = 0;
    char *expanded;
    if (!text_add(&out, "", 0)) return NULL;
    while (index < length) {
        char c = body[index];
        if (c != '%') {
            if (!text_add(&out, body + index, 1)) goto failed;
            ++index;
            continue;
        }
        /* an escaped percent is a literal one */
        if (index + 1 < length && body[index + 1] == '%') {
            if (!text_puts(&out, "%")) goto failed;
            index += 2;
            continue;
        }
        if (index + 1 < length && body[index + 1] == '{') {
            size_t stop = index + 2;
            int optional = 0;
            char key[256];
            size_t key_length = 0;
            const char *value = NULL;
            while (stop < length && body[stop] != '}' && key_length + 1 < sizeof key)
                key[key_length++] = body[stop++];
            key[key_length] = 0;
            if (stop < length && key_length && key[0] == '?') {
                optional = 1;
                memmove(key, key + 1, key_length);
            }
            if (stop < length && body[stop] == '}') ++stop;
            else {
                /* a malformed group is left as written so the operator sees it */
                if (!text_puts(&out, "%")) goto failed;
                ++index;
                continue;
            }
            size_t found;
            if (!strcmp(key, "name")) value = name;
            else if (!strcmp(key, "version")) value = version;
            else if (!strcmp(key, "release")) value = release;
            else {
                for (found = 0; found < macro_count; ++found)
                    if (!strcmp(macros[found].name, key)) {
                        value = macros[found].value;
                        break;
                    }
                if (!value) {
                    for (found = 0; found < sizeof builtins / sizeof *builtins; ++found)
                        if (!strcmp(builtins[found].macro, key)) {
                            value = builtins[found].value;
                            break;
                        }
                }
            }
            if (value) {
                if (!text_puts(&out, value)) goto failed;
                index = stop;
                continue;
            }
            if (optional) {
                index = stop;
                continue;
            }
            /* the group stays as written, so the operator sees what is unresolved */
            *review = 1;
            holy_note_add(note, "unknown", "macro %%{%s} is not carried in %s", key, where);
            holy_note_environment(note, "rpm-macros");
            if (!text_puts(&out, "%{") || !text_puts(&out, key) || !text_puts(&out, "}"))
                goto failed;
            index = stop;
            continue;
        }
        /* a bare %name form runs to the first non name character */
        if (index + 1 < length && name_char(body[index + 1])) {
            size_t stop = index + 1;
            char key[256];
            size_t key_length = 0;
            const char *value = NULL;
            while (stop < length && name_char(body[stop]) && key_length + 1 < sizeof key)
                key[key_length++] = body[stop++];
            key[key_length] = 0;
            if (!strcmp(key, "name")) value = name;
            else if (!strcmp(key, "version")) value = version;
            else if (!strcmp(key, "release")) value = release;
            else if (!strcmp(key, "nil")) value = "";
            else if (!strcmp(key, "dist")) value = "";
            else if (!strcmp(key, "undefine_patch") || !strcmp(key, "gettext_bin") ||
                     !strcmp(key, "make_install") || !strcmp(key, "make_build") ||
                     !strcmp(key, "make_install_sh") || !strcmp(key, "__rm") ||
                     !strcmp(key, "__mkdir_p") || !strcmp(key, "__chmod") ||
                     !strcmp(key, "__chown") || !strcmp(key, "__strip") ||
                     !strcmp(key, "__sed") || !strcmp(key, "__cp") ||
                     !strcmp(key, "__grep") || !strcmp(key, "__m4") ||
                     !strcmp(key, "__cat") || !strcmp(key, "__mkdir") ||
                     !strcmp(key, "__rm_f") || !strcmp(key, "__touch") ||
                     !strcmp(key, "__mv") || !strcmp(key, "__ln_s")) {
                *review = 1;
                holy_note_add(note, "unknown", "helper %s is not carried in %s", key, where);
            } else if (key_length == 1) {
                /* a bare %d or %f and friends are rpm builtin commands */
                *review = 1;
                holy_note_add(note, "unknown", "rpm builtin command %s is not carried in %s", key,
                              where);
            } else {
                size_t macro_index;
                for (macro_index = 0; macro_index < macro_count; ++macro_index)
                    if (!strcmp(macros[macro_index].name, key)) {
                        value = macros[macro_index].value;
                        break;
                    }
            }
            if (value) {
                if (!text_puts(&out, value)) goto failed;
                index = stop;
                continue;
            }
            /* an rpm macro command stays in the body, reported as not carried */
            if (!text_puts(&out, "%")) goto failed;
            if (!text_puts(&out, key)) goto failed;
            index = stop;
            continue;
        }
        if (!text_puts(&out, "%")) goto failed;
        ++index;
    }
    expanded = out.data;
    return expanded;
failed:
    free(out.data);
    return NULL;
}

/* the file list of a %files section, with the rpm attributes removed */
static char *file_paths(const char *body, size_t length, const char *name, const char *version,
                        const struct spec_macro *macros, size_t macro_count,
                        struct recipe_note *note, int *review)
{
    struct text out = {NULL, 0, 0};
    size_t offset = 0;
    if (!text_add(&out, "", 0)) return NULL;
    while (offset < length) {
        const char *start = body + offset;
        const char *newline = memchr(start, '\n', length - offset);
        size_t size = newline ? (size_t)(newline - start) : length - offset;
        char *entry;
        char *cursor;
        offset += size + (newline ? 1 : 0);
        entry = clean_line(start, size);
        if (!entry) goto failed;
        if (!*entry || *entry == '#') { free(entry); continue; }
        /* an attribute such as %doc, %license or %attr(0755,root,root) */
        while (*entry == '%') {
            char *stop = entry + 1;
            int depth = 0;
            while (*stop && (name_char(*stop) || *stop == '(' || *stop == ',' || *stop == ')' ||
                             *stop == ' ' || *stop == '-' || *stop == '+')) {
                if (*stop == '(') ++depth;
                if (*stop == ')' && !--depth) { ++stop; break; }
                ++stop;
            }
            {
                char *tail = clean_line(stop, strlen(stop));
                free(entry);
                entry = tail;
                if (!entry) goto failed;
            }
            if (!*entry) break;
        }
        cursor = entry;
        while (*cursor == ' ') ++cursor;
        if (!*cursor) { free(entry); continue; }
        /* a literal path is carried; anything with a macro left in it is reported */
        if (strchr(cursor, '%')) {
            *review = 1;
            holy_note_add(note, "unknown", "file path %s keeps a macro in %s", cursor, name);
        holy_note_environment(note, "rpm-macros");
            free(entry);
            continue;
        }
        {
            char *expanded = expand_macros(cursor, strlen(cursor), name, version, "", macros,
                                           macro_count, note, review, "a file list");
            if (expanded) {
                /* one path per line, since the step reads the list back line by line */
                if (*expanded && strcmp(expanded, "-") &&
                    (!text_puts(&out, expanded) || !text_puts(&out, "\n"))) {
                    free(expanded);
                    goto failed;
                }
                free(expanded);
            }
        }
        free(entry);
    }
    if (!out.used) return out.data;
    {
        char *joined = malloc(out.used + 1);
        if (!joined) goto failed;
        memcpy(joined, out.data, out.used + 1);
        free(out.data);
        return joined;
    }
failed:
    free(out.data);
    return NULL;
}

/* the comparison an rpm requirement states, split into its three parts */
static int split_requirement(const char *raw, char *name, size_t size, char *relation,
                             size_t relation_size, char *version, size_t version_size,
                             struct recipe_note *note, int *review, const char *where)
{
    const char *cursor = raw;
    const char *stop;
    size_t used = 0;
    while (*cursor == ' ' || *cursor == '\t') ++cursor;
    stop = strpbrk(cursor, " \t<>=!");
    if (!stop) stop = cursor + strlen(cursor);
    if (stop == cursor) {
        *review = 1;
        holy_note_add(note, "unknown", "requirement %s in %s", raw, where);
        return 0;
    }
    if ((size_t)(stop - cursor) >= size) {
        *review = 1;
        holy_note_add(note, "unknown", "requirement name is too long in %s", where);
        return 0;
    }
    memcpy(name, cursor, (size_t)(stop - cursor));
    name[stop - cursor] = 0;
    if (strchr(name, ':')) {
        *review = 1;
        holy_note_add(note, "unknown", "requirement %s uses a resolver-specific form in %s",
                      name, where);
        return 0;
    }
    while (*stop == ' ' || *stop == '\t') ++stop;
    used = 0;
    {
        char operator[8];
        size_t operator_length = 0;
        while (*stop && *stop != ' ' && *stop != '\t' && operator_length + 1 < sizeof operator) {
            if (strchr("<>=~", *stop)) operator[operator_length++] = *stop;
            ++stop;
        }
        operator[operator_length] = 0;
        if (!operator_length) snprintf(relation, relation_size, "any");
        else snprintf(relation, relation_size, "%s", holy_relation_name(operator));
    }
    (void)used;
    while (*stop == ' ' || *stop == '\t') ++stop;
    snprintf(version, version_size, "%s", stop);
    if (!relation[0]) snprintf(relation, relation_size, "any");
    return 1;
}

/* the rpm section commands that stand for a plain shell line, with what they run.
   a command that is not here is reported and left in the body, so the build fails
   visibly rather than silently dropping a step. */
static const struct { const char *command; const char *runs; } carried[] = {
    { "make_install", "make install" },
    { "make_install_sh", "sh install-sh" },
    { "make_build", "make" },
    { "__mkdir_p", "mkdir -p" },
    { "__rm_f", "rm -f" },
    { "__rm", "rm -rf" },
    { "__chmod", "chmod" },
    { "__strip", "strip" },
    { "__cp", "cp" },
    { "__cat", "cat" },
    { "__grep", "grep" },
    { "__sed", "sed" },
    { "__m4", "m4" },
    { "__touch", "touch" },
    { "__mv", "mv" },
    { "__ln_s", "ln -s" },
    { NULL, NULL }
};

/* writes one body, carrying the section commands that stand for a shell line */
static int emit_body(FILE *out, const char *body, size_t length, const char *name,
                     const char *version, const char *release,
                     const struct spec_macro *macros, size_t macro_count,
                     struct recipe_note *note, int *review, const char *where)
{
    size_t offset = 0;
    while (offset < length) {
        const char *start = body + offset;
        const char *newline = memchr(start, '\n', length - offset);
        size_t size = newline ? (size_t)(newline - start) : length - offset;
        char line[4096];
        const char *cursor = start;
        size_t command = 0;
        if (size >= sizeof line) size = sizeof line - 1;
        memcpy(line, start, size);
        line[size] = 0;
        offset += size + (newline ? 1 : 0);
        while (*cursor == ' ' || *cursor == '\t') ++cursor;
        if (*cursor == '%') {
            char key[128];
            size_t key_length = 0;
            const char *arguments;
            cursor += 1;
            while (key_length + 1 < sizeof key &&
                   (isalnum((unsigned char)cursor[key_length]) ||
                    cursor[key_length] == '_')) {
                key[key_length] = cursor[key_length];
                ++key_length;
            }
            key[key_length] = 0;
            arguments = cursor + key_length;
            if (!strcmp(key, "setup") || !strcmp(key, "autosetup") ||
                !strcmp(key, "autopatch")) {
                char *expanded_arguments = expand_macros(arguments, strlen(arguments), name,
                                                        version, release, macros, macro_count,
                                                        note, review, "a section command");
                if (expanded_arguments) {
                    arguments = expanded_arguments;
                }
                /* the directory the sources were unpacked into, and the patch level */
                char directory[1024];
                const char *at = strstr(arguments, " -n ");
                int level = 1;
                if (at) {
                    char *stop = (char *)at + 4;
                    while (*stop && !isspace((unsigned char)*stop)) ++stop;
                    *stop = 0;
                    snprintf(directory, sizeof directory, "%s", at + 4);
                    *stop = ' ';
                } else {
                    snprintf(directory, sizeof directory, "%s-%s", name, version);
                }
                at = strstr(arguments, " -p");
                if (at && isdigit((unsigned char)at[3])) level = at[3] - '0';
                if (fprintf(out, "cd \"$HOLY_SRC/%s\"\n", directory) < 0) return 0;
                /* every patch the recipe declared is applied, the way %autopatch does,
                   and --forward keeps a rejected hunk from asking for an answer */
                fputs("for patch in \"$HOLY_SRC\"/*.patch \"$HOLY_SRC\"/*.diff \\\n"
                      "           \"$HOLY_SRC\"/patches/*.patch; do\n"
                      "  [ -f \"$patch\" ] || continue\n", out);
                fprintf(out, "  patch --batch --forward -p%d -i \"$patch\"\n", level);
                fputs("done\n", out);
                holy_note_add(note, "preserved", "%%%s becomes a cd and the patch pass", key);
                if (expanded_arguments) free((char *)arguments);
                continue;
            }
            for (command = 0; carried[command].command; ++command)
                if (!strcmp(key, carried[command].command)) break;
            if (carried[command].command) {
                if (fprintf(out, "%s%s\n", carried[command].runs, arguments) < 0) return 0;
                continue;
            }
        }
        {
            char *expanded = expand_macros(line, size, name, version, release, macros,
                                           macro_count, note, review, where);
            if (!expanded) return 0;
            if (fprintf(out, "%s\n", expanded) < 0) { free(expanded); return 0; }
            free(expanded);
        }
    }
    return 1;
}

int holy_convert_rpmspec(const char *input, const char *source, const char *output)
{
    struct spec_field fields[MAX_FIELDS];
    struct spec_macro macros[MAX_MACROS];
    struct spec_section sections[64];
    struct spec_package packages[MAX_PACKAGES];
    struct spec_source sources[MAX_SOURCES];
    struct recipe_note note;
    struct stat st;
    char *text = NULL;
    char recipe_path[4096], report_path[4096], target[4096];
    char name[512] = {0}, version[512] = {0}, release[128] = {0}, arch[64] = "any";
    char *summary = NULL, *homepage = NULL, *license = NULL;
    char script_hash[65] = {0};
    size_t field_count = 0, macro_count = 0, section_count = 0, package_count = 0;
    size_t source_count = 0;
    size_t length = 0;
    size_t offset = 0, line = 0, index;
    int current_package = -1;
    FILE *out = NULL;
    int result = 1, review = 0, i;

    memset(&st, 0, sizeof st);
    memset(fields, 0, sizeof fields);
    memset(macros, 0, sizeof macros);
    memset(sections, 0, sizeof sections);
    memset(packages, 0, sizeof packages);
    memset(sources, 0, sizeof sources);
    memset(&note, 0, sizeof note);

    if (!input || !output || !*output) {
        fputs("usage: holypkg convert NAME.spec --source NAME --output NEW_DIRECTORY\n", stderr);
        return 2;
    }
    if (!source || !*source || !strcmp(source, "local")) {
        fputs("holypkg: a converted recipe needs the source name it came from\n", stderr);
        return 2;
    }
    for (i = 0; source[i]; ++i)
        if ((unsigned char)source[i] <= 32 || source[i] == ':' || source[i] == '/' ||
            source[i] == '@') {
            fputs("holypkg: invalid source name for conversion\n", stderr);
            return 2;
        }
    {
        const char *label = base_name(input);
        FILE *in = stat(input, &st) || !S_ISREG(st.st_mode) || st.st_size > 4 * 1024 * 1024
                      ? NULL : fopen(input, "rb");
        if (!in) {
            fprintf(stderr, "holypkg: %s unavailable: %s\n", label, input);
            return 6;
        }
        size_t size;
        length = (size_t)st.st_size;
        size = length;
        text = malloc(size + 1);
        if (!text || fread(text, 1, size, in) != size) {
            free(text);
            fclose(in);
            fprintf(stderr, "holypkg: %s could not be read\n", label);
            return 6;
        }
        fclose(in);
        text[st.st_size] = 0;
    }
    {
        char *directory = strdup(input);
        if (!directory) { result = 1; goto done; }
        free(directory);
    }
    if (mkdir(output, 0700) && errno != EEXIST) {
        fprintf(stderr, "holypkg: conversion directory unavailable: %s\n", output);
        result = 1;
        goto done;
    }

    /* one pass over the spec: preamble fields, macros, sections and packages */
    while (offset < length) {
        char *row = text + offset;
        char *newline = memchr(row, '\n', length - offset);
        size_t size = newline ? (size_t)(newline - row) : length - offset;
        char *value = clean_line(row, size);
        char *colon;
        ++line;
        offset += size + (newline ? 1 : 0);
        if (!value) { result = 1; goto done; }
        if (!*value || *value == '#') { free(value); continue; }
        if (*value != '%' && (colon = strchr(value, ':')) != NULL && colon != value) {
            char *key = clean_line(value, (size_t)(colon - value));
            char *field = clean_line(colon + 1, strlen(colon + 1));
            if (key && field) {
                /* every preamble field is recorded, so the lists stay in file order */
                if (field_count < MAX_FIELDS) {
                    size_t used = strlen(field);
                    if (used >= sizeof fields[0].value) used = sizeof fields[0].value - 1;
                    snprintf(fields[field_count].key, sizeof fields[0].key, "%s", key);
                    memcpy(fields[field_count].value, field, used);
                    fields[field_count].value[used] = 0;
                    fields[field_count].line = line;
                    fields[field_count].package = current_package;
                    ++field_count;
                }
                if (!strcmp(key, "Name") && !*name) {
                    snprintf(name, sizeof name, "%s", field);
                    holy_note_add(&note, "carried", "Name %zu", line);
                } else if (!strcmp(key, "Version") && !*version) {
                    literal_part(field, version, sizeof version, &note, &review, "Version", line);
                    holy_note_add(&note, "carried", "Version %zu", line);
                } else if (!strcmp(key, "Release") && !*release) {
                    char raw[256];
                    snprintf(raw, sizeof raw, "%s", field);
                    literal_part(raw, release, sizeof release, &note, &review, "Release", line);
                    holy_note_add(&note, "carried", "Release %zu", line);
                    if (strlen(field) != strlen(release))
                        holy_note_add(&note, "semantic-change", "the distribution suffix on "
                                      "Release is left out, so the Holy release is %s", release);
                } else if (!strcmp(key, "Summary") && !summary) {
                    summary = strdup(field);
                    holy_note_add(&note, "carried", "Summary %zu", line);
                } else if (!strcmp(key, "URL") && !homepage) {
                    homepage = strdup(field);
                    holy_note_add(&note, "carried", "URL %zu", line);
                } else if (!strcmp(key, "License") && !license) {
                    license = strdup(field);
                    holy_note_add(&note, "carried", "License %zu", line);
                } else if (!strcmp(key, "BuildArch")) {
                    snprintf(arch, sizeof arch, "%s",
                             !strcmp(field, "noarch") ? "noarch" : "any");
                    if (strcmp(field, "noarch"))
                        holy_note_add(&note, "semantic-change", "BuildArch %s becomes any, the "
                                      "payload decides the machine", field);
                } else if (!strcmp(key, "ExclusiveArch")) {
                    review = 1;
                    holy_note_add(&note, "preserved", "ExclusiveArch %s", field);
                }
            }
            free(key);
            free(field);
            free(value);
            continue;
        }
        if (*value != '%') { free(value); continue; }
        {
            /* %global and %define record a macro; every other %word starts a section */
            static const struct { const char *word; int is_macro; } words[] = {
                { "global", 1 }, { "define", 1 }, { "bcond_with", 0 }, { "bcond_without", 0 },
                { "package", 0 }, { "description", 0 }, { "prep", 0 }, { "build", 0 },
                { "check", 0 }, { "install", 0 }, { "files", 0 }, { "changelog", 0 },
                { "clean", 0 }, { "post", 0 }, { "preun", 0 }, { "postun", 0 },
                { "pretrans", 0 }, { "posttrans", 0 }, { "triggerin", 0 }, { "triggerun", 0 },
                { "triggerpostun", 0 }, { "sepolicy", 0 }, { "verifyscript", 0 },
                { "pre", 0 }, { "postun_trans", 0 }
            };
            size_t used;
            for (used = 0; used < sizeof words / sizeof *words; ++used) {
                size_t at = strlen(words[used].word);
                if (strncmp(value + 1, words[used].word, at)) continue;
                if (value[1 + at] && value[1 + at] != ' ' && value[1 + at] != '\t') continue;
                break;
            }
            if (used >= sizeof words / sizeof *words) {
                /* only a section keyword starts a section; every other %word is body
                   text, and an rpm conditional is recorded with its line */
                if (!strncmp(value, "%if", 3) || !strncmp(value, "%else", 5) ||
                    !strncmp(value, "%endif", 6) || !strncmp(value, "%elif", 5)) {
                    review = 1;
                    holy_note_add(&note, "unknown", "conditional %s at line %zu", value, line);
                }
                free(value);
                continue;
            }
            if (words[used].is_macro) {
                char *rest = clean_line(value + 1 + strlen(words[used].word),
                                        strlen(value + 1 + strlen(words[used].word)));
                if (rest && *rest && macro_count < MAX_MACROS) {
                    size_t name_length = 0;
                    while (rest[name_length] && name_char(rest[name_length])) ++name_length;
                    snprintf(macros[macro_count].name, sizeof macros[0].name, "%.*s",
                             (int)(name_length < sizeof macros[0].name - 1
                                       ? name_length : sizeof macros[0].name - 1),
                             rest);
                    {
                        /* the value is the rest of the line, without its blanks */
                        char *value = clean_line(rest + name_length,
                                                 strlen(rest + name_length));
                        snprintf(macros[macro_count].value, sizeof macros[0].value, "%s",
                                 value ? value : "");
                        free(value);
                    }
                    macros[macro_count].line = line;
                    ++macro_count;
                }
                free(rest);
                free(value);
                continue;
            }
            {
                char *rest = clean_line(value + 1 + strlen(words[used].word),
                                        strlen(value + 1 + strlen(words[used].word)));
                struct spec_section *section;
                if (!strcmp(words[used].word, "package")) {
                    if (!rest || !*rest) {
                        review = 1;
                        holy_note_add(&note, "unknown", "a %%package without a name %zu", line);
                        free(rest);
                        free(value);
                        continue;
                    }
                    if (package_count < MAX_PACKAGES) {
                        snprintf(packages[package_count].name, sizeof packages[0].name, "%s",
                                 rest);
                        packages[package_count].line = line;
                        current_package = (int)package_count;
                        packages[package_count].has_body = 1;
                        ++package_count;
                        holy_note_add(&note, "carried", "package %s %zu", rest, line);
                    } else {
                        review = 1;
                        holy_note_add(&note, "unknown", "more subpackages than outputs are "
                                      "carried %s", rest);
                    }
                    free(rest);
                    free(value);
                    continue;
                }
                if (!strcmp(words[used].word, "description") && current_package >= 0) {
                    if (section_count < sizeof sections / sizeof *sections) {
                        section = &sections[section_count++];
                        snprintf(section->name, sizeof section->name, "description");
                        section->marker = (size_t)(row - text);
                        section->first = section->marker + size + (newline ? 1 : 0);
                        section->last = section->first;
                        section->line = line;
                    }
                    free(rest);
                    free(value);
                    continue;
                }
                if (!strcmp(words[used].word, "files") && rest && *rest && strcmp(rest, "-")) {
                    char *argument = rest;
                    char *mark;
                    if (argument[0] == '-') {
                        /* -n NAME and -f FILE both name something other than a package */
                        review = 1;
                        holy_note_add(&note, "unknown", "the %%files option %s is not carried",
                                      argument);
                    } else if (current_package >= 0) {
                        mark = argument;
                        while (*mark && *mark != ' ' && *mark != '\t') ++mark;
                        *mark = 0;
                        if (!strcmp(argument, packages[current_package].name)) {
                            packages[current_package].has_files = 1;
                            if (section_count < sizeof sections / sizeof *sections) {
                                struct spec_section *files =
                                    &sections[section_count++];
                                snprintf(files->name, sizeof files->name, "files");
                                snprintf(files->argument, sizeof files->argument, "%s",
                                         argument);
                                files->marker = (size_t)(row - text);
                                files->first = files->marker + size + (newline ? 1 : 0);
                                files->last = files->first;
                                files->line = line;
                                packages[current_package].files_section = section_count - 1;
                            }
                        } else {
                            review = 1;
                            holy_note_add(&note, "unknown", "%%files %s has no %%package of that "
                                          "name", argument);
                        }
                    } else {
                        review = 1;
                        holy_note_add(&note, "unknown", "%%files %s at the top level", argument);
                    }
                    free(rest);
                    free(value);
                    continue;
                }
                if (section_count < sizeof sections / sizeof *sections) {
                    section = &sections[section_count++];
                    snprintf(section->name, sizeof section->name, "%s", words[used].word);
                    snprintf(section->argument, sizeof section->argument, "%s", rest ? rest : "");
                    section->marker = (size_t)(row - text);
                    section->first = section->marker + size + (newline ? 1 : 0);
                    section->last = section->first;
                    section->line = line;
                    if (!strcmp(section->name, "files") && current_package >= 0 &&
                        !packages[current_package].has_files) {
                        packages[current_package].has_files = 1;
                        packages[current_package].files_section = section_count - 1;
                    }
                } else {
                    review = 1;
                    holy_note_add(&note, "unknown", "more sections than are carried %s", value);
                }
                free(rest);
                free(value);
            }
        }
    }
    /* a section body runs to the next section marker */
    for (index = 0; index < section_count; ++index) {
        size_t stop = length;
        size_t other;
        for (other = 0; other < section_count; ++other) {
            size_t at;
            if (other == index) continue;
            at = sections[other].marker;
            if (at > sections[index].marker && at < stop) stop = at;
        }
        sections[index].last = stop;
    }
    if (!*name || !*version || !*release) {
        fputs("holypkg: spec: Name, Version and Release are required\n", stderr);
        result = 2;
        goto done;
    }
    if (strlen(name) > 480 || strlen(version) > 480) {
        fputs("holypkg: spec: the identity must be literal and short\n", stderr);
        result = 2;
        goto done;
    }

    {
        char *expanded_name = expand_macros(name, strlen(name), "", "", "", macros, macro_count,
                                            &note, &review, "the identity");
        if (expanded_name) {
            if (strchr(expanded_name, '%') || strpbrk(expanded_name, "$`/ \t")) {
                fputs("holypkg: spec: the identity must be literal\n", stderr);
                free(expanded_name);
                result = 2;
                goto done;
            }
            snprintf(name, sizeof name, "%s", expanded_name);
            free(expanded_name);
        }
        if (strpbrk(version, "$`/ \t")) {
            fputs("holypkg: spec: the version must be literal\n", stderr);
            result = 2;
            goto done;
        }
    }

    snprintf(target, sizeof target, "%s/%s", output, base_name(input));
    if (!holy_copy_and_hash(input, target, script_hash)) {
        fputs("holypkg: spec copy failed\n", stderr);
        result = 1;
        goto done;
    }
    snprintf(recipe_path, sizeof recipe_path, "%s/%s.recipe", output, name);
    snprintf(report_path, sizeof report_path, "%s/conversion", output);
    out = fopen(recipe_path, "wb");
    if (!out) {
        fprintf(stderr, "holypkg: recipe unavailable: %s\n", recipe_path);
        result = 1;
        goto done;
    }
    fputs("format holy-recipe-1\nname ", out); holy_token(out, name);
    fputs("\nversion ", out); holy_token(out, version);
    fputs("\nrelease ", out); holy_token(out, release);
    fputs("\narch ", out); holy_token(out, arch);
    fputs("\nlibc any\n", out);
    if (summary && *summary) { fputs("summary ", out); holy_token(out, summary); fputc('\n', out); }
    if (homepage && *homepage) { fputs("homepage ", out); holy_token(out, homepage); fputc('\n', out); }
    if (license && *license) { fputs("license ", out); holy_token(out, license); fputc('\n', out); }
    fputs("x-source-family rpm\nx-converter rpmspec-1\n", out);
    fputs("output ", out); holy_token(out, name);
    fputs(" runtime\n", out);
    /* the Source and Patch records name the files the build needs */
    for (index = 0; index < field_count; ++index) {
        char *expanded;
        char *items;
        size_t count = 0, item;
        char **words;
        int patch = !strncmp(fields[index].key, "Patch", 5);
        if (!patch && strncmp(fields[index].key, "Source", 6)) continue;
        if (source_count >= MAX_SOURCES) {
            review = 1;
            holy_note_add(&note, "unknown", "more sources than are carried %s", fields[index].key);
            continue;
        }
        expanded = expand_macros(fields[index].value, strlen(fields[index].value), name,
                                 version, release, macros, macro_count, &note, &review,
                                 "a source record");
        if (!expanded) { result = 1; goto done; }
        /* a patch record holds one file name, a source record a list of them */
        items = patch ? NULL : strdup(expanded);
        if (!patch && !items) { free(expanded); result = 1; goto done; }
        words = holy_shell_words(items ? items : expanded, &count);
        for (item = 0; words && item < count; ++item) {
            const char *mark = strrchr(words[item], '/');
            const char *base = mark ? mark + 1 : words[item];
            if (!*base || strlen(base) > sizeof sources[0].name - 1) continue;
            if (!strcmp(base, "-") || !strcmp(base, "/dev/null")) continue;
            snprintf(sources[source_count].name, sizeof sources[0].name, "%s", base);
            snprintf(sources[source_count].url, sizeof sources[source_count].url, "%s",
                     words[item]);
            sources[source_count].line = fields[index].line;
            sources[source_count].patch = patch;
            ++source_count;
        }
        holy_shell_words_free(words);
        free(items);
        free(expanded);
    }
    {
        char *directory = strdup(input);
        char *slash = directory ? strrchr(directory, '/') : NULL;
        char *original;
        size_t at;
        if (!directory) { result = 1; goto done; }
        if (slash) *slash = 0;
        else strcpy(directory, ".");
        for (at = 0; at < source_count; ++at) {
            struct stat local;
            original = join_path(directory, sources[at].name);
            if (original && !stat(original, &local) && S_ISREG(local.st_mode)) {
                char *copied = join_path(output, sources[at].name);
                char digest[65];
                if (!copied || !holy_copy_and_hash(original, copied, digest)) {
                    free(copied);
                    free(original);
                    free(directory);
                    result = 1;
                    goto done;
                }
                fputs(sources[at].patch ? "source " : "source ", out);
                holy_token(out, sources[at].name);
                fputc(' ', out);
                holy_token(out, sources[at].name);
                fputc('\n', out);
                fputs("source-sha256 ", out);
                holy_token(out, sources[at].name);
                fputc(' ', out);
                holy_token(out, digest);
                fputc('\n', out);
                holy_note_add(&note, "carried", "%s %zu", sources[at].name,
                              sources[at].line);
                holy_note_add(&note, "semantic-change", "local %s copied next to the recipe and "
                              "hashed as sha256", sources[at].name);
                free(copied);
            } else {
                review = 1;
                holy_note_add(&note, "unknown", "%s %s is not beside the spec, so it has no "
                              "sha256 digest", sources[at].patch ? "patch" : "source",
                              sources[at].name);
            }
            free(original);
        }
        free(directory);
    }

    {
        /* the engine extracts each source under its own name, so one lift turns that
           into the single _sourcedir tree an rpm phase expects */
        fputs("step unpack /bin/sh <<UNPACK\n"
              "for entry in \"$HOLY_SRC\"/*; do\n"
              "  [ -d \"$entry\" ] || continue\n"
              "  for child in \"$entry\"/* \"$entry\"/.[!.]* \"$entry\"/..?*; do\n"
              "    [ -e \"$child\" ] || continue\n"
              "    mv \"$child\" \"$HOLY_SRC/\"\n"
              "  done\n"
              "  rmdir \"$entry\" 2>/dev/null || true\n"
              "done\n"
              "UNPACK\n", out);
        holy_note_add(&note, "semantic-change", "the engine fetches and unpacks the recorded "
                      "sources, so the extracted tree takes the place of _sourcedir");
    }

    /* each phase section becomes one Holy step */
    for (index = 0; index < section_count; ++index) {
        const char *phase = phase_of(sections[index].name);
        char *body;
        if (!phase) continue;
        body = clean_line(text + sections[index].first,
                          sections[index].last - sections[index].first);
        if (!body) { result = 1; goto done; }
        if (!*body) {
            free(body);
            holy_note_add(&note, "helper", "the %s section is empty, so the rpm build "
                          "environment supplies it", sections[index].name);
            holy_note_environment(&note, "rpmbuild");
            review = 1;
            continue;
        }
        fprintf(out, "step %s /bin/sh <<STEP\n", phase);
        fputs("# the rpm macros this body reads, rebuilt from the exported Holy paths\n", out);
        {
            size_t macro_index;
            fprintf(out, "_sourcedir=\"$HOLY_SRC\"\n_srcrpmdir=\"$HOLY_SRC\"\n");
            fprintf(out, "_builddir=\"$HOLY_BUILD\"\n_topdir=\"$HOLY_WORK\"\n");
            fprintf(out, "buildroot=\"$HOLY_DEST\"\n");
            fprintf(out, "name=%s\nversion=%s\nrelease=%s\n", name, version, release);
            /* rpm runs every section in %{_builddir}/%{name}-%{version}, so a step
               changes there first, when the tree was unpacked under that name */
            fprintf(out, "if [ -d \"$HOLY_SRC/%s-%s\" ]; then cd \"$HOLY_SRC/%s-%s\"; fi\n",
                    name, version, name, version);
            for (macro_index = 0; macro_index < macro_count; ++macro_index) {
                size_t builtin;
                const char *value = macros[macro_index].value;
                for (builtin = 0; builtin < sizeof builtins / sizeof *builtins; ++builtin)
                    if (!strcmp(builtins[builtin].macro, macros[macro_index].name)) {
                        value = builtins[builtin].value;
                        break;
                    }
                /* a value that is not a plain word is a pattern or a command, so it
                   stays inside the body where the shell can read it */
                if (is_shell_word(value))
                    fprintf(out, "%s=%s\n", macros[macro_index].name, value);
            }
        }
        if (!emit_body(out, body, strlen(body), name, version, release, macros, macro_count,
                       &note, &review, sections[index].name)) {
            free(body);
            result = 1;
            goto done;
        }
        free(body);
        fputs("STEP\n", out);
        holy_note_add(&note, "preserved", "the %s section at line %zu", sections[index].name,
                      sections[index].line);
    }
    /* an rpm conditional picks a body this converter cannot choose between */
    for (index = 0; index < section_count; ++index) {
        const char *phase = phase_of(sections[index].name);
        size_t at;
        if (!phase) continue;
        for (at = sections[index].first; at < sections[index].last; ++at)
            if (text[at] == '%' && at + 2 < sections[index].last && text[at + 1] == 'i' &&
                text[at + 2] == 'f') {
                review = 1;
                holy_note_add(&note, "unknown", "the %s section keeps a conditional, which "
                              "this converter does not choose between", sections[index].name);
                break;
            }
    }

    /* a subpackage is a file list rather than a body, so its step copies the paths */
    for (index = 0; index < package_count; ++index) {
        struct spec_package *package = &packages[index];
        char *expanded_name;
        char *paths;
        if (!*package->name) continue;
        expanded_name = expand_macros(package->name, strlen(package->name), name, version,
                                     release, macros, macro_count, &note, &review,
                                     "a package name");
        if (!expanded_name) { result = 1; goto done; }
        if (!*expanded_name || strchr(expanded_name, '%') || strpbrk(expanded_name, "$`/ \t")) {
            review = 1;
            holy_note_add(&note, "unknown", "subpackage %s has no usable name", package->name);
            free(expanded_name);
            continue;
        }
        fputs("output ", out);
        holy_token(out, expanded_name);
        fputs(" runtime\n", out);
        if (!package->has_files) {
            review = 1;
            holy_note_add(&note, "unknown", "subpackage %s has no %%files list, so it gets no "
                          "payload of its own", expanded_name);
            free(expanded_name);
            continue;
        }
        {
            size_t files_first = sections[package->files_section].first;
            size_t files_last = sections[package->files_section].last;
            char *body = clean_line(text + files_first, files_last - files_first);
            if (!body) { free(expanded_name); result = 1; goto done; }
            paths = file_paths(body, strlen(body), expanded_name, version, macros, macro_count,
                               &note, &review);
            free(body);
        }
        if (!paths) { free(expanded_name); result = 1; goto done; }
        if (!*paths) {
            review = 1;
            holy_note_add(&note, "unknown", "subpackage %s has no path this converter can "
                          "carry", expanded_name);
            free(paths);
            free(expanded_name);
            continue;
        }
        fprintf(out, "split-step %s split /bin/sh <<SPLIT\n", expanded_name);
        fputs("# the subpackage list names the paths the rpm %files section installed\n", out);
        fputs("set -f\n", out);
        fputs("for entry in", out);
        {
            char *cursor = paths;
            while (*cursor) {
                char *stop = strchr(cursor, '\n');
                size_t length = stop ? (size_t)(stop - cursor) : strlen(cursor);
                char line[1024];
                if (length >= sizeof line) length = sizeof line - 1;
                memcpy(line, cursor, length);
                line[length] = 0;
                if (*line) {
                    fputc(' ', out);
                    holy_token(out, line);
                }
                cursor += length + (stop ? 1 : 0);
            }
        }
        fputs("; do\n", out);
        fputs("  [ -e \"$HOLY_DEST/$entry\" ] || continue\n", out);
        fputs("  mkdir -p \"$HOLY_SPLIT_DEST/$(dirname \"$entry\")\"\n", out);
        fputs("  cp -a \"$HOLY_DEST/$entry\" \"$HOLY_SPLIT_DEST/$entry\"\n", out);
        fputs("done\n", out);
        fputs("SPLIT\n", out);
        holy_note_add(&note, "preserved", "subpackage %s from its %%files list at line %zu",
                      expanded_name, package->line);
        holy_note_add(&note, "semantic-change", "the %%files list of %s becomes a copy out of "
                      "the main tree, so an rpm glob cannot grow a file the install did not "
                      "place", expanded_name);
        free(paths);
        free(expanded_name);
    }
    /* the main %files list only checks what the install already placed */
    for (index = 0; index < section_count; ++index)
        if (!strcmp(sections[index].name, "files") && !*sections[index].argument) {
            holy_note_add(&note, "preserved", "the main %%files list is not carried, it only "
                          "checks what the install placed");
            review = 1;
        }

    /* the requirement lists become dependency records */
    for (index = 0; index < field_count; ++index) {
        static const struct { const char *key; const char *kind; const char *where; } lists[] = {
            { "BuildRequires", "build-depend", "BuildRequires" },
            { "Requires", "depend", "Requires" },
            { "Recommends", NULL, NULL },
            { "Suggests", NULL, NULL },
            { "Enhances", NULL, NULL },
            { "Conflicts", NULL, NULL },
            { "Obsoletes", NULL, NULL },
            { "Provides", NULL, NULL },
            { NULL, NULL, NULL }
        };
        size_t list_index;
        char *expanded;
        size_t count = 0, item;
        char **items;
        if (fields[index].package >= 0) continue;
        for (list_index = 0; lists[list_index].key; ++list_index)
            if (!strcmp(fields[index].key, lists[list_index].key)) break;
        if (!lists[list_index].key) continue;
        if (!lists[list_index].key) continue;
        expanded = expand_macros(fields[index].value, strlen(fields[index].value), name,
                                 version, release, macros, macro_count, &note, &review,
                                 lists[list_index].where);
        if (!expanded) { result = 1; goto done; }
        /* an rpm requirement list holds one requirement per line, and a wrapped one
           ends with a backslash, so the line is the record rather than the word */
        items = holy_shell_lines(expanded, &count);
        for (item = 0; items && item < count; ++item) {
            char *raw = items[item];
            if (!lists[list_index].kind) {
                /* a recommendation is not a requirement, and a capability or a
                   conflict is not either, so none of them becomes a depend record */
                int provides = !strcmp(fields[index].key, "Provides");
                char requirement[512], relation[16], wanted[512];
                if (!provides && (!strcmp(fields[index].key, "Conflicts") ||
                                  !strcmp(fields[index].key, "Obsoletes"))) {
                    fputs("x-conflicts ", out);
                    holy_token(out, raw);
                    fputc('\n', out);
                    continue;
                }
                if (split_requirement(raw, requirement, sizeof requirement, relation,
                                      sizeof relation, wanted, sizeof wanted, &note, &review,
                                      lists[list_index].where)) {
                    fputs(provides ? "x-provides " : "x-suggests ", out);
                    holy_token(out, requirement);
                    fputc('\n', out);
                    if (strcmp(relation, "any"))
                        holy_note_add(&note, "preserved", "%s %s %s", fields[index].key,
                                      relation, wanted);
                }
                continue;
            }
            /* a rich dependency and an rpmlib capability are one token, so they are
               reported whole rather than split into a name that does not exist */
            if (strchr(raw, '(')) {
                review = 1;
                holy_note_add(&note, "unknown", "requirement %s uses a resolver-specific form "
                              "in %s", raw, lists[list_index].where);
                continue;
            }
            if (!strcmp(lists[list_index].kind, "depend") && raw[0] == '/') {
                review = 1;
                holy_note_add(&note, "unknown", "requirement %s names a file, which a Holy "
                              "depend record cannot", raw);
                continue;
            }
            {
                char requirement[512], relation[16], wanted[512];
                if (!split_requirement(raw, requirement, sizeof requirement, relation,
                                       sizeof relation, wanted, sizeof wanted, &note, &review,
                                       lists[list_index].where))
                    continue;
                if (!strcmp(relation, "any")) snprintf(wanted, sizeof wanted, "-");
                {
                    char *expanded_version = strcmp(wanted, "-")
                        ? expand_macros(wanted, strlen(wanted), name, version, release, macros,
                                        macro_count, &note, &review, lists[list_index].where)
                        : strdup("-");
                    if (expanded_version && !strchr(expanded_version, '%')) {
                        fputs(lists[list_index].kind, out);
                        fputc(' ', out);
                        holy_token(out, requirement);
                        fputc(' ', out);
                        holy_token(out, relation);
                        fputc(' ', out);
                        holy_token(out, expanded_version);
                        fputc('\n', out);
                    }
                    free(expanded_version);
                }
            }
        }
        holy_shell_lines_free(items);
        free(expanded);
    }
    holy_note_environment_records(out, &note);
    if (fflush(out) || fclose(out)) { out = NULL; result = 1; goto done; }
    out = NULL;
    out = fopen(report_path, "wb");
    if (!out) {
        fprintf(stderr, "holypkg: report unavailable: %s\n", report_path);
        result = 1;
        goto done;
    }
    fputs("format holy-recipe-conversion-1\nconverter rpmspec-1\n", out);
    fputs("source-name ", out); holy_token(out, source); fputc('\n', out);
    fputs("source-file ", out); holy_token(out, base_name(input)); fputc('\n', out);
    fprintf(out, "source-sha256 %s\n", script_hash);
    fputs("pkgbase ", out); holy_token(out, name); fputc('\n', out);
    fputs("version ", out); holy_token(out, version); fputc('\n', out);
    fputs("release ", out); holy_token(out, release); fputc('\n', out);
    fputs("arch ", out); holy_token(out, arch); fputc('\n', out);
    fputs("recipe ", out); holy_token(out, name); fputs(".recipe\n", out);
    fprintf(out, "status %s\n", review ? "review-required" : "native");
    holy_note_environments(out, &note);
    for (index = 0; index < note.count; ++index) fprintf(out, "%s\n", note.lines[index]);
    fprintf(out, "summary carried %zu preserved %zu helper %zu unknown %zu changes %zu\n",
            note.carried, note.preserved, note.helper, note.unknown, note.changes);
    if (fflush(out) || fclose(out)) { out = NULL; result = 1; goto done; }
    out = NULL;
    printf("converted %s status %s\n", name, review ? "review-required" : "native");
    printf("recipe %s\nreport %s\n", recipe_path, report_path);
    if (review) {
        fputs("holypkg: the converted recipe needs review before its first build\n", stderr);
        result = 3;
    } else {
        result = 0;
    }
done:
    if (out) fclose(out);
    free(text);
    free(summary);
    free(homepage);
    free(license);
    holy_note_free(&note);
    return result;
}
