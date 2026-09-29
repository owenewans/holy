/* Debian source package to holy-recipe(5) conversion; see man/holy-recipe.5 and
   man/holypkg.8. the debian directory is read as text and never run. a source
   package is a control file, a changelog, a rules file and a set of file lists,
   so it needs a parser of its own. debhelper is a macro framework rather than a
   build script, so the rules body is carried and every dh call in it is reported
   as a helper the converter cannot run. */
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1
#include "debsrc.h"
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

#define MAX_BINARIES 32
#define MAX_FIELDS 96

struct deb_field {
    char name[64];
    char value[2048];
    size_t line;
    int binary;
};

struct deb_binary {
    char name[256];
    char summary[1024];
    char architecture[64];
    size_t line;
    int has_list;
    char list[2048];
    size_t list_line;
    int main;
};

/* a growing text buffer */
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

static char *join_path(const char *directory, const char *name)
{
    char path[4096];
    if (!name || !*name || strlen(name) > 400 || strchr(name, '/') || !strcmp(name, ".") ||
        !strcmp(name, ".."))
        return NULL;
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

/* reads a whole file into memory, or NULL when it is not there */
static char *read_file(const char *path, size_t *length)
{
    struct stat st;
    FILE *in = stat(path, &st) || !S_ISREG(st.st_mode) || st.st_size > 4 * 1024 * 1024
                  ? NULL : fopen(path, "rb");
    char *data;
    size_t size;
    if (!in) return NULL;
    size = (size_t)st.st_size;
    data = malloc(size + 1);
    if (!data || fread(data, 1, size, in) != size) {
        free(data);
        fclose(in);
        return NULL;
    }
    fclose(in);
    data[size] = 0;
    if (length) *length = size;
    return data;
}

/* the debian substitution variables dpkg fills in, which carry no meaning here */
static int is_substitution(const char *value)
{
    return value[0] == '$' && value[1] == '{';
}

/* one debian requirement, split into its name, relation and version. a Debian
   version is epoch:upstream-revision, so the epoch is reported and dropped. */
static int split_requirement(const char *raw, char *name, size_t size, char *relation,
                             size_t relation_size, char *version, size_t version_size,
                             int *epoch, size_t *at)
{
    const char *cursor = raw;
    const char *stop;
    while (*cursor == ' ' || *cursor == '\t') ++cursor;
    /* an alternative and an architecture qualifier are not one package name */
    if (strchr(cursor, '|') || strchr(cursor, '[')) {
        *at = 1;
        return 0;
    }
    stop = cursor;
    while (*stop && *stop != ' ' && *stop != '\t' && *stop != '(') ++stop;
    if (stop == cursor) return 0;
    if ((size_t)(stop - cursor) >= size) return 0;
    memcpy(name, cursor, (size_t)(stop - cursor));
    name[stop - cursor] = 0;
    while (*stop == ' ' || *stop == '\t') ++stop;
    if (*stop != '(') {
        snprintf(relation, relation_size, "any");
        snprintf(version, version_size, "-");
        return 1;
    }
    ++stop;
    /* the comparison takes the same name a Holy depend record reads */
    {
        char operator[8];
        size_t operator_length = 0;
        while (*stop && *stop != ' ' && operator_length + 1 < sizeof operator) {
            if (strchr("<>=", *stop)) operator[operator_length++] = *stop;
            ++stop;
        }
        operator[operator_length] = 0;
        if (!operator_length) snprintf(relation, relation_size, "any");
        else if (!strcmp(operator, "<<")) snprintf(relation, relation_size, "lt");
        else if (!strcmp(operator, ">>")) snprintf(relation, relation_size, "gt");
        else snprintf(relation, relation_size, "%s", holy_relation_name(operator));
    }
    while (*stop == ' ' || *stop == '\t') ++stop;
    snprintf(version, version_size, "%s", stop);
    if (!relation[0]) snprintf(relation, relation_size, "any");
    /* a closing paren and a build profile may follow the version */
    {
        char *close = strchr(version, ')');
        char *profile = strchr(version, '<');
        if (close) *close = 0;
        if (profile) *profile = 0;
        if (profile) *at = 2;
    }
    /* the epoch names a packaging revision order and is not part of the version */
    {
        char *colon = strchr(version, ':');
        if (colon) {
            *epoch = 1;
            memmove(version, colon + 1, strlen(colon + 1) + 1);
        }
    }
    /* the revision follows the last dash, and it is the Debian release */
    {
        char *dash = strrchr(version, '-');
        if (dash) *dash = 0;
    }
    if (!version[0]) snprintf(version, version_size, "-");
    return 1;
}

/* a debian relationship field is comma separated groups, and a group may offer
   alternatives with a pipe. a Holy depend record names one package, so the first
   alternative of each group is carried and the rest are reported. */
static char **relationship_groups(const char *value, size_t *count)
{
    char **list = NULL;
    size_t used = 0;
    const char *cursor = value;
    *count = 0;
    while (cursor && *cursor) {
        const char *comma = strchr(cursor, ',');
        size_t length = comma ? (size_t)(comma - cursor) : strlen(cursor);
        char *group = clean_line(cursor, length);
        char **grown;
        if (!group) break;
        cursor = comma ? comma + 1 : NULL;
        if (!*group) { free(group); continue; }
        grown = realloc(list, (used + 2) * sizeof *grown);
        if (!grown) { free(group); break; }
        list = grown;
        list[used++] = group;
        list[used] = NULL;
    }
    *count = used;
    return list;
}

static void list_free(char **list);

/* writes one depend record */
static void emit_dependency(FILE *out, const char *raw, const char *kind,
                            struct recipe_note *note, int *review, const char *where)
{
    char name[512], relation[16], version[512];
    int epoch = 0;
    size_t at = 0;
    if (is_substitution(raw)) {
        *review = 1;
        holy_note_add(note, "unknown", "the substitution %s in %s is filled in by dpkg", raw,
                      where);
        return;
    }
    if (!split_requirement(raw, name, sizeof name, relation, sizeof relation, version,
                          sizeof version, &epoch, &at))
        return;
    if (at == 1) {
        *review = 1;
        holy_note_add(note, "unknown", "requirement %s uses an alternative or a qualifier in "
                      "%s", raw, where);
        return;
    }
    if (at == 2)
        holy_note_add(note, "preserved", "the build profile of %s in %s", name, where);
    if (epoch)
        holy_note_add(note, "preserved", "the epoch of %s in %s", name, where);
    fputs(kind, out);
    fputc(' ', out);
    holy_token(out, name);
    fputc(' ', out);
    holy_token(out, relation);
    fputc(' ', out);
    holy_token(out, version);
    fputc('\n', out);
}

/* one record per line of a debian list, where a blank line continues the record
   before it, the way dpkg reads a wrapped field */
static char **list_lines(const char *text, size_t *count)
{
    char **list = NULL;
    size_t used = 0;
    const char *cursor = text;
    *count = 0;
    while (cursor && *cursor) {
        const char *newline = strchr(cursor, '\n');
        size_t length = newline ? (size_t)(newline - cursor) : strlen(cursor);
        char *entry = clean_line(cursor, length);
        cursor = newline ? newline + 1 : NULL;
        if (!entry) break;
        if (!*entry) {
            /* an empty line wraps the record before it, so the next line joins it */
            if (used && cursor && *cursor && *cursor != '\n') continue;
            free(entry);
            continue;
        }
        if (*entry == '#') { free(entry); continue; }
        if (used && entry[0] == ' ') {
            /* a wrapped continuation is indented, and joins the record before it */
            char *joined = malloc(strlen(list[used - 1]) + strlen(entry) + 1);
            if (joined) {
                sprintf(joined, "%s%s", list[used - 1], entry);
                free(list[used - 1]);
                list[used - 1] = joined;
            }
            free(entry);
            continue;
        }
        {
            char **grown = realloc(list, (used + 2) * sizeof *grown);
            if (!grown) { free(entry); break; }
            list = grown;
            list[used++] = entry;
            list[used] = NULL;
        }
    }
    *count = used;
    return list;
}

static void list_free(char **list)
{
    size_t index;
    if (!list) return;
    for (index = 0; list[index]; ++index) free(list[index]);
    free(list);
}

int holy_convert_debsrc(const char *input, const char *source, const char *output)
{
    struct deb_field fields[MAX_FIELDS];
    struct deb_binary binaries[MAX_BINARIES];
    struct recipe_note note;
    char *control = NULL, *changelog = NULL, *rules = NULL;
    char *directory = NULL;
    char name[512] = {0}, version[512] = {0}, release[64] = "1";
    char summary[1024] = {0}, homepage[1024] = {0}, arch[64] = "any";
    char recipe_path[4096], report_path[4096], control_hash[65] = {0};
    FILE *out = NULL;
    size_t field_count = 0, binary_count = 0, control_length = 0;
    size_t offset = 0, line = 0, index;
    size_t mains = 0;
    int current = -1, last_field = -1, review = 0, result = 1, i, wrote = 1;

    memset(fields, 0, sizeof fields);
    memset(binaries, 0, sizeof binaries);
    memset(&note, 0, sizeof note);

    if (!input || !output || !*output) {
        fputs("usage: holypkg convert debian --source NAME --output NEW_DIRECTORY\n", stderr);
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
    directory = strdup(input);
    if (!directory) return 1;
    {
        size_t used = strlen(directory);
        while (used && directory[used - 1] == '/') directory[--used] = 0;
    }
    {
        char *path = join_path(directory, "control");
        if (!path) { result = 1; goto done; }
        control = read_file(path, &control_length);
        if (!control) {
            fprintf(stderr, "holypkg: debian/control unavailable: %s\n", path);
            free(path);
            result = 6;
            goto done;
        }
        free(path);
    }
    if (mkdir(output, 0700) && errno != EEXIST) {
        fprintf(stderr, "holypkg: conversion directory unavailable: %s\n", output);
        result = 1;
        goto done;
    }
    /* the control file travels with the recipe, and its digest is the provenance */
    {
        char *path = join_path(directory, "control");
        char *copy = join_path(output, "control");
        if (path && copy) {
            if (!holy_copy_and_hash(path, copy, control_hash)) wrote = 0;
            else holy_note_add(&note, "carried", "debian/control");
        }
        free(path);
        free(copy);
    }

    /* one pass over the control file: a source stanza then one per binary */
    while (offset < control_length) {
        const char *row = control + offset;
        const char *newline = memchr(row, '\n', control_length - offset);
        size_t size = newline ? (size_t)(newline - row) : control_length - offset;
        /* a leading blank marks a continuation, so it is read before the line is
           trimmed, since the trimmed text no longer says so */
        int continuation = size && (row[0] == ' ' || row[0] == '\t');
        char *value = clean_line(row, size);
        ++line;
        offset += size + (newline ? 1 : 0);
        if (!value) { result = 1; goto done; }
        if (!*value) {
            /* a blank line ends a stanza, so the fields before it belong to one package */
            current = -1;
            last_field = -1;
            free(value);
            continue;
        }
        if (continuation) {
            /* a continuation line belongs to the field it follows, so the field before
               it is tracked rather than searched for, since a stanza repeats names */
            if (last_field >= 0 && (size_t)last_field < field_count) {
                size_t used = strlen(fields[last_field].value);
                if (used + size + 2 < sizeof fields[0].value) {
                    fields[last_field].value[used++] = ' ';
                    memcpy(fields[last_field].value + used, value, size + 1);
                } else {
                    review = 1;
                    holy_note_add(&note, "unknown", "%s runs past what a record holds",
                                  fields[last_field].name);
                }
            }
            free(value);
            continue;
        }
        {
            char *colon = strchr(value, ':');
            char *key;
            char *field;
            if (!colon || colon == value) { free(value); continue; }
            *colon = 0;
            key = clean_line(value, strlen(value));
            field = clean_line(colon + 1, strlen(colon + 1));
            if (key && field) {
                int binary = current < 0 ? 0 : current + 1;
                if (!strcmp(key, "Package")) {
                    if (binary_count < MAX_BINARIES) {
                        snprintf(binaries[binary_count].name, sizeof binaries[0].name, "%s",
                                 field);
                        binaries[binary_count].line = line;
                        current = (int)binary_count;
                        ++binary_count;
                        holy_note_add(&note, "carried", "Package %s %zu", field, line);
                    } else {
                        review = 1;
                        holy_note_add(&note, "unknown", "more binary packages than outputs are "
                                      "carried %s", field);
                    }
                }
                if (field_count < MAX_FIELDS) {
                    snprintf(fields[field_count].name, sizeof fields[0].name, "%s", key);
                    snprintf(fields[field_count].value, sizeof fields[0].value, "%s", field);
                    fields[field_count].line = line;
                    fields[field_count].binary = binary;
                    last_field = (int)field_count;
                    ++field_count;
                    if (!binary) {
                        if (!strcmp(key, "Source")) {
                            const char *mark = strchr(field, '(');
                            if (mark) {
                                size_t used = (size_t)(mark - field);
                                while (used && isspace((unsigned char)field[used - 1])) --used;
                                if (used >= sizeof name) used = sizeof name - 1;
                                memcpy(name, field, used);
                                name[used] = 0;
                            } else {
                                snprintf(name, sizeof name, "%s", field);
                            }
                        } else if (!strcmp(key, "Homepage") && !*homepage) {
                            snprintf(homepage, sizeof homepage, "%s", field);
                        } else if (!strcmp(key, "Standards-Version")) {
                            holy_note_add(&note, "preserved", "Standards-Version %s", field);
                        } else if (!strcmp(key, "Vcs-Browser") && !*homepage) {
                            snprintf(homepage, sizeof homepage, "%s", field);
                        }
                    } else {
                        struct deb_binary *package = &binaries[binary - 1];
                        if (!strcmp(key, "Architecture")) {
                            snprintf(package->architecture, sizeof package->architecture, "%s",
                                     field);
                        } else if (!strcmp(key, "Description")) {
                            snprintf(package->summary, sizeof package->summary, "%s", field);
                        }
                    }
                }
            }
            free(key);
            free(field);
        }
        free(value);
    }
    if (!*name) {
        fputs("holypkg: debian/control: the source stanza needs a Source or Package\n", stderr);
        result = 2;
        goto done;
    }

    /* the changelog first record gives the version the source was built at */
    {
        char *path = join_path(directory, "changelog");
        if (path) {
            changelog = read_file(path, NULL);
            free(path);
        }
    }
    if (!changelog || !*changelog) {
        review = 1;
        holy_note_add(&note, "unknown", "debian/changelog is not beside the control file, so "
                      "the version is unknown");
        snprintf(version, sizeof version, "0");
    } else {
        const char *open = strchr(changelog, '(');
        const char *close = open ? strchr(open, ')') : NULL;
        if (!close) {
            fputs("holypkg: debian/changelog: the first record is malformed\n", stderr);
            result = 2;
            goto done;
        }
        {
            char *value = clean_line(open + 1, (size_t)(close - open - 1));
            char *epoch;
            if (!value) { result = 1; goto done; }
            epoch = strchr(value, ':');
            if (epoch) {
                review = 1;
                holy_note_add(&note, "preserved", "the epoch %.*s of the changelog version",
                              (int)(epoch - value), value);
                memmove(value, epoch + 1, strlen(epoch + 1) + 1);
            }
            snprintf(version, sizeof version, "%s", value);
            free(value);
        }
        /* a Debian version is upstream-revision, and a native package has no revision */
        {
            char *dash = strrchr(version, '-');
            if (dash) {
                size_t at;
                for (at = 1; dash[at]; ++at)
                    if (!isdigit((unsigned char)dash[at])) break;
                if (!dash[at] && (size_t)(dash - version + 1) < sizeof release) {
                    memcpy(release, dash + 1, strlen(dash + 1) + 1);
                    *dash = 0;
                    holy_note_add(&note, "semantic-change", "the Debian revision %s becomes the "
                                  "Holy release", release);
                } else {
                    snprintf(release, sizeof release, "1");
                }
            } else {
                snprintf(release, sizeof release, "1");
            }
        }
        holy_note_add(&note, "carried", "changelog version %s", version);
    }
    /* the changelog is copied so the record travels with the recipe */
    if (changelog) {
        char *path = join_path(directory, "changelog");
        char *copy = join_path(output, "changelog");
        char digest[65];
        if (path && copy && !holy_copy_and_hash(path, copy, digest))
            wrote = 0;
        free(path);
        free(copy);
    }
    if (strpbrk(name, "$`/% \t") || !*version || strlen(name) > 480 || strlen(version) > 480) {
        fputs("holypkg: debian/control: the identity must be literal and short\n", stderr);
        result = 2;
        goto done;
    }

    /* a binary that lists its own files becomes a split output */
    for (index = 0; index < binary_count; ++index) {
        static const char *const suffixes[] = { "install", "docs", "manpages", "links", NULL };
        size_t used;
        for (used = 0; suffixes[used]; ++used) {
            char file[512];
            char *path;
            /* a debian file name is NAME.SUFFIX, and a long NAME would overrun */
            snprintf(file, sizeof file, "%.*s.%s",
                     (int)(strlen(binaries[index].name) < sizeof file - 32
                               ? strlen(binaries[index].name) : sizeof file - 32),
                     binaries[index].name, suffixes[used]);
            path = join_path(directory, file);
            if (!path) continue;
            {
                struct stat st;
                if (!stat(path, &st) && S_ISREG(st.st_mode)) {
                    binaries[index].has_list = 1;
                    snprintf(binaries[index].list, sizeof binaries[index].list, "%s", file);
                    binaries[index].list_line = 0;
                }
            }
            free(path);
        }
    }
    {
        for (index = 0; index < binary_count; ++index)
            if (!binaries[index].has_list) ++mains;
        if (mains > 1) {
            review = 1;
            holy_note_add(&note, "unknown", "%zu binary packages name no file list, so one of "
                          "them cannot be told apart", mains);
        }
        for (index = 0; index < binary_count; ++index)
            binaries[index].main = !binaries[index].has_list && mains == 1;
    }
    if (!binary_count) {
        /* a source package with no binary stanza still builds one output */
        {
            size_t used = strlen(name);
            if (used >= sizeof binaries[0].name) used = sizeof binaries[0].name - 1;
            memcpy(binaries[0].name, name, used);
            binaries[0].name[used] = 0;
        }
        binaries[0].main = 1;
        binary_count = 1;
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
    {
        /* the short description is the first line, the rest is the long one */
        size_t at = 0;
        const char *main_summary = summary;
        for (at = 0; at < binary_count; ++at)
            if (binaries[at].main && *binaries[at].summary) main_summary = binaries[at].summary;
        if (*main_summary) { fputs("summary ", out); holy_token(out, main_summary); fputc('\n', out); }
    }
    if (*homepage) { fputs("homepage ", out); holy_token(out, homepage); fputc('\n', out); }
    fputs("x-source-family deb\nx-converter debsrc-1\n", out);
    for (index = 0; index < binary_count; ++index)
        if (binaries[index].has_list) {
            fputs("output ", out); holy_token(out, binaries[index].name);
            fputs(" runtime\n", out);
        }
    if (mains <= 1) {
        /* the binary that names no file list is the one the whole tree belongs to */
        fputs("output ", out); holy_token(out, name);
        fputs(" runtime\n", out);
    }

    /* the requirement lists of the main package become dependency records */
    for (index = 0; index < field_count; ++index) {
        static const struct { const char *key; const char *kind; const char *where; } lists[] = {
            { "Build-Depends", "build-depend", "Build-Depends" },
            { "Build-Depends-Indep", "build-depend", "Build-Depends-Indep" },
            { "Depends", "depend", "Depends" },
            { "Pre-Depends", "depend", "Pre-Depends" },
            { "Recommends", NULL, NULL },
            { "Suggests", NULL, NULL },
            { "Enhances", NULL, NULL },
            { "Breaks", NULL, NULL },
            { "Conflicts", NULL, NULL },
            { "Replaces", NULL, NULL },
            { "Provides", NULL, NULL },
            { NULL, NULL, NULL }
        };
        size_t list_index;
        char **items;
        size_t count = 0, item;
        for (list_index = 0; lists[list_index].key; ++list_index)
            if (!strcmp(fields[index].name, lists[list_index].key)) break;
        if (!lists[list_index].key) continue;
        /* only the main package and the source stanza reach the recipe */
        if (fields[index].binary && fields[index].binary > (int)binary_count) continue;
        if (fields[index].binary) {
            int at;
            for (at = 0; at < (int)binary_count; ++at)
                if (at + 1 == fields[index].binary && !binaries[at].main) break;
            if (at < (int)binary_count) continue;
        }
        if (!lists[list_index].kind) {
            /* a capability, a conflict and a replacement are none of them a requirement,
               and each carries its own version, so only the name is recorded */
            int provides = !strcmp(fields[index].name, "Provides");
            int suggests = !strcmp(fields[index].name, "Recommends") ||
                           !strcmp(fields[index].name, "Suggests") ||
                           !strcmp(fields[index].name, "Enhances");
            char **entries;
            size_t entries_used = 0, entry;
            entries = relationship_groups(fields[index].value, &entries_used);
            for (entry = 0; entries && entry < entries_used; ++entry) {
                char requirement[512], relation[16], wanted[512];
                int epoch = 0;
                size_t at = 0;
                if (!split_requirement(entries[entry], requirement, sizeof requirement, relation,
                                       sizeof relation, wanted, sizeof wanted, &epoch, &at)) {
                    review = 1;
                    holy_note_add(&note, "unknown", "%s %s carries an entry this converter "
                                  "cannot name", fields[index].name, entries[entry]);
                    continue;
                }
                fputs(provides ? "x-provides " : suggests ? "x-suggests " : "x-conflicts ", out);
                holy_token(out, requirement);
                fputc('\n', out);
                if (strcmp(relation, "any"))
                    holy_note_add(&note, "preserved", "%s %s %s", fields[index].name,
                                  relation, wanted);
            }
            list_free(entries);
            continue;
        }
        items = relationship_groups(fields[index].value, &count);
        for (item = 0; items && item < count; ++item) {
            char *pipe = strchr(items[item], '|');
            if (pipe) {
                size_t used = (size_t)(pipe - items[item]);
                review = 1;
                while (used && items[item][used - 1] == ' ') --used;
                items[item][used] = 0;
                holy_note_add(&note, "unknown", "%s offers alternatives for %s, only the first "
                              "is carried", lists[list_index].where, items[item]);
            }
            emit_dependency(out, items[item], lists[list_index].kind, &note, &review,
                            lists[list_index].where);
        }
        list_free(items);
    }

    /* the rules file is the build, and dh is a macro framework, not a script */
    {
        char *path = join_path(directory, "rules");
        if (path) {
            rules = read_file(path, NULL);
            free(path);
        }
    }
    {
        /* the lintian and helper files beside control are carried as records */
        static const char *const carried[] = { "source/format", "copyright", "watch", NULL };
        size_t used;
        for (used = 0; carried[used]; ++used) {
            char file[512];
            struct stat st;
            snprintf(file, sizeof file, "%s", carried[used]);
            {
                char *path = join_path(directory, file);
                if (path && !stat(path, &st) && S_ISREG(st.st_mode)) {
                    char digest[65];
                    char *copy = join_path(output, file);
                    if (copy && !holy_copy_and_hash(path, copy, digest)) wrote = 0;
                    holy_note_add(&note, "preserved", "%s", file);
                    free(copy);
                }
                free(path);
            }
        }
    }
    for (index = 0; index < binary_count; ++index) {
        struct deb_binary *package = &binaries[index];
        static const char *const hooks[] = { "postinst", "preinst", "prerm", "postrm", NULL };
        size_t used;
        for (used = 0; hooks[used]; ++used) {
            char file[512];
            char *path;
            struct stat st;
            snprintf(file, sizeof file, "%.*s.%s",
                     (int)(strlen(package->name) < sizeof file - 32 ? strlen(package->name)
                                                                   : sizeof file - 32),
                     package->name, hooks[used]);
            path = join_path(directory, file);
            if (path && !stat(path, &st) && S_ISREG(st.st_mode)) {
                char digest[65];
                char *copy = join_path(output, file);
                if (!copy || !holy_copy_and_hash(path, copy, digest)) { wrote = 0; }
                free(copy);
                holy_note_add(&note, "preserved", "maintainer script %s", file);
                free(path);
                continue;
            }
            free(path);
        }
        if (!package->has_list) continue;
    }
    if (!wrote) { result = 1; goto done; }

    /* the file list of a binary names the paths its own package carries */
    for (index = 0; index < binary_count; ++index) {
        struct deb_binary *package = &binaries[index];
        char *path;
        char *list;
        char **items;
        size_t count = 0, item;
        if (!package->has_list) continue;
        path = join_path(directory, package->list);
        list = path ? read_file(path, NULL) : NULL;
        if (!list) {
            review = 1;
            holy_note_add(&note, "unknown", "the file list %s of %s could not be read",
                          package->list, package->name);
            free(path);
            continue;
        }
        /* the destinations the list names, so a list with none is reported rather than
           written as a split step that would fill no tree */
        struct text paths = {NULL, 0, 0};
        items = list_lines(list, &count);

        if (!text_add(&paths, "", 0)) { wrote = 0; }
        for (item = 0; items && item < count && wrote; ++item) {
            /* a line is SOURCE DESTINATION, or a source with no destination */
            char *cursor = items[item];
            char *space;
            char *destination;
            while (*cursor == ' ') ++cursor;
            if (*cursor == '.') continue;
            space = strchr(cursor, ' ');
            if (space) {
                *space = 0;
                destination = space + 1;
                while (*destination == ' ') ++destination;
            } else {
                destination = cursor;
            }
            {
                /* a path ending in a slash names the directory itself */
                size_t used = strlen(destination);
                if (used && destination[used - 1] == '/') destination[used - 1] = 0;
            }
            if (!*destination) continue;
            if (!text_puts(&paths, destination) || !text_puts(&paths, " ")) wrote = 0;
        }
        if (!paths.data || !*paths.data) {
            review = 1;
            holy_note_add(&note, "unknown", "the file list %s of %s names no path this "
                          "converter can carry", package->list, package->name);
            free(paths.data);
            list_free(items);
            free(list);
            free(path);
            continue;
        }
        fprintf(out, "split-step %s split /bin/sh <<SPLIT\n", package->name);
        fputs("# the debian file list names the paths this binary package carries\n", out);
        fputs("set -f\n", out);
        fputs("for entry in", out);
        {
            char *cursor = paths.data;
            while (*cursor) {
                char *stop = strchr(cursor, ' ');
                size_t used = stop ? (size_t)(stop - cursor) : strlen(cursor);
                char line[1024];
                if (used >= sizeof line) used = sizeof line - 1;
                memcpy(line, cursor, used);
                line[used] = 0;
                if (*line) { fputc(' ', out); holy_token(out, line); }
                cursor += used + (stop ? 1 : 0);
            }
        }
        fputs("; do\n", out);
        fputs("  [ -e \"$HOLY_DEST/$entry\" ] || continue\n", out);
        fputs("  mkdir -p \"$HOLY_SPLIT_DEST/$(dirname \"$entry\")\"\n", out);
        fputs("  cp -a \"$HOLY_DEST/$entry\" \"$HOLY_SPLIT_DEST/$entry\"\n", out);
        fputs("done\n", out);
        free(paths.data);
        list_free(items);
        free(list);
        free(path);
        fputs("SPLIT\n", out);
        holy_note_add(&note, "preserved", "subpackage %s from its file list", package->name);
        holy_note_add(&note, "semantic-change", "the file list of %s becomes a copy out of "
                      "the main tree, so a debian path cannot grow a file the build did not "
                      "place", package->name);
    }

    /* the rules body keeps its own shell behind a prologue */
    if (rules) {
        char *copy = join_path(output, "rules");
        {
            char *from = join_path(directory, "rules");
            char digest[65];
            if (!from || !copy || !holy_copy_and_hash(from, copy, digest)) wrote = 0;
            free(from);
        }
        free(copy);
    }
    {
        static const struct { const char *token; const char *text; } helpers[] = {
            { "dh ", "debhelper calls the recipe make, which this converter cannot run" },
            { "dh_auto", "debhelper autodetects the build system, which this converter cannot" },
            { "dh_install", "debhelper installs the file lists, which this converter cannot" },
            { "dpkg-buildpackage", "the dpkg build driver is not carried" },
            { "debian/rules", "the rules file is included, which a Holy step cannot" },
            { "override_dh_", "a debhelper override, which debhelper runs and this cannot" }
        };
        size_t used;
        for (used = 0; used < sizeof helpers / sizeof *helpers; ++used)
            if (rules && strstr(rules, helpers[used].token)) {
                review = 1;
                holy_note_add(&note, "unknown", "%s", helpers[used].text);
            }
    }
    if (rules && *rules) {
        fputs("step build /bin/sh <<STEP\n", out);
        fputs("# the debian rules keep their own shell; dh itself is not carried\n", out);
        fputs("DEB_HOST_MULTIARCH=$(uname -m)-linux-gnu\n", out);
        fputs("DEB_BUILD_OPTIONS=nocheck\n", out);
        fputs("cd \"$HOLY_SRC\"\n", out);
        fputs(rules, out);
        if (rules[strlen(rules) - 1] != '\n') fputc('\n', out);
        fputs("STEP\n", out);
        holy_note_add(&note, "preserved", "debian/rules");
    } else {
        review = 1;
        holy_note_add(&note, "unknown", "debian/rules is not beside the control file, so the "
                      "build has no body");
    }
    /* the lintian overrides beside control do not build anything */
    {
        char *path = join_path(directory, "lintian-overrides");
        struct stat st;
        if (path && !stat(path, &st) && S_ISREG(st.st_mode)) {
            review = 1;
            holy_note_add(&note, "unknown", "lintian-overrides is a lint suppression list, "
                          "which has no place in a build");
        }
        free(path);
    }

    if (fflush(out) || fclose(out)) { out = NULL; result = 1; goto done; }
    out = NULL;
    out = fopen(report_path, "wb");
    if (!out) {
        fprintf(stderr, "holypkg: report unavailable: %s\n", report_path);
        result = 1;
        goto done;
    }
    fputs("format holy-recipe-conversion-1\nconverter debsrc-1\n", out);
    fputs("source-name ", out); holy_token(out, source); fputc('\n', out);
    fputs("source-file debian/control\n", out);
    fprintf(out, "source-sha256 %s\n", control_hash);
    fputs("pkgbase ", out); holy_token(out, name); fputc('\n', out);
    fputs("version ", out); holy_token(out, version); fputc('\n', out);
    fputs("release ", out); holy_token(out, release); fputc('\n', out);
    fputs("arch ", out); holy_token(out, arch); fputc('\n', out);
    fputs("recipe ", out); holy_token(out, name); fputs(".recipe\n", out);
    fprintf(out, "status %s\n", review ? "review-required" : "native");
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
    if (result > 1 && result != 3)
        fprintf(stderr, "holypkg: Debian conversion failed (status %d)\n", result);
    free(control);
    free(changelog);
    free(rules);
    free(directory);
    holy_note_free(&note);
    return result;
}
