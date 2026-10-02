/* SlackBuild script to holy-recipe(5) conversion; see man/holy-recipe.5 and
   man/holypkg.8. the script is read as text and never run. a SlackBuild script is
   one linear shell program rather than a set of phase functions, so it becomes a
   single build step behind a prologue that rebuilds the slackbuild variables
   from the exported Holy paths. */
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1
#include "slackbuild.h"
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

struct sb_script {
    char *text;
    size_t length;
    char *directory;
};

/* the value of the last NAME=value line at the top level of a script, and the
   line it was written on. a case body still assigns, so it is read as well. */
static char *find_assignment(const struct sb_script *script, const char *key, size_t *at)
{
    size_t offset = 0, line = 0, depth = 0, cases = 0;
    size_t used = strlen(key);
    while (offset < script->length) {
        const char *start = script->text + offset;
        const char *newline = memchr(start, '\n', script->length - offset);
        size_t size = newline ? (size_t)(newline - start) : script->length - offset;
        char *value;
        ++line;
        offset = (size_t)(start + size + (newline ? 1 : 0) - script->text);
        while (size && isspace((unsigned char)start[0])) { ++start; --size; }
        while (size && isspace((unsigned char)start[size - 1])) --size;
        if (!size || *start == '#') continue;
        if (!strncmp(start, "if", 2) && (size == 2 || start[2] == ' ' || start[2] == '\t')) {
            ++depth;
            continue;
        }
        if (!strncmp(start, "case", 4) && (size == 4 || start[4] == ' ' || start[4] == '\t')) {
            ++depth;
            ++cases;
            continue;
        }
        if (!strncmp(start, "esac", 4) && (size == 4 || start[4] == ' ' || start[4] == '\t')) {
            if (depth) --depth;
            if (cases) --cases;
            continue;
        }
        if (!strncmp(start, "fi", 2) && (size == 2 || start[2] == ' ' || start[2] == '\t')) {
            if (depth) --depth;
            continue;
        }
        /* a case pattern ends at its closing paren, so only a body after it assigns */
        if (depth && cases) {
            const char *close = memchr(start, ')', size);
            size_t body = close ? (size_t)(close + 1 - start) : size;
            while (body < size && isspace((unsigned char)start[body])) ++body;
            start += body;
            size -= body;
            if (!size) continue;
        }
        /* a top level record is a name at the first column with a plain = after it */
        if (strncmp(start, key, used) || start[used] != '=' || (depth && !cases)) continue;
        /* a record is often quoted, and one layer of quoting is part of the syntax */
        value = holy_shell_unquote(start + used + 1, size - used - 1);
        if (!value) return NULL;
        if (!*value) { free(value); continue; }
        if (at) *at = line;
        return value;
    }
    return NULL;
}

/* the default of a ${NAME:-VALUE} record, or NULL when it is not that form */
static char *default_value(const char *text)
{
    size_t length = strlen(text), used = 2;
    if (length < 6 || text[0] != '$' || text[1] != '{') return NULL;
    while (used < length && (isalnum((unsigned char)text[used]) || text[used] == '_')) ++used;
    if (used + 3 > length || text[used] != ':' || text[used + 1] != '-' ||
        text[length - 1] != '}') return NULL;
    return holy_shell_copy(text + used + 2, length - used - 3);
}

/* an identity field, written as NAME=x or as NAME=${NAME:-x}. a computed value
   has no literal form here, so it is reported rather than guessed. */
static char *identity(const struct sb_script *script, const char *key, size_t *at, int *dynamic)
{
    char *value = find_assignment(script, key, at), *fallback;
    if (!value) return NULL;
    /* an unquoted record ends at a comment, the way the shell reads it */
    if (*value != '\'' && *value != '"') {
        char *hash = strstr(value, " #");
        if (hash) *hash = 0;
    }
    fallback = default_value(value);
    if (fallback) {
        free(value);
        value = fallback;
    }
    fallback = holy_shell_unquote(value, strlen(value));
    if (fallback) {
        free(value);
        value = fallback;
    }
    if (strpbrk(value, "$`\"/ \t")) {
        if (dynamic) *dynamic = 1;
        free(value);
        return NULL;
    }
    return value;
}

/* a byte search over a script body; the bodies are short and few */
static const char *find_bytes(const char *body, size_t length, const char *needle)
{
    size_t size = strlen(needle), index;
    if (!size || size > length) return NULL;
    for (index = 0; index + size <= length; ++index)
        if (!memcmp(body + index, needle, size)) return body + index;
    return NULL;
}

static int contains(const char *body, size_t length, const char *needle)
{
    return find_bytes(body, length, needle) != NULL;
}

/* the identity fields a source name may name, in the form the script writes them */
static char *expand_identity(const char *text, const char *name, const char *version,
                             const char *build)
{
    size_t used = 0, capacity = strlen(text) + 128;
    char *out = malloc(capacity);
    if (!out) return NULL;
    out[0] = 0;
    while (*text) {
        static const char *const fields[] = { "$PRGNAM", "$VERSION", "$BUILD" };
        const char *value = NULL;
        size_t index;
        for (index = 0; index < 3; ++index) {
            size_t at = strlen(fields[index]);
            if (strncmp(text, fields[index], at)) continue;
            value = index == 0 ? name : index == 1 ? version : build;
            if (used + at + strlen(value) + 1 > capacity) {
                char *grown = realloc(out, capacity * 2);
                if (!grown) { free(out); return NULL; }
                out = grown;
                capacity *= 2;
            }
            memcpy(out + used, value, strlen(value));
            used += strlen(value);
            out[used] = 0;
            text += at;
            break;
        }
        if (value) continue;
        if (used + 2 > capacity) {
            char *grown = realloc(out, capacity * 2);
            if (!grown) { free(out); return NULL; }
            out = grown;
            capacity *= 2;
        }
        out[used++] = *text++;
        out[used] = 0;
    }
    return out;
}

/* a plain file name beside the script, or NULL when the name is unusable */
static char *join_path(const char *directory, const char *name)
{
    char path[4096];
    if (!name || !*name || strlen(name) > 400 || strchr(name, '/') || strchr(name, '$') ||
        !strcmp(name, ".") || !strcmp(name, "..")) return NULL;
    if (snprintf(path, sizeof path, "%s/%s", directory, name) >= (int)sizeof path) return NULL;
    return strdup(path);
}

static const char *base_name(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/* the commands a script runs that this converter cannot supply or reproduce */
static void report_unknowns(const char *body, size_t length, struct recipe_note *note, int *review)
{
    static const struct { const char *token; const char *text; } unresolved[] = {
        { "uname -m", "the machine the script probes itself for is not carried" },
        { "strip ", "the slackbuild strip pass is not reproduced" },
        { "install-strip", "the install-strip target strips inside the build system" },
        { "chown -R root:root", "the script rewrites ownership, which a Holy step cannot" },
        { "git clone", "a source this script fetches from git is not carried" },
        { "git checkout", "a source this script fetches from git is not carried" },
        { "hg clone", "a source this script fetches from mercurial is not carried" },
        { "svn co", "a source this script fetches from subversion is not carried" },
        { "bzr ", "a source this script fetches from bazaar is not carried" },
        { "cpan ", "a source this script installs from cpan is not carried" },
        { "npm ", "a source this script installs from npm is not carried" },
        { "pip ", "a source this script installs from pip is not carried" },
        { "useradd", "the script creates a user, which a Holy step cannot" },
        { "groupadd", "the script creates a group, which a Holy step cannot" },
        { "ldconfig", "the script updates the loader cache, which a Holy step may not" },
        { "update-desktop-database", "the desktop cache helper is not carried" },
        { "update-mime-database", "the mime cache helper is not carried" },
        { "gtk-update-icon-cache", "the icon cache helper is not carried" },
        { "fc-cache", "the font cache helper is not carried" }
    };
    size_t index;
    for (index = 0; index < sizeof unresolved / sizeof *unresolved; ++index)
        if (contains(body, length, unresolved[index].token)) {
            holy_note_add(note, "unknown", "%s", unresolved[index].text);
            /* the script keeps its own shell, so what it could not carry is named */
            holy_note_environment(note, "slackbuild-script");
            *review = 1;
        }
}

/* the slackbuild variables a script body may read, rebuilt from the exported
   paths. CWD is the directory holding the recipe, which is where the script keeps
   the files it references, so the local sources travel next to the recipe. */
static char *prologue(const char *name, const char *version, const char *build,
                      const char *tag, const char *pkgtype)
{
    char *text = NULL;
    size_t used = 0;
    FILE *out = open_memstream(&text, &used);
    if (!out) return NULL;
    fputs("# slackbuild variables rebuilt from the exported Holy paths\n", out);
    fprintf(out, "PRGNAM=%s\nVERSION=%s\nBUILD=%s\nTAG=%s\nPKGTYPE=%s\n", name, version, build,
            tag, pkgtype);
    fputs("ARCH=\"$HOLY_ARCH\"\n", out);
    /* CWD is the source tree, where the engine stages every file the recipe declares */
    fputs("CWD=\"$HOLY_SRC\"\nTMP=\"$HOLY_SRC\"\nPKG=\"$HOLY_DEST\"\nOUTPUT=\"$HOLY_OUT\"\n",
          out);
    fputs("PKGDESTDIR=\"$HOLY_DEST\"\nDESTDIR=\"$HOLY_DEST\"\n", out);
    fputs("LIBDIRSUFFIX=\"\"\n", out);
    fputs("SLKCFLAGS=\"${SLKCFLAGS:--O2 -fPIC}\"\n", out);
    fputs("CFLAGS=\"${CFLAGS:-$SLKCFLAGS}\"\n", out);
    fputs("CXXFLAGS=\"${CXXFLAGS:-$SLKCFLAGS}\"\n", out);
    fputs("LDFLAGS=\"${LDFLAGS:--Wl,-z,relro}\"\n", out);
    fputs("MAKEFLAGS=\"${MAKEFLAGS:--j$HOLY_JOBS}\"\n", out);
    fclose(out);
    return text;
}

/* the description lines of a slack-desc file, as one summary */
static char *desc_summary(const char *desc, const char *name, char **homepage,
                          char **requires, char **conflicts, char **optional)
{
    char *summary = NULL;
    const char *cursor = desc;
    static const char *const fields[] = { "homepage", "requires", "conflicts", "replaces",
                                          "optional", "suggest" };
    while (cursor && *cursor) {
        const char *newline = strchr(cursor, '\n');
        size_t length = newline ? (size_t)(newline - cursor) : strlen(cursor);
        const char *text = cursor;
        char *grown;
        size_t field;
        cursor = newline ? newline + 1 : NULL;
        if (!length || strncmp(text, name, strlen(name)) || text[strlen(name)] != ':') continue;
        text += strlen(name) + 1;
        length -= strlen(name) + 1;
        while (length && (*text == ' ' || *text == '\t')) { ++text; --length; }
        for (field = 0; field < sizeof fields / sizeof *fields; ++field) {
            size_t at = strlen(fields[field]);
            if (length > at + 1 && !strncmp(text, fields[field], at) && text[at] == ':' &&
                text[at + 1] == ' ') break;
        }
        if (field < sizeof fields / sizeof *fields) {
            size_t at = strlen(fields[field]) + 2;
            const char *value = text + at;
            size_t used = length - at;
            char **target = field == 0 ? homepage : field == 1 ? requires :
                            field == 2 ? conflicts : optional;
            /* a field may repeat, so a later line is appended to the earlier one */
            grown = malloc((*target ? strlen(*target) : 0) + used + 2);
            if (!grown) continue;
            if (*target) sprintf(grown, "%s %.*s", *target, (int)used, value);
            else {
                memcpy(grown, value, used);
                grown[used] = 0;
            }
            free(*target);
            *target = grown;
            continue;
        }
        if (!length) continue;
        grown = summary ? malloc(strlen(summary) + length + 2) : malloc(length + 1);
        if (!grown) continue;
        if (summary) sprintf(grown, "%s %.*s", summary, (int)length, text);
        else {
            memcpy(grown, text, length);
            grown[length] = 0;
        }
        free(summary);
        summary = grown;
    }
    return summary;
}

/* every file the script reads from its own directory travels beside the recipe and is
   declared as a source, so the engine stages it where CWD points during a step */
static void collect_local_sources(const struct sb_script *script, const char *name,
                                  const char *version, const char *build, const char *output,
                                  const char *archive, char **sources, size_t *used,
                                  struct recipe_note *note, int *review)
{
    const char *at = find_bytes(script->text, script->length, "$CWD/");
    size_t capacity = *used;
    while (at && capacity < 16) {
        const char *end = memchr(at, '\n', (size_t)(script->text + script->length - at));
        size_t length = end ? (size_t)(end - at) : (size_t)(script->text + script->length - at);
        char line[1024];
        char *value = NULL;
        char *stop;
        if (length >= sizeof line) length = sizeof line - 1;
        memcpy(line, at, length);
        line[length] = 0;
        if ((value = strstr(line, "$CWD/")) != NULL) {
            struct stat st;
            char *original;
            char *copied;
            size_t index;
            char *expanded;
            value += 5;
            stop = value;
            while (*stop && !isspace((unsigned char)*stop) && !strchr("*?'\";|)", *stop))
                ++stop;
            *stop = 0;
            expanded = *value ? expand_identity(value, name, version, build) : NULL;
            if (expanded && !strchr(expanded, '$') && strcmp(expanded, archive)) {
                for (index = 0; index < *used; ++index)
                    if (!strcmp(sources[index], expanded)) break;
                original = join_path(script->directory, expanded);
                if (index == *used && original && !stat(original, &st) && S_ISREG(st.st_mode)) {
                    char digest[65];
                    copied = join_path(output, expanded);
                    if (copied && holy_copy_and_hash(original, copied, digest) &&
                        (sources[*used] = strdup(expanded)) != NULL) {
                        ++*used;
                        ++capacity;
                        holy_note_add(note, "carried", "local source %s", expanded);
                    } else {
                        *review = 1;
                        holy_note_add(note, "unknown", "local source %s could not be copied",
                                      expanded);
                    }
                    free(copied);
                }
                free(original);
            } else if (expanded && *expanded && strcmp(expanded, archive)) {
                *review = 1;
                holy_note_add(note, "unknown", "local source %s is not beside the script",
                              expanded);
            }
            free(expanded);
        }
        at = find_bytes(at + 1, (size_t)(script->text + script->length - at - 1), "$CWD/");
    }
}

/* writes the build body, leaving out the extraction the engine has already done */
static int write_body(FILE *out, const char *body, size_t length, const char *name,
                      const char *version, const char *archive, struct recipe_note *note,
                      int *review)
{
    size_t offset = 0;
    while (offset < length) {
        const char *start = body + offset;
        const char *newline = memchr(start, '\n', length - offset);
        size_t size = newline ? (size_t)(newline - start) : length - offset;
        char line[1024];
        int keep = 1;
        if (size >= sizeof line) size = sizeof line - 1;
        memcpy(line, start, size);
        line[size] = 0;
        /* the engine fetched and unpacked the archive, so the script extracts nothing */
        if (!strncmp(line, "tar ", 4) && strstr(line, "$CWD/")) {
            keep = 0;
            *review = 1;
            holy_note_add(note, "semantic-change", "the tar line unpacks %s, which the engine "
                          "already did from the recorded source", archive);
        } else if (!strcmp(line, "rm -rf $PRGNAM-$VERSION") ||
                   !strncmp(line, "rm -rf $PRGNAM-$VERSION ", 24)) {
            keep = 0;
        }
        {
            size_t written = newline ? (size_t)(newline + 1 - start) : size;
            if (keep && fwrite(start, 1, written, out) != written) return 0;
            offset += written;
        }
    }
    (void)name;
    (void)version;
    return 1;
}

int holy_convert_slackbuild(const char *input, const char *source, const char *output)
{
    struct sb_script script;
    struct recipe_note note;
    char *name = NULL, *version = NULL, *build = NULL, *tag = NULL, *pkgtype = NULL;
    char *sources[16];
    size_t sources_used = 0;
    char *summary = NULL, *homepage = NULL, *requires = NULL, *conflicts = NULL;
    char *optional = NULL, *archive = NULL, *info = NULL, *desc = NULL;
    char recipe_path[4096], report_path[4096], target[4096];
    char script_hash[65] = {0}, source_hash[65] = {0};
    const char *body = NULL;
    size_t body_length = 0, index;
    FILE *out = NULL;
    size_t at_prgnam = 0, at_version = 0, at_build = 0, at_tag = 0, at_pkgtype = 0;
    int dynamic = 0, has_hook = 0, has_archive = 0, result = 1, review = 0, i, wrote = 1;

    memset(&script, 0, sizeof script);
    memset(&note, 0, sizeof note);
    memset(sources, 0, sizeof sources);

    if (!input || !output || !*output) {
        fputs("usage: holypkg convert NAME.SlackBuild --source NAME --output NEW_DIRECTORY\n",
              stderr);
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
        /* the script is read as text and is never run */
        struct stat st;
        const char *label = base_name(input);
        FILE *in = stat(input, &st) || !S_ISREG(st.st_mode) || st.st_size > 4 * 1024 * 1024
                      ? NULL : fopen(input, "rb");
        if (!in) {
            fprintf(stderr, "holypkg: %s unavailable: %s\n", label, input);
            return 6;
        }
        script.length = (size_t)st.st_size;
        script.text = malloc(script.length + 1);
        if (!script.text || fread(script.text, 1, script.length, in) != script.length) {
            if (script.text) free(script.text);
            fclose(in);
            fprintf(stderr, "holypkg: %s could not be read\n", label);
            return 6;
        }
        fclose(in);
        script.text[script.length] = 0;
        script.directory = strdup(input);
        if (!script.directory) { free(script.text); return 1; }
        {
            char *slash = strrchr(script.directory, '/');
            if (slash) *slash = 0;
            else strcpy(script.directory, ".");
        }
    }
    if (mkdir(output, 0700) && errno != EEXIST) {
        fprintf(stderr, "holypkg: conversion directory unavailable: %s\n", output);
        result = 1;
        goto done;
    }

    /* the identity fields; a script that computes one cannot be converted */
    name = identity(&script, "PRGNAM", &at_prgnam, &dynamic);
    if (!name || !*name) {
        fputs(dynamic ? "holypkg: SlackBuild: PRGNAM must be a literal name\n"
                      : "holypkg: SlackBuild: PRGNAM is required\n", stderr);
        result = 2;
        goto done;
    }
    version = identity(&script, "VERSION", &at_version, &dynamic);
    build = identity(&script, "BUILD", &at_build, &dynamic);
    if (!version || !build) {
        fputs(dynamic ? "holypkg: SlackBuild: VERSION and BUILD must be literal\n"
                      : "holypkg: SlackBuild: VERSION and BUILD are required\n", stderr);
        result = 2;
        goto done;
    }
    tag = identity(&script, "TAG", &at_tag, NULL);
    if (!tag) tag = strdup("_SBo");
    pkgtype = identity(&script, "PKGTYPE", &at_pkgtype, NULL);
    if (!pkgtype) pkgtype = strdup("tgz");
    if (!tag || !pkgtype) { result = 1; goto done; }
    holy_note_add(&note, "carried", "PRGNAM %zu", at_prgnam);
    holy_note_add(&note, "carried", "VERSION %zu", at_version);
    holy_note_add(&note, "carried", "BUILD %zu", at_build);
    holy_note_add(&note, "preserved", "TAG %zu", at_tag);
    holy_note_add(&note, "preserved", "PKGTYPE %zu", at_pkgtype);

    /* slack-desc beside the script carries the summary, homepage and requirements */
    {
        char *desc_path = join_path(script.directory, "slack-desc");
        struct stat st;
        FILE *in = desc_path ? fopen(desc_path, "rb") : NULL;
        if (in) {
            size_t size;
            fclose(in);
            in = fopen(desc_path, "rb");
            if (in && !stat(desc_path, &st) && st.st_size > 0 && st.st_size < 256 * 1024 &&
                (size = (size_t)st.st_size, desc = malloc(size + 1)) != NULL &&
                fread(desc, 1, size, in) == size)
                desc[size] = 0;
            else {
                free(desc);
                desc = NULL;
            }
            if (in) fclose(in);
        }
        if (desc) {
        summary = desc_summary(desc, name, &homepage, &requires, &conflicts, &optional);
            holy_note_add(&note, "carried", "slack-desc %s", desc_path);
            if (summary) holy_note_add(&note, "carried", "slack-desc summary");
        } else {
            review = 1;
            holy_note_add(&note, "unknown", "slack-desc is not readable beside the script");
        }
        free(desc_path);
    }
    if (optional && *optional) {
        review = 1;
        holy_note_add(&note, "preserved", "slack-desc optional %s", optional);
    }

    /* the archive the script unpacks names the source, with the identity fields expanded */
    {
        const char *at = find_bytes(script.text, script.length, "tar xvf $CWD/");
        while (at) {
            const char *end = memchr(at, '\n', (size_t)(script.text + script.length - at));
            size_t length = end ? (size_t)(end - at) : (size_t)(script.text + script.length - at);
            char line[1024];
            char *value;
            if (length >= sizeof line) length = sizeof line - 1;
            memcpy(line, at, length);
            line[length] = 0;
            value = strstr(line, "$CWD/");
            if (value) {
                char *stop;
                value += 5;
                stop = value;
                while (*stop && !isspace((unsigned char)*stop) && !strchr("*?'\";", *stop))
                    ++stop;
                if (stop > value) {
                    char *expanded;
                    *stop = 0;
                    expanded = expand_identity(value, name, version, build);
                    if (expanded && !strchr(expanded, '$')) {
                        free(archive);
                        archive = expanded;
                        break;
                    }
                    free(expanded);
                }
            }
            at = find_bytes(at + 1, (size_t)(script.text + script.length - at - 1),
                            "tar xvf $CWD/");
        }
    }
    if (!archive) {
        /* the common form is PRGNAM-VERSION.tar.gz, so that name is assumed */
        size_t length = strlen(name) + strlen(version) + 16;
        archive = malloc(length);
        if (!archive) { result = 1; goto done; }
        snprintf(archive, length, "%s-%s.tar.gz", name, version);
        review = 1;
        holy_note_add(&note, "unknown", "the script unpacks with a wildcard, so the archive "
                      "name is taken as %s", archive);
    }
    {
        char *original = join_path(script.directory, archive);
        struct stat st;
        if (original && !stat(original, &st) && S_ISREG(st.st_mode)) {
            /* a local archive travels with the recipe and is hashed as sha256 */
            char *copied = join_path(output, archive);
            if (!copied || !holy_copy_and_hash(original, copied, source_hash)) wrote = 0;
            else {
                has_archive = 1;
                holy_note_add(&note, "carried", "source %s", archive);
                holy_note_add(&note, "semantic-change", "local source %s copied next to the "
                              "recipe and hashed as sha256", archive);
            }
            free(copied);
        } else {
            review = 1;
            holy_note_add(&note, "unknown", "source %s is not beside the script, so it has no "
                          "sha256 digest", archive);
        }
        free(original);
    }
    /* the info file beside the script names the upstream URL and an md5 */
    {
        char *info_path = join_path(script.directory, "info");
        struct stat st;
        FILE *in = info_path ? fopen(info_path, "rb") : NULL;
        if (in) {
            size_t size;
            fclose(in);
            in = fopen(info_path, "rb");
            if (in && !stat(info_path, &st) && st.st_size > 0 && st.st_size < 256 * 1024 &&
                (size = (size_t)st.st_size, info = malloc(size + 1)) != NULL &&
                fread(info, 1, size, in) == size)
                info[size] = 0;
            else {
                free(info);
                info = NULL;
            }
            if (in) fclose(in);
        }
        free(info_path);
    }
    if (info) {
        const char *at = strstr(info, "DOWNLOAD=\"");
        if (at) {
            const char *start = strchr(at, '"') + 1;
            const char *end = strchr(start, '"');
            if (end && end > start) {
                char url[1024];
                size_t length = (size_t)(end - start);
                if (length < sizeof url) {
                    memcpy(url, start, length);
                    url[length] = 0;
                    review = 1;
                    holy_note_add(&note, "preserved", "info DOWNLOAD %s", url);
                }
            }
        }
        review = 1;
        holy_note_add(&note, "unknown", "the md5sum this format pins is not a Holy source "
                      "digest, so a local copy is hashed as sha256 instead");
    }

    collect_local_sources(&script, name, version, build, output, archive,
                         sources, &sources_used, &note, &review);

    /* an install script the script copies into $PKG/install runs as one hook */
    if (contains(script.text, script.length, "$CWD/doinst.sh")) {
        size_t index;
        for (index = 0; index < sources_used; ++index)
            if (!strcmp(sources[index], "doinst.sh")) has_hook = 1;
        if (has_hook) {
            holy_note_add(&note, "preserved", "hook doinst.sh");
        } else {
            review = 1;
            holy_note_add(&note, "unknown", "the script installs doinst.sh but no such file is "
                          "beside it");
        }
    }
    /* the body runs from the first real command to the packaging helper */
    {
        const char *at = find_bytes(script.text, script.length, "\nset -e\n");
        const char *pack = find_bytes(script.text, script.length, "\n/sbin/makepkg");
        body = at ? at + strlen("\nset -e\n") : script.text;
        body_length = (size_t)(script.text + script.length - body);
        if (pack && pack + 1 >= body)
            body_length = pack > body ? (size_t)(pack - body) : 0;
        while (body_length && (body[0] == '\n' || body[0] == '\r')) { ++body; --body_length; }
        while (body_length && (body[body_length - 1] == '\n' || body[body_length - 1] == '\r'))
            --body_length;
        /* the script changes into the package tree only to hand it to makepkg */
        {
            size_t end = body_length, start = end;
            while (start && body[start - 1] != '\n') --start;
            if (end - start == 7 && !memcmp(body + start, "cd $PKG", 7)) {
                body_length = start;
                while (body_length && body[body_length - 1] == '\n') --body_length;
            }
        }
        report_unknowns(body, body_length, &note, &review);
        /* the script packages with makepkg, which the engine replaces with its own packer */
        if (pack) {
            review = 1;
            holy_note_add(&note, "semantic-change", "the cd $PKG and /sbin/makepkg lines are "
                          "left out, the engine packs the payload");
        }
        if (!body_length) {
            review = 1;
            holy_note_add(&note, "unknown", "the script has no build body between set -e and "
                          "makepkg");
        }
    }
    /* the machine the script picks and the flag set it derives from it */
    if (contains(script.text, script.length, "ARCH=")) {
        review = 1;
        holy_note_add(&note, "semantic-change", "the machine the script detects from uname -m "
                      "becomes $HOLY_ARCH");
    }
    if (contains(script.text, script.length, "LIBDIRSUFFIX")) {
        review = 1;
        holy_note_add(&note, "semantic-change", "the LIBDIRSUFFIX the script chooses per machine "
                      "becomes empty on x86_64");
    }

    snprintf(target, sizeof target, "%s/%s", output, base_name(input));
    if (!holy_copy_and_hash(input, target, script_hash)) {
        fputs("holypkg: SlackBuild copy failed\n", stderr);
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
    fputs("\nrelease ", out); holy_token(out, build);
    fputs("\narch any\nlibc any\n", out);
    if (summary && *summary) { fputs("summary ", out); holy_token(out, summary); fputc('\n', out); }
    if (homepage && *homepage) { fputs("homepage ", out); holy_token(out, homepage); fputc('\n', out); }
    fputs("x-source-family slackware\nx-converter slackbuild-1\n", out);
    { fputs("x-tag ", out); holy_token(out, tag); fputc('\n', out); }
    { fputs("x-pkgtype ", out); holy_token(out, pkgtype); fputc('\n', out); }
    if (has_archive) {
        fputs("source ", out); holy_token(out, archive);
        fputc(' ', out); holy_token(out, archive); fputc('\n', out);
        fputs("source-sha256 ", out); holy_token(out, archive);
        fputc(' ', out); holy_token(out, source_hash); fputc('\n', out);
    }
    /* a plain local file needs no digest, the engine stages it as written */
    for (index = 0; index < sources_used; ++index) {
        fputs("source ", out); holy_token(out, sources[index]);
        fputc(' ', out); holy_token(out, sources[index]); fputc('\n', out);
    }
    if (requires && *requires) {
        size_t count = 0;
        char **items = holy_shell_words(requires, &count);
        for (index = 0; items && index < count; ++index) {
            if (strchr(items[index], ' ') || strchr(items[index], '/') || !*items[index]) {
                review = 1;
                holy_note_add(&note, "unknown", "requirement %s in slack-desc", items[index]);
                continue;
            }
            holy_emit_dependency(out, items[index], "depend");
        }
        holy_shell_words_free(items);
    }
    if (conflicts && *conflicts) {
        size_t count = 0;
        char **items = holy_shell_words(conflicts, &count);
        for (index = 0; items && index < count; ++index) {
            fputs("x-conflicts ", out);
            holy_token(out, items[index]);
            fputc('\n', out);
        }
        holy_shell_words_free(items);
    }
    fputs("output ", out); holy_token(out, name);
    fputs(" runtime\n", out);
    if (contains(script.text, script.length, "$PKG/install")) {
        review = 1;
        holy_note_add(&note, "semantic-change", "the $PKG/install tree is slackbuild packaging "
                      "metadata, so it stays in the payload as ordinary files");
    }
    if (has_hook) {
        fputs("hook-install /bin/sh ", out);
        holy_token(out, "usr/share/holy/slackbuild/doinst.sh");
        fputc('\n', out);
        holy_note_add(&note, "semantic-change", "the doinst.sh script runs as a postinstall "
                      "hook with the destination as its working directory");
    }
    {
        /* the engine unpacks the archive, so the script's own extraction is not run */
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
        holy_note_add(&note, "semantic-change", "the engine fetches and unpacks the archive, so "
                      "the script's tar line is reported instead of run");
    }
    {
        char *prefix = prologue(name, version, build, tag, pkgtype);
        if (!prefix) { result = 1; goto done; }
        fputs("step build /bin/sh <<STEP\n", out);
        fputs(prefix, out);
        if (!write_body(out, body, body_length, name, version, archive, &note, &review)) {
            wrote = 0;
            result = 1;
            goto done;
        }
        fputc('\n', out);
        fputs("STEP\n", out);
        holy_note_add(&note, "preserved", "build body from the set -e line to makepkg");
        free(prefix);
    }
    if (!wrote) { result = 1; goto done; }
    if (has_hook) {
        /* the hook script travels in the payload so the installer can read it */
        fputs("step build /bin/sh <<HOOK\n"
              "mkdir -p \"$HOLY_DEST/usr/share/holy/slackbuild\"\n"
              "cp \"$HOLY_SRC/doinst.sh\" \"$HOLY_DEST/usr/share/holy/slackbuild/doinst.sh\"\n"
              "HOOK\n", out);
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
    fputs("format holy-recipe-conversion-1\nconverter slackbuild-1\n", out);
    fputs("source-name ", out); holy_token(out, source); fputc('\n', out);
    fputs("source-file ", out); holy_token(out, base_name(input)); fputc('\n', out);
    fprintf(out, "source-sha256 %s\n", script_hash);
    fputs("pkgbase ", out); holy_token(out, name); fputc('\n', out);
    fputs("version ", out); holy_token(out, version); fputc('\n', out);
    fputs("release ", out); holy_token(out, build); fputc('\n', out);
    fputs("arch any\n", out);
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
    if (result > 1 && result != 3)
        fprintf(stderr, "holypkg: SlackBuild conversion failed (status %d)\n", result);
    free(name); free(version); free(build); free(tag); free(pkgtype);
    free(summary); free(homepage); free(requires); free(conflicts); free(optional);
    free(archive); free(info); free(desc);
    for (index = 0; index < sources_used; ++index) free(sources[index]);
    free(script.directory); free(script.text);
    holy_note_free(&note);
    return result;
}
