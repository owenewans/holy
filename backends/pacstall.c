/* Pacstall pacscript to holy-recipe(5) conversion; see man/holy-recipe.5 and
   man/holypkg.8. the pacscript is read as text and never run. a pacscript is
   bash with a metadata header written as assignments, a small set of phase
   functions and a package manager environment that exports DEB variables, so
   each phase body keeps its own shell behind a prologue that rebuilds the
   variables Pacstall exports onto the Holy paths, and every helper that
   environment supplies is reported rather than invented. */
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1
#include "pacstall.h"
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

/* the phase functions, in the order Pacstall runs them */
static const struct {
    const char *pacscript;
    const char *phase;
} phases[] = {
    { "prepare", "prepare" },
    { "build", "build" },
    { "check", "check" },
    { "package", "package" }
};

/* the install time functions, which run beside the phases. Pacstall picks
   pre_install or pre_upgrade and post_install or post_upgrade for itself, and a
   Holy hook runs with ACTION unset, so one group becomes one hook. */
static const struct {
    const char *pacscript;
    const char *group;
} hooks[] = {
    { "pre_install", "install" },
    { "pre_upgrade", "install" },
    { "post_install", "install" },
    { "post_upgrade", "install" },
    { "pre_remove", "remove" },
    { "post_remove", "remove" }
};

/* the helper functions Pacstall exports. a body that calls one cannot run without
   the Pacstall environment, so each call is reported by name. */
static const char *const helpers[] = {
    "fancy_message", "ask", "select_options", "is_function", "makedeb", "makepkg",
    "makepkg_env", "parse_options", "dependency_check", "check_deps", "log_error",
    "error_log", "checks", "pre_checks", "gettext", "hashcheck_down",
    "genextr_down", "net_down", "git_down", "add_pacscript", NULL
};

/* the variables a body may read that a recipe cannot rebuild: they name a running
   installation, a host kernel or a maintainer decision */
static const struct {
    const char *name;
    const char *why;
} environment[] = {
    { "KVER", "the running kernel a DKMS body builds for" },
    { "STAGEDIR", "the staging root Pacstall lays out itself" },
    { "homedir", "the home directory of the installing user" },
    { "DISTRO", "the distribution Pacstall was started for" },
    { "DIR", "the directory Pacstall cached the pacscript in" },
    { "full_version", "the string Pacstall builds a package file name from" },
    { "pacstall_root", "the Pacstall installation prefix" }
};

/* the dependency lists, in the order Pacstall evaluates them */
static const struct {
    const char *key;
    const char *kind;
} dependencies[] = {
    { "depends", "depend" },
    { "makedepends", "build-depend" },
    { "checkdepends", "build-depend" },
    { NULL, NULL }
};

/* pacdeps are packages of the same pacstall repository rather than of the
   distribution, and a Holy resolver has to find them somewhere, so they become
   requirements and the fact is reported */
#define PACDEPS "pacdeps"

/* the relations, none of which names a requirement, so they are preserved as x-
   records */
static const struct {
    const char *key;
    const char *record;
} relations[] = {
    { "provides", "x-provides" },
    { "conflicts", "x-conflicts" },
    { "breaks", "x-conflicts" },
    { "makeconflicts", "x-makeconflicts" },
    { "checkconflicts", "x-checkconflicts" },
    { "replaces", "x-replaces" },
    { "enhances", "x-recommends" },
    { "recommends", "x-recommends" },
    { "suggests", "x-recommends" },
    { NULL, NULL }
};

/* the digest lists, none of which pins the SHA-256 a Holy source needs */
static const char *const digests[] = {
    "md5sums", "sha1sums", "sha224sums", "sha384sums", "sha512sums", "b2sums",
    "blake2sums", NULL
};

/* the settings that steer a Pacstall run and that a Holy recipe has no place for */
static const char *const settings[] = {
    "priority", "external_connection", "incompatible", "compatible", "mask",
    "noextract", "custom_fields", "ppa", NULL
};

/* the lists that exist per machine or per distribution under a suffixed name */
static const char *const lists[] = {
    "source", "sha256sums", "depends", "makedepends", "checkdepends", PACDEPS,
    "optdepends", "provides", "conflicts", "breaks", "replaces", "enhances",
    "recommends", "suggests", NULL
};

/* the metadata a recipe records as an x- value, in the order a pacscript writes
   it */
static const struct {
    const char *key;
    const char *record;
} carried[] = {
    { "license", "x-license" },
    { "maintainer", "x-maintainer" },
    { "repology", "x-repology" },
    { "bugs", "x-bugs" },
    { NULL, NULL }
};

/* the keys a pacscript may set that the converter reads itself */
static const char *const known[] = {
    "pkgname", "pkgbase", "pkgver", "pkgrel", "epoch", "pkgdesc", "url", "arch",
    "license", "maintainer", "repology", "bugs", "gives", "source", "sha256sums",
    PACDEPS, "optdepends", "backup", "depends", "makedepends", "checkdepends",
    "provides", "conflicts", "breaks", "replaces", "enhances", "recommends",
    "suggests", "makeconflicts", "checkconflicts", "md5sums", "sha1sums",
    "sha224sums", "sha384sums", "sha512sums", "b2sums", "blake2sums", "priority",
    "external_connection", "incompatible", "compatible", "mask", "noextract",
    "custom_fields", "ppa", NULL
};

struct pac_value {
    char *text;
    size_t line;
};

struct pac_list {
    struct pac_value *items;
    size_t count;
};

/* the identity a pacscript declares in its own assignments */
struct pacscript_name {
    char name[256];
    char base[256];
    char version[256];
    char release[64];
    char epoch[16];
    char gives[256];
    char arch[64];
};

static int is_label(const char *value)
{
    size_t at;
    if (!value || !*value) return 0;
    for (at = 0; value[at]; ++at)
        if (!isalnum((unsigned char)value[at]) &&
            !(value[at] == '.' || value[at] == '_' || value[at] == '+' || value[at] == '-'))
            return 0;
    return 1;
}

/* a computed value cannot be written into a manifest, so it is refused */
static int literal(const char *value, size_t size)
{
    return value && *value && strlen(value) < size && !strpbrk(value, "$`\"'\\ \t");
}

/* copies one list out of the parsed script, because the parser hands out a
   snapshot that its own next call replaces */
static int read_list(const struct shell_script *script, const char *key, struct pac_list *list)
{
    const struct shell_value *entries;
    size_t count = 0, index;
    memset(list, 0, sizeof *list);
    entries = holy_shell_entries(script, key, &count);
    if (!count) return 1;
    list->items = malloc(count * sizeof *list->items);
    if (!list->items) return 0;
    list->count = count;
    for (index = 0; index < count; ++index) {
        list->items[index].text = strdup(entries[index].text);
        list->items[index].line = entries[index].line;
        if (!list->items[index].text) {
            for (size_t before = 0; before < index; ++before) free(list->items[before].text);
            free(list->items);
            memset(list, 0, sizeof *list);
            return 0;
        }
    }
    return 1;
}

static void free_list(struct pac_list *list)
{
    size_t index;
    for (index = 0; index < list->count; ++index) free(list->items[index].text);
    free(list->items);
    memset(list, 0, sizeof *list);
}

/* a list joined with single spaces, which is what one x- record holds */
static char *join_list(const struct pac_list *list)
{
    char *joined;
    size_t used = 0, index;
    if (!list->count) return NULL;
    for (index = 0; index < list->count; ++index) used += strlen(list->items[index].text) + 1;
    joined = malloc(used + 1);
    if (!joined) return NULL;
    joined[0] = 0;
    for (index = 0; index < list->count; ++index) {
        if (index) strcat(joined, " ");
        strcat(joined, list->items[index].text);
    }
    return joined;
}

/* the directory that holds the pacscript, which also holds the files it names */
static char *pacscript_directory(const char *input)
{
    char *copy, *slash;
    size_t used;
    if (!strchr(input, '/')) return strdup(".");
    copy = strdup(input);
    if (!copy) return NULL;
    used = strlen(copy);
    while (used && copy[used - 1] == '/') copy[--used] = 0;
    slash = strrchr(copy, '/');
    if (slash) *slash = 0;
    if (!*copy) {
        free(copy);
        return strdup("/");
    }
    return copy;
}

/* 1 when a body calls a helper, which is a name in a command position that is not
   inside a comment and is not part of a longer name */
static int calls_helper(const char *body, size_t length, const char *name)
{
    size_t used = strlen(name);
    size_t index;
    for (index = 0; index + used <= length; ++index) {
        const char *at = body + index;
        const char *before = index ? at - 1 : NULL;
        const char *after = at + used;
        size_t line;
        if (memcmp(at, name, used)) continue;
        if (before && (isalnum((unsigned char)*before) || *before == '_' || *before == '-' ||
                       *before == '.' || *before == '/'))
            continue;
        if (after < body + length && (isalnum((unsigned char)*after) || *after == '_' ||
                                     *after == '-' || *after == '.'))
            continue;
        if (after < body + length && *after != ' ' && *after != '\t' && *after != '"' &&
            *after != '\'' && *after != '\n' && *after != ')' && *after != ';' &&
            *after != '|' && *after != '&')
            continue;
        for (line = index; line; --line)
            if (at[-(ptrdiff_t)(index - line)] == '\n') break;
        for (line = line ? line : 0; line < index; ++line)
            if (at[-(ptrdiff_t)(index - line)] == '#') break;
        if (line < index) continue;
        return 1;
    }
    return 0;
}

/* 1 when a body reads a variable, which is a name a dollar sign introduces */
static int reads_variable(const char *body, size_t length, const char *name)
{
    size_t used = strlen(name);
    size_t index;
    for (index = 0; index + 1 < length; ++index) {
        size_t at;
        if (body[index] != '$') continue;
        if (body[index + 1] == '{') {
            at = index + 2;
            if (at + used >= length || memcmp(body + at, name, used)) continue;
        } else {
            at = index + 1;
            if (at + used > length || memcmp(body + at, name, used)) continue;
        }
        if (at + used < length && (isalnum((unsigned char)body[at + used]) ||
                                   body[at + used] == '_'))
            continue;
        return 1;
    }
    return 0;
}

/* 1 when the ${...} body names the variable and nothing else */
static int variable(const char *body, size_t used, const char *name)
{
    return used == strlen(name) && !memcmp(body, name, used);
}

/* the identity a variable names, or NULL when it names something else */
static const char *identity_value(const struct pacscript_name *name, const char *variable_name,
                                  size_t used)
{
    if (variable(variable_name, used, "pkgname")) return name->name;
    if (variable(variable_name, used, "pkgbase")) return name->base;
    if (variable(variable_name, used, "pkgver")) return name->version;
    if (variable(variable_name, used, "pkgrel")) return name->release;
    if (variable(variable_name, used, "gives")) return name->gives;
    if (variable(variable_name, used, "epoch")) return name->epoch;
    return NULL;
}

/* a pacscript names its own identity in these variables, so a value written with
   only them can be written out; a variable the file states in an assignment of its
   own is read from there, and one that needs the Pacstall environment, or a
   parameter expansion modifier, is refused rather than half expanded */
static char *expand(const char *value, const struct shell_script *script,
                    const struct pacscript_name *name)
{
    const char *cursor = value;
    char *out = NULL;
    size_t used = 0;
    for (;;) {
        const char *open = strchr(cursor, '$');
        const char *body;
        size_t at, length, inner_length, braces;
        char *stated = NULL;
        const char *text = NULL;
        if (!open) break;
        if (open[1] != '{' && open[1] != '(' && !isalpha((unsigned char)open[1]) &&
            open[1] != '_') {
            cursor = open + 1;
            continue;
        }
        braces = open[1] == '{' || open[1] == '(';
        if (braces) {
            char stop = open[1] == '{' ? '}' : ')';
            size_t depth = 0, scan;
            for (at = 2; open[at]; ++at) {
                if (open[at] == open[1]) ++depth;
                else if (open[at] == stop) {
                    if (!depth) break;
                    --depth;
                }
            }
            if (!open[at]) {
                free(out);
                return NULL;
            }
            for (scan = 2; scan < at; ++scan)
                if (open[scan] == '/' || open[scan] == ':' || open[scan] == '#' ||
                    open[scan] == '%' || open[scan] == '?' || open[scan] == '-' ||
                    open[scan] == '+') {
                    free(out);
                    return NULL;
                }
            body = open + 2;
            inner_length = at - 2;
            length = (size_t)(open - cursor);
            at += 1;
        } else {
            /* the shell reads $name as well as ${name}, and a name runs to the
               first character that is not part of it */
            for (at = 1; open[at] && (isalnum((unsigned char)open[at]) || open[at] == '_');
                 ++at)
                ;
            body = open + 1;
            inner_length = at - 1;
            length = (size_t)(open - cursor);
        }
        text = identity_value(name, body, inner_length);
        if (!text) {
            /* a private assignment of the same file, which the shell would read
               before this value, and only when it holds a literal of its own */
            char key[256];
            if (inner_length >= sizeof key) {
                free(out);
                return NULL;
            }
            memcpy(key, body, inner_length);
            key[inner_length] = 0;
            stated = holy_shell_join(script, key);
            if (stated && (!*stated || strpbrk(stated, "$`"))) {
                free(stated);
                free(out);
                return NULL;
            }
            if (stated) text = stated;
        }
        if (!text) {
            /* an unknown variable in the unbraced form stays as it was written, and
               a braced one is a value this converter cannot reach */
            if (!braces) {
                cursor = open + 1;
                continue;
            }
            free(out);
            return NULL;
        }
        {
            size_t add = length + strlen(text) + at + 1;
            char *grown = realloc(out, used + add + 1);
            if (!grown) {
                free(stated);
                free(out);
                return NULL;
            }
            out = grown;
            memcpy(out + used, cursor, length);
            used += length;
            memcpy(out + used, text, strlen(text));
            used += strlen(text);
            out[used] = 0;
        }
        free(stated);
        /* the braced form stops after its closing brace, the plain one after the
           name, and at names the first character of either */
        cursor = open + at;
    }
    {
        size_t add = strlen(cursor);
        char *grown = realloc(out, used + add + 1);
        if (!grown) {
            free(out);
            return NULL;
        }
        out = grown;
        memcpy(out + used, cursor, add + 1);
    }
    return out;
}

/* the same expansion over a whole list, where one element that cannot be written
   out is a refusal rather than a silent drop */
static int expand_list(struct pac_list *list, const struct shell_script *script,
                       const struct pacscript_name *name)
{
    size_t index;
    for (index = 0; index < list->count; ++index) {
        char *written = expand(list->items[index].text, script, name);
        if (!written) return 0;
        free(list->items[index].text);
        list->items[index].text = written;
    }
    return 1;
}

/* the arch list mapped onto the machines Holy carries. a foreign machine is
   reported and written as it stands, since a manifest records what the upstream
   recipe said. */
static void map_arch(const struct pac_list *list, char *arch, size_t size,
                     struct recipe_note *note, int *review)
{
    size_t index;
    snprintf(arch, size, "any");
    for (index = 0; index < list->count; ++index) {
        const char *value = list->items[index].text;
        if (!strcmp(value, "any") || !strcmp(value, "all")) {
            snprintf(arch, size, "any");
        } else if (!strcmp(value, "amd64") || !strcmp(value, "x86_64")) {
            if (list->count > 1) {
                *review = 1;
                holy_note_add(note, "unknown", "arch %s is one machine of a list, so the recipe is "
                              "built for the machine the payload needs", value);
            }
            snprintf(arch, size, "x86_64");
        } else if (!strcmp(value, "i386") || !strcmp(value, "i686") ||
                   !strcmp(value, "x86")) {
            if (list->count > 1) {
                *review = 1;
                holy_note_add(note, "unknown", "arch %s is one machine of a list, so the recipe is "
                              "built for the machine the payload needs", value);
            }
            snprintf(arch, size, "i686");
        } else {
            *review = 1;
            holy_note_add(note, "unknown", "arch %s names a machine Holy does not carry, so it is "
                          "written as it stands", value);
            snprintf(arch, size, "%s", value);
        }
    }
}

/* a dependency entry is a name with an optional comparison, and a group offers
   alternatives with a pipe. a Holy record holds one name and one comparison, so
   the first alternative is carried and the rest are reported. */
static int emit_dependency(FILE *out, const char *raw, const char *kind, size_t line,
                           const char *input, struct recipe_note *note, int *review)
{
    const char *bar = strchr(raw, '|');
    if (bar) {
        char *first = holy_shell_copy(raw, (size_t)(bar - raw));
        int ok = 1;
        *review = 1;
        holy_note_add(note, "unknown", "the group %s at %s:%zu offers alternatives with a pipe, "
                      "and a Holy record cannot choose one, so the first is carried", raw, input,
                      line);
        if (first) {
            ok = emit_dependency(out, first, kind, line, input, note, review);
            free(first);
        }
        return ok;
    }
    if (!*raw) {
        *review = 1;
        holy_note_add(note, "unknown", "an empty dependency at %s:%zu is dropped", input, line);
        return 1;
    }
    if (strpbrk(raw, "$`")) {
        *review = 1;
        holy_note_add(note, "unknown", "the dependency %s at %s:%zu is written with a variable, "
                      "which this converter does not expand", raw, input, line);
        return 1;
    }
    holy_emit_dependency(out, raw, kind);
    return 1;
}

static int emit_dependencies(FILE *out, const struct pac_list *list, const char *kind,
                             const char *key, const char *input, struct recipe_note *note,
                             int *review)
{
    size_t index;
    for (index = 0; index < list->count; ++index)
        if (!emit_dependency(out, list->items[index].text, kind, list->items[index].line, input,
                             note, review))
            return 0;
    if (list->count)
        holy_note_add(note, "carried", "%s %s:%zu", key, input, list->items[0].line);
    return 1;
}

/* the prologue every phase body runs behind, rebuilt from the exported paths. dest
   is the tree the body installs into, which is the split tree in a split step. */
static int emit_prologue(FILE *out, const struct pacscript_name *name, const char *child,
                         const char *dest)
{
    fputs("pkgdir=\"", out); fputs(dest, out); fputs("\"\n", out);
    fputs("pacdir=\"$HOLY_WORK\"\nsrcdir=\"$HOLY_SRC\"\n", out);
    fputs("startdir=\"$HOLY_BUILD\"\nbuilddir=\"$HOLY_SRC\"\nTARCH=\"$HOLY_ARCH\"\n", out);
    fputs("NCPU=\"$HOLY_JOBS\"\npkgname=", out);
    holy_token(out, child ? child : name->name);
    fputs("\npkgbase=", out); holy_token(out, name->name);
    fputs("\npkgver=", out); holy_token(out, name->version);
    fputs("\npkgrel=", out); holy_token(out, name->release);
    fputs("\npacname=", out); holy_token(out, child ? child : name->name);
    fputs("\ngives=", out); holy_token(out, name->gives);
    fputc('\n', out);
    if (*name->epoch) {
        fputs("epoch=", out);
        holy_token(out, name->epoch);
        fputc('\n', out);
    }
    return fputs("cd \"$HOLY_SRC\" || exit 1\n", out) >= 0;
}

/* one source record. an entry is NAME::URL, ?NAME::URL or a plain URL, and a
   digest list runs parallel to the source list. a local file is copied next to the
   recipe; a remote source with no sha256 is reported rather than fetched. */
static int emit_sources(FILE *out, const struct pac_list *sources, const struct pac_list *sums,
                        const char *directory, const char *output,
                        const struct shell_script *script, const struct pacscript_name *name,
                        const char *input, struct recipe_note *note, int *review)
{
    size_t index;
    for (index = 0; index < sources->count; ++index) {
        const char *raw = sources->items[index].text;
        size_t line = sources->items[index].line;
        char *entry = expand(raw, script, name);
        char *url = NULL, *written = NULL;
        char *digest = NULL;
        int ok = 1;
        if (!entry) {
            *review = 1;
            holy_note_add(note, "unknown", "the source %s at %s:%zu is written with a variable "
                          "this converter does not expand, so it is reported", raw, input, line);
            continue;
        }
        if (!strncmp(entry, "git+", 4)) {
            *review = 1;
            holy_note_add(note, "unknown", "the source %s at %s:%zu is a git address, and a Holy "
                          "recipe fetches archives, so it is reported", raw, input, line);
            free(entry);
            continue;
        }
        {
            char *marker = strstr(entry, "::");
            if (marker) {
                *marker = 0;
                url = strdup(marker + 2);
                /* a leading ? says the recorded name is only a suggestion */
                if (*entry == '?') ++entry;
            } else {
                url = strdup(entry);
            }
        }
        free(entry);
        if (!url) return 0;
        if (!*url) {
            *review = 1;
            holy_note_add(note, "unknown", "an empty source at %s:%zu is dropped", input, line);
            free(url);
            continue;
        }
        if (strpbrk(url, "$`")) {
            *review = 1;
            holy_note_add(note, "unknown", "the source %s at %s:%zu still holds a variable after "
                          "expansion, so it is reported rather than fetched", url, input, line);
            free(url);
            continue;
        }
        if (index < sums->count) {
            char *value = expand(sums->items[index].text, script, name);
            if (value && *value && strcmp(value, "SKIP")) digest = value;
            else free(value);
        }
        if (strstr(url, "://")) {
            /* the fetched object is named after the file in the address, because the
               engine extracts into a directory that carries that name */
            const char *leaf = strrchr(url, '/');
            leaf = leaf ? leaf + 1 : url;
            if (strchr(leaf, '?')) {
                const char *stop = strchr(leaf, '?');
                written = holy_shell_copy(leaf, (size_t)(stop - leaf));
            } else {
                written = strdup(leaf);
            }
            if (!written) {
                free(url);
                return 0;
            }
            if (!*written) {
                *review = 1;
                holy_note_add(note, "unknown", "the source %s at %s:%zu names no file, so this "
                              "converter cannot give the fetched object a name", url, input, line);
                free(written);
                free(url);
                continue;
            }
            if (!digest) {
                *review = 1;
                holy_note_add(note, "unknown", "the source %s at %s:%zu has no sha256sums entry, "
                              "and a Holy source needs one, so it is reported rather than "
                              "fetched", url, input, line);
            } else if (!strncmp(url, "https://", 8)) {
                fputs("source ", out);
                holy_token(out, written);
                fputc(' ', out);
                holy_token(out, url);
                fputc('\n', out);
                fputs("source-sha256 ", out);
                holy_token(out, written);
                fputc(' ', out);
                holy_token(out, digest);
                fputc('\n', out);
                holy_note_add(note, "carried", "the remote source %s", written);
            } else {
                /* a Holy source is fetched over https, so a plain http address is one
                   the recipe cannot carry */
                *review = 1;
                holy_note_add(note, "unknown", "the source %s at %s:%zu is a plain http address, "
                              "and a Holy source is fetched over https, so it is reported", url,
                              input, line);
            }
        } else {
            char original[4096], copied[4096], hash[65];
            const char *file = strrchr(url, '/');
            struct stat st;
            file = file ? file + 1 : url;
            if (strpbrk(file, " \t") || !*file || !strcmp(file, ".") || !strcmp(file, "..")) {
                *review = 1;
                holy_note_add(note, "unknown", "the source %s at %s:%zu names a path this "
                              "converter cannot read", url, input, line);
                free(url);
                continue;
            }
            snprintf(original, sizeof original, "%s/%s", directory, file);
            snprintf(copied, sizeof copied, "%s/%s", output, file);
            if (stat(original, &st) || !S_ISREG(st.st_mode)) {
                *review = 1;
                holy_note_add(note, "unknown", "the source %s at %s:%zu is not beside the "
                              "pacscript, so this converter cannot hash it", file, input, line);
            } else if (!holy_copy_and_hash(original, copied, hash)) {
                ok = 0;
            } else {
                fputs("source ", out);
                holy_token(out, file);
                fputc(' ', out);
                holy_token(out, file);
                fputc('\n', out);
                fputs("source-sha256 ", out);
                holy_token(out, file);
                fputc(' ', out);
                holy_token(out, hash);
                fputc('\n', out);
                holy_note_add(note, "carried", "the local source %s", file);
                holy_note_add(note, "semantic-change", "the local source %s is copied next to the "
                              "recipe and hashed as sha256", file);
            }
        }
        free(url);
        free(written);
        free(digest);
        if (!ok) return 0;
    }
    return 1;
}

/* writes one hook script beside the recipe from the functions of one group, and
   returns the path it is installed at */
static char *emit_hook(FILE *out, const char *group, const struct pacscript_name *name,
                       const char *input, const char *output, const struct shell_script *script,
                       struct recipe_note *note, int *review)
{
    char base[600], installed[900], copied[4096];
    FILE *hook;
    size_t index, i;
    snprintf(base, sizeof base, "%s.%s", name->name, group);
    snprintf(installed, sizeof installed, "usr/share/holy/%s/%s", name->name, base);
    snprintf(copied, sizeof copied, "%s/%s", output, base);
    hook = fopen(copied, "wb");
    if (!hook) return NULL;
    fputs("# a Holy hook runs with ACTION unset, so the pre and post bodies of the\n"
          "# pacscript arrive in the order Pacstall calls them.\n", hook);
    fprintf(hook, "pkgname=%s\n", name->name);
    fprintf(hook, "pkgbase=%s\n", name->name);
    fprintf(hook, "pkgver=%s\n", name->version);
    fprintf(hook, "pkgrel=%s\n", name->release);
    fprintf(hook, "gives=%s\n", name->gives);
    for (index = 0; index < sizeof hooks / sizeof *hooks; ++index) {
        const struct shell_function *function;
        if (strcmp(hooks[index].group, group)) continue;
        function = holy_shell_function(script, hooks[index].pacscript);
        if (!function) continue;
        fprintf(hook, "# %s\n", hooks[index].pacscript);
        if (function->length &&
            fwrite(function->body, 1, function->length, hook) != function->length) {
            fclose(hook);
            return NULL;
        }
        if (function->length && function->body[function->length - 1] != '\n') fputc('\n', hook);
        holy_note_add(note, "preserved", "the %s body %s:%zu", hooks[index].pacscript, input,
                      function->first);
        if (function->conditional) {
            *review = 1;
            holy_note_add(note, "unknown", "the %s function is written inside a conditional, which "
                          "this converter does not choose between", hooks[index].pacscript);
        }
    }
    if (fclose(hook)) return NULL;
    fputs("source ", out);
    holy_token(out, base);
    fputc(' ', out);
    holy_token(out, base);
    fputc('\n', out);
    fputs(strcmp(group, "remove") ? "hook-install " : "hook-remove ", out);
    fputs("/bin/bash ", out);
    holy_token(out, installed);
    fputc('\n', out);
    holy_note_add(note, "semantic-change", "the %s functions become one %s hook at %s", group,
                  group, installed);
    for (index = 0; index < script->function_count; ++index) {
        const struct shell_function *function = &script->functions[index];
        int same = 0;
        for (i = 0; i < sizeof hooks / sizeof *hooks; ++i)
            if (!strcmp(function->name, hooks[i].pacscript) &&
                !strcmp(hooks[i].group, group))
                same = 1;
        if (!same) continue;
        for (i = 0; helpers[i]; ++i)
            if (calls_helper(function->body, function->length, helpers[i])) {
                *review = 1;
                holy_note_add(note, "unknown", "the %s body calls the %s helper, which the "
                              "Pacstall environment supplies and this converter does not",
                              function->name, helpers[i]);
            }
        for (i = 0; i < sizeof environment / sizeof *environment; ++i)
            if (reads_variable(function->body, function->length, environment[i].name)) {
                *review = 1;
                holy_note_add(note, "helper", "the %s body reads %s, which is %s", function->name,
                              environment[i].name, environment[i].why);
            }
    }
    return strdup(installed);
}

int holy_convert_pacstall(const char *input, const char *source, const char *output)
{
    struct shell_script script = {0};
    struct recipe_note note = {0};
    struct pacscript_name name;
    struct pac_list names = {0}, arches = {0}, sources = {0}, sums = {0};
    char *directory = NULL, *summary = NULL, *homepage = NULL, *joined = NULL;
    char recipe_path[4096], report_path[4096], digest[65];
    char *hook_paths[2] = {NULL, NULL};
    size_t index, i;
    FILE *out = NULL;
    int result = 1, review = 0, read_status, split = 0;

    memset(&name, 0, sizeof name);
    snprintf(name.release, sizeof name.release, "1");
    snprintf(name.arch, sizeof name.arch, "any");
    if (!input || !output || !*output) {
        fputs("usage: holypkg convert NAME.pacscript --source NAME --output NEW_DIRECTORY\n",
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
    directory = pacscript_directory(input);
    if (!directory) return 1;
    read_status = holy_shell_read(input, &script);
    if (read_status == 6) { result = 6; goto done; }
    if (read_status == 2) { result = 2; goto done; }
    if (read_status) { result = 1; goto done; }
    if (!read_list(&script, "pkgname", &names) ||
        !read_list(&script, "arch", &arches) || !read_list(&script, "source", &sources) ||
        !read_list(&script, "sha256sums", &sums)) {
        result = 1;
        goto done;
    }
    if (!names.count) {
        fputs("holypkg: a pacscript needs a pkgname\n", stderr);
        result = 2;
        goto done;
    }
    /* gives is read first, because a pacscript may write its own name with it, and
       a body installs under it */
    joined = holy_shell_join(&script, "gives");
    if (joined) {
        char *given = expand(joined, &script, &name);
        if (given && literal(given, sizeof name.gives) && is_label(given))
            snprintf(name.gives, sizeof name.gives, "%s", given);
        free(given);
        free(joined);
        joined = NULL;
    }
    /* a name written with the identity the file states for itself, which the shell
       reads before the value, is written out; one that needs the Pacstall
       environment is a computed identity and is refused */
    if (!expand_list(&names, &script, &name)) {
        fputs("holypkg: a pacscript needs a literal pkgname\n", stderr);
        result = 2;
        goto done;
    }
    /* a list of names is a split pkgbase, and the parent is named by pkgbase */
    if (names.count > 1) {
        char *base = holy_shell_join(&script, "pkgbase");
        char *written = base ? expand(base, &script, &name) : NULL;
        split = 1;
        if (!written || !literal(written, sizeof name.base) || !is_label(written)) {
            free(written);
            free(base);
            fputs("holypkg: a pacscript with a list of names needs a literal pkgbase\n", stderr);
            result = 2;
            goto done;
        }
        snprintf(name.name, sizeof name.name, "%s", written);
        snprintf(name.base, sizeof name.base, "%s", written);
        free(written);
        free(base);
        for (index = 0; index < names.count; ++index)
            if (!literal(names.items[index].text, 256) ||
                !is_label(names.items[index].text)) {
                fputs("holypkg: a pacscript needs literal names\n", stderr);
                result = 2;
                goto done;
            }
    } else if (!literal(names.items[0].text, sizeof name.name) ||
               !is_label(names.items[0].text)) {
        fputs("holypkg: a pacscript needs a literal pkgname\n", stderr);
        result = 2;
        goto done;
    } else {
        snprintf(name.name, sizeof name.name, "%s", names.items[0].text);
        snprintf(name.base, sizeof name.base, "%s", names.items[0].text);
    }
    {
        char *version = holy_shell_join(&script, "pkgver");
        char *packager = holy_shell_join(&script, "pkgrel");
        char *epoch = holy_shell_join(&script, "epoch");
        char *written = version ? expand(version, &script, &name) : NULL;
        /* the engine records a version as a label, so a distribution version that
           carries a tilde is not one a recipe can hold */
        if (!written || !literal(written, sizeof name.version) || !is_label(written)) {
            free(written);
            free(version);
            fputs("holypkg: a pacscript needs a literal pkgver\n", stderr);
            result = 2;
            goto done;
        }
        snprintf(name.version, sizeof name.version, "%s", written);
        free(written);
        free(version);
        if (packager) {
            written = expand(packager, &script, &name);
            if (!literal(written, sizeof name.release) || !is_label(written)) {
                free(written);
                free(packager);
                fputs("holypkg: a pacscript needs a literal pkgrel\n", stderr);
                result = 2;
                goto done;
            }
            snprintf(name.release, sizeof name.release, "%s", written);
            free(written);
            free(packager);
        }
        /* an epoch orders a packaging revision rather than naming a version, so
           it is preserved and dropped */
        if (epoch) {
            snprintf(name.epoch, sizeof name.epoch, "%s", epoch);
            free(epoch);
        }
    }
    /* a gives that names the package now that the name is known */
    if (!name.gives[0]) {
        joined = holy_shell_join(&script, "gives");
        if (joined) {
            char *given = expand(joined, &script, &name);
            if (given && literal(given, sizeof name.gives) && is_label(given))
                snprintf(name.gives, sizeof name.gives, "%s", given);
            free(given);
            free(joined);
            joined = NULL;
        }
    }
    if (!name.gives[0]) snprintf(name.gives, sizeof name.gives, "%s", name.name);

    if (mkdir(output, 0700) && errno != EEXIST) {
        fprintf(stderr, "holypkg: conversion directory unavailable: %s\n", output);
        result = 1;
        goto done;
    }
    snprintf(recipe_path, sizeof recipe_path, "%s/%s.recipe", output, name.name);
    snprintf(report_path, sizeof report_path, "%s/conversion", output);
    out = fopen(recipe_path, "wb");
    if (!out) {
        fprintf(stderr, "holypkg: recipe unavailable: %s\n", recipe_path);
        result = 1;
        goto done;
    }
    summary = holy_shell_join(&script, "pkgdesc");
    homepage = holy_shell_join(&script, "url");
    fputs("format holy-recipe-1\nname ", out); holy_token(out, name.name);
    fputs("\nversion ", out); holy_token(out, name.version);
    fputs("\nrelease ", out); holy_token(out, name.release);
    if (arches.count) map_arch(&arches, name.arch, sizeof name.arch, &note, &review);
    else {
        review = 1;
        holy_note_add(&note, "unknown", "the pacscript names no arch, so the recipe is built for "
                      "the machine that runs the build");
    }
    fputs("\narch ", out); holy_token(out, name.arch);
    fputs("\nlibc any\n", out);
    if (summary && *summary) {
        char *stop = strchr(summary, '\n');
        if (stop) *stop = 0;
        if (*summary) { fputs("summary ", out); holy_token(out, summary); fputc('\n', out); }
    }
    if (homepage && *homepage && *homepage != '[') {
        char *written = expand(homepage, &script, &name);
        if (written && *written && !strpbrk(written, "$`") && strstr(written, "://")) {
            fputs("homepage ", out); holy_token(out, written); fputc('\n', out);
        } else {
            review = 1;
            holy_note_add(&note, "unknown", "url %s is not a single address, so it is reported",
                          homepage);
        }
        free(written);
    }
    fputs("x-source-family pacstall\nx-converter pacstall-1\n", out);
    if (*name.epoch) {
        fputs("x-epoch ", out); holy_token(out, name.epoch); fputc('\n', out);
        holy_note_add(&note, "semantic-change", "the epoch %s is preserved and dropped, since it "
                      "orders a packaging revision and is not a version", name.epoch);
    }
    if (split) {
        fputs("x-pkgbase ", out); holy_token(out, name.base); fputc('\n', out);
        holy_note_add(&note, "semantic-change", "the list of names becomes one output each, and "
                      "pkgbase %s names the build they come from", name.base);
    }
    for (index = 0; carried[index].key; ++index) {
        struct pac_list list = {0};
        if (!read_list(&script, carried[index].key, &list)) { result = 1; goto done; }
        joined = join_list(&list);
        if (joined && *joined) {
            fputs(carried[index].record, out);
            fputc(' ', out);
            holy_token(out, joined);
            fputc('\n', out);
            holy_note_add(&note, "carried", "%s %s", carried[index].key, joined);
        }
        free(joined);
        joined = NULL;
        free_list(&list);
    }
    {
        /* the machine specific lists a pacscript may declare, and the keys that
           steer a Pacstall run */
        for (index = 0; index < script.value_count; ++index) {
            const char *key = script.values[index].name;
            int seen = 0;
            for (i = 0; known[i]; ++i)
                if (!strcmp(key, known[i])) seen = 1;
            if (seen) continue;
            for (i = 0; lists[i]; ++i) {
                size_t used = strlen(lists[i]);
                if (strncmp(key, lists[i], used) || key[used] != '_') continue;
                review = 1;
                holy_note_add(&note, "unknown", "the %s list names a machine or a distribution, "
                              "which a Holy recipe holds no list for", key);
                seen = 1;
                break;
            }
            if (seen) continue;
            review = 1;
            holy_note_add(&note, "unknown", "the %s key is a Pacstall setting this converter "
                          "reports", key);
        }
        for (index = 0; settings[index]; ++index) {
            if (!holy_shell_present(&script, settings[index])) continue;
            review = 1;
            holy_note_add(&note, "unknown", "%s steers a Pacstall run and a Holy recipe carries "
                          "it neither", settings[index]);
        }
        for (index = 0; digests[index]; ++index) {
            if (!holy_shell_present(&script, digests[index])) continue;
            review = 1;
            holy_note_add(&note, "unknown", "the %s list pins a digest a Holy source cannot use",
                          digests[index]);
        }
    }

    /* the outputs: one per name a list declares, or one for the package itself */
    if (split) {
        for (index = 0; index < names.count; ++index) {
            fputs("output ", out);
            holy_token(out, names.items[index].text);
            fputs(" runtime\n", out);
        }
    } else {
        fputs("output ", out); holy_token(out, name.name);
        fputs(" runtime\n", out);
    }

    /* the engine fetches and unpacks the recorded sources, so the extracted tree
       takes the place of the pacstall srcdir */
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
    holy_note_add(&note, "semantic-change", "the engine fetches and unpacks the recorded sources, "
                  "so the extracted tree takes the place of srcdir");

    if (sources.count) {
        if (!emit_sources(out, &sources, &sums, directory, output, &script, &name, input, &note,
                          &review)) {
            result = 1;
            goto done;
        }
        if (sums.count > sources.count) {
            review = 1;
            holy_note_add(&note, "unknown", "the sha256sums list holds %zu entries for %zu "
                          "sources, and this converter reads them in the order the sources stand",
                          sums.count, sources.count);
        }
    } else {
        review = 1;
        holy_note_add(&note, "unknown", "the pacscript names no source, so the recipe builds "
                      "nothing to package");
    }

    for (index = 0; dependencies[index].key; ++index) {
        struct pac_list list = {0};
        if (!read_list(&script, dependencies[index].key, &list)) { result = 1; goto done; }
        if (list.count) {
            if (!emit_dependencies(out, &list, dependencies[index].kind,
                                   dependencies[index].key, input, &note, &review)) {
                free_list(&list);
                result = 1;
                goto done;
            }
        }
        free_list(&list);
    }
    {
        /* a pacdep is a package of the same pacstall repository, so a Holy
           resolver has to find it in a source that has it */
        struct pac_list list = {0};
        if (!read_list(&script, PACDEPS, &list)) { result = 1; goto done; }
        for (index = 0; index < list.count; ++index) {
            if (!emit_dependency(out, list.items[index].text, "depend", list.items[index].line,
                                 input, &note, &review)) {
                free_list(&list);
                result = 1;
                goto done;
            }
            review = 1;
            holy_note_add(&note, "unknown", "the pacdep %s names a package of the same pacstall "
                          "repository, so a Holy resolver has to find it in a source that has it",
                          list.items[index].text);
        }
        if (list.count)
            holy_note_add(&note, "carried", "%s %s:%zu", PACDEPS, input, list.items[0].line);
        free_list(&list);
    }
    for (index = 0; relations[index].key; ++index) {
        struct pac_list list = {0};
        if (!read_list(&script, relations[index].key, &list)) { result = 1; goto done; }
        for (i = 0; i < list.count; ++i) {
            fputs(relations[index].record, out);
            fputc(' ', out);
            holy_token(out, list.items[i].text);
            fputc('\n', out);
        }
        if (list.count)
            holy_note_add(&note, "carried", "%s %s:%zu", relations[index].key, input,
                          list.items[0].line);
        free_list(&list);
    }
    {
        /* an optional dependency is a name with a description, and a Holy recipe
           holds no soft requirement, so it is preserved as an x- record */
        struct pac_list list = {0};
        if (!read_list(&script, "optdepends", &list)) { result = 1; goto done; }
        for (i = 0; i < list.count; ++i) {
            const char *text = list.items[i].text;
            const char *colon = strchr(text, ':');
            const char *hint = colon ? colon + 1 : NULL;
            char item[512];
            while (hint && isspace((unsigned char)*hint)) ++hint;
            snprintf(item, sizeof item, "%.*s",
                     colon ? (int)(colon - text) : (int)strlen(text), text);
            fputs("x-optdepend ", out);
            holy_token(out, item);
            if (hint && *hint) { fputc(' ', out); holy_token(out, hint); }
            fputc('\n', out);
            holy_note_add(&note, "carried", "optdepends %s:%zu", text, list.items[i].line);
        }
        free_list(&list);
    }
    {
        /* a backup entry is a configuration file apt keeps across an upgrade, and
           an r: prefix asks for the old file to be removed */
        struct pac_list list = {0};
        if (!read_list(&script, "backup", &list)) { result = 1; goto done; }
        for (i = 0; i < list.count; ++i) {
            const char *path = list.items[i].text;
            if (strpbrk(path, "$` \t") || !*path || strstr(path, "..")) {
                review = 1;
                holy_note_add(&note, "unknown", "the backup entry %s at %s:%zu is not a plain "
                              "path, so it is reported", path, input, list.items[i].line);
                continue;
            }
            if (!strncmp(path, "r:", 2)) {
                const char *kept = path + 2;
                fputs("config ", out);
                holy_token(out, *kept == '/' ? kept + 1 : kept);
                fputs(" mutable\n", out);
                review = 1;
                holy_note_add(&note, "unknown", "the backup entry %s asks for the old file to be "
                              "removed on an upgrade, and a config record only marks a file as "
                              "mutable", path);
                continue;
            }
            fputs("config ", out);
            holy_token(out, *path == '/' ? path + 1 : path);
            fputc('\n', out);
            holy_note_add(&note, "carried", "backup %s:%zu", path, list.items[i].line);
        }
        free_list(&list);
    }

    /* the phase functions, each behind the prologue that rebuilds the Pacstall
       variables the body reads */
    for (index = 0; index < sizeof phases / sizeof *phases; ++index) {
        const struct shell_function *function =
            holy_shell_function(&script, phases[index].pacscript);
        if (!function) continue;
        if (split && !strcmp(phases[index].pacscript, "package")) {
            review = 1;
            holy_note_add(&note, "unknown", "the pacscript defines package beside the "
                          "package_CHILD functions of a split pkgbase, and a Holy recipe gives each "
                          "output one split step");
            continue;
        }
        if (function->conditional) {
            review = 1;
            holy_note_add(&note, "unknown", "the %s function is written inside a conditional, which "
                          "this converter does not choose between", phases[index].pacscript);
        }
        fprintf(out, "step %s /bin/sh <<STEP\n", phases[index].phase);
        fputs("# the Pacstall variables this body reads, rebuilt from the exported Holy paths\n",
              out);
        if (!emit_prologue(out, &name, NULL, "$HOLY_DEST")) { result = 1; goto done; }
        if (function->length &&
            fwrite(function->body, 1, function->length, out) != function->length) {
            result = 1;
            goto done;
        }
        if (function->length && function->body[function->length - 1] != '\n') fputc('\n', out);
        fputs("STEP\n", out);
        holy_note_add(&note, "preserved", "the %s body %s:%zu", phases[index].pacscript, input,
                      function->first);
        for (i = 0; helpers[i]; ++i)
            if (calls_helper(function->body, function->length, helpers[i])) {
                review = 1;
                holy_note_add(&note, "unknown", "the %s body calls the %s helper, which the "
                              "Pacstall environment supplies and this converter does not",
                              phases[index].pacscript, helpers[i]);
            }
        for (i = 0; i < sizeof environment / sizeof *environment; ++i)
            if (reads_variable(function->body, function->length, environment[i].name)) {
                review = 1;
                holy_note_add(&note, "helper", "the %s body reads %s, which is %s",
                              phases[index].pacscript, environment[i].name, environment[i].why);
            }
    }
    if (split) {
        /* each package_CHILD function is a file list of its own, and a Holy recipe
           gives it a staging tree */
        for (index = 0; index < names.count; ++index) {
            char function_name[300];
            const struct shell_function *function;
            snprintf(function_name, sizeof function_name, "package_%s",
                     names.items[index].text);
            function = holy_shell_function(&script, function_name);
            if (!function) {
                review = 1;
                holy_note_add(&note, "unknown", "the split output %s has no %s function, and a "
                              "Holy recipe gives each output one split step",
                              names.items[index].text, function_name);
                continue;
            }
            fprintf(out, "split-step \"%s\" split /bin/sh <<STEP\n", names.items[index].text);
            fputs("# the Pacstall variables this body reads, rebuilt from the exported Holy paths\n",
                  out);
            if (!emit_prologue(out, &name, names.items[index].text, "$HOLY_SPLIT_DEST")) {
                result = 1;
                goto done;
            }
            if (function->length &&
                fwrite(function->body, 1, function->length, out) != function->length) {
                result = 1;
                goto done;
            }
            if (function->length && function->body[function->length - 1] != '\n') fputc('\n', out);
            fputs("STEP\n", out);
            holy_note_add(&note, "preserved", "the %s body %s:%zu", function_name, input,
                          function->first);
            for (i = 0; helpers[i]; ++i)
                if (calls_helper(function->body, function->length, helpers[i])) {
                    review = 1;
                    holy_note_add(&note, "unknown", "the %s body calls the %s helper, which the "
                                  "Pacstall environment supplies and this converter does not",
                                  function_name, helpers[i]);
                }
            for (i = 0; i < sizeof environment / sizeof *environment; ++i)
                if (reads_variable(function->body, function->length, environment[i].name)) {
                    review = 1;
                    holy_note_add(&note, "helper", "the %s body reads %s, which is %s", function_name,
                                  environment[i].name, environment[i].why);
                }
        }
    }

    /* the install time functions become one hook per group, and the script travels
       with the recipe so that the payload carries it */
    for (i = 0; i < sizeof hooks / sizeof *hooks; ++i) {
        size_t group = !strcmp(hooks[i].group, "install") ? 0 : 1;
        if (hook_paths[group]) continue;
        if (!holy_shell_function(&script, hooks[i].pacscript)) continue;
        hook_paths[group] = emit_hook(out, hooks[i].group, &name, input, output, &script, &note,
                                      &review);
        if (!hook_paths[group]) { result = 1; goto done; }
    }
    for (i = 0; i < 2; ++i) {
        char *slash;
        if (!hook_paths[i]) continue;
        slash = strrchr(hook_paths[i], '/');
        if (!slash) { result = 1; goto done; }
        *slash = 0;
        fprintf(out, "step package /bin/sh <<HOOKS\n"
                     "mkdir -p \"$HOLY_DEST/%s\"\n"
                     "cp \"$HOLY_SRC/%s.%s\" \"$HOLY_DEST/%s\"\n"
                     "HOOKS\n", hook_paths[i], name.name, i ? "remove" : "install",
                hook_paths[i]);
    }

    /* the conditional blocks a pacscript uses to choose between builds, and the
       statements that no reader of a pacscript can interpret */
    for (index = 0; index < script.condition_count; ++index) {
        const char *text = script.conditions[index].text;
        const char *newline = strchr(text, '\n');
        char *line = holy_shell_copy(text, newline ? (size_t)(newline - text) : strlen(text));
        review = 1;
        if (script.conditions[index].unreadable)
            holy_note_add(&note, "unknown", "unreadable statement %s:%zu %s", input,
                          script.conditions[index].line, line ? line : "");
        else
            holy_note_add(&note, "unknown", "conditional block %s:%zu %s", input,
                          script.conditions[index].line, line ? line : "");
        free(line);
    }
    for (index = 0; index < script.value_count; ++index) {
        if (!script.values[index].conditional) continue;
        review = 1;
        holy_note_add(&note, "unknown", "conditional assignment %s %s:%zu",
                      script.values[index].name, input, script.values[index].line);
    }

    if (fclose(out)) { out = NULL; result = 1; goto done; }
    out = NULL;
    out = fopen(report_path, "wb");
    if (!out) {
        fprintf(stderr, "holypkg: report unavailable: %s\n", report_path);
        result = 1;
        goto done;
    }
    fputs("format holy-recipe-conversion-1\nconverter pacstall-1\n", out);
    fputs("source-name ", out); holy_token(out, source); fputc('\n', out);
    {
        const char *at = strrchr(input, '/');
        fputs("source-file ", out); holy_token(out, at ? at + 1 : input); fputc('\n', out);
    }
    if (holy_hash_file(input, digest)) {
        fputs("source-sha256 ", out); holy_token(out, digest); fputc('\n', out);
    }
    fputs("pkgbase ", out); holy_token(out, name.name); fputc('\n', out);
    fputs("version ", out); holy_token(out, name.version); fputc('\n', out);
    fputs("release ", out); holy_token(out, name.release); fputc('\n', out);
    fputs("arch ", out); holy_token(out, name.arch); fputc('\n', out);
    {
        /* one record holds one value, so the recipe file name is one token */
        char named[300];
        snprintf(named, sizeof named, "%s.recipe", name.name);
        fputs("recipe ", out);
        holy_token(out, named);
        fputc('\n', out);
    }
    fprintf(out, "status %s\n", review ? "review-required" : "native");
    for (index = 0; index < note.count; ++index) fprintf(out, "%s\n", note.lines[index]);
    fprintf(out, "summary carried %zu preserved %zu helper %zu unknown %zu changes %zu\n",
            note.carried, note.preserved, note.helper, note.unknown, note.changes);
    if (fclose(out)) { out = NULL; result = 1; goto done; }
    out = NULL;
    result = review ? 3 : 0;
    printf("converted %s status %s\n", name.name, review ? "review-required" : "native");
    printf("recipe %s\nreport %s\n", recipe_path, report_path);
    if (review) fputs("holypkg: the converted recipe needs review before its first build\n",
                      stderr);
done:
    if (out) fclose(out);
    for (i = 0; i < 2; ++i) free(hook_paths[i]);
    free_list(&names);
    free_list(&arches);
    free_list(&sources);
    free_list(&sums);
    free(summary);
    free(homepage);
    free(directory);
    holy_shell_free(&script);
    holy_note_free(&note);
    return result;
}
