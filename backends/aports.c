/* APKBUILD to holy-recipe(5) conversion; see man/holy-recipe.5 and man/holypkg.8.
   the file is read as text. no part of it is executed by the converter.
   the abuild phase bodies keep their original shell; a step prologue rebuilds the
   abuild variables from the exported Holy paths. */
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1
#include "aports.h"
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

/* a byte search over a template body; the bodies are short and few */
static const char *find_bytes(const char *body, size_t length, const char *needle)
{
    size_t size = strlen(needle), index;
    if (!size || size > length) return NULL;
    for (index = 0; index + size <= length; ++index)
        if (!memcmp(body + index, needle, size)) return body + index;
    return NULL;
}

/* the abuild split functions that move files without one being written */
static const struct {
    const char *name;
    const char *files;
} default_splits[] = {
    { "dev", "headers, static archives, pkg-config files and unversioned .so files" },
    { "doc", "usr/share/{doc,man,info,html,sgml,licenses,gtk-doc,ri,help}" },
    { "static", "static archives from lib and usr/lib" },
    { "openrc", "etc/conf.d and etc/init.d" },
    { "libs", "shared objects without their unversioned symlink" }
};

static const char *default_split_help(const char *name)
{
    size_t index;
    for (index = 0; index < sizeof default_splits / sizeof *default_splits; ++index)
        if (!strcmp(default_splits[index].name, name)) return default_splits[index].files;
    return NULL;
}

struct apk_source {
    char name[512];
    char url[1024];
    char declared[512];
    size_t line;
};

/* the helpers and variables a body uses that this converter cannot supply. a split
   step does carry $subpkgdir, so that name is only unresolved in the main package. */
static void report_unknowns(const char *body, size_t length, struct recipe_note *note, int *review,
                            const char *where, int split)
{
    static const struct {
        const char *token;
        const char *text;
    } unresolved[] = {
        { "default_dev", "helper default_dev is not carried" },
        { "default_doc", "helper default_doc is not carried" },
        { "default_static", "helper default_static is not carried" },
        { "default_openrc", "helper default_openrc is not carried" },
        { "default_unpack", "helper default_unpack is not carried" },
        { "default_prepare", "helper default_prepare is not carried" },
        { "default_check", "helper default_check is not carried" },
        { "default_python", "helper default_python is not carried" },
        { "default_luarocks", "helper default_luarocks is not carried" },
        { "default_cargo", "helper default_cargo is not carried" },
        { "default_pie", "helper default_pie is not carried" },
        { "default_perl", "helper default_perl is not carried" },
        { "default_ruby", "helper default_ruby is not carried" },
        { "default_meson", "helper default_meson is not carried" },
        { "lang6to4", "helper lang6to4 is not carried" },
        { "fetch", "helper fetch is not carried" },
        { "verify", "helper verify is not carried" },
        { "unpack", "helper unpack is not carried" },
        { "mkusers", "helper mkusers is not carried" },
        { "snapshot", "helper snapshot is not carried" },
        { "update_abuild_depends", "helper update_abuild_depends is not carried" },
        { "abuild_depends", "helper abuild_depends is not carried" },
        { "run_rc_service", "helper run_rc_service is not carried" },
        { "scanelf", "helper scanelf is not carried" },
        { "abuild-checksums", "helper abuild-checksums is not carried" },
        { "abuild-tar", "helper abuild-tar is not carried" },
        { "$CBUILD", "build architecture is not carried" },
        { "$CHOST", "host architecture is not carried" },
        { "$CTARGET", "target architecture is not carried" },
        { "$CARCH", "architecture is not carried" },
        { "$CROSS_COMPILE", "cross compilation is not carried" },
        { "$CBUILD_ROOT", "cross build root is not carried" },
        { "$CTARGET_ROOT", "cross target root is not carried" },
        { "$CHOST_ROOT", "cross host root is not carried" },
        { "$repo", "abuild repository scope is not carried" },
        { "$GIT_COMMIT", "abuild git state is not carried" },
        { "$abuild_basename", "abuild repository scope is not carried" },
        { "$REPODEST", "abuild repository scope is not carried" },
        { "$srcdest", "abuild distfile cache is not carried" },
        { "$tmpdir", "abuild working directory is not carried" },
        { "$pkgbasedir", "abuild working directory is not carried" },
        { "$subpkgdir", "the subpackage staging tree is not carried inside the main package" },
        { "$startdir", "abuild source directory is not carried" }
    };
    size_t index;
    for (index = 0; index < sizeof unresolved / sizeof *unresolved; ++index) {
        if (split && !strcmp(unresolved[index].token, "$subpkgdir")) continue;
        if (find_bytes(body, length, unresolved[index].token)) {
            holy_note_add(note, "unknown", "%s in %s", unresolved[index].text, where);
            *review = 1;
        }
    }
}

/* the abuild variables a phase body may read, rebuilt from the exported paths */
static char *prologue(const struct shell_script *pkg, const char *name, const char *version,
                      const char *release, const char *builddir, const char *pkgdir)
{
    static const char *const carried[] = {
        "patch_args", "conflicts", "replaces", "provides", "install_if", "triggers",
        "pkgusers", "pkggroups", "provider_priority", "replaces_priority", "options",
        "makedepends", "makedepends_build", "makedepends_host", "checkdepends", NULL
    };
    static const struct { const char *key; const char *text; } abuild[] = {
        { "CFLAGS", "\"${CFLAGS:--Os -fomit-frame-pointer}\"" },
        { "CXXFLAGS", "\"${CXXFLAGS:-$CFLAGS}\"" },
        { "CPPFLAGS", "\"${CPPFLAGS:-}\"" },
        { "LDFLAGS", "\"${LDFLAGS:--Wl,-z,relro}\"" },
        { "JOBS", "\"$HOLY_JOBS\"" },
        { "MAKEFLAGS", "\"-j$HOLY_JOBS\"" },
        { "SAMUFLAGS", "\"-j$HOLY_JOBS\"" },
        { "NINJAFLAGS", "\"-j$HOLY_JOBS\"" },
        { "CARGO_BUILD_JOBS", "\"$HOLY_JOBS\"" },
        { "CMAKE_BUILD_PARALLEL_LEVEL", "\"$HOLY_JOBS\"" },
        { "CTEST_PARALLEL_LEVEL", "\"$HOLY_JOBS\"" },
        { "DISTDIR", "\"$HOLY_WORK\"" },
        { "PKGDIR", "\"$HOLY_DEST\"" },
        { "GOTMPDIR", "\"$HOLY_BUILD/gotmp\"" },
        { "HOME", "\"$HOLY_WORK/home\"" },
        { "TMPDIR", "\"$HOLY_WORK/tmp\"" }
    };
    char *text = NULL;
    size_t used = 0, index;
    FILE *out = open_memstream(&text, &used);
    if (!out) return NULL;
    fputs("# abuild variables rebuilt from the exported Holy paths\n", out);
    fprintf(out, "pkgname=%s\npkgver=%s\npkgrel=%s\npkgver_real=\"%s-r%s\"\n", name, version,
            release, version, release);
    fprintf(out, "srcdir=\"$HOLY_SRC\"\nstartdir=\"$HOLY_WORK\"\nbuilddir=%s\n", builddir);
    /* DESTDIR is the tree being filled, so a split function fills $HOLY_SPLIT_DEST
       while $pkgdir keeps naming the main tree it moves files out of */
    fprintf(out, "DESTDIR=%s\n", pkgdir);
    fprintf(out, "PKGDESTDIR=%s\n", pkgdir);
    fputs("pkgdir=\"$HOLY_DEST\"\nsubpkgdir=\"$HOLY_SPLIT_DEST\"\n", out);
    for (index = 0; index < sizeof abuild / sizeof *abuild; ++index)
        fprintf(out, "%s=%s\n", abuild[index].key, abuild[index].text);
    for (index = 0; carried[index]; ++index) {
        char *value;
        if (!holy_shell_present(pkg, carried[index])) continue;
        value = holy_shell_join(pkg, carried[index]);
        if (!value || !*value) { free(value); continue; }
        fprintf(out, "%s=\"%s\"\n", carried[index], value);
        free(value);
    }
    fclose(out);
    return text;
}

/* the identity variables an entry may name; the rest stay unresolved. a source entry
   expands $pkgver to the bare upstream version, a dependency to version-rrelease. */
static const char *identity_value(const char *word, const char *name, const char *version,
                                  const char *release, int apk_version, char *out, size_t size)
{
    if (!strcmp(word, "pkgname")) snprintf(out, size, "%s", name);
    else if (!strcmp(word, "pkgver"))
        snprintf(out, size, apk_version ? "%s-r%s" : "%s", version, release);
    else if (!strcmp(word, "pkgrel")) snprintf(out, size, "%s", release);
    else return NULL;
    return out;
}

static int append_text(char **out, size_t *used, size_t *capacity, const char *text, size_t length)
{
    while (*used + length + 1 > *capacity) {
        char *grown = realloc(*out, *capacity * 2);
        if (!grown) return 0;
        *capacity *= 2;
        *out = grown;
    }
    memcpy(*out + *used, text, length);
    *used += length;
    (*out)[*used] = 0;
    return 1;
}

static int is_word_char(char c)
{
    return isalnum((unsigned char)c) || c == '_';
}

/* expands pkgname, pkgver and pkgrel in one entry and flags every other reference */
static char *expand_names(const char *value, const char *name, const char *version,
                          const char *release, int apk_version, int *unknown)
{
    size_t used = 0, capacity = strlen(value) + 256, i = 0;
    char *out = malloc(capacity);
    if (!out) return NULL;
    out[0] = 0;
    while (value[i]) {
        char word[128], replacement[1024];
        size_t length = 0, start;
        const char *resolved;
        if (value[i] != '$' || i + 1 >= strlen(value)) {
            if (!append_text(&out, &used, &capacity, value + i, 1)) goto failed;
            ++i;
            continue;
        }
        if (value[i + 1] == '{') {
            start = i + 2;
            while (value[start] && value[start] != '}' && length + 1 < sizeof word)
                word[length++] = value[start++];
            if (value[start] != '}') { if (unknown) *unknown = 1; goto kept; }
            word[length] = 0;
            resolved = identity_value(word, name, version, release, apk_version, replacement,
                                      sizeof replacement);
            if (!resolved) { if (unknown) *unknown = 1; goto kept; }
            if (!append_text(&out, &used, &capacity, resolved, strlen(resolved))) goto failed;
            i = start + 1;
            continue;
        }
        if (!is_word_char(value[i + 1])) {
            if (!append_text(&out, &used, &capacity, value + i, 1)) goto failed;
            ++i;
            continue;
        }
        start = i + 1;
        while (value[start] && is_word_char(value[start]) && length + 1 < sizeof word)
            word[length++] = value[start++];
        word[length] = 0;
        resolved = identity_value(word, name, version, release, apk_version, replacement,
                                  sizeof replacement);
        if (!resolved) { if (unknown) *unknown = 1; goto kept; }
        if (!append_text(&out, &used, &capacity, resolved, strlen(resolved))) goto failed;
        i = start;
        continue;
kept:
        /* a reference this converter does not know keeps its text and needs review */
        if (!append_text(&out, &used, &capacity, value + i, strlen(value + i))) goto failed;
        return out;
    }
    return out;
failed:
    free(out);
    return NULL;
}

static int is_digest(const char *value)
{
    size_t index;
    for (index = 0; index < 64; ++index)
        if (!isxdigit((unsigned char)value[index])) return 0;
    return !value[64];
}

/* the declared sha256 for one source name, or NULL when the file has none */
static char *declared_digest(const struct shell_script *pkg, const char *name)
{
    char *raw = holy_shell_join(pkg, "sha256sums");
    size_t count = 0, index;
    char **items = raw ? holy_shell_words(raw, &count) : NULL;
    char *found = NULL;
    for (index = 0; items && index + 1 < count; index += 2)
        if (!strcmp(items[index + 1], name) && is_digest(items[index])) {
            found = strdup(items[index]);
            break;
        }
    holy_shell_words_free(items);
    free(raw);
    return found;
}

/* one source record: a local file travels with the recipe, a remote one is reported */
static int emit_source(FILE *out, const struct shell_script *pkg, const struct apk_source *source,
                       const char *directory, const char *output, struct recipe_note *note,
                       int *review)
{
    char original[4096], copied[4096], local_hash[65];
    struct stat st;
    char *declared = declared_digest(pkg, source->name);
    int local = !strstr(source->url, "://");
    if (local) {
        snprintf(original, sizeof original, "%s/%s", directory, source->url);
        snprintf(copied, sizeof copied, "%s/%s", output, source->name);
        if (stat(original, &st) || !S_ISREG(st.st_mode)) {
            *review = 1;
            holy_note_add(note, "unknown", "source %s is not next to the APKBUILD APKBUILD:%zu",
                          source->name, source->line);
            free(declared);
            return 1;
        }
        if (!holy_copy_and_hash(original, copied, local_hash)) { free(declared); return 0; }
        if (declared && strcmp(declared, local_hash)) {
            *review = 1;
            holy_note_add(note, "unknown", "source %s does not match its declared sha256",
                          source->name);
            free(declared);
            return 0;
        }
        fputs("source ", out);
        holy_token(out, source->name);
        fputc(' ', out);
        holy_token(out, source->name);
        fputc('\n', out);
        fputs("source-sha256 ", out);
        holy_token(out, source->name);
        fputc(' ', out);
        holy_token(out, local_hash);
        fputc('\n', out);
        holy_note_add(note, "carried", "source %s APKBUILD:%zu", source->name, source->line);
        holy_note_add(note, "semantic-change",
                      "local source %s copied next to the recipe and hashed as sha256",
                      source->name);
        free(declared);
        return 1;
    }
    *review = 1;
    holy_note_add(note, "unknown", "source %s APKBUILD:%zu", source->name, source->line);
    if (!declared) {
        holy_note_add(note, "unknown", "source %s has no sha256 digest", source->name);
        return 1;
    }
    fputs("source ", out);
    holy_token(out, source->name);
    fputc(' ', out);
    holy_token(out, source->url);
    fputc('\n', out);
    fputs("source-sha256 ", out);
    holy_token(out, source->name);
    fputc(' ', out);
    holy_token(out, declared);
    fputc('\n', out);
    holy_note_add(note, "carried", "source %s APKBUILD:%zu", source->name, source->line);
    free(declared);
    return 1;
}

/* one source entry: an optional filename:: prefix, then the URL */
static int read_source(const char *entry, const char *name, const char *version,
                       const char *release, struct apk_source *source, int *unknown)
{
    const char *url = entry;
    const char *split = strstr(entry, "::");
    const char *base;
    size_t size;
    memset(source, 0, sizeof *source);
    if (split) {
        url = split + 2;
        if ((size_t)(split - entry) >= sizeof source->name) return 0;
        memcpy(source->name, entry, (size_t)(split - entry));
        source->name[split - entry] = 0;
        if (strlen(url) >= sizeof source->url) return 0;
        snprintf(source->url, sizeof source->url, "%s", url);
        return 1;
    }
    {
        char *expanded = expand_names(url, name, version, release, 0, unknown);
        if (!expanded) return 0;
        if (strlen(expanded) >= sizeof source->url) { free(expanded); return 0; }
        snprintf(source->url, sizeof source->url, "%s", expanded);
        free(expanded);
    }
    base = strrchr(source->url, '/');
    base = base ? base + 1 : source->url;
    size = strlen(base);
    if (!size || size >= sizeof source->name || !strcmp(base, ".") || !strcmp(base, ".."))
        return 0;
    memcpy(source->name, base, size + 1);
    return 1;
}

/* the arch field names a machine; anything else needs review */
static void map_arch(const char *value, char *arch, size_t size, struct recipe_note *note,
                     int *review)
{
    size_t count = 0, index;
    char **items = holy_shell_words(value, &count);
    int x86_64 = 0, i686 = 0, noarch = 0, other = 0, negated = 0;
    snprintf(arch, size, "noarch");
    for (index = 0; items && index < count; ++index) {
        const char *item = items[index];
        if (item[0] == '!') { negated = 1; continue; }
        if (!strcmp(item, "all") || !strcmp(item, "noarch")) noarch = 1;
        else if (!strcmp(item, "x86_64")) x86_64 = 1;
        else if (!strcmp(item, "x86")) i686 = 1;
        else other = 1;
    }
    holy_shell_words_free(items);
    if (negated) {
        *review = 1;
        holy_note_add(note, "preserved", "arch %s", value);
    }
    if (other) {
        *review = 1;
        holy_note_add(note, "unknown", "arch %s names a machine Holy does not carry", value);
    }
    if (x86_64) snprintf(arch, size, "x86_64");
    else if (i686 && !noarch && !other) snprintf(arch, size, "i686");
    else if (noarch) snprintf(arch, size, "noarch");
}

/* writes one depend record; a conflict or a provided capability is not a requirement */
static int emit_one_dependency(FILE *out, const char *raw, const char *kind,
                               struct recipe_note *note, int *review, const char *where)
{
    if (raw[0] == '!') {
        fputs("x-conflicts ", out);
        holy_token(out, raw + 1);
        fputc('\n', out);
        *review = 1;
        holy_note_add(note, "preserved", "conflict %s %s", raw + 1, where);
        return 1;
    }
    if (!strncmp(raw, "so:", 3) || !strncmp(raw, "cmd:", 4)) {
        *review = 1;
        holy_note_add(note, "unknown", "dependency %s uses a resolver-specific prefix", raw);
        return 0;
    }
    holy_emit_dependency(out, raw, kind);
    return 1;
}

struct apk_split {
    char name[512];
    char function[256];
    struct shell_function body;
    int has_body;
};

/* the split body is copied so the script keeps ownership of its own text */
static int copy_split_body(const struct shell_function *source, struct shell_function *target)
{
    target->name = strdup(source->name);
    target->body = holy_shell_copy(source->body, source->length);
    target->length = source->length;
    target->first = source->first;
    target->last = source->last;
    target->conditional = source->conditional;
    if (!target->name || !target->body) {
        holy_shell_function_free(target);
        return 0;
    }
    return 1;
}

static void split_free(struct apk_split *split)
{
    if (split->has_body) holy_shell_function_free(&split->body);
    split->has_body = 0;
}

static int write_body(FILE *out, const char *body)
{
    size_t length = strlen(body);
    if (!length) return 1;
    if (fwrite(body, 1, length, out) != length) return 0;
    if (body[length - 1] != '\n' && fputc('\n', out) == EOF) return 0;
    return 1;
}

static int emit_phase_step(FILE *out, const char *phase, const char *prefix, const char *body)
{
    if (fprintf(out, "step %s /bin/sh <<STEP\n", phase) < 0) return 0;
    if (fputs(prefix, out) < 0) return 0;
    /* abuild runs a phase in builddir, so the step has to move there first */
    if (fputs("cd \"$builddir\"\n", out) < 0) return 0;
    if (!write_body(out, body)) return 0;
    return fprintf(out, "STEP\n") >= 0;
}

static int emit_split_step(FILE *out, const struct apk_split *split, const char *prefix)
{
    if (fprintf(out, "split-step %s split /bin/sh <<SPLIT\n", split->name) < 0) return 0;
    if (fputs(prefix, out) < 0) return 0;
    if (fputs("cd \"$builddir\"\n", out) < 0) return 0;
    if (split->has_body && !write_body(out, split->body.body)) return 0;
    return fprintf(out, "SPLIT\n") >= 0;
}

int holy_convert_aports(const char *input, const char *source, const char *output)
{
    struct shell_script pkg;
    struct recipe_note note;
    struct apk_source *sources = NULL;
    struct apk_split splits[24];
    char name[512] = {0}, version[512] = {0}, release[64] = {0}, arch[64] = "noarch";
    char *summary = NULL, *homepage = NULL, *license = NULL, *maintainer = NULL;
    char *builddir = NULL;
    char recipe_path[4096], report_path[4096], target[4096];
    char hash[65] = {0};
    FILE *out = NULL;
    size_t source_count = 0, split_count = 0, index, k;
    int result = 1, review = 0, i, wrote = 1;

    memset(&pkg, 0, sizeof pkg);
    memset(&note, 0, sizeof note);
    memset(splits, 0, sizeof splits);

    if (!input || !output || !*output) {
        fputs("usage: holypkg convert APKBUILD --source NAME --output NEW_DIRECTORY\n", stderr);
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
    result = holy_shell_read(input, &pkg);
    if (result) return result;

    {
        char *declared = holy_shell_join(&pkg, "pkgname");
        char *given_version = holy_shell_join(&pkg, "pkgver");
        char *given_release = holy_shell_join(&pkg, "pkgrel");
        if (!declared || !given_version || !given_release) {
            fputs("holypkg: APKBUILD: pkgname, pkgver and pkgrel are required\n", stderr);
            result = 2;
            goto done;
        }
        if (strpbrk(declared, "$`") || strpbrk(given_version, "$`") ||
            strpbrk(given_release, "$`") || strlen(declared) > 480 ||
            strlen(given_version) > 480 || strlen(given_release) > 60) {
            fputs("holypkg: APKBUILD: identity must be literal and short\n", stderr);
            result = 2;
            goto done;
        }
        snprintf(name, sizeof name, "%s", declared);
        snprintf(version, sizeof version, "%s", given_version);
        snprintf(release, sizeof release, "%s", given_release);
        free(declared);
        free(given_version);
        free(given_release);
    }
    summary = holy_shell_join(&pkg, "pkgdesc");
    homepage = holy_shell_join(&pkg, "url");
    license = holy_shell_join(&pkg, "license");
    maintainer = holy_shell_join(&pkg, "maintainer");
    {
        char *arches = holy_shell_join(&pkg, "arch");
        if (arches) map_arch(arches, arch, sizeof arch, &note, &review);
        else {
            review = 1;
            holy_note_add(&note, "unknown", "arch is unset, the payload decides");
        }
        free(arches);
    }
    if (pkg.condition_count) {
        for (k = 0; k < pkg.condition_count; ++k) {
            review = 1;
            if (pkg.conditions[k].unreadable)
                holy_note_add(&note, "unknown", "unreadable statement APKBUILD:%zu %s",
                              pkg.conditions[k].line, pkg.conditions[k].text);
            else
                holy_note_add(&note, "unknown", "conditional block APKBUILD:%zu %s",
                              pkg.conditions[k].line, pkg.conditions[k].text);
        }
    }
    for (k = 0; k < pkg.value_count; ++k) {
        if (!pkg.values[k].conditional) continue;
        review = 1;
        holy_note_add(&note, "unknown", "conditional assignment %s APKBUILD:%zu",
                      pkg.values[k].name, pkg.values[k].line);
    }
    holy_note_add(&note, "carried", "name APKBUILD:%zu", holy_shell_line(&pkg, "pkgname"));
    holy_note_add(&note, "carried", "version APKBUILD:%zu", holy_shell_line(&pkg, "pkgver"));
    holy_note_add(&note, "carried", "release APKBUILD:%zu", holy_shell_line(&pkg, "pkgrel"));
    if (summary && *summary)
        holy_note_add(&note, "carried", "pkgdesc APKBUILD:%zu", holy_shell_line(&pkg, "pkgdesc"));
    if (homepage && *homepage)
        holy_note_add(&note, "carried", "url APKBUILD:%zu", holy_shell_line(&pkg, "url"));
    if (license && *license)
        holy_note_add(&note, "carried", "license APKBUILD:%zu", holy_shell_line(&pkg, "license"));
    if (maintainer && *maintainer)
        holy_note_add(&note, "carried", "maintainer APKBUILD:%zu",
                      holy_shell_line(&pkg, "maintainer"));

    /* the source list carries patches, install scripts and conf files as well */
    {
        char *entries = holy_shell_join(&pkg, "source");
        size_t count = 0, item;
        char **items = entries ? holy_shell_words(entries, &count) : NULL;
        size_t entry_count = 0;
        for (item = 0; items && item < count; ++item) ++entry_count;
        if (entry_count) {
            sources = calloc(entry_count, sizeof *sources);
            if (!sources) { wrote = 0; item = count; }
            for (item = 0; sources && item < count; ++item) {
                int unknown = 0;
                if (!read_source(items[item], name, version, release, &sources[source_count],
                                 &unknown)) {
                    review = 1;
                    holy_note_add(&note, "unknown", "source %s", items[item]);
                    continue;
                }
                sources[source_count].line = holy_shell_line(&pkg, "source");
                if (unknown) {
                    review = 1;
                    holy_note_add(&note, "unknown", "source %s uses an expansion this converter "
                                  "does not know", items[item]);
                    continue;
                }
                ++source_count;
            }
        }
        holy_shell_words_free(items);
        free(entries);
    }

    if (mkdir(output, 0700) && errno != EEXIST) {
        fprintf(stderr, "holypkg: conversion directory unavailable: %s\n", output);
        result = 1;
        goto done;
    }
    snprintf(target, sizeof target, "%s/APKBUILD", output);
    if (!holy_copy_and_hash(input, target, hash)) {
        fputs("holypkg: APKBUILD copy failed\n", stderr);
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
    fputs("x-source-family apk\nx-converter aports-1\n", out);
    if (maintainer && *maintainer) {
        fputs("x-maintainer ", out); holy_token(out, maintainer); fputc('\n', out);
    }
    {
        static const char *const kept[] = {
            "options", "provider_priority", "replaces_priority", "triggers", "install_if",
            "pkggroups", "pkgusers", "giturl", "pcprefix", "sonameprefix",
            "langdir", "soname", "provides", "replaces", NULL
        };
        for (index = 0; kept[index]; ++index) {
            char *value = holy_shell_join(&pkg, kept[index]);
            if (!value || !*value) { free(value); continue; }
            fputs("x-", out);
            fputs(kept[index], out);
            fputc(' ', out);
            holy_token(out, value);
            fputc('\n', out);
            review = 1;
            holy_note_add(&note, "preserved", "%s APKBUILD:%zu", kept[index],
                          holy_shell_line(&pkg, kept[index]));
            free(value);
        }
    }

    /* the local source entries travel with the recipe so the build needs no network */
    for (k = 0; k < source_count; ++k) {
        if (!emit_source(out, &pkg, &sources[k], pkg.directory, output, &note, &review)) {
            wrote = 0;
            break;
        }
    }
    if (!wrote) { result = 1; goto done; }
    {
        char *sha512 = holy_shell_join(&pkg, "sha512sums");
        if (sha512 && *sha512) {
            review = 1;
            holy_note_add(&note, "unknown", "sha512sums pins a digest a Holy source cannot use, "
                          "the sha256 of each file is taken from a local copy instead");
        }
        free(sha512);
    }

    /* dependency lists; the per subpackage ones belong to an output Holy cannot split */
    {
        static const char *const build_lists[] = {
            "makedepends_build", "makedepends_host", "makedepends", "checkdepends", NULL
        };
        static const char *const split_depends[] = {
            "depends_dev", "depends_doc", "depends_openrc", "depends_libs", "depends_static",
            "depends_systemd", "depends_udev", NULL
        };
        char *raw = holy_shell_join(&pkg, "depends");
        size_t count = 0, item;
        char **items = raw ? holy_shell_words(raw, &count) : NULL;
        size_t list_index;
        for (item = 0; items && item < count; ++item) {
            char *fixed = expand_names(items[item], name, version, release, 1, NULL);
            if (fixed && *fixed && emit_one_dependency(out, fixed, "depend", &note, &review,
                                                       "depends"))
                holy_note_add(&note, "carried", "depends %s APKBUILD:%zu", fixed,
                              holy_shell_line(&pkg, "depends"));
            free(fixed);
        }
        holy_shell_words_free(items);
        free(raw);
        for (list_index = 0; build_lists[list_index]; ++list_index) {
            char *list = holy_shell_join(&pkg, build_lists[list_index]);
            size_t list_size = 0;
            char **entries = list ? holy_shell_words(list, &list_size) : NULL;
            for (item = 0; entries && item < list_size; ++item) {
                char *fixed = expand_names(entries[item], name, version, release, 1, NULL);
                if (fixed && *fixed)
                    emit_one_dependency(out, fixed, "build-depend", &note, &review,
                                        build_lists[list_index]);
                free(fixed);
            }
            holy_shell_words_free(entries);
            free(list);
        }
        for (list_index = 0; split_depends[list_index]; ++list_index) {
            if (!holy_shell_present(&pkg, split_depends[list_index])) continue;
            review = 1;
            holy_note_add(&note, "preserved", "%s APKBUILD:%zu", split_depends[list_index],
                          holy_shell_line(&pkg, split_depends[list_index]));
        }
    }

    /* an install action script beside the APKBUILD becomes one hook */
    {
        static const struct { const char *action; const char *key; const char *text; } actions[] = {
            { "post-install", "hook-install", "postinstall" },
            { "pre-install", "hook-install", "preinstall" },
            { "pre-upgrade", NULL, NULL },
            { "post-upgrade", NULL, NULL },
            { "pre-deinstall", "hook-remove", "preremove" },
            { "post-deinstall", NULL, NULL }
        };
        char *entries = holy_shell_join(&pkg, "install");
        size_t count = 0, item;
        char **items = entries ? holy_shell_words(entries, &count) : NULL;
        char *hooks[8];
        size_t hook_count = 0;
        for (item = 0; items && item < count; ++item) {
            char *expanded = expand_names(items[item], name, version, release, 0, NULL);
            const char *entry = expanded ? expanded : items[item];
            const char *action = strchr(entry, '.') ? strchr(entry, '.') + 1 : NULL;
            char original[4096], copied[4096], installed[600];
            struct stat st;
            char local_hash[65];
            const char *base;
            int known = 0;
            if (!action) { free(expanded); continue; }
            for (index = 0; index < sizeof actions / sizeof *actions; ++index)
                if (!strcmp(action, actions[index].action)) known = 1;
            if (!known) {
                review = 1;
                holy_note_add(&note, "unknown", "install action %s", entry);
                free(expanded);
                continue;
            }
            base = strrchr(entry, '/');
            base = base ? base + 1 : entry;
            snprintf(original, sizeof original, "%s/%s", pkg.directory, base);
            if (stat(original, &st) || !S_ISREG(st.st_mode)) {
                review = 1;
                holy_note_add(&note, "unknown", "install script %s is not next to the APKBUILD "
                              "APKBUILD:%zu", entry, holy_shell_line(&pkg, "install"));
                free(expanded);
                continue;
            }
            for (index = 0; index < sizeof actions / sizeof *actions; ++index) {
                if (strcmp(action, actions[index].action)) continue;
                if (actions[index].key) {
                    snprintf(installed, sizeof installed, "usr/share/holy/%s/%s", name, base);
                    snprintf(copied, sizeof copied, "%s/%s", output, base);
                    if (!holy_copy_and_hash(original, copied, local_hash)) { wrote = 0; break; }
                    fputs("source ", out);
                    holy_token(out, base);
                    fputc(' ', out);
                    holy_token(out, base);
                    fputc('\n', out);
                    fputs(actions[index].key, out);
                    fputc(' ', out);
                    fputs("/bin/sh ", out);
                    holy_token(out, installed);
                    fputc('\n', out);
                    if (hook_count < sizeof hooks / sizeof *hooks)
                        hooks[hook_count++] = strdup(base);
                    holy_note_add(&note, "preserved", "hook %s (%s)", base, actions[index].text);
                    holy_note_add(&note, "semantic-change", "%s runs with ACTION unset, its pre "
                                  "and post branches are not reproduced", base);
                } else {
                    review = 1;
                    holy_note_add(&note, "unknown", "install action %s has no Holy hook stage",
                                  entry);
                }
            }
            free(expanded);
        }
        holy_shell_words_free(items);
        free(entries);
        if (!wrote) { result = 1; goto done; }
        /* the hook scripts live in the payload so the installer can read them */
        if (hook_count) {
            fprintf(out, "step package /bin/sh <<HOOKS\n"
                    "mkdir -p \"$HOLY_DEST/usr/share/holy/%s\"\n", name);
            for (item = 0; item < hook_count; ++item)
                fprintf(out, "cp \"$HOLY_SRC/%s\" \"$HOLY_DEST/usr/share/holy/%s/%s\"\n",
                        hooks[item], name, hooks[item]);
            fputs("HOOKS\n", out);
        }
        for (item = 0; item < hook_count; ++item) free(hooks[item]);
    }
    if (!wrote) { result = 1; goto done; }

    /* every declared subpackage becomes one output */
    {
        char *entries = holy_shell_join(&pkg, "subpackages");
        size_t count = 0, item;
        char **items = entries ? holy_shell_words(entries, &count) : NULL;
        for (item = 0; items && item < count; ++item) {
            const char *entry = items[item];
            const char *first = strchr(entry, ':');
            size_t entry_size = first ? (size_t)(first - entry) : strlen(entry);
            char *entry_text = holy_shell_copy(entry, entry_size);
            char *expanded = entry_text ?
                expand_names(entry_text, name, version, release, 1, NULL) : NULL;
            const char *split_name = first ? first + 1 : NULL;
            struct apk_split *split;
            free(entry_text);
            if (!expanded) { wrote = 0; break; }
            if (split_name) {
                const char *second = strchr(split_name, ':');
                if (second) {
                    review = 1;
                    holy_note_add(&note, "preserved", "subpackage %s declares its own arch %s",
                                  expanded, second + 1);
                }
            }
            if (split_count >= sizeof splits / sizeof *splits) {
                review = 1;
                holy_note_add(&note, "unknown", "more subpackages than outputs are carried %s",
                              expanded);
                free(expanded);
                continue;
            }
            split = &splits[split_count];
            if (!*expanded || strlen(expanded) >= sizeof split->name) {
                review = 1;
                holy_note_add(&note, "unknown", "subpackage %s has no usable name", entry);
                free(expanded);
                continue;
            }
            snprintf(split->name, sizeof split->name, "%s", expanded);
            /* abuild takes the split function from the entry, else from the last suffix */
            if (split_name) {
                const char *second = strchr(split_name, ':');
                size_t size = second ? (size_t)(second - split_name) : strlen(split_name);
                if (!size) {
                    /* an empty function means the name suffix picks one */
                    const char *dash = strrchr(expanded, '-');
                    split_name = dash ? dash + 1 : expanded;
                } else {
                    snprintf(split->function, sizeof split->function, "%.*s",
                             (int)(size < sizeof split->function - 1 ? size
                                                                    : sizeof split->function - 1),
                             split_name);
                }
            }
            if (!*split->function) {
                static const struct { const char *suffix; const char *function; } completions[] = {
                    { "-bash-completion", "bashcomp" },
                    { "-zsh-completion", "zshcomp" },
                    { "-fish-completion", "fishcomp" }
                };
                const char *function = NULL;
                size_t used;
                for (used = 0; used < sizeof completions / sizeof *completions; ++used) {
                    size_t at = strlen(completions[used].suffix);
                    if (strlen(expanded) > at &&
                        !strcmp(expanded + strlen(expanded) - at, completions[used].suffix)) {
                        function = completions[used].function;
                        break;
                    }
                }
                if (!function) {
                    const char *dash = strrchr(expanded, '-');
                    function = dash ? dash + 1 : expanded;
                }
                snprintf(split->function, sizeof split->function, "%s", function);
            }
            {
                const struct shell_function *body =
                    *split->function ? holy_shell_function(&pkg, split->function) : NULL;
                if (body) {
                    split->has_body = copy_split_body(body, &split->body);
                    if (!split->has_body) { wrote = 0; break; }
                    holy_note_add(&note, "preserved", "subpackage %s from %s APKBUILD:%zu-%zu",
                                  split->name, split->function, body->first, body->last);
                } else {
                    const char *help = default_split_help(split->function);
                    review = 1;
                    if (help)
                        holy_note_add(&note, "unknown", "subpackage %s needs the abuild default_%s "
                                      "helper, which moves %s", split->name, split->function,
                                      help);
                    else
                        holy_note_add(&note, "unknown", "subpackage %s has no split function %s "
                                      "APKBUILD:%zu", split->name, split->function,
                                      holy_shell_line(&pkg, "subpackages"));
                }
            }
            ++split_count;
            free(expanded);
        }
        holy_shell_words_free(items);
        free(entries);
        if (!wrote) { result = 1; goto done; }
    }

    fputs("output ", out); holy_token(out, name);
    fputs(" runtime\n", out);
    for (k = 0; k < split_count; ++k) {
        if (!splits[k].has_body) continue;
        fputs("output ", out); holy_token(out, splits[k].name);
        fputs(" runtime\n", out);
    }
    {
        /* the engine extracts each source under its own name, so one lift turns that
           into the single $srcdir tree an abuild phase expects */
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
        holy_note_add(&note, "semantic-change", "the extracted tree takes the place of the "
                      "abuild $srcdir directory, and the source lift replaces default_unpack");
    }

    /* abuild runs a phase in $builddir, which defaults to $srcdir/$pkgname-$pkgver */
    {
        char *declared = holy_shell_join(&pkg, "builddir");
        char *text = NULL;
        size_t length;
        int unknown = 0;
        if (declared && *declared)
            text = expand_names(declared, name, version, release, 1, &unknown);
        if (!text || unknown || strncmp(text, "$srcdir", 7)) {
            if (declared && *declared) {
                review = 1;
                holy_note_add(&note, "unknown", "builddir %s names a path this converter cannot "
                              "rebase on the source tree", declared);
            }
            length = strlen(name) + strlen(version) + 32;
            builddir = malloc(length);
            if (builddir) snprintf(builddir, length, "\"$HOLY_SRC/%s-%s\"", name, version);
        } else {
            length = strlen(text) + 32;
            builddir = malloc(length);
            if (builddir) snprintf(builddir, length, "\"$HOLY_SRC%s\"", text + 7);
        }
        free(text);
        if (declared && *declared) {
            review = 1;
            holy_note_add(&note, "semantic-change", "builddir %s becomes %s", declared,
                          builddir ? builddir : "\"$HOLY_SRC\"");
        } else {
            holy_note_add(&note, "helper", "abuild supplies the default builddir %s-%s under "
                          "the source tree", name, version);
        }
        free(declared);
        if (!builddir) { result = 1; goto done; }
    }

    {
        static const struct { const char *phase; const char *function; } phases[] = {
            { "prepare", "prepare" }, { "build", "build" }, { "check", "check" },
            { "package", "package" }, { NULL, NULL }
        };
        for (index = 0; phases[index].phase; ++index) {
            const struct shell_function *function =
                holy_shell_function(&pkg, phases[index].function);
            char *prefix;
            if (!function) {
                if (strcmp(phases[index].phase, "prepare")) {
                    holy_note_add(&note, "helper", "abuild runs the built-in %s phase, which "
                                  "this converter does not reproduce", phases[index].phase);
                    continue;
                }
                holy_note_add(&note, "helper", "abuild runs default_prepare, which applies the "
                              "patches listed in source");
                review = 1;
                continue;
            }
            report_unknowns(function->body, function->length, &note, &review,
                            phases[index].function, 0);
            holy_note_add(&note, "preserved", "%s APKBUILD:%zu-%zu", phases[index].function,
                          function->first, function->last);
            prefix = prologue(&pkg, name, version, release, builddir, "\"$HOLY_DEST\"");
            if (!prefix || !emit_phase_step(out, phases[index].phase, prefix, function->body)) {
                free(prefix);
                wrote = 0;
                break;
            }
            free(prefix);
        }
        if (!wrote) { result = 1; goto done; }
    }
    for (k = 0; k < split_count; ++k) {
        char *prefix;
        if (!splits[k].has_body) continue;
        report_unknowns(splits[k].body.body, splits[k].body.length, &note, &review,
                        splits[k].name, 1);
        prefix = prologue(&pkg, name, version, release, builddir, "\"$HOLY_SPLIT_DEST\"");
        if (!prefix || !emit_split_step(out, &splits[k], prefix)) {
            free(prefix);
            wrote = 0;
            break;
        }
        free(prefix);
    }
    if (!wrote) { result = 1; goto done; }
    if (fflush(out) || fclose(out)) { out = NULL; result = 1; goto done; }
    out = NULL;

    out = fopen(report_path, "wb");
    if (!out) {
        fprintf(stderr, "holypkg: report unavailable: %s\n", report_path);
        result = 1;
        goto done;
    }
    fputs("format holy-recipe-conversion-1\nconverter aports-1\n", out);
    fputs("source-name ", out); holy_token(out, source); fputc('\n', out);
    fputs("source-file APKBUILD\n", out);
    fprintf(out, "source-sha256 %s\n", hash);
    fputs("pkgbase ", out); holy_token(out, name); fputc('\n', out);
    fputs("version ", out); holy_token(out, version); fputc('\n', out);
    fputs("release ", out); holy_token(out, release); fputc('\n', out);
    fputs("arch ", out); holy_token(out, arch); fputc('\n', out);
    fputs("recipe ", out); holy_token(out, name); fputs(".recipe\n", out);
    fprintf(out, "status %s\n", review ? "review-required" : "native");
    for (k = 0; k < note.count; ++k) fprintf(out, "%s\n", note.lines[k]);
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
        fprintf(stderr, "holypkg: APKBUILD conversion failed (status %d)\n", result);
    for (k = 0; k < split_count; ++k) split_free(&splits[k]);
    free(sources);
    free(builddir);
    holy_note_free(&note);
    free(summary); free(homepage); free(license); free(maintainer);
    holy_shell_free(&pkg);
    return result;
}
