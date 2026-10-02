/* Flatpak manifest to holy-recipe(5) conversion; see man/holy-recipe.5 and
   man/holypkg.8. the manifest is read as JSON text and never built. a manifest
   names its runtime and its SDK as Flatpak ids, builds every module through a
   template flatpak-builder supplies and asks for sandbox permissions the
   installed program may use, so an id becomes a requirement, a buildsystem
   becomes the shell that runs the same tools and each permission is reported as
   dropped rather than kept as a promise. */
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1
#include "flatpak.h"
#include "shrecipe.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* a manifest states no shell, so a value that asks one is reported rather than
   expanded */
static int json_literal(const char *value)
{
    return value && *value && !strpbrk(value, "$`\\\"'");
}

static int json_label(const char *value)
{
    size_t at;
    if (!value || !*value) return 0;
    for (at = 0; value[at]; ++at)
        if (!isalnum((unsigned char)value[at]) &&
            !(value[at] == '.' || value[at] == '_' || value[at] == '+' || value[at] == '-'))
            return 0;
    return 1;
}

/* the last dotted component of a Flatpak id, which is the part a package name
   may hold; a branch after // names a remote and is left out */
static int flatpak_component(const char *id, char *out, size_t size)
{
    const char *at, *stop;
    size_t length;
    if (!id) return 0;
    at = strstr(id, "//");
    stop = at ? at : id + strlen(id);
    if (stop == id) return 0;
    for (at = stop; at > id && at[-1] != '.'; --at) continue;
    length = (size_t)(stop - at);
    if (!length || length >= size) return 0;
    memcpy(out, at, length);
    out[length] = 0;
    return json_label(out);
}

/* what one module leaves for the step that builds it */
struct flatpak_build {
    FILE *out;
    struct recipe_note *note;
    const char *input;
    const char *directory;
    const char *output;
    const char *name;
    char tree[256];
    char **patches;
    size_t patch_count;
    char **collected;
    size_t collected_count;
    int review;
};

static int flatpak_note(struct flatpak_build *build, const char *kind, const char *format, ...);

/* the lines a source or an option asks the build to run, kept until the step that
   carries them is open */
static int flatpak_collect(struct flatpak_build *build, const char *line)
{
    char **grown = realloc(build->collected, (build->collected_count + 1) * sizeof *grown);
    if (!grown) return 0;
    build->collected = grown;
    build->collected[build->collected_count] = strdup(line);
    if (!build->collected[build->collected_count]) return 0;
    ++build->collected_count;
    return 1;
}

static int flatpak_keep_line(struct flatpak_build *build, const char *line)
{
    size_t length = strlen(line);
    if (!length) return 1;
    if (fputs(line, build->out) < 0 || fputc('\n', build->out) == EOF) return 0;
    return 1;
}

/* a /app path is where the Flatpak template installs and where a Holy build root
   has nothing, so a path of its own becomes the payload and the rewrite is
   reported; anything else is left as the manifest wrote it */
static void flatpak_keep_command(struct flatpak_build *build, const char *line)
{
    static const char before[] = "\"'=(:$ ";
    static const char after[] = "/\"' ):;=";
    const char *mark = line;
    const char *at = line;
    int rewritten = 0;
    while ((at = strstr(at, "/app"))) {
        char next = at[4];
        if ((at == line || strchr(before, at[-1])) && (!next || strchr(after, next))) {
            size_t used = (size_t)(at - mark);
            if (used && fwrite(mark, 1, used, build->out) != used) return;
            fputs("$DESTDIR", build->out);
            mark = at + 4;
            at = mark;
            rewritten = 1;
            continue;
        }
        at += 4;
    }
    if (!rewritten) {
        flatpak_keep_line(build, line);
        return;
    }
    fputs(mark, build->out);
    fputc('\n', build->out);
    flatpak_note(build, "semantic-change", "the build command %s writes under /app, so the "
                  "path becomes $DESTDIR and the install stays in the payload", line);
}

/* a command list a module runs, kept in the order the manifest writes it */
static void flatpak_keep_commands(struct flatpak_build *build, const struct holy_json_value *list)
{
    size_t i;
    for (i = 0; i < (list ? list->count : 0); ++i) {
        const char *line = holy_json_text(list->members[i].value);
        if (line) flatpak_keep_command(build, line);
    }
}

/* one local file the conversion directory carries, with the digest it has there */
static int flatpak_local_record(struct flatpak_build *build, const char *base, const char *digest,
                                const char *kind)
{
    fputs("source ", build->out);
    holy_token(build->out, base);
    fputc(' ', build->out);
    holy_token(build->out, base);
    fputc('\n', build->out);
    fputs("source-sha256 ", build->out);
    holy_token(build->out, base);
    fputc(' ', build->out);
    holy_token(build->out, digest);
    fputc('\n', build->out);
    flatpak_note(build, "carried", "the %s file %s travels beside the recipe and is verified "
                  "there", kind, base);
    return 1;
}

/* copies a file the manifest names beside it into the conversion directory and
   records it as a local source with its own digest */
static int flatpak_local(struct flatpak_build *build, const char *path, const char *base,
                         char named[4096], char digest[65], const char *kind)
{
    char target[4096];
    size_t at;
    if (!json_literal(base) || !json_label(base) || strstr(base, "/")) return 0;
    at = snprintf(target, sizeof target, "%s/%s", build->output, base);
    if (at >= sizeof target) return 0;
    if (!holy_copy_and_hash(path, target, digest)) {
        flatpak_note(build, "unknown", "the %s file %s is not beside the manifest, so a Holy "
                      "recipe has no source for it", kind, base);
        build->review = 1;
        return 0;
    }
    snprintf(named, 4096, "%s", base);
    return flatpak_local_record(build, base, digest, kind);
}

static int flatpak_patch(struct flatpak_build *build, const char *file)
{
    char **grown = realloc(build->patches, (build->patch_count + 1) * sizeof *grown);
    if (!grown) return 0;
    build->patches = grown;
    build->patches[build->patch_count] = strdup(file);
    if (!build->patches[build->patch_count]) return 0;
    ++build->patch_count;
    return 1;
}

/* one source of one module: a recipe record where the format allows one, and a
   step line or a report where it does not */
static void flatpak_source(struct flatpak_build *build, const char *label, size_t index,
                           const struct holy_json_value *entry)
{
    const char *type = holy_json_text(holy_json_get(entry, "type"));
    const char *url = holy_json_text(holy_json_get(entry, "url"));
    const char *sum = holy_json_text(holy_json_get(entry, "sha256"));
    const char *path = holy_json_text(holy_json_get(entry, "path"));
    const char *contents = holy_json_text(holy_json_get(entry, "contents"));
    const char *options = holy_json_text(holy_json_get(entry, "options"));
    const struct holy_json_value *expressions = holy_json_get(entry, "sed");
    char named[4096], named_path[4096], digest[65], record[512];
    size_t at;    if (!type && url) type = "archive";
    if (!type) type = "file";
    if (!strcmp(type, "archive") || !strcmp(type, "archive-url")) {
        if (!url || !json_literal(url)) {
            flatpak_note(build, "unknown", "the %s source of module %s names no address, which "
                          "a Holy source needs", type, label);
            build->review = 1;
            return;
        }
        if (!strstr(url, "://")) {
            /* an archive beside the manifest travels with the recipe, and the engine
               extracts it where the module builds */
            at = snprintf(named_path, sizeof named_path, "%s/%s", build->directory, url);
            if (at >= sizeof named_path) return;
            if (!flatpak_local(build, named_path, url, named, digest, "archive")) return;
            if (sum && strcmp(sum, digest)) {
                flatpak_note(build, "unknown", "the archive %s states the digest %s and has "
                              "%s beside the manifest", url, sum, digest);
                build->review = 1;
            }
            if (!build->tree[0] && strlen(url) < sizeof build->tree)
                memcpy(build->tree, url, strlen(url) + 1);
        } else if (strncmp(url, "https://", 8)) {
            flatpak_note(build, "unknown", "the %s source of module %s is %s, and a Holy source "
                          "is fetched over https", type, label,
                          strncmp(url, "http://", 7) ? "a non-https address" :
                          "a plain http address");
            build->review = 1;
            return;
        } else {
            snprintf(record, sizeof record, "%s-%zu", label, index);
            if (!json_label(record)) {
                flatpak_note(build, "unknown", "the module %s has a name a source record cannot "
                              "hold", label);
                build->review = 1;
                return;
            }
            fputs("source ", build->out);
            holy_token(build->out, record);
            fputc(' ', build->out);
            holy_token(build->out, url);
            fputc('\n', build->out);
            flatpak_note(build, "preserved", "the archive %s of module %s", url, label);
            if (!sum) {
                flatpak_note(build, "unknown", "the archive %s states no sha256, and a Holy "
                              "network source needs one", url);
                build->review = 1;
                return;
            }
            fputs("source-sha256 ", build->out);
            holy_token(build->out, record);
            fputc(' ', build->out);
            holy_token(build->out, sum);
            fputc('\n', build->out);
            /* the engine extracts an archive into HOLY_SRC/NAME, and that tree is
               where the module builds */
            if (!build->tree[0] && strlen(record) < sizeof build->tree)
                memcpy(build->tree, record, strlen(record) + 1);
        }
        if (holy_json_get(entry, "strip-components"))
            flatpak_note(build, "unknown", "the archive %s asks for strip-components, which the "
                          "engine does not apply", url);
        if (holy_json_get(entry, "dest-filename"))
            flatpak_note(build, "unknown", "the archive %s names dest-filename, and the engine "
                          "names the extracted tree itself", url);
        if (holy_json_text(holy_json_get(entry, "dest")) &&
            strcmp(holy_json_text(holy_json_get(entry, "dest")), "."))
            flatpak_note(build, "unknown", "the archive %s places itself at %s inside the build "
                          "tree, and a Holy source has one extracted directory", url,
                          holy_json_text(holy_json_get(entry, "dest")));
        return;
    }
    if (!strcmp(type, "file") || !strcmp(type, "patch") || !strcmp(type, "directory")) {
        if (!path || strchr(path, '/') || !json_label(path)) {
            flatpak_note(build, "unknown", "the %s source of module %s names no file beside the "
                          "manifest", type, label);
            build->review = 1;
            return;
        }
        at = snprintf(named_path, sizeof named_path, "%s/%s", build->directory, path);
        if (at >= sizeof named_path) return;
        if (!strcmp(type, "directory")) {
            flatpak_note(build, "unknown", "the directory source %s of module %s is copied into "
                          "the conversion directory as one archive, which this converter does "
                          "not do", path, label);
            build->review = 1;
            return;
        }
        if (!flatpak_local(build, named_path, path, named, digest, type)) return;
        if (!strcmp(type, "patch")) {
            if (!flatpak_patch(build, path)) return;
            if (options && strcmp(options, "-p1")) {
                flatpak_note(build, "unknown", "the patch %s asks for the option %s, and the step "
                              "applies it with -p1", path, options);
                build->review = 1;
            } else {
                flatpak_note(build, "preserved", "the patch %s applies with -p1 before module %s "
                              "builds", path, label);
            }
        }
        return;
    }
    if (!strcmp(type, "inline")) {
        char target[4096];
        const char *name;
        FILE *written;
        if (!contents) {
            flatpak_note(build, "unknown", "the inline source of module %s states no contents",
                          label);
            build->review = 1;
            return;
        }
        name = holy_json_text(holy_json_get(entry, "dest-filename"));
        if (!name || !json_literal(name) || !json_label(name)) name = "inline-source";
        at = snprintf(target, sizeof target, "%s/%s", build->output, name);
        if (at >= sizeof target) return;
        written = fopen(target, "wb");
        if (!written) return;
        if (fputs(contents, written) == EOF || fputc('\n', written) == EOF || fclose(written)) {
            flatpak_note(build, "unknown", "the inline source of module %s cannot be written",
                          label);
            build->review = 1;
            return;
        }
        if (!holy_hash_file(target, digest)) return;
        if (!flatpak_local_record(build, name, digest, "inline")) return;
        flatpak_note(build, "preserved", "the inline source of module %s becomes the file %s",
                      label, name);
        return;
    }
    if (!strcmp(type, "sed")) {
        size_t i;
        if (!expressions || expressions->kind != HOLY_JSON_ARRAY) {
            flatpak_note(build, "unknown", "the sed source of module %s names no expression",
                          label);
            build->review = 1;
            return;
        }
        for (i = 0; i < expressions->count; ++i) {
            const char *expression = holy_json_text(expressions->members[i].value);
            if (!expression) continue;
            flatpak_note(build, "unknown", "the sed source of module %s rewrites a file the "
                          "Flatpak template owns (%s), so the build needs it by hand", label,
                          expression);
            build->review = 1;
        }
        return;
    }
    if (!strcmp(type, "shell")) {
        const struct holy_json_value *commands = holy_json_get(entry, "commands");
        size_t i;
        for (i = 0; i < (commands ? commands->count : 0); ++i) {
            const char *line = holy_json_text(commands->members[i].value);
            if (line && !flatpak_collect(build, line)) return;
        }
        flatpak_note(build, "preserved", "the shell source of module %s runs before the module "
                      "builds", label);
        return;
    }
    flatpak_note(build, "unknown", "the %s source of module %s is a checkout or a rule that a "
                  "Holy recipe has no record for", type, label);
    build->review = 1;
}

/* the shell that runs the tools a buildsystem names, since the flatpak-builder
   template that normally runs them does not travel with the recipe */
static void flatpak_buildsystem(struct flatpak_build *build, const char *system,
                                const struct holy_json_value *options, const char *prefix)
{
    const struct holy_json_value *flags = holy_json_get(options, "flags");
    const struct holy_json_value *directory = holy_json_get(options, "build-dir");
    size_t i;
    int separate = 0;
    if (holy_json_text(directory) && strcmp(holy_json_text(directory), "false")) separate = 1;
    if (directory && directory->kind == HOLY_JSON_LITERAL && !strcmp(directory->text, "true"))
        separate = 1;
    if (separate && !strcmp(system, "simple")) {
        flatpak_note(build, "unknown", "the simple buildsystem has no build directory, so the "
                      "build-dir option of module %s does nothing", build->name);
        build->review = 1;
    }
    if (flags && flags->count && (!system || !strcmp(system, "simple"))) {
        flatpak_note(build, "unknown", "the flags of module %s name no build system, since it is "
                      "simple", build->name);
        build->review = 1;
    }
    if (!system) system = "simple";
    if (!strcmp(system, "simple")) return;
    if (separate)
        flatpak_note(build, "semantic-change", "the %s template of module %s builds in a "
                      "separate directory, and the step below changes into the source tree",
                      system, build->name);
    if (!strcmp(system, "make")) {
        flatpak_note(build, "semantic-change", "the make template of module %s is replaced by the "
                      "make and make install lines below", build->name);
        flatpak_keep_line(build, "make -j\"$HOLY_JOBS\"");
        flatpak_keep_line(build, "make DESTDIR=\"$HOLY_DEST\" install");
        return;
    }
    if (!strcmp(system, "autotools") || !strcmp(system, "autogen")) {
        flatpak_note(build, "semantic-change", "the %s template of module %s is replaced by the "
                      "configure, make and make install lines below", system, build->name);
        if (!strcmp(system, "autogen")) {
            flatpak_keep_line(build, "NOCONFIGURE=1 sh ./autogen.sh");
        }
        fprintf(build->out, "./configure --prefix=\"%s\"", prefix);
        for (i = 0; i < (flags ? flags->count : 0); ++i) {
            const char *flag = holy_json_at(flags, i);
            if (flag) fprintf(build->out, " %s", flag);
        }
        fputc('\n', build->out);
        flatpak_keep_line(build, "make -j\"$HOLY_JOBS\"");
        flatpak_keep_line(build, "make DESTDIR=\"$HOLY_DEST\" install");
        return;
    }
    if (!strcmp(system, "cmake")) {
        flatpak_note(build, "semantic-change", "the cmake template of module %s is replaced by the "
                      "cmake configure, build and install lines below", build->name);
        flatpak_keep_line(build, "cmake -S . -B build -DCMAKE_INSTALL_PREFIX=\"$PREFIX\""
                          " -DCMAKE_INSTALL_LIBDIR=lib");
        for (i = 0; i < (flags ? flags->count : 0); ++i) {
            const char *flag = holy_json_at(flags, i);
            if (flag) fprintf(build->out, " %s\n", flag);
        }
        flatpak_keep_line(build, "cmake --build build -j \"$HOLY_JOBS\"");
        flatpak_keep_line(build, "DESTDIR=\"$HOLY_DEST\" cmake --install build");
        return;
    }
    if (!strcmp(system, "meson")) {
        flatpak_note(build, "semantic-change", "the meson template of module %s is replaced by the "
                      "meson setup, compile and install lines below", build->name);
        flatpak_keep_line(build, "meson setup build --prefix=\"$PREFIX\" --libdir=lib");
        for (i = 0; i < (flags ? flags->count : 0); ++i) {
            const char *flag = holy_json_at(flags, i);
            if (flag) fprintf(build->out, " %s\n", flag);
        }
        flatpak_keep_line(build, "meson compile -C build -j \"$HOLY_JOBS\"");
        flatpak_keep_line(build, "DESTDIR=\"$HOLY_DEST\" meson install -C build");
        return;
    }
    if (!strcmp(system, "cargo")) {
        flatpak_note(build, "unknown", "the cargo template of module %s installs the binaries it "
                      "finds under target/release, and this converter does not choose one",
                      build->name);
        flatpak_note(build, "semantic-change", "the cargo template of module %s is replaced by "
                      "the cargo build line below", build->name);
        build->review = 1;
        flatpak_keep_line(build, "cargo build --release");
        return;
    }
    flatpak_note(build, "helper", "the %s buildsystem of module %s is a flatpak-builder "
                  "template, which no Holy phase provides", system, build->name);
    holy_note_environment(build->note, "flatpak-builder");
    build->review = 1;
}

/* the environment a module asks the build to run with */
static void flatpak_environment(struct flatpak_build *build, const struct holy_json_value *options)
{
    static const struct {
        const char *key;
        const char *variable;
    } variables[] = {
        { "cflags", "CFLAGS" }, { "cxxflags", "CXXFLAGS" }, { "ldflags", "LDFLAGS" },
        { "cppflags", "CPPFLAGS" }, { NULL, NULL }
    };
    const struct holy_json_value *env = holy_json_get(options, "env");
    const struct holy_json_value *append = holy_json_get(options, "append-path");
    const char *prefix = holy_json_text(holy_json_get(options, "prefix"));
    size_t i, j;
    if (prefix && strcmp(prefix, "/app"))
        flatpak_note(build, "semantic-change", "the prefix %s of module %s is kept, where a "
                      "Flatpak module installs under /app", prefix, build->name);
    else if (prefix)
        flatpak_note(build, "semantic-change", "the prefix /app of module %s becomes /usr, "
                      "because a Holy payload has no /app", build->name);
    /* env is written as a record or as a list of NAME=VALUE */
    for (i = 0; i < (env ? env->count : 0); ++i) {
        if (env->kind == HOLY_JSON_OBJECT) {
            const char *key = env->members[i].key;
            const char *value = holy_json_text(env->members[i].value);
            if (key && value) fprintf(build->out, "export %s=\"%s\"\n", key, value);
            continue;
        }
        {
            const char *entry = holy_json_at(env, i);
            if (entry) fprintf(build->out, "export %s\n", entry);
        }
    }
    for (i = 0; variables[i].key; ++i) {
        char *value = holy_json_joined(holy_json_get(options, variables[i].key));
        if (!value) continue;
        fprintf(build->out, "export %s=\"%s\"\n", variables[i].variable, value);
        free(value);
    }
    for (i = 0; i < (append ? append->count : 0); ++i) {
        const char *entry = holy_json_at(append, i);
        if (!entry) continue;
        fprintf(build->out, "PATH=\"%s:$PATH\"\n", entry);
    }
    if (env && env->kind != HOLY_JSON_OBJECT && (!append || !append->count)) {
        for (j = 0; j < env->count; ++j) {
            const char *entry = holy_json_at(env, j);
            if (entry && !strncmp(entry, "PATH=", 5))
                flatpak_note(build, "unknown", "module %s sets PATH in env, where the template "
                              "reads the search path of the SDK", build->name);
        }
    }
}

/* one module: its sources, then the step that builds it */
static void flatpak_module(struct flatpak_build *build, const struct holy_json_value *module,
                           const struct holy_json_value *shared)
{
    const char *name = holy_json_text(holy_json_get(module, "name"));
    const char *system = holy_json_text(holy_json_get(module, "buildsystem"));
    const struct holy_json_value *options = holy_json_get(module, "build-options");
    const struct holy_json_value *commands = holy_json_get(module, "build-commands");
    const struct holy_json_value *sources = holy_json_get(module, "sources");
    const struct holy_json_value *pre, *post, *install;
    const char *prefix = "usr";
    size_t i;
    if (!name) name = "module";
    if (!json_label(name)) {
        flatpak_note(build, "unknown", "the module name %s is not one a source record holds",
                      name);
        build->review = 1;
        return;
    }
    build->name = name;
    build->patch_count = 0;
    build->tree[0] = 0;
    for (i = 0; i < (sources ? sources->count : 0); ++i)
        flatpak_source(build, name, i, sources->members[i].value);
    /* the options of a module replace the ones the manifest states for them all */
    if (!options) options = shared;
    pre = options ? holy_json_get(options, "pre-commands") : NULL;
    post = options ? holy_json_get(options, "post-commands") : NULL;
    install = options ? holy_json_get(options, "post-install") : NULL;
    if (options && holy_json_text(holy_json_get(options, "prefix")))
        prefix = holy_json_text(holy_json_get(options, "prefix"));
    while (*prefix == '/') ++prefix;
    /* the patches of a module apply to its tree, so they run before it builds */
    if (build->patch_count) {
        fprintf(build->out, "step prepare /bin/sh <<STEP\n"
                            "# the patches of the flatpak-builder module %s, applied to its tree\n",
                name);
        if (build->tree[0]) {
            fprintf(build->out, "cd \"$HOLY_SRC/%s\" || exit 1\n", build->tree);
        } else {
            flatpak_keep_line(build, "cd \"$HOLY_SRC\" || exit 1");
        }
        for (i = 0; i < build->patch_count; ++i)
            fprintf(build->out, "patch -p1 -i \"$HOLY_SRC/%s\" < /dev/null || exit 1\n",
                    build->patches[i]);
        fputs("STEP\n", build->out);
        flatpak_note(build, "preserved", "the patches of module %s apply before it builds",
                      name);
    }
    fprintf(build->out, "step build /bin/sh <<STEP\n"
                        "# the flatpak-builder module %s, run as the shell its template runs\n",
            name);
    fprintf(build->out, "export PREFIX=/%s\n", prefix);
    flatpak_keep_line(build, "export DESTDIR=\"$HOLY_DEST\"");
    if (options) flatpak_environment(build, options);
    if (build->tree[0]) {
        fprintf(build->out, "cd \"$HOLY_SRC/%s\" || exit 1\n", build->tree);
    } else {
        flatpak_keep_line(build, "cd \"$HOLY_SRC\" || exit 1");
    }
    flatpak_keep_commands(build, pre);
    for (i = 0; i < build->collected_count; ++i)
        flatpak_keep_command(build, build->collected[i]);
    flatpak_keep_commands(build, commands);
    flatpak_buildsystem(build, system, options, "$PREFIX");
    flatpak_keep_commands(build, install);
    flatpak_keep_commands(build, post);
    fputs("STEP\n", build->out);
    flatpak_note(build, "preserved", "the module %s builds as one step in module order", name);
    if (holy_json_get(module, "cleanup"))
        flatpak_note(build, "unknown", "the cleanup of module %s removes or rewrites metadata the "
                      "Flatpak template owns", name);
    if (holy_json_get(module, "build-extension") ||
        (options && holy_json_get(options, "build-extension")))
        flatpak_note(build, "unknown", "module %s names a build extension, which is an SDK "
                      "feature a Holy build root has no place for", name);
    for (i = 0; i < build->patch_count; ++i) free(build->patches[i]);
    free(build->patches);
    build->patches = NULL;
    for (i = 0; i < build->collected_count; ++i) free(build->collected[i]);
    free(build->collected);
    build->collected = NULL;
    build->collected_count = 0;
}

static int flatpak_note(struct flatpak_build *build, const char *kind, const char *format, ...)
{
    char body[1024];
    va_list arguments;
    va_start(arguments, format);
    vsnprintf(body, sizeof body, format, arguments);
    va_end(arguments);
    if (!strcmp(kind, "helper") || !strcmp(kind, "unknown")) build->review = 1;
    return holy_note_add(build->note, kind, "%s", body);
}

/* whether any module of the manifest pulls an archive the engine has to extract */
static int flatpak_has_archive(const struct holy_json_value *modules)
{
    size_t index, i;
    for (index = 0; modules && index < modules->count; ++index) {
        const struct holy_json_value *module = modules->members[index].value;
        const struct holy_json_value *sources = holy_json_get(module, "sources");
        for (i = 0; i < (sources ? sources->count : 0); ++i) {
            const char *type = holy_json_text(holy_json_get(sources->members[i].value, "type"));
            if (type && (!strcmp(type, "archive") || !strcmp(type, "archive-url"))) return 1;
            if (!type && holy_json_get(sources->members[i].value, "url")) return 1;
        }
    }
    return 0;
}

int holy_convert_flatpak(const char *input, const char *source, const char *output)
{
    struct holy_json_value *manifest = NULL;
    struct recipe_note note = {0};
    struct flatpak_build build;
    char *directory = NULL, *cut;
    char name[256], version[256], release[64], arch[64], digest[65];
    char recipe_path[4096], report_path[4096], component[256], branch_text[256];
    const char *id, *branch, *summary, *homepage, *command, *sdk, *runtime;
    const struct holy_json_value *modules, *options, *permissions, *cleanup, *extension;
    const char *at;
    size_t index, i;
    int result = 1, read_status = 0;

    memset(&build, 0, sizeof build);
    build.note = &note;
    snprintf(release, sizeof release, "1");
    snprintf(version, sizeof version, "0");
    snprintf(arch, sizeof arch, "any");
    if (!input || !output || !*output) {
        fputs("usage: holypkg convert NAME.json --source NAME --output NEW_DIRECTORY\n", stderr);
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
    cut = strrchr(directory, '/');
    if (cut && cut != directory) *cut = 0;
    else {
        free(directory);
        directory = strdup(".");
        if (!directory) return 1;
    }
    manifest = holy_json_read(input, &read_status);
    if (!manifest) {
        if (read_status == 6) {
            fprintf(stderr, "holypkg: manifest unavailable: %s\n", input);
        } else {
            fputs("holypkg: a Flatpak manifest is JSON text, and this converter reads no other "
                  "form\n", stderr);
        }
        result = read_status;
        goto done;
    }
    if (manifest->kind != HOLY_JSON_OBJECT) {
        fputs("holypkg: a Flatpak manifest is JSON text, and this converter reads no other form\n",
              stderr);
        result = 2;
        goto done;
    }
    id = holy_json_text(holy_json_get(manifest, "id"));
    if (!id || !json_literal(id)) {
        fputs("holypkg: a Flatpak manifest needs a literal id\n", stderr);
        result = 2;
        goto done;
    }
    {
        /* an id may name its own machine and branch after a slash, so the package name
           is the last dotted component of the application id before it */
        const char *cursor = strchr(id, '/');
        const char *stop = cursor ? cursor : id + strlen(id);
        if (stop == id) {
            fputs("holypkg: a Flatpak manifest needs an id with a component\n", stderr);
            result = 2;
            goto done;
        }
        cursor = stop;
        while (cursor > id && cursor[-1] != '.') --cursor;
        if ((size_t)(stop - cursor) >= sizeof name) {
            fputs("holypkg: a Flatpak manifest id is too long to record\n", stderr);
            result = 2;
            goto done;
        }
        memcpy(name, cursor, (size_t)(stop - cursor));
        name[stop - cursor] = 0;
        if (!json_label(name)) {
            fputs("holypkg: a Flatpak manifest id is not a package name\n", stderr);
            result = 2;
            goto done;
        }
    }
    if (holy_json_text(holy_json_get(manifest, "version"))) {
        snprintf(version, sizeof version, "%s", holy_json_text(holy_json_get(manifest, "version")));
        if (!json_label(version)) {
            fputs("holypkg: a Flatpak manifest version is not one a recipe can hold\n", stderr);
            result = 2;
            goto done;
        }
    }
    branch = holy_json_text(holy_json_get(manifest, "branch"));
    if (!branch) {
        /* an id may carry its own machine and branch, so the tail of the id is the
           branch the manifest did not write on its own */
        const char *tail = strchr(id, '/');
        if (tail) {
            if (snprintf(branch_text, sizeof branch_text, "%s", tail + 1) >=
                (int)sizeof branch_text) {
                fputs("holypkg: a Flatpak manifest id carries too long a branch\n", stderr);
                result = 2;
                goto done;
            }
            branch = branch_text;
        }
    }
    if (holy_json_text(holy_json_get(manifest, "arch"))) {
        const char *machine = holy_json_text(holy_json_get(manifest, "arch"));
        if (!machine) machine = holy_json_at(holy_json_get(manifest, "arch"), 0);
        if (machine && !strcmp(machine, "x86_64")) snprintf(arch, sizeof arch, "x86_64");
        else if (machine && (!strcmp(machine, "i386") || !strcmp(machine, "i686")))
            snprintf(arch, sizeof arch, "i686");
        else if (machine && *machine) {
            snprintf(arch, sizeof arch, "%s", machine);
            flatpak_note(&build, "unknown", "the machine %s is written as it stands, and the "
                          "payload decides what the artifact is", machine);
        }
    } else if (branch) {
        /* a branch names the machine and the stability of a build */
        char machine[64];
        size_t used = 0;
        while (branch[used] && branch[used] != '/' && used + 1 < sizeof machine) {
            machine[used] = branch[used];
            ++used;
        }
        machine[used] = 0;
        if (!strcmp(machine, "x86_64")) snprintf(arch, sizeof arch, "x86_64");
        else if (!strcmp(machine, "i386")) snprintf(arch, sizeof arch, "i686");
    }

    if (mkdir(output, 0700) && errno != EEXIST) {
        fprintf(stderr, "holypkg: conversion directory unavailable: %s\n", output);
        goto done;
    }
    snprintf(recipe_path, sizeof recipe_path, "%s/%s.recipe", output, name);
    snprintf(report_path, sizeof report_path, "%s/conversion", output);
    build.out = fopen(recipe_path, "wb");
    if (!build.out) {
        fprintf(stderr, "holypkg: recipe unavailable: %s\n", recipe_path);
        goto done;
    }
    build.note = &note;
    build.input = input;
    build.directory = directory;
    build.output = output;
    build.name = name;

    fputs("format holy-recipe-1\nname ", build.out); holy_token(build.out, name);
    fputs("\nversion ", build.out); holy_token(build.out, version);
    fputs("\nrelease ", build.out); holy_token(build.out, release);
    fputs("\narch ", build.out); holy_token(build.out, arch);
    fputs("\nlibc any\n", build.out);
    summary = holy_json_text(holy_json_get(manifest, "summary"));
    if (summary && json_literal(summary) && *summary) {
        fputs("summary ", build.out); holy_token(build.out, summary); fputc('\n', build.out);
        flatpak_note(&build, "carried", "the summary of the manifest");
    }
    homepage = holy_json_text(holy_json_get(manifest, "url"));
    if (homepage && json_literal(homepage) && strstr(homepage, "://")) {
        fputs("homepage ", build.out); holy_token(build.out, homepage); fputc('\n', build.out);
        flatpak_note(&build, "carried", "the url of the manifest");
    }
    fputs("x-source-family flatpak\nx-converter flatpak-1\n", build.out);
    fputs("x-app-id ", build.out); holy_token(build.out, id); fputc('\n', build.out);
    if (strcmp(arch, "any"))
        flatpak_note(&build, "carried", "the machine %s of the manifest or its branch", arch);
    else
        flatpak_note(&build, "unknown", "the manifest names no machine, so the payload decides "
                      "which artifact the recipe builds");
    if (strcmp(version, "0"))
        flatpak_note(&build, "carried", "the version %s of the manifest", version);
    else
        flatpak_note(&build, "semantic-change", "the manifest states no version, so the recipe "
                      "records zero and the build report names it");
    if (branch) {
        fputs("x-flatpak-branch ", build.out); holy_token(build.out, branch); fputc('\n', build.out);
        flatpak_note(&build, "carried", "the branch %s", branch);
    }
    command = holy_json_text(holy_json_get(manifest, "command"));
    if (command) {
        fputs("x-flatpak-command ", build.out); holy_token(build.out, command);
        fputc('\n', build.out);
        flatpak_note(&build, "semantic-change", "the command %s is a path under /app, and a "
                      "Holy payload installs under /usr", command);
    }
    sdk = holy_json_text(holy_json_get(manifest, "sdk"));
    runtime = holy_json_text(holy_json_get(manifest, "runtime"));
    if (sdk && flatpak_component(sdk, component, sizeof component)) {
        fputs("build-depend ", build.out); holy_token(build.out, component);
        fputs(" \"any\" \"-\"\n", build.out);
        flatpak_note(&build, "carried", "the sdk %s becomes the build requirement %s", sdk,
                      component);
    } else if (sdk) {
        flatpak_note(&build, "unknown", "the sdk %s has no component a requirement could name",
                      sdk);
        build.review = 1;
    }
    if (runtime && flatpak_component(runtime, component, sizeof component)) {
        fputs("depend ", build.out); holy_token(build.out, component);
        fputs(" \"any\" \"-\"\n", build.out);
        flatpak_note(&build, "carried", "the runtime %s becomes the requirement %s", runtime,
                      component);
    } else if (runtime) {
        flatpak_note(&build, "unknown", "the runtime %s has no component a requirement could "
                      "name", runtime);
        build.review = 1;
    }
    if (sdk && runtime) {
        const char *version_text = holy_json_text(holy_json_get(manifest, "runtime-version"));
        flatpak_note(&build, "semantic-change", "the sdk %s builds the modules and the runtime "
                      "%s%s%s is what the program runs on, so they are separate requirements",
                      sdk, runtime, version_text ? "//" : "", version_text ? version_text : "");
    }
    fputs("output ", build.out); holy_token(build.out, name); fputs(" runtime\n", build.out);

    permissions = holy_json_get(manifest, "finish-args");
    if (permissions && permissions->count) {
        char joined[1024];
        size_t used = 0;
        for (i = 0; i < permissions->count; ++i) {
            const char *permission = holy_json_at(permissions, i);
            if (!permission) continue;
            flatpak_note(&build, "unknown", "the permission %s is a Flatpak sandbox decision, "
                          "and a Holy package runs with the caller's context", permission);
            used += (size_t)snprintf(joined + used, sizeof joined - used, "%s%s",
                                     used ? " " : "", permission);
            if (used >= sizeof joined) used = sizeof joined - 1;
        }
        fputs("x-flatpak-finish-args ", build.out);
        holy_token(build.out, joined);
        fputc('\n', build.out);
    }
    cleanup = holy_json_get(manifest, "cleanup");
    for (i = 0; i < (cleanup ? cleanup->count : 0); ++i) {
        const char *entry = holy_json_at(cleanup, i);
        if (entry)
            flatpak_note(&build, "unknown", "the cleanup step %s runs after the build inside the "
                          "Flatpak sandbox", entry);
    }
    extension = holy_json_get(manifest, "build-extension");
    if (extension)
        flatpak_note(&build, "unknown", "the manifest names the build extension %s, which is an "
                      "SDK feature a Holy build root has no place for",
                      holy_json_text(holy_json_get(extension, "name")) ? holy_json_text(holy_json_get(extension, "name"))
                      : "unknown");

    modules = holy_json_get(manifest, "modules");
    if (!modules || modules->kind != HOLY_JSON_ARRAY || !modules->count) {
        flatpak_note(&build, "unknown", "the manifest names no module, so the recipe builds "
                      "nothing to package");
        build.review = 1;
    } else {
        options = holy_json_get(manifest, "build-options");
        if (flatpak_has_archive(modules)) {
            /* the engine extracts an archive into HOLY_SRC/NAME, and a module builds
               where its sources are, so one top directory inside it is lifted */
            fputs("step unpack /bin/sh <<UNPACK\n"
                  "# a module builds in the directory its own sources make, so one top\n"
                  "# directory inside an extracted archive is lifted into place\n"
                  "for entry in \"$HOLY_SRC\"/*; do\n"
                  "  [ -d \"$entry\" ] || continue\n"
                  "  set -- \"$entry\"/*\n"
                  "  [ \"$#\" = 1 ] && [ -d \"$1\" ] || continue\n"
                  "  mv \"$1\" \"$HOLY_SRC/.lifted\"\n"
                  "  rmdir \"$entry\"\n"
                  "  mkdir -p \"$entry\"\n"
                  "  mv \"$HOLY_SRC/.lifted\"/* \"$HOLY_SRC/.lifted\"/.[!.]* \"$entry\"/ "
                  "2>/dev/null || true\n"
                  "  rm -rf \"$HOLY_SRC/.lifted\"\n"
                  "done\n"
                  "UNPACK\n", build.out);
            flatpak_note(&build, "semantic-change", "the engine extracts every archive into "
                          "HOLY_SRC/NAME, and one top directory inside it is lifted, so a module "
                          "builds where the manifest expects its sources");
        }
        for (index = 0; index < modules->count; ++index) {
            const struct holy_json_value *module = modules->members[index].value;
            if (!module || module->kind != HOLY_JSON_OBJECT) {
                flatpak_note(&build, "unknown", "the module %zu of the manifest is not a "
                              "record", index + 1);
                build.review = 1;
                continue;
            }
            flatpak_module(&build, module, options);
        }
        if (modules->count > 1)
            flatpak_note(&build, "semantic-change", "a Flatpak build shares one prefix across "
                          "its %zu modules, while each step here installs into the payload, so a "
                          "later module cannot read an earlier install", modules->count);
    }
    holy_note_environment_records(build.out, &note);
    if (ferror(build.out) || fclose(build.out)) {
        build.out = NULL;
        goto done;
    }
    build.out = fopen(report_path, "wb");
    if (!build.out) {
        fprintf(stderr, "holypkg: report unavailable: %s\n", report_path);
        goto done;
    }
    fputs("format holy-recipe-conversion-1\nconverter flatpak-1\n", build.out);
    fputs("source-name ", build.out); holy_token(build.out, source); fputc('\n', build.out);
    at = strrchr(input, '/');
    fputs("source-file ", build.out); holy_token(build.out, at ? at + 1 : input);
    fputc('\n', build.out);
    if (holy_hash_file(input, digest)) {
        fputs("source-sha256 ", build.out); holy_token(build.out, digest); fputc('\n', build.out);
    }
    fputs("app-id ", build.out); holy_token(build.out, id); fputc('\n', build.out);
    fputs("name ", build.out); holy_token(build.out, name); fputc('\n', build.out);
    fputs("version ", build.out); holy_token(build.out, version); fputc('\n', build.out);
    fputs("release ", build.out); holy_token(build.out, release); fputc('\n', build.out);
    fputs("arch ", build.out); holy_token(build.out, arch); fputc('\n', build.out);
    {
        char named[300];
        snprintf(named, sizeof named, "%s.recipe", name);
        fputs("recipe ", build.out); holy_token(build.out, named); fputc('\n', build.out);
    }
    fprintf(build.out, "status %s\n", build.review ? "review-required" : "native");
    holy_note_environments(build.out, &note);
    for (index = 0; index < note.count; ++index) fprintf(build.out, "%s\n", note.lines[index]);
    fprintf(build.out, "summary carried %zu preserved %zu helper %zu unknown %zu changes %zu\n",
            note.carried, note.preserved, note.helper, note.unknown, note.changes);
    if (fclose(build.out)) { build.out = NULL; goto done; }
    build.out = NULL;
    result = build.review ? 3 : 0;
    printf("converted %s status %s\n", name, build.review ? "review-required" : "native");
    printf("recipe %s\nreport %s\n", recipe_path, report_path);
    if (build.review)
        fputs("holypkg: the converted recipe needs review before its first build\n", stderr);
done:
    if (build.out) fclose(build.out);
    for (i = 0; i < build.patch_count; ++i) free(build.patches[i]);
    free(build.patches);
    for (i = 0; i < build.collected_count; ++i) free(build.collected[i]);
    free(build.collected);
    holy_json_free(manifest);
    free(directory);
    holy_note_free(&note);
    return result;
}
