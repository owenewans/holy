/* Void template to holy-recipe(5) conversion; see man/holy-recipe.5 and man/holypkg.8.
   the template is read as text and no part of it is executed by the converter.
   the xbps-src phase bodies keep their original bash; a step prologue rebuilds the
   xbps-src variables from the exported Holy paths and carries the v* helpers. */
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1
#include "voidsrc.h"
#include "shrecipe.h"

#include <archive.h>
#include <archive_entry.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* drops one layer of shell quoting; an unquoted value is used as written. */

/* the last assignment of a name wins and an appended value follows the earlier one. */

/* the end of a $( ) group that starts at cursor, or NULL when it is unterminated */

/* 1 while a quote is open, so a value may continue on the next line. a $( ) group
   carries its own quoting, so it never closes the quote that contains it. */

/* the closing brace of a function body, ignoring quoted and substituted text. */

/* reads assignments, conditional blocks and function bodies from the template text. */

/* a byte search over a template body; the bodies are short and few */
static const char *find_bytes(const char *body, size_t length, const char *needle)
{
    size_t size = strlen(needle);
    size_t index;
    if (!size || size > length) return NULL;
    for (index = 0; index + size <= length; ++index)
        if (!memcmp(body + index, needle, size)) return body + index;
    return NULL;
}

/* a shell name continues while it is a letter, a digit or an underscore */
static int name_char(char c, int first)
{
    if (isalpha((unsigned char)c) || c == '_') return 1;
    return !first && isdigit((unsigned char)c);
}

static int is_sha256(const char *value)
{
    size_t i;
    for (i = 0; i < 64; ++i)
        if (!isxdigit((unsigned char)value[i])) return 0;
    return !value[64];
}

/* xbps-src spells a version comparator after the package name without a space. */

/* splits a whitespace separated list into a NULL terminated array of words. */

struct option_set {
    char **names;
    size_t count;
    char **enabled;
    size_t enabled_count;
};

static int option_listed(const struct option_set *set, const char *name)
{
    size_t i;
    for (i = 0; i < set->count; ++i)
        if (!strcmp(set->names[i], name)) return 1;
    return 0;
}

static int option_enabled(const struct option_set *set, const char *name)
{
    size_t i;
    for (i = 0; i < set->enabled_count; ++i)
        if (!strcmp(set->enabled[i], name)) return 1;
    return 0;
}

/* the end of a $( ... ) substitution, or NULL when it is not closed */
static const char *command_end(const char *start, const char *stop)
{
    size_t depth = 0, i;
    char quote = 0;
    for (i = 0; start + i < stop; ++i) {
        char c = start[i];
        if (quote) {
            if (c == quote) quote = 0;
            else if (c == '\\' && quote == '"') ++i;
            continue;
        }
        if (c == '\'' || c == '"') { quote = c; continue; }
        if (c == '(') ++depth;
        else if (c == ')') {
            if (!depth) return start + i;
            --depth;
        }
    }
    return NULL;
}

/* replaces one $(vopt_...) call with the value its fixed option set produces. */
static char *option_call(const char *call, size_t length, const struct option_set *set,
                         struct recipe_note *note, int *review, const char *where)
{
    char *inner = holy_shell_copy(call + 2, length - 3);
    char **parts = NULL;
    size_t part_count = 0;
    char *out = NULL;
    const char *function;
    int enabled = 0;
    if (!inner) return NULL;
    parts = holy_shell_words(inner, &part_count);
    free(inner);
    if (!parts || !part_count) { holy_shell_words_free(parts); return NULL; }
    function = parts[0];
    if (!strcmp(function, "vopt_conflict")) {
        /* xbps-src only checks the pair; nothing appears in the built text */
        holy_shell_words_free(parts);
        return holy_shell_copy("", 0);
    }
    if (part_count < 2) {
        holy_note_add(note, "unknown", "helper %s in %s takes no option", function, where);
        *review = 1;
        holy_shell_words_free(parts);
        return NULL;
    }
    if (!option_listed(set, parts[1])) {
        holy_note_add(note, "unknown", "%s names the option %s, which build_options does not list",
                 function, parts[1]);
        *review = 1;
    }
    enabled = option_enabled(set, parts[1]);
    if (!strcmp(function, "vopt_if")) {
        const char *yes = part_count > 2 ? parts[2] : "";
        const char *no = part_count > 3 ? parts[3] : "";
        out = holy_shell_copy(enabled ? yes : no, strlen(enabled ? yes : no));
    } else if (!strcmp(function, "vopt_with")) {
        const char *flag = part_count > 2 ? parts[2] : parts[1];
        char text[512];
        snprintf(text, sizeof text, enabled ? "--with-%s" : "--without-%s", flag);
        out = holy_shell_copy(text, strlen(text));
    } else if (!strcmp(function, "vopt_enable")) {
        const char *flag = part_count > 2 ? parts[2] : parts[1];
        char text[512];
        snprintf(text, sizeof text, enabled ? "--enable-%s" : "--disable-%s", flag);
        out = holy_shell_copy(text, strlen(text));
    } else if (!strcmp(function, "vopt_bool") || !strcmp(function, "vopt_feature")) {
        const char *property = part_count > 2 ? parts[2] : parts[1];
        char text[512];
        if (!strcmp(function, "vopt_bool"))
            snprintf(text, sizeof text, "-D%s=%s", property, enabled ? "true" : "false");
        else
            snprintf(text, sizeof text, "-D%s=%s", property, enabled ? "enabled" : "disabled");
        out = holy_shell_copy(text, strlen(text));
    } else {
        holy_note_add(note, "unknown", "helper %s in %s", function, where);
        *review = 1;
    }
    holy_shell_words_free(parts);
    return out;
}

static void option_set_free(struct option_set *set)
{
    size_t i;
    holy_shell_words_free(set->names);
    for (i = 0; i < set->enabled_count; ++i) free(set->enabled[i]);
    free(set->enabled);
    memset(set, 0, sizeof *set);
}

static void option_set_read(struct option_set *set, const struct shell_script *pkg)
{
    char *joined = holy_shell_all(pkg, "build_options");
    char *defaults = holy_shell_all(pkg, "build_options_default");
    memset(set, 0, sizeof *set);
    if (joined) {
        set->names = holy_shell_words(joined, &set->count);
        free(joined);
    }
    if (defaults) {
        size_t count = 0, index;
        char **list = holy_shell_words(defaults, &count);
        free(defaults);
        for (index = 0; index < count; ++index) {
            char **grown;
            /* a ~name entry names no build option, so xbps-src never enables it */
            if (list[index][0] == '~') continue;
            grown = realloc(set->enabled, (set->enabled_count + 2) * sizeof *grown);
            if (!grown) break;
            set->enabled = grown;
            if (!(set->enabled[set->enabled_count] = strdup(list[index]))) break;
            ++set->enabled_count;
            set->enabled[set->enabled_count] = NULL;
        }
        holy_shell_words_free(list);
    }
}

/* fixes every $(vopt_...) call in one value, so the recipe carries no shell helper. */
static char *resolve_options(const struct shell_script *pkg, struct recipe_note *note, int *review,
                             const char *value, const char *where)
{
    struct option_set set;
    char *out = NULL;
    size_t i = 0, used = 0, capacity;
    if (!value) return NULL;
    if (!*value || !strstr(value, "$(")) return holy_shell_copy(value, strlen(value));
    option_set_read(&set, pkg);
    capacity = strlen(value) + 256;
    out = malloc(capacity);
    if (!out) { option_set_free(&set); return NULL; }
    while (value[i]) {
        const char *close;
        char *replacement;
        size_t size;
        if (value[i] != '$' || value[i + 1] != '(') {
            while (used + 2 > capacity) {
                char *grown = realloc(out, capacity * 2);
                if (!grown) { free(out); option_set_free(&set); return NULL; }
                capacity *= 2;
                out = grown;
            }
            out[used++] = value[i++];
            continue;
        }
        close = command_end(value + i + 2, value + strlen(value));
        if (!close || strncmp(value + i + 2, "vopt_", 5)) {
            while (used + 2 > capacity) {
                char *grown = realloc(out, capacity * 2);
                if (!grown) { free(out); option_set_free(&set); return NULL; }
                capacity *= 2;
                out = grown;
            }
            out[used++] = value[i++];
            continue;
        }
        replacement = option_call(value + i, (size_t)(close - value - i) + 1, &set,
                                  note, review, where);
        if (!replacement) { free(out); option_set_free(&set); return NULL; }
        size = strlen(replacement);
        while (used + size + 2 > capacity) {
            char *grown = realloc(out, capacity * 2);
            if (!grown) { free(replacement); free(out); option_set_free(&set); return NULL; }
            capacity *= 2;
            out = grown;
        }
        memcpy(out + used, replacement, size);
        used += size;
        free(replacement);
        i = (size_t)(close - value) + 1;
    }
    out[used] = 0;
    option_set_free(&set);
    return out;
}

/* the v* helpers a carried body may call, with the place they land in the payload */
static const struct {
    const char *name;
    const char *code;
} helper_functions[] = {
    { "vinstall", "vinstall() {\n"
      "\tif [ $# -lt 3 ]; then echo \"vinstall: <file> <mode> <target-directory>\" >&2; return 1; fi\n"
      "\ttargetfile=${4:-${1##*/}}\n"
      "\tinstall -Dm$2 \"$1\" \"$PKGDESTDIR/$3/${targetfile##*/}\"\n"
      "}\n" },
    { "vcopy", "vcopy() {\n"
      "\tif [ $# -ne 2 ]; then echo \"vcopy: <files> <target-directory>\" >&2; return 1; fi\n"
      "\tset -f\n"
      "\t# shellcheck disable=SC2086\n"
      "\tcp -a $1 \"$PKGDESTDIR/$2\"\n"
      "\tset +f\n"
      "}\n" },
    { "vmove", "vmove() {\n"
      "\tif [ \"$DESTDIR\" = \"$PKGDESTDIR\" ]; then\n"
      "\t\techo \"vmove is intended to be used in pkg_install\" >&2\n"
      "\t\treturn 1\n"
      "\tfi\n"
      "\ttargetdir=\"\"\n"
      "\tfor f in $1; do targetdir=\"${f%/*}/\"; break; done\n"
      "\tif [ -z \"$targetdir\" ]; then\n"
      "\t\tinstall -d \"$PKGDESTDIR\"\n"
      "\t\t# shellcheck disable=SC2086\n"
      "\t\tmv \"$DESTDIR\"/$1 \"$PKGDESTDIR\"\n"
      "\telse\n"
      "\t\tinstall -d \"$PKGDESTDIR/$targetdir\"\n"
      "\t\t# shellcheck disable=SC2086\n"
      "\t\tmv \"$DESTDIR\"/$1 \"$PKGDESTDIR/$targetdir\"\n"
      "\tfi\n"
      "}\n" },
    { "vmkdir", "vmkdir() {\n"
      "\tif [ -z \"$1\" ]; then echo \"vmkdir: directory argument unset\" >&2; return 1; fi\n"
      "\tif [ -z \"$2\" ]; then install -d \"$PKGDESTDIR/$1\"; else install -dm$2 \"$PKGDESTDIR/$1\"; fi\n"
      "}\n" },
    { "vbin", "vbin() {\n"
      "\tvinstall \"$1\" 755 usr/bin \"${2:-}\"\n"
      "}\n" },
    { "vdoc", "vdoc() {\n"
      "\tvinstall \"$1\" 644 \"usr/share/doc/$pkgname\" \"${2:-}\"\n"
      "}\n" },
    { "vconf", "vconf() {\n"
      "\tvinstall \"$1\" 644 etc \"${2:-}\"\n"
      "}\n" },
    { "vsconf", "vsconf() {\n"
      "\tvinstall \"$1\" 644 \"usr/share/examples/$pkgname\" \"${2:-}\"\n"
      "}\n" },
    { "vlicense", "vlicense() {\n"
      "\tvinstall \"$1\" 644 \"usr/share/licenses/$pkgname\" \"${2:-}\"\n"
      "}\n" }
};

/* notes every helper and variable a body uses that the conversion cannot supply */
static void report_unknowns(const char *body, size_t length, struct recipe_note *note, int *review,
                            const char *where, int files, int patches)
{
    static const struct {
        const char *token;
        const char *text;
    } unresolved[] = {
        { "vman", "helper vman is not carried" },
        { "vsv", "helper vsv is not carried" },
        { "vcompletion", "helper vcompletion is not carried" },
        { "vsed", "helper vsed is not carried" },
        { "vsrccopy", "helper vsrccopy is not carried" },
        { "vsrcextract", "helper vsrcextract is not carried" },
        { "msg_error", "helper msg_error is not carried" },
        { "msg_normal", "helper msg_normal is not carried" },
        { "msg_warn", "helper msg_warn is not carried" },
        { "msg_red", "helper msg_red is not carried" },
        { "msg_verbose", "helper msg_verbose is not carried" },
        { "msgfunc", "helper msgfunc is not carried" },
        { "vsrcextract", "helper vsrcextract is not carried" },
        { "xbps_uhelper", "helper xbps_uhelper is not carried" },
        { "XBPS_CROSS_", "cross build environment is not carried" },
        { "XBPS_MAKEJOBS_ORIG", "parallel build override is not carried" },
        { "XBPS_ORIG_MAKEJOBS", "parallel build override is not carried" },
        { "XBPS_VERBOSE", "verbose build flag is not carried" },
        { "XBPS_BUILD_OPTIONS", "build option state is not carried" },
        { "build_option_", "build_option_ test is not carried" },
        { "INSTALL.msg", "INSTALL.msg is not carried" },
        { "REMOVE.msg", "REMOVE.msg is not carried" }
    };
    static const char *const variables[] = {
        "FILESDIR", "PATCHESDIR", "XBPS_CROSS_TRIPLET", "XBPS_CROSS_BASE", "XBPS_TARGET_QEMU_MACHINE",
        "XBPS_PKGSRCDIR", "XBPS_SRCPKGDIR", "XBPS_COMMONDIR", "XBPS_BUILDHELPERDIR", "CHROOT_READY",
        "XBPS_CHECK_PKGS", "XBPS_ARCH", "XBPS_MACHINE", "XBPS_TARGET_ARCH", "XBPS_TARGET_MACHINE",
        "XBPS_DESTDIR", "XBPS_BUILD_FORCEMODE", "XBPS_STRICT", NULL
    };
    size_t index;
    for (index = 0; index < sizeof unresolved / sizeof *unresolved; ++index)
        if (find_bytes(body, length, unresolved[index].token)) {
            holy_note_add(note, "unknown", "%s in %s", unresolved[index].text, where);
            *review = 1;
        }
    for (index = 0; variables[index]; ++index) {
        char braced[80];
        if (!strcmp(variables[index], "FILESDIR") && files) continue;
        if (!strcmp(variables[index], "PATCHESDIR") && patches) continue;
        snprintf(braced, sizeof braced, "${%s}", variables[index]);
        if (find_bytes(body, length, braced)) {
            holy_note_add(note, "unknown", "variable %s in %s", variables[index], where);
            *review = 1;
        }
    }
}

/* a carried body needs the v* helpers when it calls one of them */
static int body_uses_helper(const char *body, size_t length)
{
    size_t index;
    for (index = 0; index < sizeof helper_functions / sizeof *helper_functions; ++index)
        if (find_bytes(body, length, helper_functions[index].name)) return 1;
    return 0;
}

/* the xbps-src variables the step prologue rebuilds from the exported paths */
static char *prologue(const struct shell_script *pkg, const char *name, const char *version,
                      const char *release, const char *pkgdir, int helpers, int files, int patches,
                      int split)
{
    static const char *const carried[] = {
        "configure_args", "make_build_args", "make_check_args", "make_install_args",
        "make_build_target", "make_check_target", "make_install_target", "make_check_pre",
        "make_cmd", "configure_script", "patch_args", "build_wrksrc", "cmake_builddir",
        "meson_builddir", "gem_cmd", "meson_cmd", "go_import_path", NULL
    };
    char *text = NULL;
    size_t used = 0, index;
    FILE *out = open_memstream(&text, &used);
    if (!out) return NULL;
    fputs("# xbps-src variables rebuilt from the exported Holy paths\n", out);
    fprintf(out, "pkgname=%s\nversion=%s\nrevision=%s\n", name, version, release);
    fprintf(out, "sourcepkg=\"%s-%s_%s\"\npkgver=\"%s-%s_%s\"\n", name, version, release,
            name, version, release);
    fputs("wrksrc=\"$HOLY_SRC\"\nbuild_wrksrc=\"$HOLY_SRC\"\nmasterdir=\"$HOLY_WORK\"\n", out);
    fputs("XBPS_SRCDIR=\"$HOLY_WORK/sources\"\nXBPS_BUILDDIR=\"$HOLY_BUILD\"\n", out);
    fputs("XBPS_MACHINE=\"$HOLY_ARCH\"\nXBPS_ARCH=\"$HOLY_ARCH\"\n", out);
    fputs("XBPS_TARGET_MACHINE=\"$HOLY_BUILD_TARGET\"\nXBPS_MAKEJOBS=\"$HOLY_JOBS\"\n", out);
    fputs("makejobs=\"-j$HOLY_JOBS\"\n", out);
    /* DESTDIR stays the main tree so a vmove in a subpackage has something to move */
    fprintf(out, "DESTDIR=\"%s\"\n", split ? "$HOLY_DEST" : pkgdir);
    fprintf(out, "PKGDESTDIR=\"%s\"\n", pkgdir);
    fputs("CFLAGS=${CFLAGS:--O2 -pipe}\nCXXFLAGS=${CXXFLAGS:-$CFLAGS}\n", out);
    fputs("CPPFLAGS=${CPPFLAGS:-}\nLDFLAGS=${LDFLAGS:--Wl,-z,relro -Wl,--as-needed}\n", out);
    if (files) fputs("FILESDIR=\"$HOLY_SRC/files\"\n", out);
    if (patches) fputs("PATCHESDIR=\"$HOLY_SRC/patches\"\n", out);
    for (index = 0; carried[index]; ++index) {
        char *value, *fixed;
        struct recipe_note ignored;
        int flag = 0;
        memset(&ignored, 0, sizeof ignored);
        if (!holy_shell_present(pkg, carried[index])) continue;
        value = holy_shell_join(pkg, carried[index]);
        if (!value || !*value) { free(value); continue; }
        /* a build option call in a variable is fixed before it reaches the prologue */
        fixed = resolve_options(pkg, &ignored, &flag, value, carried[index]);
        if (strpbrk(value, "\n\"\\")) {
            fprintf(out, "# %s is not a single line assignment and stays out of the prologue\n",
                    carried[index]);
        } else {
            fprintf(out, "%s=\"%s\"\n", carried[index], fixed ? fixed : value);
        }
        free(fixed);
        free(value);
    }
    if (helpers) {
        fputs("# v* helpers carried from common/environment/setup/install.sh\n", out);
        for (index = 0; index < sizeof helper_functions / sizeof *helper_functions; ++index)
            fputs(helper_functions[index].code, out);
    }
    fclose(out);
    return text;
}

static int add_tree(struct archive *writer, const char *root, const char *prefix)
{
    DIR *directory = opendir(root);
    struct dirent *entry;
    int result = 1;
    if (!directory) return 0;
    while ((entry = readdir(directory))) {
        char child[4096], name[4096];
        struct stat st;
        struct archive_entry *item;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        snprintf(child, sizeof child, "%s/%s", root, entry->d_name);
        snprintf(name, sizeof name, "%s/%s", prefix, entry->d_name);
        if (lstat(child, &st)) { result = 0; break; }
        item = archive_entry_new();
        if (!item) { result = 0; break; }
        archive_entry_set_pathname(item, name);
        archive_entry_set_perm(item, st.st_mode & 07777);
        archive_entry_set_uid(item, st.st_uid);
        archive_entry_set_gid(item, st.st_gid);
        archive_entry_set_mtime(item, 0, 0);
        if (S_ISDIR(st.st_mode)) {
            archive_entry_set_filetype(item, AE_IFDIR);
            archive_entry_set_size(item, 0);
            if (archive_write_header(writer, item) != ARCHIVE_OK) result = 0;
            archive_entry_free(item);
            if (!result || !add_tree(writer, child, name)) { result = 0; break; }
            continue;
        }
        if (S_ISLNK(st.st_mode)) {
            char target[4096];
            ssize_t size = readlink(child, target, sizeof target - 1);
            if (size < 0) { archive_entry_free(item); result = 0; break; }
            target[size] = 0;
            archive_entry_set_filetype(item, AE_IFLNK);
            archive_entry_set_symlink(item, target);
            archive_entry_set_size(item, 0);
        } else if (S_ISREG(st.st_mode)) {
            unsigned char buffer[65536];
            FILE *in = fopen(child, "rb");
            size_t got;
            if (!in) { archive_entry_free(item); result = 0; break; }
            archive_entry_set_filetype(item, AE_IFREG);
            archive_entry_set_size(item, st.st_size);
            if (archive_write_header(writer, item) != ARCHIVE_OK) {
                fclose(in);
                archive_entry_free(item);
                result = 0;
                break;
            }
            while ((got = fread(buffer, 1, sizeof buffer, in)) > 0)
                if (archive_write_data(writer, buffer, got) != (ssize_t)got) { result = 0; break; }
            if (ferror(in)) result = 0;
            fclose(in);
        } else {
            archive_entry_free(item);
            result = 0;
            break;
        }
        archive_entry_free(item);
        if (!result) break;
    }
    closedir(directory);
    return result;
}

/* the files or patches directory travels as one archive the build can stage */
static int write_tree(const char *root, const char *prefix, const char *target, char digest[65])
{
    struct archive *writer = archive_write_new();
    int result = 0;
    if (!writer) return 0;
    if (archive_write_set_format_pax_restricted(writer) != ARCHIVE_OK ||
        archive_write_open_filename(writer, target) != ARCHIVE_OK) goto done;
    result = add_tree(writer, root, prefix);
done:
    if (archive_write_close(writer) != ARCHIVE_OK) result = 0;
    archive_write_free(writer);
    if (!result) { unlink(target); return 0; }
    return holy_hash_file(target, digest);
}

/* the identity a distfile may name; every other expansion stays unknown */
static const char *identity_value(const char *word, const char *name, const char *version,
                                  const char *release, char *out, size_t size)
{
    if (!strcmp(word, "pkgname") || !strcmp(word, "pkgbase"))
        snprintf(out, size, "%s", name);
    else if (!strcmp(word, "version"))
        snprintf(out, size, "%s", version);
    else if (!strcmp(word, "revision"))
        snprintf(out, size, "%s", release);
    else if (!strcmp(word, "sourcepkg") || !strcmp(word, "pkgver"))
        snprintf(out, size, "%s-%s_%s", name, version, release);
    else
        return NULL;
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

/* expands the identity variables in one distfile or patch entry and flags the rest. */
static char *expand_names(const char *value, const char *name, const char *version,
                          const char *release, int *unknown)
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
            if (value[start] != '}') { *unknown = 1; goto failed_unexpanded; }
            word[length] = 0;
            resolved = identity_value(word, name, version, release, replacement, sizeof replacement);
            if (!resolved) { *unknown = 1; goto failed_unexpanded; }
            if (!append_text(&out, &used, &capacity, resolved, strlen(resolved))) goto failed;
            i = start + 1;
            continue;
        }
        if (!name_char(value[i + 1], 0)) {
            if (!append_text(&out, &used, &capacity, value + i, 1)) goto failed;
            ++i;
            continue;
        }
        start = i + 1;
        while (value[start] && name_char(value[start], 0) && length + 1 < sizeof word)
            word[length++] = value[start++];
        word[length] = 0;
        resolved = identity_value(word, name, version, release, replacement, sizeof replacement);
        if (!resolved) { *unknown = 1; goto failed_unexpanded; }
        if (!append_text(&out, &used, &capacity, resolved, strlen(resolved))) goto failed;
        i = start;
    }
    return out;
failed_unexpanded:
    /* an expansion this converter does not know keeps its text and needs review */
    if (!append_text(&out, &used, &capacity, value + i, strlen(value + i))) {
        free(out);
        return NULL;
    }
    return out;
failed:
    free(out);
    return NULL;
}

struct phase_map {
    const char *holy;
    const char *pre;
    const char *body;
    const char *post;
};

static const struct phase_map phase_maps[] = {
    { "fetch", "pre_fetch", "do_fetch", "post_fetch" },
    { "unpack", "pre_extract", "do_extract", "post_extract" },
    { "prepare", "pre_patch", "do_patch", "post_patch" },
    { "configure", "pre_configure", "do_configure", "post_configure" },
    { "build", "pre_build", "do_build", "post_build" },
    { "check", "pre_check", "do_check", "post_check" },
    { "package", "pre_install", "do_install", "post_install" }
};

static int is_phase_function(const char *name)
{
    size_t index;
    for (index = 0; index < sizeof phase_maps / sizeof *phase_maps; ++index)
        if (!strcmp(name, phase_maps[index].pre) || !strcmp(name, phase_maps[index].body) ||
            !strcmp(name, phase_maps[index].post)) return 1;
    return 0;
}

static int write_body(FILE *out, const char *body, size_t length)
{
    if (!length) return 1;
    if (fwrite(body, 1, length, out) != length) return 0;
    if (body[length - 1] != '\n' && fputc('\n', out) == EOF) return 0;
    return 1;
}

/* the prologue, an optional lead and tail, then the carried bodies in xbps-src order */
static int emit_body(FILE *out, const char *prefix, const char *lead, const char *tail,
                     char *const *bodies, size_t body_count, const char *tag)
{
    size_t index;
    if (fputs(prefix, out) < 0) return 0;
    if (lead && fputs(lead, out) < 0) return 0;
    for (index = 0; index < body_count; ++index) {
        if (!bodies[index]) continue;
        if (!write_body(out, bodies[index], strlen(bodies[index]))) return 0;
    }
    if (tail && fputs(tail, out) < 0) return 0;
    return fprintf(out, "%s\n", tag) >= 0;
}

static int emit_phase_step(FILE *out, const char *phase, const char *prefix, const char *lead,
                           const char *tail, char *const *bodies, size_t body_count)
{
    if (fprintf(out, "step %s /bin/bash <<STEP\n", phase) < 0) return 0;
    return emit_body(out, prefix, lead, tail, bodies, body_count, "STEP");
}

static int emit_split_step(FILE *out, const char *output, const char *prefix, const char *body)
{
    char *bodies[1];
    bodies[0] = (char *)body;
    if (fprintf(out, "split-step %s split /bin/bash <<SPLIT\n", output) < 0) return 0;
    return emit_body(out, prefix, NULL, NULL, bodies, 1, "SPLIT");
}

/* the assignments a subpackage function makes outside its pkg_install body. Holy has one
   depend list per recipe, so these are reported rather than moved into the main output. */
static void split_records(struct recipe_note *note, int *review, const struct shell_function *function,
                          const char *const *keys, size_t key_count)
{
    size_t index, start = 0, line = function->first + 1;
    for (start = 0; start <= function->length; ) {
        size_t end = start, at = 0;
        while (end < function->length && function->body[end] != '\n') ++end;
        while (at < end - start && (function->body[start + at] == ' ' ||
                                    function->body[start + at] == '\t')) ++at;
        for (index = 0; index < key_count; ++index) {
            size_t size = strlen(keys[index]);
            if (end - start < at + size + 1) continue;
            if (strncmp(function->body + start + at, keys[index], size)) continue;
            if (function->body[start + at + size] != '=' &&
                function->body[start + at + size] != '+') continue;
            *review = 1;
            holy_note_add(note, "preserved", "%s %.*s template:%zu", keys[index],
                     (int)(end - start - at), function->body + start + at, line);
        }
        if (end < function->length) ++line;
        start = end + 1;
    }
}

/* the pkg_install body inside a subpackage function fills one staging tree */
static int split_body(const struct shell_function *function, struct shell_function *out)
{
    static const char *const marker = "pkg_install()";
    const char *at = memmem(function->body, function->length, marker, strlen(marker));
    const char *brace, *close;
    size_t line = function->first, index;
    if (!at) return 0;
    brace = memchr(at, '{', function->length - (size_t)(at - function->body));
    if (!brace) return 0;
    close = holy_shell_block_end(brace + 1, function->body + function->length);
    if (!close) return 0;
    for (index = 0; function->body + index < brace + 1; ++index)
        if (function->body[index] == '\n') ++line;
    memset(out, 0, sizeof *out);
    out->name = strdup("pkg_install");
    out->body = holy_shell_copy(brace + 1, (size_t)(close - brace - 1));
    out->length = (size_t)(close - brace - 1);
    out->first = line;
    out->last = line;
    out->conditional = function->conditional;
    if (!out->name || !out->body) {
        free(out->name);
        free(out->body);
        memset(out, 0, sizeof *out);
        return 0;
    }
    return 1;
}

int holy_convert_voidsrc(const char *input, const char *source, const char *output)
{
    struct shell_script pkg = {0};
    struct recipe_note note = {0};
    struct { char name[512]; struct shell_function install; } splits[16];
    char name[512] = {0}, version[512] = {0}, release[64] = {0};
    char *summary = NULL, *homepage = NULL, *license = NULL, *maintainer = NULL;
    char *style = NULL, *distfiles = NULL, *checksum = NULL;
    char recipe_path[4096], report_path[4096], target[4096];
    char hook_list[256] = {0};
    char hash[65] = {0};
    FILE *out = NULL;
    size_t splits_used = 0, hooks_used = 0, k, index;
    int result = 1, review = 0, helpers = 0, files = 0, patches = 0, i, wrote = 1;

    if (!input || !output || !*output) {
        fputs("usage: holypkg convert TEMPLATE --source NAME --output NEW_DIRECTORY\n", stderr);
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
    if (result) goto done;

    {
        const char *declared = holy_shell_join(&pkg, "pkgname");
        const char *given_version = holy_shell_join(&pkg, "version");
        const char *given_release = holy_shell_join(&pkg, "revision");
        if (!declared || !given_version || !given_release) {
            fputs("holypkg: template: pkgname, version and revision are required\n", stderr);
            free((char *)declared);
            free((char *)given_version);
            free((char *)given_release);
            result = 2;
            goto done;
        }
        if (strpbrk(declared, "$`") || strpbrk(given_version, "$`") ||
            strpbrk(given_release, "$`") || strlen(declared) > 480 ||
            strlen(given_version) > 480 || strlen(given_release) > 60) {
            fputs("holypkg: template: identity must be literal and short\n", stderr);
            free((char *)declared);
            free((char *)given_version);
            free((char *)given_release);
            result = 2;
            goto done;
        }
        snprintf(name, sizeof name, "%s", declared);
        snprintf(version, sizeof version, "%s", given_version);
        snprintf(release, sizeof release, "%s", given_release);
        free((char *)declared);
        free((char *)given_version);
        free((char *)given_release);
    }
    summary = holy_shell_join(&pkg, "short_desc");
    homepage = holy_shell_join(&pkg, "homepage");
    license = holy_shell_all(&pkg, "license");
    maintainer = holy_shell_all(&pkg, "maintainer");
    style = holy_shell_join(&pkg, "build_style");
    if (!result && pkg.condition_count) {
        for (k = 0; k < pkg.condition_count; ++k) {
            const char *text = pkg.conditions[k].text;
            review = 1;
            if (!strncmp(text, "vopt_conflict", 13))
                holy_note_add(&note, "semantic-change",
                         "vopt_conflict checked against the fixed option set template:%zu %s",
                         pkg.conditions[k].line, text);
            else
                holy_note_add(&note, "unknown", "conditional block template:%zu %s",
                         pkg.conditions[k].line, text);
        }
    }
    for (k = 0; k < pkg.value_count; ++k) {
        if (!pkg.values[k].conditional) continue;
        review = 1;
        holy_note_add(&note, "unknown", "conditional assignment %s template:%zu",
                 pkg.values[k].name, pkg.values[k].line);
    }
    holy_note_add(&note, "carried", "name template:%zu", holy_shell_line(&pkg, "pkgname"));
    holy_note_add(&note, "carried", "version template:%zu", holy_shell_line(&pkg, "version"));
    holy_note_add(&note, "carried", "release template:%zu", holy_shell_line(&pkg, "revision"));
    if (summary && *summary) holy_note_add(&note, "carried", "short_desc template:%zu",
                                      holy_shell_line(&pkg, "short_desc"));
    if (homepage && *homepage) holy_note_add(&note, "carried", "homepage template:%zu",
                                        holy_shell_line(&pkg, "homepage"));
    if (license && *license) holy_note_add(&note, "carried", "license template:%zu",
                                      holy_shell_line(&pkg, "license"));
    if (maintainer && *maintainer) holy_note_add(&note, "carried", "maintainer template:%zu",
                                            holy_shell_line(&pkg, "maintainer"));

    /* the subpackage functions become one output each */
    for (k = 0; k < pkg.function_count; ++k) {
        const struct shell_function *function = &pkg.functions[k];
        size_t name_length = strlen(function->name);
        if (name_length <= 8 || strcmp(function->name + name_length - 8, "_package")) {
            /* a phase function belongs to a step; anything else has no place here */
            if (is_phase_function(function->name)) continue;
            review = 1;
            if (!strcmp(function->name, "do_clean"))
                holy_note_add(&note, "unknown", "do_clean runs after the package step and has no "
                         "Holy phase template:%zu-%zu", function->first, function->last);
            else
                holy_note_add(&note, "unknown", "function %s template:%zu-%zu", function->name,
                         function->first, function->last);
            continue;
        }
        if (function->name[strlen(name)] == '_' && !strncmp(function->name, name, strlen(name))) {
            review = 1;
            holy_note_add(&note, "unknown", "function %s names the main package template:%zu-%zu",
                     function->name, function->first, function->last);
            continue;
        }
        if (splits_used >= sizeof splits / sizeof *splits) {
            review = 1;
            holy_note_add(&note, "unknown", "more subpackage functions than outputs are carried "
                     "template:%zu", function->first);
            continue;
        }
        if (!split_body(function, &splits[splits_used].install)) {
            review = 1;
            holy_note_add(&note, "unknown", "subpackage %s has no pkg_install template:%zu-%zu",
                     function->name, function->first, function->last);
            continue;
        }
        snprintf(splits[splits_used].name, sizeof splits[splits_used].name, "%.*s",
                 (int)(name_length - 8), function->name);
        split_records(&note, &review, function,
                      (const char *[]){ "depends", "replaces", "conflicts", "short_desc" },
                      4);
        if (function->conditional) {
            review = 1;
            holy_note_add(&note, "unknown", "subpackage %s is defined in a conditional block "
                     "template:%zu", splits[splits_used].name, function->first);
        }
        holy_note_add(&note, "preserved", "subpackage %s template:%zu-%zu", splits[splits_used].name,
                 function->first, function->last);
        ++splits_used;
    }

    if (mkdir(output, 0700) && errno != EEXIST) {
        fprintf(stderr, "holypkg: conversion directory unavailable: %s\n", output);
        result = 1;
        goto done;
    }
    snprintf(target, sizeof target, "%s/template", output);
    if (!holy_copy_and_hash(input, target, hash)) {
        fputs("holypkg: template copy failed\n", stderr);
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
    fputs("\narch any\nlibc any\n", out);
    if (summary && *summary) { fputs("summary ", out); holy_token(out, summary); fputc('\n', out); }
    if (homepage && *homepage) { fputs("homepage ", out); holy_token(out, homepage); fputc('\n', out); }
    if (license && *license) { fputs("license ", out); holy_token(out, license); fputc('\n', out); }
    fputs("x-source-family xbps\nx-converter voidsrc-1\n", out);
    if (maintainer && *maintainer) {
        fputs("x-maintainer ", out); holy_token(out, maintainer); fputc('\n', out);
    }
    {
        char *changelog = holy_shell_all(&pkg, "changelog");
        if (changelog && *changelog) {
            fputs("x-changelog ", out); holy_token(out, changelog); fputc('\n', out);
            holy_note_add(&note, "carried", "changelog template:%zu", holy_shell_line(&pkg, "changelog"));
        }
        free(changelog);
    }
    if (style && *style) {
        fputs("x-build-style ", out); holy_token(out, style); fputc('\n', out);
    }
    {
        static const char *const preserved[] = {
            "build_options", "build_options_default", "build_helper", "bootstrap", "nocross",
            "broken", "restricted", "repository", "tags", "archs", "subpackages", "skip_extraction",
            "shlib_provides", "shlib_requires", "make_dirs", "alternatives", "font_dirs",
            "dkms_modules", "register_shell", "preserve", "nodebug", "nostrip", "nostrip_files",
            "noshlibprovides", "noverifyrdeps", "skiprdeps", "ignore_elf_files", "ignore_elf_dirs",
            "nopie", "nopie_files", "disable_parallel_build", "disable_parallel_check",
            "make_check", "keep_libtool_archives", "make_use_env", "create_wrksrc",
            "conf_files", "mutable_files", "reverts", "fetch_cmd", "disabled", NULL
        };
        for (index = 0; preserved[index]; ++index) {
            char *value;
            char *fixed;
            if (!holy_shell_present(&pkg, preserved[index])) continue;
            fixed = resolve_options(&pkg, &note, &review, holy_shell_all(&pkg, preserved[index]),
                                    preserved[index]);
            if (!fixed) { wrote = 0; break; }
            value = fixed;
            if (!strcmp(preserved[index], "build_options_default")) {
                review = 1;
                holy_note_add(&note, "semantic-change", "build options fixed to build_options_default "
                         "template:%zu", holy_shell_line(&pkg, preserved[index]));
            } else {
                review = 1;
                holy_note_add(&note, "preserved", "%s template:%zu", preserved[index],
                         holy_shell_line(&pkg, preserved[index]));
            }
            fputs("x-", out);
            fputs(preserved[index], out);
            fputc(' ', out);
            holy_token(out, value);
            fputc('\n', out);
            free(value);
        }
        if (!wrote) { result = 1; goto done; }
    }

    /* distfiles with their checksum entries */
    distfiles = holy_shell_all(&pkg, "distfiles");
    checksum = holy_shell_all(&pkg, "checksum");
    {
        size_t distfile_count = 0, digest_count = 0;
        char **urls = distfiles ? holy_shell_words(distfiles, &distfile_count) : NULL;
        char **digests = checksum ? holy_shell_words(checksum, &digest_count) : NULL;
        if (distfile_count && !digest_count) {
            review = 1;
            holy_note_add(&note, "unknown", "distfiles without a checksum template:%zu",
                     holy_shell_line(&pkg, "distfiles"));
        }
        for (k = 0; k < distfile_count; ++k) {
            const char *entry = urls[k];
            char *url;
            const char *base;
            char ignored[65], copied[4096], original[4096];
            struct stat st;
            int unknown = 0;
            int ok = 1;
            if (strchr(entry, '>')) {
                const char *after = strchr(entry, '>') + 1;
                review = 1;
                holy_note_add(&note, "semantic-change", "mirror name in distfile %s dropped", entry);
                entry = after;
            }
            url = expand_names(entry, name, version, release, &unknown);
            if (!url || !*url) ok = 0;
            if (ok && unknown) {
                review = 1;
                holy_note_add(&note, "unknown", "distfile %s uses an expansion this converter "
                         "does not know template:%zu", entry, holy_shell_line(&pkg, "distfiles"));
                ok = 0;
            }
            base = url ? strrchr(url, '/') : NULL;
            base = base ? base + 1 : url;
            if (ok && (!base || !*base || strlen(base) > 400 || strpbrk(base, " \t$`'\"")))
                ok = 0;
            if (ok && !strpbrk(url, ":/")) {
                snprintf(original, sizeof original, "%s/%s", pkg.directory, url);
                snprintf(copied, sizeof copied, "%s/%s", output, base);
                if (stat(original, &st) || !S_ISREG(st.st_mode) ||
                    !holy_copy_and_hash(original, copied, ignored)) {
                    review = 1;
                    holy_note_add(&note, "unknown", "distfile %s is not next to the template "
                             "template:%zu", url, holy_shell_line(&pkg, "distfiles"));
                    ok = 0;
                } else {
                    holy_note_add(&note, "semantic-change", "local distfile %s copied next to the "
                             "recipe", url);
                }
            }
            if (!ok) {
                if (url) holy_note_add(&note, "unknown", "source %s template:%zu", entry,
                                  holy_shell_line(&pkg, "distfiles"));
                free(url);
                continue;
            }
            fputs("source ", out);
            holy_token(out, base);
            fputc(' ', out);
            holy_token(out, url);
            fputc('\n', out);
            if (k < digest_count && digests[k][0] == '@') {
                review = 1;
                holy_note_add(&note, "unknown", "contents checksum for %s template:%zu", base,
                         holy_shell_line(&pkg, "checksum"));
            } else if (k < digest_count && is_sha256(digests[k])) {
                fputs("source-sha256 ", out);
                holy_token(out, base);
                fputc(' ', out);
                holy_token(out, digests[k]);
                fputc('\n', out);
            } else {
                review = 1;
                holy_note_add(&note, "unknown", "source %s has no sha256 checksum template:%zu", base,
                         holy_shell_line(&pkg, "distfiles"));
            }
            holy_note_add(&note, "carried", "distfiles %s template:%zu", entry,
                     holy_shell_line(&pkg, "distfiles"));
            free(url);
        }
        holy_shell_words_free(urls);
        holy_shell_words_free(digests);
    }
    /* the files and patches directories travel as archives the build can stage */
    {
        static const char *const trees[] = { "files", "patches", NULL };
        for (index = 0; trees[index]; ++index) {
            char root[4096], archive[4096];
            char digest[65];
            struct stat st;
            size_t count = 0;
            snprintf(root, sizeof root, "%s/%s", pkg.directory, trees[index]);
            if (stat(root, &st) || !S_ISDIR(st.st_mode)) continue;
            {
                DIR *directory = opendir(root);
                struct dirent *entry;
                if (!directory) continue;
                while ((entry = readdir(directory))) ++count;
                closedir(directory);
            }
            /* an empty or placeholder directory carries nothing into the build */
            if (count <= 2) continue;
            snprintf(archive, sizeof archive, "%s/%s.tar", output, trees[index]);
            if (!write_tree(root, trees[index], archive, digest)) {
                wrote = 0;
                break;
            }
            if (!strcmp(trees[index], "files")) files = 1;
            else patches = 1;
            {
                char named[256];
                snprintf(named, sizeof named, "%s.tar", trees[index]);
                fputs("source ", out);
                holy_token(out, trees[index]);
                fputc(' ', out);
                holy_token(out, named);
                fputc('\n', out);
            }
            fputs("source-sha256 ", out);
            holy_token(out, trees[index]);
            fputc(' ', out);
            holy_token(out, digest);
            fputc('\n', out);
            holy_note_add(&note, "carried", "%s directory beside the template", trees[index]);
            if (patches) {
                holy_note_add(&note, "semantic-change", "the patches directory is applied with "
                         "patch and one .args file per patch");
                fputs("build-depend cmd:patch\n", out);
            }
        }
        if (!wrote) { result = 1; goto done; }
    }

    /* runtime and build dependencies */
    {
        static const char *const build_lists[] = {
            "hostmakedepends", "makedepends", "checkdepends", NULL
        };
        size_t list_index;
        for (list_index = 0; build_lists[list_index]; ++list_index) {
            size_t count = 0;
            char *raw = holy_shell_all(&pkg, build_lists[list_index]);
            char **items = raw ? holy_shell_words(raw, &count) : NULL;
            free(raw);
            for (k = 0; items && k < count; ++k) {
                char *fixed;
                if (strchr(items[k], '<') || strchr(items[k], '>')) {
                    review = 1;
                    holy_note_add(&note, "unknown", "%s %s carries a version template:%zu",
                             build_lists[list_index], items[k],
                             holy_shell_line(&pkg, build_lists[list_index]));
                    continue;
                }
                fixed = resolve_options(&pkg, &note, &review, items[k], build_lists[list_index]);
                if (!fixed) { holy_shell_words_free(items); wrote = 0; break; }
                holy_emit_dependency(out, fixed, "build-depend");
                holy_note_add(&note, "carried", "%s %s template:%zu", build_lists[list_index],
                         items[k], holy_shell_line(&pkg, build_lists[list_index]));
                free(fixed);
            }
            holy_shell_words_free(items);
            if (!wrote) { result = 1; goto done; }
        }
    }
    {
        size_t count = 0;
        char *raw = holy_shell_all(&pkg, "depends");
        char **items = raw ? holy_shell_words(raw, &count) : NULL;
        free(raw);
        for (k = 0; items && k < count; ++k) {
            char *fixed;
            if (!strncmp(items[k], "virtual?", 8)) {
                review = 1;
                holy_note_add(&note, "unknown", "virtual dependency %s template:%zu", items[k],
                         holy_shell_line(&pkg, "depends"));
                continue;
            }
            fixed = resolve_options(&pkg, &note, &review, items[k], "depends");
            if (!fixed) { holy_shell_words_free(items); wrote = 0; break; }
            holy_emit_dependency(out, fixed, "depend");
            holy_note_add(&note, "carried", "depends %s template:%zu", items[k],
                     holy_shell_line(&pkg, "depends"));
            free(fixed);
        }
        holy_shell_words_free(items);
        if (!wrote) { result = 1; goto done; }
    }
    /* the conf_files and mutable_files lists name owned payload paths */
    {
        static const struct { const char *key; const char *flag; } config_keys[] = {
            { "conf_files", NULL }, { "mutable_files", "mutable" }, { NULL, NULL }
        };
        for (index = 0; config_keys[index].key; ++index) {
            size_t count = 0;
            char *raw = holy_shell_all(&pkg, config_keys[index].key);
            char **items = raw ? holy_shell_words(raw, &count) : NULL;
            free(raw);
            for (k = 0; items && k < count; ++k) {
                const char *path = items[k];
                if (path[0] == '/') ++path;
                if (strpbrk(path, "*?[]$`") || path[0] == '/' || !*path) {
                    review = 1;
                    holy_note_add(&note, "unknown", "%s %s is not one payload path template:%zu",
                             config_keys[index].key, items[k],
                             holy_shell_line(&pkg, config_keys[index].key));
                    continue;
                }
                fputs("config ", out);
                holy_token(out, path);
                if (config_keys[index].flag) {
                    fputc(' ', out);
                    fputs(config_keys[index].flag, out);
                }
                fputc('\n', out);
                holy_note_add(&note, "carried", "%s %s template:%zu", config_keys[index].key,
                         items[k], holy_shell_line(&pkg, config_keys[index].key));
            }
            holy_shell_words_free(items);
        }
    }
    /* an INSTALL or REMOVE file beside the template becomes one hook each */
    {
        static const struct { const char *file; const char *key; } hooks_map[] = {
            { "INSTALL", "hook-install" },
            { "REMOVE", "hook-remove" },
            { NULL, NULL }
        };
        for (index = 0; hooks_map[index].file; ++index) {
            char original[4096], copied[4096], installed[600];
            struct stat st;
            char ignored[65];
            snprintf(original, sizeof original, "%s/%s", pkg.directory, hooks_map[index].file);
            if (stat(original, &st) || !S_ISREG(st.st_mode)) continue;
            snprintf(copied, sizeof copied, "%s/%s", output, hooks_map[index].file);
            snprintf(installed, sizeof installed, "usr/share/holy/%s/%s", name,
                     hooks_map[index].file);
            if (!holy_copy_and_hash(original, copied, ignored)) { wrote = 0; break; }
            fputs("source ", out);
            holy_token(out, hooks_map[index].file);
            fputc(' ', out);
            holy_token(out, hooks_map[index].file);
            fputc('\n', out);
            fputs(hooks_map[index].key, out);
            fputc(' ', out);
            fputs("/bin/bash ", out);
            holy_token(out, installed);
            fputc('\n', out);
            snprintf(hook_list + strlen(hook_list),
                     sizeof hook_list - strlen(hook_list), " %s", hooks_map[index].file);
            ++hooks_used;
            review = 1;
            holy_note_add(&note, "preserved", "hook %s", hooks_map[index].file);
            holy_note_add(&note, "semantic-change", "%s runs with ACTION unset, so its pre and post "
                     "branches are not reproduced", hooks_map[index].file);
        }
        if (!wrote) { result = 1; goto done; }
    }

    /* metapackage=yes makes the output empty; any other value leaves it a runtime package */
    {
        char *meta = holy_shell_join(&pkg, "metapackage");
        int empty = meta && *meta && strcmp(meta, "no") && strcmp(meta, "0");
        fputs("output ", out);
        holy_token(out, name);
        fputs(empty ? " metapackage\n" : " runtime\n", out);
        free(meta);
    }
    for (k = 0; k < splits_used; ++k) {
        fputs("output ", out);
        holy_token(out, splits[k].name);
        fputs(" runtime\n", out);
    }
    /* every carried body is scanned once, so the prologue can carry the helpers it needs */
    for (index = 0; index < sizeof phase_maps / sizeof *phase_maps; ++index) {
        const char *slots[3] = { phase_maps[index].pre, phase_maps[index].body,
                                 phase_maps[index].post };
        for (i = 0; i < 3; ++i) {
            const struct shell_function *function = holy_shell_function(&pkg, slots[i]);
            if (!function) continue;
            report_unknowns(function->body, function->length, &note, &review, function->name,
                            files, patches);
            if (body_uses_helper(function->body, function->length)) helpers = 1;
        }
    }
    for (k = 0; k < splits_used; ++k) {
        report_unknowns(splits[k].install.body, splits[k].install.length, &note, &review,
                        splits[k].name, files, patches);
        if (body_uses_helper(splits[k].install.body, splits[k].install.length)) helpers = 1;
    }
    if (helpers)
        holy_note_add(&note, "helper", "v* helpers carried from common/environment/setup/install.sh");
    if (distfiles || hooks_used || files || patches) {
        /* xbps-src moves a single top level directory to $wrksrc, so HOLY_SRC gets the
           content of that directory rather than the directory itself */
        fputs("step unpack /bin/sh <<UNPACK\n"
              "# the archive name and its own top directory both lift into HOLY_SRC\n"
              "while true; do\n"
              "  only=\"\"\n"
              "  for entry in \"$HOLY_SRC\"/*; do\n"
              "    [ -d \"$entry\" ] || continue\n"
              "    case \"$(basename \"$entry\")\" in files|patches) continue;; esac\n"
              "    if [ -z \"$only\" ]; then\n"
              "      only=\"$entry\"\n"
              "    else\n"
              "      only=\"$HOLY_SRC/.keep\"\n"
              "      break\n"
              "    fi\n"
              "  done\n"
              "  [ -n \"$only\" ] && [ \"$only\" != \"$HOLY_SRC/.keep\" ] || break\n"
              "  for child in \"$only\"/* \"$only\"/.[!.]* \"$only\"/..?*; do\n"
              "    [ -e \"$child\" ] || continue\n"
              "    mv \"$child\" \"$HOLY_SRC/\"\n"
              "  done\n"
              "  rmdir \"$only\" 2>/dev/null || break\n"
              "done\n"
              "UNPACK\n", out);
        holy_note_add(&note, "semantic-change", "distfiles are extracted into HOLY_SRC, which takes "
                 "the place of the xbps-src $wrksrc directory");
    }
    {
        static const char *const lead =
            "for patch_file in \"$HOLY_SRC/patches\"/*; do\n"
            "  [ -f \"$patch_file\" ] || continue\n"
            "  patch_name=\"${patch_file##*/}\"\n"
            "  case \"$patch_name\" in *.args) continue;; esac\n"
            "  patch_args=-Np1\n"
            "  [ -f \"$HOLY_SRC/patches/$patch_name.args\" ] &&\n"
            "    patch_args=\"$(cat \"$HOLY_SRC/patches/$patch_name.args\")\"\n"
            "  cp \"$patch_file\" \"$HOLY_SRC/\"\n"
            "  case \"$patch_name\" in\n"
            "    *.gz) gunzip -f \"$HOLY_SRC/$patch_name\"; patch_name=\"${patch_name%.gz}\";;\n"
            "    *.bz2) bunzip2 -f \"$HOLY_SRC/$patch_name\"; patch_name=\"${patch_name%.bz2}\";;\n"
            "    *.patch|*.diff) ;;\n"
            "    *) rm -f \"$HOLY_SRC/$patch_name\"; continue;;\n"
            "  esac\n"
            "  ( cd \"$HOLY_SRC\" && patch -s $patch_args < \"$patch_name\" ) || exit 1\n"
            "  rm -f \"$HOLY_SRC/$patch_name\"\n"
            "done\n";
        static const char *const tail =
            "for hook_source in%s; do\n"
            "  [ -f \"$HOLY_SRC/$hook_source\" ] || continue\n"
            "  mkdir -p \"$HOLY_DEST/$(dirname \"$hook_source\")\"\n"
            "  cp \"$HOLY_SRC/$hook_source\" \"$HOLY_DEST/$hook_source\"\n"
            "done\n";
        for (index = 0; index < sizeof phase_maps / sizeof *phase_maps; ++index) {
            const struct phase_map *map = &phase_maps[index];
            const struct shell_function *functions[3];
            char *bodies[3];
            char *prefix;
            char *hook_tail = NULL;
            char working[64];
            size_t missing = 0;
            functions[0] = holy_shell_function(&pkg, map->pre);
            functions[1] = holy_shell_function(&pkg, map->body);
            functions[2] = holy_shell_function(&pkg, map->post);
            for (i = 0; i < 3; ++i) {
                bodies[i] = NULL;
                if (functions[i]) continue;
                ++missing;
            }
            if (missing == 3 && !(patches && !strcmp(map->holy, "prepare"))) {
                /* a build style supplies the steps the template leaves out */
                if (style && *style && strcmp(map->holy, "fetch") && strcmp(map->holy, "unpack")) {
                    review = 1;
                    holy_note_add(&note, "helper", "common/build-style/%s.sh supplies the %s step",
                             style, map->holy);
                }
                continue;
            }
            /* a patches directory needs the prepare step even without a patch function */
            if (patches && !strcmp(map->holy, "prepare"))
                holy_note_add(&note, "carried", "patches directory applied in the prepare step");
            if (style && *style)
                holy_note_add(&note, "helper", "common/build-style/%s.sh is not run, the %s body "
                         "comes from the template", style, map->holy);
            prefix = prologue(&pkg, name, version, release, "$HOLY_DEST", helpers, files, patches, 0);
            if (!prefix) { result = 1; goto done; }
            for (i = 0; i < 3; ++i) {
                char *label = NULL;
                if (!functions[i]) continue;
                label = resolve_options(&pkg, &note, &review, functions[i]->body,
                                        functions[i]->name);
                if (!label) {
                    bodies[i] = holy_shell_copy(functions[i]->body, functions[i]->length);
                    if (!bodies[i]) { free(prefix); result = 1; goto done; }
                    holy_note_add(&note, "unknown", "build option call in %s is not resolved",
                             functions[i]->name);
                    review = 1;
                } else {
                    bodies[i] = label;
                }
                holy_note_add(&note, "preserved", "%s template:%zu-%zu", functions[i]->name,
                         functions[i]->first, functions[i]->last);
            }
            {
                if (hooks_used && !strcmp(map->holy, "package")) {
                    char text[1024];
                    snprintf(text, sizeof text, tail, hook_list);
                    hook_tail = holy_shell_copy(text, strlen(text));
                }
                /* xbps-src runs a phase in wrksrc; a Holy step starts in its own working directory */
            snprintf(working, sizeof working, "cd \"$wrksrc\"\n");
            if (!emit_phase_step(out, map->holy, prefix,
                                   !strcmp(map->holy, "prepare") && patches ? lead : working,
                                   hook_tail, bodies, 3)) wrote = 0;
            }
            free(hook_tail);
            for (i = 0; i < 3; ++i) free(bodies[i]);
            free(prefix);
            if (!wrote) { result = 1; goto done; }
        }
    }
    /* each subpackage fills the staging tree of its own output */
    for (k = 0; k < splits_used; ++k) {
        const struct shell_function *install = &splits[k].install;
        char *body, *prefix;
        body = resolve_options(&pkg, &note, &review, install->body, splits[k].name);
        if (!body) body = holy_shell_copy(install->body, install->length);
        prefix = prologue(&pkg, name, version, release, "$HOLY_SPLIT_DEST", helpers, files,
                          patches, 1);
        if (!body || !prefix || !emit_split_step(out, splits[k].name, prefix, body)) {
            free(body);
            free(prefix);
            result = 1;
            goto done;
        }
        free(body);
        free(prefix);
    }
    if (fflush(out) || fclose(out)) { out = NULL; result = 1; goto done; }
    out = NULL;

    out = fopen(report_path, "wb");
    if (!out) {
        fprintf(stderr, "holypkg: report unavailable: %s\n", report_path);
        result = 1;
        goto done;
    }
    fputs("format holy-recipe-conversion-1\nconverter voidsrc-1\n", out);
    fputs("source-name ", out); holy_token(out, source); fputc('\n', out);
    fputs("source-file template\n", out);
    fprintf(out, "source-sha256 %s\n", hash);
    fputs("pkgbase ", out); holy_token(out, name); fputc('\n', out);
    fputs("version ", out); holy_token(out, version); fputc('\n', out);
    fputs("release ", out); holy_token(out, release); fputc('\n', out);
    fputs("arch any\n", out);
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
        fprintf(stderr, "holypkg: template conversion failed (status %d)\n", result);
    for (k = 0; k < splits_used; ++k) {
        free(splits[k].install.name);
        free(splits[k].install.body);
    }
    holy_note_free(&note);
    free(summary); free(homepage); free(license); free(maintainer); free(style);
    free(distfiles); free(checksum);
    holy_shell_free(&pkg);
    return result;
}
