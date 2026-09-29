/* Gentoo ebuild to holy-recipe(5) conversion; see man/holy-recipe.5 and man/holypkg.8.
   the ebuild is read as text and never run. an ebuild is bash with a metadata
   header, a set of standard phase functions and a package manager environment,
   so each phase body keeps its own shell behind a prologue that rebuilds the
   variables Portage exports onto the Holy paths, and every helper that
   environment supplies is reported rather than invented. */
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1
#include "gentoo.h"
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

/* the standard phase functions, in the order Portage runs them */
static const struct {
    const char *ebuild;
    const char *phase;
} phases[] = {
    { "src_unpack", "unpack" },
    { "src_prepare", "prepare" },
    { "src_configure", "configure" },
    { "src_compile", "build" },
    { "src_test", "check" },
    { "src_install", "package" }
};

/* the functions a maintainer writes to run beside the standard phases. Portage
   runs them at install time, so they are not build phases. */
static const char *const maintainer[] = {
    "pkg_preinst", "pkg_postinst", "pkg_prerm", "pkg_postrm", NULL
};

/* the helper functions ebuild.sh exports. a body that calls one cannot run
   without the Portage environment, so each call is reported by name. */
static const char *const helpers[] = {
    "econf", "econfargs", "emake", "einstall", "einstalldocs", "einfo", "ewarn",
    "eerror", "elog", "die", "assert", "use", "usex", "useq", "usen", "has",
    "hasq", "hasv", "hasd", "hask", "ver_test", "ver_cut", "ver_cmp", "diropts",
    "into", "insinto", "doins", "dolib", "dobin", "doexe", "doman", "dosbin",
    "dosrc", "dosed", "dosym", "newbin", "newman", "newdoc", "newrdoc",
    "newhtmldoc", "newreadme", "dohtml", "doinfo", "dofiledoc", "doicon",
    "docinto", "default", "strip-bin", "strip-libs", "append-cxxflags",
    "append-cflags", "append-fflags", "append-cppflags", "append-ldflags",
    "append-lfs", "filter-flags", "filter-ldflags", "tc-getCC", "tc-getCXX",
    "tc-getAS", "tc-getNM", "tc-getAR", "tc-getRANLIB", "tc-getSTRIP",
    "tc-getPKG_TOOL", "tc-getPKG_CONFIG", "tc-getBUILD_CC", "tc-getFEATURES",
    "tc-getCHOST", "tc-getBUILD_CHOST", "tc-getBUILD_CXX",
    "tc-export_PKG_CONFIG_ALLOW_SYSTEM_CLIBS",
    "tc-export_PKG_CONFIG_ALLOW_SYSTEM_LIBS", "user_vacant", "nonfatal",
    "get_libdir", "get_libdir_arch", NULL
};

/* the metadata that steers a build but that a Holy recipe has no place for */
static const char *const metadata[] = {
    "IUSE", "REQUIRED_USE", "RESTRICT", "PROPERTIES", NULL
};

/* the dependency lists, in the order Portage evaluates them */
static const struct {
    const char *key;
    const char *kind;
} dependencies[] = {
    { "RDEPEND", "depend" },
    { "PDEPEND", "depend" },
    { "DEPEND", "build-depend" },
    { "BDEPEND", "build-depend" },
    { NULL, NULL }
};

/* an ebuild states its identity in the file name, which is PN-PV-rPR.ebuild */
struct ebuild_name {
    char name[256];
    char version[256];
    char release[64];
    char epoch[16];
};

static int is_label_char(char c, int first)
{
    if (isalnum((unsigned char)c)) return 1;
    if (first) return 0;
    return c == '.' || c == '_' || c == '+' || c == '-';
}

static int is_label(const char *value)
{
    size_t at;
    if (!value || !*value) return 0;
    for (at = 0; value[at]; ++at)
        if (!is_label_char(value[at], at == 0)) return 0;
    return 1;
}

/* the package name, version and revision out of a PN-PV-rPR.ebuild file name.
   the package name may carry dashes, so the split is taken from the right: a
   trailing -rN is the revision and the last dash a digit follows is the one that
   starts the version. */
static int split_file_name(const char *file, struct ebuild_name *out)
{
    char base[512];
    const char *leaf;
    size_t length;
    char *at, *revision = NULL, *split = NULL, *version, *epoch;

    memset(out, 0, sizeof *out);
    length = strlen(file);
    if (length >= sizeof base) return 0;
    memcpy(base, file, length + 1);
    /* the identity is in the leaf, so the directory in front of it is dropped */
    leaf = strrchr(base, '/');
    if (leaf) {
        ++leaf;
        memmove(base, leaf, strlen(leaf) + 1);
    } else {
        leaf = base;
    }
    length = strlen(base);
    if (length < 9 || strcmp(base + length - 7, ".ebuild")) return 0;
    base[length - 7] = 0;
    for (at = base; (at = strchr(at, '-')) != NULL; ++at) {
        if (at[1] != 'r' || !isdigit((unsigned char)at[2])) continue;
        {
            const char *scan = at + 2;
            size_t digits = 0;
            for (; isdigit((unsigned char)*scan); ++scan) ++digits;
            if (!*scan && digits) revision = at;
        }
    }
    if (revision) {
        size_t used = 0;
        for (at = revision + 2; *at; ++at)
            if (used + 1 < sizeof out->release) out->release[used++] = *at;
        out->release[used] = 0;
        if (used > 1 && out->release[0] == '0') return 0;
        *revision = 0;
    } else {
        snprintf(out->release, sizeof out->release, "1");
    }
    for (at = base; (at = strchr(at, '-')) != NULL; ++at)
        if (isdigit((unsigned char)at[1])) split = at;
    if (!split || split == base) return 0;
    version = split + 1;
    /* an epoch names a packaging revision order and is not part of the version */
    epoch = strchr(version, ':');
    if (epoch) {
        if (epoch - version >= (ptrdiff_t)sizeof out->epoch) return 0;
        memcpy(out->epoch, version, (size_t)(epoch - version));
        out->epoch[epoch - version] = 0;
        memmove(version, epoch + 1, strlen(epoch + 1) + 1);
    }
    if (!is_label(version) || strlen(version) >= sizeof out->version) return 0;
    memcpy(out->version, version, strlen(version) + 1);
    *split = 0;
    if (!is_label(base) || strlen(base) >= sizeof out->name) return 0;
    memcpy(out->name, base, strlen(base) + 1);
    return 1;
}

/* the directory that holds the ebuild, which also holds its files directory */
static char *ebuild_directory(const char *input)
{
    const char *at = strrchr(input, '/');
    size_t used;
    char *copy;
    if (!at) return strdup(".");
    copy = strdup(input);
    if (!copy) return NULL;
    used = strlen(copy);
    while (used && copy[used - 1] == '/') copy[--used] = 0;
    {
        char *slash = strrchr(copy, '/');
        if (slash) *slash = 0;
    }
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
            *after != '\'' && *after != '\n' && *after != ')')
            continue;
        for (line = index; line; --line)
            if (at[-(ptrdiff_t)(index - line)] == '\n') break;
        for (line = line ? line : 0; line < index; ++line)
            if (body[line] == '#') break;
        if (line < index) continue;
        return 1;
    }
    return 0;
}

/* the eclasses an ebuild inherits, in the order Portage loads them */
static char **inherited(const struct shell_script *script, size_t *count)
{
    char **list = NULL;
    size_t used = 0, index;
    *count = 0;
    for (index = 0; index < script->condition_count; ++index) {
        const char *text = script->conditions[index].text;
        const char *newline = strchr(text, '\n');
        char *line;
        char **words;
        size_t word_count = 0, word;
        if (strncmp(text, "inherit", 7) || (text[7] != ' ' && text[7] != '\t')) continue;
        /* an unreadable statement carries the rest of the file, so only the line
           that named the eclasses is read */
        line = holy_shell_copy(text, newline ? (size_t)(newline - text) : strlen(text));
        if (!line) break;
        words = holy_shell_words(line + 7, &word_count);
        for (word = 0; words && word < word_count; ++word) {
            char **grown = realloc(list, (used + 2) * sizeof *grown);
            if (!grown) break;
            list = grown;
            list[used++] = words[word];
            words[word] = NULL;
        }
        if (words) holy_shell_words_free(words);
        free(line);
    }
    if (list) list[used] = NULL;
    *count = used;
    return list;
}

/* a Portage version starts at the last dash a digit follows, since a package name
   may carry dashes of its own */
static const char *atom_split(const char *atom)
{
    const char *last = strrchr(atom, '/');
    const char *dash = NULL, *at;
    last = last ? last + 1 : atom;
    for (at = last; (at = strchr(at, '-')) != NULL; ++at)
        if (isdigit((unsigned char)at[1])) dash = at;
    return dash;
}

/* the package name of an atom, which is what a Holy record names */
static void atom_name(const char *atom, char *out, size_t size)
{
    const char *last = strrchr(atom, '/');
    const char *dash;
    size_t used;
    last = last ? last + 1 : atom;
    dash = atom_split(atom);
    used = dash ? (size_t)(dash - last) : strlen(last);
    if (used >= size) used = size - 1;
    memcpy(out, last, used);
    out[used] = 0;
}

/* the version of an atom, which keeps no revision, because a Holy record carries
   the upstream version */
static int atom_version(const char *atom, char *out, size_t size)
{
    const char *dash = atom_split(atom);
    size_t used, at;
    if (!dash) {
        snprintf(out, size, "-");
        return 1;
    }
    ++dash;
    used = strlen(dash);
    if (!used || used >= size) return 0;
    for (at = 0; at < used; ++at)
        if (!is_label_char(dash[at], at == 0)) return 0;
    memcpy(out, dash, used + 1);
    return 1;
}

/* a Gentoo atom is [!!|!][~][OP]CATEGORY/PACKAGE[-PV][:SLOT][use-deps]. a Holy
   depend record names one package with one comparison, so a blocker becomes a
   conflict, a version keeps only its upstream part, and a use dependency, a slot
   and a version range are reported. */
static int emit_atom(FILE *out, const char *raw, const char *kind, struct recipe_note *note,
                     int *review, const char *where)
{
    const char *cursor = raw;
    char requirement[512], package[256], relation[16] = "any", wanted[256];
    size_t used = 0;
    int blocker = 0, strong = 0, weak = 0;

    while (*cursor == ' ' || *cursor == '\t') ++cursor;
    if (*cursor == '!') {
        ++cursor;
        blocker = 1;
        if (*cursor == '!') { ++cursor; strong = 1; }
    }
    if (*cursor == '~') { ++cursor; weak = 1; }
    if (*cursor == '<' || *cursor == '>' || *cursor == '=') {
        char operator[4] = {0};
        size_t operator_length = 0;
        while (*cursor == '<' || *cursor == '>' || *cursor == '=') {
            if (operator_length + 1 < sizeof operator) operator[operator_length++] = *cursor;
            ++cursor;
        }
        operator[operator_length] = 0;
        snprintf(relation, sizeof relation, "%s", holy_relation_name(operator));
    }
    while (used < sizeof requirement && cursor[used] && cursor[used] != ' ' &&
           cursor[used] != '\t' && cursor[used] != ':' && cursor[used] != '[')
        ++used;
    if (!used) return 1;
    memcpy(requirement, cursor, used);
    requirement[used] = 0;
    cursor += used;
    if (*cursor == ':') {
        *review = 1;
        holy_note_add(note, "unknown", "the slot of %s in %s is dropped, because a Holy recipe "
                      "holds one version of a package", raw, where);
    }
    if (!strchr(requirement, '/')) {
        *review = 1;
        holy_note_add(note, "unknown", "%s in %s is not a category/package atom", raw, where);
        return 1;
    }
    if (!strncmp(requirement, "virtual/", 8)) {
        /* a virtual names an interface rather than a package, so a record that holds
           the name alone cannot say which package is meant */
        *review = 1;
        holy_note_add(note, "unknown", "the virtual %s in %s names an interface, not a "
                      "package, so a Holy record cannot require it", raw, where);
    }
    if (!atom_version(requirement, wanted, sizeof wanted)) {
        *review = 1;
        holy_note_add(note, "unknown", "the version of %s in %s is a range or a wildcard, "
                      "which a Holy record cannot hold", raw, where);
        return 1;
    }
    atom_name(requirement, package, sizeof package);
    if (!*package) return 1;
    /* an atom with no comparator but a version still names one version */
    if (strcmp(wanted, "-") && !strcmp(relation, "any"))
        snprintf(relation, sizeof relation, "eq");
    if (blocker) {
        fputs("x-conflicts ", out);
        holy_token(out, package);
        fputc('\n', out);
        if (strong) {
            *review = 1;
            holy_note_add(note, "unknown", "the strong blocker %s in %s names a blocker with "
                          "no expiry, which a conflict record cannot hold", raw, where);
        }
        if (strcmp(wanted, "-")) {
            *review = 1;
            holy_note_add(note, "unknown", "the blocker %s in %s names a version, which a "
                          "conflict record cannot hold", raw, where);
        }
        holy_note_add(note, "carried", "%s %s becomes a conflict", where, raw);
        return 1;
    }
    if (weak) {
        *review = 1;
        holy_note_add(note, "unknown", "the ~ atom %s in %s is a version range, which a Holy "
                      "depend record cannot hold, so only the package is carried", raw, where);
        snprintf(wanted, sizeof wanted, "-");
        snprintf(relation, sizeof relation, "any");
    }
    fputs(kind, out);
    fputc(' ', out);
    holy_token(out, package);
    if (strcmp(wanted, "-")) {
        fputc(' ', out);
        holy_token(out, relation);
        fputc(' ', out);
        holy_token(out, wanted);
    }
    fputc('\n', out);
    holy_note_add(note, "carried", "%s %s becomes a requirement", where, raw);
    return 1;
}

/* 1 when a ${...} body names the variable, and nothing else */
static int variable(const char *body, size_t used, const char *name)
{
    return used == strlen(name) && !memcmp(body, name, used);
}

/* an ebuild names its own identity in these variables, so a value written with
   only them can be written out; one that needs the Portage environment, or a
   parameter expansion modifier, is refused rather than half expanded */
static char *expand_identity(const char *value, const struct ebuild_name *name, const char *eapi)
{
    const char *cursor = value;
    char *out = NULL;
    size_t used = 0;
    char joined[600];
    for (;;) {
        const char *open = strchr(cursor, '$');
        size_t at, length, inner_length;
        const char *text = NULL;
        if (!open) break;
        if (open[1] != '{' && open[1] != '(') {
            cursor = open + 1;
            continue;
        }
        {
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
                    open[scan] == '%') {
                    free(out);
                    return NULL;
                }
        }
        length = (size_t)(open - cursor);
        inner_length = at - 2;
        if (variable(open + 2, inner_length, "PN")) text = name->name;
        else if (variable(open + 2, inner_length, "PV")) text = name->version;
        else if (variable(open + 2, inner_length, "PR")) text = name->release;
        else if (variable(open + 2, inner_length, "PF")) text = name->name;
        else if (variable(open + 2, inner_length, "EAPI")) text = eapi;
        else if (variable(open + 2, inner_length, "PVR")) {
            if (strcmp(name->release, "1"))
                snprintf(joined, sizeof joined, "%s-r%s", name->version, name->release);
            else
                snprintf(joined, sizeof joined, "%s", name->version);
            text = joined;
        } else if (variable(open + 2, inner_length, "P")) {
            if (strcmp(name->release, "1"))
                snprintf(joined, sizeof joined, "%s-%s-r%s", name->name, name->version,
                         name->release);
            else
                snprintf(joined, sizeof joined, "%s-%s", name->name, name->version);
            text = joined;
        }
        /* any other variable needs the Portage environment, so it is refused */
        if (!text) {
            free(out);
            return NULL;
        }
        {
            size_t add = length + strlen(text) + at + 1;
            char *grown = realloc(out, used + add + 1);
            if (!grown) {
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
        cursor = open + at + 1;
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

/* a PATCHES entry names a file in the files directory beside the ebuild, so the
   ${FILESDIR} prefix is the one path this converter can write out, and the rest of
   the entry is expanded afterwards */
static char *files_directory_path(const char *entry, const char *directory,
                                  const struct ebuild_name *name, const char *eapi)
{
    const char *marker = strstr(entry, "${FILESDIR}");
    char *joined;
    char *out;
    if (!marker) return expand_identity(entry, name, eapi);
    /* a ${FILESDIR:-path} default needs a shell to pick, so it is refused */
    if (marker[11] == ':' || marker[11] == '-' || marker[11] == '+' || marker[11] == '=' ||
        marker[11] == '#' || marker[11] == '%' || marker[11] == '?')
        return NULL;
    {
        size_t head = (size_t)(marker - entry);
        size_t tail = strlen(entry + head + 11);
        joined = malloc(head + strlen(directory) + 7 + tail + 1);
        if (!joined) return NULL;
        memcpy(joined, entry, head);
        sprintf(joined + head, "%s/files/%s", directory, entry + head + 11);
    }
    out = expand_identity(joined, name, eapi);
    free(joined);
    return out;
}

/* the name of the USE flag a mark? stands for, which runs back over the name and
   an optional leading bang. returns the start of the name. */
static const char *flag_start(const char *begin, const char *mark)
{
    const char *at = mark;
    while (at > begin && (at[-1] == '!' || at[-1] == '*' || at[-1] == '@')) --at;
    while (at > begin && (isalnum((unsigned char)at[-1]) || at[-1] == '_' || at[-1] == '-' ||
                          at[-1] == '+' || at[-1] == '.'))
        --at;
    return at;
}

/* a dependency string is a list of atoms, USE conditionals and any-of groups. a
   Holy recipe has no USE flags, so a conditional group is reported and the atoms
   inside it are carried anyway, since dropping them would lose a dependency the
   build needs when the flag is on. */
static int emit_dependencies(FILE *out, const char *value, const char *kind,
                             struct recipe_note *note, int *review, const char *where,
                             int depth)
{
    const char *cursor = value;
    if (depth > 6) {
        *review = 1;
        holy_note_add(note, "unknown", "the groups in %s nest too deeply for this converter",
                      where);
        return 1;
    }
    while (*cursor) {
        const char *start;
        char *atom;
        size_t used;
        while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n') ++cursor;
        if (!*cursor) break;
        /* an any-of group is a set of alternatives of which one is enough */
        if ((cursor[0] == '|' && cursor[1] == '|') ||
            (cursor[0] == '^' && cursor[1] == '^')) {
            const char *open = strchr(cursor, '(');
            const char *close = open ? memchr(open, ')', strlen(open)) : NULL;
            *review = 1;
            holy_note_add(note, "unknown", "the any-of group in %s is reported as a whole, "
                          "since a Holy recipe cannot choose one of its members", where);
            if (open && open - cursor < 4 && close) {
                char *inner = holy_shell_copy(open + 1, (size_t)(close - open - 1));
                if (inner) {
                    if (!emit_dependencies(out, inner, kind, note, review, where, depth + 1)) {
                        free(inner);
                        return 0;
                    }
                    free(inner);
                }
                cursor = close + 1;
                continue;
            }
            /* a group with no parentheses runs to the end of the list, so every
               remaining atom is one of its members */
            {
                char *rest = strdup(cursor + 2);
                if (rest && !emit_dependencies(out, rest, kind, note, review, where,
                                              depth + 1)) {
                    free(rest);
                    return 0;
                }
                free(rest);
            }
            break;
        }
        /* a USE conditional is flag? ( list ), which this converter cannot switch */
        {
            const char *mark = strchr(cursor, '?');
            const char *open = strchr(cursor, '(');
            int header = 1;
            const char *scan;
            for (scan = cursor; mark && scan < mark; ++scan)
                if (!isalnum((unsigned char)*scan) && !strchr("_-.+!*@", *scan)) header = 0;
            if (mark && open && header && open > mark && open[-1] != '^' && open[-1] != '|') {
                const char *close = memchr(open, ')', strlen(open));
                const char *from = flag_start(cursor, mark);
                size_t between = (size_t)(mark - from);
                if (close && between < 128) {
                    char flag[128];
                    int negated = mark > from && mark[-1] == '!';
                    memcpy(flag, from, between);
                    flag[between] = 0;
                    *review = 1;
                    holy_note_add(note, "unknown", "the USE flag %s in %s gates its atoms, and "
                                  "a Holy recipe cannot switch a flag, so the group is reported",
                                  negated ? flag + 1 : flag, where);
                    {
                        char *inner = holy_shell_copy(open + 1, (size_t)(close - open - 1));
                        if (inner) {
                            if (!emit_dependencies(out, inner, kind, note, review, where,
                                                   depth + 1)) {
                                free(inner);
                                return 0;
                            }
                            free(inner);
                        }
                    }
                    cursor = close + 1;
                    continue;
                }
            }
        }
        start = cursor;
        while (*cursor && *cursor != ' ' && *cursor != '\t' && *cursor != '\n')
            ++cursor;
        used = (size_t)(cursor - start);
        atom = holy_shell_copy(start, used);
        if (!atom) return 0;
        {
            /* a use dependency is bracketed and a group is parenthesized, and a
               Holy record holds neither, so both are cut and the first is named */
            char *mark = strchr(atom, '[');
            if (mark) {
                *review = 1;
                holy_note_add(note, "unknown", "the use dependency of %s in %s is dropped, "
                              "because a Holy recipe has no USE flags", atom, where);
                *mark = 0;
            } else {
                mark = strchr(atom, '(');
                if (mark) *mark = 0;
            }
        }
        if (strncmp(atom, "${", 2) && strncmp(atom, "$(", 2)) {
            if (!emit_atom(out, atom, kind, note, review, where)) {
                free(atom);
                return 0;
            }
        } else {
            *review = 1;
            holy_note_add(note, "unknown", "the list in %s includes %s, which this converter "
                          "does not expand", where, atom);
        }
        free(atom);
    }
    return 1;
}

/* the prologue every phase body runs behind, rebuilt from the exported paths */
static int emit_prologue(FILE *out, const struct ebuild_name *name, const char *eapi)
{
    fprintf(out, "EPREFIX=\"\"\nED=\"$HOLY_DEST\"\nD=\"$HOLY_DEST\"\nDESTDIR=\"$HOLY_DEST\"\n");
    fprintf(out, "WORKDIR=\"$HOLY_SRC\"\nDISTDIR=\"$HOLY_SRC\"\nT=\"$HOLY_BUILD\"\n");
    fprintf(out, "PN=%s\nPV=%s\nPR=%s\nPF=%s\nEAPI=%s\n", name->name, name->version, name->release,
            name->name, eapi);
    fprintf(out, "P=%s-%s", name->name, name->version);
    if (strcmp(name->release, "1")) fprintf(out, "-r%s", name->release);
    fputc('\n', out);
    fprintf(out, "PVR=%s", name->version);
    if (strcmp(name->release, "1")) fprintf(out, "-r%s", name->release);
    fputc('\n', out);
    return fputs("cd \"$HOLY_SRC\" || exit 1\n", out) >= 0;
}

/* one source record. a remote archive has no digest here, because a Gentoo
   Manifest pins a BLAKE2B and a SHA-512 rather than the SHA-256 a Holy source
   needs, so it is reported; a file from the files directory travels with the
   recipe. */
static int emit_source(FILE *out, const char *entry, const char *directory, const char *output,
                       const struct ebuild_name *name, const char *eapi,
                       struct recipe_note *note, int *review)
{
    char *copy = NULL;
    char *written = NULL;
    char *target_name = NULL;
    char *arrow;
    int ok = 1;
    copy = strdup(entry);
    if (!copy) return 0;
    arrow = strstr(copy, "->");
    if (arrow) {
        char *stop = arrow + 2;
        *arrow = 0;
        while (*stop == ' ') ++stop;
        target_name = strdup(stop);
    } else {
        target_name = strdup(entry);
    }
    if (!target_name) {
        free(copy);
        return 0;
    }
    /* the file name Portage uses is the target of a rename, and it is the name an
       archive keeps in the distfiles directory */
    written = expand_identity(target_name, name, eapi);
    free(target_name);
    if (!written) {
        free(copy);
        return 0;
    }
    target_name = written;
    if (!strncmp(target_name, "mirror://", 9)) {
        *review = 1;
        holy_note_add(note, "unknown", "the source %s is a mirror URI, which names no single "
                      "address, so it is reported rather than fetched", target_name);
    } else if (strstr(target_name, "://")) {
        *review = 1;
        holy_note_add(note, "unknown", "the source %s has no sha256, and a Gentoo Manifest "
                      "pins a BLAKE2B rather than one, so it is reported rather than fetched",
                      target_name);
    } else if (strchr(target_name, '/')) {
        *review = 1;
        holy_note_add(note, "unknown", "the source %s names a path this converter cannot read",
                      target_name);
    } else {
        char original[4096], target[4096], digest[65];
        struct stat st;
        snprintf(original, sizeof original, "%s/files/%s", directory, target_name);
        snprintf(target, sizeof target, "%s/%s", output, target_name);
        if (stat(original, &st) || !S_ISREG(st.st_mode)) {
            *review = 1;
            holy_note_add(note, "unknown", "the source %s is not in the files directory, so "
                          "this converter cannot hash it", target_name);
        } else if (!holy_copy_and_hash(original, target, digest)) {
            ok = 0;
        } else {
            fputs("source ", out);
            holy_token(out, target_name);
            fputc(' ', out);
            holy_token(out, target_name);
            fputc('\n', out);
            fputs("source-sha256 ", out);
            holy_token(out, target_name);
            fputc(' ', out);
            holy_token(out, digest);
            fputc('\n', out);
            holy_note_add(note, "carried", "the local source %s", target_name);
            holy_note_add(note, "semantic-change", "the local source %s is copied next to the "
                          "recipe and hashed as sha256", target_name);
        }
    }
    free(copy);
    free(target_name);
    return ok;
}

/* SRC_URI is a list of entries, and an entry behind a USE flag is written
   flag? ( url ), which names a file a Holy recipe cannot reach */
static int emit_sources(FILE *out, const char *uri, const char *directory, const char *output,
                        const struct ebuild_name *name, const char *eapi,
                        struct recipe_note *note, int *review)
{
    const char *cursor = uri;
    while (*cursor) {
        const char *start, *after;
        char *entry;
        size_t used;
        while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n') ++cursor;
        if (!*cursor) break;
        start = cursor;
        while (*cursor && *cursor != ' ' && *cursor != '\t' && *cursor != '\n') ++cursor;
        used = (size_t)(cursor - start);
        after = cursor;
        entry = holy_shell_copy(start, used);
        if (!entry) return 0;
        /* the closing paren of the group follows the entries it holds */
        if (used && entry[used - 1] == '?') {
            const char *open = strchr(after, '(');
            const char *close = open ? memchr(open, ')', strlen(open)) : NULL;
            const char *from = flag_start(start, start + used - 1);
            char flag[128];
            size_t between = (size_t)((start + used - 1) - from);
            if (close && between < sizeof flag) {
                memcpy(flag, from, between);
                flag[between] = 0;
                *review = 1;
                holy_note_add(note, "unknown", "the USE flag %s gates the sources inside it, "
                              "and a Holy recipe cannot switch a flag", flag);
                if (open > after + 1) {
                    char *inner = holy_shell_copy(after + 1, (size_t)(open - after - 1));
                    if (inner) {
                        if (!emit_sources(out, inner, directory, output, name, eapi, note, review)) {
                            free(inner);
                            free(entry);
                            return 0;
                        }
                        free(inner);
                    }
                }
                free(entry);
                cursor = close + 1;
                continue;
            }
        }
        if (!emit_source(out, entry, directory, output, name, eapi, note, review)) {
            free(entry);
            return 0;
        }
        free(entry);
    }
    return 1;
}

int holy_convert_gentoo(const char *input, const char *source, const char *output)
{
    struct shell_script script = {0};
    struct recipe_note note = {0};
    struct ebuild_name name;
    char *directory = NULL, *summary = NULL, *homepage = NULL, *eapi = NULL;
    char *license = NULL, *slot = NULL;
    char recipe_path[4096], report_path[4096], digest[65];
    char **eclasses = NULL;
    size_t eclass_count = 0, index, i;
    FILE *out = NULL;
    int result = 1, review = 0, read_status;

    if (!input || !output || !*output) {
        fputs("usage: holypkg convert NAME.ebuild --source NAME --output NEW_DIRECTORY\n", stderr);
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
    if (!split_file_name(input, &name)) {
        fputs("holypkg: an ebuild is named PN-PV-rPR.ebuild\n", stderr);
        return 2;
    }
    directory = ebuild_directory(input);
    if (!directory) return 1;
    read_status = holy_shell_read(input, &script);
    if (read_status == 6) { result = 6; goto done; }
    if (read_status == 2) { result = 2; goto done; }
    if (read_status) { result = 1; goto done; }

    eapi = holy_shell_join(&script, "EAPI");
    summary = holy_shell_join(&script, "DESCRIPTION");
    homepage = holy_shell_join(&script, "HOMEPAGE");
    license = holy_shell_join(&script, "LICENSE");
    slot = holy_shell_join(&script, "SLOT");
    if (!eapi || !*eapi) {
        free(eapi);
        eapi = strdup("0");
        if (!eapi) { result = 1; goto done; }
    }

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
    fputs("format holy-recipe-1\nname ", out); holy_token(out, name.name);
    fputs("\nversion ", out); holy_token(out, name.version);
    fputs("\nrelease ", out); holy_token(out, name.release);
    /* a keyword names a machine an ebuild is tested on rather than the machine
       that builds it, so the recipe is built for the machine that runs the build */
    fputs("\narch \"any\"\nlibc any\n", out);
    if (summary && *summary) {
        char *stop = strchr(summary, '\n');
        if (stop) *stop = 0;
        if (*summary) { fputs("summary ", out); holy_token(out, summary); fputc('\n', out); }
    }
    if (homepage && *homepage && !strchr(homepage, '$')) {
        fputs("homepage ", out); holy_token(out, homepage); fputc('\n', out);
    }
    fputs("x-source-family gentoo\nx-converter gentoo-1\n", out);
    if (strcmp(eapi, "0")) {
        fputs("x-eapi ", out); holy_token(out, eapi); fputc('\n', out);
        holy_note_add(&note, "carried", "EAPI %s", eapi);
    } else {
        review = 1;
        holy_note_add(&note, "unknown", "the ebuild names no EAPI, so the phase functions it "
                      "defines are the only ones a recipe can see");
    }
    if (license && *license && !strchr(license, '$')) {
        fputs("x-license ", out); holy_token(out, license); fputc('\n', out);
        holy_note_add(&note, "carried", "LICENSE %s", license);
    }
    if (slot && *slot && !strchr(slot, '$')) {
        fputs("x-slot ", out); holy_token(out, slot); fputc('\n', out);
        holy_note_add(&note, "carried", "SLOT %s", slot);
    }
    fputs("output ", out); holy_token(out, name.name);
    fputs(" runtime\n", out);

    /* the eclasses an ebuild inherits, each of which is a helper environment */
    eclasses = inherited(&script, &eclass_count);
    for (index = 0; index < eclass_count; ++index) {
        review = 1;
        holy_note_add(&note, "helper", "the %s eclass, which this converter does not run",
                      eclasses[index]);
    }

    /* the metadata that steers a build and that a Holy recipe has no place for */
    for (index = 0; metadata[index]; ++index) {
        char *value = holy_shell_join(&script, metadata[index]);
        if (!value) continue;
        if (*value && strcmp(value, "(")) {
            review = 1;
            holy_note_add(&note, "unknown", "%s %s is a package manager setting, and a Holy "
                          "recipe carries neither", metadata[index], value);
        }
        free(value);
    }

    /* the revision is a packaging revision of its own, and a Holy release names it */
    if (strcmp(name.release, "1")) {
        holy_note_add(&note, "semantic-change", "the revision r%s becomes the Holy release",
                      name.release);
    }
    if (*name.epoch) {
        holy_note_add(&note, "semantic-change", "the epoch %s: of the file name is preserved "
                      "and dropped, since it orders a packaging revision and is not a version",
                      name.epoch);
    }
    {
        /* the engine unpacks each declared source under its own name, so one lift
           turns that into the single WORKDIR tree an ebuild phase expects */
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
                      "sources, so the extracted tree takes the place of WORKDIR");
    }

    {
        char *value = holy_shell_join(&script, "SRC_URI");
        if (value) {
            if (!emit_sources(out, value, directory, output, &name, eapi, &note, &review)) {
                free(value);
                result = 1;
                goto done;
            }
            free(value);
        }
    }

    /* a patch the ebuild names lives in the files directory, so it travels with
       the recipe for the src_prepare default to apply */
    {
        char *value = holy_shell_join(&script, "PATCHES");
        const char *cursor = value;
        if (value) {
            while (*cursor) {
                const char *start;
                char *raw, *quoted, *file, *expanded;
                size_t used;
                while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n' ||
                       *cursor == '(' || *cursor == ')')
                    ++cursor;
                if (!*cursor) break;
                start = cursor;
                while (*cursor && *cursor != ' ' && *cursor != '\t' && *cursor != '\n' &&
                       *cursor != ')' && *cursor != '(')
                    ++cursor;
                used = (size_t)(cursor - start);
                raw = holy_shell_copy(start, used);
                if (!raw) break;
                quoted = *raw == '"' ? holy_shell_unquote(raw, used) : strdup(raw);
                free(raw);
                if (!quoted) break;
                if (!quoted) break;
                {
                    /* a list entry may be two adjacent quoted words, and a file name
                       in a patch list never holds a quote of its own */
                    char *read = quoted, *write = quoted;
                    while (*read) {
                        if (*read != '"') *write++ = *read;
                        ++read;
                    }
                    *write = 0;
                }
                expanded = files_directory_path(quoted, directory, &name, eapi);
                free(quoted);
                if (!expanded) {
                    review = 1;
                    holy_note_add(&note, "unknown", "a PATCHES entry is written with a variable "
                                  "this converter does not expand, so the patch does not travel "
                                  "with the recipe");
                    continue;
                }
                file = strrchr(expanded, '/');
                file = file ? file + 1 : expanded;
                {
                    char target[4096], digest[65];
                    struct stat st;
                    snprintf(target, sizeof target, "%s/%s", output, file);
                    if (stat(expanded, &st) || !S_ISREG(st.st_mode)) {
                        review = 1;
                        holy_note_add(&note, "unknown", "the patch %s is not in the files "
                                      "directory, so this converter cannot hash it", file);
                    } else if (!holy_copy_and_hash(expanded, target, digest)) {
                        result = 1;
                        free(expanded);
                        break;
                    } else {
                        fputs("source ", out);
                        holy_token(out, file);
                        fputc(' ', out);
                        holy_token(out, file);
                        fputc('\n', out);
                        fputs("source-sha256 ", out);
                        holy_token(out, file);
                        fputc(' ', out);
                        holy_token(out, digest);
                        fputc('\n', out);
                        holy_note_add(&note, "carried", "the local patch %s", file);
                        holy_note_add(&note, "semantic-change", "the patch %s is copied next to "
                                      "the recipe and hashed as sha256", file);
                    }
                }
                free(expanded);
            }
            free(value);
        }
    }

    for (index = 0; dependencies[index].key; ++index) {
        char *value = holy_shell_join(&script, dependencies[index].key);
        if (!value) continue;
        if (*value) {
            if (!emit_dependencies(out, value, dependencies[index].kind, &note, &review,
                                   dependencies[index].key, 0)) {
                free(value);
                result = 1;
                goto done;
            }
            holy_note_add(&note, "carried", "%s %s:%zu", dependencies[index].key, input,
                          holy_shell_line(&script, dependencies[index].key));
        }
        free(value);
    }

    /* each standard phase function becomes the matching phase, and a phase the
       ebuild leaves out is the one the eclasses supply */
    for (index = 0; index < sizeof phases / sizeof *phases; ++index) {
        const struct shell_function *function =
            holy_shell_function(&script, phases[index].ebuild);
        if (!function) {
            review = 1;
            holy_note_add(&note, "helper", "the %s phase, which the inherited eclasses supply "
                          "and this converter does not run", phases[index].phase);
            continue;
        }
        if (function->conditional) {
            review = 1;
            holy_note_add(&note, "unknown", "the %s function is written inside a conditional, "
                          "which this converter does not choose between", phases[index].ebuild);
        }
        fprintf(out, "step %s /bin/sh <<STEP\n", phases[index].phase);
        fputs("# the Portage variables this body reads, rebuilt from the exported Holy paths\n",
              out);
        if (!emit_prologue(out, &name, eapi)) { result = 1; goto done; }
        if (function->length &&
            fwrite(function->body, 1, function->length, out) != function->length) {
            result = 1;
            goto done;
        }
        if (function->length && function->body[function->length - 1] != '\n') fputc('\n', out);
        fputs("STEP\n", out);
        holy_note_add(&note, "preserved", "the %s body %s:%zu", phases[index].ebuild, input,
                      function->first);
        for (i = 0; helpers[i]; ++i)
            if (calls_helper(function->body, function->length, helpers[i])) {
                review = 1;
                holy_note_add(&note, "unknown", "the %s body calls the %s helper, which the "
                              "Portage environment supplies and this converter does not",
                              phases[index].ebuild, helpers[i]);
            }
    }

    /* the maintainer scripts run beside the phases rather than inside them */
    for (i = 0; maintainer[i]; ++i) {
        if (!holy_shell_function(&script, maintainer[i])) continue;
        review = 1;
        holy_note_add(&note, "unknown", "the %s function runs at install time through Portage, "
                      "and a Holy hook carries a script rather than a function", maintainer[i]);
    }

    if (fclose(out)) { out = NULL; result = 1; goto done; }
    out = NULL;

    out = fopen(report_path, "wb");
    if (!out) {
        fprintf(stderr, "holypkg: report unavailable: %s\n", report_path);
        result = 1;
        goto done;
    }
    fputs("format holy-recipe-conversion-1\nconverter gentoo-1\n", out);
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
    fputs("arch \"any\"\nrecipe ", out); holy_token(out, name.name);
    fprintf(out, ".recipe\n");
    fprintf(out, "status %s\n", review ? "review-required" : "native");
    for (index = 0; index < note.count; ++index) fprintf(out, "%s\n", note.lines[index]);
    fprintf(out, "summary carried %zu preserved %zu helper %zu unknown %zu changes %zu\n",
            note.carried, note.preserved, note.helper, note.unknown, note.changes);
    if (fclose(out)) { out = NULL; result = 1; goto done; }
    out = NULL;
    result = 3;
    printf("converted %s status %s\n", name.name, review ? "review-required" : "native");
    printf("recipe %s\nreport %s\n", recipe_path, report_path);
    if (review) fputs("holypkg: the converted recipe needs review before its first build\n",
                      stderr);
done:
    if (out) fclose(out);
    if (eclasses) holy_shell_words_free(eclasses);
    free(eapi);
    free(summary);
    free(homepage);
    free(license);
    free(slot);
    free(directory);
    holy_shell_free(&script);
    holy_note_free(&note);
    return result;
}
