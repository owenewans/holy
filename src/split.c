/* proposes the split outputs of a prepared package tree; see man/holy-recipe(5) and
   man/holypkg.8. a recipe assigns payload paths to outputs with explicit split
   patterns, and this command writes those patterns from what a tree actually holds:
   every non-directory path receives one output, an explicit rule outranks a
   heuristic, and a path no rule settles is reported as a decision rather than
   guessed. a file extension alone never decides, because a shared object without a
   version may be opened through dlopen at runtime, and a license or a runtime data
   file is never carved out by a general documentation pattern. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#include "split.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define SPLIT_PATHS 100000
#define SPLIT_DECISIONS 4096

/* one explicit rule, as the caller wrote it on the command line */
struct split_rule {
    const char *output, *pattern;
};

struct split_path {
    char *path;
    char *output;
    /* what a heuristic would place the path in, kept when the path is a decision so
       the operator sees the proposal without this command making it */
    char *suggested;
    int explicit_rule, decision, decision_kind;
    /* the reason a heuristic gave, reported so the operator can overrule it */
    char reason[64];
};

struct split_tree {
    struct split_path *items;
    size_t count, capacity;
};

/* a decision kind names what could not be settled from the tree itself */
enum {
    SPLIT_UNASSIGNED = 0,
    SPLIT_REPEATED,
    SPLIT_UNVERSIONED_OBJECT,
    SPLIT_STATIC_ARCHIVE,
    SPLIT_ESCAPING_LINK
};

static const char *decision_name(int kind)
{
    switch (kind) {
    case SPLIT_REPEATED: return "repeated";
    case SPLIT_UNVERSIONED_OBJECT: return "unversioned-object";
    case SPLIT_STATIC_ARCHIVE: return "static-archive";
    case SPLIT_ESCAPING_LINK: return "escaping-link";
    default: return "unassigned";
    }
}

static int tree_add(struct split_tree *tree, const char *path, const char *output,
                    int explicit_rule, int decision, int kind, const char *suggested,
                    const char *reason)
{
    struct split_path *grown;
    if (tree->count == SPLIT_PATHS) return 0;
    if (tree->count == tree->capacity) {
        size_t next = tree->capacity ? tree->capacity * 2 : 64;
        if (next < tree->capacity || next > SPLIT_PATHS) next = SPLIT_PATHS;
        grown = realloc(tree->items, next * sizeof *grown);
        if (!grown) return 0;
        tree->items = grown;
        tree->capacity = next;
    }
    memset(&tree->items[tree->count], 0, sizeof tree->items[0]);
    tree->items[tree->count].path = strdup(path);
    tree->items[tree->count].output = output ? strdup(output) : NULL;
    tree->items[tree->count].suggested = suggested ? strdup(suggested) : NULL;
    if (!tree->items[tree->count].path || (output && !tree->items[tree->count].output) ||
        (suggested && !tree->items[tree->count].suggested)) {
        free(tree->items[tree->count].path);
        free(tree->items[tree->count].output);
        free(tree->items[tree->count].suggested);
        return 0;
    }
    tree->items[tree->count].explicit_rule = explicit_rule;
    tree->items[tree->count].decision = decision;
    tree->items[tree->count].decision_kind = kind;
    snprintf(tree->items[tree->count].reason, sizeof tree->items[tree->count].reason, "%s",
             reason ? reason : "");
    ++tree->count;
    return 1;
}

static void tree_free(struct split_tree *tree)
{
    size_t i;
    for (i = 0; i < tree->count; ++i) {
        free(tree->items[i].path);
        free(tree->items[i].output);
        free(tree->items[i].suggested);
    }
    free(tree->items);
    memset(tree, 0, sizeof *tree);
}

static int safe_component(const char *value)
{
    const char *at = value;
    if (!value || !*value || value[0] == '/') return 0;
    while (*at) {
        size_t length = strcspn(at, "/");
        if (!length || (length == 1 && at[0] == '.') ||
            (length == 2 && at[0] == '.' && at[1] == '.')) return 0;
        at += length;
        if (*at == '/') ++at;
    }
    return 1;
}

static char *join(const char *left, const char *right)
{
    size_t a = strlen(left), b = strlen(right);
    char *result;
    if (a > (size_t)-1 - b - 2) return NULL;
    result = malloc(a + b + 2);
    if (!result) return NULL;
    memcpy(result, left, a);
    result[a] = '/';
    memcpy(result + a + 1, right, b + 1);
    return result;
}

/* a relative path is safe when it cannot leave the tree it names. the base is the
   directory a link sits in, because that is what a relative target resolves against */
static int link_escapes(const char *path, const char *target)
{
    char stack[64][256];
    size_t depth = 0;
    const char *at = path;
    const char *slash = strrchr(path, '/');
    const char *stop = slash ? slash : path;
    if (target[0] == '/') return 1;
    while (at < stop) {
        const char *next = memchr(at, '/', (size_t)(stop - at));
        size_t length = next ? (size_t)(next - at) : (size_t)(stop - at);
        if (depth == sizeof stack / sizeof *stack || length + 1 > sizeof stack[0]) return 1;
        if (length == 2 && at[0] == '.' && at[1] == '.') {
            if (!depth) return 1;
            --depth;
        } else if (!(length == 1 && at[0] == '.')) {
            memcpy(stack[depth], at, length);
            stack[depth][length] = 0;
            ++depth;
        }
        if (!next) break;
        at = next + 1;
    }
    for (at = target; *at;) {
        const char *slash = strchr(at, '/');
        size_t length = slash ? (size_t)(slash - at) : strlen(at);
        if (length == 2 && at[0] == '.' && at[1] == '.') {
            if (!depth) return 1;
            --depth;
        } else if (!(length == 1 && at[0] == '.')) {
            if (depth == sizeof stack / sizeof *stack || length + 1 > sizeof stack[0]) return 1;
            memcpy(stack[depth], at, length);
            stack[depth][length] = 0;
            ++depth;
        }
        if (!slash) break;
        at = slash + 1;
    }
    return 0;
}

/* a documentation path a general pattern would also match, except a license and a
   data file the runtime needs, which a documentation output must not take */
static int documentation(const char *path)
{
    static const char *const licenses[] = {
        "COPYING", "COPYRIGHT", "LICENSE", "LICENCE", "NOTICE", NULL
    };
    static const char *const sections[] = {"/man/", "/doc/", "/docs/", "/info/", NULL};
    const char *base = strrchr(path, '/');
    const char *at;
    size_t i;
    base = base ? base + 1 : path;
    for (i = 0; licenses[i]; ++i) {
        size_t length = strlen(licenses[i]);
        if (strncasecmp(base, licenses[i], length)) continue;
        if (!base[length] || base[length] == '.') return 0;
    }
    for (i = 0; sections[i]; ++i)
        if (strstr(path, sections[i])) return 1;
    /* a bare section directory is documentation too */
    at = strstr(path, "/man");
    if (at && (!at[4] || at[4] == '/')) return 1;
    return 0;
}


static int ends_with(const char *value, const char *suffix)
{
    size_t value_length = strlen(value), suffix_length = strlen(suffix);
    return value_length > suffix_length &&
           !strcmp(value + value_length - suffix_length, suffix);
}

/* a shared object carrying a version stays in the runtime output, and one without a
   version may still be a plugin the payload opens through dlopen */
static int shared_object(const char *base, int *versioned)
{
    const char *at;
    if (!strstr(base, ".so")) return 0;
    at = strstr(base, ".so");
    if (at[3] == '.') {
        const char *digit = at + 3;
        while (*digit == '.') ++digit;
        if (*digit >= '0' && *digit <= '9') {
            *versioned = 1;
            return 1;
        }
    }
    *versioned = 0;
    return 1;
}

/* the heuristic for one path, which names its output and why, or leaves the output
   unset and records a decision kind */
static const char *heuristic(const char *path, int is_regular, int executable,
                             const char **reason, int *decision_kind, const char *devel,
                             const char *docs, const char *runtime)
{
    const char *base = strrchr(path, '/');
    int versioned = 0;
    base = base ? base + 1 : path;
    *decision_kind = 0;
    *reason = "runtime payload";
    if (!is_regular) return runtime;
    if (ends_with(path, "/include") || strstr(path, "/include/")) {
        *reason = "header";
        return devel;
    }
    if (ends_with(base, ".h") || ends_with(base, ".hpp") || ends_with(base, ".hxx") ||
        ends_with(base, ".hh") || ends_with(base, ".inc")) {
        *reason = "header";
        return devel;
    }
    if (ends_with(base, ".pc") || strstr(path, "/pkgconfig/")) {
        *reason = "pkg-config metadata";
        return devel;
    }
    if (ends_with(base, ".a")) {
        *reason = "static archive";
        *decision_kind = SPLIT_STATIC_ARCHIVE;
        return devel;
    }
    if (shared_object(base, &versioned)) {
        if (versioned) {
            *reason = "versioned shared object";
            return runtime;
        }
        /* an unversioned object is not development material on the strength of its
           name: metadata or a dlopen probe decides, and a tree states neither */
        *reason = "shared object without a version";
        *decision_kind = SPLIT_UNVERSIONED_OBJECT;
        return runtime;
    }
    if (documentation(path)) {
        *reason = "documentation";
        return docs;
    }
    if (executable) *reason = "executable";
    return runtime;
}

static const char *explicit_output(const char *path, const struct split_rule *rules,
                                   size_t count, int *matched)
{
    size_t i;
    const char *found = NULL;
    for (i = 0; i < count; ++i) {
        if (fnmatch(rules[i].pattern, path, 0)) continue;
        /* the first rule wins, and a second rule naming another output is a
           contradiction the operator has to settle */
        if (!found) found = rules[i].output;
        else if (strcmp(found, rules[i].output)) {
            *matched = 1;
            return NULL;
        }
    }
    *matched = found ? 1 : 0;
    return found;
}

static int walk(struct split_tree *tree, int parent, const char *prefix, unsigned depth,
                const struct split_rule *rules, size_t rule_count, const char *devel,
                const char *docs, const char *runtime)
{
    DIR *list;
    struct dirent *entry;
    int copy, ok = 1;
    if (depth > 64 || tree->count >= SPLIT_PATHS) return 0;
    copy = dup(parent);
    if (copy < 0) return 0;
    list = fdopendir(copy);
    if (!list) { close(copy); return 0; }
    errno = 0;
    while ((entry = readdir(list))) {
        struct stat st;
        char *path = NULL;
        const char *output;
        int matched = 0, kind = 0, is_regular = 0, executable = 0;
        const char *reason = NULL;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (!safe_component(entry->d_name)) {
            fputs("holypkg: a tree member is not a payload path this manager can place\n",
                  stderr);
            ok = 0;
            break;
        }
        /* the payload path is relative to the tree, so a top-level member has no
           directory prefix at all */
        path = *prefix ? join(prefix, entry->d_name) : strdup(entry->d_name);
        if (!path) { ok = 0; break; }
        if (fstatat(parent, entry->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
            free(path);
            ok = 0;
            break;
        }
        if (S_ISDIR(st.st_mode)) {
            int child = openat(parent, entry->d_name,
                               O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (child < 0 || !walk(tree, child, path, depth + 1, rules, rule_count, devel,
                                   docs, runtime))
                ok = 0;
            if (child >= 0) close(child);
            free(path);
            if (!ok) break;
            errno = 0;
            continue;
        }
        if (S_ISLNK(st.st_mode)) {
            char target[4096];
            ssize_t length = readlinkat(parent, entry->d_name, target, sizeof target - 1);
            if (length <= 0) { free(path); ok = 0; break; }
            target[length] = 0;
            output = explicit_output(path, rules, rule_count, &matched);
            if (output) {
                if (!tree_add(tree, path, output, 1, 0, 0, NULL, "explicit rule")) ok = 0;
            } else if (matched) {
                if (!tree_add(tree, path, NULL, 0, 1, SPLIT_REPEATED, NULL, NULL)) ok = 0;
            } else if (link_escapes(path, target)) {
                if (!tree_add(tree, path, NULL, 0, 1, SPLIT_ESCAPING_LINK, NULL, NULL))
                    ok = 0;
            } else if (!tree_add(tree, path, runtime, 0, 0, 0, NULL, "payload link")) ok = 0;
            free(path);
            if (!ok) break;
            errno = 0;
            continue;
        }
        if (!S_ISREG(st.st_mode)) {
            fputs("holypkg: a tree member is a device, socket or fifo, and a payload does not\n"
                  "       carry one\n", stderr);
            free(path);
            ok = 0;
            break;
        }
        is_regular = 1;
        executable = (st.st_mode & 0111) != 0;
        output = explicit_output(path, rules, rule_count, &matched);
        if (output) {
            if (!tree_add(tree, path, output, 1, 0, 0, NULL, "explicit rule")) ok = 0;
        } else if (matched) {
            if (!tree_add(tree, path, NULL, 0, 1, SPLIT_REPEATED, NULL, NULL)) ok = 0;
        } else {
            const char *guess = heuristic(path, is_regular, executable, &reason, &kind, devel,
                                          docs, runtime);
            /* a heuristic that cannot settle the path records what it would have
               chosen and lets the operator decide */
            if (!tree_add(tree, path, kind ? NULL : guess, 0, kind ? 1 : 0, kind,
                          kind ? guess : NULL, reason)) ok = 0;
        }
        free(path);
        if (!ok) break;
        errno = 0;
    }
    if (errno) ok = 0;
    closedir(list);
    return ok;
}

/* a name the outputs may be derived from, read from the prepared tree's own meta */
static int read_name(int holy, char *name, size_t size)
{
    char line[512];
    FILE *stream;
    int found = 0;
    int fd = openat(holy, "meta", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 0;
    stream = fdopen(fd, "r");
    if (!stream) { close(fd); return 0; }
    while (fgets(line, sizeof line, stream)) {
        size_t length = strlen(line);
        while (length && (line[length - 1] == '\n' || line[length - 1] == '\r')) --length;
        if (length <= 5 || strncmp(line, "name ", 5)) continue;
        if (length - 5 >= size) break;
        memcpy(name, line + 5, length - 5);
        name[length - 5] = 0;
        found = 1;
        break;
    }
    if (ferror(stream)) found = 0;
    fclose(stream);
    return found;
}

static int label(const char *value)
{
    size_t at;
    if (!value || !*value || !isalnum((unsigned char)value[0])) return 0;
    for (at = 0; value[at]; ++at)
        if (!isalnum((unsigned char)value[at]) &&
            !(value[at] == '.' || value[at] == '_' || value[at] == '+' || value[at] == '-'))
            return 0;
    return 1;
}

static void quoted(FILE *out, const char *value)
{
    const unsigned char *at = (const unsigned char *)value;
    fputc('"', out);
    for (; *at; ++at) {
        if (*at == '"' || *at == '\\') fprintf(out, "\\%c", *at);
        else if (*at < 32 || *at >= 127) fprintf(out, "\\x%02x", (unsigned int)*at);
        else fputc(*at, out);
    }
    fputc('"', out);
}

int holy_split_propose(const char *tree, const char *output, char *const *rule, size_t rules)
{
    struct split_tree paths = {0};
    struct split_rule declared[64];
    size_t i, decisions = 0, runtime_files = 0;
    size_t devel_files = 0, doc_files = 0, rule_count = 0;
    int devel_declared = 0, docs_declared = 0, devel_pending = 0;
    char name[256], devel[288], docs[288], runtime[288];
    int root = -1, holy = -1, data = -1, result = 1;
    FILE *out = NULL;

    if (!tree || !*tree || !output || !*output) {
        fputs("usage: holypkg split TREE --output NEW_FILE [--split OUTPUT GLOB ...]\n", stderr);
        return 2;
    }
    if (rules % 2) {
        fputs("holypkg: split --split takes an output and a pattern\n", stderr);
        return 2;
    }
    if (rules / 2 > sizeof declared / sizeof *declared) {
        fputs("holypkg: too many split rules for one proposal\n", stderr);
        return 2;
    }
    for (i = 0; i < rules; i += 2) {
        if (!label(rule[i]) || !rule[i + 1] || !*rule[i + 1]) {
            fputs("holypkg: a split rule names an output and a pattern\n", stderr);
            return 2;
        }
        declared[rule_count].output = rule[i];
        declared[rule_count].pattern = rule[i + 1];
        ++rule_count;
    }
    root = open(tree, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) {
        fprintf(stderr, "holypkg: prepared tree unavailable: %s\n", tree);
        return 6;
    }
    holy = openat(root, "HOLY", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    data = openat(root, "DATA", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (holy < 0 || data < 0 || !read_name(holy, name, sizeof name)) {
        fputs("holypkg: a prepared tree carries HOLY/meta with a package name\n", stderr);
        result = 2;
        goto done;
    }
    if (!label(name)) {
        fputs("holypkg: the tree names no package a split output may be derived from\n", stderr);
        result = 2;
        goto done;
    }
    snprintf(runtime, sizeof runtime, "%s", name);
    snprintf(devel, sizeof devel, "%s-devel", name);
    snprintf(docs, sizeof docs, "%s-doc", name);
    for (i = 0; i < rule_count; ++i) {
        if (strcmp(declared[i].output, runtime) && strcmp(declared[i].output, devel) &&
            strcmp(declared[i].output, docs)) {
            /* a rule may only name one of the outputs this proposal declares, or the
               proposal would describe a set the tree does not name */
            fprintf(stderr, "holypkg: a split rule names the undeclared output %s\n",
                    declared[i].output);
            result = 2;
            goto done;
        }
    }
    if (!walk(&paths, data, "", 0, declared, rule_count, devel, docs, runtime)) goto done;
    /* an output is declared only when at least one path is assigned to it, because a
       declared output that receives nothing fails the build it is proposed for */
    for (i = 0; i < paths.count; ++i) {
        if (paths.items[i].decision) { ++decisions; continue; }
        if (!strcmp(paths.items[i].output, devel)) ++devel_files;
        else if (!strcmp(paths.items[i].output, docs)) ++doc_files;
        else ++runtime_files;
    }
    /* a decision that suggests the development output still needs the output declared,
       because the operator settles it that way more often than not, and a declared
       output that receives nothing is what a build rejects */
    for (i = 0; i < paths.count; ++i)
        if (paths.items[i].decision && paths.items[i].suggested &&
            !strcmp(paths.items[i].suggested, devel)) devel_pending = 1;
    if (devel_files || devel_pending) devel_declared = 1;
    if (doc_files) docs_declared = 1;
    out = fopen(output, "w");
    if (!out) {
        fprintf(stderr, "holypkg: proposal unavailable: %s\n", output);
        goto done;
    }
    fputs("format holy-split-1\nname ", out); quoted(out, name);
    fputs("\noutput ", out); quoted(out, runtime); fputs(" runtime\n", out);
    if (devel_declared) {
        fputs("output ", out); quoted(out, devel); fputs(" devel\n", out);
    }
    if (docs_declared) {
        fputs("output ", out); quoted(out, docs); fputs(" docs\n", out);
    }
    for (i = 0; i < rule_count; ++i) {
        fputs("split ", out); quoted(out, declared[i].output); fputc(' ', out);
        quoted(out, declared[i].pattern);
        fputc('\n', out);
    }
    for (i = 0; i < paths.count; ++i) {
        const struct split_path *item = &paths.items[i];
        if (item->decision) continue;
        fputs("path ", out); quoted(out, item->path); fputc(' ', out);
        quoted(out, item->output);
        fputc(' ', out); quoted(out, item->reason);
        fputc('\n', out);
    }
    for (i = 0; i < paths.count; ++i) {
        const struct split_path *item = &paths.items[i];
        if (!item->decision) continue;
        fputs("decision ", out); quoted(out, item->path); fputc(' ', out);
        quoted(out, decision_name(item->decision_kind));
        if (item->suggested) {
            fputs(" suggested ", out);
            quoted(out, item->suggested);
        }
        if (*item->reason) {
            fputs(" reason ", out);
            quoted(out, item->reason);
        }
        fputc('\n', out);
    }
    fputs("count paths ", out);
    fprintf(out, "%zu runtime %zu devel %zu docs %zu decisions %zu rules %zu\n",
            paths.count, runtime_files, devel_files, doc_files, decisions, rule_count);
    if (ferror(out) || fclose(out)) {
        out = NULL;
        fputs("holypkg: the split proposal was not written completely\n", stderr);
        goto done;
    }
    out = NULL;
    printf("split %s paths %zu runtime %zu devel %zu docs %zu decisions %zu\n", output,
           paths.count, runtime_files, devel_files, doc_files, decisions);
    for (i = 0; i < paths.count; ++i)
        if (paths.items[i].decision)
            printf("decision %s %s\n", paths.items[i].path,
                   decision_name(paths.items[i].decision_kind));
    result = decisions ? 3 : 0;
done:
    if (out) fclose(out);
    tree_free(&paths);
    if (data >= 0) close(data);
    if (holy >= 0) close(holy);
    if (root >= 0) close(root);
    return result;
}
