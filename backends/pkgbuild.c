/* PKGBUILD to holy-recipe(5) conversion; see man/holy-recipe.5 and man/holypkg.8.
   the file is read as text. no part of it is executed by the converter. */
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1
#include "pkgbuild.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct kb_value {
    char *name;
    char *text;
    size_t line;
};

struct kb_list {
    char *name;
    struct kb_value *items;
    size_t count;
    size_t line;
};

struct kb_block {
    char *name;
    char *body;
    size_t length;
    size_t first;
    size_t last;
};

struct pkgbuild {
    char *text;
    size_t length;
    char *directory;
    struct kb_list *lists;
    size_t list_count;
    struct kb_value *scalars;
    size_t scalar_count;
    struct kb_block *blocks;
    size_t block_count;
};

static void free_list(struct kb_list *list)
{
    size_t i;
    for (i = 0; i < list->count; ++i) { free(list->items[i].name); free(list->items[i].text); }
    free(list->items);
    free(list->name);
}

static void pkgbuild_free(struct pkgbuild *pkg)
{
    size_t i;
    for (i = 0; i < pkg->list_count; ++i) free_list(&pkg->lists[i]);
    for (i = 0; i < pkg->scalar_count; ++i) {
        free(pkg->scalars[i].name);
        free(pkg->scalars[i].text);
    }
    for (i = 0; i < pkg->block_count; ++i) {
        free(pkg->blocks[i].name);
        free(pkg->blocks[i].body);
    }
    free(pkg->lists);
    free(pkg->scalars);
    free(pkg->blocks);
    free(pkg->directory);
    free(pkg->text);
    memset(pkg, 0, sizeof *pkg);
}

static char *copy_range(const char *start, size_t length)
{
    char *value = malloc(length + 1);
    if (!value) return NULL;
    memcpy(value, start, length);
    value[length] = 0;
    return value;
}

/* drops one layer of shell quoting; an unquoted value is used as written. */
static char *unquote(const char *start, size_t length)
{
    char *value = copy_range(start, length), *out;
    size_t used = 0, i;
    if (!value) return NULL;
    if (length < 2 || (start[0] != '\'' && start[0] != '"') ||
        start[length - 1] != start[0]) return value;
    out = malloc(length + 1);
    if (!out) { free(value); return NULL; }
    for (i = 1; i + 1 < length; ++i) {
        char c = start[i];
        if (c == '\\' && i + 2 < length &&
            (start[i + 1] == '\'' || start[i + 1] == '"' || start[i + 1] == '\\')) {
            out[used++] = start[++i];
            continue;
        }
        out[used++] = c;
    }
    out[used] = 0;
    free(value);
    return out;
}

static int name_char(char c, int first)
{
    if (isalpha((unsigned char)c) || c == '_') return 1;
    return !first && isdigit((unsigned char)c);
}

static struct kb_list *list_for(struct pkgbuild *pkg, const char *name, size_t line, int create)
{
    size_t i;
    struct kb_list *grown;
    for (i = 0; i < pkg->list_count; ++i)
        if (!strcmp(pkg->lists[i].name, name)) return &pkg->lists[i];
    if (!create) return NULL;
    grown = realloc(pkg->lists, (pkg->list_count + 1) * sizeof *grown);
    if (!grown) return NULL;
    pkg->lists = grown;
    memset(&grown[pkg->list_count], 0, sizeof grown[0]);
    grown[pkg->list_count].name = strdup(name);
    if (!grown[pkg->list_count].name) return NULL;
    grown[pkg->list_count].line = line;
    ++pkg->list_count;
    return &pkg->lists[pkg->list_count - 1];
}

static const struct kb_list *find_list(const struct pkgbuild *pkg, const char *name)
{
    size_t i;
    for (i = 0; i < pkg->list_count; ++i)
        if (!strcmp(pkg->lists[i].name, name)) return &pkg->lists[i];
    return NULL;
}

static const char *find_scalar(const struct pkgbuild *pkg, const char *name)
{
    size_t i;
    for (i = 0; i < pkg->scalar_count; ++i)
        if (!strcmp(pkg->scalars[i].name, name)) return pkg->scalars[i].text;
    return NULL;
}

static size_t scalar_line(const struct pkgbuild *pkg, const char *name)
{
    size_t i;
    for (i = 0; i < pkg->scalar_count; ++i)
        if (!strcmp(pkg->scalars[i].name, name)) return pkg->scalars[i].line;
    return 0;
}

static int list_push(struct kb_list *list, char *text, size_t line)
{
    struct kb_value *grown = realloc(list->items, (list->count + 1) * sizeof *grown);
    if (!grown) return 0;
    list->items = grown;
    memset(&grown[list->count], 0, sizeof grown[0]);
    grown[list->count].text = text;
    grown[list->count].line = line;
    ++list->count;
    return 1;
}

/* makepkg accepts both source=('a') and a single source=a; several keys are scalars. */
static struct kb_list *list_or_scalar(struct pkgbuild *pkg, const char *key)
{
    struct kb_list *list = list_for(pkg, key, 0, 0);
    const char *value = find_scalar(pkg, key);
    char *copy;
    if (list || !value) return list;
    list = list_for(pkg, key, scalar_line(pkg, key), 1);
    if (!list || !(copy = strdup(value))) return list;
    if (!list_push(list, copy, scalar_line(pkg, key))) { free(copy); return NULL; }
    return list;
}

static const struct kb_block *find_block(const struct pkgbuild *pkg, const char *name)
{
    size_t i;
    for (i = 0; i < pkg->block_count; ++i)
        if (!strcmp(pkg->blocks[i].name, name)) return &pkg->blocks[i];
    return NULL;
}

static int is_sha256(const char *value)
{
    size_t i;
    for (i = 0; i < 64; ++i)
        if (!isxdigit((unsigned char)value[i])) return 0;
    return !value[64];
}

/* makepkg expands these names inside source entries; the values are known here. */
static char *expand_names(const char *value, const char *pkgbase, const char *name,
                          const char *version, const char *release)
{
    static const char *const tokens[] = { "$pkgbase", "$pkgname", "$pkgver", "$pkgrel", NULL };
    const char *names[4];
    char *out = copy_range(value, strlen(value));
    size_t index;
    if (!out) return NULL;
    names[0] = pkgbase;
    names[1] = name;
    names[2] = version;
    names[3] = release;
    for (index = 0; tokens[index]; ++index) {
        size_t size = strlen(tokens[index]), used = 0, at = 0;
        size_t length = strlen(out);
        char *next;
        if (!strstr(out, tokens[index])) continue;
        next = malloc(length + 1);
        if (!next) { free(out); return NULL; }
        while (at < length) {
            if (!strncmp(out + at, tokens[index], size)) {
                used += (size_t)sprintf(next + used, "%s", names[index]);
                at += size;
                continue;
            }
            next[used++] = out[at++];
        }
        next[used] = 0;
        free(out);
        out = next;
    }
    return out;
}

/* quote aware scan for the end of a list body; returns NULL when unterminated. */
static const char *list_end(const char *cursor, const char *stop)
{
    char quote = 0;
    for (; cursor < stop; ++cursor) {
        char c = *cursor;
        if (quote) {
            if (c == quote) quote = 0;
            else if (c == '\\' && quote == '"' && cursor + 1 < stop) ++cursor;
            continue;
        }
        if (c == '\'' || c == '"') quote = c;
        else if (c == ')' || c == '\n') return cursor;
    }
    return NULL;
}

/* splits the body of a parenthesized list into its elements. */
static int parse_list(struct pkgbuild *pkg, const char *name, const char *body, size_t length,
                      size_t line)
{
    struct kb_list *list = list_for(pkg, name, line, 1);
    size_t i = 0;
    if (!list) return 0;
    /* a shell array separates elements on whitespace, so a comma stays in the name */
    while (i < length) {
        char quote = 0;
        size_t start;
        while (i < length && isspace((unsigned char)body[i])) ++i;
        if (i >= length) break;
        start = i;
        while (i < length) {
            char c = body[i];
            if (quote) {
                if (c == quote) quote = 0;
                else if (c == '\\' && quote == '"' && i + 1 < length) ++i;
            } else if (c == '\'' || c == '"') {
                quote = c;
            } else if (isspace((unsigned char)c)) {
                break;
            }
            ++i;
        }
        if (quote) return 0;
        {
            char *text = unquote(body + start, i - start);
            if (!text || !list_push(list, text, line)) { free(text); return 0; }
        }
    }
    return 1;
}

/* finds the closing brace of a function body, ignoring quoted and substituted text. */
static const char *block_end(const char *body, const char *stop)
{
    size_t depth = 0, i;
    char quote = 0;
    for (i = 0; body + i < stop; ++i) {
        char c = body[i];
        if (quote) {
            if (c == quote) quote = 0;
            else if (c == '\\' && quote == '"') ++i;
            continue;
        }
        if (c == '\'' || c == '"' || c == '`') { quote = c; continue; }
        if ((c == '$' || c == '\\') && body + i + 1 < stop &&
            (body[i + 1] == '(' || body[i + 1] == '{')) {
            char open = body[i + 1];
            char close = open == '(' ? ')' : '}';
            size_t inner = 0;
            for (++i; body + i < stop; ++i) {
                if (body[i] == open) ++inner;
                else if (body[i] == close) {
                    if (!inner) break;
                    --inner;
                }
            }
            continue;
        }
        if (c == '{') ++depth;
        else if (c == '}') {
            if (!depth) return body + i;
            --depth;
        }
    }
    return NULL;
}

/* reads name=value records, name=( ... ) lists and function bodies. */
static int parse_pkgbuild(struct pkgbuild *pkg)
{
    size_t offset = 0, line = 0;
    while (offset < pkg->length) {
        char *start = pkg->text + offset;
        char *newline = memchr(start, '\n', pkg->length - offset);
        size_t size = newline ? (size_t)(newline - start) : pkg->length - offset;
        size_t name_length = 0, i;
        char *cursor;
        ++line;
        offset += size + (newline ? 1 : 0);
        while (size && (*start == ' ' || *start == '\t' || start[size - 1] == '\r')) {
            ++start;
            --size;
        }
        if (!size || *start == '#') continue;
        cursor = start;
        while (name_length < size && name_char(cursor[name_length], !name_length)) ++name_length;
        if (!name_length) {
            fprintf(stderr, "holypkg: PKGBUILD:%zu: unsupported top level statement\n", line);
            return 2;
        }
        if (name_length + 2 < size && cursor[name_length] == '(' && cursor[name_length + 1] == ')' &&
            isspace((unsigned char)cursor[name_length + 2])) {
            const char *brace = memchr(cursor, '{', size);
            const char *body = brace ? brace + 1 : start + size;
            const char *close = block_end(body, pkg->text + pkg->length);
            size_t body_line = line;
            struct kb_block block;
            if (!close) {
                fprintf(stderr, "holypkg: PKGBUILD:%zu: unterminated function\n", line);
                return 2;
            }
            for (i = 0; body + i < close; ++i) if (body[i] == '\n') ++line;
            offset = (size_t)(close - pkg->text) + 1;
            memset(&block, 0, sizeof block);
            block.name = copy_range(start, name_length);
            block.body = copy_range(body, (size_t)(close - body));
            block.length = (size_t)(close - body);
            block.first = body_line;
            block.last = line;
            if (!block.name || !block.body) {
                free(block.name);
                free(block.body);
                return 2;
            }
            {
                struct kb_block *grown = realloc(pkg->blocks,
                                        (pkg->block_count + 1) * sizeof *grown);
                if (!grown) { free(block.name); free(block.body); return 2; }
                pkg->blocks = grown;
                pkg->blocks[pkg->block_count++] = block;
            }
            continue;
        }
        if (name_length >= size || cursor[name_length] != '=') {
            fprintf(stderr, "holypkg: PKGBUILD:%zu: unsupported statement\n", line);
            return 2;
        }
        {
            char *name = copy_range(start, name_length);
            char *value = cursor + name_length + 1;
            size_t value_size = size - name_length - 1;
            while (value_size && (*value == ' ' || *value == '\t')) { ++value; --value_size; }
            if (!name) return 2;
            if (value_size && *value == '(') {
                const char *body = value + 1;
                const char *stop = pkg->text + pkg->length;
                size_t body_line = line;
                const char *close = list_end(body, value + value_size);
                int ok;
                while (!close && offset < pkg->length) {
                    char *row = pkg->text + offset;
                    char *row_end = memchr(row, '\n', pkg->length - offset);
                    size_t row_size = row_end ? (size_t)(row_end - row) : pkg->length - offset;
                    ++line;
                    offset += row_size + (row_end ? 1 : 0);
                    close = list_end(row, row + row_size);
                    if (close) break;
                }
                if (!close) close = stop;
                ok = close > body && parse_list(pkg, name, body, (size_t)(close - body), body_line);
                free(name);
                if (!ok) {
                    fprintf(stderr, "holypkg: PKGBUILD: unterminated list\n");
                    return 2;
                }
                continue;
            }
            {
                char *text = unquote(value, value_size);
                struct kb_value *grown = realloc(pkg->scalars,
                                        (pkg->scalar_count + 1) * sizeof *grown);
                if (!text || !grown) { free(text); free(name); return 2; }
                pkg->scalars = grown;
                pkg->scalars[pkg->scalar_count].name = name;
                pkg->scalars[pkg->scalar_count].text = text;
                pkg->scalars[pkg->scalar_count].line = line;
                ++pkg->scalar_count;
            }
        }
    }
    return 0;
}

struct note {
    char **lines;
    size_t count;
    size_t carried, preserved, helper, unknown, changes;
};

static int note_add(struct note *note, const char *kind, const char *format, ...)
{
    char body[1024], *line;
    va_list arguments;
    char **grown;
    va_start(arguments, format);
    if (vsnprintf(body, sizeof body, format, arguments) < 0) { va_end(arguments); return 0; }
    va_end(arguments);
    line = malloc(strlen(kind) + strlen(body) + 2);
    if (!line) return 0;
    sprintf(line, "%s %s", kind, body);
    grown = realloc(note->lines, (note->count + 1) * sizeof *grown);
    if (!grown) { free(line); return 0; }
    note->lines = grown;
    note->lines[note->count++] = line;
    if (!strcmp(kind, "carried")) ++note->carried;
    else if (!strcmp(kind, "preserved")) ++note->preserved;
    else if (!strcmp(kind, "helper")) ++note->helper;
    else if (!strcmp(kind, "unknown")) ++note->unknown;
    else if (!strcmp(kind, "semantic-change")) ++note->changes;
    return 1;
}

static void note_free(struct note *note)
{
    size_t i;
    for (i = 0; i < note->count; ++i) free(note->lines[i]);
    free(note->lines);
    memset(note, 0, sizeof *note);
}

static void token(FILE *out, const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    fputc('"', out);
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') fprintf(out, "\\%c", *p);
        else if (*p < 32 || *p >= 127) fprintf(out, "\\x%02x", *p);
        else fputc(*p, out);
    }
    fputc('"', out);
}

/* the manager names relations itself, so the upstream operator is translated. */
static const char *relation_name(const char *operator)
{
    if (!strcmp(operator, ">=")) return "ge";
    if (!strcmp(operator, "<=")) return "le";
    if (!strcmp(operator, ">")) return "gt";
    if (!strcmp(operator, "<")) return "lt";
    if (!strcmp(operator, "=")) return "eq";
    return "any";
}

/* writes one dependency keeping the upstream name, its relation and its version. */
static void emit_dependency(FILE *out, const char *raw, const char *kind)
{
    static const char *const operators[] = { ">=", "<=", "=", ">", "<", NULL };
    char name[256];
    size_t used = 0;
    const char *cursor = raw;
    const char *relation = NULL;
    while (*cursor == ' ' || *cursor == '\t') ++cursor;
    if (!*cursor) return;
    if (!strcmp(kind, "build-depend") && !strncmp(cursor, "cmd:", 4)) {
        fputs("build-depend cmd:", out);
        token(out, cursor + 4);
        fputc('\n', out);
        return;
    }
    /* the name ends at whitespace, at a description colon or at a relation operator */
    while (*cursor && !isspace((unsigned char)*cursor) && *cursor != ':' &&
           !strchr("<>=~", *cursor) && used + 1 < sizeof name)
        name[used++] = *cursor++;
    name[used] = 0;
    if (!used) return;
    while (isspace((unsigned char)*cursor)) ++cursor;
    {
        size_t index;
        for (index = 0; operators[index]; ++index)
            if (!strncmp(cursor, operators[index], strlen(operators[index]))) {
                relation = operators[index];
                cursor += strlen(operators[index]);
                break;
            }
    }
    while (*cursor == ' ' || *cursor == '\t') ++cursor;
    fputs(kind, out);
    fputc(' ', out);
    token(out, name);
    if (relation && *cursor) {
        fputc(' ', out);
        token(out, relation_name(relation));
        fputc(' ', out);
        token(out, cursor);
    } else {
        fputs(" \"any\" \"-\"", out);
    }
    fputc('\n', out);
}

struct substitution {
    const char *from;
    const char *to;
};

static const struct substitution common_variables[] = {
    { "$srcdir", "$HOLY_SRC" },
    { "$startdir", "$HOLY_BUILD" },
    { "$builddir", "$HOLY_BUILD" },
    { "$srcdest", "$HOLY_WORK/sources" },
    { "$pkgdest", "$HOLY_OUT" }
};

/* rewrites the makepkg working variables the manager already exports.
   a reference inside a double quoted word needs no quoting of its own. */
static char *substitute(const char *body, size_t length, const char *pkgdir, size_t *out_length)
{
    struct substitution variables[6];
    size_t capacity = length * 2 + 256, used = 0, i = 0, count = 0, index;
    char quote = 0;
    char *out = malloc(capacity);
    if (!out) return NULL;
    variables[count].from = "$pkgdir";
    variables[count++].to = pkgdir;
    for (index = 0; index < sizeof common_variables / sizeof *common_variables; ++index)
        variables[count++] = common_variables[index];
    while (i < length) {
        size_t rule;
        int matched = 0;
        for (rule = 0; quote != '\'' && rule < count; ++rule) {
            size_t size = strlen(variables[rule].from);
            size_t size_to = strlen(variables[rule].to);
            size_t end = i + size;
            if (strncmp(body + i, variables[rule].from, size)) continue;
            if (body[end] == '{') {
                const char *close = memchr(body + end, '}', length - end);
                if (!close) continue;
                end = (size_t)(close - body) + 1;
            }
            if (used + size_to + 2 > capacity) {
                char *grown = realloc(out, capacity * 2);
                if (!grown) { free(out); return NULL; }
                capacity *= 2;
                out = grown;
            }
            /* inside quotes the variable expands in place, outside it is one word */
            if (quote != '"') out[used++] = '"';
            memcpy(out + used, variables[rule].to, size_to);
            used += size_to;
            if (quote != '"') out[used++] = '"';
            i = end;
            matched = 1;
            break;
        }
        if (matched) continue;
        if (quote) {
            if (body[i] == quote) quote = 0;
            else if (body[i] == '\\' && quote == '"' && i + 1 < length) out[used++] = body[i++];
        } else if (body[i] == '\'' || body[i] == '"') {
            quote = body[i];
        }
        out[used++] = body[i++];
    }
    out[used] = 0;
    if (out_length) *out_length = used;
    return out;
}

/* the makepkg variables a phase body may read, rebuilt from the exported paths. */
static char *prologue(const char *name, const char *version, const char *release,
                      const char *arch, int split)
{
    char *text = NULL;
    size_t used = 0;
    FILE *out = open_memstream(&text, &used);
    if (!out) return NULL;
    fputs("# makepkg variables translated from PKGBUILD\n", out);
    fprintf(out, "pkgname=%s\npkgver=%s\npkgrel=%s\narch=%s\n", name, version, release, arch);
    fputs("srcdir=\"$HOLY_SRC\"\nstartdir=\"$HOLY_BUILD\"\nbuilddir=\"$HOLY_BUILD\"\n", out);
    fprintf(out, "pkgdir=%s\n", split ? "\"$HOLY_SPLIT_DEST\"" : "\"$HOLY_DEST\"");
    fputs("srcdest=\"$HOLY_WORK/sources\"\npkgdest=\"$HOLY_OUT\"\n", out);
    fputs("CFLAGS=${CFLAGS:--O2 -pipe}\nCXXFLAGS=${CXXFLAGS:-$CFLAGS}\n", out);
    fputs("CPPFLAGS=${CPPFLAGS:-}\nLDFLAGS=${LDFLAGS:--Wl,-z,relro -Wl,--as-needed}\n", out);
    fputs("MAKEFLAGS=${MAKEFLAGS:--j$HOLY_JOBS}\n", out);
    fclose(out);
    return text;
}

static int emit_block(FILE *out, const char *phase, const char *tag, const char *prefix,
                      const char *pkgdir, const struct kb_block *block)
{
    size_t length = 0;
    char *body = substitute(block->body, block->length, pkgdir, &length);
    int result = 1;
    if (!body) return 0;
    if (fprintf(out, "step %s /bin/bash <<%s\n", phase, tag) < 0 ||
        fputs(prefix, out) < 0 || fwrite(body, 1, length, out) != length ||
        fprintf(out, "\n%s\n", tag) < 0) result = 0;
    free(body);
    return result;
}

/* a package_NAME function fills the staging tree of one named output. */
static int emit_split_block(FILE *out, const char *output, const char *prefix,
                            const struct kb_block *block)
{
    size_t length = 0;
    char *body = substitute(block->body, block->length, "$HOLY_SPLIT_DEST", &length);
    int result = 1;
    if (!body) return 0;
    if (fputs("split-step ", out) < 0 || fputs(output, out) < 0 ||
        fputs(" split /bin/bash <<SPLIT\n", out) < 0 ||
        fputs(prefix, out) < 0 || fwrite(body, 1, length, out) != length ||
        fprintf(out, "\nSPLIT\n") < 0) result = 0;
    free(body);
    return result;
}

static int write_digest(const char *target, const char *input, char hash[65])
{
    unsigned char buffer[65536], bytes[32];
    unsigned size = 0;
    size_t got, i;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    FILE *in = fopen(input, "rb"), *out = fopen(target, "wb");
    int result = 0;
    if (!in || !out || !context || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) goto done;
    while ((got = fread(buffer, 1, sizeof buffer, in)) > 0)
        if (EVP_DigestUpdate(context, buffer, got) != 1 ||
            fwrite(buffer, 1, got, out) != got) goto done;
    if (ferror(in) || EVP_DigestFinal_ex(context, bytes, &size) != 1 || size != 32) goto done;
    for (i = 0; i < 32; ++i) snprintf(hash + i * 2, 3, "%02x", bytes[i]);
    hash[64] = 0;
    result = !fflush(out);
done:
    if (out) { if (fclose(out) && !result) result = 0; }
    if (in) fclose(in);
    EVP_MD_CTX_free(context);
    if (result) chmod(target, 0600);
    else unlink(target);
    return result;
}

int holy_convert_pkgbuild(const char *input, const char *source, const char *output)
{
    struct pkgbuild pkg = {0};
    struct note note = {0};
    struct { char name[512]; const struct kb_block *block; } splits[16];
    struct { char base[256]; char installed[600]; } hook_paths[8];
    FILE *out = NULL;
    char hash[65] = {0};
    char recipe_path[4096], report_path[4096], target[4096];
    char name[512] = {0}, arch[64] = "x86_64", version[512] = {0}, release[64] = {0};
    const char *license = NULL;
    size_t splits_used = 0, hooks = 0, k;
    int result = 1, review = 0, i, wrote = 1;

    if (!input || !output || !*output) {
        fputs("usage: holypkg convert PKGBUILD --source NAME --output NEW_DIRECTORY\n", stderr);
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
        struct stat st;
        FILE *file;
        if (stat(input, &st) || !S_ISREG(st.st_mode) || st.st_size > 4 * 1024 * 1024) {
            fprintf(stderr, "holypkg: PKGBUILD unavailable: %s\n", input);
            return 6;
        }
        pkg.length = (size_t)st.st_size;
        pkg.text = malloc(pkg.length + 1);
        file = pkg.text ? fopen(input, "rb") : NULL;
        if (!file || fread(pkg.text, 1, pkg.length, file) != pkg.length) {
            if (file) fclose(file);
            pkgbuild_free(&pkg);
            fputs("holypkg: PKGBUILD could not be read\n", stderr);
            return 6;
        }
        fclose(file);
        pkg.text[pkg.length] = 0;
    }
    pkg.directory = strdup(input);
    if (!pkg.directory) { pkgbuild_free(&pkg); return 1; }
    {
        char *slash = strrchr(pkg.directory, '/');
        if (slash) *slash = 0;
        else strcpy(pkg.directory, ".");
    }
    result = parse_pkgbuild(&pkg);
    if (result) goto done;

    {
        const char *pkgname = find_scalar(&pkg, "pkgname");
        const char *pkgbase = find_scalar(&pkg, "pkgbase");
        const char *declared = find_scalar(&pkg, "pkgver");
        const char *packager = find_scalar(&pkg, "pkgrel");
        const struct kb_list *arches = find_list(&pkg, "arch");
        const struct kb_list *licenses = find_list(&pkg, "license");
        if (!pkgbase) pkgbase = pkgname;
        if (!pkgbase || !declared || !packager) {
            fputs("holypkg: PKGBUILD: pkgbase, pkgver and pkgrel are required\n", stderr);
            result = 2;
            goto done;
        }
        if (strpbrk(declared, "$`") || strpbrk(packager, "$`") ||
            strlen(pkgbase) > 480 || strlen(declared) > 480 || strlen(packager) > 60) {
            fputs("holypkg: PKGBUILD: identity must be literal and short\n", stderr);
            result = 2;
            goto done;
        }
        snprintf(name, sizeof name, "%s", pkgbase);
        snprintf(version, sizeof version, "%s", declared);
        snprintf(release, sizeof release, "%s", packager);
        if (licenses && licenses->count) {
            char joined[512];
            size_t used = 0;
            for (k = 0; k < licenses->count; ++k)
                used += (size_t)snprintf(joined + used, sizeof joined - used, "%s%s",
                                         used ? " " : "", licenses->items[k].text);
            license = strdup(joined);
        } else {
            license = strdup(find_scalar(&pkg, "license") ? find_scalar(&pkg, "license") : "");
        }
        if (!license) { result = 1; goto done; }
        if (arches) {
            int x86_64 = 0, i686 = 0, noarch = 0, any = 0;
            for (k = 0; k < arches->count; ++k) {
                if (!strcmp(arches->items[k].text, "x86_64")) x86_64 = 1;
                else if (!strcmp(arches->items[k].text, "x86")) i686 = 1;
                else if (!strcmp(arches->items[k].text, "noarch")) noarch = 1;
                else if (!strcmp(arches->items[k].text, "any")) any = 1;
            }
            if (noarch && arches->count == 1) snprintf(arch, sizeof arch, "noarch");
            else if (i686 && !x86_64) snprintf(arch, sizeof arch, "i686");
            else if (x86_64) snprintf(arch, sizeof arch, "x86_64");
            else if (any && arches->count == 1) snprintf(arch, sizeof arch, "any");
            else {
                snprintf(arch, sizeof arch, "%s", arches->items[0].text);
                review = 1;
                note_add(&note, "unknown", "arch list PKGBUILD:%zu", arches->line);
            }
        }
    }
    note_add(&note, "carried", "name PKGBUILD:%zu", scalar_line(&pkg, "pkgbase") ?
             scalar_line(&pkg, "pkgbase") : scalar_line(&pkg, "pkgname"));
    note_add(&note, "carried", "version PKGBUILD:%zu", scalar_line(&pkg, "pkgver"));
    note_add(&note, "carried", "release PKGBUILD:%zu", scalar_line(&pkg, "pkgrel"));
    for (k = 0; k < pkg.block_count; ++k) {
        const char *block_name = pkg.blocks[k].name;
        if (!strcmp(block_name, "prepare") || !strcmp(block_name, "build") ||
            !strcmp(block_name, "check") || !strcmp(block_name, "package")) continue;
        if (strncmp(block_name, "package_", 8) || !block_name[8] ||
            splits_used >= sizeof splits / sizeof *splits ||
            snprintf(splits[splits_used].name, sizeof splits[splits_used].name, "%s-%s",
                     name, block_name + 8) >= (int)sizeof splits[splits_used].name) {
            review = 1;
            note_add(&note, "unknown", "function %s PKGBUILD:%zu-%zu",
                     block_name, pkg.blocks[k].first, pkg.blocks[k].last);
            continue;
        }
        splits[splits_used].block = &pkg.blocks[k];
        ++splits_used;
    }
    {
        static const char *const unmapped[] = {
            "noextract", "validpgpkeys", "options", "b2sums", "md5sums",
            "source_x86_64", "source_i686", "source_aarch64", "source_any", NULL
        };
        size_t index;
        for (index = 0; unmapped[index]; ++index) {
            const struct kb_list *list = find_list(&pkg, unmapped[index]);
            if (!list) continue;
            review = 1;
            note_add(&note, "unknown", "%s PKGBUILD:%zu", unmapped[index], list->line);
        }
    }

    if (mkdir(output, 0700) && errno != EEXIST) {
        fprintf(stderr, "holypkg: conversion directory unavailable: %s\n", output);
        result = 1;
        goto done;
    }
    snprintf(target, sizeof target, "%s/PKGBUILD", output);
    if (!write_digest(target, input, hash)) {
        fprintf(stderr, "holypkg: PKGBUILD copy failed\n");
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
    fputs("format holy-recipe-1\nname ", out); token(out, name);
    fputs("\nversion ", out); token(out, version);
    fputs("\nrelease ", out); token(out, release);
    fputs("\narch ", out); token(out, arch);
    fputs("\nlibc any\n", out);
    {
        const char *summary = find_scalar(&pkg, "pkgdesc");
        const char *homepage = find_scalar(&pkg, "url");
        if (summary) { fputs("summary ", out); token(out, summary); fputc('\n', out); }
        if (homepage) { fputs("homepage ", out); token(out, homepage); fputc('\n', out); }
        if (*license) { fputs("license ", out); token(out, license); fputc('\n', out); }
    }
    fputs("x-source-family pacman\nx-converter pkgbuild-1\n", out);
    {
        const char *epoch = find_scalar(&pkg, "epoch");
        const char *groups = find_scalar(&pkg, "groups");
        const char *data = find_scalar(&pkg, "xdata");
        if (epoch) { fputs("x-epoch ", out); token(out, epoch); fputc('\n', out); }
        if (groups) { fputs("x-groups ", out); token(out, groups); fputc('\n', out); }
        if (data) { fputs("x-data ", out); token(out, data); fputc('\n', out); }
    }
    {
        const struct kb_list *sources = find_list(&pkg, "source");
        const struct kb_list *sums = find_list(&pkg, "sha256sums");
        const char *pkgname = find_scalar(&pkg, "pkgname");
        for (k = 0; sources && k < sources->count; ++k) {
            char *url = expand_names(sources->items[k].text, name,
                                     pkgname ? pkgname : name, version, release);
            const char *base = url ? strrchr(url, '/') : NULL;
            const char *digest = sums && k < sums->count && is_sha256(sums->items[k].text) ?
                                sums->items[k].text : NULL;
            char copied[4096], original[4096], ignored[65];
            struct stat st;
            int ok = url && *url;
            base = base ? base + 1 : url;
            if (ok && (!base || !*base || strlen(base) > 400 || strpbrk(base, " \t$`'\"") ||
                       !strcmp(base, ".") || !strcmp(base, ".."))) ok = 0;
            /* a local source travels with the recipe, so it is copied beside it */
            if (ok && !strpbrk(url, ":/")) {
                snprintf(original, sizeof original, "%s/%s", pkg.directory, url);
                snprintf(copied, sizeof copied, "%s/%s", output, base);
                if (stat(original, &st) || !S_ISREG(st.st_mode) ||
                    !write_digest(copied, original, ignored)) {
                    review = 1;
                    note_add(&note, "unknown", "local source %s is not next to the PKGBUILD "
                             "PKGBUILD:%zu", url, sources->items[k].line);
                    free(url);
                    continue;
                }
                note_add(&note, "semantic-change", "local source %s copied next to the recipe",
                         url);
            }
            if (!ok) {
                review = 1;
                note_add(&note, "unknown", "source %s PKGBUILD:%zu",
                         sources->items[k].text, sources->items[k].line);
                free(url);
                continue;
            }
            fputs("source ", out);
            token(out, base);
            fputc(' ', out);
            token(out, url);
            fputc('\n', out);
            if (digest) {
                fputs("source-sha256 ", out);
                token(out, base);
                fputc(' ', out);
                token(out, digest);
                fputc('\n', out);
            } else if (strpbrk(url, ":/")) {
                review = 1;
                note_add(&note, "unknown", "source %s has no sha256sum PKGBUILD:%zu",
                         url, sources->items[k].line);
            }
            note_add(&note, "carried", "source %s PKGBUILD:%zu", url, sources->items[k].line);
            free(url);
        }
    }
    {
        static const char *const build_lists[] = { "makedepends", "checkdepends", NULL };
        size_t index;
        for (index = 0; build_lists[index]; ++index) {
            const struct kb_list *list = find_list(&pkg, build_lists[index]);
            for (k = 0; list && k < list->count; ++k) {
                emit_dependency(out, list->items[k].text, "build-depend");
                note_add(&note, "carried", "%s %s PKGBUILD:%zu",
                         build_lists[index], list->items[k].text, list->items[k].line);
            }
        }
    }
    {
        const struct kb_list *depends = find_list(&pkg, "depends");
        for (k = 0; depends && k < depends->count; ++k) {
            emit_dependency(out, depends->items[k].text, "depend");
            note_add(&note, "carried", "depends %s PKGBUILD:%zu",
                     depends->items[k].text, depends->items[k].line);
        }
    }
    {
        static const char *const kept[] = { "provides", "conflicts", "replaces", NULL };
        size_t index;
        for (index = 0; kept[index]; ++index) {
            const struct kb_list *list = find_list(&pkg, kept[index]);
            for (k = 0; list && k < list->count; ++k) {
                fputs("x-", out);
                fputs(kept[index], out);
                fputc(' ', out);
                token(out, list->items[k].text);
                fputc('\n', out);
                review = 1;
                note_add(&note, "carried", "%s %s PKGBUILD:%zu",
                         kept[index], list->items[k].text, list->items[k].line);
            }
        }
    }
    {
        const struct kb_list *optional = find_list(&pkg, "optdepends");
        for (k = 0; optional && k < optional->count; ++k) {
            const char *text = optional->items[k].text;
            const char *colon = strchr(text, ':');
            const char *hint = colon ? colon + 1 : NULL;
            char item[512];
            while (hint && isspace((unsigned char)*hint)) ++hint;
            snprintf(item, sizeof item, "%.*s", colon ? (int)(colon - text) : (int)strlen(text),
                     text);
            fputs("x-optdepend ", out);
            token(out, item);
            if (hint && *hint) { fputc(' ', out); token(out, hint); }
            fputc('\n', out);
            note_add(&note, "carried", "optdepends %s PKGBUILD:%zu", text,
                     optional->items[k].line);
        }
    }
    {
        const struct kb_list *backup = find_list(&pkg, "backup");
        for (k = 0; backup && k < backup->count; ++k) {
            const char *path = backup->items[k].text;
            if (strncmp(path, "etc/", 4) || strpbrk(path, "$` \t")) {
                review = 1;
                note_add(&note, "unknown", "backup %s PKGBUILD:%zu", path, backup->items[k].line);
                continue;
            }
            fputs("config ", out);
            token(out, path);
            fputc('\n', out);
            note_add(&note, "carried", "backup %s PKGBUILD:%zu", path, backup->items[k].line);
        }
    }
    {
        const struct kb_list *installs = list_or_scalar(&pkg, "install");
        for (k = 0; installs && k < installs->count; ++k) {
            const char *file = installs->items[k].text;
            const char *base = strrchr(file, '/');
            char installed[600], copied[4096], original[4096], ignored[65];
            struct stat st;
            size_t size;
            base = base ? base + 1 : file;
            if (strpbrk(file, "$` \t") || !base[0] || strlen(base) > 200 ||
                !strcmp(base, ".") || !strcmp(base, "..")) {
                review = 1;
                note_add(&note, "unknown", "install %s PKGBUILD:%zu", file, installs->items[k].line);
                continue;
            }
            size = strlen(base);
            if (size > 8 && !strcmp(base + size - 8, ".install"))
                snprintf(installed, sizeof installed, "usr/share/holy/%s/%s", name, base);
            else
                snprintf(installed, sizeof installed, "usr/share/holy/%s/%s.install", name, base);
            snprintf(original, sizeof original, "%s/%s", pkg.directory, file);
            snprintf(copied, sizeof copied, "%s/%s", output, base);
            if (stat(original, &st) || !S_ISREG(st.st_mode) ||
                !write_digest(copied, original, ignored)) {
                review = 1;
                note_add(&note, "unknown", "install %s is not next to the PKGBUILD PKGBUILD:%zu",
                         file, installs->items[k].line);
                continue;
            }
            fputs("source ", out);
            token(out, base);
            fputc(' ', out);
            token(out, base);
            fputc('\n', out);
            fputs("hook-install /bin/bash ", out);
            token(out, installed);
            fputc('\n', out);
            if (hooks >= sizeof hook_paths / sizeof *hook_paths) continue;
            snprintf(hook_paths[hooks].base, sizeof hook_paths[hooks].base, "%s", base);
            snprintf(hook_paths[hooks].installed, sizeof hook_paths[hooks].installed, "%s", installed);
            ++hooks;
            note_add(&note, "preserved", "hook %s PKGBUILD:%zu", file, installs->items[k].line);
            note_add(&note, "semantic-change",
                     "%s installed as %s; pre_install and post_install become one postinstall",
                     file, installed);
        }
    }
    {
        const struct kb_list *sources = find_list(&pkg, "source");
        if (sources && sources->count == 1) {
            const char *pkgname = find_scalar(&pkg, "pkgname");
            char *url = expand_names(sources->items[0].text, name,
                                     pkgname ? pkgname : name, version, release);
            const char *base = url ? strrchr(url, '/') : NULL;
            base = base ? base + 1 : url;
            if (url && *base && !strpbrk(base, " \t$`'\"")) {
                /* makepkg points srcdir at the directory inside the archive, not at
                   the archive name, so the extracted content is lifted one level. */
                fputs("step unpack /bin/sh <<UNPACK\n", out);
                fprintf(out, "for entry in \"$HOLY_SRC/%s\"/* \"$HOLY_SRC/%s\"/.[!.]* "
                             "\"$HOLY_SRC/%s\"/..?*; do\n"
                             "  [ -e \"$entry\" ] || continue\n"
                             "  mv \"$entry\" \"$HOLY_SRC/\"\n"
                             "done\n"
                             "rm -rf \"$HOLY_SRC/%s\"\n"
                             "UNPACK\n", base, base, base, base);
                note_add(&note, "semantic-change",
                         "single source lifted so HOLY_SRC matches the makepkg srcdir");
            }
            free(url);
        }
    }
    {
        const struct kb_block *package = find_block(&pkg, "package");
        const struct kb_block *prepare = find_block(&pkg, "prepare");
        const struct kb_block *build = find_block(&pkg, "build");
        const struct kb_block *check = find_block(&pkg, "check");
        char *prefix = prologue(name, version, release, arch, 0);
        if (!prefix) { result = 1; goto done; }
        fputs("output ", out);
        token(out, name);
        fputs(package ? " runtime\n" : " metapackage\n", out);
        for (k = 0; k < splits_used; ++k) {
            fputs("output ", out);
            token(out, splits[k].name);
            fputs(" runtime\n", out);
        }
        if (package) {
            if (prepare && !emit_block(out, "prepare", "PREPARE", prefix, "$HOLY_DEST", prepare))
                wrote = 0;
            if (build && !emit_block(out, "build", "BUILD", prefix, "$HOLY_DEST", build)) wrote = 0;
            if (check && !emit_block(out, "check", "CHECK", prefix, "$HOLY_DEST", check)) wrote = 0;
            if (!emit_block(out, "package", "PACKAGE", prefix, "$HOLY_DEST", package)) wrote = 0;
        }
        free(prefix);
        for (k = 0; k < hooks; ++k) {
            char directory[600];
            char *slash;
            snprintf(directory, sizeof directory, "%s", hook_paths[k].installed);
            slash = strrchr(directory, '/');
            if (!slash) { wrote = 0; break; }
            *slash = 0;
            if (fprintf(out, "step package /bin/sh <<HOOKS\n"
                             "mkdir -p \"$HOLY_DEST/%s\"\n"
                             "cp \"$HOLY_SRC/%s\" \"$HOLY_DEST/%s\"\n"
                             "HOOKS\n", directory, hook_paths[k].base,
                        hook_paths[k].installed) < 0) wrote = 0;
        }
        for (k = 0; k < splits_used && wrote; ++k) {
            char *split_prefix = prologue(name, version, release, arch, 1);
            if (!split_prefix || !emit_split_block(out, splits[k].name, split_prefix,
                                                   splits[k].block)) wrote = 0;
            free(split_prefix);
        }
        if (package) {
            note_add(&note, "preserved", "package PKGBUILD:%zu-%zu",
                     package->first, package->last);
            if (prepare) note_add(&note, "preserved", "prepare PKGBUILD:%zu-%zu",
                                  prepare->first, prepare->last);
            if (build) note_add(&note, "preserved", "build PKGBUILD:%zu-%zu",
                                build->first, build->last);
            if (check) note_add(&note, "preserved", "check PKGBUILD:%zu-%zu",
                                check->first, check->last);
        }
        for (k = 0; k < splits_used; ++k)
            note_add(&note, "preserved", "split %s PKGBUILD:%zu-%zu", splits[k].name,
                     splits[k].block->first, splits[k].block->last);
    }
    if (find_block(&pkg, "prepare"))
        note_add(&note, "helper", "makepkg prepare environment not carried");
    if (find_block(&pkg, "build"))
        note_add(&note, "helper", "makepkg.conf CFLAGS and LDFLAGS profile not carried");
    if (find_block(&pkg, "check"))
        note_add(&note, "helper", "makepkg check environment not carried");
    if (fflush(out) || fclose(out)) { out = NULL; result = 1; goto done; }
    out = NULL;
    if (!wrote) {
        unlink(recipe_path);
        fputs("holypkg: the converted recipe could not be written\n", stderr);
        result = 1;
        goto done;
    }

    out = fopen(report_path, "wb");
    if (!out) {
        fprintf(stderr, "holypkg: report unavailable: %s\n", report_path);
        result = 1;
        goto done;
    }
    fputs("format holy-recipe-conversion-1\nconverter pkgbuild-1\n", out);
    fputs("source-name ", out); token(out, source); fputc('\n', out);
    fputs("source-file PKGBUILD\n", out);
    fprintf(out, "source-sha256 %s\n", hash);
    fputs("pkgbase ", out); token(out, name); fputc('\n', out);
    fputs("version ", out); token(out, version); fputc('\n', out);
    fputs("release ", out); token(out, release); fputc('\n', out);
    fputs("arch ", out); token(out, arch); fputc('\n', out);
    fputs("recipe ", out); token(out, name); fputs(".recipe\n", out);
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
        fprintf(stderr, "holypkg: PKGBUILD conversion failed (status %d)\n", result);
    note_free(&note);
    free((char *)license);
    pkgbuild_free(&pkg);
    return result;
}
