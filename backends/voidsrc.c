/* Void template to holy-recipe(5) conversion; see man/holy-recipe.5 and man/holypkg.8.
   the template is read as text and no part of it is executed by the converter.
   the xbps-src phase bodies keep their original bash; a step prologue rebuilds the
   xbps-src variables from the exported Holy paths and carries the v* helpers. */
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1
#include "voidsrc.h"

#include <archive.h>
#include <archive_entry.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <openssl/evp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct vs_value {
    char *name;
    char *text;
    size_t line;
    int append;
    int conditional;
};

struct vs_function {
    char *name;
    char *body;
    size_t length;
    size_t first;
    size_t last;
    int conditional;
};

struct vs_condition {
    char *text;
    size_t line;
};

struct voidsrc {
    char *text;
    size_t length;
    char *directory;
    struct vs_value *values;
    size_t value_count;
    struct vs_function *functions;
    size_t function_count;
    struct vs_condition *conditions;
    size_t condition_count;
};

static void voidsrc_free(struct voidsrc *pkg)
{
    size_t i;
    for (i = 0; i < pkg->value_count; ++i) {
        free(pkg->values[i].name);
        free(pkg->values[i].text);
    }
    for (i = 0; i < pkg->function_count; ++i) {
        free(pkg->functions[i].name);
        free(pkg->functions[i].body);
    }
    for (i = 0; i < pkg->condition_count; ++i) free(pkg->conditions[i].text);
    free(pkg->values);
    free(pkg->functions);
    free(pkg->conditions);
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

/* the last assignment of a name wins and an appended value follows the earlier one. */
static char *value_join(const struct voidsrc *pkg, const char *name)
{
    char *out = NULL;
    size_t i;
    for (i = 0; i < pkg->value_count; ++i) {
        if (strcmp(pkg->values[i].name, name)) continue;
        if (out && pkg->values[i].append) {
            char *grown = realloc(out, strlen(out) + strlen(pkg->values[i].text) + 1);
            if (!grown) { free(out); return NULL; }
            strcat(grown, pkg->values[i].text);
            out = grown;
            continue;
        }
        free(out);
        out = strdup(pkg->values[i].text);
        if (!out) return NULL;
    }
    return out;
}

static size_t value_line(const struct voidsrc *pkg, const char *name)
{
    size_t i;
    for (i = 0; i < pkg->value_count; ++i)
        if (!strcmp(pkg->values[i].name, name)) return pkg->values[i].line;
    return 0;
}

static int value_present(const struct voidsrc *pkg, const char *name)
{
    size_t i;
    for (i = 0; i < pkg->value_count; ++i)
        if (!strcmp(pkg->values[i].name, name)) return 1;
    return 0;
}

static const struct vs_function *find_function(const struct voidsrc *pkg, const char *name)
{
    size_t i;
    for (i = 0; i < pkg->function_count; ++i)
        if (!strcmp(pkg->functions[i].name, name)) return &pkg->functions[i];
    return NULL;
}

/* the end of a $( ) group that starts at cursor, or NULL when it is unterminated */
static const char *substitution_end(const char *cursor, const char *stop)
{
    size_t depth = 1, i = 0;
    char inner = 0;
    for (i = 0; cursor + i < stop; ++i) {
        char c = cursor[i];
        if (inner) {
            if (c == inner) inner = 0;
            else if (c == '\\' && inner == '"') ++i;
            continue;
        }
        if (c == '\'' || c == '"') inner = c;
        else if (c == '(') ++depth;
        else if (c == ')' && !--depth) return cursor + i;
    }
    return NULL;
}

/* 1 while a quote is open, so a value may continue on the next line. a $( ) group
   carries its own quoting, so it never closes the quote that contains it. */
static int quote_open(const char *text, size_t length)
{
    char quote = 0;
    size_t i = 0;
    if (length && text[0] == '#') return 0;
    while (i < length) {
        char c = text[i];
        if (quote == '\'') {
            if (c == '\'') quote = 0;
            ++i;
            continue;
        }
        if (c == '\\') { i += 2; continue; }
        if ((c == '$' || c == '`') && text[i + 1] == '(') {
            const char *close = substitution_end(text + i + 2, text + length);
            if (!close) return 1;
            i = (size_t)(close - text) + 1;
            continue;
        }
        if (c == '`') {
            const char *close = memchr(text + i + 1, '`', length - i - 1);
            if (!close) return 1;
            i = (size_t)(close - text) + 1;
            continue;
        }
        if (quote == '"') {
            if (c == '"') quote = 0;
            ++i;
            continue;
        }
        if (c == '\'' || c == '"') { quote = c; ++i; continue; }
        ++i;
    }
    return quote ? 1 : 0;
}

/* the closing brace of a function body, ignoring quoted and substituted text. */
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
        /* a comment ends at the newline and its quotes are not shell quotes */
        if (c == '#') {
            while (body + i < stop && body[i] != '\n') ++i;
            continue;
        }
        if (c == '\'' || c == '"' || c == '`') { quote = c; continue; }
        if ((c == '$' || c == '\\') && body + i + 1 < stop &&
            (body[i + 1] == '(' || body[i + 1] == '{')) {
            char open = body[i + 1];
            char close = open == '(' ? ')' : '}';
            /* the scan starts past the opener, so the first close ends the group */
            size_t inner = 0;
            for (i += 2; body + i < stop; ++i) {
                if (body[i] == open) ++inner;
                else if (body[i] == close) {
                    if (inner) --inner;
                    else break;
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

static int push_value(struct voidsrc *pkg, char *name, char *text, size_t line, int append,
                      int conditional)
{
    struct vs_value *grown = realloc(pkg->values, (pkg->value_count + 1) * sizeof *grown);
    if (!grown) return 0;
    pkg->values = grown;
    memset(&grown[pkg->value_count], 0, sizeof grown[0]);
    grown[pkg->value_count].name = name;
    grown[pkg->value_count].text = text;
    grown[pkg->value_count].line = line;
    grown[pkg->value_count].append = append;
    grown[pkg->value_count].conditional = conditional;
    ++pkg->value_count;
    return 1;
}

static int push_condition(struct voidsrc *pkg, const char *text, size_t line)
{
    struct vs_condition *grown;
    char *copy = copy_range(text, strlen(text));
    if (!copy) return 0;
    grown = realloc(pkg->conditions, (pkg->condition_count + 1) * sizeof *grown);
    if (!grown) { free(copy); return 0; }
    pkg->conditions = grown;
    grown[pkg->condition_count].text = copy;
    grown[pkg->condition_count].line = line;
    ++pkg->condition_count;
    return 1;
}

/* reads assignments, conditional blocks and function bodies from the template text. */
static int parse_template(struct voidsrc *pkg)
{
    size_t offset = 0, line = 0, depth = 0, cases = 0;
    while (offset < pkg->length) {
        char *start = pkg->text + offset;
        char *newline = memchr(start, '\n', pkg->length - offset);
        size_t size = newline ? (size_t)(newline - start) : pkg->length - offset;
        char *next = newline ? newline + 1 : pkg->text + pkg->length;
        size_t name_length = 0, i;
        char *cursor;
        int conditional;
        ++line;
        offset = (size_t)(next - pkg->text);
        while (size && (*start == ' ' || *start == '\t' || start[size - 1] == '\r')) {
            ++start;
            --size;
        }
        if (!size || *start == '#') continue;
        conditional = depth > 0;
        if (!strncmp(start, "if", 2) &&
            (size == 2 || start[2] == ' ' || start[2] == '\t')) {
            if (!push_condition(pkg, start, line)) return 1;
            ++depth;
            continue;
        }
        /* a case block selects values this converter cannot evaluate, so it is reported */
        if (!strncmp(start, "case", 4) &&
            (size == 4 || start[4] == ' ' || start[4] == '\t')) {
            if (!push_condition(pkg, start, line)) return 1;
            ++depth;
            ++cases;
            continue;
        }
        if (!strncmp(start, "esac", 4) &&
            (size == 4 || start[4] == ' ' || start[4] == '\t')) {
            if (!depth) {
                fprintf(stderr, "holypkg: template:%zu: esac without case\n", line);
                return 2;
            }
            --depth;
            if (cases) --cases;
            continue;
        }
        if (!strncmp(start, "esac", 4) && size >= 4) continue;
        /* a case pattern ends at its closing paren; only the body after it is an assignment */
        if (cases) {
            const char *close = memchr(start, ')', size);
            size_t body = close ? (size_t)(close + 1 - start) : size;
            while (body < size && isspace((unsigned char)start[body])) ++body;
            start = start + body;
            size -= body;
            if (!size) continue;
            if (!memchr(start, '=', size)) continue;
            if (start[0] == '#') continue;
        }
        /* a top level vopt_conflict only checks a pair, so it produces no assignment */
        if (!strncmp(start, "vopt_conflict", 13) &&
            (size == 13 || start[13] == ' ' || start[13] == '\t')) {
            if (!push_condition(pkg, start, line)) return 1;
            continue;
        }
        if (!strncmp(start, "export ", 7)) {
            start += 7;
            size -= 7;
            while (size && (*start == ' ' || *start == '\t')) { ++start; --size; }
            while (size && start[size - 1] == ' ') --size;
            if (!size) {
                fprintf(stderr, "holypkg: template:%zu: empty export\n", line);
                return 2;
            }
        }
        if (!strncmp(start, "elif", 4) || !strncmp(start, "else", 4)) {
            if (!depth || !push_condition(pkg, start, line)) return 1;
            continue;
        }
        if (!strncmp(start, "fi", 2) && (size == 2 || start[2] == ' ' || start[2] == '\t')) {
            if (!depth) {
                fprintf(stderr, "holypkg: template:%zu: fi without if\n", line);
                return 2;
            }
            --depth;
            continue;
        }
        cursor = start;
        /* a subpackage name carries dashes, a C++ library name carries a double plus,
           and a package may begin with a digit */
        while (name_length < size) {
            if (isdigit((unsigned char)cursor[name_length]) ||
                name_char(cursor[name_length], !name_length)) {
                ++name_length;
                continue;
            }
            if (cursor[name_length] == '+') {
                char next = cursor[name_length + 1];
                if (next == '+') name_length += 2;
                else if (name_char(next, 0) || next == '-' || next == '.') ++name_length;
                else break;
                continue;
            }
            if ((cursor[name_length] == '-' || cursor[name_length] == '.') &&
                name_char(cursor[name_length + 1], 0)) {
                ++name_length;
                continue;
            }
            break;
        }
        if (name_length + 2 < size && cursor[name_length] == '(' && cursor[name_length + 1] == ')' &&
            (isspace((unsigned char)cursor[name_length + 2]) || cursor[name_length + 2] == '{')) {
            const char *brace = memchr(cursor, '{', size);
            const char *body = brace ? brace + 1 : start + size;
            const char *close = block_end(body, pkg->text + pkg->length);
            struct vs_function function;
            struct vs_function *grown;
            if (!close) {
                fprintf(stderr, "holypkg: template:%zu: unterminated function\n", line);
                return 2;
            }
            for (i = 0; body + i < close; ++i) if (body[i] == '\n') ++line;
            offset = (size_t)(close - pkg->text) + 1;
            memset(&function, 0, sizeof function);
            function.name = copy_range(start, name_length);
            function.body = copy_range(body, (size_t)(close - body));
            function.length = (size_t)(close - body);
            function.first = line - (size_t)(close - body > 0 ? 1 : 0);
            function.last = line;
            function.conditional = conditional;
            /* the body may span lines, so the first line is the one the name is on */
            {
                size_t before = 0;
                for (i = 0; i < function.length; ++i) if (function.body[i] == '\n') ++before;
                function.first = line - before - 1;
            }
            if (!function.name || !function.body) {
                free(function.name);
                free(function.body);
                return 1;
            }
            grown = realloc(pkg->functions, (pkg->function_count + 1) * sizeof *grown);
            if (!grown) { free(function.name); free(function.body); return 1; }
            pkg->functions = grown;
            pkg->functions[pkg->function_count++] = function;
            continue;
        }
        /* a plain name=value record or an appended name+=value one */
        if (name_length >= size || (cursor[name_length] != '=' &&
                                    !(cursor[name_length] == '+' && name_length + 2 < size &&
                                      cursor[name_length + 1] == '='))) {
            fprintf(stderr, "holypkg: template:%zu: unsupported top level statement\n", line);
            return 2;
        }
        {
            char *name = copy_range(start, name_length);
            size_t at = name_length + 1;
            int append = 0;
            char *value;
            size_t value_size;
            char *text;
            if (name_length + 2 < size && cursor[name_length] == '+') { append = 1; at = name_length + 2; }
            value = cursor + at;
            value_size = size - at;
            while (value_size && (*value == ' ' || *value == '\t')) { ++value; --value_size; }
            /* an unquoted value ends at a comment the way the shell reads it */
            if (value_size && *value != '"' && *value != '\'') {
                char quote = 0;
                size_t index;
                for (index = 0; index < value_size; ++index) {
                    if (quote) {
                        if (value[index] == quote) quote = 0;
                        continue;
                    }
                    if (value[index] == '\'' || value[index] == '"') { quote = value[index]; continue; }
                    if (value[index] == '#' && (index == 0 || isspace((unsigned char)value[index - 1]))) {
                        while (index && isspace((unsigned char)value[index - 1])) --index;
                        value_size = index;
                        break;
                    }
                }
            }
            /* a long list continues on the next indented line while the quote is open */
            if (quote_open(value, value_size)) {
                size_t used = value_size;
                char *joined = malloc(used + 2);
                if (!joined) { free(name); return 1; }
                memcpy(joined, value, value_size);
                while (quote_open(joined, used) && offset < pkg->length) {
                    char *row = pkg->text + offset;
                    char *row_end = memchr(row, '\n', pkg->length - offset);
                    size_t row_size = row_end ? (size_t)(row_end - row) : pkg->length - offset;
                    char *grown;
                    size_t capacity = used + row_size + 2;
                    ++line;
                    offset = (size_t)(row_end ? row_end + 1 : pkg->text + pkg->length) -
                             (size_t)pkg->text;
                    grown = realloc(joined, capacity);
                    if (!grown) { free(joined); free(name); return 1; }
                    joined = grown;
                    joined[used++] = '\n';
                    memcpy(joined + used, row, row_size);
                    used += row_size;
                    joined[used] = 0;
                }
                if (quote_open(joined, used)) {
                    fprintf(stderr, "holypkg: template:%zu: unterminated value\n", line);
                    free(joined);
                    free(name);
                    return 2;
                }
                text = unquote(joined, used);
                free(joined);
            } else {
                text = unquote(value, value_size);
            }
            if (!text || !push_value(pkg, name, text, line, append, conditional)) {
                free(name);
                free(text);
                return 1;
            }
        }
    }
    if (depth) {
        fputs("holypkg: template: unterminated if block\n", stderr);
        return 2;
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

static int is_sha256(const char *value)
{
    size_t i;
    for (i = 0; i < 64; ++i)
        if (!isxdigit((unsigned char)value[i])) return 0;
    return !value[64];
}

static const char *relation_name(const char *operator)
{
    if (!strcmp(operator, ">=")) return "ge";
    if (!strcmp(operator, "<=")) return "le";
    if (!strcmp(operator, ">")) return "gt";
    if (!strcmp(operator, "<")) return "lt";
    if (!strcmp(operator, "=")) return "eq";
    return "any";
}

/* xbps-src spells a version comparator after the package name without a space. */
static void emit_dependency(FILE *out, const char *raw, const char *kind)
{
    static const char *const operators[] = { ">=", "<=", "=", ">", "<", NULL };
    char name[256];
    size_t used = 0;
    const char *cursor = raw;
    const char *relation = NULL;
    while (*cursor == ' ' || *cursor == '\t') ++cursor;
    if (!*cursor) return;
    while (*cursor && !isspace((unsigned char)*cursor) && !strchr("<>=~", *cursor) &&
           used + 1 < sizeof name)
        name[used++] = *cursor++;
    name[used] = 0;
    if (!used) return;
    {
        size_t index;
        for (index = 0; operators[index]; ++index)
            if (!strncmp(cursor, operators[index], strlen(operators[index]))) {
                relation = operators[index];
                cursor += strlen(operators[index]);
                break;
            }
    }
    while (isspace((unsigned char)*cursor)) ++cursor;
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

/* splits a whitespace separated list into a NULL terminated array of words. */
static char **words(const char *value, size_t *count)
{
    char **list = NULL;
    size_t used = 0, i = 0;
    *count = 0;
    if (!value) return NULL;
    while (i < strlen(value)) {
        size_t start;
        char *copy;
        char **grown;
        while (value[i] && isspace((unsigned char)value[i])) ++i;
        if (!value[i]) break;
        start = i;
        while (value[i] && !isspace((unsigned char)value[i])) ++i;
        copy = copy_range(value + start, i - start);
        if (!copy) goto failed;
        grown = realloc(list, (used + 2) * sizeof *grown);
        if (!grown) { free(copy); goto failed; }
        list = grown;
        list[used++] = copy;
        list[used] = NULL;
    }
    if (!list) {
        list = malloc(sizeof *list);
        if (!list) return NULL;
        list[0] = NULL;
    }
    *count = used;
    return list;
failed:
    for (i = 0; i < used; ++i) free(list[i]);
    free(list);
    return NULL;
}

static void words_free(char **list)
{
    size_t i;
    if (!list) return;
    for (i = 0; list[i]; ++i) free(list[i]);
    free(list);
}

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
                         struct note *note, int *review, const char *where)
{
    char *inner = copy_range(call + 2, length - 3);
    char **parts = NULL;
    size_t part_count = 0;
    char *out = NULL;
    const char *function;
    int enabled = 0;
    if (!inner) return NULL;
    parts = words(inner, &part_count);
    free(inner);
    if (!parts || !part_count) { words_free(parts); return NULL; }
    function = parts[0];
    if (!strcmp(function, "vopt_conflict")) {
        /* xbps-src only checks the pair; nothing appears in the built text */
        words_free(parts);
        return copy_range("", 0);
    }
    if (part_count < 2) {
        note_add(note, "unknown", "helper %s in %s takes no option", function, where);
        *review = 1;
        words_free(parts);
        return NULL;
    }
    if (!option_listed(set, parts[1])) {
        note_add(note, "unknown", "%s names the option %s, which build_options does not list",
                 function, parts[1]);
        *review = 1;
    }
    enabled = option_enabled(set, parts[1]);
    if (!strcmp(function, "vopt_if")) {
        const char *yes = part_count > 2 ? parts[2] : "";
        const char *no = part_count > 3 ? parts[3] : "";
        out = copy_range(enabled ? yes : no, strlen(enabled ? yes : no));
    } else if (!strcmp(function, "vopt_with")) {
        const char *flag = part_count > 2 ? parts[2] : parts[1];
        char text[512];
        snprintf(text, sizeof text, enabled ? "--with-%s" : "--without-%s", flag);
        out = copy_range(text, strlen(text));
    } else if (!strcmp(function, "vopt_enable")) {
        const char *flag = part_count > 2 ? parts[2] : parts[1];
        char text[512];
        snprintf(text, sizeof text, enabled ? "--enable-%s" : "--disable-%s", flag);
        out = copy_range(text, strlen(text));
    } else if (!strcmp(function, "vopt_bool") || !strcmp(function, "vopt_feature")) {
        const char *property = part_count > 2 ? parts[2] : parts[1];
        char text[512];
        if (!strcmp(function, "vopt_bool"))
            snprintf(text, sizeof text, "-D%s=%s", property, enabled ? "true" : "false");
        else
            snprintf(text, sizeof text, "-D%s=%s", property, enabled ? "enabled" : "disabled");
        out = copy_range(text, strlen(text));
    } else {
        note_add(note, "unknown", "helper %s in %s", function, where);
        *review = 1;
    }
    words_free(parts);
    return out;
}

static void option_set_free(struct option_set *set)
{
    size_t i;
    words_free(set->names);
    for (i = 0; i < set->enabled_count; ++i) free(set->enabled[i]);
    free(set->enabled);
    memset(set, 0, sizeof *set);
}

static void option_set_read(struct option_set *set, const struct voidsrc *pkg)
{
    char *joined = value_join(pkg, "build_options");
    char *defaults = value_join(pkg, "build_options_default");
    memset(set, 0, sizeof *set);
    if (joined) {
        set->names = words(joined, &set->count);
        free(joined);
    }
    if (defaults) {
        size_t count = 0, index;
        char **list = words(defaults, &count);
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
        words_free(list);
    }
}

/* fixes every $(vopt_...) call in one value, so the recipe carries no shell helper. */
static char *resolve_options(const struct voidsrc *pkg, struct note *note, int *review,
                             const char *value, const char *where)
{
    struct option_set set;
    char *out = NULL;
    size_t i = 0, used = 0, capacity;
    if (!value) return NULL;
    if (!*value || !strstr(value, "$(")) return copy_range(value, strlen(value));
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
static void report_unknowns(const char *body, size_t length, struct note *note, int *review,
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
            note_add(note, "unknown", "%s in %s", unresolved[index].text, where);
            *review = 1;
        }
    for (index = 0; variables[index]; ++index) {
        char braced[80];
        if (!strcmp(variables[index], "FILESDIR") && files) continue;
        if (!strcmp(variables[index], "PATCHESDIR") && patches) continue;
        snprintf(braced, sizeof braced, "${%s}", variables[index]);
        if (find_bytes(body, length, braced)) {
            note_add(note, "unknown", "variable %s in %s", variables[index], where);
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
static char *prologue(const struct voidsrc *pkg, const char *name, const char *version,
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
        struct note ignored;
        int flag = 0;
        memset(&ignored, 0, sizeof ignored);
        if (!value_present(pkg, carried[index])) continue;
        value = value_join(pkg, carried[index]);
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

static int hash_file(const char *path, char digest[65])
{
    unsigned char buffer[65536], bytes[32];
    unsigned size = 0;
    size_t got, i;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    FILE *in = context ? fopen(path, "rb") : NULL;
    int result = 0;
    if (!in || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) goto done;
    while ((got = fread(buffer, 1, sizeof buffer, in)) > 0)
        if (EVP_DigestUpdate(context, buffer, got) != 1) goto done;
    if (ferror(in) || EVP_DigestFinal_ex(context, bytes, &size) != 1 || size != 32) goto done;
    for (i = 0; i < 32; ++i) snprintf(digest + i * 2, 3, "%02x", bytes[i]);
    digest[64] = 0;
    result = 1;
done:
    if (in) fclose(in);
    EVP_MD_CTX_free(context);
    return result;
}

static int copy_file(const char *source, const char *target, char digest[65])
{
    unsigned char buffer[65536];
    size_t got;
    FILE *in = fopen(source, "rb"), *out = fopen(target, "wb");
    int result = 0;
    if (!in || !out) goto done;
    while ((got = fread(buffer, 1, sizeof buffer, in)) > 0)
        if (fwrite(buffer, 1, got, out) != got) goto done;
    if (ferror(in) || fflush(out)) goto done;
    result = 1;
done:
    if (in) fclose(in);
    if (out) { if (fclose(out) && result) result = 0; }
    if (!result) { unlink(target); return 0; }
    if (chmod(target, 0600) || !hash_file(target, digest)) return 0;
    return 1;
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
    return hash_file(target, digest);
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

static int append_text(char *out, size_t *used, size_t *capacity, const char *text, size_t length)
{
    while (*used + length + 1 > *capacity) {
        char *grown = realloc(out, *capacity * 2);
        if (!grown) return 0;
        *capacity *= 2;
        out = grown;
    }
    memcpy(out + *used, text, length);
    *used += length;
    out[*used] = 0;
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
            if (!append_text(out, &used, &capacity, value + i, 1)) goto failed;
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
            if (!append_text(out, &used, &capacity, resolved, strlen(resolved))) goto failed;
            i = start + 1;
            continue;
        }
        if (!name_char(value[i + 1], 0)) {
            if (!append_text(out, &used, &capacity, value + i, 1)) goto failed;
            ++i;
            continue;
        }
        start = i + 1;
        while (value[start] && name_char(value[start], 0) && length + 1 < sizeof word)
            word[length++] = value[start++];
        word[length] = 0;
        resolved = identity_value(word, name, version, release, replacement, sizeof replacement);
        if (!resolved) { *unknown = 1; goto failed_unexpanded; }
        if (!append_text(out, &used, &capacity, resolved, strlen(resolved))) goto failed;
        i = start;
    }
    return out;
failed_unexpanded:
    /* an expansion this converter does not know keeps its text and needs review */
    if (!append_text(out, &used, &capacity, value + i, strlen(value + i))) {
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
static void split_records(struct note *note, int *review, const struct vs_function *function,
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
            note_add(note, "preserved", "%s %.*s template:%zu", keys[index],
                     (int)(end - start - at), function->body + start + at, line);
        }
        if (end < function->length) ++line;
        start = end + 1;
    }
}

/* the pkg_install body inside a subpackage function fills one staging tree */
static int split_body(const struct vs_function *function, struct vs_function *out)
{
    static const char *const marker = "pkg_install()";
    const char *at = memmem(function->body, function->length, marker, strlen(marker));
    const char *brace, *close;
    size_t line = function->first, index;
    if (!at) return 0;
    brace = memchr(at, '{', function->length - (size_t)(at - function->body));
    if (!brace) return 0;
    close = block_end(brace + 1, function->body + function->length);
    if (!close) return 0;
    for (index = 0; function->body + index < brace + 1; ++index)
        if (function->body[index] == '\n') ++line;
    memset(out, 0, sizeof *out);
    out->name = strdup("pkg_install");
    out->body = copy_range(brace + 1, (size_t)(close - brace - 1));
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
    struct voidsrc pkg = {0};
    struct note note = {0};
    struct { char name[512]; struct vs_function install; } splits[16];
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
    {
        struct stat st;
        FILE *file;
        if (stat(input, &st) || !S_ISREG(st.st_mode) || st.st_size > 4 * 1024 * 1024) {
            fprintf(stderr, "holypkg: template unavailable: %s\n", input);
            return 6;
        }
        pkg.length = (size_t)st.st_size;
        pkg.text = malloc(pkg.length + 1);
        file = pkg.text ? fopen(input, "rb") : NULL;
        if (!file || fread(pkg.text, 1, pkg.length, file) != pkg.length) {
            if (file) fclose(file);
            voidsrc_free(&pkg);
            fputs("holypkg: template could not be read\n", stderr);
            return 6;
        }
        fclose(file);
        pkg.text[pkg.length] = 0;
    }
    pkg.directory = strdup(input);
    if (!pkg.directory) { voidsrc_free(&pkg); return 1; }
    {
        char *slash = strrchr(pkg.directory, '/');
        if (slash) *slash = 0;
        else strcpy(pkg.directory, ".");
    }
    result = parse_template(&pkg);
    if (result) goto done;

    {
        const char *declared = value_join(&pkg, "pkgname");
        const char *given_version = value_join(&pkg, "version");
        const char *given_release = value_join(&pkg, "revision");
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
    summary = value_join(&pkg, "short_desc");
    homepage = value_join(&pkg, "homepage");
    license = value_join(&pkg, "license");
    maintainer = value_join(&pkg, "maintainer");
    style = value_join(&pkg, "build_style");
    if (!result && pkg.condition_count) {
        for (k = 0; k < pkg.condition_count; ++k) {
            const char *text = pkg.conditions[k].text;
            review = 1;
            if (!strncmp(text, "vopt_conflict", 13))
                note_add(&note, "semantic-change",
                         "vopt_conflict checked against the fixed option set template:%zu %s",
                         pkg.conditions[k].line, text);
            else
                note_add(&note, "unknown", "conditional block template:%zu %s",
                         pkg.conditions[k].line, text);
        }
    }
    for (k = 0; k < pkg.value_count; ++k) {
        if (!pkg.values[k].conditional) continue;
        review = 1;
        note_add(&note, "unknown", "conditional assignment %s template:%zu",
                 pkg.values[k].name, pkg.values[k].line);
    }
    note_add(&note, "carried", "name template:%zu", value_line(&pkg, "pkgname"));
    note_add(&note, "carried", "version template:%zu", value_line(&pkg, "version"));
    note_add(&note, "carried", "release template:%zu", value_line(&pkg, "revision"));
    if (summary && *summary) note_add(&note, "carried", "short_desc template:%zu",
                                      value_line(&pkg, "short_desc"));
    if (homepage && *homepage) note_add(&note, "carried", "homepage template:%zu",
                                        value_line(&pkg, "homepage"));
    if (license && *license) note_add(&note, "carried", "license template:%zu",
                                      value_line(&pkg, "license"));
    if (maintainer && *maintainer) note_add(&note, "carried", "maintainer template:%zu",
                                            value_line(&pkg, "maintainer"));

    /* the subpackage functions become one output each */
    for (k = 0; k < pkg.function_count; ++k) {
        const struct vs_function *function = &pkg.functions[k];
        size_t name_length = strlen(function->name);
        if (name_length <= 8 || strcmp(function->name + name_length - 8, "_package")) {
            /* a phase function belongs to a step; anything else has no place here */
            if (is_phase_function(function->name)) continue;
            review = 1;
            if (!strcmp(function->name, "do_clean"))
                note_add(&note, "unknown", "do_clean runs after the package step and has no "
                         "Holy phase template:%zu-%zu", function->first, function->last);
            else
                note_add(&note, "unknown", "function %s template:%zu-%zu", function->name,
                         function->first, function->last);
            continue;
        }
        if (function->name[strlen(name)] == '_' && !strncmp(function->name, name, strlen(name))) {
            review = 1;
            note_add(&note, "unknown", "function %s names the main package template:%zu-%zu",
                     function->name, function->first, function->last);
            continue;
        }
        if (splits_used >= sizeof splits / sizeof *splits) {
            review = 1;
            note_add(&note, "unknown", "more subpackage functions than outputs are carried "
                     "template:%zu", function->first);
            continue;
        }
        if (!split_body(function, &splits[splits_used].install)) {
            review = 1;
            note_add(&note, "unknown", "subpackage %s has no pkg_install template:%zu-%zu",
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
            note_add(&note, "unknown", "subpackage %s is defined in a conditional block "
                     "template:%zu", splits[splits_used].name, function->first);
        }
        note_add(&note, "preserved", "subpackage %s template:%zu-%zu", splits[splits_used].name,
                 function->first, function->last);
        ++splits_used;
    }

    if (mkdir(output, 0700) && errno != EEXIST) {
        fprintf(stderr, "holypkg: conversion directory unavailable: %s\n", output);
        result = 1;
        goto done;
    }
    snprintf(target, sizeof target, "%s/template", output);
    if (!copy_file(input, target, hash)) {
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
    fputs("format holy-recipe-1\nname ", out); token(out, name);
    fputs("\nversion ", out); token(out, version);
    fputs("\nrelease ", out); token(out, release);
    fputs("\narch any\nlibc any\n", out);
    if (summary && *summary) { fputs("summary ", out); token(out, summary); fputc('\n', out); }
    if (homepage && *homepage) { fputs("homepage ", out); token(out, homepage); fputc('\n', out); }
    if (license && *license) { fputs("license ", out); token(out, license); fputc('\n', out); }
    fputs("x-source-family xbps\nx-converter voidsrc-1\n", out);
    if (maintainer && *maintainer) {
        fputs("x-maintainer ", out); token(out, maintainer); fputc('\n', out);
    }
    {
        char *changelog = value_join(&pkg, "changelog");
        if (changelog && *changelog) {
            fputs("x-changelog ", out); token(out, changelog); fputc('\n', out);
            note_add(&note, "carried", "changelog template:%zu", value_line(&pkg, "changelog"));
        }
        free(changelog);
    }
    if (style && *style) {
        fputs("x-build-style ", out); token(out, style); fputc('\n', out);
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
            if (!value_present(&pkg, preserved[index])) continue;
            fixed = resolve_options(&pkg, &note, &review, value_join(&pkg, preserved[index]),
                                    preserved[index]);
            if (!fixed) { wrote = 0; break; }
            value = fixed;
            if (!strcmp(preserved[index], "build_options_default")) {
                review = 1;
                note_add(&note, "semantic-change", "build options fixed to build_options_default "
                         "template:%zu", value_line(&pkg, preserved[index]));
            } else {
                review = 1;
                note_add(&note, "preserved", "%s template:%zu", preserved[index],
                         value_line(&pkg, preserved[index]));
            }
            fputs("x-", out);
            fputs(preserved[index], out);
            fputc(' ', out);
            token(out, value);
            fputc('\n', out);
            free(value);
        }
        if (!wrote) { result = 1; goto done; }
    }

    /* distfiles with their checksum entries */
    distfiles = value_join(&pkg, "distfiles");
    checksum = value_join(&pkg, "checksum");
    {
        size_t distfile_count = 0, digest_count = 0;
        char **urls = distfiles ? words(distfiles, &distfile_count) : NULL;
        char **digests = checksum ? words(checksum, &digest_count) : NULL;
        if (distfile_count && !digest_count) {
            review = 1;
            note_add(&note, "unknown", "distfiles without a checksum template:%zu",
                     value_line(&pkg, "distfiles"));
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
                note_add(&note, "semantic-change", "mirror name in distfile %s dropped", entry);
                entry = after;
            }
            url = expand_names(entry, name, version, release, &unknown);
            if (!url || !*url) ok = 0;
            if (ok && unknown) {
                review = 1;
                note_add(&note, "unknown", "distfile %s uses an expansion this converter "
                         "does not know template:%zu", entry, value_line(&pkg, "distfiles"));
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
                    !copy_file(original, copied, ignored)) {
                    review = 1;
                    note_add(&note, "unknown", "distfile %s is not next to the template "
                             "template:%zu", url, value_line(&pkg, "distfiles"));
                    ok = 0;
                } else {
                    note_add(&note, "semantic-change", "local distfile %s copied next to the "
                             "recipe", url);
                }
            }
            if (!ok) {
                if (url) note_add(&note, "unknown", "source %s template:%zu", entry,
                                  value_line(&pkg, "distfiles"));
                free(url);
                continue;
            }
            fputs("source ", out);
            token(out, base);
            fputc(' ', out);
            token(out, url);
            fputc('\n', out);
            if (k < digest_count && digests[k][0] == '@') {
                review = 1;
                note_add(&note, "unknown", "contents checksum for %s template:%zu", base,
                         value_line(&pkg, "checksum"));
            } else if (k < digest_count && is_sha256(digests[k])) {
                fputs("source-sha256 ", out);
                token(out, base);
                fputc(' ', out);
                token(out, digests[k]);
                fputc('\n', out);
            } else {
                review = 1;
                note_add(&note, "unknown", "source %s has no sha256 checksum template:%zu", base,
                         value_line(&pkg, "distfiles"));
            }
            note_add(&note, "carried", "distfiles %s template:%zu", entry,
                     value_line(&pkg, "distfiles"));
            free(url);
        }
        words_free(urls);
        words_free(digests);
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
                token(out, trees[index]);
                fputc(' ', out);
                token(out, named);
                fputc('\n', out);
            }
            fputs("source-sha256 ", out);
            token(out, trees[index]);
            fputc(' ', out);
            token(out, digest);
            fputc('\n', out);
            note_add(&note, "carried", "%s directory beside the template", trees[index]);
            if (patches) {
                note_add(&note, "semantic-change", "the patches directory is applied with "
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
            char *raw = value_join(&pkg, build_lists[list_index]);
            char **items = raw ? words(raw, &count) : NULL;
            free(raw);
            for (k = 0; items && k < count; ++k) {
                char *fixed;
                if (strchr(items[k], '<') || strchr(items[k], '>')) {
                    review = 1;
                    note_add(&note, "unknown", "%s %s carries a version template:%zu",
                             build_lists[list_index], items[k],
                             value_line(&pkg, build_lists[list_index]));
                    continue;
                }
                fixed = resolve_options(&pkg, &note, &review, items[k], build_lists[list_index]);
                if (!fixed) { words_free(items); wrote = 0; break; }
                emit_dependency(out, fixed, "build-depend");
                note_add(&note, "carried", "%s %s template:%zu", build_lists[list_index],
                         items[k], value_line(&pkg, build_lists[list_index]));
                free(fixed);
            }
            words_free(items);
            if (!wrote) { result = 1; goto done; }
        }
    }
    {
        size_t count = 0;
        char *raw = value_join(&pkg, "depends");
        char **items = raw ? words(raw, &count) : NULL;
        free(raw);
        for (k = 0; items && k < count; ++k) {
            char *fixed;
            if (!strncmp(items[k], "virtual?", 8)) {
                review = 1;
                note_add(&note, "unknown", "virtual dependency %s template:%zu", items[k],
                         value_line(&pkg, "depends"));
                continue;
            }
            fixed = resolve_options(&pkg, &note, &review, items[k], "depends");
            if (!fixed) { words_free(items); wrote = 0; break; }
            emit_dependency(out, fixed, "depend");
            note_add(&note, "carried", "depends %s template:%zu", items[k],
                     value_line(&pkg, "depends"));
            free(fixed);
        }
        words_free(items);
        if (!wrote) { result = 1; goto done; }
    }
    /* the conf_files and mutable_files lists name owned payload paths */
    {
        static const struct { const char *key; const char *flag; } config_keys[] = {
            { "conf_files", NULL }, { "mutable_files", "mutable" }, { NULL, NULL }
        };
        for (index = 0; config_keys[index].key; ++index) {
            size_t count = 0;
            char *raw = value_join(&pkg, config_keys[index].key);
            char **items = raw ? words(raw, &count) : NULL;
            free(raw);
            for (k = 0; items && k < count; ++k) {
                const char *path = items[k];
                if (path[0] == '/') ++path;
                if (strpbrk(path, "*?[]$`") || path[0] == '/' || !*path) {
                    review = 1;
                    note_add(&note, "unknown", "%s %s is not one payload path template:%zu",
                             config_keys[index].key, items[k],
                             value_line(&pkg, config_keys[index].key));
                    continue;
                }
                fputs("config ", out);
                token(out, path);
                if (config_keys[index].flag) {
                    fputc(' ', out);
                    fputs(config_keys[index].flag, out);
                }
                fputc('\n', out);
                note_add(&note, "carried", "%s %s template:%zu", config_keys[index].key,
                         items[k], value_line(&pkg, config_keys[index].key));
            }
            words_free(items);
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
            if (!copy_file(original, copied, ignored)) { wrote = 0; break; }
            fputs("source ", out);
            token(out, hooks_map[index].file);
            fputc(' ', out);
            token(out, hooks_map[index].file);
            fputc('\n', out);
            fputs(hooks_map[index].key, out);
            fputc(' ', out);
            fputs("/bin/bash ", out);
            token(out, installed);
            fputc('\n', out);
            snprintf(hook_list + strlen(hook_list),
                     sizeof hook_list - strlen(hook_list), " %s", hooks_map[index].file);
            ++hooks_used;
            review = 1;
            note_add(&note, "preserved", "hook %s", hooks_map[index].file);
            note_add(&note, "semantic-change", "%s runs with ACTION unset, so its pre and post "
                     "branches are not reproduced", hooks_map[index].file);
        }
        if (!wrote) { result = 1; goto done; }
    }

    /* metapackage=yes makes the output empty; any other value leaves it a runtime package */
    {
        char *meta = value_join(&pkg, "metapackage");
        int empty = meta && *meta && strcmp(meta, "no") && strcmp(meta, "0");
        fputs("output ", out);
        token(out, name);
        fputs(empty ? " metapackage\n" : " runtime\n", out);
        free(meta);
    }
    for (k = 0; k < splits_used; ++k) {
        fputs("output ", out);
        token(out, splits[k].name);
        fputs(" runtime\n", out);
    }
    /* every carried body is scanned once, so the prologue can carry the helpers it needs */
    for (index = 0; index < sizeof phase_maps / sizeof *phase_maps; ++index) {
        const char *slots[3] = { phase_maps[index].pre, phase_maps[index].body,
                                 phase_maps[index].post };
        for (i = 0; i < 3; ++i) {
            const struct vs_function *function = find_function(&pkg, slots[i]);
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
        note_add(&note, "helper", "v* helpers carried from common/environment/setup/install.sh");
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
        note_add(&note, "semantic-change", "distfiles are extracted into HOLY_SRC, which takes "
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
            const struct vs_function *functions[3];
            char *bodies[3];
            char *prefix;
            char *hook_tail = NULL;
            char working[64];
            size_t missing = 0;
            functions[0] = find_function(&pkg, map->pre);
            functions[1] = find_function(&pkg, map->body);
            functions[2] = find_function(&pkg, map->post);
            for (i = 0; i < 3; ++i) {
                bodies[i] = NULL;
                if (functions[i]) continue;
                ++missing;
            }
            if (missing == 3 && !(patches && !strcmp(map->holy, "prepare"))) {
                /* a build style supplies the steps the template leaves out */
                if (style && *style && strcmp(map->holy, "fetch") && strcmp(map->holy, "unpack")) {
                    review = 1;
                    note_add(&note, "helper", "common/build-style/%s.sh supplies the %s step",
                             style, map->holy);
                }
                continue;
            }
            /* a patches directory needs the prepare step even without a patch function */
            if (patches && !strcmp(map->holy, "prepare"))
                note_add(&note, "carried", "patches directory applied in the prepare step");
            if (style && *style)
                note_add(&note, "helper", "common/build-style/%s.sh is not run, the %s body "
                         "comes from the template", style, map->holy);
            prefix = prologue(&pkg, name, version, release, "$HOLY_DEST", helpers, files, patches, 0);
            if (!prefix) { result = 1; goto done; }
            for (i = 0; i < 3; ++i) {
                char *label = NULL;
                if (!functions[i]) continue;
                label = resolve_options(&pkg, &note, &review, functions[i]->body,
                                        functions[i]->name);
                if (!label) {
                    bodies[i] = copy_range(functions[i]->body, functions[i]->length);
                    if (!bodies[i]) { free(prefix); result = 1; goto done; }
                    note_add(&note, "unknown", "build option call in %s is not resolved",
                             functions[i]->name);
                    review = 1;
                } else {
                    bodies[i] = label;
                }
                note_add(&note, "preserved", "%s template:%zu-%zu", functions[i]->name,
                         functions[i]->first, functions[i]->last);
            }
            {
                if (hooks_used && !strcmp(map->holy, "package")) {
                    char text[1024];
                    snprintf(text, sizeof text, tail, hook_list);
                    hook_tail = copy_range(text, strlen(text));
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
        const struct vs_function *install = &splits[k].install;
        char *body, *prefix;
        body = resolve_options(&pkg, &note, &review, install->body, splits[k].name);
        if (!body) body = copy_range(install->body, install->length);
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
    fputs("source-name ", out); token(out, source); fputc('\n', out);
    fputs("source-file template\n", out);
    fprintf(out, "source-sha256 %s\n", hash);
    fputs("pkgbase ", out); token(out, name); fputc('\n', out);
    fputs("version ", out); token(out, version); fputc('\n', out);
    fputs("release ", out); token(out, release); fputc('\n', out);
    fputs("arch any\n", out);
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
        fprintf(stderr, "holypkg: template conversion failed (status %d)\n", result);
    for (k = 0; k < splits_used; ++k) {
        free(splits[k].install.name);
        free(splits[k].install.body);
    }
    note_free(&note);
    free(summary); free(homepage); free(license); free(maintainer); free(style);
    free(distfiles); free(checksum);
    voidsrc_free(&pkg);
    return result;
}
