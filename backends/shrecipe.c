/* the shell text a Void template and an APKBUILD are written in.
   see man/holy-recipe.5; the file is read as text and never executed. */
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1
#include "shrecipe.h"

#include <ctype.h>
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

/* the JSON text a manifest or a lock file is written in: objects, arrays,
   strings, numbers and the three literals. such a file is a few hundred lines, so
   a value tree that keeps the line of each node is enough to report against. */
#define HOLY_JSON_MAX_DEPTH 64
#define HOLY_JSON_MAX_INPUT (4u * 1024u * 1024u)

struct holy_json_reader {
    const char *text;
    size_t at;
    size_t length;
    size_t line;
};

static struct holy_json_value *holy_json_value(struct holy_json_reader *reader, unsigned depth);

void holy_json_free(struct holy_json_value *value)
{
    size_t i;
    if (!value) return;
    for (i = 0; i < value->count; ++i) {
        if (value->kind == HOLY_JSON_OBJECT) free(value->members[i].key);
        holy_json_free(value->members[i].value);
    }
    free(value->members);
    free(value->text);
    free(value);
}

/* writes one code point as UTF-8, which a manifest needs for a translated name */
static size_t holy_json_utf8(unsigned long point, char *out)
{
    if (point < 0x80) { out[0] = (char)point; return 1; }
    if (point < 0x800) {
        out[0] = (char)(0xc0 | (point >> 6));
        out[1] = (char)(0x80 | (point & 0x3f));
        return 2;
    }
    if (point < 0x10000) {
        out[0] = (char)(0xe0 | (point >> 12));
        out[1] = (char)(0x80 | ((point >> 6) & 0x3f));
        out[2] = (char)(0x80 | (point & 0x3f));
        return 3;
    }
    out[0] = (char)(0xf0 | (point >> 18));
    out[1] = (char)(0x80 | ((point >> 12) & 0x3f));
    out[2] = (char)(0x80 | ((point >> 6) & 0x3f));
    out[3] = (char)(0x80 | (point & 0x3f));
    return 4;
}

static int holy_json_hex(struct holy_json_reader *reader, unsigned long *point)
{
    unsigned long value = 0;
    size_t i;
    for (i = 0; i < 4; ++i) {
        char c;
        if (reader->at >= reader->length) return 0;
        c = reader->text[reader->at++];
        value <<= 4;
        if (c >= '0' && c <= '9') value |= (unsigned long)(c - '0');
        else if (c >= 'a' && c <= 'f') value |= (unsigned long)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') value |= (unsigned long)(c - 'A' + 10);
        else return 0;
    }
    *point = value;
    return 1;
}

static int holy_json_string(struct holy_json_reader *reader, char **out)
{
    size_t start, used = 0;
    char *text;
    if (reader->at >= reader->length || reader->text[reader->at] != '"') return 0;
    start = ++reader->at;
    while (reader->at < reader->length && reader->text[reader->at] != '"') {
        if (reader->text[reader->at] == '\\' && reader->at + 1 < reader->length) ++reader->at;
        ++reader->at;
    }
    if (reader->at >= reader->length) return 0;
    text = malloc(reader->at - start + 1);
    if (!text) return 0;
    while (start < reader->at) {
        char c = reader->text[start++];
        unsigned long point;
        size_t written;
        if (c != '\\') { text[used++] = c; continue; }
        if (start >= reader->at) break;
        c = reader->text[start++];
        switch (c) {
        case 'n': text[used++] = '\n'; break;
        case 't': text[used++] = '\t'; break;
        case 'r': text[used++] = '\r'; break;
        case 'b': text[used++] = '\b'; break;
        case 'f': text[used++] = '\f'; break;
        case 'u':
            if (!holy_json_hex(reader, &point)) { free(text); return 0; }
            if (point >= 0xd800 && point < 0xdc00 && start + 1 < reader->at &&
                reader->text[start] == '\\' && reader->text[start + 1] == 'u') {
                unsigned long low;
                start += 2;
                if (!holy_json_hex(reader, &low) || low < 0xdc00 || low > 0xdfff) {
                    free(text);
                    return 0;
                }
                point = 0x10000 + ((point - 0xd800) << 10) + (low - 0xdc00);
            }
            if (point >= 0xd800 && point <= 0xdfff) { free(text); return 0; }
            written = holy_json_utf8(point, text + used);
            used += written;
            break;
        default: text[used++] = c; break;
        }
    }
    text[used] = 0;
    *out = text;
    ++reader->at;
    return 1;
}

static int holy_json_container(struct holy_json_reader *reader, unsigned depth, char close,
                          enum holy_json_kind kind, struct holy_json_value **out)
{
    struct holy_json_value *value = calloc(1, sizeof *value);
    if (!value) return 0;
    value->kind = kind;
    value->line = reader->line;
    ++reader->at;
    for (;;) {
        struct holy_json_member member;
        struct holy_json_value *child;
        struct holy_json_member *grown;
        while (reader->at < reader->length &&
               isspace((unsigned char)reader->text[reader->at])) {
            if (reader->text[reader->at] == '\n') ++reader->line;
            ++reader->at;
        }
        if (reader->at >= reader->length) { holy_json_free(value); return 0; }
        if (reader->text[reader->at] == close) {
            ++reader->at;
            *out = value;
            return 1;
        }
        if (reader->text[reader->at] == ',') { ++reader->at; continue; }
        memset(&member, 0, sizeof member);
        if (kind == HOLY_JSON_OBJECT) {
            char *key = NULL;
            if (!holy_json_string(reader, &key)) { holy_json_free(value); return 0; }
            member.key = key;
            if (reader->at >= reader->length || reader->text[reader->at] != ':') {
                free(key);
                holy_json_free(value);
                return 0;
            }
            ++reader->at;
        }
        child = holy_json_value(reader, depth + 1);
        if (!child) { free(member.key); holy_json_free(value); return 0; }
        member.value = child;
        grown = realloc(value->members, (value->count + 1) * sizeof *grown);
        if (!grown) { free(member.key); holy_json_free(child); holy_json_free(value); return 0; }
        value->members = grown;
        value->members[value->count++] = member;
        if (value->count > 65536) { holy_json_free(value); return 0; }
    }
}

static struct holy_json_value *holy_json_value(struct holy_json_reader *reader, unsigned depth)
{
    struct holy_json_value *value = NULL;
    char c;
    size_t start;
    if (depth > HOLY_JSON_MAX_DEPTH) return NULL;
    while (reader->at < reader->length && isspace((unsigned char)reader->text[reader->at])) {
        if (reader->text[reader->at] == '\n') ++reader->line;
        ++reader->at;
    }
    if (reader->at >= reader->length) return NULL;
    c = reader->text[reader->at];
    if (c == '"') {
        char *text = NULL;
        if (!holy_json_string(reader, &text)) return NULL;
        value = calloc(1, sizeof *value);
        if (!value) { free(text); return NULL; }
        value->kind = HOLY_JSON_STRING;
        value->line = reader->line;
        value->text = text;
        return value;
    }
    if (c == '{' || c == '[') {
        char close = c == '{' ? '}' : ']';
        enum holy_json_kind kind = c == '{' ? HOLY_JSON_OBJECT : HOLY_JSON_ARRAY;
        if (!holy_json_container(reader, depth, close, kind, &value)) return NULL;
        return value;
    }
    /* a number or one of the three literals runs to the next structural character */
    start = reader->at;
    while (reader->at < reader->length &&
           (isalnum((unsigned char)reader->text[reader->at]) || reader->text[reader->at] == '-' ||
            reader->text[reader->at] == '+' || reader->text[reader->at] == '.'))
        ++reader->at;
    if (reader->at == start) return NULL;
    value = calloc(1, sizeof *value);
    if (!value) return NULL;
    value->kind = isdigit((unsigned char)c) || c == '-' ? HOLY_JSON_NUMBER : HOLY_JSON_LITERAL;
    value->line = reader->line;
    value->text = malloc(reader->at - start + 1);
    if (!value->text) { free(value); return NULL; }
    memcpy(value->text, reader->text + start, reader->at - start);
    value->text[reader->at - start] = 0;
    return value;
}

/* the field of an object, or NULL */
const struct holy_json_value *holy_json_get(const struct holy_json_value *object, const char *key)
{
    size_t i;
    if (!object || object->kind != HOLY_JSON_OBJECT) return NULL;
    for (i = 0; i < object->count; ++i)
        if (object->members[i].key && !strcmp(object->members[i].key, key))
            return object->members[i].value;
    return NULL;
}

/* the text of a string value, or NULL */
const char *holy_json_text(const struct holy_json_value *value)
{
    return value && value->kind == HOLY_JSON_STRING ? value->text : NULL;
}

/* one element of an array of strings, or NULL */
const char *holy_json_at(const struct holy_json_value *array, size_t index)
{
    if (!array || array->kind != HOLY_JSON_ARRAY || index >= array->count) return NULL;
    return holy_json_text(array->members[index].value);
}

/* a flag list a manifest writes as one string or as a list of them */
char *holy_json_joined(const struct holy_json_value *value)
{
    char *joined;
    size_t used = 0, i;
    if (!value) return NULL;
    if (value->kind == HOLY_JSON_STRING) return strdup(value->text);
    if (value->kind != HOLY_JSON_ARRAY) return NULL;
    joined = malloc(1);
    if (!joined) return NULL;
    for (i = 0; i < value->count; ++i) {
        const char *entry = holy_json_at(value, i);
        size_t length = entry ? strlen(entry) + 1 : 0;
        char *grown = realloc(joined, used + length + 1);
        if (!grown) { free(joined); return NULL; }
        joined = grown;
        if (used) joined[used++] = ' ';
        if (entry) { memcpy(joined + used, entry, strlen(entry)); used += strlen(entry); }
        joined[used] = 0;
    }
    return joined;
}

/* the document at PATH, its root value, or NULL. status is 6 when the file cannot
   be read and 2 when it is not the JSON this reader accepts. the caller frees the
   root with holy_json_free. */
struct holy_json_value *holy_json_read(const char *path, int *status)
{
    struct holy_json_reader reader;
    struct holy_json_value *root;
    FILE *in;
    long size;
    char *text;
    int parsed;
    *status = 0;
    in = fopen(path, "rb");
    if (!in) {
        *status = 6;
        return NULL;
    }
    if (fseek(in, 0, SEEK_END) || (size = ftell(in)) < 0 ||
        (unsigned long)size > HOLY_JSON_MAX_INPUT || fseek(in, 0, SEEK_SET)) {
        fclose(in);
        *status = 6;
        return NULL;
    }
    text = malloc((size_t)size + 1);
    if (!text) {
        fclose(in);
        *status = 6;
        return NULL;
    }
    parsed = fread(text, 1, (size_t)size, in) == (size_t)size && !ferror(in);
    fclose(in);
    if (!parsed) {
        free(text);
        *status = 6;
        return NULL;
    }
    text[size] = 0;
    reader.text = text;
    reader.at = 0;
    reader.length = (size_t)size;
    reader.line = 1;
    root = holy_json_value(&reader, 0);
    while (root && reader.at < reader.length &&
           isspace((unsigned char)reader.text[reader.at])) {
        if (reader.text[reader.at] == '\n') ++reader.line;
        ++reader.at;
    }
    /* anything after the root value is not the document this reader accepts */
    if (root && reader.at < reader.length) {
        holy_json_free(root);
        root = NULL;
    }
    free(text);
    if (!root) *status = 2;
    return root;
}

char *holy_shell_copy(const char *text, size_t length)
{
    char *value = malloc(length + 1);
    if (!value) return NULL;
    memcpy(value, text, length);
    value[length] = 0;
    return value;
}

/* drops one layer of shell quoting; an unquoted value is used as written. */
char *holy_shell_unquote(const char *text, size_t length)
{
    char *value = holy_shell_copy(text, length), *out;
    size_t used = 0, i;
    if (!value) return NULL;
    if (length < 2 || (text[0] != '\'' && text[0] != '"') ||
        text[length - 1] != text[0]) return value;
    out = malloc(length + 1);
    if (!out) { free(value); return NULL; }
    for (i = 1; i + 1 < length; ++i) {
        char c = text[i];
        if (c == '\\' && i + 2 < length &&
            (text[i + 1] == '\'' || text[i + 1] == '"' || text[i + 1] == '\\')) {
            out[used++] = text[++i];
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

char **holy_shell_words(const char *value, size_t *count)
{
    char **list = NULL;
    size_t used = 0, i = 0;
    *count = 0;
    if (!value) return NULL;
    while (i < strlen(value)) {
        size_t start;
        char *copy, **grown;
        while (value[i] && isspace((unsigned char)value[i])) ++i;
        if (!value[i]) break;
        start = i;
        while (value[i] && !isspace((unsigned char)value[i])) ++i;
        copy = holy_shell_copy(value + start, i - start);
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

void holy_shell_words_free(char **list)
{
    size_t i;
    if (!list) return;
    for (i = 0; list[i]; ++i) free(list[i]);
    free(list);
}

char *holy_shell_join(const struct shell_script *script, const char *name)
{
    char *out = NULL;
    size_t i;
    for (i = 0; i < script->value_count; ++i) {
        if (strcmp(script->values[i].name, name)) continue;
        if (out && script->values[i].append) {
            char *grown = realloc(out, strlen(out) + strlen(script->values[i].text) + 1);
            if (!grown) { free(out); return NULL; }
            strcat(grown, script->values[i].text);
            out = grown;
            continue;
        }
        free(out);
        out = strdup(script->values[i].text);
        if (!out) return NULL;
    }
    return out;
}

/* every record of NAME joined with a space. a list is one record per element, so a
   reader that splits the result into words sees the whole list, whether it was
   written on one line or on many. */
char *holy_shell_all(const struct shell_script *script, const char *name)
{
    char *out = NULL;
    size_t i, used = 0;
    for (i = 0; i < script->value_count; ++i) {
        size_t add;
        char *grown;
        if (strcmp(script->values[i].name, name)) continue;
        add = strlen(script->values[i].text) + 1;
        grown = realloc(out, used + add + 1);
        if (!grown) { free(out); return NULL; }
        out = grown;
        if (used) out[used++] = ' ';
        memcpy(out + used, script->values[i].text, add);
        used += add - 1;
    }
    if (out) out[used] = 0;
    return out;
}

const struct shell_value *holy_shell_entries(const struct shell_script *script, const char *name,
                                             size_t *count){
    static struct shell_value *snapshot;
    size_t i, used = 0;
    free(snapshot);
    snapshot = NULL;
    *count = 0;
    for (i = 0; i < script->value_count; ++i)
        if (!strcmp(script->values[i].name, name)) ++used;
    if (!used) return NULL;
    snapshot = malloc(used * sizeof *snapshot);
    if (!snapshot) return NULL;
    for (i = 0, used = 0; i < script->value_count; ++i)
        if (!strcmp(script->values[i].name, name)) snapshot[used++] = script->values[i];
    *count = used;
    return snapshot;
}

int holy_shell_present(const struct shell_script *script, const char *name)
{
    size_t i;
    for (i = 0; i < script->value_count; ++i)
        if (!strcmp(script->values[i].name, name)) return 1;
    return 0;
}

size_t holy_shell_line(const struct shell_script *script, const char *name)
{
    size_t i;
    for (i = 0; i < script->value_count; ++i)
        if (!strcmp(script->values[i].name, name)) return script->values[i].line;
    return 0;
}

const struct shell_function *holy_shell_function(const struct shell_script *script,
                                                 const char *name)
{
    size_t i;
    for (i = 0; i < script->function_count; ++i)
        if (!strcmp(script->functions[i].name, name)) return &script->functions[i];
    return NULL;
}

void holy_shell_function_free(struct shell_function *function)
{
    free(function->name);
    free(function->body);
    memset(function, 0, sizeof *function);
}

/* the end of a ( ) or { } group that starts at cursor, or NULL when it is
   unterminated. a quote inside the group carries its own end, so a closing
   character inside a string does not close the group. */
static const char *group_end(const char *cursor, const char *stop, char open, char close)
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
        if (c == '\\') { ++i; continue; }
        if (c == '\'' || c == '"') inner = c;
        else if (c == open) ++depth;
        else if (c == close && !--depth) return cursor + i;
    }
    return NULL;
}

static const char *substitution_end(const char *cursor, const char *stop)
{
    return group_end(cursor, stop, '(', ')');
}

/* 1 while a quote is open, so a value may continue on the next line. a $( ) group
   carries its own quoting, so it never closes the quote that contains it. a comment
   ends at the newline, and a quote inside one is not a shell quote. */
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
        if (quote == '"') {
            /* a backslash escapes inside a double quoted string, so \" closes nothing */
            if (c == '\\') { i += 2; continue; }
            if (c == '"') quote = 0;
            ++i;
            continue;
        }
        if (c == '\\') { i += 2; continue; }
        /* a comment is not quoted, so an apostrophe in one opens no quote */
        if (c == '#' && (i == 0 || isspace((unsigned char)text[i - 1]))) {
            while (i < length && text[i] != '\n') ++i;
            continue;
        }
        if (c == '`' && text[i + 1] == '(') {
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
        if (c == '\'' || c == '"') { quote = c; ++i; continue; }
        ++i;
    }
    return quote ? 1 : 0;
}

/* the terminator word of a heredoc that starts at offset, with its length and
   whether it is a <<- terminator that may carry leading tabs, or NULL */
static const char *heredoc_word(const char *body, size_t offset, const char *stop,
                                size_t *length, int *strip)
{
    const char *cursor = body + offset, *word;
    *strip = 0;
    /* a heredoc word may be written apart from the <<, since both forms are shell */
    while (cursor < stop && isspace((unsigned char)*cursor)) ++cursor;
    if (cursor < stop && *cursor == '-') { ++cursor; *strip = 1; }
    while (cursor < stop && isspace((unsigned char)*cursor)) ++cursor;
    if (cursor < stop && (*cursor == '\'' || *cursor == '"')) {
        char quote = *cursor;
        word = ++cursor;
        while (cursor < stop && *cursor != quote) ++cursor;
    } else {
        word = cursor;
        while (cursor < stop && !isspace((unsigned char)*cursor) && *cursor != ';' &&
               *cursor != '|' && *cursor != '&' && *cursor != '(')
            ++cursor;
    }
    if (cursor <= word || cursor > stop) return NULL;
    *length = (size_t)(cursor - word);
    return word;
}

/* the closing brace of a function body, ignoring quoted, substituted, commented
   and heredoc text */
const char *holy_shell_block_end(const char *body, const char *stop)
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
        /* an escaped character is neither a quote nor a brace */
        if (c == '\\') { ++i; continue; }
        if (c == '\'' || c == '"' || c == '`') { quote = c; continue; }
        if ((c == '$' || c == '\\') && body + i + 1 < stop &&
            (body[i + 1] == '(' || body[i + 1] == '{')) {
            char open = body[i + 1];
            const char *close = group_end(body + i + 2, stop, open, open == '(' ? ')' : '}');
            i = close ? (size_t)(close - body) : (size_t)(stop - body) - 1;
            continue;
        }
        /* a heredoc body is literal text, so a brace in it closes nothing. a <<< is
           a here string, whose word is the whole rest of the command, not a body. */
        if (c == '<' && body + i + 1 < stop && body[i + 1] == '<' &&
            !(body + i + 2 < stop && body[i + 2] == '<')) {
            size_t used = 0;
            int strip = 0;
            const char *word = heredoc_word(body, i + 2, stop, &used, &strip);
            if (!word) continue;
            /* the body ends at the line that names the terminator on its own, and a
               <<- terminator may carry leading tabs */
            for (i = (size_t)(word - body); body + i < stop; ++i) {
                const char *row;
                char after;
                if (body[i] != '\n') continue;
                row = body + i + 1;
                if (strip) while (row < stop && *row == '\t') ++row;
                if ((size_t)(row - body) + used >= (size_t)(stop - body)) break;
                after = row[used];
                if (!memcmp(row, word, used) && (after == '\n' || after == 0)) {
                    i = (size_t)(row - body) + used - 1;
                    break;
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

static int push_value(struct shell_script *script, char *name, char *text, size_t line,
                      int append, int conditional)
{
    struct shell_value *grown = realloc(script->values,
                                        (script->value_count + 1) * sizeof *grown);
    if (!grown) return 0;
    script->values = grown;
    memset(&grown[script->value_count], 0, sizeof grown[0]);
    grown[script->value_count].name = name;
    grown[script->value_count].text = text;
    grown[script->value_count].line = line;
    grown[script->value_count].append = append;
    grown[script->value_count].conditional = conditional;
    ++script->value_count;
    return 1;
}

static int push_condition(struct shell_script *script, const char *text, size_t line,
                          int unreadable)
{
    struct shell_condition *grown;
    char *copy = holy_shell_copy(text, strlen(text));
    if (!copy) return 0;
    grown = realloc(script->conditions, (script->condition_count + 1) * sizeof *grown);
    if (!grown) { free(copy); return 0; }
    script->conditions = grown;
    grown[script->condition_count].text = copy;
    grown[script->condition_count].line = line;
    grown[script->condition_count].unreadable = unreadable;
    ++script->condition_count;
    return 1;
}

/* splits a parenthesized list body into one record per element */
static int push_list(struct shell_script *script, const char *name, const char *body,
                     size_t length, size_t line, int append, int conditional)
{
    size_t i = 0;
    while (i < length) {
        char quote = 0, *text;
        size_t start;
        /* a shell array separates elements on whitespace, so a comma stays in the name */
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
        text = holy_shell_unquote(body + start, i - start);
        if (!text || !push_value(script, strdup(name), text, line, append, conditional)) {
            free(text);
            return 0;
        }
    }
    return 1;
}

/* the closing paren of a list body, or NULL */
/* a shell list runs until its closing paren, so a newline is an element separator
   like any other blank, and a comment ends at the newline */
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
        if (c == '#' && (cursor == stop || !cursor[-1] || isspace((unsigned char)cursor[-1]))) {
            while (cursor < stop && *cursor != '\n') ++cursor;
            continue;
        }
        if (c == '\'' || c == '"') quote = c;
        else if (c == ')') return cursor;
    }
    return NULL;
}

/* reads assignments, lists, conditional blocks and function bodies from the text */
static int parse(struct shell_script *script, const char *label)
{
    size_t offset = 0, line = 0, depth = 0, cases = 0;
    while (offset < script->length) {
        char *start = script->text + offset;
        char *newline = memchr(start, '\n', script->length - offset);
        size_t size = newline ? (size_t)(newline - start) : script->length - offset;
        char *next = newline ? newline + 1 : script->text + script->length;
        size_t name_length = 0, i;
        char *cursor;
        int conditional;
        ++line;
        offset = (size_t)(next - script->text);
        while (size && (*start == ' ' || *start == '\t' || start[size - 1] == '\r')) {
            ++start;
            --size;
        }
        if (!size || *start == '#') continue;
        conditional = depth > 0;
        if (!strncmp(start, "if", 2) && (size == 2 || start[2] == ' ' || start[2] == '\t')) {
            if (!push_condition(script, start, line, 0)) return 1;
            ++depth;
            continue;
        }
        /* a case block selects values this reader cannot evaluate, so it is recorded */
        if (!strncmp(start, "case", 4) && (size == 4 || start[4] == ' ' || start[4] == '\t')) {
            if (!push_condition(script, start, line, 0)) return 1;
            ++depth;
            ++cases;
            continue;
        }
        if (!strncmp(start, "esac", 4) && (size == 4 || start[4] == ' ' || start[4] == '\t')) {
            if (!depth) {
                fprintf(stderr, "holypkg: %s:%zu: esac without case\n", label, line);
                return 2;
            }
            --depth;
            if (cases) --cases;
            continue;
        }
        if (!strncmp(start, "esac", 4) && size >= 4) continue;
        /* a case pattern ends at its closing paren; only the body after it is a record */
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
            if (!push_condition(script, start, line, 0)) return 1;
            continue;
        }
        /* an export of a name this reader uses is the same assignment */
        if (!strncmp(start, "export ", 7)) {
            start += 7;
            size -= 7;
            while (size && (*start == ' ' || *start == '\t')) { ++start; --size; }
            while (size && start[size - 1] == ' ') --size;
            if (!size) {
                fprintf(stderr, "holypkg: %s:%zu: empty export\n", label, line);
                return 2;
            }
        }
        if (!strncmp(start, "elif", 4) || !strncmp(start, "else", 4)) {
            if (!depth || !push_condition(script, start, line, 0)) return 1;
            continue;
        }
        if (!strncmp(start, "fi", 2) && (size == 2 || start[2] == ' ' || start[2] == '\t')) {
            if (!depth) {
                fprintf(stderr, "holypkg: %s:%zu: fi without if\n", label, line);
                return 2;
            }
            --depth;
            continue;
        }
        cursor = start;
        /* a subpackage name carries dashes, a versioned one carries a dot, and a
           C++ library name carries a double plus; a package may begin with a digit */
        while (name_length < size) {
            if (isdigit((unsigned char)cursor[name_length]) ||
                name_char(cursor[name_length], !name_length)) {
                ++name_length;
                continue;
            }
            if (cursor[name_length] == '+') {
                char next_char = cursor[name_length + 1];
                if (next_char == '+') name_length += 2;
                else if (name_char(next_char, 0) || next_char == '-' || next_char == '.')
                    ++name_length;
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
            const char *close = holy_shell_block_end(body, script->text + script->length);
            struct shell_function function;
            struct shell_function *grown;
            size_t before = 0;
            if (!close) {
                fprintf(stderr, "holypkg: %s:%zu: unterminated function\n", label, line);
                return 2;
            }
            for (i = 0; body + i < close; ++i) if (body[i] == '\n') ++line;
            offset = (size_t)(close - script->text) + 1;
            memset(&function, 0, sizeof function);
            function.name = holy_shell_copy(start, name_length);
            function.body = holy_shell_copy(body, (size_t)(close - body));
            function.length = (size_t)(close - body);
            function.last = line;
            function.conditional = conditional;
            for (i = 0; i < function.length; ++i)
                if (function.body[i] == '\n') ++before;
            function.first = line - before - 1;
            if (!function.name || !function.body) {
                free(function.name);
                free(function.body);
                return 1;
            }
            grown = realloc(script->functions, (script->function_count + 1) * sizeof *grown);
            if (!grown) { free(function.name); free(function.body); return 1; }
            script->functions = grown;
            script->functions[script->function_count++] = function;
            continue;
        }
        /* a list is written name=( one element per line ) as often as it is written
           on one line, so an opening paren alone starts a list too */
        if (name_length + 2 <= size && cursor[name_length] == '=' && cursor[name_length + 1] == '(' &&
            (cursor[name_length + 2] == ')' || size == name_length + 2)) {
            char *name = holy_shell_copy(start, name_length);
            const char *body = cursor + name_length + 3;
            const char *close = NULL;
            int ok = 1;
            if (!name) return 1;
            if (cursor[name_length + 2] == ')') {
                /* an empty list holds nothing, so reading past it would take the
                   next line for an element of it */
                offset = (size_t)(body - script->text) + 1;
            } else {
                close = list_end(body, script->text + script->length);
                while (!close && offset < script->length) {
                    char *row = script->text + offset;
                    char *row_end = memchr(row, '\n', script->length - offset);
                    size_t row_size = row_end ? (size_t)(row_end - row) :
                                              script->length - offset;
                    ++line;
                    offset = (size_t)(row_end ? row_end + 1 : script->text + script->length) -
                             (size_t)script->text;
                    close = list_end(row, row + row_size);
                    if (close) break;
                }
                if (!close) close = script->text + script->length;
                ok = close > body && push_list(script, name, body, (size_t)(close - body), line,
                                               0, conditional);
                /* the elements start on the line below the opening paren and the
                   closing paren may be several lines further down, so the line
                   count has to follow the whole list */
                ++line;
                for (i = 0; body + i < close; ++i) if (body[i] == '\n') ++line;
                /* the newline that ends the line is stepped over here, so that it
                   does not count as a line of its own */
                offset = (size_t)(close - script->text) + (close[1] == '\n' ? 2 : 1);
            }
            free(name);
            if (!ok) {
                fprintf(stderr, "holypkg: %s: unterminated list\n", label);
                return 2;
            }
            continue;
        }
        /* a plain name=value record or an appended name+=value one */
        if (name_length >= size || (cursor[name_length] != '=' &&
                                    !(cursor[name_length] == '+' && name_length + 2 < size &&
                                      cursor[name_length + 1] == '='))) {
            /* the file is sourced as a shell script, so any other statement would run
               at conversion time. it is recorded with its line instead of executed. */
            if (!push_condition(script, start, line, 1)) return 1;
            continue;
        }
        {
            char *name = holy_shell_copy(start, name_length);
            size_t at = name_length + 1;
            int append = 0;
            char *value, *text;
            size_t value_size;
            if (name_length + 2 < size && cursor[name_length] == '+') {
                append = 1;
                at = name_length + 2;
            }
            value = cursor + at;
            value_size = size - at;
            while (value_size && (*value == ' ' || *value == '\t')) { ++value; --value_size; }
            /* a quoted value ends at its closing quote, so a case pattern that ends
               its assignment with ;; does not put the terminator in the value */
            if (value_size && (*value == '"' || *value == '\'')) {
                size_t index;
                char quote = *value;
                for (index = 1; index < value_size; ++index) {
                    if (value[index] == quote) break;
                    if (quote == '"' && value[index] == '\\') ++index;
                }
                if (index < value_size) value_size = index + 1;
            }
            /* a list runs to its closing paren, which is often several lines below,
               and an element may hold a comment, so the value ends at that paren */
            if (value_size && *value == '(') {
                const char *close = list_end(value + 1, script->text + script->length);
                if (close) {
                    /* a parenthesized value is a list, so every element is one record
                       and not one value with the parens left in it, whether the list
                       is written on one line or on many */
                    int ok = push_list(script, name, value + 1,
                                       (size_t)(close - value - 1), line, append, conditional);
                    free(name);
                    if (!ok) {
                        fprintf(stderr, "holypkg: %s:%zu: unterminated list\n", label, line);
                        return 2;
                    }
                    for (i = 0; i < (size_t)(close - value) + 1; ++i)
                        if (value[i] == '\n') ++line;
                    /* the newline that ends the line is stepped over here, so that it
                       does not count as a line of its own */
                    offset = (size_t)(close - script->text) + (close[1] == '\n' ? 2 : 1);
                    continue;
                }
            }
            /* an unquoted value ends at a comment the way the shell reads it */
            if (value_size && *value != '"' && *value != '\'') {
                char quote = 0;
                size_t index;
                for (index = 0; index < value_size; ++index) {
                    if (quote) {
                        if (value[index] == quote) quote = 0;
                        continue;
                    }
                    if (value[index] == '\'' || value[index] == '"') {
                        quote = value[index];
                        continue;
                    }
                    if (value[index] == '#' &&
                        (index == 0 || isspace((unsigned char)value[index - 1]))) {
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
                while (quote_open(joined, used) && offset < script->length) {
                    char *row = script->text + offset;
                    char *row_end = memchr(row, '\n', script->length - offset);
                    size_t row_size = row_end ? (size_t)(row_end - row) : script->length - offset;
                    char *grown;
                    size_t capacity = used + row_size + 2;
                    ++line;
                    offset = (size_t)(row_end ? row_end + 1 : script->text + script->length) -
                             (size_t)script->text;
                    grown = realloc(joined, capacity);
                    if (!grown) { free(joined); free(name); return 1; }
                    joined = grown;
                    joined[used++] = '\n';
                    memcpy(joined + used, row, row_size);
                    used += row_size;
                    joined[used] = 0;
                }
                if (quote_open(joined, used)) {
                    fprintf(stderr, "holypkg: %s:%zu: unterminated value\n", label, line);
                    free(joined);
                    free(name);
                    return 2;
                }
                text = holy_shell_unquote(joined, used);
                free(joined);
            } else {
                text = holy_shell_unquote(value, value_size);
            }
            if (!name || !text || !push_value(script, name, text, line, append, conditional)) {
                free(name);
                free(text);
                return 1;
            }
        }
    }
    if (depth) {
        fprintf(stderr, "holypkg: %s: unterminated block\n", label);
        return 2;
    }
    return 0;
}

int holy_shell_read(const char *path, struct shell_script *script)
{
    struct stat st;
    FILE *file;
    const char *label = strrchr(path, '/');
    int result;
    label = label ? label + 1 : path;
    memset(script, 0, sizeof *script);
    if (stat(path, &st) || !S_ISREG(st.st_mode) || st.st_size > 4 * 1024 * 1024) {
        fprintf(stderr, "holypkg: %s unavailable: %s\n", label, path);
        return 6;
    }
    script->length = (size_t)st.st_size;
    script->text = malloc(script->length + 1);
    file = script->text ? fopen(path, "rb") : NULL;
    if (!file || fread(script->text, 1, script->length, file) != script->length) {
        if (file) fclose(file);
        holy_shell_free(script);
        fprintf(stderr, "holypkg: %s could not be read\n", label);
        return 6;
    }
    fclose(file);
    script->text[script->length] = 0;
    script->directory = strdup(path);
    if (!script->directory) { holy_shell_free(script); return 1; }
    {
        char *slash = strrchr(script->directory, '/');
        if (slash) *slash = 0;
        else strcpy(script->directory, ".");
    }
    result = parse(script, label);
    if (result) { holy_shell_free(script); return result; }
    return 0;
}

void holy_shell_free(struct shell_script *script)
{
    size_t i;
    for (i = 0; i < script->value_count; ++i) {
        free(script->values[i].name);
        free(script->values[i].text);
    }
    for (i = 0; i < script->function_count; ++i) {
        free(script->functions[i].name);
        free(script->functions[i].body);
    }
    for (i = 0; i < script->condition_count; ++i) free(script->conditions[i].text);
    free(script->values);
    free(script->functions);
    free(script->conditions);
    free(script->directory);
    free(script->text);
    memset(script, 0, sizeof *script);
}

/* the body of the function named marker inside another function body */
int holy_shell_nested(const struct shell_function *function, const char *marker,
                      struct shell_function *out)
{
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
    out->name = strdup(marker);
    out->body = holy_shell_copy(brace + 1, (size_t)(close - brace - 1));
    out->length = (size_t)(close - brace - 1);
    out->first = line;
    out->last = line;
    out->conditional = function->conditional;
    if (!out->name || !out->body) {
        holy_shell_function_free(out);
        return 0;
    }
    return 1;
}

int holy_note_add(struct recipe_note *note, const char *kind, const char *format, ...)
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

void holy_note_free(struct recipe_note *note)
{
    size_t i;
    for (i = 0; i < note->count; ++i) free(note->lines[i]);
    free(note->lines);
    memset(note, 0, sizeof *note);
}

const char *holy_relation_name(const char *operator)
{
    if (!strcmp(operator, ">=")) return "ge";
    if (!strcmp(operator, "<=")) return "le";
    if (!strcmp(operator, ">")) return "gt";
    if (!strcmp(operator, "<")) return "lt";
    if (!strcmp(operator, "=")) return "eq";
    return "any";
}

void holy_token(FILE *out, const char *value)
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

/* writes one depend record, keeping the upstream name, relation and version */
void holy_emit_dependency(FILE *out, const char *raw, const char *kind)
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
    holy_token(out, name);
    if (relation && *cursor) {
        fputc(' ', out);
        holy_token(out, holy_relation_name(relation));
        fputc(' ', out);
        holy_token(out, cursor);
    } else {
        fputs(" \"any\" \"-\"", out);
    }
    fputc('\n', out);
}

int holy_hash_file(const char *path, char digest[65])
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

int holy_copy_and_hash(const char *source, const char *target, char digest[65])
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
    if (chmod(target, 0600) || !holy_hash_file(target, digest)) return 0;
    return 1;
}
