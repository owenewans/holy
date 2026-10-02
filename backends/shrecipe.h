#ifndef HOLY_SHRECIPE_H
#define HOLY_SHRECIPE_H

#include <stddef.h>
#include <stdio.h>

/* a shell recipe file is read as text: assignments, lists, conditional and case
   blocks and function bodies. no part of it is executed. */

struct shell_value {
    char *name;
    char *text;
    size_t line;
    int append;
    int conditional;
};

struct shell_function {
    char *name;
    char *body;
    size_t length;
    size_t first;
    size_t last;
    int conditional;
};

struct shell_condition {
    char *text;
    size_t line;
    int unreadable;
};

struct shell_script {
    char *text;
    size_t length;
    char *directory;
    struct shell_value *values;
    size_t value_count;
    struct shell_function *functions;
    size_t function_count;
    struct shell_condition *conditions;
    size_t condition_count;
};

/* one entry per assignment; a parenthesized list gives one entry per element. */
int holy_shell_read(const char *path, struct shell_script *script);
void holy_shell_free(struct shell_script *script);

/* the value of NAME with every appended record following the earlier one. */
char *holy_shell_join(const struct shell_script *script, const char *name);
/* every record of NAME joined with a space, which is a whole list. */
char *holy_shell_all(const struct shell_script *script, const char *name);
const struct shell_value *holy_shell_entries(const struct shell_script *script, const char *name,
                                             size_t *count);
int holy_shell_present(const struct shell_script *script, const char *name);
size_t holy_shell_line(const struct shell_script *script, const char *name);
const struct shell_function *holy_shell_function(const struct shell_script *script, const char *name);

/* whitespace separates words the way a shell array does. */
char **holy_shell_words(const char *value, size_t *count);
void holy_shell_words_free(char **list);
char *holy_shell_unquote(const char *text, size_t length);
char *holy_shell_copy(const char *text, size_t length);

/* the body of the function named marker inside a function body, or NULL. */
int holy_shell_nested(const struct shell_function *function, const char *marker,
                      struct shell_function *out);
void holy_shell_function_free(struct shell_function *function);
/* the closing brace that ends a body, or NULL when the body is unterminated. */
const char *holy_shell_block_end(const char *body, const char *stop);

/* the JSON text a foreign manifest or lock file is written in. the value tree keeps
   the line of every node, so a report can name it. */
enum holy_json_kind {
    HOLY_JSON_STRING, HOLY_JSON_NUMBER, HOLY_JSON_LITERAL, HOLY_JSON_ARRAY, HOLY_JSON_OBJECT
};

struct holy_json_member {
    char *key;
    struct holy_json_value *value;
};

struct holy_json_value {
    enum holy_json_kind kind;
    size_t line;
    char *text;
    struct holy_json_member *members;
    size_t count;
};

/* the root value of the document at PATH, or NULL with status 6 when the file
   cannot be read and 2 when it is not JSON. the caller owns the value. */
struct holy_json_value *holy_json_read(const char *path, int *status);
void holy_json_free(struct holy_json_value *value);
const struct holy_json_value *holy_json_get(const struct holy_json_value *object,
                                             const char *key);
const char *holy_json_text(const struct holy_json_value *value);
const char *holy_json_at(const struct holy_json_value *array, size_t index);
/* a list written as one string or as an array of them, joined; the caller frees it. */
char *holy_json_joined(const struct holy_json_value *value);

/* the conversion report vocabulary shared by the recipe converters. */
struct recipe_note {
    char **lines;
    size_t count;
    size_t carried, preserved, helper, unknown, changes;
    char **environments;   /* helper environments in the order the converter names them */
    size_t environment_count;
};

int holy_note_add(struct recipe_note *note, const char *kind, const char *format, ...);
/* one named helper environment the converter did not run. the name joins the ordered
   list whose SHA-256 both the report and the build record carry. */
int holy_note_environment(struct recipe_note *note, const char *name);
/* writes the environment lines and their digest, and returns 1 when there are any. */
int holy_note_environments(FILE *out, const struct recipe_note *note);
/* writes the same names as x- records, so HOLY/meta carries the helper environment the
   converter could not run. */
int holy_note_environment_records(FILE *out, const struct recipe_note *note);
/* the SHA-256 of the ordered names, separated by NUL so two spellings differ. */
int holy_environment_digest(char *const *names, size_t count, char digest[65]);
void holy_note_free(struct recipe_note *note);
const char *holy_relation_name(const char *operator);
/* writes one depend record, keeping the upstream name, relation and version. */
void holy_emit_dependency(FILE *out, const char *raw, const char *kind);
/* writes one quoted manifest value. */
void holy_token(FILE *out, const char *value);
/* copies a file next to the recipe and returns its SHA-256. */
int holy_copy_and_hash(const char *source, const char *target, char digest[65]);
int holy_hash_file(const char *path, char digest[65]);

#endif
