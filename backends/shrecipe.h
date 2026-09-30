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

/* the conversion report vocabulary shared by the recipe converters. */
struct recipe_note {
    char **lines;
    size_t count;
    size_t carried, preserved, helper, unknown, changes;
};

int holy_note_add(struct recipe_note *note, const char *kind, const char *format, ...);
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
