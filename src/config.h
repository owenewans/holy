#ifndef HOLY_CONFIG_H
#define HOLY_CONFIG_H

#include <stddef.h>

struct holy_entry {
    char *section;
    char *key;
    char **values;
    size_t count;
    char *file;
    size_t line;
};

struct holy_config {
    struct holy_entry *entries;
    size_t count;
};

/* the caller owns entries on both success and failure. error is allocated. */
int holy_config_load(const char *path, struct holy_config *out, char **error);
int holy_config_load_plan(const char *path, struct holy_config *out, char **error);
void holy_config_free(struct holy_config *config);

/* the caller owns token strings and the vector on success. */
int holy_lex(const char *text, size_t length, char ***tokens, size_t *count,
             const char *file, size_t line, char **error);
void holy_tokens_free(char **tokens, size_t count);

/* one rule for a dinit service unit name, shared by the manager and the installer. */
int holy_unit_name_valid(const char *name);

#endif
