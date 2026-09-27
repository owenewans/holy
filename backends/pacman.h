#ifndef HOLY_PACMAN_H
#define HOLY_PACMAN_H

#include <stddef.h>

enum holy_pacman_field_kind {
    HOLY_PACMAN_IDENTITY, HOLY_PACMAN_DISPLAY, HOLY_PACMAN_DEPEND,
    HOLY_PACMAN_OPTIONAL, HOLY_PACMAN_BUILD, HOLY_PACMAN_CHECK,
    HOLY_PACMAN_PROVIDE, HOLY_PACMAN_CONFLICT, HOLY_PACMAN_REPLACE,
    HOLY_PACMAN_BACKUP, HOLY_PACMAN_EXTRA, HOLY_PACMAN_UNKNOWN
};

enum holy_pacman_relation_kind {
    HOLY_PACMAN_PACKAGE, HOLY_PACMAN_SONAME_V1, HOLY_PACMAN_SONAME_V2
};

struct holy_pacman_relation {
    char *storage;
    const char *name, *comparison, *version, *description, *prefix;
    enum holy_pacman_relation_kind kind;
    unsigned elf_class;
};

struct holy_pacman_field {
    const char *key, *value;
    size_t line;
    enum holy_pacman_field_kind kind;
    struct holy_pacman_relation relation;
};

struct holy_pacman_metadata {
    char *storage;
    struct holy_pacman_field *fields;
    size_t count, unknown_count;
    const char *name, *base, *version, *arch, *package_type;
};

struct holy_pacman_error {
    size_t line;
    const char *message;
};

/* parses bytes without I/O or execution; fields retain original values and lines.
   out owns storage after any result; free once. 1 parsed, 0 invalid/allocation.
   unknown fields survive and increment unknown_count; versions use pacman semantics. */
int holy_pacman_parse(const char *bytes, size_t size,
                      struct holy_pacman_metadata *out, struct holy_pacman_error *error);
void holy_pacman_free(struct holy_pacman_metadata *metadata);

#endif
