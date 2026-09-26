#ifndef HOLY_DEPS_H
#define HOLY_DEPS_H

#include <stddef.h>

/* validates and prints the supported read-only requirement subset. */
int holy_deps_local(const char *package);
int holy_deps_local_with_output(const char *package, int emit);
int holy_deps_count(const char *package, size_t *count);

#endif
