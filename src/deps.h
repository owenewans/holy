#ifndef HOLY_DEPS_H
#define HOLY_DEPS_H

#include <stddef.h>

/* validates and prints the supported read-only requirement subset. */
int holy_deps_local(const char *package);
int holy_deps_local_with_output(const char *package, int emit);
int holy_deps_count(const char *package, size_t *count);
typedef int (*holy_requirement_visit)(void *opaque, const char *id,
    const char *consumer, const char *kind, const char *name,
    const char *arch, const char *libc, const char *relation,
    const char *version, const char *original, const char *evidence);
/* visitor receives borrowed fields after all requirements validate. */
int holy_deps_visit(const char *package, holy_requirement_visit visitor,
                    void *opaque);

#endif
