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
typedef int (*holy_package_or_visit)(void *opaque, const char *name,
                                     const char *relation, const char *version);
/* package-or names use name@relation@version branches separated by |. */
int holy_package_or_each(const char *expression, holy_package_or_visit visit,
                         void *opaque);
/* visitor receives borrowed fields after all requirements validate. */
int holy_deps_visit(const char *package, holy_requirement_visit visitor,
                    void *opaque);
/* the same records from a HOLY/deps buffer already read, as an installed instance
   record is. the visitor sees every record or a parse error stops the call. */
int holy_deps_buffer_visit(const void *data, size_t length,
                           holy_requirement_visit visitor, void *opaque);
int holy_deps_record_valid(const char *id, const char *consumer,
    const char *kind, const char *name, const char *arch, const char *libc,
    const char *relation, const char *version, const char *original,
    const char *evidence);

#endif
