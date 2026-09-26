#ifndef HOLY_DEPS_H
#define HOLY_DEPS_H

/* validates and prints the supported read-only requirement subset. */
int holy_deps_local(const char *package);
int holy_deps_local_with_output(const char *package, int emit);

#endif
