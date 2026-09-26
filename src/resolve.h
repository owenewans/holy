#ifndef HOLY_RESOLVE_H
#define HOLY_RESOLVE_H

#include <stddef.h>

/* read-only local subset: 0 solved, 3 decision, 4 conflict, 6 unsupported. */
int holy_resolve_local(const char *const *paths, size_t count);

#endif
