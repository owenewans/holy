#ifndef HOLY_RESOLVE_H
#define HOLY_RESOLVE_H

#include <stddef.h>

struct holy_resolved_edge {
    char *consumer, *id, *provider, *path, *kind, *target;
};

struct holy_resolution {
    char root[65];
    char **artifacts;
    size_t artifact_count;
    struct holy_resolved_edge *edges;
    size_t edge_count;
};

struct holy_missing_requirement {
    char *consumer, *id, *kind, *name;
};

/* returns 4 with one exact missing edge, 0 when solved, or another CLI status. */
int holy_resolve_missing(const char *const *paths, size_t count,
                         struct holy_missing_requirement *missing);
void holy_missing_requirement_free(struct holy_missing_requirement *missing);

/* owned result, no stdout; free after any result. selects artifact
   candidates, not physical library bindings in a launch context. */
int holy_resolve_collect(const char *const *paths, size_t count,
                          const char *choice, struct holy_resolution *result);
/* validates a complete proposed set; every input remains selected. ambiguous
   provider edges still require a decision. root records the first input only;
   installed reasons and source/slot decisions belong to the caller. */
int holy_resolve_collect_set(const char *const *paths, size_t count,
                              struct holy_resolution *result);
void holy_resolution_free(struct holy_resolution *result);
/* canonical lexer-compatible record; caller owns the allocated bytes. */
int holy_resolution_record(const struct holy_resolution *result,
                            char **record, size_t *length);

/* read-only local subset: 0 solved, 3 decision, 4 conflict, 6 unsupported. */
/* generation is a validated sealed catalog digest, or NULL for local inputs. */
int holy_resolve_local(const char *const *paths, size_t count, int json,
                       const char *generation, const char *choice);

#endif
