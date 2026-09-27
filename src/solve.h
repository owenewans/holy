#ifndef HOLY_SOLVE_H
#define HOLY_SOLVE_H

#include <stddef.h>

struct holy_solver_requirement {
    const char *first;
    const char *alternative;
};

struct holy_solver_item {
    const char *id;
    const char *const *provides;
    size_t provides_count;
    const struct holy_solver_requirement *requires;
    size_t requires_count;
    const char *const *conflicts;
    size_t conflicts_count;
};

/* exact, already-normalized capability identities only; no version comparison.
   selected has count entries, set to 0 before any outcome. Returns 1 on a
   solution, 2 on a conflict and 0 for invalid input or operational failure. */
int holy_solve_exact(const struct holy_solver_item *items, size_t count,
                     const char *requested_id, int *selected);
/* returns 3 and clears selected if another selected package set exists.
   provider edges within the same set can still be ambiguous. */
int holy_solve_exact_unique(const struct holy_solver_item *items, size_t count,
                            const char *requested_id, int *selected);
/* requires every supplied item; cannot drop a conflicting or broken consumer.
   returns 1 on success, 2 conflict, 0 invalid input or operational failure. */
int holy_solve_exact_set(const struct holy_solver_item *items, size_t count, int *selected);

#endif
