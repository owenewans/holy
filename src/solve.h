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
};

/* exact, already-normalized capability identities only; no version comparison.
   selected has count entries, set to 0 before any outcome. Returns 1 on a
   solution, 2 on a conflict and 0 for invalid input or operational failure. */
int holy_solve_exact(const struct holy_solver_item *items, size_t count,
                     const char *requested_id, int *selected);

#endif
