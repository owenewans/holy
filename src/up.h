#ifndef HOLY_UP_H
#define HOLY_UP_H

#include <stddef.h>

int holy_up_command(int argc, char **argv);
int holy_apply_command(int argc, char **argv);

/* a saved update plan, the fixed set one prepared update leaves behind. the body is
   the update record whose digest the state-plan field carries. */
struct holy_up_plan {
    char hash[65];
    char *source_id;
    char *alias;
    char *catalog;
    char *index;
    char *old_digest;
    char *new_digest;
    char *state_plan;
    char *accept_arch;
    char *accept_privileged;
    char *body;
    size_t body_length;
};

/* stages and validates one plan file without touching a root. approved is an
   optional expected plan digest: 6 unreadable, 2 malformed, 3 digest mismatch. */
int holy_up_plan_read(const char *path, const char *approved, struct holy_up_plan *plan);
void holy_up_plan_free(struct holy_up_plan *plan);

#endif
