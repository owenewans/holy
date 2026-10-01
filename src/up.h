#ifndef HOLY_UP_H
#define HOLY_UP_H

#include <stddef.h>

int holy_up_command(int argc, char **argv);
int holy_apply_command(int argc, char **argv);

/* one slot a prepared plan updates: where it is installed from, which index generation
   decided its new artifact, and the decisions the review named for it */
struct holy_up_slot {
    char source_id[65];
    char *alias;
    char *catalog;
    char index[65];
    char old_digest[65];
    char new_digest[65];
    char *accept_arch;             /* or a dash, when the review named none */
    char *accept_privileged;
    char **services;              /* the unit names this slot was prepared with */
    size_t service_count;
};

/* a saved update plan, the fixed set one prepared update leaves behind. the body is
   the update record whose digest the state-plan field carries, and it replaces every
   slot the plan names. */
struct holy_up_plan {
    char hash[65];
    struct holy_up_slot *slots;
    size_t slot_count;
    char *state_plan;
    char *body;
    size_t body_length;
};

/* stages and validates one plan file without touching a root. approved is an
   optional expected plan digest: 6 unreadable, 2 malformed, 3 digest mismatch. */
int holy_up_plan_read(const char *path, const char *approved, struct holy_up_plan *plan);
void holy_up_plan_free(struct holy_up_plan *plan);

#endif