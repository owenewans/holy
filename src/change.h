#ifndef HOLY_CHANGE_H
#define HOLY_CHANGE_H

#include "verify.h"
#include <stddef.h>

enum holy_change_kind { HOLY_RETAIN, HOLY_ADD, HOLY_REPLACE, HOLY_REMOVE };

struct holy_file_change {
    enum holy_change_kind kind;
    const struct holy_manifest_entry *before, *after;
    char id[65];
};

struct holy_file_plan {
    char old_artifact[65], new_artifact[65];
    struct holy_manifest_entry *old_entries, *new_entries;
    size_t old_count, new_count;
    struct holy_file_change *changes;
    size_t count;
};

/* caller supplies immutable archive snapshots; result owns copied manifests.
   returns one on success; free the result after every outcome. */
int holy_file_plan_collect(const char *old_snapshot, const char *new_snapshot,
                           struct holy_file_plan *plan);
void holy_file_plan_free(struct holy_file_plan *plan);
/* requires a successfully collected plan; caller owns the allocated record.
   binds both archive hashes and normalized entry attributes, not database state. */
int holy_file_plan_record(const struct holy_file_plan *plan, char **record, size_t *size);
/* no mutation; 0 succeeds, 4 rootfs drift, 6 unsupported transition. failed is
   the change index. ownership, dependency and source checks belong to the caller. */
int holy_file_plan_check(const struct holy_file_plan *plan, int root, int recovering,
                         size_t *failed);

#endif
