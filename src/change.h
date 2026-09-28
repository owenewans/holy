#ifndef HOLY_CHANGE_H
#define HOLY_CHANGE_H

#include "verify.h"
#include <stddef.h>

enum holy_change_kind { HOLY_RETAIN, HOLY_ADD, HOLY_REPLACE, HOLY_REMOVE };

struct holy_file_change {
    enum holy_change_kind kind;
    const struct holy_manifest_entry *before, *after;
    const char *source_path;
    struct holy_manifest_entry preserved, relocated_before, relocated_after;
    unsigned char preserved_hash[32];
    char *relocated_path;
    int keep_config;
    char id[65];
};

struct holy_file_plan {
    char old_artifact[65], new_artifact[65];
    int before_privileged, after_privileged;
    struct holy_manifest_entry *old_entries, *new_entries;
    size_t old_count, new_count;
    struct holy_file_change *changes;
    size_t count;
};

/* caller supplies immutable archive snapshots; result owns copied manifests.
   returns one on success; free the result after every outcome. */
int holy_file_plan_collect(const char *old_snapshot, const char *new_snapshot,
                           struct holy_file_plan *plan);
/* freezes modified config content and redirects the incoming version to
   .holy-new; a colliding or altered prior .holy-new is a conflict. */
int holy_file_plan_preserve_configs(struct holy_file_plan *plan, int root,
                                    const char *saved_record);
void holy_file_plan_free(struct holy_file_plan *plan);
/* requires a successfully collected plan; caller owns the allocated record.
   binds both archive hashes and normalized entry attributes, not database state. */
int holy_file_plan_record(const struct holy_file_plan *plan, char **record, size_t *size);
/* rewrite only preserved config rows and add owned .holy-new rows;
   input is the verified new package's HOLY/files text. */
int holy_file_plan_installed_manifest(const struct holy_file_plan *plan,
                                     const char *source, size_t length,
                                     char **record, size_t *size);
/* no mutation; 0 succeeds, 4 rootfs drift, 6 unsupported transition. failed is
   the change index. ownership, dependency and source checks belong to the caller. */
int holy_file_plan_check(const struct holy_file_plan *plan, int root, int recovering,
                         size_t *failed);
/* caller journals reservations first. stage verifies the immutable new archive's
   changed payload before any target replacement; partial siblings require review. */
int holy_file_plan_stage(const struct holy_file_plan *plan, const char *snapshot,
                         int root, int recovering, size_t *failed);
/* no mutation; new transactions require every reserved sibling to be absent. */
int holy_file_plan_reservations(const struct holy_file_plan *plan, int root);
/* callback persists each intent/result; zero stops before the next mutation. */
typedef int (*holy_change_progress)(void *, size_t, int);
int holy_file_plan_apply(const struct holy_file_plan *plan, int root,
                         holy_change_progress progress, void *context, size_t *failed);
/* requires the completed payload; removed shared directories remain present. */
int holy_file_plan_finished(const struct holy_file_plan *plan, int root);

/* after database publication; validates the final tree before removing group witnesses. */
int holy_file_plan_cleanup(const struct holy_file_plan *plan, int root);

#endif
