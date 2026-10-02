#ifndef HOLY_PREVIEW_H
#define HOLY_PREVIEW_H

#include <stddef.h>

/* returns 0 for a collision-free preview, 4 for conflicts, 1/2/6 for errors. */
int holy_preview_local(const char *package, const char *root);
/* json emits events; -1 suppresses successful output for plan validation. */
int holy_preview_local_format(const char *package, const char *root, int json);

/* one confirmed placement: the path of this package that installs under a private
   root instead. the public path belongs to the provider the review kept, so a preview
   must read the private path or it would report the collision as unresolved. */
struct holy_preview_placement {
    const char *public_path;
    const char *private_path;
};

/* caller supplies a solved graph; completed requires separate payload verification. */
int holy_preview_resolved(const char *package, const char *root, int completed,
                          int accepted_privileged, int skipped_hooks);
/* the same with the placements this package carries, which may be NULL. */
int holy_preview_resolved_placed(const char *package, const char *root, int completed,
                                 int accepted_privileged, int skipped_hooks,
                                 const struct holy_preview_placement *placements,
                                 size_t count);

#endif
