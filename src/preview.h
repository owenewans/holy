#ifndef HOLY_PREVIEW_H
#define HOLY_PREVIEW_H

/* returns 0 for a collision-free preview, 4 for conflicts, 1/2/6 for errors. */
int holy_preview_local(const char *package, const char *root);
/* json emits events; -1 suppresses successful output for plan validation. */
int holy_preview_local_format(const char *package, const char *root, int json);

#endif
