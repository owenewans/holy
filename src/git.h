#ifndef HOLY_GIT_H
#define HOLY_GIT_H

/* clones a pinned native Git tree into a new sealed catalog directory. */
int holy_git_mirror_source(const char *url, const char *commit,
                           const char *index, const char *output,
                           const char *source_id, const char *public_key,
                           const char *ca_file);
/* verifies the recorded detached checkout; expected may be NULL. */
int holy_git_catalog_commit(const char *directory, const char *expected);

#endif
