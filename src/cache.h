#ifndef HOLY_CACHE_H
#define HOLY_CACHE_H

/* stages a verified local native package in the target root cache only. */
int holy_cache_stage_local(const char *source, const char *root_path);
/* on success copies the verified artifact digest into output when non-NULL. */
int holy_cache_stage_local_digest(const char *source, const char *root_path,
                                   char output[65]);
/* verifies one cached object by digest without changing the target root. */
int holy_cache_verify(const char *digest, const char *root_path);
/* same verification without success output; returns one for a valid object. */
int holy_cache_object(const char *digest, const char *root_path);
/* returns a verified private snapshot; caller must unlink and free it. */
char *holy_cache_snapshot(const char *digest, const char *root_path);
/* lists cached native objects and whether an installed slot uses each one. */
int holy_cache_list(const char *root_path);
/* previews or confirms removal of one object after database reference checks. */
int holy_cache_clean(const char *digest, const char *root_path, int yes);

#endif
