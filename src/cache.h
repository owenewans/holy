#ifndef HOLY_CACHE_H
#define HOLY_CACHE_H

/* stages a verified local native package in the target root cache only. */
int holy_cache_stage_local(const char *source, const char *root_path);
/* verifies one cached object by digest without changing the target root. */
int holy_cache_verify(const char *digest, const char *root_path);
/* same verification without success output; returns one for a valid object. */
int holy_cache_object(const char *digest, const char *root_path);

#endif
