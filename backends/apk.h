#ifndef HOLY_APK_H
#define HOLY_APK_H

#include <stdio.h>
#include <stdint.h>

/* returns one to three bounded gzip members as owned anonymous files. */
int holy_apk_gzip_parts(const char *snapshot, FILE *parts[3],
                        char digests[3][65], uint64_t max_expanded);

int holy_apk_index(const char *input, const char *source, const char *base,
                   const char *output);
int holy_apk_query(const char *catalog, const char *query, int info);
int holy_apk_fetch(const char *catalog, const char *name, const char *version,
                   const char *arch, const char *output, const char *sha256,
                   const char *ca_file);

#endif
