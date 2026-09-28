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

#endif
