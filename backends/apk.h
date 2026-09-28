#ifndef HOLY_APK_H
#define HOLY_APK_H

#include <stdio.h>
#include <stdint.h>

/* returns one to three bounded gzip members as owned anonymous files. */
int holy_apk_gzip_parts(const char *snapshot, FILE *parts[3],
                        char digests[3][65], uint64_t max_expanded);

int holy_apk_index(const char *input, const char *source, const char *base,
                   const char *output);
int holy_apk_verify_index(const char *input, const char *public_key);
int holy_apk_key_fingerprint(const char *public_key, char digest[65]);
/* borrowed members and key path; returns 1 only for a valid matching signature. */
int holy_apk_verify_signature(FILE *signature, FILE *control,
                              const char *public_key, const char *keyname,
                              char algorithm[16]);
int holy_apk_query(const char *catalog, const char *query, int info);
int holy_apk_fetch(const char *catalog, const char *name, const char *version,
                   const char *arch, const char *output, const char *sha256,
                   const char *ca_file, const char *root, const char *source_alias,
                   const char *public_key, int import, const char *required_soname);
int holy_apk_sync(const char *root, const char *source, const char *repo,
                  const char *output, const char *sha256,
                  const char *accept_unsigned, const char *ca_file,
                  const char *public_key);
int holy_apk_bind(const char *root, const char *source, const char *repo,
                  const char *catalog, const char *accepted,
                  const char *public_key);
/* returns an owned verified catalog path for an active source and repo. */
int holy_apk_catalog_path(const char *root, const char *source, const char *repo,
                          char **catalog);

#endif
