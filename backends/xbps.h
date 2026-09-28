#ifndef HOLY_XBPS_H
#define HOLY_XBPS_H

int holy_xbps_index(const char *input, const char *source, const char *base,
                    const char *output, const char *expected, const char *public_key,
                    const char *source_id);
int holy_xbps_sync(const char *base, const char *arch, const char *source,
                   const char *output, const char *expected, const char *ca_file,
                   const char *public_key, const char *source_id);
int holy_xbps_key_fingerprint(const char *path, char output[65]);
int holy_xbps_source_catalog(const char *directory, const char *source,
                             const char *id, const char *base, const char *key);
int holy_xbps_query(const char *directory, const char *query, int info);
int holy_xbps_fetch(const char *directory, const char *name, const char *version,
                    const char *arch, const char *output, const char *ca_file,
                    const char *public_key);

#endif
