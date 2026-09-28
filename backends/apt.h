#ifndef HOLY_APT_H
#define HOLY_APT_H

int holy_apt_index(const char *input, const char *expected, const char *source,
                   const char *base, const char *output);
int holy_apt_index_quiet(const char *input, const char *expected, const char *source,
                         const char *base, const char *output);
int holy_apt_sync(const char *url, const char *expected, const char *source,
                  const char *base, const char *output, const char *ca_file);
int holy_apt_query(const char *catalog, const char *query, int info, int file_search,
                   const char *root, const char *source);
int holy_apt_fetch(const char *catalog, const char *name, const char *version,
                   const char *arch, const char *output, const char *ca_file,
                   int import, const char *required_file,
                   const char *root, const char *source);
int holy_apt_bind(const char *root, const char *source, const char *suite,
                  const char *component, const char *index_arch,
                  const char *catalog);
/* returns a verified, owned path from the target-root APT binding. */
int holy_apt_catalog_path(const char *root, const char *source, const char *suite,
                          const char *component, const char *index_arch,
                          char **catalog);
/* verifies a catalog against an active source and returns its bound identifiers. */
int holy_apt_catalog_identity(const char *catalog, const char *root,
                              const char *source, char source_id[65],
                              char index_hash[65]);

#endif
