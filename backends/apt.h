#ifndef HOLY_APT_H
#define HOLY_APT_H

int holy_apt_index(const char *input, const char *expected, const char *source,
                   const char *base, const char *output);
int holy_apt_index_quiet(const char *input, const char *expected, const char *source,
                         const char *base, const char *output);
int holy_apt_sync(const char *url, const char *expected, const char *source,
                  const char *base, const char *output, const char *ca_file);
int holy_apt_query(const char *catalog, const char *query, int info);
int holy_apt_fetch(const char *catalog, const char *name, const char *version,
                   const char *arch, const char *output, const char *ca_file,
                   int import);

#endif
