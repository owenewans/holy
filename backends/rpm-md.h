#ifndef HOLY_RPM_MD_H
#define HOLY_RPM_MD_H

int holy_rpm_md_index(const char *repomd, const char *primary, const char *expected,
                      const char *source, const char *base, const char *output);
int holy_rpm_md_sync(const char *base, const char *expected, const char *source,
                     const char *output, const char *ca_file);
int holy_rpm_md_query(const char *catalog, const char *query, int info);
int holy_rpm_md_fetch(const char *catalog, const char *name, const char *evr,
                      const char *arch, const char *output, const char *ca_file,
                      int import);

#endif
