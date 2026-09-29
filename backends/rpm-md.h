#ifndef HOLY_RPM_MD_H
#define HOLY_RPM_MD_H

int holy_rpm_md_index(const char *repomd, const char *primary, const char *expected,
                      const char *source, const char *base, const char *output,
                      const char *source_id);
int holy_rpm_md_sync(const char *base, const char *expected, const char *source,
                     const char *output, const char *ca_file, const char *source_id);
int holy_rpm_md_query(const char *catalog, const char *query, int info);
int holy_rpm_md_fetch(const char *catalog, const char *name, const char *evr,
                      const char *arch, const char *output, const char *ca_file,
                      int import);
int holy_rpm_md_source_catalog(const char *directory, const char *id,
                               const char *base);
int holy_rpm_md_bind(const char *root, const char *source, const char *catalog);
int holy_rpm_md_catalog_path(const char *root, const char *source, char **catalog);

#endif
