#ifndef HOLY_PACKAGE_H
#define HOLY_PACKAGE_H

/* read-only inspection; returns zero on success and prints diagnostics. */
int holy_package_info(const char *path);
int holy_package_inspect(const char *path, int emit);
int holy_safe_archive_path(const char *name);

#endif
