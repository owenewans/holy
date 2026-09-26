#ifndef HOLY_PACKAGE_H
#define HOLY_PACKAGE_H

#include <stdint.h>

struct holy_package_identity {
    char *name;
    char *version;
    char *release;
    char *os;
    char *arch;
    char *libc;
    char digest[65];
    uint64_t size;
};

/* read-only inspection; returns zero on success and prints diagnostics. */
int holy_package_info(const char *path);
int holy_package_inspect(const char *path, int emit);
/* on success returns allocated arch/libc; caller frees them. */
int holy_package_tags(const char *path, char **arch, char **libc);
int holy_package_identity(const char *path, struct holy_package_identity *out);
void holy_package_identity_free(struct holy_package_identity *info);
int holy_safe_archive_path(const char *name);

#endif
