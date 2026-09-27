#ifndef HOLY_VERIFY_H
#define HOLY_VERIFY_H

#include <stddef.h>

struct holy_manifest_entry {
    const char *path;
    const char *link;
    const char *hardlink;
    const char *group;
    const unsigned char *hash;
    long long size;
    unsigned int mode;
    long long uid, gid;
    int directory;
};

/* borrowed fields remain valid only during the callback; zero aborts traversal. */
typedef int (*holy_manifest_visit)(void *context,
                                    const struct holy_manifest_entry *entry);

/* lexical target-root containment; this does not resolve other symlinks. */
int holy_safe_link(const char *path, const char *target);

/* checks the regular-file subset of HOLY/files without extracting files. */
int holy_verify(const char *path);
int holy_verify_with_output(const char *path, int emit);
/* calls visitor only after the complete archive and manifest validate. */
int holy_verify_visit(const char *path, holy_manifest_visit visitor, void *context);
/* stages a local input before reading it; prints only after validation. */
int holy_manifest_local(const char *path);

#endif
