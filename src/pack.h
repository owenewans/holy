#ifndef HOLY_PACK_H
#define HOLY_PACK_H

#include <stddef.h>

/* write a verified file/dir/symlink/hardlink .holy from a prepared tree. */
int holy_pack(const char *tree, const char *output);
/* generate a manifest for a prepared DATA tree without changing it. */
int holy_generate_files(const char *tree, const char *output);

struct holy_stream_entry {
    const char *path, *link, *hardlink, *owner, *group;
    long long offset, size, uid, gid;
    unsigned mode;
    int directory;
};

/* borrowed immutable spool and records; no payload path is opened on the host.
   writes the same native LZ4/PAX format, verifies it, then publishes without replacement. */
int holy_pack_stream(int spool, const struct holy_stream_entry *entries, size_t count,
                      int directory, const char *name);

#endif
