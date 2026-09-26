#define _POSIX_C_SOURCE 200809L
#include "cache.h"
#include "deps.h"
#include "fetch.h"
#include "package.h"
#include "scan.h"
#include "stage.h"
#include "verify.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int holy_cache_stage_local(const char *source, const char *root_path)
{
    static const char *const parts[] = {
        "var", "cache", "holypkg", "objects", "sha256"
    };
    struct holy_package_identity identity = {0};
    struct stat st;
    char name[70];
    char *snapshot = holy_stage_local(source, "holy-cache");
    size_t i;
    int root = -1, current = -1, next, ok = 0;
    if (!snapshot || !holy_verify_with_output(snapshot, 0) ||
        !holy_scan_local_with_output(snapshot, 0) ||
        !holy_deps_local_with_output(snapshot, 0) ||
        !holy_package_identity(snapshot, &identity)) goto done;
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) { perror("holypkg: target root"); goto done; }
    current = root;
    for (i = 0; i < sizeof parts / sizeof *parts; ++i) {
        if (fstat(current, &st) ||
            (st.st_uid != geteuid() && st.st_uid != 0) ||
            (st.st_mode & 0022)) {
            fprintf(stderr, "holypkg: unsafe cache directory owner or mode\n");
            goto done;
        }
        if (mkdirat(current, parts[i], 0700)) {
            if (errno != EEXIST) goto done;
        } else if (fsync(current)) goto done;
        next = openat(current, parts[i], O_RDONLY | O_DIRECTORY |
                      O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) goto done;
        if (current != root) close(current);
        current = next;
    }
    if (fstat(current, &st) ||
        (st.st_uid != geteuid() && st.st_uid != 0) ||
        (st.st_mode & 0022)) {
        fprintf(stderr, "holypkg: unsafe cache directory owner or mode\n");
        goto done;
    }
    if (!holy_fetch_at(snapshot, current, identity.digest, name) ||
        fstatat(current, name, &st, AT_SYMLINK_NOFOLLOW) ||
        !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 0022)) goto done;
    printf("%s/var/cache/holypkg/objects/sha256/%s\n", root_path, name);
    ok = 1;
done:
    if (!ok) fprintf(stderr, "holypkg: cache stage failed; inspect target cache\n");
    if (current >= 0 && current != root) close(current);
    if (root >= 0) close(root);
    holy_package_identity_free(&identity);
    if (snapshot) { unlink(snapshot); free(snapshot); }
    return ok;
}
