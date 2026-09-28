#define _POSIX_C_SOURCE 200809L
#include "cache.h"
#include "deps.h"
#include "fetch.h"
#include "package.h"
#include "scan.h"
#include "stage.h"
#include "verify.h"
#include "provides.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int cache_directory(const char *root_path, int create)
{
    static const char *const parts[] = {
        "var", "cache", "holypkg", "objects", "sha256"
    };
    struct stat st;
    size_t i;
    int current = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (current < 0) return -1;
    for (i = 0; i <= sizeof parts / sizeof *parts; ++i) {
        int next;
        if (fstat(current, &st) ||
            (st.st_uid != geteuid() && st.st_uid != 0) ||
            (st.st_mode & 0022)) {
            fprintf(stderr, "holypkg: unsafe cache directory owner or mode\n");
            close(current);
            return -1;
        }
        if (i == sizeof parts / sizeof *parts) return current;
        if (create) {
            if (mkdirat(current, parts[i], 0700)) {
                if (errno != EEXIST) { close(current); return -1; }
            } else if (fsync(current)) { close(current); return -1; }
        }
        next = openat(current, parts[i], O_RDONLY | O_DIRECTORY |
                      O_NOFOLLOW | O_CLOEXEC);
        close(current);
        if (next < 0) return -1;
        current = next;
    }
    return -1;
}

int holy_cache_stage_local_digest(const char *source, const char *root_path,
                                   char output[65])
{
    struct holy_package_identity identity = {0};
    struct stat st;
    char name[70];
    char *snapshot = holy_stage_local(source, "holy-cache");
    int current = -1, ok = 0;
    if (output) output[0] = 0;
    if (!snapshot || !holy_verify_with_output(snapshot, 0) ||
        !holy_scan_local_with_output(snapshot, 0) ||
        !holy_deps_local_with_output(snapshot, 0) ||
        !holy_provides_local(snapshot, 0) ||
        !holy_package_identity(snapshot, &identity)) goto done;
    current = cache_directory(root_path, 1);
    if (current < 0) goto done;
    if (!holy_fetch_at(snapshot, current, identity.digest, name) ||
        fstatat(current, name, &st, AT_SYMLINK_NOFOLLOW) ||
        !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 0022)) goto done;
    printf("%s/var/cache/holypkg/objects/sha256/%s\n", root_path, name);
    if (output) memcpy(output, identity.digest, 65);
    ok = 1;
done:
    if (!ok) fprintf(stderr, "holypkg: cache stage failed; inspect target cache\n");
    if (current >= 0) close(current);
    holy_package_identity_free(&identity);
    if (snapshot) { unlink(snapshot); free(snapshot); }
    return ok;
}

int holy_cache_stage_local(const char *source, const char *root_path)
{
    return holy_cache_stage_local_digest(source, root_path, NULL);
}

char *holy_cache_snapshot(const char *digest, const char *root_path)
{
    struct holy_package_identity identity = {0};
    struct stat st;
    char name[70], *snapshot = NULL;
    size_t i;
    int dir = -1, fd = -1, ok = 0;
    if (!digest || strlen(digest) != 64) goto done;
    for (i = 0; i < 64; ++i)
        if (!((digest[i] >= '0' && digest[i] <= '9') ||
              (digest[i] >= 'a' && digest[i] <= 'f'))) goto done;
    snprintf(name, sizeof name, "%s.holy", digest);
    dir = cache_directory(root_path, 0);
    if (dir < 0) goto done;
    fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        (st.st_mode & 0022)) goto done;
    snapshot = holy_stage_fd(fd, "holy-cache-verify");
    if (!snapshot || !holy_verify_with_output(snapshot, 0) ||
        !holy_scan_local_with_output(snapshot, 0) ||
        !holy_deps_local_with_output(snapshot, 0) ||
        !holy_provides_local(snapshot, 0) ||
        !holy_package_identity(snapshot, &identity) ||
        strcmp(identity.digest, digest)) goto done;
    ok = 1;
done:
    if (!ok) fprintf(stderr, "holypkg: cache object verification failed\n");
    holy_package_identity_free(&identity);
    if (fd >= 0) close(fd);
    if (dir >= 0) close(dir);
    if (!ok && snapshot) { unlink(snapshot); free(snapshot); snapshot = NULL; }
    return snapshot;
}

static int verify_object(const char *digest, const char *root_path, int emit)
{
    struct holy_package_identity identity = {0};
    char *snapshot = holy_cache_snapshot(digest, root_path);
    int ok = snapshot != NULL;
    if (ok && emit) {
        ok = holy_package_identity(snapshot, &identity);
        if (ok) printf("verified %s %s %s %s\n", identity.digest, identity.name,
                       identity.arch, identity.libc);
    }
    holy_package_identity_free(&identity);
    if (snapshot) { unlink(snapshot); free(snapshot); }
    return ok;
}

int holy_cache_verify(const char *digest, const char *root_path)
{
    return verify_object(digest, root_path, 1);
}

int holy_cache_object(const char *digest, const char *root_path)
{
    return verify_object(digest, root_path, 0);
}
