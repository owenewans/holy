#define _POSIX_C_SOURCE 200809L
#include "cache.h"
#include "deps.h"
#include "fetch.h"
#include "package.h"
#include "scan.h"
#include "stage.h"
#include "verify.h"
#include "provides.h"
#include "state.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/file.h>
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

static int unavailable_dir(int cache, int create)
{
    struct stat st;
    int dir;
    if (create && mkdirat(cache, ".unavailable", 0700) && errno != EEXIST) return -1;
    dir = openat(cache, ".unavailable", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) return -1;
    if (fstat(dir, &st) || (st.st_uid != geteuid() && st.st_uid != 0) ||
        (st.st_mode & 0022)) { close(dir); errno = EPERM; return -1; }
    return dir;
}

static int clear_unavailable(int cache, const char *digest)
{
    int dir = unavailable_dir(cache, 0), ok;
    if (dir < 0) return errno == ENOENT;
    ok = !unlinkat(dir, digest, 0) || errno == ENOENT;
    if (ok) ok = !fsync(dir);
    close(dir);
    return ok;
}

static int mark_unavailable(int cache, const char *digest)
{
    char record[120];
    size_t length = (size_t)snprintf(record, sizeof record,
                                    "format holy-cache-unavailable-1\nartifact %s\n", digest);
    struct stat st;
    int dir = unavailable_dir(cache, 1), fd, ok = 0;
    if (dir < 0 || length >= sizeof record) return 0;
    fd = openat(dir, digest, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0 && errno == EEXIST) {
        char existing[120];
        fd = openat(dir, digest, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        if (fd >= 0 && !fstat(fd, &st) && S_ISREG(st.st_mode) &&
            st.st_size == (off_t)length && !(st.st_mode & 0022) &&
            (st.st_uid == geteuid() || st.st_uid == 0) &&
            pread(fd, existing, length, 0) == (ssize_t)length &&
            !memcmp(existing, record, length)) ok = 1;
    } else if (fd >= 0) {
        ok = write(fd, record, length) == (ssize_t)length && !fsync(fd);
    }
    if (fd >= 0) close(fd);
    if (ok) ok = !fsync(dir);
    close(dir);
    return ok;
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
    if (current < 0 || flock(current, LOCK_EX)) goto done;
    if (!holy_fetch_at(snapshot, current, identity.digest, name) ||
        fstatat(current, name, &st, AT_SYMLINK_NOFOLLOW) ||
        !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 0022) || !clear_unavailable(current, identity.digest)) goto done;
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

static int cache_name(const char *name)
{
    size_t i;
    if (strlen(name) != 69 || strcmp(name + 64, ".holy")) return 0;
    for (i = 0; i < 64; ++i)
        if (!((name[i] >= '0' && name[i] <= '9') ||
              (name[i] >= 'a' && name[i] <= 'f'))) return 0;
    return 1;
}

static int unavailable_name(const char *name)
{
    char object[70];
    if (strlen(name) != 64) return 0;
    snprintf(object, sizeof object, "%s.holy", name);
    return cache_name(object);
}

static int name_order(const void *left, const void *right)
{
    const char *const *a = left, *const *b = right;
    return strcmp(*a, *b);
}

static int cache_names(int dir, char ***output, size_t *count, int unavailable)
{
    DIR *list = NULL;
    struct dirent *entry;
    char **names = NULL;
    size_t used = 0;
    int ok = 0;
    *output = NULL; *count = 0;
    list = fdopendir(dup(dir));
    if (!list) return 0;
    errno = 0;
    while ((entry = readdir(list))) {
        struct stat st;
        char **grown;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..") ||
            (!unavailable && !strcmp(entry->d_name, ".unavailable"))) continue;
        if (!(unavailable ? unavailable_name(entry->d_name) : cache_name(entry->d_name)) ||
            used == 100000 ||
            fstatat(dir, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) ||
            !S_ISREG(st.st_mode) || (st.st_mode & 0022)) goto done;
        grown = realloc(names, (used + 1) * sizeof *grown);
        if (!grown) goto done;
        names = grown;
        names[used] = strdup(entry->d_name);
        if (!names[used]) goto done;
        ++used;
        errno = 0;
    }
    if (errno) goto done;
    qsort(names, used, sizeof *names, name_order);
    *output = names; *count = used; names = NULL; used = 0;
    ok = 1;
done:
    while (used) free(names[--used]);
    free(names);
    closedir(list);
    return ok;
}

static int transaction_refs(int dir, const char *digest, unsigned depth)
{
    DIR *list;
    struct dirent *entry;
    int result = 0;
    /* a dup shares the directory offset, so a repeated walk rewinds it first */
    if (depth > 4 || lseek(dir, 0, SEEK_SET) < 0 ||
        (list = fdopendir(dup(dir))) == NULL) return -1;
    errno = 0;
    while ((entry = readdir(list))) {
        struct stat st;
        int fd;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (strstr(entry->d_name, digest)) { result = 1; break; }
        if (fstatat(dir, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) ||
            (st.st_mode & 0022)) { result = -1; break; }
        if (S_ISDIR(st.st_mode)) {
            fd = openat(dir, entry->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (fd < 0) { result = -1; break; }
            result = transaction_refs(fd, digest, depth + 1);
            close(fd);
        } else if (S_ISREG(st.st_mode) && st.st_size <= 4 * 1024 * 1024) {
            char buffer[4096 + 63];
            ssize_t got;
            size_t carry = 0, i;
            fd = openat(dir, entry->d_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
            if (fd < 0) { result = -1; break; }
            while ((got = read(fd, buffer + carry, 4096)) > 0) {
                size_t length = carry + (size_t)got;
                for (i = 0; i + 64 <= length; ++i)
                    if (!memcmp(buffer + i, digest, 64)) { result = 1; break; }
                if (result) break;
                carry = length < 63 ? length : 63;
                memmove(buffer, buffer + length - carry, carry);
            }
            if (got < 0) result = -1;
            close(fd);
        } else result = -1;
        if (result) break;
        errno = 0;
    }
    if (!entry && errno) result = -1;
    closedir(list);
    return result;
}

/* an installed artifact without its cached object is discoverable from its payload but
   cannot be reused, since a set resolves and hashes the archive it stages. the report
   names the artifact and the reason, so the fact is visible before a plan needs it. */
struct unretained {
    int cache;
    size_t count;
    int failed;
};

/* a state visitor returns 0 to continue and a nonzero status to stop the walk */
static int unretained_visit(void *context, int root, int instance, const char *digest)
{
    struct unretained *state = context;
    char name[256], object[70];
    struct stat st;
    (void)root;
    if (snprintf(object, sizeof object, "%s.holy", digest) < 0) return 1;
    if (!fstatat(state->cache, object, &st, AT_SYMLINK_NOFOLLOW)) return 0;
    if (errno != ENOENT ||
        !holy_state_instance_field(instance, "name", name, sizeof name)) {
        state->failed = 1;
        return 1;
    }
    printf("unretained %s %s reason no-cached-object\n", digest, name);
    ++state->count;
    return 0;
}

int holy_cache_list(const char *root_path)
{
    char **names = NULL;
    size_t count = 0, i, cached = 0, unavailable_count = 0;
    struct unretained state = {-1, 0, 0};
    unsigned long long generation;
    int status = 1, state_fd = -1, installed = -1, transactions = -1, cache = -1;
    int unavailable = -1, result = 1;
    state_fd = holy_state_lock(root_path, 0, &generation, &status);
    if (state_fd < 0) return status;
    installed = openat(state_fd, "installed", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    transactions = openat(state_fd, "transactions",
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    cache = cache_directory(root_path, 0);
    if (installed < 0 || transactions < 0 || cache < 0 || flock(cache, LOCK_SH) ||
        !cache_names(cache, &names, &count, 0)) goto done;
    for (i = 0; i < count; ++i) {
        struct stat st, used;
        char digest[65];
        int refs;
        memcpy(digest, names[i], 64); digest[64] = 0;
        if (fstatat(cache, names[i], &st, AT_SYMLINK_NOFOLLOW) || !S_ISREG(st.st_mode)) goto done;
        if (!fstatat(installed, digest, &used, AT_SYMLINK_NOFOLLOW)) {
            if (!S_ISDIR(used.st_mode)) goto done;
            printf("cache %s size %ju installed\n", digest, (uintmax_t)st.st_size);
            continue;
        } else if (errno != ENOENT) goto done;
        /* an object no instance owns is either plain retained or kept because a
           transaction record refers to it, which is the provenance clean needs. a
           transaction tree too deep to inspect is reported as unproven rather than
           failing an inventory of the whole cache. */
        refs = transaction_refs(transactions, digest, 0);
        printf("cache %s size %ju retained%s\n", digest, (uintmax_t)st.st_size,
               refs > 0 ? " reason transaction-reference" :
               refs < 0 ? " reason unverified-transactions" : "");
    }
    cached = count;
    for (i = 0; i < count; ++i) free(names[i]);
    free(names); names = NULL; count = 0;
    unavailable = unavailable_dir(cache, 0);
    if (unavailable >= 0) {
        if (!cache_names(unavailable, &names, &count, 1)) goto done;
        for (i = 0; i < count; ++i) {
            struct stat st;
            char object[70];
            snprintf(object, sizeof object, "%s.holy", names[i]);
            if (fstatat(cache, object, &st, AT_SYMLINK_NOFOLLOW) == 0) continue;
            if (errno != ENOENT) goto done;
            printf("cache %s unavailable\n", names[i]);
            ++unavailable_count;
        }
    } else if (errno != ENOENT) goto done;
    for (i = 0; i < count; ++i) free(names[i]);
    free(names); names = NULL; count = 0;
    state.cache = cache;
    if (holy_state_visit(root_path, unretained_visit, &state, &generation) || state.failed)
        goto done;
    printf("generation %llu cached %zu unavailable %zu unretained %zu read-only\n",
           generation, cached, unavailable_count, state.count);
    result = ferror(stdout) ? 1 : 0;
done:
    for (i = 0; i < count; ++i) free(names[i]);
    free(names);
    if (unavailable >= 0) close(unavailable);
    if (cache >= 0) close(cache);
    if (transactions >= 0) close(transactions);
    if (installed >= 0) close(installed);
    if (state_fd >= 0) close(state_fd);
    return result;
}

int holy_cache_clean(const char *digest, const char *root_path, int yes,
                     int accept_unavailable)
{
    char name[70];
    struct stat st, installed_st;
    unsigned long long generation;
    int status = 1, state = -1, installed = -1, transactions = -1;
    int cache = -1, result = 1, refs, installed_ref = 0;
    if (accept_unavailable && !yes) return 2;
    if (!digest || strlen(digest) != 64) return 2;
    snprintf(name, sizeof name, "%s.holy", digest);
    if (!cache_name(name)) return 2;
    state = holy_state_lock(root_path, yes, &generation, &status);
    if (state < 0) return status;
    installed = openat(state, "installed", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    transactions = openat(state, "transactions", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    cache = cache_directory(root_path, 0);
    if (installed < 0 || transactions < 0 || cache < 0 ||
        flock(cache, yes ? LOCK_EX : LOCK_SH)) goto done;
    if (fstatat(cache, name, &st, AT_SYMLINK_NOFOLLOW)) {
        result = errno == ENOENT ? 6 : 1; goto done;
    }
    if (!S_ISREG(st.st_mode) || (st.st_mode & 0022)) goto done;
    if (!fstatat(installed, digest, &installed_st, AT_SYMLINK_NOFOLLOW)) {
        if (!S_ISDIR(installed_st.st_mode)) goto done;
        installed_ref = 1;
    } else if (errno != ENOENT) goto done;
    refs = transaction_refs(transactions, digest, 0);
    if (refs < 0) goto done;
    if (!yes) {
        printf("cache-clean-plan %s size %ju generation %llu installed %d transactions %d read-only\n",
               digest, (uintmax_t)st.st_size, generation, installed_ref, refs);
        result = 0; goto done;
    }
    if ((installed_ref || refs) && !accept_unavailable) {
        fprintf(stderr, "holypkg: decision-required cache object %s installed=%d transactions=%d; use --accept-unavailable after review\n",
                digest, installed_ref, refs);
        result = 3; goto done;
    }
    if (!mark_unavailable(cache, digest)) goto done;
    if (unlinkat(cache, name, 0) || fsync(cache)) goto done;
    printf("cache-cleaned %s unavailable\n", digest);
    result = 0;
done:
    if (cache >= 0) close(cache);
    if (transactions >= 0) close(transactions);
    if (installed >= 0) close(installed);
    if (state >= 0) close(state);
    return result;
}
