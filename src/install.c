#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "install.h"
#include "verify.h"
#include "config.h"
#include "script.h"

#include <archive.h>
#include <archive_entry.h>
#include <openssl/evp.h>
#include <errno.h>
#include <dirent.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int transition_matches(int root, const struct holy_manifest_entry *entry,
                               struct stat *observed);

struct group_observation { char *group; struct stat state; };
struct observed_groups { struct group_observation *items; size_t count; };

static int observe_group(struct observed_groups *groups, const char *group,
                          const struct stat *state)
{
    struct group_observation *next;
    if (!group || !strcmp(group, "-")) return 1;
    if (groups->count == SIZE_MAX / sizeof *next) return 0;
    next = realloc(groups->items, (groups->count + 1) * sizeof *next);
    if (!next) return 0;
    groups->items = next;
    next[groups->count].group = strdup(group);
    if (!next[groups->count].group) return 0;
    next[groups->count++].state = *state;
    return 1;
}

static int group_order(const void *left, const void *right)
{
    return strcmp(((const struct group_observation *)left)->group,
                  ((const struct group_observation *)right)->group);
}

static int groups_intact(struct observed_groups *groups)
{
    size_t i;
    if (groups->count) qsort(groups->items, groups->count, sizeof *groups->items, group_order);
    for (i = 1; i < groups->count; ++i) {
        const struct group_observation *a = &groups->items[i-1], *b = &groups->items[i];
        if (!strcmp(a->group, b->group) &&
            (a->state.st_dev != b->state.st_dev || a->state.st_ino != b->state.st_ino)) {
            fputs("holypkg: changed-hardlink-group\n", stderr);
            return 0;
        }
    }
    return 1;
}

static void groups_free(struct observed_groups *groups)
{
    size_t i;
    for (i = 0; i < groups->count; ++i) free(groups->items[i].group);
    free(groups->items);
}

static int parent_fd(int root, const char *path, char **storage, const char **base)
{
    char *cursor, *slash;
    int current;
    struct stat st;
    *storage = strdup(path);
    if (!*storage) return -1;
    current = dup(root);
    if (current < 0) goto fail;
    cursor = *storage;
    while ((slash = strchr(cursor, '/')) != NULL) {
        int next;
        *slash = '\0';
        if (!*cursor || !strcmp(cursor, ".") || !strcmp(cursor, "..")) { errno = EINVAL; goto fail; }
        next = openat(current, cursor, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0 || fstat(next, &st) || !S_ISDIR(st.st_mode) ||
            (st.st_uid != 0 && st.st_uid != geteuid()) ||
            (st.st_mode & 0022)) {
            if (next >= 0) { close(next); errno = EPERM; }
            goto fail;
        }
        close(current);
        current = next;
        cursor = slash + 1;
    }
    if (!*cursor || !strcmp(cursor, ".") || !strcmp(cursor, "..")) { errno = EINVAL; goto fail; }
    *base = cursor;
    return current;
fail:
    {
    int error = errno;
    if (current >= 0) close(current);
    free(*storage);
    *storage = NULL;
    errno = error;
    }
    return -1;
}

struct directory_list {
    const struct holy_manifest_entry **items;
    size_t count;
};

static int directory_order(const void *left, const void *right)
{
    const struct holy_manifest_entry *a = *(const struct holy_manifest_entry *const *)left;
    const struct holy_manifest_entry *b = *(const struct holy_manifest_entry *const *)right;
    return strcmp(a->path, b->path);
}

static int declared_directory(const struct directory_list *list, const char *path)
{
    size_t low = 0, high = list->count;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        int order = strcmp(list->items[middle]->path, path);
        if (!order) return 1;
        if (order < 0) low = middle + 1;
        else high = middle;
    }
    return 0;
}

static int planned_parents(int root, const char *path, const struct directory_list *list)
{
    char *copy = strdup(path), *cursor, *slash;
    int current = dup(root), missing = 0, ok = 0;
    if (!copy || current < 0 || !*path || *path == '/') goto done;
    cursor = copy;
    while ((slash = strchr(cursor, '/'))) {
        int next = -1;
        struct stat st;
        *slash = 0;
        if (!*cursor || !strcmp(cursor, ".") || !strcmp(cursor, "..")) goto done;
        if (!missing) {
            next = openat(current, cursor, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (next < 0) {
                if (errno != ENOENT) goto done;
                missing = 1;
            } else {
                if (fstat(next, &st) || (st.st_uid != 0 && st.st_uid != geteuid()) || (st.st_mode & 0022)) {
                    close(next); goto done;
                }
                close(current); current = next;
            }
        }
        if (missing && !declared_directory(list, copy)) goto done;
        *slash = '/'; cursor = slash + 1;
    }
    ok = *cursor && strcmp(cursor, ".") && strcmp(cursor, "..");
done:
    if (current >= 0) close(current);
    free(copy);
    return ok;
}

static int directory_name(const struct holy_manifest_entry *entry, char name[75])
{
    unsigned char hash[32];
    unsigned length;
    size_t i;
    if (EVP_Digest(entry->path, strlen(entry->path), hash, &length, EVP_sha256(), NULL) != 1 ||
        length != 32) return 0;
    memcpy(name, ".holy-dir-", 10);
    for (i = 0; i < 32; ++i) snprintf(name + 10 + i * 2, 3, "%02x", hash[i]);
    return 1;
}

static int directory_empty(int fd)
{
    int copy = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC), ok = 0;
    DIR *stream;
    struct dirent *entry;
    if (copy < 0) return 0;
    stream = fdopendir(copy);
    if (!stream) { close(copy); return 0; }
    errno = 0;
    while ((entry = readdir(stream)))
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) break;
    ok = !entry && !errno;
    closedir(stream);
    return ok;
}

static int directory_stage(int root, const struct holy_manifest_entry *entry, int create, int recovering)
{
    char name[75], *storage = NULL;
    const char *base;
    struct stat st;
    int parent = -1, child = -1, ok = 0, exists;
    if (!directory_name(entry, name)) goto done;
    parent = parent_fd(root, entry->path, &storage, &base);
    if (parent < 0) { ok = !create && errno == ENOENT; goto done; }
    exists = !fstatat(parent, name, &st, AT_SYMLINK_NOFOLLOW);
    if (!exists && errno != ENOENT) goto done;
    if (exists && !recovering) goto done;
    if (!create) { ok = 1; goto done; }
    if (!exists && (mkdirat(parent, name, 0700) || fsync(parent))) goto done;
    child = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (child < 0 || fstat(child, &st) || st.st_uid != geteuid() ||
        !directory_empty(child)) goto done;
    if (exists) {
        if ((st.st_mode & 07777) != entry->mode || (long long)st.st_gid != entry->gid) goto done;
    } else if (fchown(child, (uid_t)-1, (gid_t)entry->gid) || fchmod(child, entry->mode)) goto done;
    if (fsync(child) || fstat(child, &st)) goto done;
    {
        struct stat current;
        if (fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW) ||
            current.st_dev != st.st_dev || current.st_ino != st.st_ino) goto done;
    }
#ifdef SYS_renameat2
    if (syscall(SYS_renameat2, parent, name, parent, base, 1u) || fsync(parent)) goto done;
#else
    errno = ENOSYS;
    goto done;
#endif
    ok = 1;
done:
    if (!ok) fputs("holypkg: directory staging requires inspection or a supported renameat2 filesystem\n", stderr);
    if (child >= 0) close(child);
    if (parent >= 0) close(parent);
    free(storage);
    return ok;
}

int holy_install_directory_plan(int root, const struct holy_manifest_entry *entries,
                                 size_t count, int create, int recovering)
{
    struct directory_list list = {0};
    size_t i;
    int ok = 0;
    if (count > SIZE_MAX / sizeof *list.items) return 0;
    list.items = calloc(count ? count : 1, sizeof *list.items);
    if (!list.items) return 0;
    for (i = 0; i < count; ++i) if (entries[i].directory) {
        const struct holy_manifest_entry *e = &entries[i];
        if (!e->path || e->hardlink || e->link || e->group || e->size ||
            (e->mode & ~0777u) || (e->mode & 0022) || !(e->mode & 0100) ||
            e->uid != (long long)geteuid() || e->gid != (long long)getegid()) goto done;
        list.items[list.count++] = e;
    }
    qsort(list.items, list.count, sizeof *list.items, directory_order);
    for (i = 1; i < list.count; ++i)
        if (!strcmp(list.items[i-1]->path, list.items[i]->path)) goto done;
    for (i = 0; i < count; ++i)
        if (!planned_parents(root, entries[i].path, &list)) goto done;
    for (i = 0; i < list.count; ++i) {
        int state = holy_install_check_entry(root, list.items[i]);
        if (state != 1 && (state != 2 || !directory_stage(root, list.items[i], 0, recovering))) goto done;
    }
    if (create) for (i = 0; i < list.count; ++i) {
        int state = holy_install_check_entry(root, list.items[i]);
        if (state != 1 && (state != 2 || !directory_stage(root, list.items[i], 1, recovering))) goto done;
    }
    ok = 1;
done:
    free(list.items);
    return ok;
}

struct root_check {
    int root, recovering, accepted_privileged;
    struct holy_manifest_entry *directories;
    size_t count;
    struct directory_list parents;
    struct observed_groups groups;
};

static int collect_directory(void *context, const struct holy_manifest_entry *entry)
{
    struct root_check *check = context;
    struct holy_manifest_entry *items;
    if (!entry->directory) return 1;
    if (check->count == SIZE_MAX / sizeof *items) return 0;
    items = realloc(check->directories, (check->count + 1) * sizeof *items);
    if (!items) return 0;
    check->directories = items;
    items[check->count] = *entry;
    items[check->count].path = strdup(entry->path);
    if (!items[check->count].path) return 0;
    ++check->count;
    return 1;
}

static int check_entry(void *context, const struct holy_manifest_entry *entry)
{
    struct root_check *check = context;
    int state;
    struct stat observed;
    if ((entry->link && (entry->mode != 0777 || entry->link[0] == '/')) ||
        ((entry->mode & 07000) &&
         (!check->accepted_privileged || entry->directory || entry->link || entry->hardlink ||
          (entry->mode & 03000))) || entry->uid != (long long)geteuid() ||
        entry->gid != (long long)getegid() ||
        !planned_parents(check->root, entry->path, &check->parents)) return 0;
    state = transition_matches(check->root, entry, &observed);
    if (state == 1 && !observe_group(&check->groups, entry->group, &observed)) return 0;
    return state == 2 || (state == 1 && (entry->directory || check->recovering));
}

static int prepare_directories(const char *snapshot, int root, int create,
                               int recovering, int accepted_privileged)
{
    struct root_check check = {0};
    size_t i;
    int ok = 0;
    check.root = root; check.recovering = recovering;
    check.accepted_privileged = accepted_privileged;
    if (!holy_verify_visit(snapshot, collect_directory, &check)) goto done;
    check.parents.items = calloc(check.count ? check.count : 1, sizeof *check.parents.items);
    if (!check.parents.items) goto done;
    check.parents.count = check.count;
    for (i = 0; i < check.count; ++i) check.parents.items[i] = &check.directories[i];
    qsort(check.parents.items, check.count, sizeof *check.parents.items, directory_order);
    ok = holy_install_directory_plan(root, check.directories, check.count, 0, recovering) &&
         holy_verify_visit(snapshot, check_entry, &check) && groups_intact(&check.groups) &&
         (!create || holy_install_directory_plan(root, check.directories, check.count, 1, recovering));
done:
    for (i = 0; i < check.count; ++i) free((char *)check.directories[i].path);
    free(check.parents.items);
    free(check.directories);
    groups_free(&check.groups);
    if (!ok) fputs("holypkg: install requires intact or declared safe directories and matching payload state\n", stderr);
    return ok;
}

int holy_install_preflight(const char *snapshot, int root, int accepted_privileged)
{
    return prepare_directories(snapshot, root, 0, 0, accepted_privileged);
}

int holy_install_preflight_resume(const char *snapshot, int root, int accepted_privileged)
{
    return prepare_directories(snapshot, root, 0, 1, accepted_privileged);
}

static int link_payload(int root, const char *source, const struct holy_manifest_entry *destination,
                         int missing_only)
{
    struct holy_manifest_entry input = *destination;
    struct stat expected, linked;
    char *source_storage = NULL, *dest_storage = NULL;
    const char *source_base, *dest_base;
    int source_parent = -1, dest_parent = -1, fd = -1, ok = 0;
    input.path = source; input.hardlink = NULL;
    if (transition_matches(root, &input, &expected) != 1) goto done;
    source_parent = parent_fd(root, source, &source_storage, &source_base);
    dest_parent = parent_fd(root, destination->path, &dest_storage, &dest_base);
    if (source_parent < 0 || dest_parent < 0) goto done;
    fd = openat(source_parent, source_base, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &linked) || !S_ISREG(linked.st_mode) ||
        linked.st_dev != expected.st_dev || linked.st_ino != expected.st_ino) goto done;
    if (linkat(source_parent, source_base, dest_parent, dest_base, 0) &&
        (!missing_only || errno != EEXIST)) {
        fprintf(stderr, "holypkg: linkat: %s\n", strerror(errno));
        goto done;
    }
    if (fstatat(dest_parent, dest_base, &linked, AT_SYMLINK_NOFOLLOW) ||
        !S_ISREG(linked.st_mode) || linked.st_dev != expected.st_dev ||
        linked.st_ino != expected.st_ino || fsync(fd) || fsync(dest_parent)) goto done;
    ok = 1;
done:
    if (!ok) fputs("holypkg: hardlink creation failed; inspect source, target and filesystem\n", stderr);
    if (fd >= 0) close(fd);
    if (source_parent >= 0) close(source_parent);
    if (dest_parent >= 0) close(dest_parent);
    free(source_storage); free(dest_storage);
    return ok;
}

struct link_install { int root, missing_only, restore_anchor; };

static int install_link(void *context, const struct holy_manifest_entry *entry)
{
    struct link_install *links = context;
    struct holy_manifest_entry anchor;
    int state;
    if (!entry->hardlink) return 1;
    if (!links->restore_anchor)
        return link_payload(links->root, entry->hardlink, entry, links->missing_only);
    anchor = *entry; anchor.path = entry->hardlink; anchor.hardlink = NULL;
    state = transition_matches(links->root, &anchor, NULL);
    if (state == 1) return 1;
    if (state != 2) return 0;
    state = transition_matches(links->root, entry, NULL);
    return state == 2 || (state == 1 && link_payload(links->root, entry->path, &anchor, 0));
}

static int install_payload(const char *snapshot, int root, int missing_only,
                           int accepted_privileged)
{
    struct archive *archive = archive_read_new();
    struct archive_entry *entry;
    char buffer[65536];
    int status, ok = 0;
    struct link_install links = {root, missing_only, 1};
    if (!archive) return 0;
    if (!prepare_directories(snapshot, root, 1, missing_only, accepted_privileged) ||
        (missing_only && !holy_verify_visit(snapshot, install_link, &links))) goto done;
    if (archive_read_support_filter_lz4(archive) != ARCHIVE_OK ||
        archive_read_support_format_tar(archive) != ARCHIVE_OK ||
        archive_read_open_filename(archive, snapshot, 8192) != ARCHIVE_OK) goto done;
    while ((status = archive_read_next_header(archive, &entry)) == ARCHIVE_OK) {
        const char *path = archive_entry_pathname(entry);
        char *storage = NULL;
        const char *base;
        int parent = -1, fd = -1;
        la_ssize_t got;
        la_int64_t count = 0;
        if (!path || strncmp(path, "DATA/", 5) || !path[5] ||
            archive_entry_filetype(entry) == AE_IFDIR || archive_entry_hardlink(entry)) {
            if (archive_read_data_skip(archive) != ARCHIVE_OK) goto done;
            continue;
        }
        if (archive_entry_filetype(entry) == AE_IFLNK) {
            const char *target = archive_entry_symlink(entry);
            if (!target || target[0] == '/' ||
                !holy_safe_link(path + 5, target) ||
                archive_entry_perm(entry) != 0777 ||
                archive_entry_size(entry) != 0) goto done;
            parent = parent_fd(root, path + 5, &storage, &base);
            if (parent < 0) goto done;
            if (symlinkat(target, parent, base)) {
                struct stat st;
                size_t size = strlen(target);
                char *actual;
                int same;
                if (!missing_only || errno != EEXIST ||
                    fstatat(parent, base, &st, AT_SYMLINK_NOFOLLOW) || !S_ISLNK(st.st_mode) ||
                    (long long)st.st_uid != archive_entry_uid(entry) ||
                    (long long)st.st_gid != archive_entry_gid(entry)) goto file_done;
                actual = malloc(size + 1);
                if (!actual) goto file_done;
                got = readlinkat(parent, base, actual, size + 1);
                same = got >= 0 && (size_t)got == size && !memcmp(target, actual, size);
                free(actual);
                if (!same) goto file_done;
            }
            if (fsync(parent) || archive_read_data_skip(archive) != ARCHIVE_OK) goto file_done;
            close(parent);
            free(storage);
            continue;
        }
        if (archive_entry_filetype(entry) != AE_IFREG ||
            archive_entry_hardlink(entry) || archive_entry_size(entry) < 0) goto done;
        if ((archive_entry_perm(entry) & 07000) &&
            (!accepted_privileged || (archive_entry_perm(entry) & 03000))) goto done;
        parent = parent_fd(root, path + 5, &storage, &base);
        if (parent < 0) goto done;
        if (missing_only) {
            struct stat st;
            fd = openat(parent, base, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
            if (fd >= 0) {
                char current[65536];
                if (fstat(fd, &st) || !S_ISREG(st.st_mode) ||
                    (st.st_mode & 07777) != archive_entry_perm(entry) ||
                    (long long)st.st_uid != archive_entry_uid(entry) ||
                    (long long)st.st_gid != archive_entry_gid(entry) ||
                    st.st_size != archive_entry_size(entry)) goto file_done;
                while ((got = archive_read_data(archive, buffer, sizeof buffer)) > 0) {
                    size_t used = 0;
                    while (used < (size_t)got) {
                        ssize_t n = read(fd, current + used, (size_t)got - used);
                        if (n < 0 && errno == EINTR) continue;
                        if (n <= 0) goto file_done;
                        used += (size_t)n;
                    }
                    if (memcmp(current, buffer, (size_t)got)) goto file_done;
                }
                if (got || fsync(fd)) goto file_done;
                close(fd);
                close(parent);
                free(storage);
                continue;
            }
            if (errno != ENOENT) goto file_done;
        }
        fd = openat(parent, base, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) goto file_done;
        while ((got = archive_read_data(archive, buffer, sizeof buffer)) > 0) {
            size_t offset = 0;
            if (count > archive_entry_size(entry) - got) break;
            count += got;
            while (offset < (size_t)got) {
                ssize_t sent = write(fd, buffer + offset, (size_t)got - offset);
                if (sent < 0 && errno == EINTR) continue;
                if (sent <= 0) goto file_done;
                offset += (size_t)sent;
            }
        }
        if (got != 0 || count != archive_entry_size(entry) ||
            fchmod(fd, archive_entry_perm(entry)) || fsync(fd) ||
            fsync(parent)) goto file_done;
        close(fd);
        close(parent);
        free(storage);
        continue;
file_done:
        if (fd >= 0) close(fd);
        close(parent);
        free(storage);
        goto done;
    }
    links.restore_anchor = 0;
    ok = status == ARCHIVE_EOF && holy_verify_visit(snapshot, install_link, &links);
done:
    archive_read_free(archive);
    if (!ok) fprintf(stderr, "holypkg: install payload incomplete; inspect transaction journal\n");
    return ok;
}

int holy_install_payload(const char *snapshot, int root, int accepted_privileged)
{
    return install_payload(snapshot, root, 0, accepted_privileged);
}

int holy_install_payload_missing(const char *snapshot, int root)
{
    return install_payload(snapshot, root, 1, 1);
}

static int decimal(const char *text, int base, unsigned long long *value)
{
    char *end;
    errno = 0;
    if (!*text || *text == '-' || *text == '+') return 0;
    *value = strtoull(text, &end, base);
    return !errno && !*end;
}

static int check_file(int root, char **v, struct stat *observed)
{
    unsigned long long mode, uid, gid, size;
    struct stat st;
    char *storage = NULL;
    const char *base;
    int parent, fd = -1, result = -1;
    EVP_MD_CTX *hash = NULL;
    unsigned char digest[32];
    unsigned int digest_size;
    char buffer[65536];
    ssize_t got;
    size_t i;
    int symlink = !strcmp(v[0], "symlink");
    int hardlink = !strcmp(v[0], "hardlink");
    if ((strcmp(v[0], "dir") && strcmp(v[0], "file") && !symlink && !hardlink) ||
        !decimal(v[2], 8, &mode) || mode > 07777 ||
        !decimal(v[5], 10, &uid) || uid > 0x7fffffff ||
        !decimal(v[6], 10, &gid) || gid > 0x7fffffff ||
        !decimal(v[7], 10, &size) || size > LLONG_MAX ||
        strcmp(v[9], "none") || strcmp(v[10], "-") ||
        ((symlink || !strcmp(v[0], "dir")) && strcmp(v[11], "-")) ||
        (hardlink && !strcmp(v[11], "-")))
        return -1;
    if (strcmp(v[11], "-") && (!v[11][0] ||
        strspn(v[11], "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-") != strlen(v[11]))) return -1;
    if (symlink && (mode != 0777 || v[12][0] == '/' ||
                    !holy_safe_link(v[1], v[12]))) return -1;
    if (!strcmp(v[0], "dir") || symlink) {
        if (size || strcmp(v[8], "-")) return -1;
    } else if (strlen(v[8]) != 64) return -1;
    parent = parent_fd(root, v[1], &storage, &base);
    if (parent < 0) return errno == ENOENT ? 2 : 0;
    if (symlink) {
        size_t length = strlen(v[12]);
        char *target;
        if (fstatat(parent, base, &st, AT_SYMLINK_NOFOLLOW)) {
            result = errno == ENOENT ? 2 : 0;
            goto done;
        }
        if (!S_ISLNK(st.st_mode) || (st.st_mode & 07777) != mode ||
            (unsigned long long)st.st_uid != uid ||
            (unsigned long long)st.st_gid != gid) { result = 0; goto done; }
        target = malloc(length + 1);
        if (!target) goto done;
        got = readlinkat(parent, base, target, length + 1);
        result = got >= 0 && (size_t)got == length &&
                 !memcmp(target, v[12], length);
        free(target);
        if (result && observed) *observed = st;
        goto done;
    }
    if (!strcmp(v[0], "dir")) {
        if (fstatat(parent, base, &st, AT_SYMLINK_NOFOLLOW)) {
            result = errno == ENOENT ? 2 : 0; goto done;
        }
        result = S_ISDIR(st.st_mode) &&
                 (st.st_mode & 07777) == mode &&
                 (unsigned long long)st.st_uid == uid &&
                 (unsigned long long)st.st_gid == gid &&
                 (st.st_uid == 0 || st.st_uid == geteuid()) && !(st.st_mode & 0022);
        goto done;
    }
    fd = openat(parent, base, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0 && errno == ENOENT) { result = 2; goto done; }
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        (st.st_mode & 07777) != mode || (unsigned long long)st.st_uid != uid ||
        (unsigned long long)st.st_gid != gid ||
        (unsigned long long)st.st_size != size) { result = 0; goto done; }
    hash = EVP_MD_CTX_new();
    if (!hash || EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1) goto done;
    while ((got = read(fd, buffer, sizeof buffer)) > 0)
        if (EVP_DigestUpdate(hash, buffer, (size_t)got) != 1) goto done;
    if (got < 0 || EVP_DigestFinal_ex(hash, digest, &digest_size) != 1 ||
        digest_size != sizeof digest) goto done;
    result = 1;
    for (i = 0; i < sizeof digest; ++i) {
        char hex[3];
        snprintf(hex, sizeof hex, "%02x", digest[i]);
        if (v[8][i * 2] != hex[0] || v[8][i * 2 + 1] != hex[1]) result = 0;
    }
    if (result && observed) *observed = st;
done:
    EVP_MD_CTX_free(hash);
    if (fd >= 0) close(fd);
    close(parent);
    free(storage);
    return result;
}

static void report_changed(const char *path, const char *code)
{
    const unsigned char *p = (const unsigned char *)path;
    fprintf(stderr, "holypkg: %s ", code);
    for (; *p; ++p)
        if (*p == '\\' || *p <= 32 || *p >= 127)
            fprintf(stderr, "\\x%02x", (unsigned int)*p);
        else fputc(*p, stderr);
    fputc('\n', stderr);
}

static int same_object(const struct stat *before, const struct stat *after)
{
    return before->st_dev == after->st_dev && before->st_ino == after->st_ino &&
           before->st_mode == after->st_mode && before->st_uid == after->st_uid &&
           before->st_gid == after->st_gid && before->st_size == after->st_size &&
           before->st_mtim.tv_sec == after->st_mtim.tv_sec && before->st_mtim.tv_nsec == after->st_mtim.tv_nsec &&
           before->st_ctim.tv_sec == after->st_ctim.tv_sec && before->st_ctim.tv_nsec == after->st_ctim.tv_nsec;
}

static int remove_file(int root, const char *path, const struct stat *observed)
{
    char *storage = NULL;
    const char *base;
    struct stat st;
    int parent = parent_fd(root, path, &storage, &base), ok = 0;
    if (parent < 0) return 0;
    if (!fstatat(parent, base, &st, AT_SYMLINK_NOFOLLOW) &&
        (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) &&
        same_object(&st, observed) &&
        !unlinkat(parent, base, 0) && !fsync(parent)) ok = 1;
    close(parent);
    free(storage);
    return ok;
}

struct manifest_row {
    char **fields;
    size_t count;
    int checked;
    struct stat observed;
};

static int row_path_order(const void *a, const void *b)
{
    return strcmp((*(const struct manifest_row *const *)a)->fields[1],
                  (*(const struct manifest_row *const *)b)->fields[1]);
}

static int row_group_order(const void *a, const void *b)
{
    return strcmp((*(const struct manifest_row *const *)a)->fields[11],
                  (*(const struct manifest_row *const *)b)->fields[11]);
}

static int row_inode_order(const void *a, const void *b)
{
    const struct stat *left = &(*(const struct manifest_row *const *)a)->observed;
    const struct stat *right = &(*(const struct manifest_row *const *)b)->observed;
    if (left->st_dev != right->st_dev) return left->st_dev < right->st_dev ? -1 : 1;
    if (left->st_ino != right->st_ino) return left->st_ino < right->st_ino ? -1 : 1;
    return 0;
}

static int row_links(struct manifest_row *rows, size_t count)
{
    struct manifest_row **paths = NULL, **groups = NULL;
    size_t i, j, group_count = 0;
    int ok = 0;
    if (count > SIZE_MAX / sizeof *paths) return 0;
    paths = calloc(count ? count : 1, sizeof *paths);
    groups = calloc(count ? count : 1, sizeof *groups);
    if (!paths || !groups) goto done;
    for (i = 0; i < count; ++i) {
        paths[i] = &rows[i];
        if (strcmp(rows[i].fields[11], "-")) groups[group_count++] = &rows[i];
    }
    qsort(paths, count, sizeof *paths, row_path_order);
    for (i = 1; i < count; ++i)
        if (!strcmp(paths[i-1]->fields[1], paths[i]->fields[1])) goto done;
    for (i = 0; i < count; ++i) if (!strcmp(rows[i].fields[0], "hardlink")) {
        char **v = rows[i].fields, *key_fields[2] = {NULL, v[12]};
        struct manifest_row key = {0}, *key_ptr = &key, **found;
        static const size_t attributes[] = {2, 5, 6, 7, 8, 11};
        key.fields = key_fields;
        found = bsearch(&key_ptr, paths, count, sizeof *paths, row_path_order);
        if (!found || strcmp((*found)->fields[0], "file")) goto done;
        for (j = 0; j < sizeof attributes / sizeof *attributes; ++j) {
            size_t field = attributes[j];
            if (field == 8 || field == 11) {
                if (strcmp(v[field], (*found)->fields[field])) goto done;
            } else {
                unsigned long long left, right;
                if (!decimal(v[field], field == 2 ? 8 : 10, &left) ||
                    !decimal((*found)->fields[field], field == 2 ? 8 : 10, &right) || left != right) goto done;
            }
        }
    }
    qsort(groups, group_count, sizeof *groups, row_group_order);
    for (i = 0; i < group_count;) {
        size_t end = i + 1, observed = group_count;
        char **first = groups[i]->fields;
        const char *anchor = !strcmp(first[0], "hardlink") ? first[12] : first[1];
        int drift = 0;
        while (end < group_count && !strcmp(first[11], groups[end]->fields[11])) ++end;
        for (j = i; j < end; ++j) {
            char **v = groups[j]->fields;
            const char *target = !strcmp(v[0], "hardlink") ? v[12] : v[1];
            if (strcmp(anchor, target)) goto done;
            if (groups[j]->checked != 1) continue;
            if (observed == group_count) observed = j;
            else if (groups[j]->observed.st_dev != groups[observed]->observed.st_dev ||
                     groups[j]->observed.st_ino != groups[observed]->observed.st_ino) drift = 1;
        }
        if (drift) for (j = i; j < end; ++j)
            if (groups[j]->checked == 1) groups[j]->checked = 0;
        i = end;
    }
    {
        size_t inodes = 0;
        for (i = 0; i < count; ++i)
            if (rows[i].checked == 1 && S_ISREG(rows[i].observed.st_mode)) paths[inodes++] = &rows[i];
        qsort(paths, inodes, sizeof *paths, row_inode_order);
        for (i = 0; i < inodes;) {
            size_t end = i + 1;
            const char *group = paths[i]->fields[11];
            int drift = 0;
            while (end < inodes && !row_inode_order(&paths[i], &paths[end])) ++end;
            for (j = i + 1; j < end; ++j)
                if (!strcmp(group, "-") || strcmp(group, paths[j]->fields[11])) drift = 1;
            if (drift) for (j = i; j < end; ++j) paths[j]->checked = 0;
            i = end;
        }
    }
    ok = 1;
done:
    free(paths); free(groups);
    return ok;
}

static int walk_manifest(int files_fd, int root, int mode,
                          holy_install_finding finding, void *context, const char *filter)
{
    struct stat st;
    struct manifest_row *rows = NULL;
    char *text = NULL;
    size_t length, used = 0, start = 0, i, line = 0, matches = 0, row_count = 0, capacity = 0;
    int result = -1;
    if (lseek(files_fd, 0, SEEK_SET) != 0 ||
        fstat(files_fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        st.st_size > 16 * 1024 * 1024) return -1;
    length = (size_t)st.st_size;
    text = malloc(length + 1);
    if (!text) return -1;
    while (used < length) {
        ssize_t got = read(files_fd, text + used, length - used);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) goto done;
        used += (size_t)got;
    }
    text[length] = '\0';
    for (i = 0; i <= length; ++i) {
        char **v = NULL, *error = NULL;
        size_t count = 0;
        if (i < length && text[i] != '\n') continue;
        ++line;
        if (memchr(text + start, '\0', i - start) ||
            !holy_lex(text + start, i - start, &v, &count, "installed/files", line, &error)) {
            free(error); holy_tokens_free(v, count); goto done;
        }
        start = i + 1;
        if (!count) { holy_tokens_free(v, count); continue; }
        if (count != ((!strcmp(v[0], "symlink") || !strcmp(v[0], "hardlink")) ? 13u : 12u)) {
            holy_tokens_free(v, count); goto done;
        }
        if (row_count == capacity) {
            size_t next_capacity = capacity ? capacity * 2 : 32;
            struct manifest_row *next;
            if (next_capacity < capacity || next_capacity > SIZE_MAX / sizeof *next) {
                holy_tokens_free(v, count); goto done;
            }
            next = realloc(rows, next_capacity * sizeof *next);
            if (!next) { holy_tokens_free(v, count); goto done; }
            rows = next; capacity = next_capacity;
        }
        memset(&rows[row_count], 0, sizeof *rows);
        rows[row_count].fields = v; rows[row_count].count = count;
        rows[row_count++].checked = 2;
    }
    {
        const char *group = NULL;
        if (filter) for (i = 0; i < row_count; ++i)
            if (!strcmp(filter, rows[i].fields[1]) && strcmp(rows[i].fields[11], "-"))
                group = rows[i].fields[11];
        for (i = 0; i < row_count; ++i) {
            struct manifest_row *row = &rows[i];
            if (filter && strcmp(filter, row->fields[1]) &&
                (!group || strcmp(group, row->fields[11]))) continue;
            row->checked = check_file(root, row->fields, &row->observed);
            if (row->checked < 0) goto done;
        }
    }
    if (!row_links(rows, row_count)) goto done;
    result = 1;
    for (i = 0; i < row_count; ++i) {
        struct manifest_row *row = &rows[i];
        char **v = row->fields;
        int checked = row->checked;
        if (filter && strcmp(filter, v[1])) continue;
        ++matches;
        if (checked == 2) {
            if (mode != 2 && mode != 3 && result == 1) result = 0;
            if (mode != 2 && mode != 3) report_changed(v[1], "missing-file");
        } else if (!checked) {
            report_changed(v[1], "changed-file");
            if (result == 1) result = 0;
        } else if ((mode == 1 || mode == 2) && strcmp(v[0], "dir")) {
            struct stat current;
            if (check_file(root, v, &current) != 1 ||
                current.st_dev != row->observed.st_dev || current.st_ino != row->observed.st_ino ||
                !remove_file(root, v[1], &current)) result = 0;
        }
        if (finding && (checked == 0 || checked == 2) &&
            !finding(context, v[1], checked == 2 ? "missing-file" : "changed-file", NULL)) result = -1;
        if (finding && checked == 1 && !strcmp(v[0], "file") &&
            (row->observed.st_mode & 0111)) {
            char *storage = NULL, *interpreter = NULL;
            const char *base;
            struct stat opened;
            int parent = parent_fd(root, v[1], &storage, &base), fd = -1;
            int script, status;
            if (parent < 0) { free(storage); result = -1; goto done; }
            fd = openat(parent, base, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
            if (fd < 0 || fstat(fd, &opened) ||
                opened.st_dev != row->observed.st_dev || opened.st_ino != row->observed.st_ino ||
                opened.st_size != row->observed.st_size || opened.st_mode != row->observed.st_mode) {
                if (fd >= 0) close(fd);
                close(parent); free(storage); result = -1; goto done;
            }
            script = holy_script_read_fd(fd, opened.st_size, opened.st_mode, &interpreter);
            close(fd); close(parent); free(storage);
            if (script < 0) { result = -1; goto done; }
            if (script) {
                const char *code;
                status = script == 3 ? -1 : holy_script_target_status(root, interpreter);
                if (script == 2 && status == 1) status = -1;
                code = status == 0 ? "missing-interpreter" :
                       status == -2 ? "unavailable-path-resolution" : "unknown-interpreter";
                if (status != 1) {
                    fprintf(stderr, "holypkg: %s consumer=%s interpreter=%s\n",
                            code, v[1], interpreter);
                    if (!finding(context, v[1], code, interpreter)) result = -1;
                    else if (result == 1) result = 0;
                }
            }
            free(interpreter);
        }
        if (result < 0 || (mode && result != 1)) goto done;
    }
    if (filter && matches != 1) result = -1;
done:
    for (i = 0; i < row_count; ++i) holy_tokens_free(rows[i].fields, rows[i].count);
    free(rows); free(text);
    return result;
}

int holy_install_check_manifest(int files_fd, int root)
{
    return walk_manifest(files_fd, root, 0, NULL, NULL, NULL);
}

int holy_install_check_report(int files_fd, int root,
                              holy_install_finding finding, void *context)
{
    return walk_manifest(files_fd, root, 0, finding, context, NULL);
}

int holy_install_check_path(int files_fd, int root, const char *path)
{
    return walk_manifest(files_fd, root, 0, NULL, NULL, path);
}

int holy_install_check_or_missing(int files_fd, int root)
{
    return walk_manifest(files_fd, root, 3, NULL, NULL, NULL);
}

int holy_install_remove_manifest(int files_fd, int root)
{
    if (holy_install_check_manifest(files_fd, root) != 1) return 0;
    return walk_manifest(files_fd, root, 1, NULL, NULL, NULL) == 1;
}

int holy_install_finish_remove_manifest(int files_fd, int root)
{
    if (walk_manifest(files_fd, root, 3, NULL, NULL, NULL) != 1) return 0;
    return walk_manifest(files_fd, root, 2, NULL, NULL, NULL) == 1;
}

static int manifest_claims(int files_fd, const char *path, int other)
{
    struct stat st;
    FILE *stream = NULL;
    char *line = NULL;
    size_t capacity = 0, number = 0;
    ssize_t length;
    int copy, found = 0;
    if (fstat(files_fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        st.st_size > 16 * 1024 * 1024 || lseek(files_fd, 0, SEEK_SET)) return -1;
    copy = dup(files_fd);
    if (copy < 0) return -1;
    stream = fdopen(copy, "r");
    if (!stream) { close(copy); return -1; }
    while ((length = getline(&line, &capacity, stream)) >= 0) {
        char **v = NULL, *error = NULL;
        size_t count = 0;
        ++number;
        if (memchr(line, '\0', (size_t)length) ||
            !holy_lex(line, (size_t)length, &v, &count,
                      "installed/files", number, &error)) {
            free(error);
            found = -1;
            break;
        }
        if (count) {
            if (count != ((!strcmp(v[0], "symlink") || !strcmp(v[0], "hardlink")) ? 13u : 12u) ||
                (strcmp(v[0], "file") && strcmp(v[0], "dir") &&
                 strcmp(v[0], "symlink") && strcmp(v[0], "hardlink")))
                found = -1;
            else if (other >= 0) {
                int kind = holy_install_manifest_owns(other, v[1]);
                if (kind < 0) found = -1;
                else if (kind && (kind == 1 || strcmp(v[0], "dir"))) found = 1;
            } else if (!strcmp(v[1], path)) {
                if (found) found = -1;
                else found = !strcmp(v[0], "dir") ? 2 : 1;
            }
        }
        holy_tokens_free(v, count);
        if (found < 0) break;
    }
    if (ferror(stream) || st.st_size != ftello(stream)) found = -1;
    free(line);
    fclose(stream);
    return found;
}

int holy_install_manifest_owns(int files_fd, const char *path)
{
    return manifest_claims(files_fd, path, -1);
}

static int manifest_executable_path(int files_fd, const char *path, unsigned int depth)
{
    struct stat st;
    FILE *stream = NULL;
    char *line = NULL, *link = NULL;
    size_t capacity = 0, number = 0;
    ssize_t length;
    int copy, found = 0, result = 0;
    if (depth == 16) return 0;
    if (fstat(files_fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        st.st_size > 16 * 1024 * 1024 || lseek(files_fd, 0, SEEK_SET)) return -1;
    copy = dup(files_fd);
    if (copy < 0) return -1;
    stream = fdopen(copy, "r");
    if (!stream) { close(copy); return -1; }
    while ((length = getline(&line, &capacity, stream)) >= 0) {
        char **v = NULL, *error = NULL;
        size_t count = 0;
        ++number;
        if (memchr(line, '\0', (size_t)length) ||
            !holy_lex(line, (size_t)length, &v, &count,
                      "installed/files", number, &error)) result = -1;
        free(error);
        if (result >= 0 && count) {
            int symlink = !strcmp(v[0], "symlink");
            int hardlink = !strcmp(v[0], "hardlink");
            if (count != (symlink || hardlink ? 13u : 12u) ||
                (strcmp(v[0], "file") && strcmp(v[0], "dir") &&
                 !symlink && !hardlink)) result = -1;
            else if (!strcmp(v[1], path)) {
                unsigned long long mode;
                if (found++) result = -1;
                else if (symlink) {
                    if (!holy_safe_link(v[1], v[12]) || !(link = strdup(v[12]))) result = -1;
                } else if (!strcmp(v[0], "file") || hardlink) {
                    if (!decimal(v[2], 8, &mode) || mode > 07777) result = -1;
                    else result = (mode & 0111) != 0;
                }
            }
        }
        holy_tokens_free(v, count);
        if (result < 0) break;
    }
    if (ferror(stream) || st.st_size != ftello(stream)) result = -1;
    free(line);
    fclose(stream);
    if (result >= 0 && link) {
        char *next = holy_relative_link_path(path, strlen(path), link, "");
        result = next ? manifest_executable_path(files_fd, next, depth + 1) : -1;
        free(next);
    }
    free(link);
    return result;
}

int holy_install_manifest_executable(int files_fd, const char *path)
{
    if (!path || !*path || *path == '/') return -1;
    return manifest_executable_path(files_fd, path, 0);
}

int holy_install_manifests_conflict(int left_fd, int right_fd)
{
    return manifest_claims(left_fd, NULL, right_fd);
}

static int transition_entry_valid(const struct holy_manifest_entry *entry)
{
    return entry && entry->path && entry->path[0] && entry->path[0] != '/' &&
           entry->path[strlen(entry->path) - 1] != '/' &&
           !entry->directory && !(entry->link && (entry->hardlink || entry->group)) &&
           !(entry->mode & ~07777u) &&
           (!(entry->mode & 07000) ||
            ((entry->mode & 07000) == 04000 && (entry->mode & 0111) &&
             !entry->link && !entry->hardlink && !entry->group)) &&
           entry->uid == (long long)geteuid() &&
           entry->gid == (long long)getegid() && entry->size >= 0 &&
           (entry->link ? entry->mode == 0777 && !entry->size &&
                          entry->link[0] != '/' && holy_safe_link(entry->path, entry->link) :
                          entry->hash != NULL);
}

static int transition_matches(int root, const struct holy_manifest_entry *entry,
                               struct stat *observed)
{
    char numbers[4][32], hash[65], *v[13];
    size_t i;
    if (!entry || !entry->path || (entry->directory != 0 && entry->directory != 1) ||
        (entry->directory && (entry->link || entry->hardlink || entry->group)) ||
        (!entry->directory && !entry->link && !entry->hash)) return -1;
    snprintf(numbers[0], sizeof numbers[0], "%o", entry->mode);
    snprintf(numbers[1], sizeof numbers[1], "%lld", entry->uid);
    snprintf(numbers[2], sizeof numbers[2], "%lld", entry->gid);
    snprintf(numbers[3], sizeof numbers[3], "%lld", entry->size);
    if (!entry->link && !entry->directory) for (i = 0; i < 32; ++i)
        snprintf(hash + i * 2, 3, "%02x", entry->hash[i]);
    v[0] = entry->directory ? "dir" : entry->link ? "symlink" : entry->hardlink ? "hardlink" : "file";
    v[1] = (char *)entry->path; v[2] = numbers[0]; v[3] = v[4] = "-";
    v[5] = numbers[1]; v[6] = numbers[2]; v[7] = numbers[3];
    v[8] = entry->link || entry->directory ? "-" : hash; v[9] = "none"; v[10] = "-"; v[11] = entry->group ? (char *)entry->group : "-";
    v[12] = (char *)(entry->link ? entry->link : entry->hardlink);
    return check_file(root, v, observed);
}

static int transition_absent(int root, const char *path)
{
    char *storage = NULL;
    const char *base;
    struct stat st;
    int parent = parent_fd(root, path, &storage, &base), absent = 0;
    if (parent >= 0) {
        absent = fstatat(parent, base, &st, AT_SYMLINK_NOFOLLOW) && errno == ENOENT;
        close(parent);
    } else absent = errno == ENOENT;
    free(storage);
    return absent;
}

int holy_install_check_entry(int root, const struct holy_manifest_entry *entry)
{
    struct stat observed, target;
    char *storage = NULL;
    const char *base;
    int parent, result = transition_matches(root, entry, &observed);
    if (result != 1 || !entry->hardlink) return result;
    parent = parent_fd(root, entry->hardlink, &storage, &base);
    result = parent >= 0 && !fstatat(parent, base, &target, AT_SYMLINK_NOFOLLOW) &&
             S_ISREG(target.st_mode) && target.st_dev == observed.st_dev && target.st_ino == observed.st_ino;
    if (parent >= 0) close(parent);
    free(storage);
    return result;
}

static char *transition_temporary(const char *path, const char *name)
{
    const char *slash = strrchr(path, '/'), *base = slash ? slash + 1 : path;
    size_t prefix = slash ? (size_t)(slash - path + 1) : 0, length;
    char *result;
    if (!name || strncmp(name, ".holy-update-", 13) || !name[13] ||
        strchr(name, '/') || !strcmp(base, name)) return NULL;
    length = strlen(name);
    if (length > (size_t)-1 - prefix - 1) return NULL;
    result = malloc(prefix + length + 1);
    if (result) { memcpy(result, path, prefix); memcpy(result + prefix, name, length + 1); }
    return result;
}

int holy_install_entry_state(int root, const struct holy_manifest_entry *entry,
                              const char *temporary, struct stat *observed)
{
    struct holy_manifest_entry staged;
    char *path;
    int result;
    if (!temporary) return transition_matches(root, entry, observed);
    if (!transition_entry_valid(entry) || !(path = transition_temporary(entry->path, temporary))) return -1;
    staged = *entry; staged.path = path;
    result = transition_matches(root, &staged, observed);
    free(path);
    return result;
}

int holy_install_prepare_link(int root, const struct holy_manifest_entry *next,
    const char *temporary, const struct holy_manifest_entry *source,
    const char *source_temporary, int recovering)
{
    struct holy_manifest_entry staged;
    char *path = NULL, *from = NULL;
    int ok = 0;
    if (!transition_entry_valid(next) || next->link || !source || source->link ||
        !(path = transition_temporary(next->path, temporary))) goto done;
    from = source_temporary ? transition_temporary(source->path, source_temporary) : strdup(source->path);
    if (!from) goto done;
    staged = *next; staged.path = path;
    ok = link_payload(root, from, &staged, recovering);
done:
    free(path); free(from);
    return ok;
}

int holy_install_remove_temporary(int root, const struct holy_manifest_entry *entry,
                                   const char *temporary)
{
    struct stat observed;
    char *path;
    int state = holy_install_entry_state(root, entry, temporary, &observed), ok;
    if (state == 2) return 1;
    if (state != 1 || !(path = transition_temporary(entry->path, temporary))) return 0;
    ok = remove_file(root, path, &observed);
    free(path);
    return ok;
}

int holy_install_transition_check(int root, const struct holy_manifest_entry *before,
                                  const struct holy_manifest_entry *after, int recovering)
{
    const char *path;
    if ((!before && !after) || (before && !transition_entry_valid(before)) ||
        (after && !transition_entry_valid(after)) ||
        (before && after && strcmp(before->path, after->path))) return 0;
    path = before ? before->path : after->path;
    if (before ? transition_matches(root, before, NULL) == 1 : transition_absent(root, path)) return 1;
    return recovering && (after ? transition_matches(root, after, NULL) == 1 : transition_absent(root, path));
}

int holy_install_prepare_file(int root, const struct holy_manifest_entry *next,
                              int content_fd, const char *temporary)
{
    struct holy_manifest_entry staged;
    char *path = NULL, *storage = NULL;
    const char *base;
    char buffer[65536];
    struct stat input;
    int parent = -1, fd = -1, created = 0, ok = 0;
    long long offset = 0;
    if (!transition_entry_valid(next) || next->hardlink || !(path = transition_temporary(next->path, temporary))) goto done;
    staged = *next; staged.path = path;
    parent = parent_fd(root, path, &storage, &base);
    if (parent < 0) goto done;
    if (next->link) {
        if (symlinkat(next->link, parent, base)) goto done;
        created = 1;
    } else {
        if (fstat(content_fd, &input) || !S_ISREG(input.st_mode) || input.st_size != next->size) goto done;
        fd = openat(parent, base, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) goto done;
        created = 1;
        while (offset < next->size) {
            size_t used = 0, amount = (unsigned long long)(next->size - offset) < sizeof buffer ?
                                     (size_t)(next->size - offset) : sizeof buffer;
            ssize_t got = pread(content_fd, buffer, amount, (off_t)offset);
            if (got < 0 && errno == EINTR) continue;
            if (got <= 0) goto done;
            while (used < (size_t)got) {
                ssize_t sent = write(fd, buffer + used, (size_t)got - used);
                if (sent < 0 && errno == EINTR) continue;
                if (sent <= 0) goto done;
                used += (size_t)sent;
            }
            offset += got;
        }
        if (fchmod(fd, next->mode) || fsync(fd)) goto done;
    }
    if (transition_matches(root, &staged, NULL) != 1 || fsync(parent)) goto done;
    ok = 1;
done:
    if (fd >= 0) close(fd);
    if (!ok && created) { unlinkat(parent, base, 0); fsync(parent); }
    if (parent >= 0) close(parent);
    free(storage); free(path);
    return ok;
}

int holy_install_temporary_state(int root, const struct holy_manifest_entry *next,
                                 const char *temporary)
{
    struct holy_manifest_entry staged;
    char *path;
    int result;
    if (!transition_entry_valid(next) || !(path = transition_temporary(next->path, temporary))) return 0;
    staged = *next; staged.path = path;
    result = transition_matches(root, &staged, NULL);
    free(path);
    return result < 0 ? 0 : result;
}


int holy_install_transition(int root, const struct holy_manifest_entry *before,
                            const struct holy_manifest_entry *after, const char *temporary)
{
    struct holy_manifest_entry staged;
    struct stat original, ready, current;
    char *path = NULL, *storage = NULL;
    const char *target = before ? before->path : after ? after->path : NULL, *base;
    int parent = -1, ready_state, completed, ok = 0;
    if (!holy_install_transition_check(root, before, after, 1)) return 0;
    parent = parent_fd(root, target, &storage, &base);
    if (parent < 0) goto done;
    if (!after) {
        if (transition_absent(root, target)) ok = !fsync(parent);
        else if (transition_matches(root, before, &original) == 1) ok = remove_file(root, target, &original);
        goto done;
    }
    path = transition_temporary(target, temporary);
    if (!path) goto done;
    staged = *after; staged.path = path;
    completed = transition_matches(root, after, NULL) == 1;
    ready_state = transition_matches(root, &staged, &ready);
    if (completed && ready_state == 1 &&
        (after->group || (before && (before->group || before->hardlink)))) {
        struct stat published;
        if (transition_matches(root, after, &published) != 1) goto done;
        if (published.st_dev != ready.st_dev || published.st_ino != ready.st_ino) completed = 0;
    }
    if (completed) {
        if (ready_state == 2) ok = !fsync(parent);
        else if (ready_state == 1) ok = remove_file(root, path, &ready);
        goto done;
    }
    if (ready_state != 1 || (before && transition_matches(root, before, &original) != 1)) goto done;
    if (fstatat(parent, temporary, &current, AT_SYMLINK_NOFOLLOW) || !same_object(&ready, &current)) goto done;
    if (before) {
        if (fstatat(parent, base, &current, AT_SYMLINK_NOFOLLOW) || !same_object(&original, &current)) goto done;
        if (renameat(parent, temporary, parent, base)) {
            perror("holypkg: replace update payload");
            goto done;
        }
    } else {
#ifdef SYS_renameat2
        /* rename_noreplace also works on filesystems without hard links. */
        if (syscall(SYS_renameat2, parent, temporary, parent, base, 1u)) {
            if (errno == ENOSYS || errno == EINVAL || errno == EOPNOTSUPP)
                fputs("holypkg: renameat2(RENAME_NOREPLACE) unavailable\n", stderr);
            goto done;
        }
#else
        errno = ENOSYS;
        fputs("holypkg: renameat2(RENAME_NOREPLACE) unavailable\n", stderr);
        goto done;
#endif
    }
    ok = !fsync(parent);
done:
    if (parent >= 0) close(parent);
    free(storage); free(path);
    return ok;
}
