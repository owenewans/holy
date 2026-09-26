#define _POSIX_C_SOURCE 200809L
#include "extract.h"
#include "package.h"
#include "verify.h"

#include <archive.h>
#include <archive_entry.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct pending_link {
    char *name;
    char *target;
};

struct archive_path {
    char *name;
    int blocks_children;
};

static int compare_paths(const void *left, const void *right)
{
    const struct archive_path *a = left, *b = right;
    return strcmp(a->name, b->name);
}

static int path_conflicts(struct archive_path *paths, size_t count)
{
    size_t i;
    qsort(paths, count, sizeof *paths, compare_paths);
    for (i = 0; i < count; ++i) {
        size_t low, high, len;
        char *prefix;
        if (i && !strcmp(paths[i - 1].name, paths[i].name)) return 1;
        if (!paths[i].blocks_children) continue;
        len = strlen(paths[i].name);
        if (len > (size_t)-1 - 2) return 1;
        prefix = malloc(len + 2);
        if (!prefix) return 1;
        memcpy(prefix, paths[i].name, len);
        prefix[len] = '/';
        prefix[len + 1] = '\0';
        low = 0;
        high = count;
        while (low < high) {
            size_t middle = low + (high - low) / 2;
            if (strcmp(paths[middle].name, prefix) < 0) low = middle + 1;
            else high = middle;
        }
        free(prefix);
        if (low < count && !strncmp(paths[low].name, paths[i].name, len) &&
            paths[low].name[len] == '/') return 1;
    }
    return 0;
}

static struct archive *reader(const char *source)
{
    struct archive *a = archive_read_new();
    if (!a) return NULL;
    if (archive_read_support_filter_lz4(a) != ARCHIVE_OK ||
        archive_read_support_format_tar(a) != ARCHIVE_OK ||
        archive_read_open_filename(a, source, 8192) != ARCHIVE_OK) {
        archive_read_free(a);
        return NULL;
    }
    return a;
}

static char *stage(const char *source)
{
    const char *base = geteuid() ? getenv("TMPDIR") : NULL;
    const char *suffix = "/holy-extract-XXXXXX";
    char *path = NULL;
    char buffer[65536];
    struct stat st;
    int input = -1, output = -1;
    ssize_t got;
    size_t length;
    int ok = 0;
    if (!base || !*base) base = "/tmp";
    if (strlen(base) > (size_t)-1 - strlen(suffix) - 1) return NULL;
    length = strlen(base) + strlen(suffix) + 1;
    path = malloc(length);
    if (!path) return NULL;
    snprintf(path, length, "%s%s", base, suffix);
    input = open(source, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (input < 0 || fstat(input, &st) || !S_ISREG(st.st_mode)) goto done;
    output = mkstemp(path);
    if (output < 0) goto done;
    while ((got = read(input, buffer, sizeof buffer)) != 0) {
        size_t written = 0;
        if (got < 0) {
            if (errno == EINTR) continue;
            goto done;
        }
        while (written < (size_t)got) {
            ssize_t sent = write(output, buffer + written, (size_t)got - written);
            if (sent < 0 && errno == EINTR) continue;
            if (sent <= 0) goto done;
            written += (size_t)sent;
        }
    }
    if (fsync(output)) goto done;
    ok = 1;
done:
    if (output >= 0) close(output);
    if (input >= 0) close(input);
    if (!ok) { if (output >= 0) unlink(path); free(path); path = NULL; }
    return path;
}

static int supported(struct archive_entry *entry)
{
    const char *name = archive_entry_pathname(entry);
    const char *target = archive_entry_hardlink(entry);
    mode_t type = archive_entry_filetype(entry);
    if (!holy_safe_archive_path(name) || archive_entry_size(entry) < 0 ||
        archive_entry_xattr_count(entry) > 0 || archive_entry_acl_types(entry))
        return 0;
    if (target) {
        if ((type != AE_IFREG && type != 0) ||
            strncmp(name, "DATA/", 5) || !name[5] ||
            !holy_safe_archive_path(target) || strncmp(target, "DATA/", 5) ||
            !target[5] || archive_entry_size(entry) != 0) return 0;
    } else if (type == AE_IFLNK) {
        const char *destination = archive_entry_symlink(entry);
        if (strncmp(name, "DATA/", 5) || !name[5] ||
            !destination || !*destination || destination[0] == '/' ||
            archive_entry_size(entry) != 0) return 0;
    } else if (type != AE_IFDIR && type != AE_IFREG) return 0;
    if (type == AE_IFDIR && archive_entry_size(entry) != 0) return 0;
    if (type != AE_IFDIR && name[strlen(name) - 1] == '/') return 0;
    return 1;
}

static int preflight(const char *source)
{
    struct archive *a = reader(source);
    struct archive_entry *entry;
    struct archive_path *paths = NULL;
    size_t count = 0, i;
    int status, ok = 1;
    if (!a) { fprintf(stderr, "holypkg: archive open failed\n"); return 0; }
    while ((status = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        struct archive_path *next;
        size_t length;
        if (!supported(entry)) { ok = 0; break; }
        if (count == (size_t)-1 / sizeof *paths) { ok = 0; break; }
        next = realloc(paths, (count + 1) * sizeof *paths);
        if (!next) { ok = 0; break; }
        paths = next;
        paths[count].name = strdup(archive_entry_pathname(entry));
        if (!paths[count].name) { ok = 0; break; }
        length = strlen(paths[count].name);
        if (length > 1 && paths[count].name[length - 1] == '/')
            paths[count].name[length - 1] = '\0';
        paths[count].blocks_children = archive_entry_filetype(entry) != AE_IFDIR;
        ++count;
        if (archive_read_data_skip(a) != ARCHIVE_OK) { ok = 0; break; }
    }
    if (status != ARCHIVE_EOF || (ok && path_conflicts(paths, count))) ok = 0;
    for (i = 0; i < count; ++i) free(paths[i].name);
    free(paths);
    archive_read_free(a);
    if (!ok) fprintf(stderr, "holypkg: unsupported or damaged extraction input\n");
    return ok;
}

static int directory(int root, const char *path, int create)
{
    char *parts = strdup(path), *cursor, *component, *slash;
    int current = root, next, ok = 0;
    if (!parts) return -1;
    cursor = parts;
    while (*cursor) {
        while (*cursor == '/') ++cursor;
        if (!*cursor) break;
        component = cursor;
        slash = strchr(cursor, '/');
        if (slash) *slash = '\0';
        if (create && mkdirat(current, component, 0700) && errno != EEXIST) goto done;
        next = openat(current, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) goto done;
        if (current != root) close(current);
        current = next;
        cursor = slash ? slash + 1 : component + strlen(component);
    }
    ok = 1;
done:
    free(parts);
    if (!ok && current != root) close(current);
    return ok ? current : -1;
}

static int write_file(int root, const char *name, struct archive *a,
                      struct archive_entry *entry)
{
    char *path = strdup(name), *last;
    char buffer[65536];
    int parent = root, fd = -1, ok = 0;
    la_ssize_t got;
    la_int64_t total = 0;
    if (!path) return 0;
    last = strrchr(path, '/');
    if (last) {
        *last++ = '\0';
        parent = directory(root, path, 1);
    } else last = path;
    if (parent < 0 || !*last) goto done;
    fd = openat(parent, last, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) goto done;
    while ((got = archive_read_data(a, buffer, sizeof buffer)) > 0) {
        size_t written = 0;
        if (total > archive_entry_size(entry) - got) goto done;
        total += got;
        while (written < (size_t)got) {
            ssize_t sent = write(fd, buffer + written, (size_t)got - written);
            if (sent < 0 && errno == EINTR) continue;
            if (sent <= 0) goto done;
            written += (size_t)sent;
        }
    }
    if (got < 0 || total != archive_entry_size(entry) ||
        fchmod(fd, archive_entry_perm(entry) & 0777) || fsync(fd)) goto done;
    ok = 1;
done:
    if (fd >= 0) close(fd);
    if (parent != root && parent >= 0) close(parent);
    free(path);
    return ok;
}

static int parent_for(int root, const char *name, int create,
                      char **storage, const char **base)
{
    char *slash;
    int parent;
    *storage = strdup(name);
    if (!*storage) return -1;
    slash = strrchr(*storage, '/');
    if (!slash || !slash[1]) { free(*storage); *storage = NULL; return -1; }
    *slash++ = '\0';
    parent = directory(root, *storage, create);
    if (parent < 0) { free(*storage); *storage = NULL; return -1; }
    *base = slash;
    return parent;
}

static int write_symlink(int root, const char *name, const char *target)
{
    char *path = NULL;
    const char *base;
    int parent = parent_for(root, name, 1, &path, &base), ok = 0;
    if (parent < 0) return 0;
    ok = symlinkat(target, parent, base) == 0;
    if (parent != root) close(parent);
    free(path);
    return ok;
}

static int write_hardlink(int root, const char *name, const char *target)
{
    char *from = NULL, *to = NULL;
    const char *source_name, *dest_name;
    struct stat st;
    int source_parent, dest_parent = -1, ok = 0;
    source_parent = parent_for(root, target, 0, &from, &source_name);
    if (source_parent < 0) return 0;
    dest_parent = parent_for(root, name, 1, &to, &dest_name);
    if (dest_parent >= 0 &&
        !fstatat(source_parent, source_name, &st, AT_SYMLINK_NOFOLLOW) &&
        S_ISREG(st.st_mode) &&
        !linkat(source_parent, source_name, dest_parent, dest_name, 0)) ok = 1;
    if (source_parent != root) close(source_parent);
    if (dest_parent >= 0 && dest_parent != root) close(dest_parent);
    free(from);
    free(to);
    return ok;
}

int holy_extract_local(const char *source, const char *output)
{
    struct archive *a = NULL;
    struct archive_entry *entry;
    struct pending_link *links = NULL;
    char *snapshot = stage(source);
    size_t link_count = 0, i;
    int root = -1, status, ok = 0, created = 0;
    if (!snapshot) {
        fprintf(stderr, "holypkg: could not stage regular local input\n");
        return 0;
    }
    if (!holy_verify(snapshot) || !preflight(snapshot)) goto done;
    if (mkdir(output, 0700)) {
        perror("holypkg: create extraction directory");
        goto done;
    }
    created = 1;
    root = open(output, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    a = reader(snapshot);
    if (root < 0 || !a) goto done;
    while ((status = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        const char *name = archive_entry_pathname(entry);
        const char *target = archive_entry_hardlink(entry);
        int parent;
        if (!supported(entry)) goto done;
        if (target) {
            struct pending_link *next;
            if (link_count == (size_t)-1 / sizeof *links) goto done;
            next = realloc(links, (link_count + 1) * sizeof *links);
            if (!next) goto done;
            links = next;
            links[link_count].name = strdup(name);
            links[link_count].target = strdup(target);
            if (!links[link_count].name || !links[link_count].target) {
                free(links[link_count].name);
                free(links[link_count].target);
                goto done;
            }
            ++link_count;
            if (archive_read_data_skip(a) != ARCHIVE_OK) goto done;
        } else if (archive_entry_filetype(entry) == AE_IFLNK) {
            if (!write_symlink(root, name, archive_entry_symlink(entry)) ||
                archive_read_data_skip(a) != ARCHIVE_OK) goto done;
        } else if (archive_entry_filetype(entry) == AE_IFDIR) {
            parent = directory(root, name, 1);
            if (parent < 0) goto done;
            if (parent != root) close(parent);
        } else if (!write_file(root, name, a, entry)) goto done;
    }
    if (status != ARCHIVE_EOF) goto done;
    for (i = 0; i < link_count; ++i)
        if (!write_hardlink(root, links[i].name, links[i].target)) goto done;
    if (fsync(root)) goto done;
    printf("extracted %s\n", output);
    ok = 1;
done:
    if (!ok && created)
        fprintf(stderr, "holypkg: extraction failed; inspect partial output: %s\n", output);
    if (a) archive_read_free(a);
    if (root >= 0) close(root);
    for (i = 0; i < link_count; ++i) {
        free(links[i].name);
        free(links[i].target);
    }
    free(links);
    unlink(snapshot);
    free(snapshot);
    return ok;
}
