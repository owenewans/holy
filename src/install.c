#define _POSIX_C_SOURCE 200809L
#include "install.h"
#include "verify.h"

#include <archive.h>
#include <archive_entry.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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
        if (!*cursor || !strcmp(cursor, ".") || !strcmp(cursor, "..")) goto fail;
        next = openat(current, cursor, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0 || fstat(next, &st) || !S_ISDIR(st.st_mode) ||
            (st.st_uid != 0 && st.st_uid != geteuid()) ||
            (st.st_mode & 0022)) {
            if (next >= 0) close(next);
            goto fail;
        }
        close(current);
        current = next;
        cursor = slash + 1;
    }
    if (!*cursor || !strcmp(cursor, ".") || !strcmp(cursor, "..")) goto fail;
    *base = cursor;
    return current;
fail:
    if (current >= 0) close(current);
    free(*storage);
    *storage = NULL;
    return -1;
}

struct root_check {
    int root;
};

static int check_entry(void *context, const struct holy_manifest_entry *entry)
{
    struct root_check *check = context;
    char *storage = NULL;
    const char *base;
    struct stat st;
    int parent, ok = 0;
    if (entry->link || entry->hardlink || entry->group ||
        (entry->mode & 07000) ||
        (!entry->directory && (entry->mode & 0111)) ||
        entry->uid != (long long)geteuid() ||
        entry->gid != (long long)getegid()) return 0;
    parent = parent_fd(check->root, entry->path, &storage, &base);
    if (parent < 0) return 0;
    if (!fstatat(parent, base, &st, AT_SYMLINK_NOFOLLOW))
        ok = entry->directory && S_ISDIR(st.st_mode) &&
             (st.st_uid == 0 || st.st_uid == geteuid()) && !(st.st_mode & 0022);
    else ok = errno == ENOENT && !entry->directory;
    close(parent);
    free(storage);
    return ok;
}

int holy_install_preflight(const char *snapshot, int root)
{
    struct root_check check = { root };
    if (!holy_verify_visit(snapshot, check_entry, &check)) {
        fprintf(stderr, "holypkg: install requires existing safe directories and new ordinary files\n");
        return 0;
    }
    return 1;
}

int holy_install_payload(const char *snapshot, int root)
{
    struct archive *archive = archive_read_new();
    struct archive_entry *entry;
    char buffer[65536];
    int status, ok = 0;
    if (!archive) return 0;
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
            archive_entry_filetype(entry) == AE_IFDIR) {
            if (archive_read_data_skip(archive) != ARCHIVE_OK) goto done;
            continue;
        }
        if (archive_entry_filetype(entry) != AE_IFREG ||
            archive_entry_hardlink(entry) || archive_entry_size(entry) < 0) goto done;
        parent = parent_fd(root, path + 5, &storage, &base);
        if (parent < 0) goto done;
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
            fchmod(fd, archive_entry_perm(entry) & 0777) || fsync(fd) ||
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
    ok = status == ARCHIVE_EOF;
done:
    archive_read_free(archive);
    if (!ok) fprintf(stderr, "holypkg: install payload incomplete; inspect transaction journal\n");
    return ok;
}
