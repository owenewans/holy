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
    mode_t type = archive_entry_filetype(entry);
    if (!holy_safe_archive_path(name) || archive_entry_hardlink(entry) ||
        (type != AE_IFDIR && type != AE_IFREG) || archive_entry_size(entry) < 0)
        return 0;
    if (type == AE_IFDIR && archive_entry_size(entry) != 0) return 0;
    if (type == AE_IFREG && name[strlen(name) - 1] == '/') return 0;
    return 1;
}

static int preflight(const char *source)
{
    struct archive *a = reader(source);
    struct archive_entry *entry;
    int status, ok = 1;
    if (!a) { fprintf(stderr, "holypkg: archive open failed\n"); return 0; }
    while ((status = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        if (!supported(entry)) { ok = 0; break; }
        if (archive_read_data_skip(a) != ARCHIVE_OK) { ok = 0; break; }
    }
    if (status != ARCHIVE_EOF) ok = 0;
    archive_read_free(a);
    if (!ok) fprintf(stderr, "holypkg: unsupported or damaged extraction input\n");
    return ok;
}

static int directory(int root, const char *path)
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
        if (mkdirat(current, component, 0700) && errno != EEXIST) goto done;
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
        parent = directory(root, path);
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

int holy_extract_local(const char *source, const char *output)
{
    struct archive *a = NULL;
    struct archive_entry *entry;
    char *snapshot = stage(source);
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
        int parent;
        if (!supported(entry)) goto done;
        if (archive_entry_filetype(entry) == AE_IFDIR) {
            parent = directory(root, name);
            if (parent < 0) goto done;
            if (parent != root) close(parent);
        } else if (!write_file(root, name, a, entry)) goto done;
    }
    if (status != ARCHIVE_EOF || fsync(root)) goto done;
    printf("extracted %s\n", output);
    ok = 1;
done:
    if (!ok && created)
        fprintf(stderr, "holypkg: extraction failed; inspect partial output: %s\n", output);
    if (a) archive_read_free(a);
    if (root >= 0) close(root);
    unlink(snapshot);
    free(snapshot);
    return ok;
}
