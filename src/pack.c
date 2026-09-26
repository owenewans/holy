#define _POSIX_C_SOURCE 200809L
#include "pack.h"
#include "verify.h"
#include "scan.h"
#include "deps.h"
#include "provides.h"

#include <archive.h>
#include <archive_entry.h>
#include <openssl/evp.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

struct writer {
    struct archive *archive;
    FILE *manifest;
};

static int write_manifest_path(FILE *file, const char *path)
{
    const unsigned char *p = (const unsigned char *)path;
    if (fputc('"', file) == EOF) return 0;
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') {
            if (fputc('\\', file) == EOF || fputc(*p, file) == EOF) return 0;
        } else if (*p < 0x21 || *p >= 0x7f) {
            if (fprintf(file, "\\x%02x", (unsigned)*p) < 0) return 0;
        } else if (fputc(*p, file) == EOF) return 0;
    }
    return fputc('"', file) != EOF;
}

static int write_entry(struct writer *writer, int parent, const char *name,
                       const char *archive_path, int directory)
{
    struct archive_entry *entry = NULL;
    struct stat st, original;
    char buffer[65536];
    EVP_MD_CTX *hash = NULL;
    unsigned char digest[32];
    unsigned int digest_size;
    int fd = -1, ok = 0;
    ssize_t got;
    fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC |
                (directory ? O_DIRECTORY : O_NONBLOCK));
    if (fd < 0 || fstat(fd, &st) ||
        (directory ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode)) ||
        (!directory && (st.st_nlink != 1 || st.st_size < 0)) ||
        flistxattr(fd, NULL, 0) != 0) goto done;
    original = st;
    if (writer->archive) {
        entry = archive_entry_new();
        if (!entry) goto done;
        archive_entry_set_pathname(entry, archive_path);
        archive_entry_set_filetype(entry, directory ? AE_IFDIR : AE_IFREG);
        archive_entry_set_perm(entry, st.st_mode & 07777);
        archive_entry_set_uid(entry, st.st_uid);
        archive_entry_set_gid(entry, st.st_gid);
        archive_entry_set_mtime(entry, 0, 0);
        archive_entry_set_size(entry, directory ? 0 : st.st_size);
        if (archive_write_header(writer->archive, entry) != ARCHIVE_OK) goto done;
    }
    if (writer->manifest && !directory) {
        hash = EVP_MD_CTX_new();
        if (!hash || EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1) goto done;
    }
    if (!directory) {
        off_t offset = 0;
        while (offset < st.st_size) {
            size_t want = st.st_size - offset < (off_t)sizeof buffer ?
                          (size_t)(st.st_size - offset) : sizeof buffer;
            got = read(fd, buffer, want);
            if (got < 0 && errno == EINTR) continue;
            if (got <= 0 || (writer->archive &&
                archive_write_data(writer->archive, buffer, (size_t)got) != got) ||
                (hash && EVP_DigestUpdate(hash, buffer, (size_t)got) != 1)) goto done;
            offset += got;
        }
        if (fstat(fd, &st) || st.st_size != offset ||
            st.st_dev != original.st_dev || st.st_ino != original.st_ino ||
            st.st_mode != original.st_mode || st.st_uid != original.st_uid ||
            st.st_gid != original.st_gid ||
            st.st_mtim.tv_sec != original.st_mtim.tv_sec ||
            st.st_mtim.tv_nsec != original.st_mtim.tv_nsec) goto done;
        if (hash && (EVP_DigestFinal_ex(hash, digest, &digest_size) != 1 ||
                     digest_size != sizeof digest)) goto done;
    }
    if (writer->manifest) {
        size_t i;
        if (fprintf(writer->manifest, "%s ", directory ? "dir" : "file") < 0 ||
            !write_manifest_path(writer->manifest, archive_path + 5) ||
            fprintf(writer->manifest, " %o - - %lu %lu %lld ",
                    (unsigned)(st.st_mode & 07777), (unsigned long)st.st_uid,
                    (unsigned long)st.st_gid, directory ? 0LL : (long long)st.st_size) < 0)
            goto done;
        if (directory) {
            if (fputs("-", writer->manifest) == EOF) goto done;
        } else for (i = 0; i < sizeof digest; ++i)
            if (fprintf(writer->manifest, "%02x", (unsigned)digest[i]) < 0) goto done;
        if (fputs(" none - -\n", writer->manifest) == EOF) goto done;
    }
    ok = 1;
done:
    archive_entry_free(entry);
    EVP_MD_CTX_free(hash);
    if (fd >= 0) close(fd);
    if (!ok) fprintf(stderr, "holypkg: cannot pack %s: %s\n", archive_path,
                     writer->archive && archive_error_string(writer->archive) ?
                     archive_error_string(writer->archive) : "unsupported input");
    return ok;
}

static int exact_members(int dir, const char *const *names, size_t count)
{
    int copy = dup(dir);
    DIR *list;
    struct dirent *entry;
    unsigned seen = 0;
    size_t i;
    int ok = 1;
    if (copy < 0) return 0;
    list = fdopendir(copy);
    if (!list) { close(copy); return 0; }
    if (count >= sizeof seen * 8) { closedir(list); return 0; }
    errno = 0;
    while ((entry = readdir(list))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        for (i = 0; i < count; ++i)
            if (!strcmp(entry->d_name, names[i])) break;
        if (i == count || (seen & (1u << i))) { ok = 0; break; }
        seen |= 1u << i;
        errno = 0;
    }
    if (!entry && errno) ok = 0;
    if (seen != (1u << count) - 1u) ok = 0;
    closedir(list);
    return ok;
}

static int compare_names(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static int outside_tree(int root, const char *output)
{
    const char *slash = strrchr(output, '/');
    char *parent = slash ? strndup(output, slash == output ? 1 :
                                    (size_t)(slash - output)) : strdup(".");
    struct stat source, current, above;
    int dir = -1, ok = 0;
    unsigned depth;
    if (!parent || fstat(root, &source)) goto done;
    dir = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir < 0) goto done;
    for (depth = 0; depth < 256; ++depth) {
        int next;
        if (fstat(dir, &current)) goto done;
        if (current.st_dev == source.st_dev && current.st_ino == source.st_ino)
            goto done;
        next = openat(dir, "..", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (next < 0) goto done;
        if (fstat(next, &above)) { close(next); goto done; }
        close(dir);
        dir = next;
        if (above.st_dev == current.st_dev && above.st_ino == current.st_ino) {
            ok = 1;
            goto done;
        }
    }
done:
    if (dir >= 0) close(dir);
    free(parent);
    return ok;
}

static int sync_parent(const char *output)
{
    const char *slash = strrchr(output, '/');
    char *parent = slash ? strndup(output, slash == output ? 1 :
                                    (size_t)(slash - output)) : strdup(".");
    int dir, ok;
    if (!parent) return 0;
    dir = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    free(parent);
    if (dir < 0) return 0;
    ok = !fsync(dir);
    close(dir);
    return ok;
}

static int walk_data(struct writer *writer, int parent, const char *relative,
                     const char *archive_prefix, unsigned depth)
{
    int dir = -1, scan = -1, ok = 0;
    DIR *list = NULL;
    struct dirent *item;
    char **names = NULL;
    size_t count = 0, capacity = 0, i;
    if (depth > 128) return 0;
    dir = openat(parent, relative, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || flistxattr(dir, NULL, 0) != 0) goto done;
    scan = dup(dir);
    if (scan < 0 || !(list = fdopendir(scan))) goto done;
    scan = -1;
    errno = 0;
    while ((item = readdir(list))) {
        char **grown;
        if (!strcmp(item->d_name, ".") || !strcmp(item->d_name, "..")) continue;
        if (count == capacity) {
            size_t next = capacity ? capacity * 2 : 16;
            if (next < capacity || next > SIZE_MAX / sizeof *names) goto done;
            grown = realloc(names, next * sizeof *names);
            if (!grown) goto done;
            names = grown;
            capacity = next;
        }
        names[count] = strdup(item->d_name);
        if (!names[count]) goto done;
        ++count;
        errno = 0;
    }
    if (errno) goto done;
    if (count) qsort(names, count, sizeof *names, compare_names);
    for (i = 0; i < count; ++i) {
        char *path;
        struct stat st;
        size_t prefix = strlen(archive_prefix), component = strlen(names[i]);
        int directory;
        if (prefix > SIZE_MAX - component - 2) goto done;
        path = malloc(prefix + component + 2);
        if (!path) goto done;
        snprintf(path, prefix + component + 2, "%s/%s", archive_prefix, names[i]);
        if (fstatat(dir, names[i], &st, AT_SYMLINK_NOFOLLOW)) {
            free(path);
            goto done;
        }
        directory = S_ISDIR(st.st_mode);
        if ((!directory && !S_ISREG(st.st_mode)) ||
            !write_entry(writer, dir, names[i], path, directory) ||
            (directory && !walk_data(writer, dir, names[i], path, depth + 1))) {
            free(path);
            goto done;
        }
        free(path);
    }
    ok = 1;
done:
    for (i = 0; i < count; ++i) free(names[i]);
    free(names);
    if (list) closedir(list);
    if (scan >= 0) close(scan);
    if (dir >= 0) close(dir);
    return ok;
}

int holy_pack(const char *tree, const char *output)
{
    static const char *const meta[] = {
        "meta", "files", "deps", "provides", "hooks", "origin", "transform"
    };
    static const char *const roots[] = { "HOLY", "DATA" };
    struct writer writer = {0};
    char *temporary = NULL;
    int root = -1, holy = -1, data = -1, fd = -1, archive_fd = -1, ok = 0;
    size_t i, length = strlen(output);
    if (length > SIZE_MAX - 20) return 0;
    temporary = malloc(length + 20);
    if (!temporary) return 0;
    snprintf(temporary, length + 20, "%s.holy-tmp-XXXXXX", output);
    root = open(tree, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0 || !outside_tree(root, output)) goto done;
    holy = openat(root, "HOLY", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    data = openat(root, "DATA", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (holy < 0 || data < 0 || flistxattr(holy, NULL, 0) != 0 ||
        flistxattr(data, NULL, 0) != 0 ||
        !exact_members(root, roots, 2) ||
        !exact_members(holy, meta, sizeof meta / sizeof *meta)) goto done;
    fd = mkstemp(temporary);
    if (fd < 0) goto done;
    archive_fd = dup(fd);
    if (archive_fd < 0) goto done;
    writer.archive = archive_write_new();
    if (!writer.archive || archive_write_add_filter_lz4(writer.archive) != ARCHIVE_OK ||
        archive_write_set_format_pax_restricted(writer.archive) != ARCHIVE_OK ||
        archive_write_set_options(writer.archive, "hdrcharset=UTF-8") != ARCHIVE_OK ||
        archive_write_open_fd(writer.archive, archive_fd) != ARCHIVE_OK) goto done;
    if (!write_entry(&writer, root, "HOLY", "HOLY", 1)) goto done;
    for (i = 0; i < sizeof meta / sizeof *meta; ++i) {
        char path[32];
        snprintf(path, sizeof path, "HOLY/%s", meta[i]);
        if (!write_entry(&writer, holy, meta[i], path, 0)) goto done;
    }
    if (!write_entry(&writer, root, "DATA", "DATA", 1) ||
        !walk_data(&writer, root, "DATA", "DATA", 0)) goto done;
    if (archive_write_close(writer.archive) != ARCHIVE_OK) goto done;
    archive_write_free(writer.archive);
    writer.archive = NULL;
    if (fcntl(archive_fd, F_GETFD) >= 0) close(archive_fd);
    archive_fd = -1;
    if (fsync(fd) || close(fd)) { fd = -1; goto done; }
    fd = -1;
    if (!holy_verify_with_output(temporary, 0) ||
        !holy_scan_local_with_output(temporary, 0) ||
        !holy_deps_local_with_output(temporary, 0) ||
        !holy_provides_local(temporary, 0) ||
        link(temporary, output)) goto done;
    if (!sync_parent(output)) {
        fprintf(stderr, "holypkg: output published but directory sync failed: %s\n", output);
        goto done;
    }
    printf("packed %s\n", output);
    ok = 1;
done:
    if (!ok) fprintf(stderr, "holypkg: pack failed\n");
    if (writer.archive) archive_write_free(writer.archive);
    if (archive_fd >= 0 && fcntl(archive_fd, F_GETFD) >= 0) close(archive_fd);
    if (fd >= 0) close(fd);
    if (temporary) { unlink(temporary); free(temporary); }
    if (data >= 0) close(data);
    if (holy >= 0) close(holy);
    if (root >= 0) close(root);
    return ok;
}

int holy_generate_files(const char *tree, const char *output)
{
    struct writer writer = {0};
    char *temporary = NULL;
    size_t length = strlen(output);
    int root = -1, fd = -1, ok = 0;
    if (length > SIZE_MAX - 20) return 0;
    temporary = malloc(length + 20);
    if (!temporary) return 0;
    snprintf(temporary, length + 20, "%s.holy-tmp-XXXXXX", output);
    root = open(tree, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0 || !outside_tree(root, output)) goto done;
    fd = mkstemp(temporary);
    if (fd < 0) goto done;
    writer.manifest = fdopen(fd, "w");
    if (!writer.manifest) goto done;
    fd = -1;
    if (!walk_data(&writer, root, "DATA", "DATA", 0) ||
        fflush(writer.manifest) || fsync(fileno(writer.manifest))) goto done;
    if (fclose(writer.manifest)) { writer.manifest = NULL; goto done; }
    writer.manifest = NULL;
    if (link(temporary, output)) goto done;
    if (!sync_parent(output)) {
        fprintf(stderr, "holypkg: manifest published but directory sync failed: %s\n", output);
        goto done;
    }
    printf("manifest %s\n", output);
    ok = 1;
done:
    if (!ok) fprintf(stderr, "holypkg: manifest generation failed\n");
    if (writer.manifest) fclose(writer.manifest);
    if (fd >= 0) close(fd);
    if (temporary) { unlink(temporary); free(temporary); }
    if (root >= 0) close(root);
    return ok;
}
