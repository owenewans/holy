#define _POSIX_C_SOURCE 200809L
#include "check.h"
#include "package.h"
#include "verify.h"

#include <archive.h>
#include <archive_entry.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int parent_fd(int root, const char *path, char **storage, const char **base)
{
    char *cursor, *slash;
    size_t length;
    int current = root, next;
    *storage = strdup(path);
    if (!*storage) return -1;
    length = strlen(*storage);
    if (length && (*storage)[length - 1] == '/') (*storage)[length - 1] = '\0';
    slash = strrchr(*storage, '/');
    if (!slash) { *base = *storage; return root; }
    *slash++ = '\0';
    *base = slash;
    cursor = *storage;
    while (*cursor) {
        char *end = strchr(cursor, '/');
        if (end) *end = '\0';
        next = openat(current, cursor, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (current != root) close(current);
        if (next < 0) { free(*storage); *storage = NULL; return -1; }
        current = next;
        cursor = end ? end + 1 : cursor + strlen(cursor);
    }
    return current;
}

static int hash_file(int fd, unsigned char digest[32])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    char buffer[65536];
    unsigned int length;
    ssize_t got;
    int ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    while (ok && (got = read(fd, buffer, sizeof buffer)) != 0) {
        if (got < 0) {
            if (errno == EINTR) continue;
            ok = 0;
            break;
        }
        if (EVP_DigestUpdate(ctx, buffer, (size_t)got) != 1) ok = 0;
    }
    if (ok) ok = EVP_DigestFinal_ex(ctx, digest, &length) == 1 && length == 32;
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int compare_file(struct archive *a, struct archive_entry *entry, int parent,
                        const char *name, const struct stat *st)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    char buffer[65536];
    unsigned char expected[32], actual[32];
    unsigned int length;
    la_ssize_t got;
    la_int64_t total = 0;
    struct stat opened;
    int fd = -1, ok = 0;
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        !S_ISREG(st->st_mode) || st->st_size != archive_entry_size(entry)) goto done;
    fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &opened) ||
        opened.st_dev != st->st_dev || opened.st_ino != st->st_ino ||
        opened.st_size != st->st_size || opened.st_mode != st->st_mode ||
        opened.st_uid != st->st_uid || opened.st_gid != st->st_gid) goto done;
    while ((got = archive_read_data(a, buffer, sizeof buffer)) > 0) {
        if (total > archive_entry_size(entry) - got ||
            EVP_DigestUpdate(ctx, buffer, (size_t)got) != 1) goto done;
        total += got;
    }
    if (got < 0 || total != archive_entry_size(entry) ||
        EVP_DigestFinal_ex(ctx, expected, &length) != 1 || length != 32 ||
        !hash_file(fd, actual) || memcmp(expected, actual, 32)) goto done;
    ok = 1;
done:
    if (fd >= 0) close(fd);
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int compare_link(struct archive_entry *entry, int parent, const char *name)
{
    const char *expected = archive_entry_symlink(entry);
    size_t length;
    char *actual;
    ssize_t got;
    int ok;
    if (!expected) return 0;
    length = strlen(expected);
    if (length > (size_t)-1 - 2) return 0;
    actual = malloc(length + 2);
    if (!actual) return 0;
    got = readlinkat(parent, name, actual, length + 1);
    ok = got >= 0 && (size_t)got == length && !memcmp(actual, expected, length);
    free(actual);
    return ok;
}

static int compare_hardlink(int root, struct archive_entry *entry,
                            const struct stat *current)
{
    const char *target = archive_entry_hardlink(entry);
    char *storage = NULL;
    const char *name;
    struct stat st;
    int parent, ok = 0;
    if (!target || !holy_safe_archive_path(target) ||
        strncmp(target, "DATA/", 5) || !target[5]) return 0;
    parent = parent_fd(root, target + 5, &storage, &name);
    if (parent < 0) return 0;
    if (!fstatat(parent, name, &st, AT_SYMLINK_NOFOLLOW) &&
        S_ISREG(st.st_mode) && st.st_dev == current->st_dev &&
        st.st_ino == current->st_ino) ok = 1;
    if (parent != root) close(parent);
    free(storage);
    return ok;
}

static void json_string(const char *text)
{
    const unsigned char *p = (const unsigned char *)text;
    putchar('"');
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p >= 32 && *p < 127) putchar(*p);
        else printf("\\u%04x", (unsigned int)*p);
    }
    putchar('"');
}

static void report_changed(const char *path, int json)
{
    if (!json) fprintf(stderr, "holypkg: changed payload: %s\n", path);
    else {
        fputs("{\"schema\":\"holy-check-1\",\"code\":\"changed-payload\",\"severity\":\"error\",\"status\":\"fail\",\"path\":", stdout);
        json_string(path);
        fputs("}\n", stdout);
    }
}

int holy_check_local(const char *package, const char *root_path, int json)
{
    struct archive *a = NULL;
    struct archive_entry *entry;
    int root = -1, status, ok = 0, reported = 0;
    size_t checked = 0;
    if (!holy_verify_with_output(package, 0)) {
        if (json) puts("{\"schema\":\"holy-check-1\",\"code\":\"invalid-package\",\"severity\":\"error\",\"status\":\"unknown\"}");
        return 0;
    }
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) { perror("holypkg: check root"); goto done; }
    a = archive_read_new();
    if (!a || archive_read_support_filter_lz4(a) != ARCHIVE_OK ||
        archive_read_support_format_tar(a) != ARCHIVE_OK ||
        archive_read_open_filename(a, package, 8192) != ARCHIVE_OK) goto done;
    while ((status = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        const char *path = archive_entry_pathname(entry);
        const char *name;
        char *storage = NULL;
        struct stat st;
        int parent, matches;
        if (!path || strncmp(path, "DATA/", 5) || !path[5]) {
            if (archive_read_data_skip(a) != ARCHIVE_OK) goto done;
            continue;
        }
        if (!holy_safe_archive_path(path)) {
            fprintf(stderr, "holypkg: unsafe payload path\n");
            goto done;
        }
        parent = parent_fd(root, path + 5, &storage, &name);
        if (parent < 0) {
            report_changed(path, json);
            reported = 1;
            goto done;
        }
        matches = !fstatat(parent, name, &st, AT_SYMLINK_NOFOLLOW) &&
                  (st.st_mode & 07777) == archive_entry_perm(entry) &&
                  st.st_uid == (uid_t)archive_entry_uid(entry) &&
                  st.st_gid == (gid_t)archive_entry_gid(entry);
        if (matches && archive_entry_hardlink(entry))
            matches = S_ISREG(st.st_mode) && compare_hardlink(root, entry, &st);
        else if (matches && archive_entry_filetype(entry) == AE_IFREG)
            matches = compare_file(a, entry, parent, name, &st);
        else if (matches && archive_entry_filetype(entry) == AE_IFLNK)
            matches = S_ISLNK(st.st_mode) && compare_link(entry, parent, name);
        else if (matches && archive_entry_filetype(entry) == AE_IFDIR)
            matches = S_ISDIR(st.st_mode);
        else matches = 0;
        if (parent != root) close(parent);
        free(storage);
        if (!matches) {
            report_changed(path, json);
            reported = 1;
            goto done;
        }
        ++checked;
    }
    if (status != ARCHIVE_EOF) goto done;
    if (json) printf("{\"schema\":\"holy-check-1\",\"status\":\"pass\",\"coverage\":\"local-payload\",\"checked\":%zu}\n", checked);
    else printf("checked %zu payload objects\n", checked);
    ok = 1;
done:
    if (!ok && json && !reported)
        puts("{\"schema\":\"holy-check-1\",\"code\":\"check-error\",\"severity\":\"error\",\"status\":\"unknown\"}");
    if (a) archive_read_free(a);
    if (root >= 0) close(root);
    return ok;
}
