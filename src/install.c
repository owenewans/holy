#define _POSIX_C_SOURCE 200809L
#include "install.h"
#include "verify.h"
#include "config.h"

#include <archive.h>
#include <archive_entry.h>
#include <openssl/evp.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
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
    if ((strcmp(v[0], "dir") && strcmp(v[0], "file")) ||
        !decimal(v[2], 8, &mode) || mode > 07777 ||
        !decimal(v[5], 10, &uid) || uid > 0x7fffffff ||
        !decimal(v[6], 10, &gid) || gid > 0x7fffffff ||
        !decimal(v[7], 10, &size) || size > LLONG_MAX ||
        strcmp(v[9], "none") || strcmp(v[10], "-") || strcmp(v[11], "-"))
        return -1;
    if (!strcmp(v[0], "dir")) {
        if (size || strcmp(v[8], "-")) return -1;
    } else if (strlen(v[8]) != 64) return -1;
    parent = parent_fd(root, v[1], &storage, &base);
    if (parent < 0) return 0;
    if (!strcmp(v[0], "dir")) {
        result = !fstatat(parent, base, &st, AT_SYMLINK_NOFOLLOW) &&
                 S_ISDIR(st.st_mode) &&
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

static void report_changed(const char *path)
{
    const unsigned char *p = (const unsigned char *)path;
    fputs("holypkg: changed-file ", stderr);
    for (; *p; ++p)
        if (*p == '\\' || *p <= 32 || *p >= 127)
            fprintf(stderr, "\\x%02x", (unsigned int)*p);
        else fputc(*p, stderr);
    fputc('\n', stderr);
}

static int remove_file(int root, const char *path, const struct stat *observed)
{
    char *storage = NULL;
    const char *base;
    struct stat st;
    int parent = parent_fd(root, path, &storage, &base), ok = 0;
    if (parent < 0) return 0;
    if (!fstatat(parent, base, &st, AT_SYMLINK_NOFOLLOW) &&
        S_ISREG(st.st_mode) &&
        st.st_dev == observed->st_dev && st.st_ino == observed->st_ino &&
        st.st_size == observed->st_size && st.st_mode == observed->st_mode &&
        st.st_uid == observed->st_uid && st.st_gid == observed->st_gid &&
        !unlinkat(parent, base, 0) && !fsync(parent)) ok = 1;
    close(parent);
    free(storage);
    return ok;
}

static int walk_manifest(int files_fd, int root, int mode)
{
    struct stat st;
    char *text = NULL;
    size_t length, used = 0, start = 0, i, line = 0;
    int result = 1;
    if (lseek(files_fd, 0, SEEK_SET) != 0 ||
        fstat(files_fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        st.st_size > 16 * 1024 * 1024) return -1;
    length = (size_t)st.st_size;
    text = malloc(length + 1);
    if (!text) return -1;
    while (used < length) {
        ssize_t got = read(files_fd, text + used, length - used);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { result = -1; goto done; }
        used += (size_t)got;
    }
    text[length] = '\0';
    for (i = 0; i <= length; ++i) {
        char **v = NULL, *error = NULL;
        size_t count = 0;
        int checked;
        struct stat observed;
        if (i < length && text[i] != '\n') continue;
        ++line;
        if (memchr(text + start, '\0', i - start) ||
            !holy_lex(text + start, i - start, &v, &count, "installed/files", line, &error)) {
            free(error);
            result = -1;
            goto done;
        }
        start = i + 1;
        if (!count) { holy_tokens_free(v, count); continue; }
        if (count != 12) {
            holy_tokens_free(v, count);
            result = -1;
            goto done;
        }
        checked = check_file(root, v, &observed);
        if (checked < 0) result = -1;
        else if (checked == 2) {
            if (mode != 2 && result == 1) result = 0;
            if (mode != 2) report_changed(v[1]);
        }
        else if (!checked) {
            report_changed(v[1]);
            if (result == 1) result = 0;
        } else if (mode && !strcmp(v[0], "file") &&
                   !remove_file(root, v[1], &observed)) {
            result = 0;
        }
        holy_tokens_free(v, count);
        if (result < 0 || (mode && result != 1)) goto done;
    }
done:
    free(text);
    return result;
}

int holy_install_check_manifest(int files_fd, int root)
{
    return walk_manifest(files_fd, root, 0);
}

int holy_install_remove_manifest(int files_fd, int root)
{
    if (holy_install_check_manifest(files_fd, root) != 1) return 0;
    return walk_manifest(files_fd, root, 1) == 1;
}

int holy_install_finish_remove_manifest(int files_fd, int root)
{
    if (walk_manifest(files_fd, root, 2) != 1) return 0;
    return walk_manifest(files_fd, root, 2) == 1;
}
