#define _DEFAULT_SOURCE
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
#include <sys/syscall.h>
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
    if (entry->hardlink || entry->group ||
        (entry->link && (entry->mode != 0777 || entry->link[0] == '/')) ||
        (entry->mode & 07000) ||
        entry->uid != (long long)geteuid() ||
        entry->gid != (long long)getegid()) return 0;
    parent = parent_fd(check->root, entry->path, &storage, &base);
    if (parent < 0) return 0;
    if (!fstatat(parent, base, &st, AT_SYMLINK_NOFOLLOW))
        ok = entry->directory && S_ISDIR(st.st_mode) &&
             (st.st_mode & 07777) == entry->mode &&
             (long long)st.st_uid == entry->uid &&
             (long long)st.st_gid == entry->gid &&
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
        fprintf(stderr, "holypkg: install requires existing safe directories and new files or relative symlinks\n");
        return 0;
    }
    return 1;
}

static int install_payload(const char *snapshot, int root, int missing_only)
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

int holy_install_payload(const char *snapshot, int root)
{
    return install_payload(snapshot, root, 0);
}

int holy_install_payload_missing(const char *snapshot, int root)
{
    return install_payload(snapshot, root, 1);
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
    if ((strcmp(v[0], "dir") && strcmp(v[0], "file") && !symlink) ||
        !decimal(v[2], 8, &mode) || mode > 07777 ||
        !decimal(v[5], 10, &uid) || uid > 0x7fffffff ||
        !decimal(v[6], 10, &gid) || gid > 0x7fffffff ||
        !decimal(v[7], 10, &size) || size > LLONG_MAX ||
        strcmp(v[9], "none") || strcmp(v[10], "-") || strcmp(v[11], "-"))
        return -1;
    if (symlink && (mode != 0777 || v[12][0] == '/' ||
                    !holy_safe_link(v[1], v[12]))) return -1;
    if (!strcmp(v[0], "dir") || symlink) {
        if (size || strcmp(v[8], "-")) return -1;
    } else if (strlen(v[8]) != 64) return -1;
    parent = parent_fd(root, v[1], &storage, &base);
    if (parent < 0) return 0;
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
        result = !fstatat(parent, base, &st, AT_SYMLINK_NOFOLLOW) &&
                 S_ISDIR(st.st_mode) &&
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

static int walk_manifest(int files_fd, int root, int mode,
                          holy_install_finding finding, void *context, const char *filter)
{
    struct stat st;
    char *text = NULL;
    size_t length, used = 0, start = 0, i, line = 0, matches = 0;
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
        if (count != (!strcmp(v[0], "symlink") ? 13u : 12u)) {
            holy_tokens_free(v, count);
            result = -1;
            goto done;
        }
        if (filter && strcmp(filter, v[1])) { holy_tokens_free(v, count); continue; }
        ++matches;
        checked = check_file(root, v, &observed);
        if (checked < 0) result = -1;
        else if (checked == 2) {
            if (mode != 2 && mode != 3 && result == 1) result = 0;
            if (mode != 2 && mode != 3) report_changed(v[1], "missing-file");
        }
        else if (!checked) {
            report_changed(v[1], "changed-file");
            if (result == 1) result = 0;
        } else if ((mode == 1 || mode == 2) && strcmp(v[0], "dir") &&
                   !remove_file(root, v[1], &observed)) {
            result = 0;
        }
        if (finding && (checked == 0 || checked == 2) &&
            !finding(context, v[1], checked == 2 ? "missing-file" : "changed-file"))
            result = -1;
        holy_tokens_free(v, count);
        if (result < 0 || (mode && result != 1)) goto done;
    }
    if (filter && matches != 1) result = -1;
done:
    free(text);
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
            if (count != (!strcmp(v[0], "symlink") ? 13u : 12u) ||
                (strcmp(v[0], "file") && strcmp(v[0], "dir") &&
                 strcmp(v[0], "symlink")))
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

int holy_install_manifests_conflict(int left_fd, int right_fd)
{
    return manifest_claims(left_fd, NULL, right_fd);
}

static int transition_entry_valid(const struct holy_manifest_entry *entry)
{
    return entry && entry->path && entry->path[0] && entry->path[0] != '/' &&
           entry->path[strlen(entry->path) - 1] != '/' &&
           !entry->directory && !entry->hardlink && !entry->group &&
           !(entry->mode & ~0777u) && entry->uid == (long long)geteuid() &&
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
    if (!transition_entry_valid(entry)) return -1;
    snprintf(numbers[0], sizeof numbers[0], "%o", entry->mode);
    snprintf(numbers[1], sizeof numbers[1], "%lld", entry->uid);
    snprintf(numbers[2], sizeof numbers[2], "%lld", entry->gid);
    snprintf(numbers[3], sizeof numbers[3], "%lld", entry->size);
    if (!entry->link) for (i = 0; i < 32; ++i)
        snprintf(hash + i * 2, 3, "%02x", entry->hash[i]);
    v[0] = entry->link ? "symlink" : "file";
    v[1] = (char *)entry->path; v[2] = numbers[0]; v[3] = v[4] = "-";
    v[5] = numbers[1]; v[6] = numbers[2]; v[7] = numbers[3];
    v[8] = entry->link ? "-" : hash; v[9] = "none"; v[10] = v[11] = "-";
    v[12] = (char *)entry->link;
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
    }
    free(storage);
    return absent;
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
    if (!transition_entry_valid(next) || !(path = transition_temporary(next->path, temporary))) goto done;
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
    if (completed) {
        if (ready_state == 2) ok = !fsync(parent);
        else if (ready_state == 1) ok = remove_file(root, path, &ready);
        goto done;
    }
    if (ready_state != 1 || (before && transition_matches(root, before, &original) != 1)) goto done;
    if (fstatat(parent, temporary, &current, AT_SYMLINK_NOFOLLOW) || !same_object(&ready, &current)) goto done;
    if (before) {
        if (fstatat(parent, base, &current, AT_SYMLINK_NOFOLLOW) || !same_object(&original, &current) ||
            renameat(parent, temporary, parent, base)) goto done;
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
