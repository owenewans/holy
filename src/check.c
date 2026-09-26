#define _POSIX_C_SOURCE 200809L
#include "check.h"
#include "package.h"
#include "stage.h"
#include "scan.h"
#include "elf.h"
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
        if (next < 0) {
            int error = errno;
            free(*storage);
            *storage = NULL;
            errno = error;
            return -1;
        }
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
                        const char *name, const struct stat *st, char **interpreter,
                        int *elf_class, uint16_t *machine)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    char buffer[65536];
    unsigned char expected[32], actual[32];
    unsigned int length;
    la_ssize_t got;
    la_int64_t total = 0;
    struct stat opened;
    int fd = -1, ok = 0;
    *interpreter = NULL;
    *elf_class = 0;
    *machine = 0;
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
    if (st->st_size >= 4) {
        unsigned char magic[4];
        if (pread(fd, magic, sizeof magic, 0) != sizeof magic) goto done;
        if (!memcmp(magic, "\177ELF", sizeof magic)) {
            struct holy_elf_info info;
            int result = holy_elf_read_fd(fd, &info);
            int has_interpreter = info.interpreter != NULL;
            if (result == 0 && info.interpreter) {
                *interpreter = strdup(info.interpreter);
                *elf_class = info.elf_class;
                *machine = info.machine;
            }
            holy_elf_free(&info);
            if (result || (has_interpreter && !*interpreter))
                goto done;
        }
    }
    ok = 1;
done:
    if (!ok) { free(*interpreter); *interpreter = NULL; }
    if (fd >= 0) close(fd);
    EVP_MD_CTX_free(ctx);
    return ok;
}

/* 1: compatible ELF found, 0: missing, 2: wrong arch, -1: unknown. */
static int interpreter_status(int root, const char *interpreter,
                              int elf_class, uint16_t machine)
{
    char *storage = NULL;
    char *path;
    const char *name;
    struct stat st;
    int parent, fd = -1, result = -1;
    size_t length = strlen(interpreter);
    if (interpreter[0] != '/' || !interpreter[1] ||
        length > (size_t)-1 - 6) return -1;
    path = malloc(length + 6);
    if (!path) return -1;
    snprintf(path, length + 6, "DATA%s", interpreter);
    if (!holy_safe_archive_path(path)) { free(path); return -1; }
    free(path);
    parent = parent_fd(root, interpreter + 1, &storage, &name);
    if (parent < 0) return errno == ENOENT ? 0 : -1;
    fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        if (errno == ENOENT) result = 0;
    } else if (!fstat(fd, &st) && S_ISREG(st.st_mode) && (st.st_mode & 0111)) {
        struct holy_elf_info info;
        int parsed = holy_elf_read_fd(fd, &info);
        if (!parsed)
            result = info.elf_class == elf_class && info.machine == machine ? 1 : 2;
        holy_elf_free(&info);
    }
    if (fd >= 0) close(fd);
    if (parent != root) close(parent);
    free(storage);
    return result;
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

static void report_changed(const char *path, const char *code, int json)
{
    if (!json) fprintf(stderr, "holypkg: %s payload: %s\n",
                       !strcmp(code, "missing-payload") ? "missing" : "changed", path);
    else {
        printf("{\"schema\":\"holy-check-1\",\"code\":\"%s\",\"severity\":\"error\",\"status\":\"fail\",\"path\":", code);
        json_string(path);
        fputs("}\n", stdout);
    }
}

static void report_interpreter(const char *consumer, const char *interpreter,
                               int status, int json)
{
    const char *code = status == 0 ? "missing-interpreter" :
                       status == 2 ? "incompatible-interpreter" : "unknown-interpreter";
    if (!json) fprintf(stderr, "holypkg: %s %s for %s\n", code,
                       interpreter, consumer);
    else {
        printf("{\"schema\":\"holy-check-1\",\"code\":\"%s\",\"severity\":\"%s\",\"status\":\"%s\",\"consumer\":",
                code, status >= 0 ? "error" : "warning", status >= 0 ? "fail" : "unknown");
        json_string(consumer);
        fputs(",\"path\":", stdout);
        json_string(interpreter);
        puts("}");
    }
}

int holy_check_local(const char *package, const char *root_path, int json)
{
    struct archive *a = NULL;
    struct archive_entry *entry;
    char *snapshot = holy_stage_local(package, "holy-check");
    int root = -1, status, ok = 0, completed = 0;
    size_t checked = 0, findings = 0, unknowns = 0;
    if (!snapshot) fprintf(stderr, "holypkg: could not stage regular local input\n");
    if (!snapshot || !holy_verify_with_output(snapshot, 0) ||
        !holy_scan_local_with_output(snapshot, 0)) {
        if (json) puts("{\"schema\":\"holy-check-1\",\"code\":\"invalid-package\",\"severity\":\"error\",\"status\":\"unknown\"}");
        if (snapshot) { unlink(snapshot); free(snapshot); }
        return 0;
    }
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) { perror("holypkg: check root"); goto done; }
    a = archive_read_new();
    if (!a || archive_read_support_filter_lz4(a) != ARCHIVE_OK ||
        archive_read_support_format_tar(a) != ARCHIVE_OK ||
        archive_read_open_filename(a, snapshot, 8192) != ARCHIVE_OK) goto done;
    while ((status = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        const char *path = archive_entry_pathname(entry);
        const char *name;
        char *storage = NULL;
        char *interpreter = NULL;
        int elf_class = 0;
        uint16_t machine = 0;
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
        ++checked;
        parent = parent_fd(root, path + 5, &storage, &name);
        if (parent < 0) {
            if (errno != ENOENT && errno != ENOTDIR && errno != ELOOP) goto done;
            report_changed(path, errno == ENOENT ? "missing-payload" : "changed-payload", json);
            ++findings;
            if (archive_read_data_skip(a) != ARCHIVE_OK) goto done;
            continue;
        }
        matches = !fstatat(parent, name, &st, AT_SYMLINK_NOFOLLOW);
        if (!matches && errno != ENOENT) {
            if (parent != root) close(parent);
            free(storage);
            goto done;
        }
        if (!matches) {
            if (parent != root) close(parent);
            free(storage);
            report_changed(path, "missing-payload", json);
            ++findings;
            if (archive_read_data_skip(a) != ARCHIVE_OK) goto done;
            continue;
        }
        matches = (st.st_mode & 07777) == archive_entry_perm(entry) &&
                  st.st_uid == (uid_t)archive_entry_uid(entry) &&
                  st.st_gid == (gid_t)archive_entry_gid(entry);
        if (matches && archive_entry_hardlink(entry))
            matches = S_ISREG(st.st_mode) && compare_hardlink(root, entry, &st);
        else if (matches && archive_entry_filetype(entry) == AE_IFREG)
            matches = compare_file(a, entry, parent, name, &st, &interpreter,
                                   &elf_class, &machine);
        else if (matches && archive_entry_filetype(entry) == AE_IFLNK)
            matches = S_ISLNK(st.st_mode) && compare_link(entry, parent, name);
        else if (matches && archive_entry_filetype(entry) == AE_IFDIR)
            matches = S_ISDIR(st.st_mode);
        else matches = 0;
        if (parent != root) close(parent);
        free(storage);
        if (!matches) {
            report_changed(path, "changed-payload", json);
            ++findings;
        } else if (interpreter) {
            int loader = interpreter_status(root, interpreter, elf_class, machine);
            if (loader != 1) {
                report_interpreter(path, interpreter, loader, json);
                ++findings;
                if (loader < 0) ++unknowns;
            }
        }
        free(interpreter);
        if (archive_read_data_skip(a) != ARCHIVE_OK) goto done;
    }
    if (status != ARCHIVE_EOF) goto done;
    if (json) {
        if (findings)
            printf("{\"schema\":\"holy-check-1\",\"status\":\"%s\",\"coverage\":\"local-payload\",\"checked\":%zu,\"findings\":%zu,\"unknowns\":%zu}\n",
                   findings == unknowns ? "unknown" : "fail", checked, findings, unknowns);
        else printf("{\"schema\":\"holy-check-1\",\"status\":\"pass\",\"coverage\":\"local-payload\",\"checked\":%zu}\n", checked);
    } else if (findings) printf("checked %zu payload objects, %zu findings, %zu unknown\n",
                                checked, findings, unknowns);
    else printf("checked %zu payload objects\n", checked);
    ok = findings == 0;
    completed = 1;
done:
    if (!completed && json)
        puts("{\"schema\":\"holy-check-1\",\"code\":\"check-error\",\"severity\":\"error\",\"status\":\"unknown\"}");
    if (a) archive_read_free(a);
    if (root >= 0) close(root);
    unlink(snapshot);
    free(snapshot);
    return ok;
}
