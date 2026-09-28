#define _POSIX_C_SOURCE 200809L
#include "appimage.h"
#include "elf.h"
#include "stage.h"
#include "verify.h"

#include <openssl/evp.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static uint16_t le16(const unsigned char *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t le32(const unsigned char *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t le64(const unsigned char *p) { return (uint64_t)le32(p) | (uint64_t)le32(p + 4) << 32; }

static int digest_fd(int fd, char result[65])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char buffer[65536], hash[32];
    unsigned length;
    ssize_t got;
    size_t i;
    int ok = 0;
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 || lseek(fd, 0, SEEK_SET) < 0) goto done;
    while ((got = read(fd, buffer, sizeof buffer)) > 0)
        if (EVP_DigestUpdate(ctx, buffer, (size_t)got) != 1) goto done;
    if (got < 0 || EVP_DigestFinal_ex(ctx, hash, &length) != 1 || length != 32) goto done;
    for (i = 0; i < 32; ++i) snprintf(result + i * 2, 3, "%02x", hash[i]);
    ok = 1;
done:
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int image_info(int fd, off_t *offset, char hash[65], const char **arch)
{
    struct holy_elf_info elf;
    struct stat st;
    unsigned char head[11], block[65536 + 3], super[96];
    off_t pos, found = -1;
    ssize_t got;
    int parsed;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 96 || st.st_size > 4LL * 1024 * 1024 * 1024 ||
        pread(fd, head, sizeof head, 0) != sizeof head ||
        memcmp(head, "\177ELF", 4) || memcmp(head + 8, "AI\002", 3)) return 2;
    parsed = holy_elf_read_fd(fd, &elf);
    if (parsed || !strcmp(holy_elf_machine(&elf), "unknown")) {
        holy_elf_free(&elf); return 3;
    }
    *arch = !strcmp(holy_elf_machine(&elf), "x86") ? "x86" :
            !strcmp(holy_elf_machine(&elf), "x86_64") ? "x86_64" : NULL;
    holy_elf_free(&elf);
    if (!*arch) return 3;
    for (pos = 0; pos < st.st_size; pos += 65536) {
        size_t n, i;
        got = pread(fd, block, sizeof block, pos);
        if (got < 0) return 1;
        n = (size_t)got;
        for (i = 0; i + 96 <= n; ++i) {
            off_t candidate = pos + (off_t)i;
            uint32_t size, log;
            uint64_t used;
            if (memcmp(block + i, "hsqs", 4) || candidate + 96 > st.st_size) continue;
            memcpy(super, block + i, sizeof super);
            size = le32(super + 12); log = le16(super + 22); used = le64(super + 40);
            if (!le32(super + 4) || size < 4096 || size > 1048576 || (size & (size - 1)) ||
                log < 12 || log > 20 || size != (1u << log) ||
                le16(super + 20) < 1 || le16(super + 20) > 6 ||
                le16(super + 28) != 4 || le16(super + 30) != 0 ||
                used < 96 || used > (uint64_t)(st.st_size - candidate)) continue;
            if (found >= 0) return 3;
            found = candidate;
        }
        if (got <= 65536) break;
    }
    if (found < 0) return 2;
    *offset = found;
    return digest_fd(fd, hash) ? 0 : 1;
}

static int snapshot(const char *input, char **path, off_t *offset, char hash[65], const char **arch)
{
    int fd = open(input, O_RDONLY | O_NONBLOCK | O_CLOEXEC), copy, result = 6;
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size < 96 || st.st_size > 4LL * 1024 * 1024 * 1024) goto done;
    *path = holy_stage_fd(fd, "holy-appimage");
    if (!*path) { result = 1; goto done; }
    copy = open(*path, O_RDONLY | O_CLOEXEC);
    if (copy < 0) { result = 1; goto done; }
    result = image_info(copy, offset, hash, arch);
    close(copy);
done:
    if (fd >= 0) close(fd);
    return result;
}

int holy_appimage_inspect(const char *input)
{
    char *path = NULL, hash[65];
    const char *arch = NULL;
    off_t offset = 0;
    int result = snapshot(input, &path, &offset, hash, &arch);
    if (!result) printf("type appimage-2\narch %s\nsquashfs-offset %lld\nsha256 %s\n", arch, (long long)offset, hash);
    else fprintf(stderr, "holypkg: AppImage inspection failed (status %d)\n", result);
    if (path) { unlink(path); free(path); }
    return result;
}

static int copy_original(const char *source, int output)
{
    unsigned char buffer[65536];
    int in = open(source, O_RDONLY | O_CLOEXEC), out = -1, ok = 0;
    ssize_t got;
    if (in < 0) goto done;
    out = openat(output, "original", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (out < 0) goto done;
    while ((got = read(in, buffer, sizeof buffer)) > 0) {
        size_t at = 0;
        while (at < (size_t)got) {
            ssize_t n = write(out, buffer + at, (size_t)got - at);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) goto done;
            at += (size_t)n;
        }
    }
    ok = got == 0 && !fsync(out) && !fsync(output);
done:
    if (in >= 0) close(in);
    if (out >= 0) close(out);
    return ok;
}

struct scan_state {
    FILE *report;
    size_t files, elfs, scripts, unknown, links;
};

static void quoted(FILE *out, const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    fputc('"', out);
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') fprintf(out, "\\%c", *p);
        else if (*p < 32 || *p >= 127) fprintf(out, "\\x%02x", *p);
        else fputc(*p, out);
    }
    fputc('"', out);
}

static char *child_path(const char *parent, const char *name)
{
    size_t a = strlen(parent), b = strlen(name);
    char *path;
    if (a > SIZE_MAX - b - 2) return NULL;
    path = malloc(a + b + 2);
    if (path) sprintf(path, "%s%s%s", parent, a ? "/" : "", name);
    return path;
}

static int classify_file(int parent, const char *name, const char *path, struct scan_state *scan)
{
    struct holy_elf_info elf;
    unsigned char head[256];
    ssize_t got;
    int fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    int parsed;
    if (fd < 0) return 0;
    got = pread(fd, head, sizeof head, 0);
    if (got < 0) { close(fd); return 0; }
    parsed = holy_elf_read_fd(fd, &elf);
    if (!parsed) {
        const char *arch = holy_elf_machine(&elf), *libc = holy_elf_runtime(&elf);
        fputs("elf ", scan->report); quoted(scan->report, path);
        fprintf(scan->report, " %s %s %s\n", arch, libc, holy_elf_isa(&elf));
        ++scan->elfs;
        if (!strcmp(arch, "unknown") || !strcmp(libc, "unknown")) ++scan->unknown;
    } else if (parsed == 2 || (got >= 8 && !memcmp(head, "!<arch>\n", 8)) ||
               (got >= 2 && head[0] == 'M' && head[1] == 'Z')) {
        fputs("unknown ", scan->report); quoted(scan->report, path); fputc('\n', scan->report);
        ++scan->unknown;
    } else if (got >= 2 && head[0] == '#' && head[1] == '!') {
        size_t len = 2;
        char interpreter[256];
        while (len < (size_t)got && head[len] != '\n' && head[len] != '\r') ++len;
        memcpy(interpreter, head + 2, len - 2); interpreter[len - 2] = 0;
        fputs("script ", scan->report); quoted(scan->report, path);
        fputc(' ', scan->report); quoted(scan->report, interpreter); fputc('\n', scan->report);
        ++scan->scripts;
    } else {
        struct stat st;
        if (fstat(fd, &st)) { holy_elf_free(&elf); close(fd); return 0; }
        if (st.st_mode & 0111) {
            fputs("unknown-executable ", scan->report); quoted(scan->report, path); fputc('\n', scan->report);
            ++scan->unknown;
        }
    }
    holy_elf_free(&elf);
    close(fd);
    ++scan->files;
    return !ferror(scan->report);
}

static int classify_tree(int parent, const char *prefix, struct scan_state *scan, unsigned depth)
{
    DIR *dir;
    struct dirent *entry;
    int copy, ok = 1;
    if (depth > 64 || scan->files + scan->links > 100000) return 0;
    copy = dup(parent);
    if (copy < 0) return 0;
    dir = fdopendir(copy);
    if (!dir) { close(copy); return 0; }
    errno = 0;
    while ((entry = readdir(dir))) {
        struct stat st;
        char *path;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        path = child_path(prefix, entry->d_name);
        if (!path || fstatat(parent, entry->d_name, &st, AT_SYMLINK_NOFOLLOW)) { free(path); ok = 0; break; }
        if (S_ISDIR(st.st_mode)) {
            int child = openat(parent, entry->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (child < 0 || !classify_tree(child, path, scan, depth + 1)) ok = 0;
            if (child >= 0) close(child);
        } else if (S_ISREG(st.st_mode)) ok = classify_file(parent, entry->d_name, path, scan);
        else if (S_ISLNK(st.st_mode)) {
            size_t capacity = 128;
            char *target = NULL;
            ssize_t got;
            for (;;) {
                char *next = realloc(target, capacity);
                if (!next) { ok = 0; break; }
                target = next;
                got = readlinkat(parent, entry->d_name, target, capacity - 1);
                if (got < 0) { ok = 0; break; }
                if ((size_t)got < capacity - 1) { target[got] = 0; break; }
                if (capacity > 1024 * 1024) { ok = 0; break; }
                capacity *= 2;
            }
            if (ok) {
                fputs(target[0] != '/' && holy_safe_link(path, target) ?
                      "symlink " : "path-view-required ", scan->report);
                quoted(scan->report, path); fputc(' ', scan->report);
                quoted(scan->report, target); fputc('\n', scan->report);
                ++scan->links;
            }
            free(target);
        } else {
            fputs("unsupported-node ", scan->report); quoted(scan->report, path); fputc('\n', scan->report);
            ++scan->unknown;
        }
        free(path);
        if (!ok || ferror(scan->report) || scan->files + scan->links > 100000) { ok = 0; break; }
        errno = 0;
    }
    if (errno) ok = 0;
    closedir(dir);
    return ok;
}

static int classify_appdir(int output)
{
    struct scan_state scan = {0};
    int appdir = openat(output, "AppDir", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int report = -1, ok = 0;
    if (appdir < 0) return 0;
    report = openat(output, "classification", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (report < 0) goto done;
    scan.report = fdopen(report, "w");
    if (!scan.report) goto done;
    report = -1;
    fputs("format holy-appimage-classification-1\n", scan.report);
    if (!classify_tree(appdir, "", &scan, 0)) goto done;
    fprintf(scan.report, "summary files %zu elf %zu scripts %zu links %zu unknown %zu\n",
            scan.files, scan.elfs, scan.scripts, scan.links, scan.unknown);
    if (fflush(scan.report) || fsync(fileno(scan.report)) || fclose(scan.report)) {
        scan.report = NULL; goto done;
    }
    scan.report = NULL;
    ok = !fsync(output);
done:
    if (scan.report) fclose(scan.report);
    if (report >= 0) close(report);
    if (!ok) unlinkat(output, "classification", 0);
    close(appdir);
    return ok;
}

int holy_appimage_extract(const char *input, const char *output)
{
    char *path = NULL, *original = NULL, *appdir = NULL, hash[65], copied_hash[65];
    const char *arch = NULL;
    off_t offset = 0;
    struct stat st;
    pid_t child;
    int dir = -1, copied = -1, status, result = snapshot(input, &path, &offset, hash, &arch);
    if (result) goto done;
    if (geteuid() == 0) { result = 6; fputs("holypkg: AppImage extraction requires an unprivileged user\n", stderr); goto done; }
    result = 1;
    if (mkdir(output, 0700)) goto done;
    dir = open(output, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || fstat(dir, &st) || st.st_uid != geteuid() || (st.st_mode & 0777) != 0700 ||
        !copy_original(path, dir)) goto done;
    copied = openat(dir, "original", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (copied < 0 || !digest_fd(copied, copied_hash) || strcmp(hash, copied_hash) ||
        mkdirat(dir, "AppDir", 0700)) goto done;
    close(copied); copied = -1;
    if (strlen(output) > SIZE_MAX - 16) goto done;
    original = malloc(strlen(output) + 10);
    appdir = malloc(strlen(output) + 8);
    if (!original || !appdir) goto done;
    sprintf(original, "%s/original", output);
    sprintf(appdir, "%s/AppDir", output);
    {
        char number[32];
        snprintf(number, sizeof number, "%lld", (long long)offset);
        child = fork();
        if (child < 0) goto done;
        if (!child) {
            execlp("unsquashfs", "unsquashfs", "-no-xattrs", "-offset", number,
                   "-d", appdir, original, (char *)NULL);
            _exit(127);
        }
    }
    while (waitpid(child, &status, 0) < 0) if (errno != EINTR) goto done;
    if (!WIFEXITED(status) || WEXITSTATUS(status)) { result = WIFEXITED(status) && WEXITSTATUS(status) == 127 ? 6 : 2; goto done; }
    if (!classify_appdir(dir)) { result = 3; goto done; }
    {
        int receipt = openat(dir, "conversion", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        FILE *file;
        if (receipt < 0) goto done;
        file = fdopen(receipt, "w");
        if (!file) { close(receipt); goto done; }
        fprintf(file, "format holy-appimage-extract-1\noriginal-sha256 %s\narch %s\nsquashfs-offset %lld\nmode extract\nstate extracted-unclassified\n", hash, arch, (long long)offset);
        if (fflush(file) || fsync(fileno(file))) { fclose(file); goto done; }
        if (fclose(file) || fsync(dir)) goto done;
    }
    printf("extracted %s arch %s original %s\n", output, arch, hash);
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: AppImage extraction incomplete (status %d); no installed state changed\n", result);
    if (copied >= 0) close(copied);
    if (dir >= 0) close(dir);
    free(original); free(appdir);
    if (path) { unlink(path); free(path); }
    return result;
}
