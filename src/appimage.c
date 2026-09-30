#define _POSIX_C_SOURCE 200809L
#include "appimage.h"
#include "elf.h"
#include "pack.h"
#include "stage.h"
#include "verify.h"
#include "version.h"

#include <openssl/evp.h>
#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
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
    size_t files, elfs, scripts, unknown, links, needed, path_views;
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
        size_t i;
        fputs("elf ", scan->report); quoted(scan->report, path);
        fprintf(scan->report, " %s %s %s\n", arch, libc, holy_elf_isa(&elf));
        if (elf.interpreter) {
            fputs("interpreter ", scan->report); quoted(scan->report, path);
            fputc(' ', scan->report); quoted(scan->report, elf.interpreter); fputc('\n', scan->report);
        }
        if (elf.soname) {
            fputs("soname ", scan->report); quoted(scan->report, path);
            fputc(' ', scan->report); quoted(scan->report, elf.soname); fputc('\n', scan->report);
        }
        if (elf.rpath) {
            fputs("rpath ", scan->report); quoted(scan->report, path);
            fputc(' ', scan->report); quoted(scan->report, elf.rpath); fputc('\n', scan->report);
        }
        if (elf.runpath) {
            fputs("runpath ", scan->report); quoted(scan->report, path);
            fputc(' ', scan->report); quoted(scan->report, elf.runpath); fputc('\n', scan->report);
        }
        for (i = 0; i < elf.needed_count; ++i) {
            fputs("needed ", scan->report); quoted(scan->report, path);
            fputc(' ', scan->report); quoted(scan->report, elf.needed[i]); fputc('\n', scan->report);
            ++scan->needed;
        }
        for (i = 0; i < elf.version_count; ++i) {
            if (elf.versions[i].weak) continue;
            fputs("version-required ", scan->report); quoted(scan->report, path);
            fputc(' ', scan->report); quoted(scan->report, elf.versions[i].provider);
            fputc(' ', scan->report); quoted(scan->report, elf.versions[i].name); fputc('\n', scan->report);
        }
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

/* a walk gets its own open file description. a duplicated descriptor shares the
   directory offset with the copy, so a second walk would start at the end. */
static int directory_copy(int parent)
{
    return openat(parent, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

static int classify_tree(int parent, const char *prefix, struct scan_state *scan, unsigned depth)
{
    DIR *dir;
    struct dirent *entry;
    int copy, ok = 1;
    if (depth > 64 || scan->files + scan->links > 100000) return 0;
    copy = directory_copy(parent);
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
                int path_view = target[0] == '/' || !holy_safe_link(path, target);
                fputs(path_view ? "path-view-required " : "symlink ", scan->report);
                quoted(scan->report, path); fputc(' ', scan->report);
                quoted(scan->report, target); fputc('\n', scan->report);
                ++scan->links;
                scan->path_views += path_view;
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
    struct stat entrypoint;
    int appdir = openat(output, "AppDir", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int report = -1, ok = 0;
    if (appdir < 0) return 0;
    report = openat(output, "classification", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (report < 0) goto done;
    scan.report = fdopen(report, "w");
    if (!scan.report) goto done;
    report = -1;
    fputs("format holy-appimage-classification-1\n", scan.report);
    if (fstatat(appdir, "AppRun", &entrypoint, AT_SYMLINK_NOFOLLOW) ||
        !(S_ISREG(entrypoint.st_mode) || S_ISLNK(entrypoint.st_mode)) ||
        (S_ISREG(entrypoint.st_mode) && !(entrypoint.st_mode & 0111)))
        fputs("entrypoint missing-or-nonexecutable\n", scan.report);
    else if (S_ISLNK(entrypoint.st_mode)) fputs("entrypoint link-review-required\n", scan.report);
    else fputs("entrypoint AppRun\n", scan.report);
    if (!classify_tree(appdir, "", &scan, 0)) goto done;
    fprintf(scan.report, "summary files %zu elf %zu scripts %zu links %zu needed %zu path-views %zu unknown %zu\n",
            scan.files, scan.elfs, scan.scripts, scan.links, scan.needed, scan.path_views, scan.unknown);
    fputs("runtime-probes plugins dlopen services graphics audio unknown\n", scan.report);
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

static int extract_image(const char *input, const char *output, const char *source)
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
        fprintf(file, "format holy-appimage-extract-1\nconverter holy-appimage-1\noriginal-sha256 %s\narch %s\nsquashfs-offset %lld\nmode extract\nverification unverified\n", hash, arch, (long long)offset);
        if (source) { fputs("source-name ", file); quoted(file, source); fputc('\n', file); }
        fputs("state extracted-unclassified\n", file);
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

int holy_appimage_extract(const char *input, const char *output)
{
    return extract_image(input, output, NULL);
}

/* the payload of one import. every byte is spooled into a single file, so the
   packer never opens a host path it was handed, and each entry keeps the digest
   the manifest records. */
struct payload {
    struct holy_stream_entry *entries;
    unsigned char (*digests)[32];
    size_t count, capacity;
    int spool;
    off_t written;
    /* a payload is installed as the installing user, so every entry this
       converter writes is attributed to that user rather than to whichever
       ids the extraction happened to produce */
    long long uid, gid;
    /* the directories the payload already declares; an installer places a file
       only under a directory the same manifest records */
    char **directories;
    size_t directory_count, directory_capacity;
};

struct name_set {
    char **items;
    size_t count, capacity;
};

/* what the payload needs and what it provides, plus the facts static inspection
   could not close */
struct closure {
    struct name_set needed, provided, absolute;
    size_t elfs, scripts, unknown, path_views, links, files;
    char arch[16], libc[16];
    int mixed, has_app;
};

/* a text buffer for the scripts and reports this converter writes itself */
struct text {
    char *data;
    size_t used, capacity;
};

static void free_entries(struct payload *out)
{
    size_t i;
    for (i = 0; i < out->count; ++i) {
        free((char *)out->entries[i].path);
        free((char *)out->entries[i].link);
    }
    for (i = 0; i < out->directory_count; ++i) free(out->directories[i]);
    free(out->directories);
    free(out->entries);
    free(out->digests);
    memset(out, 0, sizeof *out);
}

static void free_set(struct name_set *set)
{
    size_t i;
    for (i = 0; i < set->count; ++i) free(set->items[i]);
    free(set->items);
    memset(set, 0, sizeof *set);
}

static int set_add(struct name_set *set, const char *name)
{
    char **grown, *copy;
    size_t i;
    for (i = 0; i < set->count; ++i) if (!strcmp(set->items[i], name)) return 1;
    if (set->count == set->capacity) {
        size_t next = set->capacity ? set->capacity * 2 : 16;
        if (next > SIZE_MAX / sizeof *grown) return 0;
        grown = realloc(set->items, next * sizeof *grown);
        if (!grown) return 0;
        set->items = grown;
        set->capacity = next;
    }
    copy = strdup(name);
    if (!copy) return 0;
    set->items[set->count++] = copy;
    return 1;
}

static int set_has(const struct name_set *set, const char *name)
{
    size_t i;
    for (i = 0; i < set->count; ++i) if (!strcmp(set->items[i], name)) return 1;
    return 0;
}

static int entry_push(struct payload *out, const char *path, const char *link, unsigned mode,
                     long long offset, long long size, int directory)
{
    struct holy_stream_entry *grown, *slot;
    unsigned char (*digests)[32];
    if (out->count == out->capacity) {
        size_t next = out->capacity ? out->capacity * 2 : 64;
        if (next > SIZE_MAX / sizeof *grown) return 0;
        grown = realloc(out->entries, next * sizeof *grown);
        if (!grown) return 0;
        out->entries = grown;
        digests = realloc(out->digests, next * sizeof *digests);
        if (!digests) return 0;
        out->digests = digests;
        out->capacity = next;
    }
    slot = &out->entries[out->count];
    memset(slot, 0, sizeof *slot);
    memset(out->digests[out->count], 0, sizeof out->digests[0]);
    slot->path = strdup(path);
    if (!slot->path) return 0;
    if (link) {
        slot->link = strdup(link);
        if (!slot->link) return 0;
    }
    slot->mode = mode;
    slot->uid = out->uid;
    slot->gid = out->gid;
    slot->offset = offset;
    slot->size = size;
    slot->directory = directory;
    ++out->count;
    return 1;
}

static int entry_directory(struct payload *out, const char *path)
{
    char **grown;
    char *copy;
    if (out->directory_count == out->directory_capacity) {
        size_t next = out->directory_capacity ? out->directory_capacity * 2 : 32;
        if (next > SIZE_MAX / sizeof *grown) return 0;
        grown = realloc(out->directories, next * sizeof *grown);
        if (!grown) return 0;
        out->directories = grown;
        out->directory_capacity = next;
    }
    copy = strdup(path);
    if (!copy) return 0;
    out->directories[out->directory_count++] = copy;
    return entry_push(out, path, NULL, 0755, 0, 0, 1);
}

/* every directory an entry sits under is declared by the same manifest, because
   the installer refuses a file whose parents it did not place itself */
static int entry_parents(struct payload *out, const char *path)
{
    char built[1024];
    size_t at;
    for (at = 5; path[at]; ++at) {
        size_t i;
        if (path[at] != '/' || at >= sizeof built) continue;
        memcpy(built, path, at);
        built[at] = 0;
        for (i = 0; i < out->directory_count; ++i)
            if (!strcmp(out->directories[i], built)) break;
        if (i < out->directory_count) continue;
        if (!entry_directory(out, built)) return 0;
    }
    return 1;
}

static int entry_add(struct payload *out, const char *path, const char *link, unsigned mode,
                     long long offset, long long size, int directory)
{
    if (strncmp(path, "DATA/", 5)) return entry_push(out, path, link, mode, offset, size, directory);
    if (!entry_parents(out, path)) return 0;
    if (directory) {
        size_t i;
        for (i = 0; i < out->directory_count; ++i)
            if (!strcmp(out->directories[i], path)) return 1;
        return entry_directory(out, path);
    }
    return entry_push(out, path, link, mode, offset, size, directory);
}

static int text_reserve(struct text *out, size_t extra)
{
    if (out->used + extra + 1 > out->capacity) {
        size_t next = out->capacity ? out->capacity : 256;
        char *grown;
        while (next < out->used + extra + 1) {
            if (next > SIZE_MAX / 2) return 0;
            next *= 2;
        }
        grown = realloc(out->data, next);
        if (!grown) return 0;
        out->data = grown;
        out->capacity = next;
    }
    return 1;
}

static int text_add(struct text *out, const char *value)
{
    size_t length = strlen(value);
    if (!text_reserve(out, length)) return 0;
    memcpy(out->data + out->used, value, length + 1);
    out->used += length;
    return 1;
}

/* appends bytes to the spool file and reports where they landed */
static int spool_bytes(struct payload *out, const void *data, size_t size, long long *offset)
{
    const unsigned char *at = data;
    *offset = out->written;
    while (size) {
        ssize_t written = write(out->spool, at, size);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return 0;
        at += (size_t)written;
        size -= (size_t)written;
        out->written += written;
    }
    return 1;
}

static int digest_value(const void *data, size_t size, unsigned char digest[32])
{
    unsigned length = 0;
    if (EVP_Digest(data, size, digest, &length, EVP_sha256(), NULL) != 1 || length != 32) return 0;
    return 1;
}

/* copies one host file into the spool, hashing what it wrote */
static int spool_file(struct payload *out, int input, long long *offset, long long *size,
                      unsigned char digest[32])
{
    unsigned char buffer[65536], whole[32];
    EVP_MD_CTX *context;
    unsigned length = 0;
    off_t start = out->written;
    int ok = 0;
    context = EVP_MD_CTX_new();
    if (!context || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) goto done;
    for (;;) {
        ssize_t got = read(input, buffer, sizeof buffer);
        const unsigned char *at = buffer;
        size_t left;
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) goto done;
        if (!got) break;
        if (EVP_DigestUpdate(context, buffer, (size_t)got) != 1) goto done;
        left = (size_t)got;
        while (left) {
            ssize_t written = write(out->spool, at, left);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) goto done;
            at += (size_t)written;
            left -= (size_t)written;
            out->written += written;
        }
    }
    if (EVP_DigestFinal_ex(context, whole, &length) != 1 || length != sizeof whole) goto done;
    memcpy(digest, whole, sizeof whole);
    *offset = start;
    *size = (long long)(out->written - start);
    ok = 1;
done:
    EVP_MD_CTX_free(context);
    return ok;
}

static int spool_text(struct payload *out, struct text *body, const char *path, unsigned mode)
{
    unsigned char digest[32];
    long long offset;
    if (!digest_value(body->data, body->used, digest)) return 0;
    if (!spool_bytes(out, body->data, body->used, &offset)) return 0;
    if (!entry_add(out, path, NULL, mode, offset, (long long)body->used, 0)) return 0;
    memcpy(out->digests[out->count - 1], digest, sizeof digest);
    return 1;
}

/* the package name a converted image carries. a name the manifest cannot record
   is refused rather than rewritten, since it is what the operator will type. */
static int image_name(const char *input, char *name, size_t size)
{
    const char *leaf = strrchr(input, '/');
    size_t length, at;
    leaf = leaf ? leaf + 1 : input;
    length = strlen(leaf);
    if (length > 10 && !strcmp(leaf + length - 10, ".AppImage")) length -= 10;
    else if (length > 9 && !strcasecmp(leaf + length - 9, ".appimage")) length -= 9;
    if (!length || length >= size) return 0;
    memcpy(name, leaf, length);
    name[length] = 0;
    if (!isalnum((unsigned char)name[0])) return 0;
    for (at = 0; name[at]; ++at)
        if (!isalnum((unsigned char)name[at]) && name[at] != '-' && name[at] != '_' &&
            name[at] != '+' && name[at] != '.') return 0;
    return 1;
}

/* the desktop entry the image ships, and the version it states. the version is
   read from the payload only; one the payload does not state is zero. */
static int read_desktop(int appdir, struct text *content, char *version, size_t size)
{
    int copy = directory_copy(appdir);
    DIR *dir = copy < 0 ? NULL : fdopendir(copy);
    struct dirent *entry;
    int found = 0;
    if (!dir) return 0;
    while (!found && (entry = readdir(dir))) {
        size_t length = strlen(entry->d_name);
        char buffer[65536];
        struct stat st;
        int file, complete = 0;
        if (length < 8 || strcmp(entry->d_name + length - 8, ".desktop")) continue;
        if (fstatat(appdir, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) ||
            !S_ISREG(st.st_mode) || st.st_size <= 0 || st.st_size >= (off_t)sizeof buffer) continue;
        file = openat(appdir, entry->d_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (file < 0) continue;
        {
            ssize_t got = read(file, buffer, (size_t)st.st_size);
            if (got == st.st_size) { buffer[got] = 0; complete = 1; }
        }
        close(file);
        if (!complete || strncmp(buffer, "[Desktop Entry]", 15)) continue;
        {
            static const char *const keys[] = { "\nX-AppImage-Version=", "\nVersion=", NULL };
            size_t key;
            for (key = 0; keys[key]; ++key) {
                const char *at = strstr(buffer, keys[key]);
                size_t used;
                if (!at) continue;
                at += strlen(keys[key]);
                used = strcspn(at, "\r\n");
                if (!used || used + 1 >= size) continue;
                memcpy(version, at, used);
                version[used] = 0;
                found = 1;
                break;
            }
        }
        if (!text_add(content, buffer)) { closedir(dir); return 0; }
    }
    closedir(dir);
    return found;
}

/* the absolute path a link would name, with the components resolved. the link
   itself cannot travel in the payload, so this is the requirement it leaves. */
static char *link_target_path(const char *path, const char *target)
{
    struct text out = {0};
    size_t length = strlen(path) + strlen(target) + 2;
    char *joined = malloc(length);
    const char *p;
    size_t ends[256], count = 0;
    if (!joined) return NULL;
    if (target[0] == '/') snprintf(joined, length, "%s", target);
    else snprintf(joined, length, "%s/%s", path, target);
    for (p = joined; *p;) {
        const char *end = strchr(p, '/');
        size_t part = end ? (size_t)(end - p) : strlen(p);
        char piece[4096];
        if (part == 1 && p[0] == '.') {
            /* an empty component changes nothing */
        } else if (part == 2 && p[0] == '.' && p[1] == '.') {
            if (count) out.used = ends[--count];
        } else if (part) {
            if (part >= sizeof piece || count == sizeof ends / sizeof *ends ||
                !text_add(&out, "/")) {
                free(joined);
                free(out.data);
                return NULL;
            }
            memcpy(piece, p, part);
            piece[part] = 0;
            if (!text_add(&out, piece)) {
                free(joined);
                free(out.data);
                return NULL;
            }
            ends[count++] = out.used;
        }
        if (!end) break;
        p = end + 1;
    }
    free(joined);
    if (!out.used && !text_add(&out, "/")) { free(out.data); return NULL; }
    return out.data;
}

/* one file of the AppDir: its bytes, its ELF facts and what they require. the
   walk never follows a link, so an image cannot reach outside its own tree. */
static int collect_file(int parent, const char *name, const char *path,
                        struct payload *out, struct closure *closure)
{
    struct holy_elf_info elf;
    struct stat st;
    char link[4096];
    unsigned char digest[32];
    long long offset, size;
    int fd, parsed;
    /* the node is read through the directory, so a link in the image is carried
       as a link and never opened */
    if (fstatat(parent, name, &st, AT_SYMLINK_NOFOLLOW)) return 0;
    if (S_ISLNK(st.st_mode)) {
        ssize_t target = readlinkat(parent, name, link, sizeof link - 1);
        char *absolute;
        if (target < 0) return 0;
        link[target] = 0;
        ++closure->links;
        if (link[0] != '/' && holy_safe_link(path + 5, link))
            return entry_add(out, path, link, 0777, 0, 0, 0);
        /* a payload carries no absolute or escaping link, because neither the
           extractor nor the installer accepts one. the path the link named is
           recorded as a requirement, so nothing is dropped without a trace. */
        absolute = link_target_path(path + 5, link);
        ++closure->path_views;
        if (!absolute || !set_add(&closure->absolute, absolute)) {
            free(absolute);
            return 0;
        }
        free(absolute);
        return 1;
    }
    if (!S_ISREG(st.st_mode)) {
        ++closure->unknown;
        return entry_add(out, path, NULL, 0000, 0, 0, 0);
    }
    fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 0;
    if (fstat(fd, &st)) { close(fd); return 0; }
    if (!spool_file(out, fd, &offset, &size, digest)) { close(fd); return 0; }
    if (!entry_add(out, path, NULL, st.st_mode & 07777, offset, size, 0)) {
        close(fd);
        return 0;
    }
    memcpy(out->digests[out->count - 1], digest, sizeof digest);
    ++closure->files;
    parsed = holy_elf_read_fd(fd, &elf);
    if (!parsed) {
        const char *machine = holy_elf_machine(&elf), *runtime = holy_elf_runtime(&elf);
        size_t i;
        if (!strcmp(machine, "unknown") || !strcmp(runtime, "unknown")) {
            ++closure->unknown;
        } else {
            const char *known_arch = !strcmp(machine, "x86") ? "x86" : "x86_64";
            const char *known_libc = !strcmp(runtime, "glibc") || !strcmp(runtime, "musl") ?
                                     runtime : "nolibc";
            if (!closure->arch[0]) {
                snprintf(closure->arch, sizeof closure->arch, "%s", known_arch);
                snprintf(closure->libc, sizeof closure->libc, "%s", known_libc);
            } else if (strcmp(closure->arch, known_arch) || strcmp(closure->libc, known_libc)) {
                closure->mixed = 1;
            }
        }
        for (i = 0; i < elf.needed_count; ++i)
            if (elf.needed[i][0] && !strchr(elf.needed[i], '/') &&
                !set_add(&closure->needed, elf.needed[i])) {
                holy_elf_free(&elf);
                close(fd);
                return 0;
            }
        if (elf.soname && !set_add(&closure->provided, elf.soname)) {
            holy_elf_free(&elf);
            close(fd);
            return 0;
        }
        ++closure->elfs;
        holy_elf_free(&elf);
    } else {
        unsigned char head[2] = {0, 0};
        if (pread(fd, head, sizeof head, 0) == (ssize_t)sizeof head &&
            head[0] == '#' && head[1] == '!') ++closure->scripts;
        else if (st.st_mode & 0111 || parsed == 2) ++closure->unknown;
    }
    close(fd);
    return 1;
}

static int collect_tree(int parent, const char *prefix, const char *payload_prefix,
                        struct payload *out, struct closure *closure, unsigned depth)
{
    DIR *dir;
    struct dirent *entry;
    int copy, ok = 1;
    if (depth > 64 || closure->files + closure->links > 100000) return 0;
    copy = directory_copy(parent);
    if (copy < 0) return 0;
    dir = fdopendir(copy);
    if (!dir) { close(copy); return 0; }
    errno = 0;
    while ((entry = readdir(dir))) {
        struct stat st;
        char *path, *placed;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        path = child_path(prefix, entry->d_name);
        placed = path ? child_path(payload_prefix, entry->d_name) : NULL;
        if (!path || !placed || fstatat(parent, entry->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
            free(path); free(placed); ok = 0; break;
        }
        if (S_ISDIR(st.st_mode)) {
            int child = openat(parent, entry->d_name,
                               O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (child < 0 || !entry_add(out, placed, NULL, 0755, 0, 0, 1) ||
                !collect_tree(child, path, placed, out, closure, depth + 1)) ok = 0;
            if (child >= 0) close(child);
        } else if (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
            if (!collect_file(parent, entry->d_name, placed, out, closure)) ok = 0;
        } else {
            /* a device, a socket or a fifo has no place in a package payload */
            ++closure->unknown;
        }
        free(path);
        free(placed);
        if (!ok || closure->files + closure->links > 100000) { ok = 0; break; }
        errno = 0;
    }
    if (errno) ok = 0;
    closedir(dir);
    return ok;
}

/* the launcher starts the recorded payload in the run context the package owns,
   so the absolute paths the image expects come from that context. a path view
   is written only for a tree the image actually ships, because the context maps
   a private tree over a public path rather than merging the two. */
static int launcher_script(struct text *out, const char *name, const char *source,
                           const char *private, int has_app)
{
    return text_add(out, "#!/bin/sh\n"
                        "# a converted AppImage carries no sandbox of its own. this launcher starts\n"
                        "# the recorded payload in the run context the package owns, so the absolute\n"
                        "# paths the image expects come from that context instead of the host.\n"
                        "set -e\n"
                        "if [ \"$(id -u)\" = 0 ]; then\n"
                        "  echo '") &&
           text_add(out, name) &&
           text_add(out, ": the converted payload is not a sandbox; run it as your own user"
                         "' >&2\n  exit 1\nfi\n") &&
           (has_app ? text_add(out, "views=\nif [ -d /app ]; then\n  views='--view /app=/") &&
                      text_add(out, private) &&
                      text_add(out, "/appdir/app'\nfi\n") : text_add(out, "views=\n")) &&
           text_add(out, "exec holypkg run ") &&
           text_add(out, source) && text_add(out, ":") && text_add(out, name) &&
           text_add(out, " $views -- /") &&
           text_add(out, private) &&
           text_add(out, "/usr/bin/") &&
           text_add(out, name) && text_add(out, ".appimage \"$@\"\n");
}

/* the desktop entry the image ships, with Exec and TryExecup naming the launcher.
   only the first group is carried, because a desktop file the package owns
   cannot serve the actions its later groups declare. */
static int desktop_script(struct text *out, const char *content, const char *launcher)
{
    const char *cursor = content;
    int group = 0, copied = 0;
    for (;;) {
        const char *line_end = strchr(cursor, '\n');
        size_t length = line_end ? (size_t)(line_end - cursor) : strlen(cursor);
        int header = length && cursor[0] == '[';
        if (header && group) break;
        if (header) {
            if (strncmp(cursor, "[Desktop Entry]", 15)) break;
            ++group;
            if (!text_add(out, "[Desktop Entry]\n")) return 0;
            copied = 1;
        } else if (group && (!strncmp(cursor, "Exec=", 5) ||
                            !strncmp(cursor, "TryExecup=", 10))) {
            if (!text_add(out, cursor[0] == 'E' ? "Exec=" : "TryExecup=") ||
                !text_add(out, launcher) ||
                !text_add(out, cursor[0] == 'E' ? " %F\n" : "\n")) return 0;
        } else {
            char line[4096];
            if (length + 2 > sizeof line) return 0;
            memcpy(line, cursor, length);
            line[length] = 0;
            if (!text_add(out, line) || !text_add(out, "\n")) return 0;
            if (group) copied = 1;
        }
        if (!line_end) break;
        cursor = line_end + 1;
    }
    return copied;
}

static void hex_digest(FILE *out, const unsigned char digest[32])
{
    size_t i;
    for (i = 0; i < 32; ++i) fprintf(out, "%02x", (unsigned)digest[i]);
}

/* one manifest record per payload entry, in the form the packer writes */
static int write_manifest(FILE *manifest, const struct payload *out, size_t first)
{
    size_t i;
    for (i = first; i < out->count; ++i) {
        const struct holy_stream_entry *e = &out->entries[i];
        if (strncmp(e->path, "DATA/", 5)) continue;
        fputs(e->directory ? "dir " : e->link ? "symlink " : "file ", manifest);
        quoted(manifest, e->path + 5);
        fprintf(manifest, " %o - - %lld %lld %lld ", e->mode, e->uid, e->gid,
                e->directory || e->link ? 0LL : e->size);
        if (e->directory || e->link) fputc('-', manifest);
        else hex_digest(manifest, out->digests[i]);
        /* kind, hardlink group and link group; only a link carries a target */
        fputs(" none - -", manifest);
        if (e->link) { fputc(' ', manifest); quoted(manifest, e->link); }
        fputc('\n', manifest);
    }
    return !ferror(manifest);
}

/* reads a bounded report file the extraction left behind */
static int read_file(int dir, const char *name, struct text *out, size_t limit)
{
    char buffer[65536];
    int file = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (file < 0) return 0;
    for (;;) {
        ssize_t got = read(file, buffer, sizeof buffer);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) { close(file); return 0; }
        if (!got) break;
        if (out->used + (size_t)got > limit || !text_reserve(out, (size_t)got)) {
            close(file);
            return 0;
        }
        memcpy(out->data + out->used, buffer, (size_t)got);
        out->used += (size_t)got;
        out->data[out->used] = 0;
    }
    close(file);
    return 1;
}

/* the native package of one extracted image: the AppDir travels whole under a
   private path, the entry point and the launcher reach a public path, and every
   path the image hardcodes becomes a run context rather than a host fact. */
static int package_image(const char *input, const char *source, const char *output)
{
    static const char *const names[] = {
        "HOLY/meta", "HOLY/files", "HOLY/deps", "HOLY/provides", "HOLY/hooks",
        "HOLY/origin", "HOLY/transform"
    };
    static const char *const carried[] = { "classification", "conversion", NULL };
    struct payload out = {0};
    struct closure closure = {0};
    struct text launcher = {0}, desktop = {0};
    char *text[sizeof names / sizeof *names] = {0};
    size_t sizes[sizeof names / sizeof *names] = {0}, i, data_first;
    FILE *files[sizeof names / sizeof *names] = {0}, *log = NULL;
    char name[256], version[64] = "0", private[600], launcher_path[600];
    char digest[65], spool_name[43], artifact[700], path[900];
    const char *arch = "noarch", *libc = "nolibc";
    int dir = -1, appdir = -1, spool = -1, log_fd = -1, result = 1;
    int desktop_found, read_version, version_stated, order = 0, original = -1, published = 0;

    if (!image_name(input, name, sizeof name)) {
        fputs("holypkg: the image file name is not a package name\n", stderr);
        return 2;
    }
    dir = open(output, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) return 1;
    appdir = openat(dir, "AppDir", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (appdir < 0) goto done;
    version_stated = read_desktop(appdir, &desktop, version, sizeof version);
    desktop_found = desktop.used > 0;
    read_version = version_stated;
    /* a version the payload states has to be one the manifest can record */
    if (!read_version || !holy_version_compare(version, version, &order)) {
        snprintf(version, sizeof version, "0");
        read_version = 0;
    }
    original = openat(dir, "original", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (original < 0 || !digest_fd(original, digest)) goto done;
    for (i = 0; i < sizeof names / sizeof *names; ++i)
        if (!(files[i] = open_memstream(&text[i], &sizes[i]))) goto done;
    spool = holy_spool_at(dir, spool_name);
    if (spool < 0) goto done;
    out.spool = spool;
    out.uid = (long long)geteuid();
    out.gid = (long long)getegid();
    if (!entry_add(&out, "HOLY", NULL, 0755, 0, 0, 1) ||
        !entry_add(&out, "DATA", NULL, 0755, 0, 0, 1)) goto done;
    data_first = out.count;
    snprintf(private, sizeof private, "usr/lib/holy/private/%s", name);
    snprintf(path, sizeof path, "DATA/%s/appdir", private);
    if (!entry_add(&out, path, NULL, 0755, 0, 0, 1) ||
        !collect_tree(appdir, "", path, &out, &closure, 0)) goto done;
    {
        /* the entry point has to be reachable under a bin directory, because that
           is the only place the run launcher can name a file the package owns */
        struct stat entry_point;
        if (fstatat(appdir, "AppRun", &entry_point, AT_SYMLINK_NOFOLLOW)) {
            fputs("holypkg: the image has no AppRun entry point\n", stderr);
            result = 3;
            goto done;
        }
        if (!S_ISREG(entry_point.st_mode)) {
            fputs("holypkg: the AppRun entry point is not an ordinary file and needs review\n",
                  stderr);
            result = 3;
            goto done;
        }
        if (!(entry_point.st_mode & 0111)) {
            fputs("holypkg: the AppRun entry point is not executable\n", stderr);
            result = 2;
            goto done;
        }
        snprintf(path, sizeof path, "DATA/%s/usr/bin", private);
        if (!entry_add(&out, path, NULL, 0755, 0, 0, 1)) goto done;
        snprintf(path, sizeof path, "DATA/%s/usr/bin/%s.appimage", private, name);
        if (!entry_add(&out, path, "../../appdir/AppRun", 0777, 0, 0, 0)) goto done;
    }
    closure.has_app = !fstatat(appdir, "app", &(struct stat){0}, AT_SYMLINK_NOFOLLOW);
    snprintf(launcher_path, sizeof launcher_path, "/usr/bin/%s", name);
    if (!launcher_script(&launcher, name, source, private, closure.has_app)) goto done;
    snprintf(path, sizeof path, "DATA/usr/bin/%s", name);
    if (!spool_text(&out, &launcher, path, 0755)) goto done;
    if (desktop_found) {
        struct text fixed = {0};
        if (!desktop_script(&fixed, desktop.data, launcher_path)) { free(fixed.data); goto done; }
        snprintf(path, sizeof path, "DATA/usr/share/applications/%s.desktop", name);
        if (!spool_text(&out, &fixed, path, 0644)) { free(fixed.data); goto done; }
        free(fixed.data);
    }
    {
        /* the extraction reports travel with the package, so an installed copy
           can still be compared with the image it came from */
        for (i = 0; carried[i]; ++i) {
            struct text body = {0};
            int kept = read_file(dir, carried[i], &body, 1024 * 1024);
            if (kept && body.used) {
                snprintf(path, sizeof path, "DATA/usr/share/holy/%s/%s", name, carried[i]);
                kept = spool_text(&out, &body, path, 0644);
            }
            free(body.data);
            if (!kept) goto done;
        }
    }
    if (closure.mixed) {
        fputs("holypkg: the payload carries more than one architecture or runtime, and one\n"
              "       .holy records one, so the conversion stops here\n", stderr);
        result = 3;
        goto done;
    }
    if (closure.arch[0]) {
        arch = closure.arch;
        libc = closure.libc;
    }
    fputs("format holy-package-1\nname ", files[0]); quoted(files[0], name);
    fputs("\nversion ", files[0]); quoted(files[0], version);
    fputs("\nrelease \"1\"\nos linux\narch ", files[0]); quoted(files[0], arch);
    fputs("\nlibc ", files[0]); quoted(files[0], libc);
    fputs("\nx-version-family appimage\nx-source-family appimage\nx-converter holy-appimage-1\n"
          "x-source-arch ", files[0]);
    quoted(files[0], arch);
    fputs("\nx-appimage-mode extract\nx-appimage-entrypoint AppRun\n", files[0]);
    if (!write_manifest(files[1], &out, data_first)) goto done;
    for (i = 0; i < closure.needed.count; ++i) {
        char id[128];
        /* a library the payload carries is satisfied privately and names no
           requirement; the rest is what the target system has to provide */
        if (set_has(&closure.provided, closure.needed.items[i])) continue;
        snprintf(id, sizeof id, "appimage-needed-%zu", i);
        fputs("require ", files[2]); quoted(files[2], id);
        fputc(' ', files[2]); quoted(files[2], name);
        fputs(" soname ", files[2]); quoted(files[2], closure.needed.items[i]);
        fprintf(files[2], " %s %s any - ", arch, libc);
        quoted(files[2], "dt_needed");
        fputc(' ', files[2]); quoted(files[2], "appimage-payload");
        fputc('\n', files[2]);
    }
    for (i = 0; i < closure.absolute.count; ++i) {
        char id[128];
        /* a path an image link named that the payload cannot carry stays a
           requirement, so the installer reports it instead of losing it */
        snprintf(id, sizeof id, "appimage-link-%zu", i);
        fputs("require ", files[2]); quoted(files[2], id);
        fputc(' ', files[2]); quoted(files[2], name);
        fputs(" file ", files[2]); quoted(files[2], closure.absolute.items[i]);
        fputs(" any any any - ", files[2]);
        quoted(files[2], "symlink_target");
        fputc(' ', files[2]); quoted(files[2], "appimage-payload");
        fputc('\n', files[2]);
    }
    fputs("provide package ", files[3]); quoted(files[3], name);
    fprintf(files[3], " %s %s - ", arch, libc);
    quoted(files[3], "appimage-payload");
    fputc('\n', files[3]);
    for (i = 0; i < closure.provided.count; ++i) {
        fputs("provide soname ", files[3]); quoted(files[3], closure.provided.items[i]);
        fprintf(files[3], " %s %s - ", arch, libc);
        quoted(files[3], "appimage-payload");
        fputc('\n', files[3]);
    }
    fputs("format holy-import-origin-1\nfamily appimage\nsource-name ", files[5]);
    quoted(files[5], source);
    fputs("\noriginal-sha256 ", files[5]); quoted(files[5], digest);
    fputs("\nverification unverified\nconverter holy-appimage-1\noriginal-version ", files[5]);
    quoted(files[5], version);
    fputs("\nentrypoint AppRun\nmode extract\n", files[5]);
    /* this record describes changes already made to the payload; the installer
       never executes it */
    fputs("appimage AppDir extracted into a private tree\n", files[6]);
    fprintf(files[6], "launcher /usr/bin/%s starts the payload in the package run context\n", name);
    fprintf(files[6], "entry-point /usr/lib/holy/private/%s/usr/bin/%s.appimage -> "
                      "../../appdir/AppRun\n", name, name);
    if (closure.has_app)
        fprintf(files[6], "path-view /app from /usr/lib/holy/private/%s/appdir/app when the "
                          "target has /app\n", name);
    if (desktop_found)
        fprintf(files[6], "desktop-entry /usr/share/applications/%s.desktop exec-rewritten\n", name);
    fputs("sandbox dropped; the image-level FUSE mount is not reproduced\n", files[6]);
    fputs("desktop-database no hook; the distribution owns the cache\n", files[6]);
    if (ferror(files[0]) || ferror(files[2]) || ferror(files[3]) || ferror(files[5]) ||
        ferror(files[6])) goto done;
    for (i = 0; i < sizeof names / sizeof *names; ++i) {
        const char *body;
        size_t left;
        if (fflush(files[i])) goto done;
        if (!entry_add(&out, names[i], NULL, 0644, (long long)out.written,
                       (long long)sizes[i], 0)) goto done;
        body = text[i];
        left = sizes[i];
        while (left) {
            ssize_t written = write(spool, body, left);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) goto done;
            body += (size_t)written;
            left -= (size_t)written;
            out.written += written;
        }
    }
    for (i = 0; i < sizeof names / sizeof *names; ++i) {
        if (fclose(files[i])) { files[i] = NULL; goto done; }
        files[i] = NULL;
    }
    /* the report names every fact this conversion could not close */
    log_fd = openat(dir, "package", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (log_fd < 0) goto done;
    log = fdopen(log_fd, "w");
    if (!log) { log_fd = -1; goto done; }
    log_fd = -1;
    fputs("format holy-appimage-package-1\nconverter holy-appimage-1\n", log);
    fputs("status review-required\nmode extract\nentrypoint AppRun\n", log);
    fprintf(log, "name %s version %s arch %s libc %s\n", name, version, arch, libc);
    fputs("changed the launch conditions: the payload starts in the run context, not in the\n"
          "image runtime, so its own FUSE mount, its ARGV0 convention and its temporary\n"
          "directory never appear\n", log);
    fputs("dropped the image-level sandbox: portals, D-Bus filters and namespace isolation the\n"
          "image asked for are not carried, and the payload runs with the caller's context\n", log);
    fputs("runtime probes static inspection cannot close: dlopen plugins, D-Bus services,\n"
          "graphics drivers, audio and locale data\n", log);
    if (!version_stated)
        fputs("version the payload states none, so the package records zero\n", log);
    else if (!read_version)
        fputs("version the payload states one this manifest cannot record, so the package\n"
              "records zero\n", log);
    if (closure.path_views)
        fprintf(log, "path-view-required %zu links name an absolute or escaping target; a payload\n"
                     "carries neither, so each path it named is a recorded file requirement and the\n"
                     "run context or a private placement still has to resolve it\n",
                closure.path_views);
    if (closure.scripts)
        fprintf(log, "scripts %zu files carry an interpreter; nothing runs them at install\n",
                closure.scripts);
    if (closure.unknown)
        fprintf(log, "unknown %zu files are not an ELF this reader recognizes; they are carried\n"
                     "as payload and no requirement is derived from them\n", closure.unknown);
    if (desktop_found)
        fprintf(log, "desktop-entry rewritten to %s; the icon is not installed by this package\n",
                launcher_path);
    fprintf(log, "payload files %zu elf %zu links %zu provided %zu required %zu\n",
            closure.files, closure.elfs, closure.links, closure.provided.count,
            closure.needed.count);
    if (fflush(log) || fsync(fileno(log)) || fclose(log)) { log = NULL; goto done; }
    log = NULL;
    snprintf(artifact, sizeof artifact, "%s--%s--%s.holy", name, arch, libc);
    if (!holy_pack_stream(spool, out.entries, out.count, dir, artifact)) goto done;
    published = 1;
    {
        int packed = openat(dir, artifact, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (packed < 0 || !digest_fd(packed, digest)) {
            if (packed >= 0) close(packed);
            goto done;
        }
        close(packed);
    }
    printf("imported %s original ", artifact);
    quoted(stdout, digest);
    printf(" arch %s libc %s mode extract\n", arch, libc);
    result = 0;
done:
    if (log) fclose(log);
    if (log_fd >= 0) close(log_fd);
    for (i = 0; i < sizeof names / sizeof *names; ++i) if (files[i]) fclose(files[i]);
    for (i = 0; i < sizeof names / sizeof *names; ++i) free(text[i]);
    free_entries(&out);
    free_set(&closure.needed);
    free_set(&closure.provided);
    free_set(&closure.absolute);
    free(launcher.data);
    free(desktop.data);
    if (spool >= 0) {
        if (!published && spool_name[0]) unlinkat(dir, spool_name, 0);
        close(spool);
    }
    if (original >= 0) close(original);
    if (appdir >= 0) close(appdir);
    if (dir >= 0) close(dir);
    return result;
}

int holy_import_appimage(const char *input, const char *source, const char *output)
{
    size_t i;
    int result;
    if (!source || !*source || !strcmp(source, "local")) return 2;
    for (i = 0; source[i]; ++i)
        if ((unsigned char)source[i] <= 32 || source[i] == ':' ||
            source[i] == '/' || source[i] == '@') return 2;
    result = extract_image(input, output, source);
    if (result) return result;
    result = package_image(input, source, output);
    if (result) return result;
    fputs("holypkg: the package changes the launch conditions and carries no image-level\n"
          "       sandbox; read the package report before installing it\n", stderr);
    return 3;
}
