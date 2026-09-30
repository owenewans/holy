#define _POSIX_C_SOURCE 200809L
#include "image.h"
#include "elf.h"
#include "verify.h"

#include <openssl/evp.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int holy_image_directory(int parent)
{
    return openat(parent, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

char *holy_image_path(const char *parent, const char *name)
{
    size_t a = strlen(parent), b = strlen(name);
    char *path;
    if (a > SIZE_MAX - b - 2) return NULL;
    path = malloc(a + b + 2);
    if (path) sprintf(path, "%s%s%s", parent, a ? "/" : "", name);
    return path;
}

void holy_quoted(FILE *out, const char *value)
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

void holy_text_free(struct holy_text *text)
{
    free(text->data);
    memset(text, 0, sizeof *text);
}

static int text_reserve(struct holy_text *out, size_t extra)
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

int holy_text_add(struct holy_text *out, const char *value)
{
    size_t length = strlen(value);
    if (!text_reserve(out, length)) return 0;
    memcpy(out->data + out->used, value, length + 1);
    out->used += length;
    return 1;
}

int holy_text_read(int dir, const char *name, struct holy_text *out, size_t limit)
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

const char *holy_names_get(const struct holy_names *set, size_t index)
{
    return index < set->count ? set->names.data + set->offsets[index] : NULL;
}

int holy_names_has(const struct holy_names *set, const char *name)
{
    size_t i;
    for (i = 0; i < set->count; ++i)
        if (!strcmp(holy_names_get(set, i), name)) return 1;
    return 0;
}

/* a name keeps its own terminator in the set, so each offset names a C string */
static int names_append(struct holy_names *set, const char *name)
{
    size_t length = strlen(name), offset = set->names.used;
    if (!text_reserve(&set->names, length)) return 0;
    memcpy(set->names.data + offset, name, length + 1);
    set->names.used = offset + length + 1;
    return 1;
}

int holy_names_add(struct holy_names *set, const char *name)
{
    size_t next, offset;
    if (holy_names_has(set, name)) return 1;
    if (set->count == set->capacity) {
        size_t *offsets;
        next = set->capacity ? set->capacity * 2 : 16;
        if (next > SIZE_MAX / sizeof *offsets) return 0;
        offsets = realloc(set->offsets, next * sizeof *offsets);
        if (!offsets) return 0;
        set->offsets = offsets;
        set->capacity = next;
    }
    offset = set->names.used;
    if (!names_append(set, name)) return 0;
    set->offsets[set->count++] = offset;
    return 1;
}

static void names_free(struct holy_names *set)
{
    holy_text_free(&set->names);
    free(set->offsets);
    memset(set, 0, sizeof *set);
}

void holy_payload_free(struct holy_payload *payload)
{
    size_t i;
    for (i = 0; i < payload->count; ++i) {
        free((char *)payload->entries[i].path);
        free((char *)payload->entries[i].link);
    }
    free(payload->entries);
    free(payload->digests);
    names_free(&payload->directories);
    names_free(&payload->needed);
    names_free(&payload->provided);
    names_free(&payload->absolute);
    memset(payload, 0, sizeof *payload);
}

static int entry_push(struct holy_payload *out, const char *path, const char *link,
                      unsigned mode, long long offset, long long size, int directory)
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

static int entry_directory(struct holy_payload *out, const char *path)
{
    return holy_names_add(&out->directories, path) &&
           entry_push(out, path, NULL, 0755, 0, 0, 1);
}

/* every directory an entry sits under is declared by the same manifest, because
   the installer refuses a file whose parents it did not place itself */
static int entry_parents(struct holy_payload *out, const char *path)
{
    char built[1024];
    size_t at;
    for (at = 5; path[at]; ++at) {
        if (path[at] != '/' || at >= sizeof built) continue;
        memcpy(built, path, at);
        built[at] = 0;
        if (holy_names_has(&out->directories, built)) continue;
        if (!entry_directory(out, built)) return 0;
    }
    return 1;
}

int holy_payload_add(struct holy_payload *out, const char *path, const char *link,
                     unsigned mode, long long offset, long long size, int directory)
{
    if (strncmp(path, "DATA/", 5))
        return entry_push(out, path, link, mode, offset, size, directory);
    if (!entry_parents(out, path)) return 0;
    if (directory) {
        if (holy_names_has(&out->directories, path)) return 1;
        return entry_directory(out, path);
    }
    return entry_push(out, path, link, mode, offset, size, directory);
}

int holy_payload_spool_file(struct holy_payload *out, int input, long long *offset,
                            long long *size, unsigned char digest[32])
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

static int spool_bytes(struct holy_payload *out, const void *data, size_t size,
                       long long *offset)
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

int holy_payload_add_text(struct holy_payload *out, struct holy_text *body, const char *path,
                          unsigned mode)
{
    unsigned char digest[32];
    unsigned length = 0;
    long long offset;
    if (EVP_Digest(body->data, body->used, digest, &length, EVP_sha256(), NULL) != 1 ||
        length != 32) return 0;
    if (!spool_bytes(out, body->data, body->used, &offset)) return 0;
    if (!holy_payload_add(out, path, NULL, mode, offset, (long long)body->used, 0)) return 0;
    memcpy(out->digests[out->count - 1], digest, sizeof digest);
    return 1;
}

char *holy_payload_link_target(const char *path, const char *target)
{
    struct holy_text out = {0};
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
                !holy_text_add(&out, "/")) {
                free(joined);
                holy_text_free(&out);
                return NULL;
            }
            memcpy(piece, p, part);
            piece[part] = 0;
            if (!holy_text_add(&out, piece)) {
                free(joined);
                holy_text_free(&out);
                return NULL;
            }
            ends[count++] = out.used;
        }
        if (!end) break;
        p = end + 1;
    }
    free(joined);
    if (!out.used && !holy_text_add(&out, "/")) { holy_text_free(&out); return NULL; }
    return out.data;
}

/* one file of the image: its bytes, its ELF facts and what they require */
static int collect_file(struct holy_payload *out, int parent, const char *name,
                        const char *path)
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
        ++out->links;
        if (link[0] != '/' && holy_safe_link(path + 5, link))
            return holy_payload_add(out, path, link, 0777, 0, 0, 0);
        /* a payload carries no absolute or escaping link, because neither the
           extractor nor the installer accepts one. the path the link named is
           recorded as a requirement, so nothing is dropped without a trace. */
        absolute = holy_payload_link_target(path + 5, link);
        ++out->path_views;
        if (!absolute || !holy_names_add(&out->absolute, absolute)) {
            free(absolute);
            return 0;
        }
        free(absolute);
        return 1;
    }
    if (!S_ISREG(st.st_mode)) {
        ++out->unknown;
        return holy_payload_add(out, path, NULL, 0000, 0, 0, 0);
    }
    fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 0;
    if (fstat(fd, &st)) { close(fd); return 0; }
    if (!holy_payload_spool_file(out, fd, &offset, &size, digest)) { close(fd); return 0; }
    if (!holy_payload_add(out, path, NULL, st.st_mode & 07777, offset, size, 0)) {
        close(fd);
        return 0;
    }
    memcpy(out->digests[out->count - 1], digest, sizeof digest);
    ++out->files;
    parsed = holy_elf_read_fd(fd, &elf);
    if (!parsed) {
        const char *machine = holy_elf_machine(&elf), *runtime = holy_elf_runtime(&elf);
        size_t i;
        if (!strcmp(machine, "unknown") || !strcmp(runtime, "unknown")) {
            ++out->unknown;
        } else {
            const char *known_arch = !strcmp(machine, "x86") ? "x86" : "x86_64";
            const char *known_libc = !strcmp(runtime, "glibc") || !strcmp(runtime, "musl") ?
                                     runtime : HOLY_PAYLOAD_NOLIBC;
            if (!out->arch[0]) {
                snprintf(out->arch, sizeof out->arch, "%s", known_arch);
                snprintf(out->libc, sizeof out->libc, "%s", known_libc);
            } else if (strcmp(out->arch, known_arch) || strcmp(out->libc, known_libc)) {
                out->mixed = 1;
            }
        }
        for (i = 0; i < elf.needed_count; ++i)
            if (elf.needed[i][0] && !strchr(elf.needed[i], '/') &&
                !holy_names_add(&out->needed, elf.needed[i])) {
                holy_elf_free(&elf);
                close(fd);
                return 0;
            }
        if (elf.soname && !holy_names_add(&out->provided, elf.soname)) {
            holy_elf_free(&elf);
            close(fd);
            return 0;
        }
        ++out->elfs;
        holy_elf_free(&elf);
    } else {
        unsigned char head[2] = {0, 0};
        if (pread(fd, head, sizeof head, 0) == (ssize_t)sizeof head &&
            head[0] == '#' && head[1] == '!') ++out->scripts;
        else if (st.st_mode & 0111 || parsed == 2) ++out->unknown;
    }
    close(fd);
    return 1;
}

int holy_payload_walk(struct holy_payload *out, int parent, const char *prefix,
                      const char *payload_prefix, unsigned depth)
{
    DIR *dir;
    struct dirent *entry;
    int copy, ok = 1;
    if (depth > 64 || out->files + out->links > 100000) return 0;
    copy = holy_image_directory(parent);
    if (copy < 0) return 0;
    dir = fdopendir(copy);
    if (!dir) { close(copy); return 0; }
    errno = 0;
    while ((entry = readdir(dir))) {
        struct stat st;
        char *path, *placed;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        path = holy_image_path(prefix, entry->d_name);
        placed = path ? holy_image_path(payload_prefix, entry->d_name) : NULL;
        if (!path || !placed || fstatat(parent, entry->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
            free(path); free(placed); ok = 0; break;
        }
        if (S_ISDIR(st.st_mode)) {
            int child = openat(parent, entry->d_name,
                               O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (child < 0 || !holy_payload_add(out, placed, NULL, 0755, 0, 0, 1) ||
                !holy_payload_walk(out, child, path, placed, depth + 1)) ok = 0;
            if (child >= 0) close(child);
        } else if (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
            if (!collect_file(out, parent, entry->d_name, placed)) ok = 0;
        } else {
            /* a device, a socket or a fifo has no place in a package payload */
            ++out->unknown;
        }
        free(path);
        free(placed);
        if (!ok || out->files + out->links > 100000) { ok = 0; break; }
        errno = 0;
    }
    if (errno) ok = 0;
    closedir(dir);
    return ok;
}

int holy_payload_manifest(FILE *manifest, const struct holy_payload *out, size_t first)
{
    size_t i, at;
    for (i = first; i < out->count; ++i) {
        const struct holy_stream_entry *e = &out->entries[i];
        if (strncmp(e->path, "DATA/", 5)) continue;
        fputs(e->directory ? "dir " : e->link ? "symlink " : "file ", manifest);
        holy_quoted(manifest, e->path + 5);
        fprintf(manifest, " %o - - %lld %lld %lld ", e->mode, e->uid, e->gid,
                e->directory || e->link ? 0LL : e->size);
        if (e->directory || e->link) fputc('-', manifest);
        else for (at = 0; at < 32; ++at) fprintf(manifest, "%02x", (unsigned)out->digests[i][at]);
        /* kind, hardlink group and link group; only a link carries a target */
        fputs(" none - -", manifest);
        if (e->link) { fputc(' ', manifest); holy_quoted(manifest, e->link); }
        fputc('\n', manifest);
    }
    return !ferror(manifest);
}

int holy_payload_records(struct holy_payload *payload, FILE *files[7], char *text[7],
                         size_t sizes[7])
{
    static const char *const names[] = {
        "HOLY/meta", "HOLY/files", "HOLY/deps", "HOLY/provides", "HOLY/hooks",
        "HOLY/origin", "HOLY/transform"
    };
    size_t i;
    for (i = 0; i < 7; ++i) {
        const char *body;
        size_t left;
        /* the memstream sizes settle when it is flushed */
        if (fflush(files[i])) return 0;
        body = text[i];
        left = sizes[i];
        if (!holy_payload_add(payload, names[i], NULL, 0644, (long long)payload->written,
                               (long long)left, 0)) return 0;
        while (left) {
            ssize_t written = write(payload->spool, body, left);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) return 0;
            body += (size_t)written;
            left -= (size_t)written;
            payload->written += written;
        }
        if (fclose(files[i])) { files[i] = NULL; return 0; }
        files[i] = NULL;
    }
    return 1;
}
