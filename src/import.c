#define _POSIX_C_SOURCE 200809L
#include "import.h"
#include "pack.h"
#include "package.h"
#include "verify.h"
#include "stage.h"
#include "elf.h"
#include "../backends/pacman.h"
#include "../backends/deb-version.h"

#include <archive.h>
#include <archive_entry.h>
#include <openssl/evp.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

struct foreign_entry {
    struct holy_stream_entry stream;
    char *original;
    unsigned char hash[32];
    int metadata, group, hardlink_group;
};

struct foreign_group {
    const char *arch, *libc;
};

struct foreign_input {
    FILE *spool;
    struct foreign_entry *entries;
    size_t count, capacity;
    struct foreign_group groups[7];
    size_t group_count;
    char *pkginfo;
    size_t pkginfo_size;
    int unknown;
};

enum foreign_archive_kind { FOREIGN_PACMAN, FOREIGN_DEB_CONTROL, FOREIGN_DEB_DATA };

struct deb_field { char *key, *value; size_t line; };
struct deb_metadata {
    char *name, *version, *arch;
    struct deb_field *fields;
    size_t count;
};

static void token(FILE *out, const char *value)
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

static char *joined(const char *a, const char *b)
{
    size_t x = strlen(a), y = strlen(b);
    char *out;
    if (x > SIZE_MAX - y - 2) return NULL;
    out = malloc(x + y + 2);
    if (out) { memcpy(out, a, x); out[x] = '/'; memcpy(out + x + 1, b, y + 1); }
    return out;
}

static char *normalized(const char *input, int directory)
{
    char *out, *p;
    size_t n;
    if (!input) return NULL;
    while (!strncmp(input, "./", 2)) input += 2;
    if (!*input || *input == '/') return NULL;
    out = strdup(input);
    if (!out) return NULL;
    n = strlen(out);
    if (directory && n && out[n-1] == '/') out[--n] = 0;
    if (!n) { free(out); return NULL; }
    for (p = out; *p; ) {
        char *slash = strchr(p, '/');
        size_t length = slash ? (size_t)(slash - p) : strlen(p);
        if (!length || (length == 1 && *p == '.') || (length == 2 && !memcmp(p, "..", 2))) {
            free(out); return NULL;
        }
        if (!slash) break;
        p = slash + 1;
        if (!*p) { free(out); return NULL; }
    }
    return out;
}

static struct archive *foreign_reader(const char *snapshot, int *result, int lzma)
{
    unsigned char header[8];
    int fd = open(snapshot, O_RDONLY | O_CLOEXEC), support;
    ssize_t got;
    struct archive *a = NULL;
    if (fd < 0) return NULL;
    got = read(fd, header, sizeof header); close(fd);
    if (got < 0 || !(a = archive_read_new())) return NULL;
    if (lzma) support = archive_read_support_filter_lzma(a);
    else if (got >= 4 && !memcmp(header, "\x28\xb5\x2f\xfd", 4)) support = archive_read_support_filter_zstd(a);
    else if (got >= 6 && !memcmp(header, "\xfd""7zXZ\0", 6)) support = archive_read_support_filter_xz(a);
    else if (got >= 3 && !memcmp(header, "BZh", 3)) support = archive_read_support_filter_bzip2(a);
    else if (got >= 2 && header[0] == 0x1f && header[1] == 0x8b) support = archive_read_support_filter_gzip(a);
    else if (got >= 4 && !memcmp(header, "\x04\x22\x4d\x18", 4)) support = archive_read_support_filter_lz4(a);
    else support = archive_read_support_filter_none(a);
    if (support != ARCHIVE_OK) {
        fputs("holypkg: built-in foreign archive codec unavailable\n", stderr);
        *result = 6; archive_read_free(a); return NULL;
    }
    if (archive_read_support_format_tar(a) != ARCHIVE_OK ||
        archive_read_open_filename(a, snapshot, 65536) != ARCHIVE_OK) {
        *result = 2; archive_read_free(a); return NULL;
    }
    return a;
}

static int add_group(struct foreign_input *input, const char *arch, const char *libc)
{
    size_t i;
    for (i = 0; i < input->group_count; ++i)
        if (!strcmp(input->groups[i].arch, arch) && !strcmp(input->groups[i].libc, libc)) return (int)i;
    if (input->group_count == sizeof input->groups / sizeof *input->groups) return -1;
    input->groups[i].arch = arch; input->groups[i].libc = libc;
    ++input->group_count;
    return (int)i;
}

static int metadata_path(const char *path)
{
    static const char *const names[] = {".PKGINFO", ".BUILDINFO", ".MTREE", ".INSTALL", ".CHANGELOG"};
    size_t i;
    for (i = 0; i < sizeof names / sizeof *names; ++i)
        if (!strcmp(path, names[i])) return 1;
    return 0;
}

static int collect_archive(const char *snapshot, struct foreign_input *input,
                           enum foreign_archive_kind kind, int lzma)
{
    struct archive *a = NULL;
    struct archive_entry *entry;
    int status, result = 1;
    if (!input->spool && !(input->spool = tmpfile())) goto done;
    if (!(a = foreign_reader(snapshot, &result, lzma))) goto done;
    while ((status = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        struct foreign_entry *e;
        const char *name = archive_entry_pathname(entry), *hardlink = archive_entry_hardlink(entry);
        mode_t type = archive_entry_filetype(entry);
        long long size = archive_entry_size(entry), total = 0;
        char buffer[65536];
        EVP_MD_CTX *hash = NULL;
        unsigned hash_size;
        FILE *elf = NULL;
        la_ssize_t got;
        result = 2;
        if (name && (!strcmp(name, ".") || !strcmp(name, "./")) && type == AE_IFDIR && !size) continue;
        if (input->count == 100000 || size < 0 || size > 1024LL * 1024 * 1024) goto done;
        if (archive_entry_xattr_count(entry) || archive_entry_acl_types(entry) ||
            (type != AE_IFREG && type != AE_IFDIR && type != AE_IFLNK && !(hardlink && type == 0))) {
            result = 6; goto done;
        }
        if (kind == FOREIGN_DEB_CONTROL && (type != AE_IFREG || hardlink)) goto done;
        if ((type == AE_IFDIR || type == AE_IFLNK || hardlink) && size) goto done;
        if (input->count == input->capacity) {
            size_t capacity = input->capacity ? input->capacity * 2 : 64;
            void *grown = realloc(input->entries, capacity * sizeof *input->entries);
            if (!grown) { result = 1; goto done; }
            input->entries = grown; input->capacity = capacity;
        }
        e = &input->entries[input->count++];
        memset(e, 0, sizeof *e); e->group = -1; e->hardlink_group = -1;
        e->original = normalized(name, type == AE_IFDIR);
        if (!e->original) goto done;
        if (kind == FOREIGN_DEB_CONTROL && strchr(e->original, '/')) goto done;
        e->metadata = kind == FOREIGN_DEB_CONTROL ||
                      (kind == FOREIGN_PACMAN && metadata_path(e->original));
        if (e->metadata && (type != AE_IFREG || hardlink)) goto done;
        if (kind == FOREIGN_DEB_CONTROL) {
            char *original = e->original;
            e->stream.path = joined("HOLY/foreign/deb", original);
            e->original = joined("@control", original);
            free(original);
        } else e->stream.path = e->metadata ?
            joined("HOLY/foreign/pacman", e->original + 1) : joined("DATA", e->original);
        e->stream.mode = archive_entry_perm(entry);
        e->stream.uid = archive_entry_uid(entry); e->stream.gid = archive_entry_gid(entry);
        e->stream.directory = type == AE_IFDIR;
        e->stream.size = size;
        e->stream.offset = (long long)ftello(input->spool);
        if (!e->stream.path || e->stream.offset < 0 ||
            e->stream.offset > 4LL * 1024 * 1024 * 1024 - size) goto done;
        if (archive_entry_uname(entry)) e->stream.owner = strdup(archive_entry_uname(entry));
        if (archive_entry_gname(entry)) e->stream.group = strdup(archive_entry_gname(entry));
        if ((archive_entry_uname(entry) && !e->stream.owner) ||
            (archive_entry_gname(entry) && !e->stream.group)) { result = 1; goto done; }
        if (type == AE_IFLNK) {
            const char *target = archive_entry_symlink(entry);
            if (!target || !*target || !holy_safe_link(e->original, target)) goto done;
            e->stream.link = strdup(target);
            if (!e->stream.link) { result = 1; goto done; }
        }
        if (hardlink) {
            char *target = normalized(hardlink, 0);
            if (!target) goto done;
            e->stream.hardlink = joined("DATA", target);
            free(target);
            if (!e->stream.hardlink) { result = 1; goto done; }
        }
        hash = EVP_MD_CTX_new();
        if (!hash || EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1) {
            EVP_MD_CTX_free(hash); result = 1; goto done;
        }
        while ((got = archive_read_data(a, buffer, sizeof buffer)) > 0) {
            if (got > size - total || fwrite(buffer, 1, (size_t)got, input->spool) != (size_t)got ||
                EVP_DigestUpdate(hash, buffer, (size_t)got) != 1) break;
            if (!total && !e->metadata) {
                if (got >= 4 && !memcmp(buffer, "\177ELF", 4)) {
                    elf = tmpfile();
                    if (!elf) break;
                } else if ((got >= 8 && !memcmp(buffer, "!<arch>\n", 8)) ||
                           (got >= 2 && !memcmp(buffer, "MZ", 2)) ||
                           ((e->stream.mode & 0111) && (got < 2 || memcmp(buffer, "#!", 2)))) input->unknown = 1;
            }
            if (elf && fwrite(buffer, 1, (size_t)got, elf) != (size_t)got) break;
            total += got;
        }
        if (got || total != size || EVP_DigestFinal_ex(hash, e->hash, &hash_size) != 1 || hash_size != 32) {
            EVP_MD_CTX_free(hash); if (elf) fclose(elf); goto done;
        }
        EVP_MD_CTX_free(hash);
        if (elf) {
            struct holy_elf_info info;
            int parsed;
            if (fflush(elf)) { fclose(elf); result = 1; goto done; }
            parsed = holy_elf_read_fd(fileno(elf), &info);
            if (!parsed && strcmp(holy_elf_machine(&info), "unknown") && strcmp(holy_elf_runtime(&info), "unknown"))
                e->group = add_group(input, holy_elf_machine(&info), holy_elf_runtime(&info));
            else input->unknown = 1;
            holy_elf_free(&info); fclose(elf);
            if (e->group < 0) input->unknown = 1;
        }
        if ((kind == FOREIGN_PACMAN && !strcmp(e->original, ".PKGINFO")) ||
            (kind == FOREIGN_DEB_CONTROL && !strcmp(e->original, "@control/control"))) {
            if (input->pkginfo || size > 1024 * 1024 || fflush(input->spool)) goto done;
            input->pkginfo = malloc((size_t)size + 1);
            if (!input->pkginfo) { result = 1; goto done; }
            if (pread(fileno(input->spool), input->pkginfo, (size_t)size, (off_t)e->stream.offset) != size) goto done;
            input->pkginfo[size] = 0; input->pkginfo_size = (size_t)size;
        }
    }
    if (status != ARCHIVE_EOF || (kind != FOREIGN_DEB_DATA && !input->pkginfo) ||
        fflush(input->spool) || fsync(fileno(input->spool))) goto done;
    result = 0;
done:
    if (a) archive_read_free(a);
    return result;
}

static int collect_deb(const char *snapshot, struct foreign_input *input)
{
    struct archive *ar = archive_read_new();
    struct archive_entry *entry;
    char magic[8];
    int fd = open(snapshot, O_RDONLY | O_CLOEXEC);
    int stage = 0, result = 2, status;
    if (!ar) { if (fd >= 0) close(fd); return 1; }
    if (fd < 0 || read(fd, magic, sizeof magic) != sizeof magic || memcmp(magic, "!<arch>\n", sizeof magic)) {
        if (fd >= 0) close(fd);
        goto done;
    }
    close(fd);
    if (archive_read_support_filter_none(ar) != ARCHIVE_OK ||
        archive_read_support_format_ar(ar) != ARCHIVE_OK ||
        archive_read_open_filename(ar, snapshot, 65536) != ARCHIVE_OK) goto done;
    while ((status = archive_read_next_header(ar, &entry)) == ARCHIVE_OK) {
        const char *name = archive_entry_pathname(entry);
        long long size = archive_entry_size(entry), total = 0;
        FILE *part = NULL;
        char descriptor[64], buffer[65536];
        la_ssize_t got;
        if (!name || size < 0 || size > 1024LL * 1024 * 1024) goto done;
        if (name[0] == '_' && stage && stage < 3) {
            if (archive_read_data_skip(ar) != ARCHIVE_OK) goto done;
            continue;
        }
        if (stage == 0) {
            char version[5];
            if (strcmp(name, "debian-binary") || size != 4 ||
                archive_read_data(ar, version, 4) != 4 || memcmp(version, "2.0\n", 4)) goto done;
            stage = 1;
            continue;
        }
        if (stage == 1) {
            if (strncmp(name, "control.tar", 11) ||
                (strcmp(name + 11, "") && strcmp(name + 11, ".gz") &&
                 strcmp(name + 11, ".xz") && strcmp(name + 11, ".zst")) || size > 16 * 1024 * 1024) goto done;
        } else if (stage == 2) {
            if (strncmp(name, "data.tar", 8) ||
                (strcmp(name + 8, "") && strcmp(name + 8, ".gz") &&
                 strcmp(name + 8, ".xz") && strcmp(name + 8, ".zst") &&
                 strcmp(name + 8, ".bz2") && strcmp(name + 8, ".lzma"))) goto done;
        } else goto done;
        part = tmpfile();
        if (!part) { result = 1; goto done; }
        while ((got = archive_read_data(ar, buffer, sizeof buffer)) > 0) {
            if (got > size - total || fwrite(buffer, 1, (size_t)got, part) != (size_t)got) break;
            total += got;
        }
        if (got || total != size || fflush(part) || fsync(fileno(part))) { fclose(part); goto done; }
        snprintf(descriptor, sizeof descriptor, "/proc/self/fd/%d", fileno(part));
        result = collect_archive(descriptor, input, stage == 1 ? FOREIGN_DEB_CONTROL : FOREIGN_DEB_DATA,
                                 stage == 2 && !strcmp(name + 8, ".lzma"));
        fclose(part);
        if (result) goto done;
        ++stage;
    }
    result = status == ARCHIVE_EOF && stage == 3 ? 0 : 2;
done:
    archive_read_free(ar);
    return result;
}

static void free_input(struct foreign_input *input)
{
    size_t i;
    for (i = 0; i < input->count; ++i) {
        struct foreign_entry *e = &input->entries[i];
        free(e->original); free((char *)e->stream.path); free((char *)e->stream.link);
        free((char *)e->stream.hardlink); free((char *)e->stream.owner); free((char *)e->stream.group);
    }
    free(input->entries); free(input->pkginfo);
    if (input->spool) fclose(input->spool);
}

static void free_deb(struct deb_metadata *meta)
{
    size_t i;
    for (i = 0; i < meta->count; ++i) { free(meta->fields[i].key); free(meta->fields[i].value); }
    free(meta->fields);
}

static int parse_deb(const char *control, size_t length, struct deb_metadata *meta)
{
    size_t offset = 0, line = 0;
    int blank = 0;
    if (memchr(control, 0, length)) return 0;
    while (offset < length) {
        const char *start = control + offset, *end = memchr(start, '\n', length - offset), *colon;
        size_t size = end ? (size_t)(end - start) : length - offset, i;
        struct deb_field *field;
        ++line;
        offset += size + (end != NULL);
        if (size && start[size-1] == '\r') --size;
        if (!size) { if (meta->count) blank = 1; continue; }
        if (blank) return 0;
        if (*start == ' ' || *start == '\t') {
            char *value;
            size_t old;
            if (!meta->count) return 0;
            field = &meta->fields[meta->count - 1]; old = strlen(field->value);
            if (old > SIZE_MAX - size - 2) return 0;
            value = realloc(field->value, old + size + 2);
            if (!value) return 0;
            field->value = value; value[old] = '\n';
            memcpy(value + old + 1, start, size); value[old + size + 1] = 0;
            continue;
        }
        colon = memchr(start, ':', size);
        if (!colon || colon == start || meta->count >= 4096) return 0;
        for (i = 0; i < (size_t)(colon - start); ++i)
            if (!((start[i] >= 'A' && start[i] <= 'Z') ||
                  (start[i] >= 'a' && start[i] <= 'z') || start[i] == '-')) return 0;
        for (i = 0; i < meta->count; ++i)
            if (strlen(meta->fields[i].key) == (size_t)(colon - start) &&
                !strncasecmp(meta->fields[i].key, start, (size_t)(colon - start))) return 0;
        i = (size_t)(colon - start);
        while (colon + 1 < start + size && (colon[1] == ' ' || colon[1] == '\t')) ++colon;
        {
            struct deb_field *grown = realloc(meta->fields, (meta->count + 1) * sizeof *grown);
            if (!grown) return 0;
            meta->fields = grown;
        }
        field = &meta->fields[meta->count++];
        field->key = strndup(start, i);
        field->value = strndup(colon + 1, (size_t)(start + size - colon - 1));
        field->line = line;
        if (!field->key || !field->value) return 0;
    }
    for (offset = 0; offset < meta->count; ++offset) {
        struct deb_field *field = &meta->fields[offset];
        if (!strcasecmp(field->key, "Package")) meta->name = field->value;
        if (!strcasecmp(field->key, "Version")) meta->version = field->value;
        if (!strcasecmp(field->key, "Architecture")) meta->arch = field->value;
    }
    if (!meta->name || !*meta->name || !meta->version || !*meta->version || !meta->arch || !*meta->arch) return 0;
    for (offset = 0; meta->name[offset]; ++offset)
        if (!((meta->name[offset] >= 'a' && meta->name[offset] <= 'z') ||
              (meta->name[offset] >= '0' && meta->name[offset] <= '9') ||
              (offset && (meta->name[offset] == '+' || meta->name[offset] == '-' ||
                          meta->name[offset] == '.')))) return 0;
    for (offset = 0; meta->version[offset]; ++offset)
        if ((unsigned char)meta->version[offset] <= 32 || (unsigned char)meta->version[offset] >= 127) return 0;
    for (offset = 0; meta->arch[offset]; ++offset)
        if (!((meta->arch[offset] >= 'a' && meta->arch[offset] <= 'z') ||
              (meta->arch[offset] >= '0' && meta->arch[offset] <= '9'))) return 0;
    {
        int order;
        if (!holy_deb_version_compare(meta->version, meta->version, &order)) return 0;
    }
    return 1;
}

static int input_hash(const char *path, char hex[65])
{
    FILE *file = fopen(path, "rb");
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    unsigned char digest[32], bytes[65536];
    unsigned length;
    size_t got, i;
    int ok = 0;
    if (!file || !hash || EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1) goto done;
    while ((got = fread(bytes, 1, sizeof bytes, file)))
        if (EVP_DigestUpdate(hash, bytes, got) != 1) goto done;
    if (ferror(file) || EVP_DigestFinal_ex(hash, digest, &length) != 1 || length != 32) goto done;
    for (i = 0; i < 32; ++i) snprintf(hex + i * 2, 3, "%02x", digest[i]);
    ok = 1;
done:
    if (file) fclose(file);
    EVP_MD_CTX_free(hash);
    return ok;
}

static int path_order(const void *a, const void *b)
{
    const struct foreign_entry *const *x = a, *const *y = b;
    return strcmp((*x)->original, (*y)->original);
}

static struct foreign_entry *find_path(struct foreign_entry **sorted, size_t count, const char *path)
{
    struct foreign_entry key = {0}, *pointer = &key;
    struct foreign_entry **found;
    key.original = (char *)path;
    found = bsearch(&pointer, sorted, count, sizeof *sorted, path_order);
    return found ? *found : NULL;
}

static int validate_paths(struct foreign_input *input)
{
    struct foreign_entry **sorted = malloc(input->count * sizeof *sorted);
    size_t i;
    int ok = 0;
    if (!sorted) return 0;
    for (i = 0; i < input->count; ++i) sorted[i] = &input->entries[i];
    qsort(sorted, input->count, sizeof *sorted, path_order);
    for (i = 0; i < input->count; ++i) {
        struct foreign_entry *e = sorted[i];
        char *parent, *slash;
        if (i && !strcmp(sorted[i-1]->original, e->original)) goto done;
        parent = strdup(e->original);
        if (!parent) goto done;
        for (slash = strchr(parent, '/'); slash; slash = strchr(slash + 1, '/')) {
            struct foreign_entry *ancestor;
            *slash = 0;
            ancestor = find_path(sorted, input->count, parent);
            *slash = '/';
            if (ancestor && !ancestor->stream.directory) { free(parent); goto done; }
        }
        free(parent);
        if (e->stream.hardlink) {
            struct foreign_entry *target = find_path(sorted, input->count, e->stream.hardlink + 5);
            if (!target || target->metadata || target->stream.directory || target->stream.link ||
                target->stream.hardlink || e->stream.mode != target->stream.mode ||
                e->stream.uid != target->stream.uid || e->stream.gid != target->stream.gid) goto done;
            e->hardlink_group = (int)(target - input->entries);
            target->hardlink_group = e->hardlink_group;
            e->group = target->group; memcpy(e->hash, target->hash, 32);
        }
    }
    ok = 1;
done:
    free(sorted);
    return ok;
}

static int append_text(struct foreign_input *input, struct holy_stream_entry *entry,
                        const char *path, const char *text, size_t size)
{
    memset(entry, 0, sizeof *entry);
    entry->path = path; entry->mode = 0644; entry->owner = entry->group = "root";
    entry->offset = (long long)ftello(input->spool); entry->size = (long long)size;
    return entry->offset >= 0 && fwrite(text, 1, size, input->spool) == size;
}

static void hex_hash(FILE *file, const unsigned char hash[32])
{
    size_t i;
    for (i = 0; i < 32; ++i) fprintf(file, "%02x", hash[i]);
}

static int write_manifest(FILE *manifest, const struct foreign_input *input, size_t index)
{
    const struct foreign_entry *e = &input->entries[index];
    const struct holy_stream_entry *s = &e->stream;
    long long size = s->hardlink ? input->entries[e->hardlink_group].stream.size : s->size;
    fprintf(manifest, "%s ", s->directory ? "dir" : s->link ? "symlink" : s->hardlink ? "hardlink" : "file");
    token(manifest, e->original);
    fprintf(manifest, " %o ", s->mode); token(manifest, s->owner ? s->owner : "-");
    fputc(' ', manifest); token(manifest, s->group ? s->group : "-");
    fprintf(manifest, " %lld %lld %lld ", s->uid, s->gid, size);
    if (s->directory || s->link) fputc('-', manifest); else hex_hash(manifest, e->hash);
    fputs(" none - ", manifest);
    if (e->hardlink_group >= 0) fprintf(manifest, "pacman-hardlink-%d", e->hardlink_group);
    else fputc('-', manifest);
    if (s->link || s->hardlink) { fputc(' ', manifest); token(manifest, s->link ? s->link : s->hardlink + 5); }
    fputc('\n', manifest);
    return !ferror(manifest);
}

static int belongs(const struct foreign_input *input, size_t index, int group)
{
    const struct foreign_entry *e = &input->entries[index];
    size_t i, length;
    int has_children = 0;
    if (e->metadata) return 1;
    if (!e->stream.directory) return e->group == group;
    length = strlen(e->original);
    for (i = 0; i < input->count; ++i) {
        const struct foreign_entry *child = &input->entries[i];
        if (i == index || child->metadata || child->stream.directory) continue;
        if (!strncmp(child->original, e->original, length) && child->original[length] == '/') {
            has_children = 1;
            if (child->group == group) return 1;
        }
    }
    return !has_children && group == (int)input->group_count - 1;
}

static void requirement(FILE *out, const char *id, const char *consumer, const char *kind,
                         const char *name, const char *arch, const char *libc,
                         const char *relation, const char *version, const char *original,
                         const char *evidence)
{
    const char *fields[] = {id, consumer, kind, name, arch, libc, relation, version, original, evidence};
    size_t i;
    fputs("require", out);
    for (i = 0; i < sizeof fields / sizeof *fields; ++i) { fputc(' ', out); token(out, fields[i]); }
    fputc('\n', out);
}

static int deb_relations(FILE *out, const char *consumer, const struct deb_field *field,
                         int claims)
{
    char *copy = strdup(field->value), *cursor, *buffer = NULL, *original = NULL;
    const char *seen[4096];
    size_t size = 0, index = 0, seen_count = 0;
    FILE *temporary = NULL;
    int ok = 0;
    if (!copy || !(temporary = open_memstream(&buffer, &size))) goto done;
    cursor = copy;
    while (*cursor) {
        char *segment = cursor, *comma = strchr(cursor, ','), *end, *name_end, *version = NULL;
        const char *relation = "any";
        char id[64];
        size_t i;
        if (comma) { *comma = 0; cursor = comma + 1; if (!*cursor) goto done; }
        else cursor += strlen(cursor);
        while (*segment == ' ' || *segment == '\t' || *segment == '\n') ++segment;
        end = segment + strlen(segment);
        while (end > segment && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\n')) *--end = 0;
        if (end == segment || ++index > 4096) goto done;
        if ((size_t)(end - segment) > 65536 || !(original = strdup(segment))) goto done;
        name_end = segment;
        while (*name_end && *name_end != ' ' && *name_end != '\t' &&
               *name_end != '\n' && *name_end != '(') ++name_end;
        for (i = 0; segment + i < name_end; ++i)
            if (!((segment[i] >= 'a' && segment[i] <= 'z') ||
                  (segment[i] >= '0' && segment[i] <= '9') ||
                  (i && (segment[i] == '+' || segment[i] == '-' || segment[i] == '.')))) goto done;
        if (name_end == segment) goto done;
        if (*name_end) {
            char *p = name_end;
            if (*p == '(') *p++ = 0;
            else {
                *p++ = 0;
                while (*p == ' ' || *p == '\t' || *p == '\n') ++p;
                if (*p++ != '(') goto done;
            }
            while (*p == ' ' || *p == '\t') ++p;
            if (p[0] == '<' && p[1] == '<') relation = "lt";
            else if (p[0] == '<' && p[1] == '=') relation = "le";
            else if (p[0] == '=') relation = "eq";
            else if (p[0] == '>' && p[1] == '=') relation = "ge";
            else if (p[0] == '>' && p[1] == '>') relation = "gt";
            else goto done;
            p += !strcmp(relation, "eq") ? 1 : 2;
            while (*p == ' ' || *p == '\t') ++p;
            version = p;
            while (*p && *p != ' ' && *p != '\t' && *p != ')') ++p;
            if (p == version) goto done;
            if (*p == ')') { *p++ = 0; if (*p) goto done; }
            else {
                if (!*p) goto done;
                *p++ = 0;
                while (*p == ' ' || *p == '\t') ++p;
                if (*p++ != ')' || *p) goto done;
            }
            {
                int order;
                if (!holy_deb_version_compare(version, version, &order)) goto done;
            }
        } else *name_end = 0;
        if (claims) {
            if (strcmp(relation, "any") && strcmp(relation, "eq")) goto done;
            for (i = 0; i < seen_count; ++i) if (!strcmp(seen[i], segment)) goto done;
            seen[seen_count++] = segment;
            fputs("provide package ", temporary); token(temporary, segment);
            fputs(" any any ", temporary); token(temporary, version ? version : "-");
            fputs(" deb:Provides\n", temporary);
        } else {
            snprintf(id, sizeof id, "deb-%zu-%zu", field->line, index);
            requirement(temporary, id, consumer, "package", segment, "any", "any", relation,
                        version ? version : "-", original, "deb:Depends");
        }
        if (ferror(temporary)) goto done;
        free(original); original = NULL;
    }
    if (!index) goto done;
    if (fclose(temporary)) { temporary = NULL; goto done; }
    temporary = NULL;
    if (fwrite(buffer, 1, size, out) != size) goto done;
    ok = 1;
done:
    if (temporary) fclose(temporary);
    free(original); free(copy); free(buffer);
    return ok;
}

static int write_output(struct foreign_input *input, const struct holy_pacman_metadata *meta,
                         const struct deb_metadata *deb,
                         const char *source, const char *hash, const char *output, int output_fd, FILE *receipt, int group)
{
    static const char *const names[] = {
        "HOLY/meta", "HOLY/files", "HOLY/deps", "HOLY/provides", "HOLY/hooks", "HOLY/origin", "HOLY/transform"
    };
    char *text[7] = {0}, *path = NULL, *filename = NULL;
    size_t sizes[7] = {0}, i, count = 0, length;
    FILE *files[7] = {0};
    struct holy_stream_entry *entries = NULL;
    int ok = 0, aggregate = input->group_count == 1 || group == (int)input->group_count - 1;
    const char *arch = input->groups[group].arch, *libc = input->groups[group].libc;
    const char *family = deb ? "deb" : "pacman";
    const char *name = deb ? deb->name : meta->name;
    const char *version = deb ? deb->version : meta->version;
    const char *source_arch = deb ? deb->arch : meta->arch;
    for (i = 0; i < 7; ++i) if (!(files[i] = open_memstream(&text[i], &sizes[i]))) goto done;
    fputs("format holy-package-1\nname ", files[0]); token(files[0], name);
    fputs("\nversion ", files[0]); token(files[0], version);
    fprintf(files[0], "\nrelease 1\nos linux\narch %s\nlibc %s\nx-version-family %s\nx-source-arch ", arch, libc, family);
    token(files[0], source_arch); fputc('\n', files[0]);
    fprintf(files[5], "format holy-import-origin-1\nfamily %s\nsource-name ", family);
    token(files[5], source);
    fprintf(files[5], "\noriginal-sha256 %s\nverification unverified\nconverter holy-%s-1\noriginal-version ", hash, family);
    token(files[5], version); fputc('\n', files[5]);
    if (input->group_count > 1) {
        fprintf(files[6], "split %s %s %s %s\n", family, hash, arch, libc);
        for (i = 0; i < input->group_count; ++i) {
            char id[64];
            if ((aggregate && (int)i == group) || (!aggregate && i != input->group_count - 1)) continue;
            snprintf(id, sizeof id, "split-%zu", i);
            requirement(files[2], id, name, "package", name, input->groups[i].arch,
                        input->groups[i].libc, "any", "-", name, "import-output");
        }
    }
    for (i = 0; !deb && i < meta->count; ++i) {
        const struct holy_pacman_field *field = &meta->fields[i];
        char id[64];
        fputs("pkginfo ", files[5]); token(files[5], field->key); fputc(' ', files[5]);
        token(files[5], field->value); fprintf(files[5], " %zu\n", field->line);
        if (!aggregate) continue;
        snprintf(id, sizeof id, "pacman-%zu", field->line);
        if (field->kind == HOLY_PACMAN_DEPEND) {
            const struct holy_pacman_relation *r = &field->relation;
            requirement(files[2], id, meta->name,
                        r->kind == HOLY_PACMAN_PACKAGE ? "package" : "foreign",
                        r->kind == HOLY_PACMAN_PACKAGE ? r->name : field->value,
                        "any", "any", r->kind == HOLY_PACMAN_PACKAGE ? r->comparison : "any",
                        r->kind == HOLY_PACMAN_PACKAGE ? r->version : "-", field->value, "pacman");
        } else if (field->kind == HOLY_PACMAN_PROVIDE && field->relation.kind == HOLY_PACMAN_PACKAGE) {
            fputs("provide package ", files[3]); token(files[3], field->relation.name);
            fputs(" any any ", files[3]); token(files[3], field->relation.version); fputs(" pacman\n", files[3]);
        } else if (field->kind == HOLY_PACMAN_CONFLICT || field->kind == HOLY_PACMAN_REPLACE ||
                   field->kind == HOLY_PACMAN_UNKNOWN ||
                   (field->kind == HOLY_PACMAN_EXTRA && strncmp(field->value, "pkgtype=", 8)) ||
                   (field->kind == HOLY_PACMAN_PROVIDE && field->relation.kind != HOLY_PACMAN_PACKAGE)) {
            requirement(files[2], id, meta->name, "foreign", field->value,
                        "any", "any", "any", "-", field->value, field->key);
        }
    }
    for (i = 0; deb && i < deb->count; ++i) {
        const struct deb_field *field = &deb->fields[i];
        char id[64];
        fputs("control ", files[5]); token(files[5], field->key); fputc(' ', files[5]);
        token(files[5], field->value); fprintf(files[5], " %zu\n", field->line);
        if (!aggregate || !strcasecmp(field->key, "Package") || !strcasecmp(field->key, "Version") ||
            !strcasecmp(field->key, "Architecture") || !strcasecmp(field->key, "Description") ||
            !strcasecmp(field->key, "Maintainer") || !strcasecmp(field->key, "Homepage") ||
            !strcasecmp(field->key, "Section") || !strcasecmp(field->key, "Priority") ||
            !strcasecmp(field->key, "Installed-Size") || !strcasecmp(field->key, "Source")) continue;
        if (!strcasecmp(field->key, "Depends") && deb_relations(files[2], name, field, 0)) continue;
        if (!strcasecmp(field->key, "Provides") && deb_relations(files[3], name, field, 1)) continue;
        snprintf(id, sizeof id, "deb-%zu", field->line);
        requirement(files[2], id, name, "foreign", field->value, "any", "any", "any", "-",
                    field->value, field->key);
    }
    entries = calloc(input->count + 11, sizeof *entries);
    if (!entries) goto done;
    for (i = 0; i < input->count; ++i) {
        const struct foreign_entry *e = &input->entries[i];
        if (!belongs(input, i, group)) continue;
        if (!e->metadata && !write_manifest(files[1], input, i)) goto done;
        if (aggregate && !strcmp(e->original, ".INSTALL")) {
            fputs("foreign-script pacman /bin/sh HOLY/foreign/pacman/INSTALL sha256 ", files[4]);
            hex_hash(files[4], e->hash);
            fputs(" review-required\n", files[4]);
        }
        if (deb && aggregate && (!strcmp(e->original, "@control/preinst") ||
            !strcmp(e->original, "@control/postinst") || !strcmp(e->original, "@control/prerm") ||
            !strcmp(e->original, "@control/postrm"))) {
            fputs("foreign-script deb unknown ", files[4]); token(files[4], e->stream.path);
            fputs(" sha256 ", files[4]); hex_hash(files[4], e->hash);
            fputs(" review-required\n", files[4]);
        } else if (deb && aggregate && e->metadata &&
                   strcmp(e->original, "@control/control") && strcmp(e->original, "@control/md5sums")) {
            char id[64];
            snprintf(id, sizeof id, "deb-control-%zu", i);
            requirement(files[2], id, name, "foreign", e->original, "any", "any", "any", "-",
                        e->original, "deb-control-file");
        }
    }
    entries[count++] = (struct holy_stream_entry){"HOLY", NULL, NULL, "root", "root", 0, 0, 0, 0, 0755, 1};
    for (i = 0; i < 7; ++i) {
        int failed = ferror(files[i]);
        if (fclose(files[i])) failed = 1;
        files[i] = NULL;
        if (failed || !append_text(input, &entries[count++], names[i], text[i], sizes[i])) goto done;
    }
    entries[count++] = (struct holy_stream_entry){"HOLY/foreign", NULL, NULL, "root", "root", 0, 0, 0, 0, 0755, 1};
    entries[count++] = (struct holy_stream_entry){deb ? "HOLY/foreign/deb" : "HOLY/foreign/pacman", NULL, NULL, "root", "root", 0, 0, 0, 0, 0755, 1};
    for (i = 0; i < input->count; ++i)
        if (input->entries[i].metadata) entries[count++] = input->entries[i].stream;
    entries[count++] = (struct holy_stream_entry){"DATA", NULL, NULL, "root", "root", 0, 0, 0, 0, 0755, 1};
    for (i = 0; i < input->count; ++i)
        if (!input->entries[i].metadata && belongs(input, i, group)) entries[count++] = input->entries[i].stream;
    if (fflush(input->spool) || fsync(fileno(input->spool))) goto done;
    length = strlen(name) + strlen(arch) + strlen(libc) + 10;
    filename = malloc(length);
    if (!filename) goto done;
    snprintf(filename, length, "%s--%s--%s.holy", name, arch, libc);
    path = joined(output, filename);
    if (!path || !holy_pack_stream(fileno(input->spool), entries, count, output_fd, filename)) goto done;
    {
        char descriptor[64], digest[65];
        int fd = openat(output_fd, filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) goto done;
        snprintf(descriptor, sizeof descriptor, "/proc/self/fd/%d", fd);
        ok = input_hash(descriptor, digest);
        close(fd);
        if (!ok) goto done;
        ok = 0;
        fputs("output ", receipt); token(receipt, filename);
        fprintf(receipt, " %s %s %s\n", digest, arch, libc);
        if (ferror(receipt)) goto done;
    }
    printf("imported "); token(stdout, path); printf(" original %s arch %s libc %s\n", hash, arch, libc);
    ok = 1;
done:
    for (i = 0; i < 7; ++i) { if (files[i]) fclose(files[i]); free(text[i]); }
    free(entries); free(filename); free(path);
    return ok;
}

static int preserve_original(const char *snapshot, int output)
{
    char buffer[65536];
    int input = open(snapshot, O_RDONLY | O_CLOEXEC);
    int fd = openat(output, "original", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600), ok = 0;
    ssize_t got;
    if (input < 0 || fd < 0) goto done;
    while ((got = read(input, buffer, sizeof buffer)) != 0) {
        size_t offset = 0;
        if (got < 0) { if (errno == EINTR) continue; goto done; }
        while (offset < (size_t)got) {
            ssize_t n = write(fd, buffer + offset, (size_t)got - offset);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) goto done;
            offset += (size_t)n;
        }
    }
    ok = !fsync(fd) && !fsync(output);
done:
    if (input >= 0) close(input);
    if (fd >= 0) close(fd);
    return ok;
}

int holy_import_pacman(const char *input_path, const char *source, const char *output)
{
    struct foreign_input input = {0};
    struct holy_pacman_metadata metadata = {0};
    struct holy_pacman_error error = {0};
    struct stat st;
    char *snapshot = NULL, hash[65], temporary[43] = {0};
    FILE *receipt = NULL;
    int input_fd = -1, output_fd = -1, result = 1, common;
    size_t i;
    if (!*source || !strcmp(source, "local")) return 2;
    for (i = 0; source[i]; ++i)
        if ((unsigned char)source[i] <= 32 || source[i] == ':' || source[i] == '/' || source[i] == '@') return 2;
    input_fd = open(input_path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (input_fd < 0 || fstat(input_fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        st.st_size > 1024LL * 1024 * 1024) { result = 6; goto done; }
    snapshot = holy_stage_fd(input_fd, "holy-import");
    if (!snapshot || !input_hash(snapshot, hash) || mkdir(output, 0700)) goto done;
    output_fd = open(output, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (output_fd < 0 || fstat(output_fd, &st) || st.st_uid != geteuid() ||
        (st.st_mode & 0777) != 0700 || !preserve_original(snapshot, output_fd)) goto done;
    result = collect_archive(snapshot, &input, FOREIGN_PACMAN, 0);
    if (result) goto done;
    if (!validate_paths(&input) || !holy_pacman_parse(input.pkginfo, input.pkginfo_size, &metadata, &error)) {
        if (error.message) fprintf(stderr, "holypkg: PKGINFO:%zu: %s\n", error.line, error.message);
        result = 2; goto done;
    }
    result = 3;
    if (input.unknown) { fputs("holypkg: unknown payload ABI or executable format requires classification\n", stderr); goto done; }
    if (metadata.package_type && strcmp(metadata.package_type, "pkg") &&
        strcmp(metadata.package_type, "split") && strcmp(metadata.package_type, "debug")) {
        fputs("holypkg: source or unknown package type requires review\n", stderr); goto done;
    }
    for (i = 0; i < metadata.count; ++i) if (metadata.fields[i].kind == HOLY_PACMAN_BACKUP) {
        fputs("holypkg: pacman backup paths require config-manifest support\n", stderr); goto done;
    }
    if (!input.group_count) common = add_group(&input, "noarch", "nolibc");
    else if (input.group_count == 1) common = 0;
    else common = add_group(&input, "noarch", "nolibc");
    if (common < 0) { result = 6; goto done; }
    for (i = 0; i < input.count; ++i) if (input.entries[i].group < 0) input.entries[i].group = common;
    result = 1;
    {
        int fd = holy_temporary_at(output_fd, temporary);
        if (fd < 0) goto done;
        receipt = fdopen(fd, "w");
        if (!receipt) { close(fd); goto done; }
    }
    fprintf(receipt, "format holy-import-record-1\nfamily pacman\nconverter holy-pacman-1\noriginal-sha256 %s\nsource-name ", hash);
    token(receipt, source); fputs("\nverification unverified\n", receipt);
    for (i = 0; i < input.group_count; ++i)
        if (!write_output(&input, &metadata, NULL, source, hash, output, output_fd, receipt, (int)i)) goto done;
    fputs("state complete\n", receipt);
    if (fflush(receipt) || fsync(fileno(receipt))) goto done;
    if (fclose(receipt)) { receipt = NULL; goto done; }
    receipt = NULL;
    if (linkat(output_fd, temporary, output_fd, "conversion", 0) || fsync(output_fd)) goto done;
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: pacman import incomplete (status %d); no installed state changed\n", result);
    if (receipt) fclose(receipt);
    if (output_fd >= 0) { if (*temporary) unlinkat(output_fd, temporary, 0); close(output_fd); }
    if (input_fd >= 0) close(input_fd);
    if (snapshot) { unlink(snapshot); free(snapshot); }
    holy_pacman_free(&metadata); free_input(&input);
    return result;
}

int holy_import_deb(const char *input_path, const char *source, const char *output)
{
    struct foreign_input input = {0};
    struct deb_metadata metadata = {0};
    struct stat st;
    char *snapshot = NULL, hash[65], temporary[43] = {0};
    FILE *receipt = NULL;
    int input_fd = -1, output_fd = -1, result = 1, common;
    size_t i;
    if (!*source || !strcmp(source, "local")) return 2;
    for (i = 0; source[i]; ++i)
        if ((unsigned char)source[i] <= 32 || source[i] == ':' || source[i] == '/' || source[i] == '@') return 2;
    input_fd = open(input_path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (input_fd < 0 || fstat(input_fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        st.st_size > 1024LL * 1024 * 1024) { result = 6; goto done; }
    snapshot = holy_stage_fd(input_fd, "holy-import");
    if (!snapshot || !input_hash(snapshot, hash) || mkdir(output, 0700)) goto done;
    output_fd = open(output, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (output_fd < 0 || fstat(output_fd, &st) || st.st_uid != geteuid() ||
        (st.st_mode & 0777) != 0700 || !preserve_original(snapshot, output_fd)) goto done;
    result = collect_deb(snapshot, &input);
    if (result) goto done;
    if (!validate_paths(&input) || !parse_deb(input.pkginfo, input.pkginfo_size, &metadata)) {
        fputs("holypkg: malformed deb control or payload paths\n", stderr);
        result = 2; goto done;
    }
    result = 3;
    if (input.unknown) { fputs("holypkg: unknown payload ABI or executable format requires classification\n", stderr); goto done; }
    if (strcmp(metadata.arch, "all") && strcmp(metadata.arch, "amd64") && strcmp(metadata.arch, "i386")) {
        fputs("holypkg: unsupported Debian architecture requires classification\n", stderr); goto done;
    }
    for (i = 0; i < input.count; ++i) if (!strcmp(input.entries[i].original, "@control/conffiles")) {
        fputs("holypkg: Debian conffiles require config-manifest support\n", stderr); goto done;
    }
    for (i = 0; i < input.group_count; ++i) {
        const char *arch = input.groups[i].arch;
        if ((!strcmp(metadata.arch, "all") && strcmp(arch, "noarch")) ||
            (!strcmp(metadata.arch, "amd64") && strcmp(arch, "x86_64")) ||
            (!strcmp(metadata.arch, "i386") && strcmp(arch, "x86"))) {
            fputs("holypkg: Debian architecture differs from payload ELF\n", stderr); goto done;
        }
    }
    if (!input.group_count) common = add_group(&input, "noarch", "nolibc");
    else if (input.group_count == 1) common = 0;
    else common = add_group(&input, "noarch", "nolibc");
    if (common < 0) { result = 6; goto done; }
    for (i = 0; i < input.count; ++i) if (input.entries[i].group < 0) input.entries[i].group = common;
    result = 1;
    {
        int fd = holy_temporary_at(output_fd, temporary);
        if (fd < 0) goto done;
        receipt = fdopen(fd, "w");
        if (!receipt) { close(fd); goto done; }
    }
    fprintf(receipt, "format holy-import-record-1\nfamily deb\nconverter holy-deb-1\noriginal-sha256 %s\nsource-name ", hash);
    token(receipt, source); fputs("\nverification unverified\n", receipt);
    for (i = 0; i < input.group_count; ++i)
        if (!write_output(&input, NULL, &metadata, source, hash, output, output_fd, receipt, (int)i)) goto done;
    fputs("state complete\n", receipt);
    if (fflush(receipt) || fsync(fileno(receipt))) goto done;
    if (fclose(receipt)) { receipt = NULL; goto done; }
    receipt = NULL;
    if (linkat(output_fd, temporary, output_fd, "conversion", 0) || fsync(output_fd)) goto done;
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: deb import incomplete (status %d); no installed state changed\n", result);
    if (receipt) fclose(receipt);
    if (output_fd >= 0) { if (*temporary) unlinkat(output_fd, temporary, 0); close(output_fd); }
    if (input_fd >= 0) close(input_fd);
    if (snapshot) { unlink(snapshot); free(snapshot); }
    free_deb(&metadata); free_input(&input);
    return result;
}
