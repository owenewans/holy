#define _POSIX_C_SOURCE 200809L
#include "import.h"
#include "pack.h"
#include "package.h"
#include "verify.h"
#include "deps.h"
#include "stage.h"
#include "elf.h"
#include "provides.h"
#include "version.h"
#include "../backends/pacman.h"
#include "../backends/deb-version.h"
#include "../backends/apk-version.h"
#include "../backends/apk.h"
#include "../backends/xbps-version.h"
#include "../backends/rpm-version.h"

#include <archive.h>
#include <archive_entry.h>
#include <openssl/evp.h>
#ifdef HOLY_HAVE_RPM
#include <rpm/rpmlib.h>
#include <rpm/rpmts.h>
#include <rpm/rpmio.h>
#include <rpm/header.h>
#include <rpm/rpmtag.h>
#include <rpm/rpmtd.h>
#include <rpm/rpmds.h>
#include <rpm/rpmfiles.h>
#include <rpm/rpmfi.h>
#include <rpm/rpmarchive.h>
#include <rpm/rpmpgp.h>
#endif
#ifdef __TINYC__
/* libplist's fallback pragma is an error under tcc's strict warning mode. */
#define __llvm__ 1
#endif
#include <plist/plist.h>
#ifdef __TINYC__
#undef __llvm__
#endif
#include <ctype.h>
#include <elf.h>
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
    char *soname;
    unsigned char hash[32];
    int metadata, group, hardlink_group, config;
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

enum foreign_archive_kind { FOREIGN_PACMAN, FOREIGN_DEB_CONTROL, FOREIGN_DEB_DATA,
                            FOREIGN_SLACKWARE, FOREIGN_APK_SIGNATURE,
                            FOREIGN_APK_CONTROL, FOREIGN_APK_DATA, FOREIGN_XBPS, FOREIGN_RPM };

struct rpm_metadata { char *name, *version, *release, *arch;
#ifdef HOLY_HAVE_RPM
                      Header header;
#endif
};

struct deb_field { char *key, *value; size_t line; };
struct deb_metadata {
    char *name, *version, *arch;
    struct deb_field *fields;
    size_t count;
};

struct slack_metadata { char *name, *version, *arch, *build; int lzma; };

struct apk_field { char *key, *value; size_t line; };
struct apk_metadata {
    char *name, *version, *arch, *datahash;
    struct apk_field *fields;
    size_t count;
};

struct xbps_metadata {
    plist_t props;
    char *name, *version, *release, *arch;
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
    if ((archive_read_support_format_tar(a) != ARCHIVE_OK) ||
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
        if ((kind == FOREIGN_DEB_CONTROL || kind == FOREIGN_APK_CONTROL ||
             kind == FOREIGN_APK_SIGNATURE) && (type != AE_IFREG || hardlink)) goto done;
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
        if ((kind == FOREIGN_DEB_CONTROL || kind == FOREIGN_APK_CONTROL ||
             kind == FOREIGN_APK_SIGNATURE) && strchr(e->original, '/')) goto done;
        if (kind == FOREIGN_APK_SIGNATURE && strncmp(e->original, ".SIGN.", 6)) goto done;
        if (kind == FOREIGN_APK_CONTROL && e->original[0] != '.') goto done;
        e->metadata = kind == FOREIGN_DEB_CONTROL || kind == FOREIGN_APK_CONTROL ||
                      kind == FOREIGN_APK_SIGNATURE ||
                      (kind == FOREIGN_XBPS && (!strcmp(e->original, "props.plist") ||
                       !strcmp(e->original, "files.plist") || !strcmp(e->original, "INSTALL") ||
                       !strcmp(e->original, "REMOVE"))) ||
                      (kind == FOREIGN_PACMAN && metadata_path(e->original)) ||
                      (kind == FOREIGN_SLACKWARE &&
                       (!strcmp(e->original, "install") || !strncmp(e->original, "install/", 8)));
        if (e->metadata && (type != AE_IFREG || hardlink) &&
            !(kind == FOREIGN_SLACKWARE && !strcmp(e->original, "install") && type == AE_IFDIR)) goto done;
        if (kind == FOREIGN_DEB_CONTROL) {
            char *original = e->original;
            e->stream.path = joined("HOLY/foreign/deb", original);
            e->original = joined("@control", original);
            free(original);
        } else if (kind == FOREIGN_APK_CONTROL || kind == FOREIGN_APK_SIGNATURE)
            e->stream.path = joined("HOLY/foreign/apk", e->original);
        else if (kind == FOREIGN_XBPS && e->metadata)
            e->stream.path = joined("HOLY/foreign/xbps", e->original);
        else if (kind == FOREIGN_SLACKWARE && e->metadata)
            e->stream.path = joined("HOLY/foreign/slackware",
                                    !strcmp(e->original, "install") ? "" : e->original + 8);
        else e->stream.path = e->metadata ?
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
            if (!parsed && e->group >= 0 && info.type == ET_DYN && info.has_dynamic &&
                info.soname && !strchr(info.soname, '/')) {
                e->soname = strdup(info.soname);
                if (!e->soname) {
                    holy_elf_free(&info); fclose(elf); result = 1; goto done;
                }
            }
            holy_elf_free(&info); fclose(elf);
            if (e->group < 0) input->unknown = 1;
        }
        if (((kind == FOREIGN_PACMAN || kind == FOREIGN_APK_CONTROL) &&
             !strcmp(e->original, ".PKGINFO")) ||
            (kind == FOREIGN_XBPS && !strcmp(e->original, "props.plist")) ||
            (kind == FOREIGN_DEB_CONTROL && !strcmp(e->original, "@control/control"))) {
            if (input->pkginfo || size > 1024 * 1024 || fflush(input->spool)) goto done;
            input->pkginfo = malloc((size_t)size + 1);
            if (!input->pkginfo) { result = 1; goto done; }
            if (pread(fileno(input->spool), input->pkginfo, (size_t)size, (off_t)e->stream.offset) != size) goto done;
            input->pkginfo[size] = 0; input->pkginfo_size = (size_t)size;
        }
    }
    if (status != ARCHIVE_EOF ||
        ((kind == FOREIGN_PACMAN || kind == FOREIGN_DEB_CONTROL ||
          kind == FOREIGN_APK_CONTROL || kind == FOREIGN_XBPS) && !input->pkginfo) ||
        fflush(input->spool) || fsync(fileno(input->spool))) goto done;
    result = 0;
done:
    if (a) archive_read_free(a);
    return result;
}

static int deb_version(struct archive *ar, long long size)
{
    char data[4096];
    size_t used = 0, i;
    if (size < 4 || size > (long long)sizeof data) return 0;
    while (used < (size_t)size) {
        la_ssize_t got = archive_read_data(ar, data + used, (size_t)size - used);
        if (got <= 0) return 0;
        used += (size_t)got;
    }
    if (data[0] != '2' || data[1] != '.' || data[size - 1] != '\n' ||
        memchr(data, 0, (size_t)size)) return 0;
    for (i = 2; i < (size_t)size && data[i] >= '0' && data[i] <= '9'; ++i) {}
    return i > 2 && i < (size_t)size && data[i] == '\n';
}

static int deb_codec_matches(FILE *part, const char *suffix)
{
    unsigned char header[6];
    ssize_t size = pread(fileno(part), header, sizeof header, 0);
    int gzip, xz, zstd, bzip2, lz4;
    if (size < 0) return 0;
    gzip = size >= 2 && header[0] == 0x1f && header[1] == 0x8b;
    xz = size >= 6 && !memcmp(header, "\xfd""7zXZ\0", 6);
    zstd = size >= 4 && !memcmp(header, "\x28\xb5\x2f\xfd", 4);
    bzip2 = size >= 3 && !memcmp(header, "BZh", 3);
    lz4 = size >= 4 && !memcmp(header, "\x04\x22\x4d\x18", 4);
    if (lz4) return 0;
    if (!strcmp(suffix, ".gz")) return gzip;
    if (!strcmp(suffix, ".xz")) return xz;
    if (!strcmp(suffix, ".zst")) return zstd;
    if (!strcmp(suffix, ".bz2")) return bzip2;
    return !gzip && !xz && !zstd && !bzip2;
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
        result = 2;
        if (!name || size < 0 || size > 1024LL * 1024 * 1024) goto done;
        if (name[0] == '_' && stage && stage < 3) {
            if (archive_read_data_skip(ar) != ARCHIVE_OK) goto done;
            continue;
        }
        if (stage == 0) {
            if (strcmp(name, "debian-binary") || !deb_version(ar, size)) goto done;
            stage = 1;
            continue;
        }
        if (stage == 3) {
            if (archive_read_data_skip(ar) != ARCHIVE_OK) goto done;
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
        if (got || total != size || fflush(part) || fsync(fileno(part)) ||
            (strcmp(stage == 1 ? name + 11 : name + 8, ".lzma") &&
             !deb_codec_matches(part, stage == 1 ? name + 11 : name + 8))) {
            fclose(part); goto done;
        }
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
        free(e->original); free(e->soname);
        free((char *)e->stream.path); free((char *)e->stream.link);
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

static void free_apk(struct apk_metadata *meta)
{
    size_t i;
    for (i = 0; i < meta->count; ++i) { free(meta->fields[i].key); free(meta->fields[i].value); }
    free(meta->fields);
}

static int parse_apk(const char *data, size_t size, struct apk_metadata *meta)
{
    size_t offset = 0, line = 0;
    if (memchr(data, 0, size)) return 0;
    while (offset < size) {
        const char *start = data + offset, *end = memchr(start, '\n', size - offset), *separator;
        size_t length = end ? (size_t)(end - start) : size - offset, i;
        struct apk_field *field, *grown;
        ++line; offset += length + (end != NULL);
        if (!length || *start == '#') continue;
        separator = memchr(start, '=', length);
        if (!separator || separator < start + 2 || separator[-1] != ' ' ||
            separator + 1 >= start + length || separator[1] != ' ' ||
            meta->count == 4096) return 0;
        for (i = 0; i < (size_t)(separator - start - 1); ++i)
            if (!isalnum((unsigned char)start[i]) && start[i] != '_' && start[i] != '-') return 0;
        grown = realloc(meta->fields, (meta->count + 1) * sizeof *grown);
        if (!grown) return 0;
        meta->fields = grown; field = &meta->fields[meta->count++];
        field->key = strndup(start, (size_t)(separator - start - 1));
        field->value = strndup(separator + 2, (size_t)(start + length - separator - 2));
        field->line = line;
        if (!field->key || !field->value || !*field->value) return 0;
        if (!strcmp(field->key, "pkgname")) { if (meta->name) return 0; meta->name = field->value; }
        if (!strcmp(field->key, "pkgver")) { if (meta->version) return 0; meta->version = field->value; }
        if (!strcmp(field->key, "arch")) { if (meta->arch) return 0; meta->arch = field->value; }
        if (!strcmp(field->key, "datahash")) { if (meta->datahash) return 0; meta->datahash = field->value; }
    }
    if (!meta->name || !meta->version || !meta->arch) return 0;
    if (!isalnum((unsigned char)meta->name[0]) ||
        strspn(meta->name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+_.-") != strlen(meta->name)) return 0;
    return 1;
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

static void free_slack(struct slack_metadata *meta)
{
    free(meta->name); free(meta->version); free(meta->arch); free(meta->build);
}

static int parse_slack_name(const char *path, struct slack_metadata *meta)
{
    const char *base = strrchr(path, '/');
    char *copy, *part;
    size_t i, length;
    base = base ? base + 1 : path;
    length = strlen(base);
    if (length < 12 ||
        (strcmp(base + length - 4, ".txz") && strcmp(base + length - 4, ".tgz") &&
         strcmp(base + length - 4, ".tbz") && strcmp(base + length - 4, ".tlz"))) return 0;
    meta->lzma = !strcmp(base + length - 4, ".tlz");
    copy = strndup(base, length - 4);
    if (!copy) return 0;
    part = strrchr(copy, '-');
    if (!part || !part[1]) goto bad;
    meta->build = strdup(part + 1); *part = 0;
    part = strrchr(copy, '-');
    if (!part || !part[1]) goto bad;
    meta->arch = strdup(part + 1); *part = 0;
    part = strrchr(copy, '-');
    if (!part || !part[1] || part == copy) goto bad;
    meta->version = strdup(part + 1); *part = 0;
    meta->name = strdup(copy);
    if (!meta->name || !meta->version || !meta->arch || !meta->build) goto bad;
    for (i = 0; meta->name[i]; ++i)
        if (!isalnum((unsigned char)meta->name[i]) &&
            (i == 0 || (meta->name[i] != '-' && meta->name[i] != '_' &&
                        meta->name[i] != '+' && meta->name[i] != '.'))) goto bad;
    for (i = 0; meta->version[i]; ++i)
        if (!isalnum((unsigned char)meta->version[i]) &&
            meta->version[i] != '.' && meta->version[i] != '_' &&
            meta->version[i] != '+' && meta->version[i] != '~') goto bad;
    for (i = 0; meta->arch[i]; ++i)
        if (!isalnum((unsigned char)meta->arch[i]) && meta->arch[i] != '_') goto bad;
    for (i = 0; meta->build[i]; ++i)
        if (!isalnum((unsigned char)meta->build[i]) &&
            meta->build[i] != '_' && meta->build[i] != '.') goto bad;
    free(copy);
    return 1;
bad:
    free(copy);
    return 0;
}

static int slack_codec_matches(const char *snapshot, const char *path)
{
    unsigned char header[6];
    size_t length = strlen(path);
    int fd = open(snapshot, O_RDONLY | O_CLOEXEC);
    ssize_t got = fd >= 0 ? pread(fd, header, sizeof header, 0) : -1;
    if (fd >= 0) close(fd);
    if (got < 0 || length < 4) return 0;
    if (!strcmp(path + length - 4, ".txz"))
        return got >= 6 && !memcmp(header, "\xfd""7zXZ\0", 6);
    if (!strcmp(path + length - 4, ".tgz"))
        return got >= 2 && header[0] == 0x1f && header[1] == 0x8b;
    if (!strcmp(path + length - 4, ".tbz"))
        return got >= 3 && !memcmp(header, "BZh", 3);
    return got > 0;
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

static char *xbps_string(plist_t dict, const char *key)
{
    plist_t item = plist_dict_get_item(dict, key);
    char *value = NULL;
    if (item && plist_get_node_type(item) == PLIST_STRING) plist_get_string_val(item, &value);
    return value;
}

static int xbps_label(const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    if (!value || !*value || strlen(value) > 255 || !isalnum(*p)) return 0;
    for (; *p; ++p)
        if (!isalnum(*p) && *p != '-' && *p != '_' && *p != '.' && *p != '+' && *p != '~') return 0;
    return 1;
}

static int xbps_dependency(const char *expression, char **name,
                           const char **relation, const char **version)
{
    const char *op = strpbrk(expression, "<>");
    int order;
    size_t length;
    if (!op || op == expression) return 0;
    length = (size_t)(op - expression);
    *name = strndup(expression, length);
    if (!*name) return 0;
    if (!xbps_label(*name)) { free(*name); *name = NULL; return 0; }
    if (op[1] == '=') {
        *relation = *op == '<' ? "le" : "ge";
        *version = op + 2;
    } else {
        *relation = *op == '<' ? "lt" : "gt";
        *version = op + 1;
    }
    if (!holy_xbps_version_compare(*version, *version, &order)) {
        free(*name); *name = NULL; return 0;
    }
    return 1;
}

static int xbps_parse(struct foreign_input *input, struct xbps_metadata *meta)
{
    char *pkgver = NULL, *declared_version = NULL;
    const char *suffix;
    size_t i;
    if (input->pkginfo_size > UINT32_MAX ||
        plist_from_xml(input->pkginfo, (uint32_t)input->pkginfo_size, &meta->props) != PLIST_ERR_SUCCESS ||
        !meta->props || plist_get_node_type(meta->props) != PLIST_DICT) return 0;
    meta->name = xbps_string(meta->props, "pkgname");
    meta->arch = xbps_string(meta->props, "architecture");
    pkgver = xbps_string(meta->props, "pkgver");
    declared_version = xbps_string(meta->props, "version");
    if (!xbps_label(meta->name) || !xbps_label(meta->arch) ||
        !pkgver || !declared_version || strlen(pkgver) <= strlen(meta->name) + 1 ||
        strncmp(pkgver, meta->name, strlen(meta->name)) ||
        pkgver[strlen(meta->name)] != '-' ||
        strcmp(pkgver + strlen(meta->name) + 1, declared_version)) goto bad;
    suffix = strrchr(declared_version, '_');
    if (!suffix || !suffix[1] || strspn(suffix + 1, "0123456789") != strlen(suffix + 1)) goto bad;
    meta->version = strndup(declared_version, (size_t)(suffix - declared_version));
    meta->release = strdup(suffix + 1);
    if (!xbps_label(meta->version) || !meta->release) goto bad;
    for (i = 0; i < input->count; ++i)
        if (!strcmp(input->entries[i].original, "files.plist")) break;
    free(pkgver); free(declared_version);
    return i < input->count;
bad:
    free(pkgver); free(declared_version);
    return 0;
}

static char *xbps_link_target(const char *path, const char *target)
{
    if (!target || !holy_safe_link(path, target)) return NULL;
    if (target[0] == '/') return normalized(target + 1, 0);
    return holy_relative_link_path(path, strlen(path), target, "");
}

static int xbps_files(struct foreign_input *input)
{
    plist_t root = NULL;
    struct foreign_entry *control = NULL;
    unsigned char *seen = NULL;
    size_t i, covered = 0;
    int ok = 0;
    for (i = 0; i < input->count; ++i)
        if (!strcmp(input->entries[i].original, "files.plist")) control = &input->entries[i];
    if (!control || control->stream.size > 1024 * 1024) return 0;
    {
        size_t size = (size_t)control->stream.size;
        char *xml = malloc(size + 1);
        if (!xml) return 0;
        if (fflush(input->spool) || pread(fileno(input->spool), xml, size,
                                          (off_t)control->stream.offset) != (ssize_t)size ||
            plist_from_xml(xml, (uint32_t)size, &root) != PLIST_ERR_SUCCESS) {
            free(xml); return 0;
        }
        free(xml);
    }
    if (!root || plist_get_node_type(root) != PLIST_DICT) goto done;
    {
        plist_dict_iter iter = NULL;
        char *key = NULL;
        plist_t value = NULL;
        plist_dict_new_iter(root, &iter);
        if (!iter) goto done;
        for (;;) {
            plist_dict_next_item(root, iter, &key, &value);
            if (!key) break;
            if (strcmp(key, "dirs") && strcmp(key, "files") && strcmp(key, "links")) {
                fprintf(stderr, "holypkg: unsupported XBPS files.plist field %s\n", key);
                free(key); free(iter); goto done;
            }
            free(key);
        }
        free(iter);
    }
    seen = calloc(input->count ? input->count : 1, 1);
    if (!seen) goto done;
    {
        static const char *const keys[] = {"dirs", "files", "links"};
        size_t kind;
        for (kind = 0; kind < 3; ++kind) {
            plist_t array = plist_dict_get_item(root, keys[kind]);
            uint32_t j;
            if (!array) continue;
            if (plist_get_node_type(array) != PLIST_ARRAY) goto done;
            for (j = 0; j < plist_array_get_size(array); ++j) {
                plist_t item = plist_array_get_item(array, j);
                char *path, *digest = NULL;
                struct foreign_entry *entry = NULL;
                uint64_t size = 0;
                plist_t size_node;
                if (!item || plist_get_node_type(item) != PLIST_DICT) goto done;
                path = xbps_string(item, "file");
                if (!path || path[0] != '/' || !path[1]) { free(path); goto done; }
                for (i = 0; i < input->count; ++i)
                    if (!input->entries[i].metadata && !strcmp(input->entries[i].original, path + 1)) {
                        entry = &input->entries[i]; break;
                    }
                free(path);
                if (kind == 0 && !entry) continue;
                if (!entry || seen[i] || (!!entry->stream.directory != (kind == 0)) ||
                    (!!entry->stream.link != (kind == 2))) goto done;
                seen[i] = 1; ++covered;
                if (kind == 2) {
                    char *target = xbps_string(item, "target");
                    char *listed = target ? xbps_link_target(entry->original, target) : NULL;
                    char *payload = entry->stream.link ?
                        xbps_link_target(entry->original, entry->stream.link) : NULL;
                    int matches = listed && payload && !strcmp(listed, payload);
                    free(target); free(listed); free(payload);
                    if (!matches) {
                        fprintf(stderr, "holypkg: XBPS files.plist link target mismatch %s\n",
                                entry->original);
                        goto done;
                    }
                }
                if (kind != 1) continue;
                digest = xbps_string(item, "sha256");
                size_node = plist_dict_get_item(item, "size");
                if (!digest || strlen(digest) != 64 ||
                    strspn(digest, "0123456789abcdefABCDEF") != 64 ||
                    !size_node || plist_get_node_type(size_node) != PLIST_INT) {
                    free(digest); goto done;
                }
                plist_get_uint_val(size_node, &size);
                if (size != (uint64_t)entry->stream.size) { free(digest); goto done; }
                {
                    char actual[65];
                    size_t k;
                    for (k = 0; k < 32; ++k) snprintf(actual + k * 2, 3, "%02x", entry->hash[k]);
                    if (strcasecmp(actual, digest)) { free(digest); goto done; }
                }
                free(digest);
            }
        }
    }
    for (i = 0; i < input->count; ++i)
        if (!input->entries[i].metadata && !seen[i]) goto done;
    ok = covered != 0;
done:
    free(seen); plist_free(root);
    return ok;
}

static int deb_md5_matches(const struct foreign_input *input,
                           const struct foreign_entry *entry, const char *expected)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char digest[16], buffer[65536];
    unsigned length;
    long long offset = 0;
    size_t i;
    int ok = 0;
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_md5(), NULL) != 1) goto done;
    while (offset < entry->stream.size) {
        size_t size = (size_t)(entry->stream.size - offset);
        if (size > sizeof buffer) size = sizeof buffer;
        if (pread(fileno(input->spool), buffer, size,
                  (off_t)(entry->stream.offset + offset)) != (ssize_t)size ||
            EVP_DigestUpdate(ctx, buffer, size) != 1) goto done;
        offset += (long long)size;
    }
    if (EVP_DigestFinal_ex(ctx, digest, &length) != 1 || length != sizeof digest) goto done;
    for (i = 0; i < sizeof digest; ++i) {
        char hex[3];
        snprintf(hex, sizeof hex, "%02x", digest[i]);
        if (tolower((unsigned char)expected[i * 2]) != hex[0] ||
            tolower((unsigned char)expected[i * 2 + 1]) != hex[1]) goto done;
    }
    ok = 1;
done:
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int verify_deb_md5sums(const struct foreign_input *input)
{
    const struct foreign_entry *list = NULL;
    struct foreign_entry **sorted = NULL;
    unsigned char *seen = NULL;
    char *data = NULL;
    size_t i, offset = 0;
    int ok = 0;
    for (i = 0; i < input->count; ++i)
        if (!strcmp(input->entries[i].original, "@control/md5sums")) list = &input->entries[i];
    if (!list) return 1;
    if (list->stream.size < 0 || list->stream.size > 16 * 1024 * 1024) goto done;
    data = malloc((size_t)list->stream.size + 1);
    sorted = malloc(input->count * sizeof *sorted);
    seen = calloc(input->count, 1);
    if (!data || !sorted || !seen ||
        pread(fileno(input->spool), data, (size_t)list->stream.size,
              (off_t)list->stream.offset) != list->stream.size) goto done;
    data[list->stream.size] = 0;
    if (memchr(data, 0, (size_t)list->stream.size)) goto done;
    for (i = 0; i < input->count; ++i) sorted[i] = &input->entries[i];
    qsort(sorted, input->count, sizeof *sorted, path_order);
    while (offset < (size_t)list->stream.size) {
        char *line = data + offset, *end = memchr(line, '\n', (size_t)list->stream.size - offset);
        char *path, *canonical;
        struct foreign_entry *entry;
        size_t j, index;
        if (end) { *end = 0; offset = (size_t)(end - data) + 1; }
        else offset = (size_t)list->stream.size;
        if (strlen(line) < 35 || line[32] != ' ' || line[33] != ' ' ||
            !line[34] || line[strlen(line) - 1] == ' ' || line[strlen(line) - 1] == '\t') goto done;
        for (j = 0; j < 32; ++j) if (!isxdigit((unsigned char)line[j])) goto done;
        path = line + 34;
        canonical = normalized(path, 0);
        if (!canonical) goto done;
        j = strcmp(canonical, path);
        free(canonical);
        if (j) goto done;
        entry = find_path(sorted, input->count, path);
        if (!entry || entry->metadata || entry->stream.directory || entry->stream.link) goto done;
        index = (size_t)(entry - input->entries);
        if (seen[index]++) goto done;
        if (entry->stream.hardlink) entry = &input->entries[entry->hardlink_group];
        if (!deb_md5_matches(input, entry, line)) goto done;
    }
    ok = 1;
done:
    if (!ok) fputs("holypkg: Debian md5sums does not match payload\n", stderr);
    free(data); free(sorted); free(seen);
    return ok;
}

static int mark_deb_conffiles(struct foreign_input *input)
{
    struct foreign_entry *list = NULL;
    char *data = NULL;
    size_t i, offset = 0;
    int ok = 0;
    for (i = 0; i < input->count; ++i)
        if (!strcmp(input->entries[i].original, "@control/conffiles")) {
            if (list) return 0;
            list = &input->entries[i];
        }
    if (!list) return 1;
    if (list->stream.size < 0 || list->stream.size > 16 * 1024 * 1024) goto done;
    data = malloc((size_t)list->stream.size + 1);
    if (!data || pread(fileno(input->spool), data, (size_t)list->stream.size,
                       (off_t)list->stream.offset) != list->stream.size ||
        memchr(data, 0, (size_t)list->stream.size)) goto done;
    data[list->stream.size] = 0;
    while (offset < (size_t)list->stream.size) {
        char *line = data + offset, *end = strchr(line, '\n');
        char *canonical;
        struct foreign_entry *entry = NULL;
        if (end) { *end = 0; offset = (size_t)(end - data) + 1; }
        else offset = (size_t)list->stream.size;
        if (line[0] != '/' || !line[1] || line[strlen(line) - 1] == ' ' ||
            line[strlen(line) - 1] == '\r') goto done;
        canonical = normalized(line + 1, 0);
        if (!canonical) goto done;
        if (strcmp(canonical, line + 1)) { free(canonical); goto done; }
        for (i = 0; i < input->count; ++i)
            if (!input->entries[i].metadata && !strcmp(input->entries[i].original, canonical)) {
                entry = &input->entries[i]; break;
            }
        free(canonical);
        if (!entry || entry->config || entry->stream.directory ||
            entry->stream.link || entry->stream.hardlink) goto done;
        entry->config = 1;
    }
    ok = 1;
done:
    if (!ok) fputs("holypkg: Debian conffiles do not match regular payload files\n", stderr);
    free(data);
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

static int write_manifest(FILE *manifest, const struct foreign_input *input,
                          size_t index, const char *family)
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
    fprintf(manifest, " %s - ", e->config ? "config" : "none");
    if (e->hardlink_group >= 0) fprintf(manifest, "%s-hardlink-%d", family, e->hardlink_group);
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

static int soname_entry_order(const void *left, const void *right)
{
    const struct foreign_entry *a = *(const struct foreign_entry *const *)left;
    const struct foreign_entry *b = *(const struct foreign_entry *const *)right;
    int result = strcmp(a->soname, b->soname);
    return result ? result : strcmp(a->original, b->original);
}

static int emit_elf_provides(FILE *out, const struct foreign_input *input,
                             int group, const char *arch, const char *libc)
{
    const struct foreign_entry **items;
    size_t count = 0, i;
    int ok = 0;
    items = calloc(input->count ? input->count : 1, sizeof *items);
    if (!items) return 0;
    for (i = 0; i < input->count; ++i) {
        const struct foreign_entry *entry = &input->entries[i];
        if (entry->soname && belongs(input, i, group) &&
            holy_provides_claim_valid("soname", entry->soname, arch, libc,
                                      "-", entry->original)) items[count++] = entry;
    }
    qsort(items, count, sizeof *items, soname_entry_order);
    for (i = 0; i < count; ++i) {
        if (i && !strcmp(items[i-1]->soname, items[i]->soname)) continue;
        fputs("provide soname ", out); token(out, items[i]->soname);
        fprintf(out, " %s %s - ", arch, libc);
        token(out, items[i]->original); fputc('\n', out);
        {
            off_t position = ftello(out);
            if (ferror(out) || position < 0 || position > 1024 * 1024) goto done;
        }
    }
    ok = 1;
done:
    free(items);
    return ok;
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

#ifdef HOLY_HAVE_RPM
static int rpm_simple_capability(const char *name)
{
    const unsigned char *p = (const unsigned char *)name;
    for (; *p; ++p) if (*p <= 32 || *p == 127) return 0;
    return 1;
}

static int rpm_relations(FILE *deps, FILE *provides, FILE *origin, const struct rpm_metadata *rpm,
                         const char *arch, const char *libc)
{
    static const rpmTagVal names[] = {RPMTAG_REQUIRENAME, RPMTAG_PROVIDENAME,
                                      RPMTAG_CONFLICTNAME, RPMTAG_OBSOLETENAME};
    static const rpmTagVal versions[] = {RPMTAG_REQUIREVERSION, RPMTAG_PROVIDEVERSION,
                                         RPMTAG_CONFLICTVERSION, RPMTAG_OBSOLETEVERSION};
    static const rpmTagVal flags[] = {RPMTAG_REQUIREFLAGS, RPMTAG_PROVIDEFLAGS,
                                      RPMTAG_CONFLICTFLAGS, RPMTAG_OBSOLETEFLAGS};
    size_t k;
    for (k = 0; k < 4; ++k) {
        rpmtd n = rpmtdNew(), v = rpmtdNew(), f = rpmtdNew();
        rpm_count_t count, j;
        int ok = 1;
        if (!n || !v || !f) { ok = 0; goto next; }
        if (!headerGet(rpm->header, names[k], n, HEADERGET_MINMEM)) goto next;
        count = rpmtdCount(n);
        if ((headerGet(rpm->header, versions[k], v, HEADERGET_MINMEM) && rpmtdCount(v) != count) ||
            (headerGet(rpm->header, flags[k], f, HEADERGET_MINMEM) && rpmtdCount(f) != count)) {
            ok = 0; goto next;
        }
        for (j = 0; j < count; ++j) {
            const char *name, *version = "", *relation = "any";
            uint32_t bits = 0, all_flags = 0;
            char id[48], original[1024];
            if (rpmtdSetIndex(n, j) < 0) { ok = 0; break; }
            name = rpmtdGetString(n);
            if (!name || !*name || strlen(name) >= sizeof original / 2) { ok = 0; break; }
            if (rpmtdCount(v)) { if (rpmtdSetIndex(v, j) < 0) { ok = 0; break; } version = rpmtdGetString(v); }
            if (rpmtdCount(f)) { if (rpmtdSetIndex(f, j) < 0) { ok = 0; break; } all_flags = (uint32_t)rpmtdGetNumber(f); }
            if (!version) { ok = 0; break; }
            bits = all_flags;
            bits &= RPMSENSE_LESS | RPMSENSE_GREATER | RPMSENSE_EQUAL;
            if (bits == RPMSENSE_EQUAL) relation = "eq";
            else if (bits == (RPMSENSE_GREATER | RPMSENSE_EQUAL)) relation = "ge";
            else if (bits == (RPMSENSE_LESS | RPMSENSE_EQUAL)) relation = "le";
            else if (bits == RPMSENSE_GREATER) relation = "gt";
            else if (bits == RPMSENSE_LESS) relation = "lt";
            else if (bits) relation = "foreign";
            snprintf(id, sizeof id, "rpm-%zu-%u", k, j);
            if (snprintf(original, sizeof original, "%s %s %s", name, relation, version) >=
                (int)sizeof original) { ok = 0; break; }
            fputs("rpm-relation ", origin);
            token(origin, k == 0 ? "Requires" : k == 1 ? "Provides" :
                          k == 2 ? "Conflicts" : "Obsoletes");
            fputc(' ', origin); token(origin, original);
            fprintf(origin, " %u\n", all_flags);
            if (k == 1) {
                if (rpm_simple_capability(name) && ((!bits && !*version) ||
                    (bits == RPMSENSE_EQUAL && holy_rpm_version_valid(version)))) {
                    fputs("provide package ", provides); token(provides, name);
                    fputs(" any any ", provides); token(provides, *version ? version : "-");
                    fputs(" rpm\n", provides);
                }
            } else if (k == 0 && !strncmp(name, "rpmlib(", 7)) {
                /* rpmlib names describe the archive format, not a runtime dependency. */
            } else if (k == 0 && (all_flags & RPMSENSE_CONFIG) &&
                       !strncmp(name, "config(", 7) &&
                       strlen(name) == strlen(rpm->name) + 8 &&
                       !strncmp(name + 7, rpm->name, strlen(rpm->name)) &&
                       name[strlen(name) - 1] == ')') {
                /* rpm emits a config-file requirement on the package itself. */
            } else if (k == 0 && rpm_simple_capability(name) && strcmp(relation, "foreign") &&
                       ((!bits && !*version) || (bits && *version && holy_rpm_version_valid(version))) &&
                       (name[0] != '/' || !bits) &&
                       !(all_flags & ~(RPMSENSE_LESS | RPMSENSE_GREATER | RPMSENSE_EQUAL)))
                requirement(deps, id, rpm->name, name[0] == '/' ? "file" : "package", name,
                            "any", "any", relation, *version ? version : "-", original,
                            "rpm:Requires");
            else
                requirement(deps, id, rpm->name, "foreign", original, arch, libc, "any", "-",
                            original, k == 0 ? "rpm:Requires" : k == 2 ? "rpm:Conflicts" : "rpm:Obsoletes");
        }
next:
        rpmtdFree(n); rpmtdFree(v); rpmtdFree(f);
        if (!ok) return 0;
    }
    return !ferror(deps) && !ferror(provides) && !ferror(origin);
}
#endif

static int apk_simple_name(const char *name)
{
    const unsigned char *p = (const unsigned char *)name;
    if (!isalnum(*p)) return 0;
    for (; *p; ++p)
        if (!isalnum(*p) && *p != '.' && *p != '_' && *p != '+' && *p != '-') return 0;
    return 1;
}

static int apk_depends(FILE *out, const char *consumer, const struct apk_field *field)
{
    char *copy = strdup(field->value), *save = NULL, *part;
    size_t index = 0;
    if (!copy) return 0;
    for (part = strtok_r(copy, " \t", &save); part; part = strtok_r(NULL, " \t", &save)) {
        const char *kind = "foreign", *name = part;
        const char *relation = "any", *version = "-";
        char *base = NULL;
        char id[64];
        if (++index > 4096) { free(copy); return 0; }
        if (!strncmp(part, "so:", 3) && apk_simple_name(part + 3)) {
            kind = "soname"; name = part + 3;
        } else if (!strncmp(part, "cmd:", 4) && apk_simple_name(part + 4)) {
            kind = "command"; name = part + 4;
        } else if (apk_simple_name(part)) kind = "package";
        else {
            const char *operator = strpbrk(part, "<=>");
            if (operator && operator > part) {
                const char *value = operator + 1;
                int order;
                base = strndup(part, (size_t)(operator - part));
                if (!base) { free(copy); return 0; }
                if ((*operator == '<' || *operator == '>') && *value == '=') ++value;
                if (apk_simple_name(base) && *value &&
                    holy_apk_version_compare(value, value, &order)) {
                    kind = "package"; name = base; version = value;
                    relation = *operator == '<' ? value == operator + 2 ? "le" : "lt" :
                               *operator == '>' ? value == operator + 2 ? "ge" : "gt" : "eq";
                }
            }
        }
        snprintf(id, sizeof id, "apk-%zu-%zu", field->line, index);
        requirement(out, id, consumer, kind, name, "any", "any", relation, version,
                    part, "apk:depend");
        free(base);
    }
    free(copy);
    return index != 0 && !ferror(out);
}

static int deb_term(char *term, char **name, const char **relation, char **version)
{
    char *end, *name_end, *p;
    size_t i;
    int order;
    while (*term == ' ' || *term == '\t' || *term == '\n') ++term;
    end = term + strlen(term);
    while (end > term && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\n')) *--end = 0;
    if (end == term) return 0;
    name_end = term;
    while (*name_end && *name_end != ' ' && *name_end != '\t' &&
           *name_end != '\n' && *name_end != '(') ++name_end;
    if (name_end == term) return 0;
    for (i = 0; term + i < name_end; ++i)
        if (!((term[i] >= 'a' && term[i] <= 'z') ||
              (term[i] >= '0' && term[i] <= '9') ||
              (i && (term[i] == '+' || term[i] == '-' || term[i] == '.')))) return 0;
    *name = term;
    *relation = "any";
    *version = NULL;
    if (!*name_end) return 1;
    p = name_end;
    if (*p == '(') *p++ = 0;
    else {
        *p++ = 0;
        while (*p == ' ' || *p == '\t' || *p == '\n') ++p;
        if (*p++ != '(') return 0;
    }
    while (*p == ' ' || *p == '\t') ++p;
    if (p[0] == '<' && p[1] == '<') *relation = "lt";
    else if (p[0] == '<' && p[1] == '=') *relation = "le";
    else if (p[0] == '=') *relation = "eq";
    else if (p[0] == '>' && p[1] == '=') *relation = "ge";
    else if (p[0] == '>' && p[1] == '>') *relation = "gt";
    else return 0;
    p += !strcmp(*relation, "eq") ? 1 : 2;
    while (*p == ' ' || *p == '\t') ++p;
    *version = p;
    while (*p && *p != ' ' && *p != '\t' && *p != ')') ++p;
    if (p == *version) return 0;
    if (*p == ')') { *p++ = 0; if (*p) return 0; }
    else {
        if (!*p) return 0;
        *p++ = 0;
        while (*p == ' ' || *p == '\t') ++p;
        if (*p++ != ')' || *p) return 0;
    }
    return holy_deb_version_compare(*version, *version, &order);
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
        struct { char *name, *version; const char *relation; } terms[64];
        char *segment = cursor, *comma = strchr(cursor, ','), *end, *part;
        char id[64];
        size_t count = 0, i;
        if (comma) { *comma = 0; cursor = comma + 1; if (!*cursor) goto done; }
        else cursor += strlen(cursor);
        while (*segment == ' ' || *segment == '\t' || *segment == '\n') ++segment;
        end = segment + strlen(segment);
        while (end > segment && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\n')) *--end = 0;
        if (end == segment || ++index > 4096 ||
            (size_t)(end - segment) > 65536 || !(original = strdup(segment))) goto done;
        part = segment;
        while (part) {
            char *bar = strchr(part, '|');
            if (bar) *bar = 0;
            if (count == 64 || !deb_term(part, &terms[count].name,
                                         &terms[count].relation,
                                         &terms[count].version)) goto done;
            ++count;
            part = bar ? bar + 1 : NULL;
        }
        if (claims) {
            if (count != 1 || (strcmp(terms[0].relation, "any") &&
                               strcmp(terms[0].relation, "eq"))) goto done;
            for (i = 0; i < seen_count; ++i)
                if (!strcmp(seen[i], terms[0].name)) goto done;
            seen[seen_count++] = terms[0].name;
            fputs("provide package ", temporary); token(temporary, terms[0].name);
            fputs(" any any ", temporary); token(temporary, terms[0].version ? terms[0].version : "-");
            fputs(" deb:Provides\n", temporary);
        } else {
            snprintf(id, sizeof id, "deb-%zu-%zu", field->line, index);
            if (count == 1)
                requirement(temporary, id, consumer, "package", terms[0].name,
                            "any", "any", terms[0].relation,
                            terms[0].version ? terms[0].version : "-", original,
                            "deb:Depends");
            else {
                char *expression = NULL;
                size_t expression_size = 0;
                FILE *encoded = open_memstream(&expression, &expression_size);
                if (!encoded) goto done;
                for (i = 0; i < count; ++i)
                    fprintf(encoded, "%s%s@%s@%s", i ? "|" : "", terms[i].name,
                            terms[i].relation, terms[i].version ? terms[i].version : "-");
                {
                    int failed = ferror(encoded);
                    if (fclose(encoded)) failed = 1;
                    if (failed) { free(expression); goto done; }
                }
                if (!holy_package_or_each(expression, NULL, NULL)) {
                    free(expression); goto done;
                }
                requirement(temporary, id, consumer, "package-or", expression,
                            "any", "any", "any", "-", original, "deb:Depends");
                free(expression);
            }
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
                         const struct deb_metadata *deb, const struct slack_metadata *slack,
                         const struct apk_metadata *apk, const struct xbps_metadata *xbps,
                         const struct rpm_metadata *rpm,
                         const char *source, const char *hash, const char *output, int output_fd,
                         FILE *receipt, int group, const char *verification,
                         const char *key_hash, const char *signature_hash,
                         const char *index_hash, const char *source_url)
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
    const char *family = rpm ? "rpm" : xbps ? "xbps" : apk ? "apk" : slack ? "slackware" : deb ? "deb" : "pacman";
    const char *name = rpm ? rpm->name : xbps ? xbps->name : apk ? apk->name : slack ? slack->name : deb ? deb->name : meta->name;
    const char *version = rpm ? rpm->version : xbps ? xbps->version : apk ? apk->version : slack ? slack->version : deb ? deb->version : meta->version;
    const char *source_arch = rpm ? rpm->arch : xbps ? xbps->arch : apk ? apk->arch : slack ? slack->arch : deb ? deb->arch : meta->arch;
    for (i = 0; i < 7; ++i) if (!(files[i] = open_memstream(&text[i], &sizes[i]))) goto done;
    fputs("format holy-package-1\nname ", files[0]); token(files[0], name);
    fputs("\nversion ", files[0]); token(files[0], version);
    fputs("\nrelease ", files[0]); token(files[0], rpm ? rpm->release : xbps ? xbps->release : slack ? slack->build : "1");
    fprintf(files[0], "\nos linux\narch %s\nlibc %s\nx-version-family %s\nx-source-arch ", arch, libc, family);
    token(files[0], source_arch); fputc('\n', files[0]);
    if (slack) {
        fputs("x-source-build ", files[0]); token(files[0], slack->build);
        fputc('\n', files[0]);
    }
    fprintf(files[5], "format holy-import-origin-1\nfamily %s\nsource-name ", family);
    token(files[5], source);
    fprintf(files[5], "\noriginal-sha256 %s\nverification %s\nconverter holy-%s-1\noriginal-version ",
            hash, verification ? verification : "unverified", family);
    token(files[5], version); fputc('\n', files[5]);
    if (key_hash && fprintf(files[5], "%s %s\n",
                            deb ? "keyring-sha256" : "public-key-sha256", key_hash) < 0) goto done;
    if (signature_hash && fprintf(files[5], "signature-sha256 %s\n", signature_hash) < 0) goto done;
    if (index_hash && fprintf(files[5], "index-sha256 %s\n", index_hash) < 0) goto done;
    if (source_url) {
        fputs("source-url ", files[5]); token(files[5], source_url);
        fputc('\n', files[5]);
    }
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
    for (i = 0; !deb && !slack && !apk && !xbps && !rpm && i < meta->count; ++i) {
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
    for (i = 0; apk && i < apk->count; ++i) {
        const struct apk_field *field = &apk->fields[i];
        char id[64];
        fputs("pkginfo ", files[5]); token(files[5], field->key); fputc(' ', files[5]);
        token(files[5], field->value); fprintf(files[5], " %zu\n", field->line);
        if (!aggregate) continue;
        if (!strcmp(field->key, "depend")) {
            if (!apk_depends(files[2], name, field)) goto done;
        } else if (!strcmp(field->key, "install_if") ||
                   !strcmp(field->key, "replaces") || !strcmp(field->key, "provides")) {
            snprintf(id, sizeof id, "apk-%zu", field->line);
            requirement(files[2], id, name, "foreign", field->value, "any", "any", "any", "-",
                        field->value, field->key);
        }
    }
    if (xbps && aggregate) {
        static const char *const keys[] = {"run_depends", "shlib-requires", "provides", "conflicts", "replaces"};
        size_t k;
        for (k = 0; k < sizeof keys / sizeof *keys; ++k) {
            plist_t array = plist_dict_get_item(xbps->props, keys[k]);
            uint32_t j;
            if (!array) continue;
            if (plist_get_node_type(array) != PLIST_ARRAY) goto done;
            for (j = 0; j < plist_array_get_size(array); ++j) {
                char *value = NULL, id[80];
                plist_t item = plist_array_get_item(array, j);
                if (!item || plist_get_node_type(item) != PLIST_STRING) goto done;
                plist_get_string_val(item, &value);
                if (!value || !*value) { free(value); goto done; }
                snprintf(id, sizeof id, "xbps-%zu-%u", k, j);
                if (k == 2) {
                    fputs("foreign-provide ", files[5]); token(files[5], value);
                    fputc('\n', files[5]);
                } else if (k == 0) {
                    char *dependency = NULL;
                    const char *relation, *required_version;
                    if (xbps_dependency(value, &dependency, &relation, &required_version))
                        requirement(files[2], id, name, "package", dependency,
                                    "any", "any", relation, required_version, value, keys[k]);
                    else
                        requirement(files[2], id, name, "foreign", value,
                                    "any", "any", "any", "-", value, keys[k]);
                    free(dependency);
                } else
                    requirement(files[2], id, name, k == 1 ? "soname" : "foreign", value,
                                k == 1 ? arch : "any", k == 1 ? libc : "any",
                                "any", "-", value, keys[k]);
                free(value);
            }
        }
    }
#ifdef HOLY_HAVE_RPM
    if (rpm && aggregate && !rpm_relations(files[2], files[3], files[5], rpm, arch, libc)) goto done;
#endif
    if (!emit_elf_provides(files[3], input, group, arch, libc)) goto done;
    if (slack) {
        fputs("package-filename ", files[5]); token(files[5], name);
        fputc(' ', files[5]); token(files[5], version);
        fputc(' ', files[5]); token(files[5], source_arch);
        fputc(' ', files[5]); token(files[5], slack->build);
        fputc('\n', files[5]);
    }
    entries = calloc(input->count + 11, sizeof *entries);
    if (!entries) goto done;
    for (i = 0; i < input->count; ++i) {
        const struct foreign_entry *e = &input->entries[i];
        if (!belongs(input, i, group)) continue;
        if (!e->metadata && !write_manifest(files[1], input, i, family)) goto done;
        if (!apk && !deb && !slack && !xbps && !rpm && aggregate && !strcmp(e->original, ".INSTALL")) {
            fputs("foreign-script pacman /bin/sh HOLY/foreign/pacman/INSTALL sha256 ", files[4]);
            hex_hash(files[4], e->hash);
            fputs(" review-required\n", files[4]);
        }
        if (xbps && aggregate && e->metadata &&
            (!strcmp(e->original, "INSTALL") || !strcmp(e->original, "REMOVE"))) {
            fputs("foreign-script xbps /bin/sh ", files[4]); token(files[4], e->stream.path);
            fputs(" sha256 ", files[4]); hex_hash(files[4], e->hash);
            fputs(" review-required\n", files[4]);
        }
        if (apk && aggregate && e->metadata && strcmp(e->original, ".PKGINFO") &&
            strncmp(e->original, ".SIGN.", 6)) {
            if (strstr(e->original, "install") || strstr(e->original, "upgrade") ||
                strstr(e->original, "deinstall")) {
                fputs("foreign-script apk /bin/sh ", files[4]); token(files[4], e->stream.path);
                fputs(" sha256 ", files[4]); hex_hash(files[4], e->hash);
                fputs(" review-required\n", files[4]);
            } else {
                char id[64];
                snprintf(id, sizeof id, "apk-control-%zu", i);
                requirement(files[2], id, name, "foreign", e->original, "any", "any", "any", "-",
                            e->original, "apk-control-file");
            }
        }
        if (slack && aggregate && !strcmp(e->original, "install/doinst.sh")) {
            fputs("foreign-script slackware /bin/sh HOLY/foreign/slackware/doinst.sh sha256 ", files[4]);
            hex_hash(files[4], e->hash);
            fputs(" review-required\n", files[4]);
        } else if (slack && aggregate && e->metadata &&
                   strcmp(e->original, "install") &&
                   strcmp(e->original, "install/slack-desc") &&
                   strcmp(e->original, "install/doinst.sh")) {
            char id[64];
            snprintf(id, sizeof id, "slackware-control-%zu", i);
            requirement(files[2], id, name, "foreign", e->original, "any", "any", "any", "-",
                        e->original, "slackware-control-file");
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
    entries[count++] = (struct holy_stream_entry){xbps ? "HOLY/foreign/xbps" :
                                                   apk ? "HOLY/foreign/apk" :
                                                   slack ? "HOLY/foreign/slackware" :
                                                   deb ? "HOLY/foreign/deb" : rpm ? "HOLY/foreign/rpm" : "HOLY/foreign/pacman",
                                                   NULL, NULL, "root", "root", 0, 0, 0, 0, 0755, 1};
    for (i = 0; i < input->count; ++i)
        if (input->entries[i].metadata &&
            (!slack || strcmp(input->entries[i].original, "install")))
            entries[count++] = input->entries[i].stream;
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
        if (!write_output(&input, &metadata, NULL, NULL, NULL, NULL, NULL, source, hash, output, output_fd,
                          receipt, (int)i, NULL, NULL, NULL, NULL, NULL)) goto done;
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

static int lower_digest(const char *value);

int holy_import_deb_verified(const char *input_path, const char *source, const char *output,
                             const char *expected_hash, const char *verification,
                             const char *key_hash, const char *signature_hash,
                             const char *index_hash, const char *source_url)
{
    struct foreign_input input = {0};
    struct deb_metadata metadata = {0};
    struct stat st;
    char *snapshot = NULL, hash[65], temporary[43] = {0};
    FILE *receipt = NULL;
    int input_fd = -1, output_fd = -1, result = 1, common;
    size_t i;
    if (!input_path || !source || !output || !*source || !strcmp(source, "local") ||
        !verification ||
        (strcmp(verification, "unverified") && strcmp(verification, "pinned-unverified") &&
         strcmp(verification, "release-gpgv-user-key") &&
         strcmp(verification, "inrelease-gpgv-user-key")) ||
        (strcmp(verification, "unverified") &&
         (!lower_digest(expected_hash) || !lower_digest(index_hash) || !source_url)) ||
        (!strcmp(verification, "unverified") &&
         (expected_hash || index_hash || source_url || key_hash || signature_hash)) ||
        ((key_hash || signature_hash) &&
         (!lower_digest(key_hash) || !lower_digest(signature_hash))) ||
        (!strcmp(verification, "pinned-unverified") && (key_hash || signature_hash)) ||
        (strstr(verification, "gpgv") && (!key_hash || !signature_hash))) return 2;
    for (i = 0; source[i]; ++i)
        if ((unsigned char)source[i] <= 32 || source[i] == ':' || source[i] == '/' || source[i] == '@') return 2;
    input_fd = open(input_path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (input_fd < 0 || fstat(input_fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        st.st_size > 1024LL * 1024 * 1024) { result = 6; goto done; }
    snapshot = holy_stage_fd(input_fd, "holy-import");
    if (!snapshot || !input_hash(snapshot, hash)) goto done;
    if (expected_hash && strcmp(expected_hash, hash)) { result = 4; goto done; }
    if (mkdir(output, 0700)) goto done;
    output_fd = open(output, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (output_fd < 0 || fstat(output_fd, &st) || st.st_uid != geteuid() ||
        (st.st_mode & 0777) != 0700 || !preserve_original(snapshot, output_fd)) goto done;
    result = collect_deb(snapshot, &input);
    if (result) goto done;
    if (!validate_paths(&input) || !verify_deb_md5sums(&input) ||
        !parse_deb(input.pkginfo, input.pkginfo_size, &metadata)) {
        fputs("holypkg: malformed deb control or payload paths\n", stderr);
        result = 2; goto done;
    }
    result = 3;
    if (input.unknown) { fputs("holypkg: unknown payload ABI or executable format requires classification\n", stderr); goto done; }
    if (strcmp(metadata.arch, "all") && strcmp(metadata.arch, "amd64") && strcmp(metadata.arch, "i386")) {
        fputs("holypkg: unsupported Debian architecture requires classification\n", stderr); goto done;
    }
    if (!mark_deb_conffiles(&input)) { result = 2; goto done; }
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
    token(receipt, source); fprintf(receipt, "\nverification %s\n", verification);
    if (key_hash) fprintf(receipt, "keyring-sha256 %s\n", key_hash);
    if (signature_hash) fprintf(receipt, "signature-sha256 %s\n", signature_hash);
    if (index_hash) fprintf(receipt, "index-sha256 %s\n", index_hash);
    if (source_url) {
        fputs("source-url ", receipt); token(receipt, source_url);
        fputc('\n', receipt);
    }
    for (i = 0; i < input.group_count; ++i)
        if (!write_output(&input, NULL, &metadata, NULL, NULL, NULL, NULL, source, hash, output, output_fd,
                          receipt, (int)i, verification, key_hash, signature_hash,
                          index_hash, source_url)) goto done;
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

int holy_import_deb(const char *input_path, const char *source, const char *output)
{
    return holy_import_deb_verified(input_path, source, output, NULL,
                                    "unverified", NULL, NULL, NULL, NULL);
}

int holy_import_slackware(const char *input_path, const char *source, const char *output)
{
    struct foreign_input input = {0};
    struct slack_metadata metadata = {0};
    struct stat st;
    char *snapshot = NULL, hash[65], temporary[43] = {0};
    FILE *receipt = NULL;
    int input_fd = -1, output_fd = -1, result = 1, common;
    size_t i;
    if (!*source || !strcmp(source, "local")) return 2;
    for (i = 0; source[i]; ++i)
        if ((unsigned char)source[i] <= 32 || source[i] == ':' ||
            source[i] == '/' || source[i] == '@') return 2;
    if (!parse_slack_name(input_path, &metadata)) { result = 2; goto done; }
    input_fd = open(input_path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (input_fd < 0 || fstat(input_fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size < 0 || st.st_size > 1024LL * 1024 * 1024) {
        result = 6; goto done;
    }
    snapshot = holy_stage_fd(input_fd, "holy-import");
    if (!snapshot || !input_hash(snapshot, hash) || mkdir(output, 0700)) goto done;
    output_fd = open(output, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (output_fd < 0 || fstat(output_fd, &st) || st.st_uid != geteuid() ||
        (st.st_mode & 0777) != 0700 || !preserve_original(snapshot, output_fd)) goto done;
    if (!slack_codec_matches(snapshot, input_path)) { result = 2; goto done; }
    result = collect_archive(snapshot, &input, FOREIGN_SLACKWARE, metadata.lzma);
    if (result) goto done;
    if (!validate_paths(&input)) { result = 2; goto done; }
    result = 3;
    if (input.unknown) {
        fputs("holypkg: unknown payload ABI or executable format requires classification\n", stderr);
        goto done;
    }
    if (strcmp(metadata.arch, "noarch") && strcmp(metadata.arch, "x86_64") &&
        strcmp(metadata.arch, "i386") && strcmp(metadata.arch, "i486") &&
        strcmp(metadata.arch, "i586") && strcmp(metadata.arch, "i686")) {
        fputs("holypkg: unsupported Slackware architecture requires classification\n", stderr);
        goto done;
    }
    for (i = 0; i < input.group_count; ++i) {
        const char *arch = input.groups[i].arch;
        if ((!strcmp(metadata.arch, "noarch") && strcmp(arch, "noarch")) ||
            (!strcmp(metadata.arch, "x86_64") && strcmp(arch, "x86_64") &&
             strcmp(arch, "x86")) ||
            (strcmp(metadata.arch, "noarch") && strcmp(metadata.arch, "x86_64") &&
             strcmp(arch, "x86"))) {
            fputs("holypkg: Slackware architecture differs from payload ELF\n", stderr);
            goto done;
        }
    }
    if (!input.group_count) common = add_group(&input, "noarch", "nolibc");
    else if (input.group_count == 1) common = 0;
    else common = add_group(&input, "noarch", "nolibc");
    if (common < 0) { result = 6; goto done; }
    for (i = 0; i < input.count; ++i)
        if (input.entries[i].group < 0) input.entries[i].group = common;
    result = 1;
    {
        int fd = holy_temporary_at(output_fd, temporary);
        if (fd < 0) goto done;
        receipt = fdopen(fd, "w");
        if (!receipt) { close(fd); goto done; }
    }
    fprintf(receipt, "format holy-import-record-1\nfamily slackware\nconverter holy-slackware-1\noriginal-sha256 %s\nsource-name ", hash);
    token(receipt, source); fputs("\nverification unverified\n", receipt);
    for (i = 0; i < input.group_count; ++i)
        if (!write_output(&input, NULL, NULL, &metadata, NULL, NULL, NULL, source, hash,
                          output, output_fd, receipt, (int)i, NULL, NULL, NULL, NULL, NULL)) goto done;
    fputs("state complete\n", receipt);
    if (fflush(receipt) || fsync(fileno(receipt))) goto done;
    if (fclose(receipt)) { receipt = NULL; goto done; }
    receipt = NULL;
    if (linkat(output_fd, temporary, output_fd, "conversion", 0) || fsync(output_fd)) goto done;
    result = 0;
done:
    if (result)
        fprintf(stderr, "holypkg: Slackware import incomplete (status %d); no installed state changed\n", result);
    if (receipt) fclose(receipt);
    if (output_fd >= 0) { if (*temporary) unlinkat(output_fd, temporary, 0); close(output_fd); }
    if (input_fd >= 0) close(input_fd);
    if (snapshot) { unlink(snapshot); free(snapshot); }
    free_slack(&metadata); free_input(&input);
    return result;
}

int holy_import_apk_verified(const char *input_path, const char *source, const char *output,
                             const char *public_key, const char *expected_hash,
                             const char *expected_key_hash, const char *index_hash,
                             const char *source_url)
{
    struct foreign_input input = {0};
    struct apk_metadata metadata = {0};
    struct stat st;
    FILE *parts[3] = {0}, *receipt = NULL;
    char digests[3][65] = {{0}}, *snapshot = NULL, *key_snapshot = NULL;
    char hash[65], key_hash[65] = {0}, verification[16] = "unverified";
    char temporary[43] = {0};
    int input_fd = -1, output_fd = -1, count, control, result = 1, common;
    size_t i;
    if (!input_path || !source || !output || !*source || !strcmp(source, "local") ||
        (!!expected_hash != !!index_hash) || (!!expected_hash != !!source_url) ||
        (expected_hash && (!lower_digest(expected_hash) || !lower_digest(index_hash))) ||
        (expected_key_hash && (!public_key || !lower_digest(expected_key_hash)))) return 2;
    for (i = 0; source[i]; ++i)
        if ((unsigned char)source[i] <= 32 || source[i] == ':' ||
            source[i] == '/' || source[i] == '@') return 2;
    input_fd = open(input_path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (input_fd < 0 || fstat(input_fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size < 0 || st.st_size > 1024LL * 1024 * 1024) {
        result = 6; goto done;
    }
    snapshot = holy_stage_fd(input_fd, "holy-import");
    if (!snapshot || !input_hash(snapshot, hash)) goto done;
    if (expected_hash && strcmp(expected_hash, hash)) { result = 4; goto done; }
    if (mkdir(output, 0700)) goto done;
    output_fd = open(output, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (output_fd < 0 || fstat(output_fd, &st) || st.st_uid != geteuid() ||
        (st.st_mode & 0777) != 0700 || !preserve_original(snapshot, output_fd)) goto done;
    result = 2;
    count = holy_apk_gzip_parts(snapshot, parts, digests, 4ULL * 1024 * 1024 * 1024);
    if (count < 2) goto done;
    control = count - 2;
    for (i = 0; i < (size_t)count; ++i) {
        char descriptor[64];
        enum foreign_archive_kind kind = (int)i < control ? FOREIGN_APK_SIGNATURE :
                                         (int)i == control ? FOREIGN_APK_CONTROL : FOREIGN_APK_DATA;
        if (fstat(fileno(parts[i]), &st) ||
            (kind != FOREIGN_APK_DATA && st.st_size > 16 * 1024 * 1024)) goto done;
        snprintf(descriptor, sizeof descriptor, "/proc/self/fd/%d", fileno(parts[i]));
        result = collect_archive(descriptor, &input, kind, 0);
        if (result) goto done;
    }
    if (!validate_paths(&input) || !parse_apk(input.pkginfo, input.pkginfo_size, &metadata)) {
        result = 2; goto done;
    }
    if (metadata.datahash) {
        if (strlen(metadata.datahash) != 64 ||
            strspn(metadata.datahash, "0123456789abcdefABCDEF") != 64 ||
            strcasecmp(metadata.datahash, digests[count - 1])) {
            fputs("holypkg: APK datahash differs from compressed data member\n", stderr);
            result = 2; goto done;
        }
    }
    if (public_key) {
        const char *keyname = strrchr(public_key, '/');
        keyname = keyname ? keyname + 1 : public_key;
        if (count != 3 || !metadata.datahash ||
            !(key_snapshot = holy_stage_local(public_key, "holy-apk-key")) ||
            !holy_apk_key_fingerprint(key_snapshot, key_hash) ||
            !holy_apk_verify_signature(parts[0], parts[1], key_snapshot,
                                       keyname, verification)) {
            fputs("holypkg: APK package signature verification failed\n", stderr);
            result = 4; goto done;
        }
        if (expected_key_hash && strcmp(expected_key_hash, key_hash)) {
            result = 4; goto done;
        }
    }
    result = 3;
    if (input.unknown) {
        fputs("holypkg: unknown APK payload ABI or executable format requires classification\n", stderr);
        goto done;
    }
    if (strcmp(metadata.arch, "noarch") && strcmp(metadata.arch, "x86_64") &&
        strcmp(metadata.arch, "x86")) {
        fputs("holypkg: unsupported APK architecture requires classification\n", stderr);
        goto done;
    }
    for (i = 0; i < input.group_count; ++i) {
        const char *arch = input.groups[i].arch;
        if ((!strcmp(metadata.arch, "noarch") && strcmp(arch, "noarch")) ||
            (!strcmp(metadata.arch, "x86_64") && strcmp(arch, "x86_64") && strcmp(arch, "x86")) ||
            (!strcmp(metadata.arch, "x86") && strcmp(arch, "x86"))) {
            fputs("holypkg: APK architecture differs from payload ELF\n", stderr);
            goto done;
        }
    }
    if (!input.group_count) common = add_group(&input, "noarch", "nolibc");
    else if (input.group_count == 1) common = 0;
    else common = add_group(&input, "noarch", "nolibc");
    if (common < 0) { result = 6; goto done; }
    for (i = 0; i < input.count; ++i)
        if (input.entries[i].group < 0) input.entries[i].group = common;
    result = 1;
    {
        int fd = holy_temporary_at(output_fd, temporary);
        if (fd < 0) goto done;
        receipt = fdopen(fd, "w");
        if (!receipt) { close(fd); goto done; }
    }
    fprintf(receipt, "format holy-import-record-1\nfamily apk\nconverter holy-apk-1\noriginal-sha256 %s\nsource-name ", hash);
    token(receipt, source);
    fprintf(receipt, "\nverification %s\ndata-sha256 %s\n",
            verification, digests[count - 1]);
    if (key_hash[0]) fprintf(receipt, "public-key-sha256 %s\n", key_hash);
    if (index_hash) fprintf(receipt, "index-sha256 %s\n", index_hash);
    if (source_url) {
        fputs("source-url ", receipt); token(receipt, source_url);
        fputc('\n', receipt);
    }
    for (i = 0; i < input.group_count; ++i)
        if (!write_output(&input, NULL, NULL, NULL, &metadata, NULL, NULL, source, hash,
                          output, output_fd, receipt, (int)i, verification,
                          key_hash[0] ? key_hash : NULL, NULL,
                          index_hash, source_url)) goto done;
    fputs("state complete\n", receipt);
    if (fflush(receipt) || fsync(fileno(receipt))) goto done;
    if (fclose(receipt)) { receipt = NULL; goto done; }
    receipt = NULL;
    if (linkat(output_fd, temporary, output_fd, "conversion", 0) || fsync(output_fd)) goto done;
    result = 0;
done:
    if (result)
        fprintf(stderr, "holypkg: APK import incomplete (status %d); no installed state changed\n", result);
    if (receipt) fclose(receipt);
    for (i = 0; i < 3; ++i) if (parts[i]) fclose(parts[i]);
    if (output_fd >= 0) { if (*temporary) unlinkat(output_fd, temporary, 0); close(output_fd); }
    if (input_fd >= 0) close(input_fd);
    if (snapshot) { unlink(snapshot); free(snapshot); }
    if (key_snapshot) { unlink(key_snapshot); free(key_snapshot); }
    free_apk(&metadata); free_input(&input);
    return result;
}

int holy_import_apk(const char *input_path, const char *source, const char *output,
                    const char *public_key)
{
    return holy_import_apk_verified(input_path, source, output, public_key,
                                    NULL, NULL, NULL, NULL);
}

static int lower_digest(const char *value)
{
    return value && strlen(value) == 64 && strspn(value, "0123456789abcdef") == 64;
}

int holy_import_xbps_verified(const char *input_path, const char *source, const char *output,
                              const char *expected_hash, const char *verification,
                              const char *key_hash, const char *signature_hash,
                              const char *index_hash, const char *source_url)
{
    struct foreign_input input = {0};
    struct xbps_metadata metadata = {0};
    struct stat st;
    char *snapshot = NULL, hash[65], temporary[43] = {0};
    FILE *receipt = NULL;
    int input_fd = -1, output_fd = -1, result = 1, common;
    size_t i;
    if (!input_path || !source || !output || !*source || !strcmp(source, "local") ||
        !verification ||
        (strcmp(verification, "unverified") && strcmp(verification, "hash-pinned") &&
         strcmp(verification, "rsa-sha256")) ||
        (strcmp(verification, "unverified") && !lower_digest(expected_hash)) ||
        (expected_hash && !lower_digest(expected_hash)) ||
        (index_hash && !lower_digest(index_hash)) ||
        (!!index_hash != !!source_url) ||
        (strcmp(verification, "unverified") && !index_hash) ||
        (!strcmp(verification, "unverified") && index_hash) ||
        (!strcmp(verification, "rsa-sha256") ?
         !lower_digest(key_hash) || !lower_digest(signature_hash) :
         key_hash || signature_hash)) return 2;
    for (i = 0; source[i]; ++i)
        if ((unsigned char)source[i] <= 32 || source[i] == ':' || source[i] == '/' || source[i] == '@') return 2;
    input_fd = open(input_path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (input_fd < 0 || fstat(input_fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        st.st_size > 1024LL * 1024 * 1024) { result = 6; goto done; }
    snapshot = holy_stage_fd(input_fd, "holy-import");
    if (!snapshot || !input_hash(snapshot, hash)) goto done;
    if (expected_hash && strcmp(expected_hash, hash)) { result = 4; goto done; }
    if (mkdir(output, 0700)) goto done;
    output_fd = open(output, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (output_fd < 0 || fstat(output_fd, &st) || st.st_uid != geteuid() ||
        (st.st_mode & 0777) != 0700 || !preserve_original(snapshot, output_fd)) goto done;
    result = collect_archive(snapshot, &input, FOREIGN_XBPS, 0);
    if (result) goto done;
    if (!validate_paths(&input) || !xbps_parse(&input, &metadata) || !xbps_files(&input)) {
        fputs("holypkg: XBPS plist or payload manifest is invalid\n", stderr);
        result = 2; goto done;
    }
    result = 3;
    if (input.unknown) { fputs("holypkg: unknown XBPS payload ABI requires classification\n", stderr); goto done; }
    if (strcmp(metadata.arch, "noarch") && strcmp(metadata.arch, "x86_64") &&
        strcmp(metadata.arch, "i686") && strcmp(metadata.arch, "x86_64-musl") &&
        strcmp(metadata.arch, "i686-musl")) {
        fputs("holypkg: unsupported XBPS architecture requires classification\n", stderr); goto done;
    }
    for (i = 0; i < input.group_count; ++i) {
        const char *arch = input.groups[i].arch;
        if ((!strcmp(metadata.arch, "noarch") && strcmp(arch, "noarch")) ||
            (!strncmp(metadata.arch, "x86_64", 6) && strcmp(arch, "x86_64") && strcmp(arch, "x86")) ||
            (!strncmp(metadata.arch, "i686", 4) && strcmp(arch, "x86")) ||
            (strstr(metadata.arch, "-musl") && strcmp(input.groups[i].libc, "musl") &&
             strcmp(input.groups[i].libc, "nolibc")) ||
            (!strstr(metadata.arch, "-musl") && strcmp(input.groups[i].libc, "glibc") &&
             strcmp(input.groups[i].libc, "nolibc"))) {
            fputs("holypkg: XBPS architecture differs from payload ELF\n", stderr); goto done;
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
    fprintf(receipt, "format holy-import-record-1\nfamily xbps\nconverter holy-xbps-1\noriginal-sha256 %s\nsource-name ", hash);
    token(receipt, source); fprintf(receipt, "\nverification %s\n", verification);
    if (key_hash) fprintf(receipt, "public-key-sha256 %s\n", key_hash);
    if (signature_hash) fprintf(receipt, "signature-sha256 %s\n", signature_hash);
    if (index_hash) fprintf(receipt, "index-sha256 %s\n", index_hash);
    if (source_url) {
        fputs("source-url ", receipt); token(receipt, source_url);
        fputc('\n', receipt);
    }
    for (i = 0; i < input.group_count; ++i)
        if (!write_output(&input, NULL, NULL, NULL, NULL, &metadata, NULL, source, hash,
                          output, output_fd, receipt, (int)i, verification,
                          key_hash, signature_hash, index_hash, source_url)) goto done;
    fputs("state complete\n", receipt);
    if (fflush(receipt) || fsync(fileno(receipt))) goto done;
    if (fclose(receipt)) { receipt = NULL; goto done; }
    receipt = NULL;
    if (linkat(output_fd, temporary, output_fd, "conversion", 0) || fsync(output_fd)) goto done;
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: XBPS import incomplete (status %d); no installed state changed\n", result);
    if (receipt) fclose(receipt);
    if (output_fd >= 0) { if (*temporary) unlinkat(output_fd, temporary, 0); close(output_fd); }
    if (input_fd >= 0) close(input_fd);
    if (snapshot) { unlink(snapshot); free(snapshot); }
    plist_free(metadata.props); free(metadata.name); free(metadata.version);
    free(metadata.release); free(metadata.arch); free_input(&input);
    return result;
}

int holy_import_xbps(const char *input_path, const char *source, const char *output)
{
    return holy_import_xbps_verified(input_path, source, output, NULL,
                                     "unverified", NULL, NULL, NULL, NULL);
}

#ifdef HOLY_HAVE_RPM
static int rpm_header(const char *snapshot, struct rpm_metadata *meta)
{
    static const rpmTagVal scripts[] = {RPMTAG_PREIN, RPMTAG_POSTIN, RPMTAG_PREUN,
                                        RPMTAG_POSTUN, RPMTAG_PRETRANS, RPMTAG_POSTTRANS,
                                        RPMTAG_VERIFYSCRIPT, RPMTAG_TRIGGERSCRIPTS,
                                        RPMTAG_FILETRIGGERSCRIPTS, RPMTAG_TRANSFILETRIGGERSCRIPTS};
    rpmts ts = rpmtsCreate();
    FD_t fd = NULL;
    Header h = NULL;
    const char *value;
    size_t i;
    int result = 2;
    if (!ts) return 1;
    rpmtsSetVSFlags(ts, _RPMVSF_NOSIGNATURES);
    fd = Fopen(snapshot, "r.ufdio");
    if (!fd || rpmReadPackageFile(ts, fd, snapshot, &h) != RPMRC_OK || !h) goto done;
    if (headerGetNumber(h, RPMTAG_RPMFORMAT) &&
        headerGetNumber(h, RPMTAG_RPMFORMAT) != 4 &&
        headerGetNumber(h, RPMTAG_RPMFORMAT) != 6) {
        fputs("holypkg: unsupported RPM payload format\n", stderr);
        result = 6; goto done;
    }
    for (i = 0; i < sizeof scripts / sizeof *scripts; ++i)
        if (headerGetString(h, scripts[i])) {
            fputs("holypkg: RPM scriptlets require review support\n", stderr);
            result = 3; goto done;
        }
    value = headerGetString(h, RPMTAG_NAME); if (!value || !apk_simple_name(value)) goto done;
    meta->name = strdup(value);
    value = headerGetString(h, RPMTAG_VERSION); if (!value || !*value) goto done;
    meta->version = strdup(value);
    value = headerGetString(h, RPMTAG_RELEASE); if (!value || !*value) goto done;
    meta->release = strdup(value);
    value = headerGetString(h, RPMTAG_ARCH); if (!value || !*value) goto done;
    meta->arch = strdup(value);
    if (!meta->name || !meta->version || !meta->release || !meta->arch) { result = 1; goto done; }
    {
        uint64_t epoch = headerGetNumber(h, RPMTAG_EPOCH);
        if (epoch) {
            size_t length = strlen(meta->version) + 32;
            char *with_epoch = malloc(length);
            if (!with_epoch) { result = 1; goto done; }
            snprintf(with_epoch, length, "%llu:%s", (unsigned long long)epoch, meta->version);
            free(meta->version);
            meta->version = with_epoch;
        }
        if (!holy_rpm_version_valid(meta->version) ||
            !holy_rpm_version_valid(meta->release) ||
            strchr(meta->release, ':') || strchr(meta->release, '-')) {
            fputs("holypkg: invalid RPM version or release\n", stderr);
            result = 2; goto done;
        }
    }
    if (strcmp(meta->arch, "noarch") && strcmp(meta->arch, "i686") &&
        strcmp(meta->arch, "x86_64")) {
        fputs("holypkg: RPM source arch requires mapping\n", stderr);
        result = 3; goto done;
    }
    meta->header = h; h = NULL;
    result = 0;
done:
    if (h) headerFree(h);
    if (fd) Fclose(fd);
    rpmtsFree(ts);
    return result;
}

static int rpm_files(struct foreign_input *input, const struct rpm_metadata *meta)
{
    rpmfiles files = rpmfilesNew(NULL, meta->header, RPMTAG_BASENAMES, 0);
    unsigned char *seen = calloc(input->count ? input->count : 1, 1);
    struct foreign_entry **sorted = malloc((input->count ? input->count : 1) * sizeof *sorted);
    rpm_count_t i;
    int ok = 0;
    if (!files || !seen || !sorted) goto done;
    for (i = 0; i < input->count; ++i) sorted[i] = &input->entries[i];
    qsort(sorted, input->count, sizeof *sorted, path_order);
    for (i = 0; i < rpmfilesFC(files); ++i) {
        char *name = rpmfilesFN(files, i);
        const char *relative = name;
        struct foreign_entry *entry;
        size_t j;
        rpmfileAttrs flags = rpmfilesFFlags(files, i);
        if (!name) goto done;
        while (*relative == '/') ++relative;
        while (!strncmp(relative, "./", 2)) relative += 2;
        entry = find_path(sorted, input->count, relative);
        if (!entry) { free(name); goto done; }
        j = (size_t)(entry - input->entries);
        if (seen[j] || (flags & RPMFILE_GHOST) ||
            (rpmfilesFCaps(files, i) && *rpmfilesFCaps(files, i)) ||
            ((flags & RPMFILE_CONFIG) && entry->stream.directory)) { free(name); goto done; }
        seen[j] = 1;
        entry->config = !!(flags & RPMFILE_CONFIG);
        free(name);
    }
    for (i = 0; i < input->count; ++i) if (!seen[i]) goto done;
    ok = 1;
done:
    rpmfilesFree(files); free(seen); free(sorted);
    return ok;
}

static const EVP_MD *rpm_digest(int algorithm)
{
    switch (algorithm) {
    case PGPHASHALGO_MD5: return EVP_md5();
    case PGPHASHALGO_SHA1: return EVP_sha1();
    case PGPHASHALGO_SHA256: return EVP_sha256();
    case PGPHASHALGO_SHA512: return EVP_sha512();
    case PGPHASHALGO_SHA3_256: return EVP_sha3_256();
    default: return NULL;
    }
}

static int rpm_payload_to_tar(const char *snapshot, FILE *tar)
{
    rpmts ts = rpmtsCreate();
    FD_t fd = NULL;
    Header h = NULL;
    rpmfiles files = NULL;
    rpmfi fi = NULL;
    struct archive *writer = NULL;
    struct archive_entry *entry = NULL;
    char **targets = NULL;
    const char *compression;
    char mode[64], buffer[65536];
    rpm_count_t count = 0;
    int result = 2, next = RPMERR_ITER_END;
    size_t i;
    if (!ts) return 1;
    rpmtsSetVSFlags(ts, _RPMVSF_NOSIGNATURES);
    fd = Fopen(snapshot, "r.ufdio");
    if (!fd || rpmReadPackageFile(ts, fd, snapshot, &h) != RPMRC_OK || !h) goto done;
    compression = headerGetString(h, RPMTAG_PAYLOADCOMPRESSOR);
    if (!compression) compression = "gzip";
    if (strlen(compression) > sizeof mode - 3) goto done;
    snprintf(mode, sizeof mode, "r.%s", compression);
    {
        FD_t decoded = Fdopen(fd, mode);
        if (!decoded) { result = 6; goto done; }
        fd = decoded;
    }
    files = rpmfilesNew(NULL, h, 0, RPMFI_KEEPHEADER);
    if (!files) goto done;
    count = rpmfilesFC(files);
    if (count > 100000) goto done;
    targets = calloc(count ? count : 1, sizeof *targets);
    writer = archive_write_new(); entry = archive_entry_new();
    if (!targets || !writer || !entry) { result = 1; goto done; }
    if (archive_write_set_format_pax_restricted(writer) != ARCHIVE_OK ||
        archive_write_open_FILE(writer, tar) != ARCHIVE_OK) goto done;
    fi = rpmfiNewArchiveReader(fd, files, RPMFI_ITER_READ_ARCHIVE_CONTENT_FIRST);
    if (!fi) goto done;
    while ((next = rpmfiNext(fi)) >= 0) {
        const char *name = rpmfiFN(fi), *relative;
        const int *links = NULL;
        struct stat st;
        int index = rpmfiFX(fi), algorithm = 0;
        size_t digest_size = 0;
        const unsigned char *expected;
        char *clean;
        uint32_t nlinks;
        if (!name || index < 0 || (rpm_count_t)index >= count || rpmfiStat(fi, 0, &st)) goto done;
        relative = name;
        while (*relative == '/') ++relative;
        clean = normalized(relative, S_ISDIR(st.st_mode));
        if (!clean) goto done;
        archive_entry_clear(entry);
        archive_entry_set_pathname(entry, clean);
        archive_entry_copy_stat(entry, &st);
        archive_entry_set_uname(entry, rpmfiFUser(fi));
        archive_entry_set_gname(entry, rpmfiFGroup(fi));
        if (S_ISLNK(st.st_mode)) archive_entry_set_symlink(entry, rpmfiFLink(fi));
        nlinks = rpmfiFLinks(fi, &links);
        if (S_ISREG(st.st_mode) && nlinks > 1) {
            if (rpmfiArchiveHasContent(fi)) {
                uint32_t j;
                if (!links) { free(clean); goto done; }
                archive_entry_set_size(entry, rpmfiFSize(fi));
                for (j = 0; j < nlinks; ++j) {
                    int linked = links[j];
                    if (linked < 0 || (rpm_count_t)linked >= count || targets[linked]) { free(clean); goto done; }
                    targets[linked] = strdup(clean);
                    if (!targets[linked]) { free(clean); result = 1; goto done; }
                }
            } else {
                if (!targets[index]) { free(clean); goto done; }
                archive_entry_set_hardlink(entry, targets[index]);
                archive_entry_set_size(entry, 0);
            }
        }
        free(clean);
        if (archive_write_header(writer, entry) != ARCHIVE_OK) goto done;
        if (S_ISREG(st.st_mode) && rpmfiArchiveHasContent(fi)) {
            rpm_loff_t left = rpmfiFSize(fi);
            EVP_MD_CTX *digest = EVP_MD_CTX_new();
            unsigned char actual[EVP_MAX_MD_SIZE];
            unsigned actual_size = 0;
            const EVP_MD *md;
            expected = rpmfiFDigest(fi, &algorithm, &digest_size);
            md = rpm_digest(algorithm);
            if (left > 1024LL * 1024 * 1024 || !expected || !md || !digest ||
                digest_size != (size_t)EVP_MD_size(md) || EVP_DigestInit_ex(digest, md, NULL) != 1) {
                EVP_MD_CTX_free(digest); result = 6; goto done;
            }
            while (left) {
                size_t want = left > (rpm_loff_t)sizeof buffer ? sizeof buffer : (size_t)left;
                ssize_t got = rpmfiArchiveRead(fi, buffer, want);
                size_t offset = 0;
                if (got <= 0 || EVP_DigestUpdate(digest, buffer, (size_t)got) != 1) {
                    EVP_MD_CTX_free(digest); goto done;
                }
                while (offset < (size_t)got) {
                    la_ssize_t written = archive_write_data(writer, buffer + offset, (size_t)got - offset);
                    if (written <= 0) { EVP_MD_CTX_free(digest); goto done; }
                    offset += (size_t)written;
                }
                left -= got;
            }
            if (EVP_DigestFinal_ex(digest, actual, &actual_size) != 1 ||
                actual_size != digest_size || memcmp(actual, expected, digest_size)) {
                EVP_MD_CTX_free(digest); goto done;
            }
            EVP_MD_CTX_free(digest);
        }
    }
    if (next != RPMERR_ITER_END || rpmfiArchiveClose(fi) ||
        archive_write_close(writer) != ARCHIVE_OK || fflush(tar) || fseeko(tar, 0, SEEK_SET)) goto done;
    result = 0;
done:
    if (fi) rpmfiFree(fi);
    if (writer) archive_write_free(writer);
    if (entry) archive_entry_free(entry);
    for (i = 0; i < count; ++i) free(targets ? targets[i] : NULL);
    free(targets);
    rpmfilesFree(files);
    if (h) headerFree(h);
    if (fd) Fclose(fd);
    rpmtsFree(ts);
    return result;
}
#endif

int holy_import_rpm(const char *input_path, const char *source, const char *output)
{
#ifndef HOLY_HAVE_RPM
    (void)input_path; (void)source; (void)output;
    fputs("holypkg: RPM importer requires librpm at build time\n", stderr);
    return 6;
#else
    struct foreign_input input = {0};
    struct rpm_metadata metadata = {0};
    struct stat st;
    char *snapshot = NULL, hash[65], temporary[43] = {0};
    FILE *receipt = NULL, *tar = NULL;
    char descriptor[64];
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
    result = rpm_header(snapshot, &metadata);
    if (result) goto done;
    tar = tmpfile();
    if (!tar) goto done;
    result = rpm_payload_to_tar(snapshot, tar);
    if (result) goto done;
    snprintf(descriptor, sizeof descriptor, "/proc/self/fd/%d", fileno(tar));
    result = collect_archive(descriptor, &input, FOREIGN_RPM, 0);
    if (result) goto done;
    if (!validate_paths(&input) || !rpm_files(&input, &metadata)) { result = 2; goto done; }
    result = 3;
    if (input.unknown) {
        fputs("holypkg: unknown RPM payload ABI requires classification\n", stderr);
        goto done;
    }
    if (!strcmp(metadata.arch, "noarch") && input.group_count) {
        fputs("holypkg: noarch RPM contains machine code\n", stderr);
        goto done;
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
    fprintf(receipt, "format holy-import-record-1\nfamily rpm\nconverter holy-rpm-1\noriginal-sha256 %s\nsource-name ", hash);
    token(receipt, source); fputs("\nverification unverified\n", receipt);
    for (i = 0; i < input.group_count; ++i)
        if (!write_output(&input, NULL, NULL, NULL, NULL, NULL, &metadata, source, hash,
                          output, output_fd, receipt, (int)i, NULL, NULL, NULL, NULL, NULL)) goto done;
    fputs("state complete\n", receipt);
    if (fflush(receipt) || fsync(fileno(receipt))) goto done;
    if (fclose(receipt)) { receipt = NULL; goto done; }
    receipt = NULL;
    if (linkat(output_fd, temporary, output_fd, "conversion", 0) || fsync(output_fd)) goto done;
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: RPM import incomplete (status %d); no installed state changed\n", result);
    if (receipt) fclose(receipt);
    if (tar) fclose(tar);
    if (output_fd >= 0) { if (*temporary) unlinkat(output_fd, temporary, 0); close(output_fd); }
    if (input_fd >= 0) close(input_fd);
    if (snapshot) { unlink(snapshot); free(snapshot); }
    if (metadata.header) headerFree(metadata.header);
    free(metadata.name); free(metadata.version); free(metadata.release); free(metadata.arch);
    free_input(&input);
    return result;
#endif
}
