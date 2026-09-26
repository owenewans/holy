#define _POSIX_C_SOURCE 200809L
#include "verify.h"
#include "config.h"
#include "package.h"

#include <archive.h>
#include <archive_entry.h>
#include <errno.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct payload {
    char *path;
    char *link;
    char *hardlink;
    char *group;
    int directory;
    unsigned char hash[32];
    long long size;
    unsigned int mode;
    long long uid, gid;
    int matched;
};

static int safe_link(const char *path, const char *target)
{
    const char *p, *end;
    int depth = 0;
    if (!target || !*target) return 0;
    if (target[0] != '/') {
        for (p = path; *p; ++p) if (*p == '/') ++depth;
    }
    for (p = target; *p;) {
        size_t n;
        while (*p == '/') ++p;
        if (!*p) break;
        end = strchr(p, '/');
        n = end ? (size_t)(end - p) : strlen(p);
        if (n == 1 && p[0] == '.') { p += n; continue; }
        if (n == 2 && p[0] == '.' && p[1] == '.') {
            if (!depth) return 0;
            --depth;
        } else ++depth;
        p += n;
    }
    return 1;
}

static int compare(const void *a, const void *b)
{
    const struct payload *x = a, *y = b;
    return strcmp(x->path, y->path);
}

static int number(const char *s, int base, unsigned long long *out)
{
    char *end;
    errno = 0;
    *out = strtoull(s, &end, base);
    return s[0] && s[0] != '-' && !errno && !*end;
}

static int valid_group(const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    if (!*p || (p[0] == '-' && !p[1])) return 0;
    for (; *p; ++p)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '_' || *p == '-' || *p == '.'))
            return 0;
    return 1;
}

static int resolve_hardlinks(const char *path, struct payload *files, size_t count)
{
    size_t i;
    for (i = 0; i < count; ++i) {
        struct payload key, *target;
        if (!files[i].hardlink) continue;
        key.path = files[i].hardlink;
        target = bsearch(&key, files, count, sizeof *files, compare);
        if (!target || target->directory || target->link || target->hardlink ||
            files[i].size != 0 || files[i].mode != target->mode ||
            files[i].uid != target->uid || files[i].gid != target->gid) {
            fprintf(stderr, "%s: invalid hardlink target or attributes\n", path);
            return 0;
        }
        files[i].size = target->size;
        memcpy(files[i].hash, target->hash, sizeof files[i].hash);
    }
    return 1;
}

static int validate_manifest(const char *path, char *text, size_t size,
                             struct payload *files, size_t count)
{
    size_t start = 0, i, line = 0, seen = 0;
    char *error = NULL;
    for (i = 0; i <= size; ++i) {
        char **v = NULL;
        size_t n = 0;
        struct payload key, *found;
        unsigned long long mode, uid, gid, length;
        size_t j;
        int symlink, directory, hardlink;
        if (i < size && text[i] != '\n') continue;
        ++line;
        if (memchr(text + start, '\0', i - start) ||
            !holy_lex(text + start, i - start, &v, &n, path, line, &error)) {
            fprintf(stderr, "%s: HOLY/files:%zu: %s\n", path, line,
                    error ? error : "NUL or invalid record");
            free(error);
            return 0;
        }
        start = i + 1;
        if (!n) { holy_tokens_free(v, n); continue; }
        symlink = n && !strcmp(v[0], "symlink");
        directory = n && !strcmp(v[0], "dir");
        hardlink = n && !strcmp(v[0], "hardlink");
        if (((symlink || hardlink) ? n != 13 : n != 12 ||
             (strcmp(v[0], "file") && !directory)) ||
            !number(v[2], 8, &mode) || !number(v[5], 10, &uid) ||
            !number(v[6], 10, &gid) || !number(v[7], 10, &length) ||
            ((symlink || directory) ? strcmp(v[8], "-") || length != 0 :
                                     strlen(v[8]) != 64) ||
            strcmp(v[9], "none") ||
            strcmp(v[10], "-") ||
            ((symlink || directory) ? strcmp(v[11], "-") :
             strcmp(v[11], "-") && !valid_group(v[11])) ||
            (hardlink && (!valid_group(v[11]) || !v[12][0])) ||
            (symlink && (!v[12][0] || !safe_link(v[1], v[12]))) ||
            mode > 07777 || uid > 0x7fffffff || gid > 0x7fffffff ||
            length > 0x7fffffffffffffffULL) {
            fprintf(stderr, "%s: HOLY/files:%zu: unsupported or invalid record\n", path, line);
            holy_tokens_free(v, n);
            return 0;
        }
        key.path = v[1];
        found = count ? bsearch(&key, files, count, sizeof *files, compare) : NULL;
        if (!found || found->matched || !!found->link != !!symlink ||
            !!found->hardlink != !!hardlink ||
            found->directory != directory ||
            (symlink && strcmp(found->link, v[12])) ||
            (hardlink && strcmp(found->hardlink, v[12])) ||
            (unsigned long long)found->size != length ||
            found->mode != mode || (unsigned long long)found->uid != uid ||
            (unsigned long long)found->gid != gid) {
            fprintf(stderr, "%s: HOLY/files:%zu: payload or attributes mismatch\n", path, line);
            holy_tokens_free(v, n);
            return 0;
        }
        if (!symlink && !directory) {
            for (j = 0; j < 32; ++j) {
                char byte[3] = {v[8][j * 2], v[8][j * 2 + 1], 0};
                unsigned long long hex;
                if (!number(byte, 16, &hex) || hex != found->hash[j]) break;
            }
            if (j != 32) {
                fprintf(stderr, "%s: HOLY/files:%zu: payload SHA-256 mismatch\n", path, line);
                holy_tokens_free(v, n);
                return 0;
            }
        }
        if (!symlink && !directory && strcmp(v[11], "-")) {
            found->group = strdup(v[11]);
            if (!found->group) { holy_tokens_free(v, n); return 0; }
        }
        found->matched = 1;
        ++seen;
        holy_tokens_free(v, n);
    }
    if (seen != count) {
        fprintf(stderr, "%s: unlisted payload object\n", path);
        return 0;
    }
    for (i = 0; i < count; ++i) if (files[i].hardlink) {
        struct payload key, *target;
        key.path = files[i].hardlink;
        target = bsearch(&key, files, count, sizeof *files, compare);
        if (!target->matched || !files[i].group || !target->group ||
            strcmp(files[i].group, target->group)) {
            fprintf(stderr, "%s: hardlink group mismatch\n", path);
            return 0;
        }
    }
    return 1;
}

int holy_verify_with_output(const char *path, int emit)
{
    struct archive *a = NULL;
    struct archive_entry *entry;
    struct payload *files = NULL;
    size_t count = 0, i, manifest_size = 0, symlinks = 0, directories = 0, hardlinks = 0;
    char *manifest = NULL;
    char buffer[8192];
    int status, seen = 0, ok = 0;
    if (!holy_package_inspect(path, emit)) return 0;
    a = archive_read_new();
    if (!a || archive_read_support_filter_lz4(a) != ARCHIVE_OK ||
        archive_read_support_format_tar(a) != ARCHIVE_OK ||
        archive_read_open_filename(a, path, 8192) != ARCHIVE_OK) {
        fprintf(stderr, "%s: archive open failed\n", path);
        goto done;
    }
    while ((status = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        const char *name = archive_entry_pathname(entry);
        int is_manifest = name && !strcmp(name, "HOLY/files");
        int is_data = name && !strncmp(name, "DATA/", 5) && name[5];
        EVP_MD_CTX *hash = NULL;
        la_ssize_t got;
        unsigned int digest_size;
        unsigned long long actual = 0;
        if (!holy_safe_archive_path(name)) {
            fprintf(stderr, "%s: unsafe archive path\n", path);
            goto done;
        }
        if (is_data && archive_entry_xattr_count(entry) > 0) {
            fprintf(stderr, "%s: unsupported payload xattrs\n", path);
            goto done;
        }
        if (is_data && archive_entry_acl_types(entry)) {
            fprintf(stderr, "%s: unsupported payload ACL\n", path);
            goto done;
        }
        if ((!strcmp(name, "HOLY") || !strcmp(name, "HOLY/") ||
             !strcmp(name, "DATA") || !strcmp(name, "DATA/")) &&
            archive_entry_filetype(entry) != AE_IFDIR) {
            fprintf(stderr, "%s: archive root marker is not a directory\n", path);
            goto done;
        }
        if (is_manifest) {
            if (seen++ || archive_entry_filetype(entry) != AE_IFREG ||
                archive_entry_size(entry) < 0 || archive_entry_size(entry) > 16 * 1024 * 1024) {
                fprintf(stderr, "%s: invalid HOLY/files\n", path);
                goto done;
            }
        }
        if (is_data) {
            struct payload *next;
            size_t pathlen = strlen(name + 5);
            const char *target_path = archive_entry_hardlink(entry);
            if ((archive_entry_filetype(entry) != AE_IFREG &&
                 archive_entry_filetype(entry) != AE_IFLNK &&
                 archive_entry_filetype(entry) != AE_IFDIR &&
                 !(target_path && archive_entry_filetype(entry) == 0)) ||
                archive_entry_size(entry) < 0 || count == (size_t)-1 / sizeof *files) {
                fprintf(stderr, "%s: unsupported payload type\n", path);
                goto done;
            }
            next = realloc(files, (count + 1) * sizeof *files);
            if (!next) goto done;
            files = next;
            files[count].path = strdup(name + 5);
            if (!files[count].path) goto done;
            if (files[count].path[pathlen - 1] == '/' &&
                archive_entry_filetype(entry) != AE_IFDIR) {
                free(files[count].path);
                fprintf(stderr, "%s: non-directory path ends in slash\n", path);
                goto done;
            }
            if (files[count].path[pathlen - 1] == '/')
                files[count].path[pathlen - 1] = '\0';
            files[count].link = NULL;
            files[count].hardlink = NULL;
            files[count].group = NULL;
            files[count].directory = archive_entry_filetype(entry) == AE_IFDIR;
            files[count].size = archive_entry_size(entry);
            files[count].mode = archive_entry_perm(entry);
            files[count].uid = archive_entry_uid(entry);
            files[count].gid = archive_entry_gid(entry);
            files[count].matched = 0;
            if (target_path) {
                if ((archive_entry_filetype(entry) != AE_IFREG &&
                     archive_entry_filetype(entry) != 0) ||
                    !holy_safe_archive_path(target_path) ||
                    strncmp(target_path, "DATA/", 5) || !target_path[5]) {
                    free(files[count].path);
                    fprintf(stderr, "%s: unsafe hardlink target\n", path);
                    goto done;
                }
                files[count].hardlink = strdup(target_path + 5);
                if (!files[count].hardlink) { free(files[count].path); goto done; }
                ++hardlinks;
            } else if (files[count].directory) {
                if (files[count].size != 0) {
                    free(files[count].path);
                    fprintf(stderr, "%s: directory contains archive data\n", path);
                    goto done;
                }
                ++directories;
            } else if (archive_entry_filetype(entry) == AE_IFLNK) {
                const char *target = archive_entry_symlink(entry);
                if (!safe_link(files[count].path, target)) {
                    free(files[count].path);
                    fprintf(stderr, "%s: unsafe symlink target\n", path);
                    goto done;
                }
                files[count].link = strdup(target);
                if (!files[count].link) { free(files[count].path); goto done; }
                ++symlinks;
            } else {
                hash = EVP_MD_CTX_new();
                if (!hash || EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1) {
                    EVP_MD_CTX_free(hash);
                    free(files[count].path);
                    goto done;
                }
            }
        }
        while ((got = archive_read_data(a, buffer, sizeof buffer)) > 0) {
            if (is_data) actual += (unsigned long long)got;
            if (hash && EVP_DigestUpdate(hash, buffer, (size_t)got) != 1) break;
            if (is_manifest) {
                char *next;
                if ((size_t)got > 16 * 1024 * 1024 - manifest_size) break;
                next = realloc(manifest, manifest_size + (size_t)got + 1);
                if (!next) break;
                manifest = next;
                memcpy(manifest + manifest_size, buffer, (size_t)got);
                manifest_size += (size_t)got;
                manifest[manifest_size] = '\0';
            }
        }
        if (got < 0 || got > 0 ||
            (is_data && actual != (unsigned long long)files[count].size) ||
            (hash && (EVP_DigestFinal_ex(hash, files[count].hash, &digest_size) != 1 ||
                      digest_size != 32))) {
            EVP_MD_CTX_free(hash);
            if (is_data) { free(files[count].path); free(files[count].link); free(files[count].hardlink); }
            fprintf(stderr, "%s: invalid archive data\n", path);
            goto done;
        }
        if (is_data) ++count;
        EVP_MD_CTX_free(hash);
    }
    if (status != ARCHIVE_EOF || !seen) {
        fprintf(stderr, "%s: missing HOLY/files or truncated archive\n", path);
        goto done;
    }
    if (count) qsort(files, count, sizeof *files, compare);
    for (i = 1; i < count; ++i)
        if (!strcmp(files[i - 1].path, files[i].path)) {
            fprintf(stderr, "%s: duplicate payload path\n", path);
            goto done;
        }
    if (!resolve_hardlinks(path, files, count)) goto done;
    ok = validate_manifest(path, manifest ? manifest : "", manifest_size, files, count);
    if (ok && emit) printf("verified %zu regular files, %zu symlinks, %zu directories, %zu hardlinks\n",
                   count - symlinks - directories - hardlinks, symlinks, directories, hardlinks);
done:
    for (i = 0; i < count; ++i) {
        free(files[i].path);
        free(files[i].link);
        free(files[i].hardlink);
        free(files[i].group);
    }
    free(files);
    free(manifest);
    if (a) archive_read_free(a);
    return ok;
}

int holy_verify(const char *path)
{
    return holy_verify_with_output(path, 1);
}
