#define _POSIX_C_SOURCE 200809L
#include "repo.h"
#include "config.h"
#include "fetch.h"
#include "cache.h"
#include "deps.h"
#include "extract.h"
#include "provides.h"
#include "resolve.h"
#include "package.h"
#include "scan.h"
#include "stage.h"
#include "verify.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int same_identity(const struct holy_package_identity *a,
                         const struct holy_package_identity *b)
{
    return !strcmp(a->name, b->name) && !strcmp(a->version, b->version) &&
           !strcmp(a->release, b->release) && !strcmp(a->os, b->os) &&
           !strcmp(a->arch, b->arch) && !strcmp(a->libc, b->libc);
}

static int same_slot(const struct holy_package_identity *a,
                     const struct holy_package_identity *b)
{
    return !strcmp(a->name, b->name) && !strcmp(a->os, b->os) &&
           !strcmp(a->arch, b->arch) && !strcmp(a->libc, b->libc);
}

struct claim {
    char *kind, *name, *arch, *libc, *version, *evidence;
};

struct object {
    char *filename;
    struct holy_package_identity identity;
    int provider_match;
    struct claim *claims;
    size_t claim_count;
    char **files;
    size_t file_count;
};

static void free_files(struct object *object)
{
    size_t i;
    for (i = 0; i < object->file_count; ++i) free(object->files[i]);
    free(object->files);
}

static int add_file(struct object *object, const char *path)
{
    char **next;
    char *copy;
    if (object->file_count == (size_t)-1 / sizeof *object->files) return 0;
    copy = strdup(path);
    if (!copy) return 0;
    next = realloc(object->files, (object->file_count + 1) * sizeof *object->files);
    if (!next) { free(copy); return 0; }
    object->files = next;
    object->files[object->file_count++] = copy;
    return 1;
}

static int collect_file(void *opaque, const struct holy_manifest_entry *entry)
{
    return entry->directory || add_file(opaque, entry->path);
}

struct file_cursor { struct object *object; size_t index; };

static int compare_file(void *opaque, const struct holy_manifest_entry *entry)
{
    struct file_cursor *cursor = opaque;
    if (entry->directory) return 1;
    return cursor->index < cursor->object->file_count &&
           !strcmp(cursor->object->files[cursor->index++], entry->path);
}

static void free_claims(struct object *object)
{
    size_t i;
    for (i = 0; i < object->claim_count; ++i) {
        struct claim *c = &object->claims[i];
        free(c->kind); free(c->name); free(c->arch);
        free(c->libc); free(c->version); free(c->evidence);
    }
    free(object->claims);
}

static int add_claim(struct object *object, const char *kind, const char *name,
                     const char *arch, const char *libc, const char *version,
                     const char *evidence)
{
    struct claim c = {0}, *next;
    if (object->claim_count == (size_t)-1 / sizeof *object->claims) return 0;
    c.kind = strdup(kind); c.name = strdup(name); c.arch = strdup(arch);
    c.libc = strdup(libc); c.version = strdup(version);
    c.evidence = strdup(evidence);
    if (!c.kind || !c.name || !c.arch || !c.libc || !c.version || !c.evidence) {
        free(c.kind); free(c.name); free(c.arch);
        free(c.libc); free(c.version); free(c.evidence);
        return 0;
    }
    next = realloc(object->claims,
                   (object->claim_count + 1) * sizeof *object->claims);
    if (!next) {
        free(c.kind); free(c.name); free(c.arch);
        free(c.libc); free(c.version); free(c.evidence);
        return 0;
    }
    object->claims = next;
    object->claims[object->claim_count++] = c;
    return 1;
}

static int collect_claim(void *opaque, const char *kind, const char *name,
                         const char *arch, const char *libc,
                         const char *version, const char *evidence)
{
    return add_claim(opaque, kind, name, arch, libc, version, evidence);
}

struct claim_cursor { struct object *object; size_t index; };

static int compare_claim(void *opaque, const char *kind, const char *name,
                         const char *arch, const char *libc,
                         const char *version, const char *evidence)
{
    struct claim_cursor *cursor = opaque;
    struct claim *c;
    if (cursor->index == cursor->object->claim_count) return 0;
    c = &cursor->object->claims[cursor->index++];
    return !strcmp(c->kind, kind) && !strcmp(c->name, name) &&
           !strcmp(c->arch, arch) && !strcmp(c->libc, libc) &&
           !strcmp(c->version, version) && !strcmp(c->evidence, evidence);
}

static int compare_names(const void *left, const void *right)
{
    const struct object *a = left, *b = right;
    return strcmp(a->filename, b->filename);
}

static int quote(FILE *fp, const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    if (fputc('"', fp) == EOF) return 0;
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') {
            if (fputc('\\', fp) == EOF || fputc(*p, fp) == EOF) return 0;
        } else if (*p <= 32 || *p >= 127) {
            if (fprintf(fp, "\\x%02x", (unsigned int)*p) < 0) return 0;
        } else if (fputc(*p, fp) == EOF) return 0;
    }
    return fputc('"', fp) != EOF;
}

static void json_string(const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    putchar('"');
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p >= 32 && *p < 127) putchar(*p);
        else printf("\\u%04x", (unsigned int)*p);
    }
    putchar('"');
}

static void candidate_json(const struct object *object)
{
    const struct holy_package_identity *id = &object->identity;
    fputs("{\"schema\":\"holy-repo-candidates-1\",\"type\":\"candidate\",\"name\":", stdout);
    json_string(id->name);
    fputs(",\"version\":", stdout);
    json_string(id->version);
    fputs(",\"release\":", stdout);
    json_string(id->release);
    fputs(",\"os\":", stdout);
    json_string(id->os);
    fputs(",\"arch\":", stdout);
    json_string(id->arch);
    fputs(",\"libc\":", stdout);
    json_string(id->libc);
    fputs(",\"filename\":", stdout);
    json_string(object->filename);
    printf(",\"sha256\":\"%s\",\"size\":%" PRIu64 "}\n", id->digest, id->size);
}

static int record(FILE *fp, const struct object *object)
{
    const struct holy_package_identity *id = &object->identity;
    const char *values[] = {id->name, id->version, id->release, id->os,
                            id->arch, id->libc, object->filename};
    size_t i;
    if (fputs("package", fp) == EOF) return 0;
    for (i = 0; i < sizeof values / sizeof *values; ++i) {
        if (fputc(' ', fp) == EOF || !quote(fp, values[i])) return 0;
    }
    return fprintf(fp, " %s %" PRIu64 "\n", id->digest, id->size) >= 0;
}

static int claim_record(FILE *fp, const struct object *object,
                        const struct claim *claim)
{
    const char *values[] = {claim->kind, claim->name, claim->arch,
                            claim->libc, claim->version, claim->evidence};
    size_t i;
    if (fprintf(fp, "claim %s", object->identity.digest) < 0) return 0;
    for (i = 0; i < sizeof values / sizeof *values; ++i)
        if (fputc(' ', fp) == EOF || !quote(fp, values[i])) return 0;
    return fputc('\n', fp) != EOF;
}

static int file_record(FILE *fp, const struct object *object, const char *path)
{
    return fprintf(fp, "file %s ", object->identity.digest) >= 0 &&
           quote(fp, path) && fputc('\n', fp) != EOF;
}

static int digest_file(const char *path, char hex[65])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char hash[32], buffer[65536];
    unsigned int length;
    size_t n, i;
    FILE *fp = fopen(path, "rb");
    int ok = fp && ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    while (ok && (n = fread(buffer, 1, sizeof buffer, fp)) > 0)
        ok = EVP_DigestUpdate(ctx, buffer, n) == 1;
    if (ok) ok = !ferror(fp) && EVP_DigestFinal_ex(ctx, hash, &length) == 1 &&
                 length == sizeof hash;
    if (ok) {
        for (i = 0; i < sizeof hash; ++i)
            snprintf(hex + i * 2, 3, "%02x", hash[i]);
        hex[64] = '\0';
    }
    if (fp) fclose(fp);
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int read_current(int dir, char digest[65])
{
    char line[72];
    struct stat st;
    size_t i;
    int fd = openat(dir, "current", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size != sizeof line ||
        pread(fd, line, sizeof line, 0) != sizeof line ||
        memcmp(line, "sha256 ", 7) || line[71] != '\n') {
        close(fd);
        return -1;
    }
    close(fd);
    for (i = 0; i < 64; ++i)
        if (!((line[i + 7] >= '0' && line[i + 7] <= '9') ||
              (line[i + 7] >= 'a' && line[i + 7] <= 'f'))) return -1;
    memcpy(digest, line + 7, 64);
    digest[64] = '\0';
    return 1;
}

int holy_repo_index(const char *directory)
{
    struct object *objects = NULL;
    DIR *listing = NULL;
    struct dirent *entry;
    struct stat st;
    size_t count = 0, i, j;
    int dir = -1, temp = -1, ok = 0;
    FILE *stream = NULL;
    char temporary[43] = {0};

    dir = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || flock(dir, LOCK_EX) < 0) goto done;
    listing = fdopendir(dup(dir));
    if (!listing) goto done;
    errno = 0;
    while ((entry = readdir(listing)) != NULL) {
        size_t length = strlen(entry->d_name);
        struct object *next;
        if (length < 6 || strcmp(entry->d_name + length - 5, ".holy")) continue;
        if (count == (size_t)-1 / sizeof *objects) goto done;
        next = realloc(objects, (count + 1) * sizeof *objects);
        if (!next) goto done;
        objects = next;
        memset(&objects[count], 0, sizeof *objects);
        objects[count].filename = strdup(entry->d_name);
        if (!objects[count].filename) goto done;
        ++count;
        errno = 0;
    }
    if (errno) goto done;
    closedir(listing);
    listing = NULL;
    if (count) qsort(objects, count, sizeof *objects, compare_names);
    for (i = 0; i < count; ++i) {
        int input = openat(dir, objects[i].filename,
                           O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        char *snapshot;
        if (input < 0) goto done;
        snapshot = holy_stage_fd(input, "holy-index");
        close(input);
        if (!snapshot) goto done;
        if (!holy_verify_with_output(snapshot, 0) ||
            !holy_scan_local_with_output(snapshot, 0) ||
            !holy_deps_local_with_output(snapshot, 0) ||
            !holy_provides_local(snapshot, 0) ||
            !holy_package_identity(snapshot, &objects[i].identity) ||
            !holy_provides_visit(snapshot, collect_claim, &objects[i]) ||
            !holy_verify_visit(snapshot, collect_file, &objects[i])) {
            unlink(snapshot);
            free(snapshot);
            goto done;
        }
        unlink(snapshot);
        free(snapshot);
        for (j = 0; j < i; ++j) {
            struct holy_package_identity *a = &objects[i].identity;
            struct holy_package_identity *b = &objects[j].identity;
            if (same_identity(a, b)) {
                fprintf(stderr, "holypkg: duplicate package identity\n");
                goto done;
            }
        }
    }
    if (fstatat(dir, "index", &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!S_ISREG(st.st_mode)) {
            fprintf(stderr, "holypkg: index is not a regular file\n");
            goto done;
        }
    } else if (errno != ENOENT) {
        goto done;
    }
    temp = holy_temporary_at(dir, temporary);
    if (temp < 0) goto done;
    stream = fdopen(temp, "w");
    if (!stream) goto done;
    temp = -1;
    if (fputs("format holy-index-prototype-3\ncoverage files complete\n", stream) == EOF) goto done;
    for (i = 0; i < count; ++i) {
        if (!record(stream, &objects[i])) goto done;
        for (j = 0; j < objects[i].claim_count; ++j)
            if (!claim_record(stream, &objects[i], &objects[i].claims[j])) goto done;
        for (j = 0; j < objects[i].file_count; ++j)
            if (!file_record(stream, &objects[i], objects[i].files[j])) goto done;
    }
    if (fflush(stream) || fchmod(fileno(stream), 0644) || fsync(fileno(stream)))
        goto done;
    if (fclose(stream)) { stream = NULL; goto done; }
    stream = NULL;
    if (renameat(dir, temporary, dir, "index") || fsync(dir)) goto done;
    temporary[0] = '\0';
    printf("indexed %zu packages\n", count);
    ok = 1;
done:
    if (!ok) fprintf(stderr, "holypkg: repository index incomplete\n");
    if (stream) fclose(stream);
    if (temp >= 0) close(temp);
    if (temporary[0] && dir >= 0) unlinkat(dir, temporary, 0);
    if (listing) closedir(listing);
    for (i = 0; i < count; ++i) {
        free(objects[i].filename);
        holy_package_identity_free(&objects[i].identity);
        free_claims(&objects[i]);
        free_files(&objects[i]);
    }
    free(objects);
    if (dir >= 0) close(dir);
    return ok;
}

static int parse_record(char **v, size_t n, struct object *object)
{
    unsigned long long size;
    char *end;
    size_t i;
    const char *filename;
    if (n != 10 || strcmp(v[0], "package")) return 0;
    filename = v[7];
    i = strlen(filename);
    if (i < 6 || strcmp(filename + i - 5, ".holy") || strchr(filename, '/') ||
        strlen(v[8]) != 64 || !v[1][0] || !v[2][0] || !v[3][0]) return 0;
    for (i = 0; i < 64; ++i)
        if (!((v[8][i] >= '0' && v[8][i] <= '9') ||
              (v[8][i] >= 'a' && v[8][i] <= 'f'))) return 0;
    errno = 0;
    size = strtoull(v[9], &end, 10);
    if (errno || !v[9][0] || *end || v[9][0] == '-' || !size) return 0;
    object->filename = v[7]; v[7] = NULL;
    object->identity.name = v[1]; v[1] = NULL;
    object->identity.version = v[2]; v[2] = NULL;
    object->identity.release = v[3]; v[3] = NULL;
    object->identity.os = v[4]; v[4] = NULL;
    object->identity.arch = v[5]; v[5] = NULL;
    object->identity.libc = v[6]; v[6] = NULL;
    memcpy(object->identity.digest, v[8], 65);
    object->identity.size = size;
    return 1;
}

static int parse_claim(char **v, size_t n, struct object *object)
{
    size_t i;
    if (n != 8 || strcmp(v[0], "claim") ||
        strcmp(v[1], object->identity.digest) ||
        !holy_provides_claim_valid(v[2], v[3], v[4], v[5], v[6], v[7]))
        return 0;
    for (i = 0; i < object->claim_count; ++i) {
        const struct claim *c = &object->claims[i];
        if (!strcmp(c->kind, v[2]) && !strcmp(c->name, v[3]) &&
            !strcmp(c->arch, v[4]) && !strcmp(c->libc, v[5]) &&
            !strcmp(c->version, v[6])) return 0;
    }
    return add_claim(object, v[2], v[3], v[4], v[5], v[6], v[7]);
}

static int safe_target_path(const char *path)
{
    size_t length = strlen(path);
    char *archive_path;
    int valid;
    if (!length || length > (size_t)-1 - 6 || path[length - 1] == '/') return 0;
    archive_path = malloc(length + 6);
    if (!archive_path) return 0;
    memcpy(archive_path, "DATA/", 5);
    memcpy(archive_path + 5, path, length + 1);
    valid = holy_safe_archive_path(archive_path);
    free(archive_path);
    return valid;
}

static int parse_file(char **v, size_t n, struct object *object)
{
    if (n != 3 || strcmp(v[0], "file") ||
        strcmp(v[1], object->identity.digest) ||
        !safe_target_path(v[2]) ||
        (object->file_count && strcmp(object->files[object->file_count - 1], v[2]) >= 0))
        return 0;
    return add_file(object, v[2]);
}

static int indexed_file(const struct object *object, const char *path)
{
    size_t low = 0, high = object->file_count;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        int cmp = strcmp(object->files[middle], path);
        if (!cmp) return 1;
        if (cmp < 0) low = middle + 1;
        else high = middle;
    }
    return 0;
}

static unsigned char ascii_lower(unsigned char c)
{
    return c >= 'A' && c <= 'Z' ? (unsigned char)(c + 'a' - 'A') : c;
}

static int ascii_prefix(const char *text, const char *prefix)
{
    while (*prefix) {
        if (!*text || ascii_lower((unsigned char)*text++) !=
                      ascii_lower((unsigned char)*prefix++)) return 0;
    }
    return 1;
}

static int fuzzy_rank(const char *query, const char *target)
{
    size_t q = strlen(query), t = strlen(target), i, j;
    unsigned int prev[129], next[129], row_min;
    if (!q || !t || q > 256 || t > 256) return -1;
    if (ascii_prefix(target, query)) return q == t ? 0 : 1;
    for (i = 1; i < t; ++i)
        if (ascii_prefix(target + i, query)) return 2;
    if (q > 128 || t > 128 || q > t + 2 || t > q + 2) return -1;
    for (j = 0; j <= t; ++j) prev[j] = (unsigned int)j;
    for (i = 1; i <= q; ++i) {
        next[0] = (unsigned int)i;
        row_min = next[0];
        for (j = 1; j <= t; ++j) {
            unsigned int cost = ascii_lower((unsigned char)query[i - 1]) ==
                                ascii_lower((unsigned char)target[j - 1]) ? 0 : 1;
            unsigned int deletion = prev[j] + 1;
            unsigned int insertion = next[j - 1] + 1;
            unsigned int replacement = prev[j - 1] + cost;
            next[j] = deletion < insertion ? deletion : insertion;
            if (replacement < next[j]) next[j] = replacement;
            if (next[j] < row_min) row_min = next[j];
        }
        if (row_min > 2) return -1;
        memcpy(prev, next, (t + 1) * sizeof *prev);
    }
    return prev[t] == 1 ? 3 : prev[t] == 2 ? 4 : -1;
}

static int file_hint(const struct object *object, const char *query,
                     const char **matched)
{
    const char *basename = strrchr(query, '/');
    size_t i;
    int best = -1;
    basename = basename ? basename + 1 : query;
    *matched = NULL;
    if (!*basename) return -1;
    for (i = 0; i < object->file_count; ++i) {
        const char *path = object->files[i], *name = strrchr(path, '/');
        int score = fuzzy_rank(basename, name ? name + 1 : path);
        if (query[0] == '/' && score >= 0) {
            if (!strcmp(query + 1, path)) score = 0;
            else ++score;
        }
        if (score >= 0 && (best < 0 || score < best ||
            (score == best && strcmp(path, *matched) < 0))) {
            best = score;
            *matched = path;
        }
    }
    return best;
}

struct mirror {
    const char *base, *ca_file, *downloads;
    int status;
};

struct stage_request {
    const char *root;
    struct holy_repo_set *set;
    const struct holy_package_identity *slot;
    int index_only;
};

static int mirror_object(struct mirror *mirror, int dir, const struct object *object)
{
    char *url = holy_fetch_child_url(mirror->base, object->filename);
    char name[70];
    int downloads, ok;
    if (!url) { mirror->status = 2; return 0; }
    mirror->status = holy_fetch_https(url, object->identity.digest,
                                      mirror->downloads, mirror->ca_file, 0);
    free(url);
    if (mirror->status) return 0;
    downloads = open(mirror->downloads, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (downloads < 0) { mirror->status = 1; return 0; }
    snprintf(name, sizeof name, "%s.holy", object->identity.digest);
    ok = !linkat(downloads, name, dir, object->filename, 0) && !fsync(dir);
    if (ok) ok = !unlinkat(downloads, name, 0) && !fsync(downloads);
    close(downloads);
    if (!ok) mirror->status = 1;
    return ok;
}

static int list(const char *directory, const char *query,
                 const char *forced_index, int lock, int emit,
                 const char *fetch_digest, const char *output,
                 const char *provider_kind, const char *provider_name,
                 const char *solve_name, const char *solve_choice,
                  int solve_json, int *solve_rc, struct mirror *mirror,
                  int extract_name, const struct stage_request *stage,
                  const char *file_query)
{
    struct object *objects = NULL;
    char **candidate_snapshots = NULL;
    struct stat st;
    FILE *index = NULL;
    char *line = NULL, *error = NULL, *index_snapshot = NULL, *chosen = NULL;
    char expected[65], actual_digest[65], index_name[71];
    size_t capacity = 0, count = 0, i, j, number = 0;
    ssize_t length;
    int dir = -1, fd = -1, ok = 0, indexed = 0, file_index = 0;

    dir = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || (lock && flock(dir, LOCK_SH) < 0)) goto done;
    if (forced_index) {
        if (!*forced_index || strlen(forced_index) >= sizeof index_name ||
            strchr(forced_index, '/')) goto done;
        strcpy(index_name, forced_index);
    } else {
        if (read_current(dir, expected) != 1) goto done;
        snprintf(index_name, sizeof index_name, "index.%s", expected);
    }
    fd = openat(dir, index_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size < 0 || st.st_size > 16 * 1024 * 1024) goto done;
    index_snapshot = holy_stage_fd(fd, "holy-catalog");
    close(fd);
    fd = -1;
    if (!index_snapshot || (!forced_index &&
        (!digest_file(index_snapshot, actual_digest) ||
         strcmp(actual_digest, expected)))) goto done;
    index = fopen(index_snapshot, "r");
    if (!index) goto done;
    while ((length = getline(&line, &capacity, index)) >= 0) {
        char **v = NULL;
        size_t n = 0;
        struct object *next;
        ++number;
        if (length > 1024 * 1024 || memchr(line, '\0', (size_t)length) ||
            !holy_lex(line, (size_t)length, &v, &n, "index", number, &error)) {
            holy_tokens_free(v, n);
            goto done;
        }
        if (number == 1) {
            int valid = n == 2 && !strcmp(v[0], "format") &&
                        (!strcmp(v[1], "holy-index-prototype-1") ||
                         !strcmp(v[1], "holy-index-prototype-2") ||
                         !strcmp(v[1], "holy-index-prototype-3"));
            if (valid) {
                indexed = strcmp(v[1], "holy-index-prototype-1") != 0;
                file_index = !strcmp(v[1], "holy-index-prototype-3");
            }
            holy_tokens_free(v, n);
            if (!valid) goto done;
            continue;
        }
        if (file_index && number == 2) {
            int valid = n == 3 && !strcmp(v[0], "coverage") &&
                        !strcmp(v[1], "files") && !strcmp(v[2], "complete");
            holy_tokens_free(v, n);
            if (!valid) goto done;
            continue;
        }
        if (indexed && n && !strcmp(v[0], "claim")) {
            int valid = count && !objects[count - 1].file_count &&
                        parse_claim(v, n, &objects[count - 1]);
            holy_tokens_free(v, n);
            if (!valid) goto done;
            continue;
        }
        if (file_index && n && !strcmp(v[0], "file")) {
            int valid = count && parse_file(v, n, &objects[count - 1]);
            holy_tokens_free(v, n);
            if (!valid) goto done;
            continue;
        }
        if (count == (size_t)-1 / sizeof *objects) {
            holy_tokens_free(v, n);
            goto done;
        }
        next = realloc(objects, (count + 1) * sizeof *objects);
        if (!next) { holy_tokens_free(v, n); goto done; }
        objects = next;
        memset(&objects[count], 0, sizeof *objects);
        if (!parse_record(v, n, &objects[count])) {
            holy_tokens_free(v, n);
            goto done;
        }
        holy_tokens_free(v, n);
        ++count;
        for (i = 0; i + 1 < count; ++i)
            if (!strcmp(objects[i].filename, objects[count - 1].filename) ||
                same_identity(&objects[i].identity, &objects[count - 1].identity))
                goto done;
    }
    if (ferror(index) || !number || (file_index && number < 2)) goto done;
    if (mirror) {
        for (i = 0; i < count; ++i)
            if (!mirror_object(mirror, dir, &objects[i])) goto done;
    }
    if (solve_name) {
        candidate_snapshots = calloc(count ? count : 1, sizeof *candidate_snapshots);
        if (!candidate_snapshots) goto done;
    }
    for (i = 0; i < count; ++i) {
        struct holy_package_identity actual;
        char *snapshot;
        int input, matches;
        if (stage && (stage->index_only ||
            (stage->slot && !same_slot(&objects[i].identity, stage->slot))))
            continue;
        if (query && (emit == 1 || emit == 3) &&
            strcmp(query, objects[i].identity.name)) continue;
        if (fetch_digest && strcmp(fetch_digest, objects[i].identity.digest))
            continue;
        if (solve_name && output && !stage &&
            strcmp(solve_name, objects[i].identity.name)) continue;
        if (emit == 5 && query && fuzzy_rank(query, objects[i].identity.name) < 0)
            continue;
        if (file_query) {
            const char *matched;
            if (!file_index || (emit == 6 ?
                file_hint(&objects[i], file_query, &matched) < 0 :
                !indexed_file(&objects[i], file_query))) continue;
        }
        if (indexed && provider_kind) {
            size_t k;
            objects[i].provider_match =
                !strcmp(provider_kind, "package") &&
                !strcmp(provider_name, objects[i].identity.name);
            for (k = 0; k < objects[i].claim_count; ++k)
                if (!strcmp(objects[i].claims[k].kind, provider_kind) &&
                    !strcmp(objects[i].claims[k].name, provider_name))
                    objects[i].provider_match = 1;
            if (!objects[i].provider_match) continue;
        }
        input = openat(dir, objects[i].filename,
                            O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        if (input < 0) goto done;
        snapshot = holy_stage_fd(input, "holy-list");
        close(input);
        if (!snapshot) goto done;
        matches = holy_verify_with_output(snapshot, 0) &&
                  holy_scan_local_with_output(snapshot, 0) &&
                  holy_deps_local_with_output(snapshot, 0) &&
                  holy_provides_local(snapshot, 0) &&
                  holy_package_identity(snapshot, &actual);
        if (matches) {
            matches = same_identity(&objects[i].identity, &actual) &&
                      !strcmp(objects[i].identity.digest, actual.digest) &&
                      objects[i].identity.size == actual.size;
            holy_package_identity_free(&actual);
        }
        if (!matches) {
            unlink(snapshot);
            free(snapshot);
            goto done;
        }
        if (indexed) {
            struct claim_cursor cursor = {&objects[i], 0};
            if (!holy_provides_visit(snapshot, compare_claim, &cursor) ||
                cursor.index != objects[i].claim_count) {
                unlink(snapshot);
                free(snapshot);
                goto done;
            }
        }
        if (file_index) {
            struct file_cursor cursor = {&objects[i], 0};
            if (!holy_verify_visit(snapshot, compare_file, &cursor) ||
                cursor.index != objects[i].file_count) {
                unlink(snapshot);
                free(snapshot);
                goto done;
            }
        }
        if (provider_kind && !indexed) {
            int claim = 0;
            if (!holy_provides_match(snapshot, provider_kind,
                                     provider_name, &claim)) {
                unlink(snapshot);
                free(snapshot);
                goto done;
            }
            objects[i].provider_match = claim ||
                (!strcmp(provider_kind, "package") &&
                 !strcmp(provider_name, objects[i].identity.name));
        }
        if (solve_name) candidate_snapshots[i] = snapshot;
        else if (fetch_digest && !strcmp(fetch_digest, objects[i].identity.digest))
            chosen = snapshot;
        else {
            unlink(snapshot);
            free(snapshot);
        }
    }
    if (fetch_digest && (!chosen || !holy_fetch_local(chosen, output))) goto done;
    if (solve_name) {
        const char **paths = NULL;
        size_t root = count, roots = 0, next = 1;
        for (i = 0; i < count; ++i) if (!strcmp(objects[i].identity.name, solve_name)) {
            root = i;
            ++roots;
        }
        if (roots != 1 && !(stage && stage->slot)) {
            *solve_rc = roots ? 3 : 6;
            fprintf(stderr, "holypkg: repository root %s\n",
                    roots ? "requires package choice" : "not found");
            if (solve_json)
                printf("{\"schema\":\"holy-local-solve-1\",\"type\":\"error\",\"code\":\"%s\"}\n",
                       roots ? "decision-required" : "unavailable-artifact");
        } else if (stage) {
            size_t position = 0;
            *solve_rc = 6;
            if (count > 100000) { ok = 1; goto done; }
            stage->set->digests = calloc(count ? count : 1, sizeof *stage->set->digests);
            if (!stage->set->digests) { *solve_rc = 1; ok = 1; goto done; }
            for (i = 0; i < count; ++i) {
                if (stage->slot && !same_slot(&objects[i].identity, stage->slot))
                    continue;
                size_t selected = stage->slot ? i : i ? (i <= root ? i - 1 : i) : root;
                char actual[65];
                if (position >= 10000) { *solve_rc = 6; ok = 1; goto done; }
                if (!holy_cache_stage_local_digest(candidate_snapshots[selected],
                                                   stage->root, actual)) {
                    *solve_rc = 1; ok = 1; goto done;
                }
                if (strcmp(actual, objects[selected].identity.digest)) {
                    *solve_rc = 4; ok = 1; goto done;
                }
                stage->set->digests[position] = strdup(actual);
                if (!stage->set->digests[position]) { *solve_rc = 1; ok = 1; goto done; }
                ++position;
                stage->set->count = position;
            }
            memcpy(stage->set->index, expected, 65);
            *solve_rc = position ? 0 : 6;
        } else if (output) {
            *solve_rc = (extract_name ?
                         holy_extract_local(candidate_snapshots[root], output) :
                         holy_fetch_local(candidate_snapshots[root], output)) ? 0 : 1;
        } else {
            paths = calloc(count, sizeof *paths);
            if (!paths) goto done;
            paths[0] = candidate_snapshots[root];
            for (i = 0; i < count; ++i)
                if (i != root) paths[next++] = candidate_snapshots[i];
            *solve_rc = holy_resolve_local(paths, count, solve_json, expected,
                                           solve_choice);
            free(paths);
        }
    }
    if (emit == 5 || emit == 6) {
        size_t matches = 0, shown = 0;
        int rank;
        for (rank = 0; rank <= 5; ++rank) for (j = 0; j < count; ++j) {
            const char *matched = NULL;
            int score = emit == 5 ? fuzzy_rank(query, objects[j].identity.name) :
                        file_index ? file_hint(&objects[j], file_query, &matched) : -1;
            if (score != rank) continue;
            ++matches;
            if (shown == 20) continue;
            printf("suggestion score %d %s ", score, emit == 5 ? "name" : "path");
            if (!quote(stdout, emit == 5 ? objects[j].identity.name : matched) ||
                fputc('\n', stdout) == EOF || !record(stdout, &objects[j])) goto done;
            ++shown;
        }
        if (emit == 6) {
            printf("coverage files %s index %s time %lld\n",
                   file_index ? "complete" : "unavailable", expected,
                   (long long)st.st_mtime);
            if (!file_index) {
                fputs("status unknown: source has no complete file index\n", stdout);
                if (solve_rc) *solve_rc = 6;
            } else if (solve_rc) *solve_rc = 0;
        }
        printf("suggested %zu of %zu %s\n", shown, matches,
               emit == 5 ? "packages" : "file candidates");
    } else {
        size_t matches = 0, only = count;
        for (j = 0; j < count; ++j) {
            if (query && strcmp(objects[j].identity.name, query)) continue;
            if (provider_kind && !objects[j].provider_match) continue;
            if (file_query && (!file_index || !indexed_file(&objects[j], file_query)))
                continue;
            if (emit == 1 && !record(stdout, &objects[j])) goto done;
            if (emit == 2) candidate_json(&objects[j]);
            if (emit == 3) only = j;
            if (emit == 4 && !record(stdout, &objects[j])) goto done;
            ++matches;
        }
        if (emit == 1) printf("listed %zu %s\n", matches,
                              provider_kind ? "candidates" : "packages");
        if (emit == 2) printf("{\"schema\":\"holy-repo-candidates-1\",\"type\":\"summary\",\"count\":%zu}\n", matches);
        if (emit == 3) {
            *solve_rc = matches > 1 ? 3 : matches ? 0 : 6;
            if (matches == 1 && !record(stdout, &objects[only])) goto done;
            if (matches != 1)
                fprintf(stderr, "holypkg: repository package %s\n",
                        matches ? "requires an architecture/ABI choice" : "not found");
        }
        if (emit == 4) {
            printf("coverage files %s index %s time %lld\n",
                   file_index ? "complete" : "unavailable", expected,
                   (long long)st.st_mtime);
            printf("listed %zu file candidates\n", matches);
            if (!file_index) {
                fputs("status unknown: source has no complete file index\n", stdout);
                if (solve_rc) *solve_rc = 6;
            } else if (solve_rc) *solve_rc = 0;
        }
    }
    if (stage && stage->index_only) memcpy(stage->set->index, expected, 65);
    ok = 1;
done:
    if (!ok) {
        fprintf(stderr, "holypkg: invalid or stale repository index%s%s\n",
                error ? ": " : "", error ? error : "");
        if (emit == 2) puts("{\"schema\":\"holy-repo-candidates-1\",\"type\":\"error\",\"code\":\"invalid-catalog\"}");
    }
    free(error);
    free(line);
    if (index) fclose(index);
    if (index_snapshot) { unlink(index_snapshot); free(index_snapshot); }
    if (chosen) { unlink(chosen); free(chosen); }
    if (candidate_snapshots) {
        for (i = 0; i < count; ++i)
            if (candidate_snapshots[i]) {
                unlink(candidate_snapshots[i]);
                free(candidate_snapshots[i]);
            }
        free(candidate_snapshots);
    }
    if (fd >= 0) close(fd);
    for (i = 0; i < count; ++i) {
        free(objects[i].filename);
        holy_package_identity_free(&objects[i].identity);
        free_claims(&objects[i]);
        free_files(&objects[i]);
    }
    free(objects);
    if (dir >= 0) close(dir);
    return ok;
}

int holy_repo_list(const char *directory)
{
    return list(directory, NULL, NULL, 1, 1, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, 0, NULL, NULL);
}

int holy_repo_search(const char *directory, const char *query)
{
    if (!query || !*query) {
        fprintf(stderr, "holypkg: package name required\n");
        return 0;
    }
    return list(directory, query, NULL, 1, 1, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, 0, NULL, NULL);
}

int holy_repo_search_fuzzy(const char *directory, const char *query)
{
    if (!query || !*query) return 2;
    return list(directory, query, NULL, 1, 5, NULL, NULL, NULL, NULL,
                NULL, NULL, 0, NULL, NULL, 0, NULL, NULL) ? 0 : 6;
}

int holy_repo_search_file(const char *directory, const char *query)
{
    int result = 6;
    if (!query || query[0] != '/' || !query[1] ||
        !safe_target_path(query + 1)) {
        fprintf(stderr, "holypkg: absolute file path required\n");
        return 2;
    }
    if (!list(directory, NULL, NULL, 1, 4, NULL, NULL, NULL, NULL,
              NULL, NULL, 0, &result, NULL, 0, NULL, query + 1)) return 6;
    return result;
}

int holy_repo_search_file_fuzzy(const char *directory, const char *query)
{
    int result = 6;
    if (!query || !*query || query[strlen(query) - 1] == '/' ||
        (query[0] != '/' && strchr(query, '/'))) return 2;
    if (query[0] == '/' && !safe_target_path(query + 1)) return 2;
    if (!list(directory, NULL, NULL, 1, 6, NULL, NULL, NULL, NULL,
              NULL, NULL, 0, &result, NULL, 0, NULL, query)) return 6;
    return result;
}

int holy_repo_info_name(const char *directory, const char *name)
{
    int result = 6;
    if (!name || !*name) return 2;
    if (!list(directory, name, NULL, 1, 3, NULL, NULL, NULL, NULL,
              NULL, NULL, 0, &result, NULL, 0, NULL, NULL)) return 6;
    return result;
}

int holy_repo_providers(const char *directory, const char *kind,
                        const char *name, int json)
{
    if (!holy_provides_kind(kind) || !name || !*name) {
        fprintf(stderr, "holypkg: provider kind and exact name required\n");
        if (json) puts("{\"schema\":\"holy-repo-candidates-1\",\"type\":\"error\",\"code\":\"invalid-query\"}");
        return 0;
    }
    return list(directory, NULL, NULL, 1, json ? 2 : 1,
                NULL, NULL, kind, name, NULL, NULL, 0, NULL, NULL, 0, NULL, NULL);
}

int holy_repo_solve(const char *directory, const char *name,
                    const char *choice, int json)
{
    int result = 6;
    if (!name || !*name) {
        fprintf(stderr, "holypkg: repository package name required\n");
        if (json) puts("{\"schema\":\"holy-local-solve-1\",\"type\":\"error\",\"code\":\"invalid-query\"}");
        return 2;
    }
    if (!list(directory, NULL, NULL, 1, 0, NULL, NULL,
              NULL, NULL, name, choice, json, &result, NULL, 0, NULL, NULL)) {
        if (json) puts("{\"schema\":\"holy-local-solve-1\",\"type\":\"error\",\"code\":\"invalid-catalog\"}");
        return 6;
    }
    return result;
}

int holy_repo_fetch(const char *directory, const char *digest, const char *output)
{
    size_t i;
    if (!digest || strlen(digest) != 64) goto invalid;
    for (i = 0; i < 64; ++i)
        if (!((digest[i] >= '0' && digest[i] <= '9') ||
              (digest[i] >= 'a' && digest[i] <= 'f'))) goto invalid;
    return list(directory, NULL, NULL, 1, 0, digest, output, NULL, NULL, NULL, NULL, 0, NULL, NULL, 0, NULL, NULL);
invalid:
    fprintf(stderr, "holypkg: expected a lowercase SHA-256 digest\n");
    return 0;
}

int holy_repo_fetch_name(const char *directory, const char *name,
                         const char *output, int extract)
{
    int result = 6;
    if (!name || !*name || !output || !*output) return 2;
    if (!list(directory, NULL, NULL, 1, 0, NULL, output, NULL, NULL,
              name, NULL, 0, &result, NULL, extract, NULL, NULL)) return 6;
    return result;
}

void holy_repo_set_free(struct holy_repo_set *set)
{
    size_t i;
    for (i = 0; i < set->count; ++i) free(set->digests[i]);
    free(set->digests);
    memset(set, 0, sizeof *set);
}

int holy_repo_stage_set(const char *directory, const char *name,
                        const char *root, struct holy_repo_set *set)
{
    struct stage_request stage = {root, set, NULL, 0};
    int result = 6;
    memset(set, 0, sizeof *set);
    if (!name || !*name || !root || !*root) return 2;
    if (!list(directory, NULL, NULL, 1, 0, NULL, NULL, NULL, NULL,
              name, NULL, 0, &result, NULL, 0, &stage, NULL)) {
        holy_repo_set_free(set);
        return 6;
    }
    if (result) holy_repo_set_free(set);
    return result;
}

int holy_repo_stage_slot(const char *directory, const char *root,
                         const struct holy_package_identity *slot,
                         struct holy_repo_set *set)
{
    struct stage_request stage = {root, set, slot, 0};
    int result = 6;
    memset(set, 0, sizeof *set);
    if (!root || !*root || !slot || !slot->name || !slot->os ||
        !slot->arch || !slot->libc) return 2;
    if (!list(directory, NULL, NULL, 1, 0, NULL, NULL, NULL, NULL,
              slot->name, NULL, 0, &result, NULL, 0, &stage, NULL)) {
        holy_repo_set_free(set);
        return 6;
    }
    if (result) holy_repo_set_free(set);
    return result;
}

int holy_repo_source_catalog(const char *directory, const char *source_id,
                             const char *url)
{
    struct stat st;
    char digest[65], *record = NULL, *expected = NULL;
    size_t used = 0, expected_size = 0;
    int dir = -1, fd = -1, ok = 0;
    FILE *stream = NULL;
    if (!source_id || strlen(source_id) != 64 ||
        strspn(source_id, "0123456789abcdef") != 64 || !url) return 0;
    dir = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || flock(dir, LOCK_SH) || read_current(dir, digest) != 1) goto done;
    fd = openat(dir, "mirror-origin", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        (st.st_mode & 0022) || (st.st_uid != geteuid() && st.st_uid != 0) ||
        st.st_size <= 0 || st.st_size > 65536) goto done;
    record = malloc((size_t)st.st_size + 1);
    if (!record) goto done;
    while (used < (size_t)st.st_size) {
        ssize_t n = pread(fd, record + used, (size_t)st.st_size - used, (off_t)used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto done;
        used += (size_t)n;
    }
    record[used] = 0;
    stream = open_memstream(&expected, &expected_size);
    if (!stream) goto done;
    {
        int wrote = fputs("format holy-mirror-1\nurl ", stream) != EOF &&
            quote(stream, url) &&
            fprintf(stream, "\nindex-sha256 %s\nverification digest-pinned-unsigned\nsource-id %s\n",
                    digest, source_id) >= 0 && !ferror(stream);
        if (fclose(stream)) wrote = 0;
        stream = NULL;
        if (!wrote) goto done;
    }
    ok = (used == expected_size && !memcmp(record, expected, used)) ||
         (used == expected_size + sizeof "selection current-accepted-unsigned\n" - 1 &&
          !memcmp(record, expected, expected_size) &&
          !memcmp(record + expected_size, "selection current-accepted-unsigned\n",
                  sizeof "selection current-accepted-unsigned\n" - 1));
done:
    if (stream) fclose(stream);
    free(record); free(expected);
    if (fd >= 0) close(fd);
    if (dir >= 0) close(dir);
    return ok;
}

int holy_repo_catalog_index(const char *directory, char digest[65])
{
    int dir = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int ok = 0;
    digest[0] = 0;
    if (dir >= 0 && !flock(dir, LOCK_SH) && read_current(dir, digest) == 1 &&
        list(directory, NULL, NULL, 1, 0, NULL, NULL, NULL, NULL, NULL,
             NULL, 0, NULL, NULL, 0, NULL, NULL)) ok = 1;
    if (dir >= 0) close(dir);
    if (!ok) digest[0] = 0;
    return ok;
}

int holy_repo_catalog_index_fast(const char *directory, char digest[65])
{
    struct holy_repo_set index = {0};
    struct stage_request stage = {NULL, &index, NULL, 1};
    int ok = list(directory, NULL, NULL, 1, 0, NULL, NULL, NULL, NULL,
                  NULL, NULL, 0, NULL, NULL, 0, &stage, NULL);
    if (ok) memcpy(digest, index.index, 65);
    else digest[0] = 0;
    return ok;
}

static int seal(const char *directory, const char *expected)
{
    char temporary[43] = {0}, pointer_temp[43] = {0};
    char index_name[71], digest[65], previous[65], line[73];
    char buffer[65536];
    char *snapshot = NULL;
    struct stat st;
    int dir = -1, input = -1, output = -1, pointer = -1, ok = 0;
    ssize_t got;
    size_t written;
    dir = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || flock(dir, LOCK_EX) < 0) goto done;
    if (read_current(dir, previous) < 0) goto done;
    input = openat(dir, "index", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (input < 0 || fstat(input, &st) || !S_ISREG(st.st_mode) ||
        st.st_size < 0 || st.st_size > 16 * 1024 * 1024) goto done;
    output = holy_temporary_at(dir, temporary);
    if (output < 0) goto done;
    while (lseek(output, 0, SEEK_CUR) < st.st_size) {
        off_t position = lseek(output, 0, SEEK_CUR);
        size_t amount;
        if (position < 0) goto done;
        amount = st.st_size - position < (off_t)sizeof buffer ?
                 (size_t)(st.st_size - position) : sizeof buffer;
        got = pread(input, buffer, amount, position);
        size_t offset = 0;
        if (got < 0) { if (errno == EINTR) continue; goto done; }
        if (!got) goto done;
        while (offset < (size_t)got) {
            ssize_t sent = write(output, buffer + offset, (size_t)got - offset);
            if (sent < 0 && errno == EINTR) continue;
            if (sent <= 0) goto done;
            offset += (size_t)sent;
        }
    }
    if (fstat(input, &st) || st.st_size < 0 ||
        lseek(output, 0, SEEK_CUR) != st.st_size) goto done;
    if (fchmod(output, 0644) || fsync(output)) goto done;
    close(output);
    output = -1;
    close(input);
    input = -1;
    if (!list(directory, NULL, temporary, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, 0, NULL, NULL)) goto done;
    input = openat(dir, temporary, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (input < 0) goto done;
    snapshot = holy_stage_fd(input, "holy-seal");
    if (!snapshot || !digest_file(snapshot, digest) ||
        (expected && strcmp(digest, expected))) goto done;
    snprintf(index_name, sizeof index_name, "index.%s", digest);
    if (linkat(dir, temporary, dir, index_name, 0)) {
        if (errno != EEXIST) goto done;
        close(input);
        input = openat(dir, index_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (input < 0) goto done;
        unlink(snapshot);
        free(snapshot);
        snapshot = holy_stage_fd(input, "holy-seal");
        if (!snapshot || !digest_file(snapshot, previous) ||
            strcmp(previous, digest)) goto done;
    }
    if (fsync(dir)) goto done;
    if (fstatat(dir, "current", &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!S_ISREG(st.st_mode)) goto done;
    } else if (errno != ENOENT) goto done;
    pointer = holy_temporary_at(dir, pointer_temp);
    if (pointer < 0) goto done;
    snprintf(line, sizeof line, "sha256 %s\n", digest);
    written = 0;
    while (written < 72) {
        ssize_t sent = write(pointer, line + written, 72 - written);
        if (sent < 0 && errno == EINTR) continue;
        if (sent <= 0) goto done;
        written += (size_t)sent;
    }
    if (fchmod(pointer, 0644) || fsync(pointer)) goto done;
    close(pointer);
    pointer = -1;
    if (renameat(dir, pointer_temp, dir, "current") || fsync(dir)) goto done;
    pointer_temp[0] = '\0';
    printf("sealed %s\n", digest);
    ok = 1;
done:
    if (!ok) fprintf(stderr, "holypkg: repository seal incomplete\n");
    if (snapshot) { unlink(snapshot); free(snapshot); }
    if (pointer >= 0) close(pointer);
    if (output >= 0) close(output);
    if (input >= 0) close(input);
    if (dir >= 0) {
        if (temporary[0]) unlinkat(dir, temporary, 0);
        if (pointer_temp[0]) unlinkat(dir, pointer_temp, 0);
        close(dir);
    }
    return ok;
}

int holy_repo_seal(const char *directory)
{
    return seal(directory, NULL);
}

int holy_repo_mirror_source(const char *base, const char *digest, const char *output,
                            const char *ca_file, const char *source_id,
                            int current_accepted)
{
    struct mirror mirror = { base, ca_file, NULL, 0 };
    char index_name[71], *url = NULL, *downloads = NULL;
    size_t i, length = strlen(output);
    int dir = -1, provenance = -1, result = 1;
    FILE *record = NULL;
    if (strlen(digest) != 64) return 2;
    for (i = 0; i < 64; ++i)
        if (!((digest[i] >= '0' && digest[i] <= '9') ||
              (digest[i] >= 'a' && digest[i] <= 'f'))) return 2;
    if (current_accepted && !source_id) return 2;
    if (source_id) {
        if (strlen(source_id) != 64) return 2;
        for (i = 0; i < 64; ++i)
            if (!((source_id[i] >= '0' && source_id[i] <= '9') ||
                  (source_id[i] >= 'a' && source_id[i] <= 'f'))) return 2;
    }
    snprintf(index_name, sizeof index_name, "index.%s", digest);
    url = holy_fetch_child_url(base, index_name);
    if (!url) return 2;
    if (length > (size_t)-1 - 12 || !(downloads = malloc(length + 12))) goto done;
    snprintf(downloads, length + 12, "%s/.downloads", output);
    mirror.downloads = downloads;
    if (mkdir(output, 0700)) goto done;
    dir = open(output, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || flock(dir, LOCK_EX) || mkdirat(dir, ".downloads", 0700)) goto done;
    result = holy_fetch_https_data(url, digest, output, ca_file);
    if (result) goto done;
    if (!list(output, NULL, digest, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, &mirror, 0, NULL, NULL)) {
        result = mirror.status ? mirror.status : 4;
        goto done;
    }
    result = 1;
    if (linkat(dir, digest, dir, "index", 0)) goto done;
    provenance = openat(dir, "mirror-origin", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (provenance < 0 || !(record = fdopen(provenance, "w"))) goto done;
    fputs("format holy-mirror-1\nurl ", record);
    if (!quote(record, base) || fprintf(record, "\nindex-sha256 %s\nverification digest-pinned-unsigned\n", digest) < 0 ||
        (source_id && fprintf(record, "source-id %s\n", source_id) < 0) ||
        (current_accepted && fputs("selection current-accepted-unsigned\n", record) == EOF) ||
        fflush(record) || fsync(provenance)) goto done;
    if (fclose(record)) { record = NULL; provenance = -1; goto done; }
    record = NULL; provenance = -1;
    if (unlinkat(dir, digest, 0) || unlinkat(dir, ".downloads", AT_REMOVEDIR) || fsync(dir)) goto done;
    /* seal takes its own exclusive lock after the private download phase. */
    close(dir); dir = -1;
    result = seal(output, digest) ? 0 : 4;
done:
    if (result) fprintf(stderr, "holypkg: HTTPS catalog mirror incomplete (status %d)\n", result);
    if (record) fclose(record);
    else if (provenance >= 0) close(provenance);
    if (dir >= 0) close(dir);
    free(downloads);
    free(url);
    return result;
}

int holy_repo_mirror(const char *base, const char *digest, const char *output,
                     const char *ca_file)
{
    return holy_repo_mirror_source(base, digest, output, ca_file, NULL, 0);
}
