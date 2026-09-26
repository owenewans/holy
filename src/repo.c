#define _POSIX_C_SOURCE 200809L
#include "repo.h"
#include "config.h"
#include "fetch.h"
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

struct object {
    char *filename;
    struct holy_package_identity identity;
};

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
            !holy_package_identity(snapshot, &objects[i].identity)) {
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
    if (fputs("format holy-index-prototype-1\n", stream) == EOF) goto done;
    for (i = 0; i < count; ++i) if (!record(stream, &objects[i])) goto done;
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

static int list(const char *directory, const char *query,
                const char *forced_index, int lock, int emit,
                const char *fetch_digest, const char *output)
{
    struct object *objects = NULL;
    struct stat st;
    FILE *index = NULL;
    char *line = NULL, *error = NULL, *index_snapshot = NULL, *chosen = NULL;
    char expected[65], actual_digest[65], index_name[71];
    size_t capacity = 0, count = 0, i, j, number = 0;
    ssize_t length;
    int dir = -1, fd = -1, ok = 0;

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
                        !strcmp(v[1], "holy-index-prototype-1");
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
    if (ferror(index) || !number) goto done;
    for (i = 0; i < count; ++i) {
        struct holy_package_identity actual;
        char *snapshot;
        int input = openat(dir, objects[i].filename,
                           O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        int matches;
        if (input < 0) goto done;
        snapshot = holy_stage_fd(input, "holy-list");
        close(input);
        if (!snapshot) goto done;
        matches = holy_verify_with_output(snapshot, 0) &&
                  holy_scan_local_with_output(snapshot, 0) &&
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
        if (fetch_digest && !strcmp(fetch_digest, objects[i].identity.digest))
            chosen = snapshot;
        else {
            unlink(snapshot);
            free(snapshot);
        }
    }
    if (fetch_digest && (!chosen || !holy_fetch_local(chosen, output))) goto done;
    {
        size_t matches = 0;
        for (j = 0; j < count; ++j) {
            if (query && strcmp(objects[j].identity.name, query)) continue;
            if (emit && !record(stdout, &objects[j])) goto done;
            ++matches;
        }
        if (emit) printf("listed %zu packages\n", matches);
    }
    ok = 1;
done:
    if (!ok) fprintf(stderr, "holypkg: invalid or stale repository index%s%s\n",
                     error ? ": " : "", error ? error : "");
    free(error);
    free(line);
    if (index) fclose(index);
    if (index_snapshot) { unlink(index_snapshot); free(index_snapshot); }
    if (chosen) { unlink(chosen); free(chosen); }
    if (fd >= 0) close(fd);
    for (i = 0; i < count; ++i) {
        free(objects[i].filename);
        holy_package_identity_free(&objects[i].identity);
    }
    free(objects);
    if (dir >= 0) close(dir);
    return ok;
}

int holy_repo_list(const char *directory)
{
    return list(directory, NULL, NULL, 1, 1, NULL, NULL);
}

int holy_repo_search(const char *directory, const char *query)
{
    if (!query || !*query) {
        fprintf(stderr, "holypkg: package name required\n");
        return 0;
    }
    return list(directory, query, NULL, 1, 1, NULL, NULL);
}

int holy_repo_fetch(const char *directory, const char *digest, const char *output)
{
    size_t i;
    if (!digest || strlen(digest) != 64) goto invalid;
    for (i = 0; i < 64; ++i)
        if (!((digest[i] >= '0' && digest[i] <= '9') ||
              (digest[i] >= 'a' && digest[i] <= 'f'))) goto invalid;
    return list(directory, NULL, NULL, 1, 0, digest, output);
invalid:
    fprintf(stderr, "holypkg: expected a lowercase SHA-256 digest\n");
    return 0;
}

int holy_repo_seal(const char *directory)
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
    if (!list(directory, NULL, temporary, 0, 0, NULL, NULL)) goto done;
    input = openat(dir, temporary, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (input < 0) goto done;
    snapshot = holy_stage_fd(input, "holy-seal");
    if (!snapshot || !digest_file(snapshot, digest)) goto done;
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
