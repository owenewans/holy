#define _POSIX_C_SOURCE 200809L
#include "repo.h"
#include "config.h"
#include "package.h"
#include "scan.h"
#include "stage.h"
#include "verify.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
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

int holy_repo_list(const char *directory)
{
    struct object *objects = NULL;
    struct stat st;
    FILE *index = NULL;
    char *line = NULL, *error = NULL;
    size_t capacity = 0, count = 0, i, j, number = 0;
    ssize_t length;
    int dir = -1, fd = -1, ok = 0;

    dir = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || flock(dir, LOCK_SH) < 0) goto done;
    fd = openat(dir, "index", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size < 0 || st.st_size > 16 * 1024 * 1024) goto done;
    index = fdopen(fd, "r");
    if (!index) goto done;
    fd = -1;
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
        unlink(snapshot);
        free(snapshot);
        if (!matches) goto done;
    }
    for (j = 0; j < count; ++j)
        if (!record(stdout, &objects[j])) goto done;
    printf("listed %zu packages\n", count);
    ok = 1;
done:
    if (!ok) fprintf(stderr, "holypkg: invalid or stale repository index%s%s\n",
                     error ? ": " : "", error ? error : "");
    free(error);
    free(line);
    if (index) fclose(index);
    if (fd >= 0) close(fd);
    for (i = 0; i < count; ++i) {
        free(objects[i].filename);
        holy_package_identity_free(&objects[i].identity);
    }
    free(objects);
    if (dir >= 0) close(dir);
    return ok;
}
