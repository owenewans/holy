#define _XOPEN_SOURCE 700
#include "apt.h"
#include "../src/config.h"
#include "../src/source.h"
#include "../src/stage.h"
#include "../src/state.h"

#include <openssl/evp.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int digest(const char *value)
{
    return value && strlen(value) == 64 && strspn(value, "0123456789abcdef") == 64;
}

static int segment(const char *value)
{
    size_t i, count = value ? strlen(value) : 0;
    if (!count || count > 128 || !strcmp(value, ".") || !strcmp(value, "..")) return 0;
    for (i = 0; i < count; ++i)
        if (!((value[i] >= 'a' && value[i] <= 'z') ||
              (value[i] >= 'A' && value[i] <= 'Z') ||
              (value[i] >= '0' && value[i] <= '9') ||
              value[i] == '.' || value[i] == '_' || value[i] == '-')) return 0;
    return 1;
}

static void quote(FILE *out, const char *value)
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

static int binding_name(const char *id, const char *suite,
                        const char *component, const char *arch, char name[130])
{
    char coordinates[512];
    unsigned char bytes[32];
    unsigned length;
    size_t i;
    int count;
    if (!digest(id) || !segment(suite) || !segment(component) || !segment(arch)) return 0;
    count = snprintf(coordinates, sizeof coordinates, "%s\n%s\n%s\n",
                     suite, component, arch);
    if (count < 0 || count >= (int)sizeof coordinates ||
        EVP_Digest(coordinates, (size_t)count, bytes, &length, EVP_sha256(), NULL) != 1 ||
        length != 32) return 0;
    memcpy(name, id, 64);
    name[64] = '.';
    for (i = 0; i < 32; ++i) snprintf(name + 65 + i * 2, 3, "%02x", bytes[i]);
    return 1;
}

static int binding_directory(int database, int create)
{
    struct stat st;
    int dir;
    if (create && mkdirat(database, "apt-catalogs", 0700) && errno != EEXIST) return -1;
    if (create && fsync(database)) return -1;
    dir = openat(database, "apt-catalogs", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) return -1;
    if (fstat(dir, &st) || !S_ISDIR(st.st_mode) ||
        (st.st_uid != 0 && st.st_uid != geteuid()) || (st.st_mode & 0022)) {
        close(dir); return -1;
    }
    return dir;
}

static int proof_coordinates(const char *catalog, const char *suite,
                             const char *component, const char *arch,
                             char release_hash[65], char key_hash[65])
{
    char *path = NULL, saved_suite[129], index_path[1025], wanted[512];
    char kind[128], signature_hash[65];
    struct stat st;
    FILE *file = NULL;
    int fd = -1, ok = 0;
    if (!segment(suite) || !segment(component) || !segment(arch)) return 0;
    if (snprintf(wanted, sizeof wanted, "%s/binary-%s/Packages.gz",
                 component, arch) >= (int)sizeof wanted) return 0;
    path = malloc(strlen(catalog) + sizeof "/release-proof");
    if (!path) return 0;
    sprintf(path, "%s/release-proof", catalog);
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size > 2048) goto done;
    file = fdopen(fd, "r");
    if (!file) goto done;
    fd = -1;
    if (fscanf(file, "release-sha256 %64s\nkey-sha256 %64s\nsuite %128s\nindex-path %1024s\n",
               release_hash, key_hash, saved_suite, index_path) == 4 &&
        digest(release_hash) && digest(key_hash) && !strcmp(saved_suite, suite) &&
        !strcmp(index_path, wanted)) {
        if (fgets(kind, sizeof kind, file))
            ok = !strcmp(kind, "signature-kind inrelease\n") &&
                 fscanf(file, "signature-sha256 %64s\n", signature_hash) == 1 &&
                 digest(signature_hash) && fgetc(file) == EOF;
        else ok = !ferror(file);
    }
done:
    if (file) fclose(file);
    if (fd >= 0) close(fd);
    free(path);
    return ok;
}

int holy_apt_bind(const char *root, const char *source, const char *suite,
                  const char *component, const char *index_arch,
                  const char *catalog)
{
    char id[65], index[65], name[130], release_hash[65], key_hash[65];
    char temporary[43] = {0}, *path = NULL, *root_path = NULL;
    unsigned long long generation;
    FILE *record = NULL;
    int database = -1, dir = -1, fd = -1, result = 2;
    if (!root || !source || !catalog || !segment(suite) ||
        !segment(component) || !segment(index_arch)) return 2;
    path = realpath(catalog, NULL);
    root_path = realpath(root, NULL);
    if (!path || !root_path) { result = 6; goto done; }
    result = holy_apt_catalog_identity(path, root, source, id, index);
    if (result) goto done;
    if (!binding_name(id, suite, component, index_arch, name) ||
        !proof_coordinates(path, suite, component, index_arch,
                           release_hash, key_hash)) { result = 4; goto done; }
    database = holy_state_lock(root, 1, &generation, &result);
    if (database < 0) goto done;
    dir = binding_directory(database, 1);
    if (dir < 0) { result = 1; goto done; }
    fd = holy_temporary_at(dir, temporary);
    if (fd < 0) { result = 1; goto done; }
    record = fdopen(fd, "w");
    if (!record) { result = 1; goto done; }
    fd = -1;
    fprintf(record, "format holy-apt-binding-1\nsource-id %s\nsuite %s\ncomponent %s\nindex-arch %s\nindex-sha256 %s\nrelease-sha256 %s\nkey-sha256 %s\n",
            id, suite, component, index_arch, index, release_hash, key_hash);
    if (strcmp(root_path, "/") && !strncmp(path, root_path, strlen(root_path)) &&
        path[strlen(root_path)] == '/') {
        fputs("root-path ", record); quote(record, path + strlen(root_path));
    } else {
        fputs("path ", record); quote(record, path);
    }
    fputc('\n', record);
    {
        int failed = ferror(record) || fflush(record);
        if (!failed && fsync(fileno(record))) failed = 1;
        if (fclose(record)) failed = 1;
        record = NULL;
        if (failed || renameat(dir, temporary, dir, name) || fsync(dir)) {
            result = 1; goto done;
        }
    }
    result = 0;
    printf("apt-catalog-bound %s %s %s %s index %s\n",
           id, suite, component, index_arch, index);
done:
    if (result) fprintf(stderr, "holypkg: APT catalog binding failed (status %d)\n", result);
    if (record) fclose(record);
    if (fd >= 0) close(fd);
    if (dir >= 0) {
        if (temporary[0]) unlinkat(dir, temporary, 0);
        close(dir);
    }
    if (database >= 0) close(database);
    free(path); free(root_path);
    return result;
}

static int read_binding(int dir, const char *name, char *values[9], int *root_relative)
{
    static const char *keys[8] = {"format", "source-id", "suite", "component",
                                  "index-arch", "index-sha256", "release-sha256",
                                  "key-sha256"};
    struct stat st;
    FILE *stream = NULL;
    char *line = NULL;
    size_t capacity = 0, i;
    int fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    int ok = 0;
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size > 4096 ||
        (st.st_uid != 0 && st.st_uid != geteuid()) || (st.st_mode & 0022)) goto done;
    stream = fdopen(fd, "r");
    if (!stream) goto done;
    fd = -1;
    for (i = 0; i < 9; ++i) {
        char **v = NULL, *error = NULL;
        size_t n = 0;
        ssize_t got = getline(&line, &capacity, stream);
        if (got <= 0 || got > 4096 ||
            !holy_lex(line, (size_t)got, &v, &n, "APT binding", 0, &error) || n != 2 ||
            (i < 8 ? strcmp(v[0], keys[i]) :
             (strcmp(v[0], "path") && strcmp(v[0], "root-path")))) {
            holy_tokens_free(v, n); free(error); goto done;
        }
        if (i == 8) *root_relative = !strcmp(v[0], "root-path");
        values[i] = strdup(v[1]);
        holy_tokens_free(v, n); free(error);
        if (!values[i]) goto done;
    }
    if (fgetc(stream) != EOF || strcmp(values[0], "holy-apt-binding-1") ||
        !digest(values[1]) || !digest(values[5]) || !digest(values[6]) ||
        !digest(values[7]) || values[8][0] != '/') goto done;
    ok = 1;
done:
    if (stream) fclose(stream);
    if (fd >= 0) close(fd);
    free(line);
    return ok;
}

int holy_apt_catalog_path(const char *root, const char *source, const char *suite,
                          const char *component, const char *index_arch,
                          char **catalog)
{
    char id[65], key[65], checked_id[65], checked_index[65], name[130];
    char release_hash[65], key_hash[65], *base = NULL, *trust = NULL;
    char *values[9] = {0}, *root_path = NULL, *joined = NULL, *path = NULL;
    unsigned long long generation;
    size_t i;
    int database = -1, dir = -1, result, root_relative = 0;
    *catalog = NULL;
    if (!root || !source || !segment(suite) || !segment(component) ||
        !segment(index_arch)) return 2;
    result = holy_source_apt(root, source, id, &base, &trust, key);
    if (result) goto done;
    if (!key[0] || !binding_name(id, suite, component, index_arch, name)) {
        result = 6; goto done;
    }
    database = holy_state_lock(root, 0, &generation, &result);
    if (database < 0) goto done;
    dir = binding_directory(database, 0);
    if (dir < 0 || !read_binding(dir, name, values, &root_relative)) {
        result = 6; goto done;
    }
    if (strcmp(values[1], id) || strcmp(values[2], suite) ||
        strcmp(values[3], component) || strcmp(values[4], index_arch) ||
        strcmp(values[7], key)) { result = 6; goto done; }
    close(dir); dir = -1;
    close(database); database = -1;
    if (root_relative) {
        root_path = realpath(root, NULL);
        if (!root_path) { result = 6; goto done; }
        joined = malloc(strlen(root_path) + strlen(values[8]) + 1);
        if (!joined) { result = 1; goto done; }
        sprintf(joined, "%s%s", strcmp(root_path, "/") ? root_path : "", values[8]);
        path = realpath(joined, NULL);
        if (!path || (strcmp(root_path, "/") &&
                      (strncmp(path, root_path, strlen(root_path)) ||
                       path[strlen(root_path)] != '/'))) { result = 6; goto done; }
    } else {
        path = realpath(values[8], NULL);
        if (!path) { result = 6; goto done; }
    }
    result = holy_apt_catalog_identity(path, root, source, checked_id, checked_index);
    if (result || strcmp(checked_id, id) || strcmp(checked_index, values[5]) ||
        !proof_coordinates(path, suite, component, index_arch,
                           release_hash, key_hash) ||
        strcmp(release_hash, values[6]) || strcmp(key_hash, values[7])) {
        if (!result) result = 6;
        goto done;
    }
    *catalog = path; path = NULL; result = 0;
done:
    if (result) fprintf(stderr, "holypkg: bound APT catalog unavailable (status %d)\n", result);
    for (i = 0; i < 9; ++i) free(values[i]);
    if (dir >= 0) close(dir);
    if (database >= 0) close(database);
    free(base); free(trust); free(root_path); free(joined); free(path);
    return result;
}
