#define _POSIX_C_SOURCE 200809L
#include "apt.h"
#include "apt-release.h"
#include "deb-version.h"
#include "../src/config.h"
#include "../src/stage.h"
#include "../src/fetch.h"
#include "../src/import.h"
#include "../src/package.h"

#include <archive.h>
#include <archive_entry.h>
#include <openssl/evp.h>
#include <ctype.h>
#include <curl/curl.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#define APT_INDEX_LIMIT (64u * 1024u * 1024u)

struct apt_entry {
    char *name, *version, *arch, *filename, *sha256, *depends, *pre_depends, *provides;
    unsigned long long size;
    unsigned fields;
};

struct apt_index {
    struct apt_entry *entries;
    size_t count, capacity;
    char *source, *base;
    char hash[65];
    int release_verified;
};

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

static int digest(const char *value)
{
    return value && strlen(value) == 64 && strspn(value, "0123456789abcdef") == 64;
}

static int token(const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    if (!*p) return 0;
    for (; *p; ++p)
        if (*p <= 32 || *p >= 127 || *p == '/' || *p == ':' || *p == '@') return 0;
    return 1;
}

static int safe_filename(const char *path)
{
    const unsigned char *p = (const unsigned char *)path;
    size_t length = strlen(path);
    if (!length || length > 1024 || *p == '/') return 0;
    while (*p) {
        const unsigned char *end = (const unsigned char *)strchr((const char *)p, '/');
        size_t count = end ? (size_t)(end - p) : strlen((const char *)p), i;
        if (!count || (count == 1 && p[0] == '.') ||
            (count == 2 && p[0] == '.' && p[1] == '.')) return 0;
        for (i = 0; i < count; ++i)
            if (!((p[i] >= 'a' && p[i] <= 'z') ||
                  (p[i] >= 'A' && p[i] <= 'Z') ||
                  (p[i] >= '0' && p[i] <= '9') || p[i] == '_' || p[i] == '-' || p[i] == '.' ||
                  p[i] == '+' || p[i] == '~' || p[i] == ':')) return 0;
        if (!end) return 1;
        p = end + 1;
    }
    return 0;
}

static void free_index(struct apt_index *index)
{
    size_t i;
    for (i = 0; i < index->count; ++i) {
        struct apt_entry *e = &index->entries[i];
        free(e->name); free(e->version); free(e->arch); free(e->filename);
        free(e->sha256); free(e->depends); free(e->pre_depends); free(e->provides);
    }
    free(index->entries); free(index->source); free(index->base);
}

static int entry_order(const void *left, const void *right)
{
    const struct apt_entry *a = left, *b = right;
    int order = strcmp(a->name, b->name);
    if (!order) order = strcmp(a->version, b->version);
    if (!order) order = strcmp(a->arch, b->arch);
    return order;
}

static int valid_entry(const struct apt_entry *e)
{
    const unsigned char *p;
    int order;
    if ((e->fields & 63) != 63 || !token(e->name) || !token(e->arch) ||
        !e->version[0] || !holy_deb_version_compare(e->version, e->version, &order) ||
        !safe_filename(e->filename) || !digest(e->sha256) || !e->size ||
        e->size > 1024ULL * 1024 * 1024) return 0;
    for (p = (const unsigned char *)e->name; *p; ++p)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
              *p == '+' || *p == '-' || *p == '.')) return 0;
    return 1;
}

static int new_entry(struct apt_index *index)
{
    struct apt_entry *next;
    size_t capacity;
    if (index->count == 100000) return 0;
    if (index->count == index->capacity) {
        capacity = index->capacity ? index->capacity * 2 : 256;
        if (capacity > 100000) capacity = 100000;
        next = realloc(index->entries, capacity * sizeof *next);
        if (!next) return 0;
        index->entries = next; index->capacity = capacity;
    }
    memset(&index->entries[index->count++], 0, sizeof *index->entries);
    return 1;
}

static int append_fold(char **slot, const char *line)
{
    size_t old = *slot ? strlen(*slot) : 0, add = strlen(line);
    char *next;
    while (*line == ' ' || *line == '\t') { ++line; --add; }
    if (old > 65536 || add > 65536 - old - 2) return 0;
    next = realloc(*slot, old + add + 2);
    if (!next) return 0;
    *slot = next;
    if (old) next[old++] = ' ';
    memcpy(next + old, line, add + 1);
    return 1;
}

static int parse_index(char *data, size_t size, struct apt_index *index)
{
    size_t pos = 0, line_number = 0;
    int field = 0, in_stanza = 0;
    while (pos < size) {
        char *line = data + pos, *end = memchr(line, '\n', size - pos);
        size_t length = end ? (size_t)(end - line) : size - pos;
        struct apt_entry *e;
        char *colon, *value, **slot = NULL;
        unsigned bit = 0;
        if (++line_number > 2000000 || length > 65536 || memchr(line, 0, length)) return 0;
        pos += length + (end != NULL);
        if (length && line[length - 1] == '\r') --length;
        line[length] = 0;
        if (!length) {
            if (in_stanza && !valid_entry(&index->entries[index->count - 1])) return 0;
            in_stanza = field = 0;
            continue;
        }
        if (*line == ' ' || *line == '\t') {
            if (!in_stanza) return 0;
            e = &index->entries[index->count - 1];
            slot = field == 7 ? &e->depends : field == 8 ? &e->pre_depends :
                   field == 9 ? &e->provides : NULL;
            if (field && field <= 6) return 0;
            if (slot && !append_fold(slot, line)) return 0;
            continue;
        }
        colon = strchr(line, ':');
        if (!colon || colon == line) return 0;
        *colon = 0;
        for (value = line; *value; ++value)
            if (!(isalnum((unsigned char)*value) || *value == '-')) return 0;
        value = colon + 1;
        while (*value == ' ' || *value == '\t') ++value;
        if (!in_stanza) {
            if (strcasecmp(line, "Package") || !new_entry(index)) return 0;
            in_stanza = 1;
        }
        e = &index->entries[index->count - 1];
        if (!strcasecmp(line, "Package")) slot = &e->name, bit = 1, field = 1;
        else if (!strcasecmp(line, "Version")) slot = &e->version, bit = 2, field = 2;
        else if (!strcasecmp(line, "Architecture")) slot = &e->arch, bit = 4, field = 3;
        else if (!strcasecmp(line, "Filename")) slot = &e->filename, bit = 8, field = 4;
        else if (!strcasecmp(line, "Size")) bit = 16, field = 5;
        else if (!strcasecmp(line, "SHA256")) slot = &e->sha256, bit = 32, field = 6;
        else if (!strcasecmp(line, "Depends")) slot = &e->depends, field = 7;
        else if (!strcasecmp(line, "Pre-Depends")) slot = &e->pre_depends, field = 8;
        else if (!strcasecmp(line, "Provides")) slot = &e->provides, field = 9;
        else field = 0;
        if (bit && (e->fields & bit)) return 0;
        e->fields |= bit;
        if (slot) {
            if (!*value || *slot) return 0;
            *slot = strdup(value);
            if (!*slot) return 0;
        }
        if (field == 5) {
            const char *p = value;
            if (!*p || *p == '0') return 0;
            for (; *p; ++p) {
                if (*p < '0' || *p > '9' || e->size > (UINT64_MAX - (unsigned)(*p - '0')) / 10) return 0;
                e->size = e->size * 10 + (unsigned)(*p - '0');
            }
        }
    }
    if (in_stanza && !valid_entry(&index->entries[index->count - 1])) return 0;
    if (!index->count) return 0;
    qsort(index->entries, index->count, sizeof *index->entries, entry_order);
    for (pos = 1; pos < index->count; ++pos)
        if (!entry_order(&index->entries[pos - 1], &index->entries[pos])) return 0;
    return 1;
}

static int decompress(const char *path, char **data, size_t *size)
{
    struct archive *archive = archive_read_new();
    struct archive_entry *entry;
    char *buffer = NULL;
    size_t used = 0, capacity = 0;
    int status, ok = 0;
    if (!archive || archive_read_support_filter_all(archive) != ARCHIVE_OK ||
        archive_read_support_format_raw(archive) != ARCHIVE_OK ||
        archive_read_open_filename(archive, path, 65536) != ARCHIVE_OK) goto done;
    if (archive_read_next_header(archive, &entry) != ARCHIVE_OK) goto done;
    for (;;) {
        char chunk[65536];
        la_ssize_t got = archive_read_data(archive, chunk, sizeof chunk);
        if (got < 0 || used > APT_INDEX_LIMIT) goto done;
        if (!got) break;
        if ((size_t)got > APT_INDEX_LIMIT - used) goto done;
        if (used + (size_t)got + 1 > capacity) {
            size_t next_size = capacity ? capacity * 2 : 65536;
            char *next;
            if (next_size < used + (size_t)got + 1) next_size = used + (size_t)got + 1;
            if (next_size > APT_INDEX_LIMIT + 1u) next_size = APT_INDEX_LIMIT + 1u;
            next = realloc(buffer, next_size);
            if (!next) goto done;
            buffer = next; capacity = next_size;
        }
        memcpy(buffer + used, chunk, (size_t)got); used += (size_t)got;
    }
    status = archive_read_next_header(archive, &entry);
    if (status != ARCHIVE_EOF || !used || !buffer) goto done;
    buffer[used] = 0;
    *data = buffer; *size = used; buffer = NULL; ok = 1;
done:
    free(buffer);
    if (archive) archive_read_free(archive);
    return ok;
}

static int file_hash(int fd, char hex[65])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char buffer[65536], bytes[32];
    unsigned length;
    ssize_t got;
    size_t i;
    int ok = 0;
    if (!ctx || lseek(fd, 0, SEEK_SET) < 0 || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto done;
    for (;;) {
        got = read(fd, buffer, sizeof buffer);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) break;
        if (EVP_DigestUpdate(ctx, buffer, (size_t)got) != 1) goto done;
    }
    if (got < 0 || EVP_DigestFinal_ex(ctx, bytes, &length) != 1 || length != 32) goto done;
    for (i = 0; i < 32; ++i) snprintf(hex + i * 2, 3, "%02x", bytes[i]);
    ok = 1;
done:
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int copy_original(const char *snapshot, int output)
{
    int source = open(snapshot, O_RDONLY | O_CLOEXEC);
    int target = -1;
    char bytes[65536];
    ssize_t got;
    int ok = 0;
    if (source < 0) goto done;
    target = openat(output, "original", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (target < 0) goto done;
    for (;;) {
        got = read(source, bytes, sizeof bytes);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) break;
        size_t used = 0;
        while (used < (size_t)got) {
            ssize_t n = write(target, bytes + used, (size_t)got - used);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) goto done;
            used += (size_t)n;
        }
    }
    ok = !got && !fsync(target) && !fsync(output);
done:
    if (source >= 0) close(source);
    if (target >= 0) close(target);
    return ok;
}

static int write_index(const char *input, const char *expected, const char *source,
                       const char *base, const char *output, int emit)
{
    struct apt_index index = {0};
    struct stat st;
    char *snapshot = NULL, *data = NULL, *url_check = NULL, actual[65];
    size_t size = 0;
    FILE *record = NULL;
    int input_fd = -1, copy = -1, dir = -1, result = 1;
    if (!input || !digest(expected) || !token(source) || !strcmp(source, "local") || !base) return 2;
    url_check = holy_fetch_child_url(base, "probe");
    if (!url_check) return 2;
    free(url_check);
    input_fd = open(input, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (input_fd < 0 || fstat(input_fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size <= 0 || st.st_size > APT_INDEX_LIMIT) { result = 6; goto done; }
    snapshot = holy_stage_fd(input_fd, "holy-apt-index");
    if (!snapshot) goto done;
    copy = open(snapshot, O_RDONLY | O_CLOEXEC);
    if (copy < 0 || !file_hash(copy, actual)) goto done;
    close(copy); copy = -1;
    if (strcmp(actual, expected)) { result = 4; goto done; }
    if (!decompress(snapshot, &data, &size) || !parse_index(data, size, &index)) { result = 2; goto done; }
    if (mkdir(output, 0700)) goto done;
    dir = open(output, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || fstat(dir, &st) || st.st_uid != geteuid() ||
        (st.st_mode & 0777) != 0700 || !copy_original(snapshot, dir)) goto done;
    copy = openat(dir, "original", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (copy < 0 || !file_hash(copy, actual) || strcmp(actual, expected)) goto done;
    close(copy); copy = -1;
    {
        int fd = openat(dir, "conversion", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) goto done;
        record = fdopen(fd, "w");
        if (!record) { close(fd); goto done; }
    }
    fputs("format holy-apt-index-1\nsource-name ", record); quote(record, source);
    fputs("\nbase-url ", record); quote(record, base);
    fprintf(record, "\nindex-sha256 %s\npackages %zu\nverification pinned-unverified\nstate complete\n",
            expected, index.count);
    {
        int failed = ferror(record);
        if (fflush(record) || fsync(fileno(record))) failed = 1;
        if (fclose(record)) failed = 1;
        record = NULL;
        if (failed || fsync(dir)) goto done;
    }
    if (emit) printf("apt index %s packages %zu sha256 %s\n", output, index.count, expected);
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: APT index incomplete (status %d)\n", result);
    if (record) fclose(record);
    if (copy >= 0) close(copy);
    if (dir >= 0) close(dir);
    if (input_fd >= 0) close(input_fd);
    if (snapshot) { unlink(snapshot); free(snapshot); }
    free(data); free_index(&index);
    return result;
}

int holy_apt_index(const char *input, const char *expected, const char *source,
                   const char *base, const char *output)
{
    return write_index(input, expected, source, base, output, 1);
}

int holy_apt_index_quiet(const char *input, const char *expected, const char *source,
                         const char *base, const char *output)
{
    return write_index(input, expected, source, base, output, 0);
}

int holy_apt_sync(const char *url, const char *expected, const char *source,
                  const char *base, const char *output, const char *ca_file)
{
    char temporary[] = "/tmp/holy-apt-sync-XXXXXX";
    char actual[65] = {0};
    char *downloaded = NULL, *probe = NULL;
    struct stat st;
    int result;
    if (!url || !digest(expected) || !token(source) || !strcmp(source, "local") ||
        !base || !output || !*output ||
        (lstat(output, &st) == 0 || errno != ENOENT)) return 2;
    probe = holy_fetch_child_url(base, "probe");
    if (!probe) return 2;
    free(probe);
    if (!mkdtemp(temporary)) return 1;
    result = holy_fetch_https_foreign(url, temporary, ca_file, actual);
    if (result) goto done;
    downloaded = malloc(strlen(temporary) + 66);
    if (!downloaded) { result = 1; goto done; }
    sprintf(downloaded, "%s/%s", temporary, actual);
    if (strcmp(actual, expected)) {
        fprintf(stderr, "holypkg: APT index hash mismatch: expected %s, received %s\n",
                expected, actual);
        result = 4; goto done;
    }
    result = holy_apt_index(downloaded, expected, source, base, output);
done:
    if (downloaded) unlink(downloaded);
    free(downloaded);
    rmdir(temporary);
    return result;
}

static int read_catalog(const char *catalog, struct apt_index *index)
{
    char *line = NULL, *data = NULL, *error = NULL;
    size_t capacity = 0, size = 0;
    FILE *record = NULL;
    int dir = open(catalog, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int fd = -1, status = 2, seen = 0, release_required = 0;
    struct stat st;
    if (dir < 0) return 6;
    fd = openat(dir, "conversion", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size > 4096) goto done;
    record = fdopen(fd, "r");
    if (!record) goto done;
    fd = -1;
    while (getline(&line, &capacity, record) > 0) {
        char **v = NULL;
        size_t n = 0;
        if (!holy_lex(line, strlen(line), &v, &n, "APT conversion", 0, &error) || n != 2) {
            holy_tokens_free(v, n); goto done;
        }
        if (!strcmp(v[0], "format") && !strcmp(v[1], "holy-apt-index-1")) seen |= 1;
        else if (!strcmp(v[0], "source-name") && !index->source) index->source = strdup(v[1]);
        else if (!strcmp(v[0], "base-url") && !index->base) index->base = strdup(v[1]);
        else if (!strcmp(v[0], "index-sha256") && !index->hash[0] && digest(v[1])) strcpy(index->hash, v[1]);
        else if (!strcmp(v[0], "state") && !strcmp(v[1], "complete")) seen |= 2;
        else if (!strcmp(v[0], "release-required") && !strcmp(v[1], "yes")) release_required = 1;
        holy_tokens_free(v, n);
    }
    if (ferror(record) || seen != 3 || !token(index->source) ||
        !index->base || !digest(index->hash)) goto done;
    {
        char *probe = holy_fetch_child_url(index->base, "probe");
        if (!probe) goto done;
        free(probe);
    }
    fclose(record); record = NULL;
    fd = openat(dir, "original", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size > APT_INDEX_LIMIT) goto done;
    {
        char actual[65], descriptor[64];
        snprintf(descriptor, sizeof descriptor, "/proc/self/fd/%d", fd);
        if (!file_hash(fd, actual) || strcmp(actual, index->hash) ||
            !decompress(descriptor, &data, &size) || !parse_index(data, size, index)) goto done;
    }
    index->release_verified = holy_apt_verify_release(catalog, index->hash);
    if (index->release_verified == -2) { status = 6; goto done; }
    if (index->release_verified < 0 || (release_required && !index->release_verified)) goto done;
    status = 0;
done:
    if (record) fclose(record);
    if (fd >= 0) close(fd);
    if (dir >= 0) close(dir);
    free(line); free(data); free(error);
    return status;
}

int holy_apt_query(const char *catalog, const char *query, int info)
{
    struct apt_index index = {0};
    size_t i, matches = 0;
    int result;
    if (!catalog || !query || !*query) return 2;
    result = read_catalog(catalog, &index);
    if (result) goto done;
    for (i = 0; i < index.count; ++i) {
        const struct apt_entry *e = &index.entries[i];
        if (info ? strcmp(e->name, query) : !strstr(e->name, query)) continue;
        ++matches;
        if (info) {
            printf("package %s\nversion %s\narch %s\nfilename %s\nsize %llu\nsha256 %s\n",
                   e->name, e->version, e->arch, e->filename, e->size, e->sha256);
            printf("verification %s\n", index.release_verified ? "release-gpgv-user-key" : "pinned-unverified");
            fputs("depends ", stdout); quote(stdout, e->depends ? e->depends : "-"); fputc('\n', stdout);
            fputs("pre-depends ", stdout); quote(stdout, e->pre_depends ? e->pre_depends : "-"); fputc('\n', stdout);
            fputs("provides ", stdout); quote(stdout, e->provides ? e->provides : "-"); fputc('\n', stdout);
        } else printf("%s %s %s\n", e->name, e->version, e->arch);
    }
    result = matches ? info && matches > 1 ? 3 : 0 : 4;
done:
    if (result == 2) fputs("holypkg: malformed APT index or catalog\n", stderr);
    free_index(&index);
    return result;
}

static char *package_url(const char *base, const char *filename)
{
    char *path = strdup(filename), *save = NULL, *part, *url = strdup(base);
    if (!path || !url) { free(path); free(url); return NULL; }
    for (part = strtok_r(path, "/", &save); part; part = strtok_r(NULL, "/", &save)) {
        char *next = holy_fetch_child_url(url, part);
        free(url);
        if (!next) { free(path); return NULL; }
        if (save && *save) {
            size_t length = strlen(next);
            url = realloc(next, length + 2);
            if (!url) { free(next); free(path); return NULL; }
            url[length] = '/'; url[length + 1] = 0;
        } else url = next;
    }
    free(path);
    return url;
}

static int imported_identity(const char *path, const struct apt_entry *selected)
{
    DIR *dir = opendir(path);
    struct dirent *entry;
    size_t count = 0;
    int ok = 0;
    if (!dir) return 0;
    errno = 0;
    while ((entry = readdir(dir))) {
        struct holy_package_identity identity = {0};
        char *filename;
        size_t length = strlen(entry->d_name);
        if (length < 6 || strcmp(entry->d_name + length - 5, ".holy")) continue;
        filename = malloc(strlen(path) + length + 2);
        if (!filename) goto done;
        sprintf(filename, "%s/%s", path, entry->d_name);
        if (!holy_package_identity(filename, &identity)) { free(filename); goto done; }
        free(filename);
        if (strcmp(identity.name, selected->name) ||
            strcmp(identity.version, selected->version) ||
            (!strcmp(selected->arch, "all") && strcmp(identity.arch, "noarch")) ||
            (!strcmp(selected->arch, "amd64") && strcmp(identity.arch, "x86_64") &&
             strcmp(identity.arch, "noarch")) ||
            (!strcmp(selected->arch, "i386") && strcmp(identity.arch, "x86") &&
             strcmp(identity.arch, "noarch"))) {
            holy_package_identity_free(&identity); goto done;
        }
        holy_package_identity_free(&identity);
        ++count;
        errno = 0;
    }
    ok = count && !errno;
done:
    closedir(dir);
    return ok;
}

int holy_apt_fetch(const char *catalog, const char *name, const char *version,
                   const char *arch, const char *output, const char *ca_file,
                   int import)
{
    struct apt_index index = {0};
    const struct apt_entry *selected = NULL;
    char downloaded[65] = {0}, *url = NULL, *converted = NULL, *original = NULL;
    struct stat st;
    FILE *receipt = NULL;
    size_t i;
    int dir = -1, fd = -1, result;
    {
        int order;
        if (!catalog || !token(name) || !version ||
            !holy_deb_version_compare(version, version, &order) ||
            !token(arch) || !output) return 2;
    }
    result = read_catalog(catalog, &index);
    if (result) goto done;
    for (i = 0; i < index.count; ++i) {
        const struct apt_entry *e = &index.entries[i];
        if (!strcmp(e->name, name) && !strcmp(e->version, version) && !strcmp(e->arch, arch)) {
            selected = e; break;
        }
    }
    if (!selected) { result = 4; goto done; }
    url = package_url(index.base, selected->filename);
    if (!url) { result = 2; goto done; }
    result = 1;
    if (mkdir(output, 0700)) goto done;
    dir = open(output, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || fstat(dir, &st) || st.st_uid != geteuid() ||
        (st.st_mode & 0777) != 0700) goto done;
    result = holy_fetch_https_foreign(url, output, ca_file, downloaded);
    if (result) goto done;
    if (strcmp(downloaded, selected->sha256)) { result = 4; goto done; }
    fd = openat(dir, downloaded, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        (unsigned long long)st.st_size != selected->size) { result = 4; goto done; }
    close(fd); fd = -1;
    result = 1;
    if (linkat(dir, downloaded, dir, "original", 0) || fsync(dir)) goto done;
    if (import) {
        converted = malloc(strlen(output) + sizeof "/converted");
        if (!converted) goto done;
        sprintf(converted, "%s/converted", output);
        original = malloc(strlen(output) + sizeof "/original");
        if (!original) { result = 1; goto done; }
        sprintf(original, "%s/original", output);
        result = holy_import_deb(original, index.source, converted);
        if (result) goto done;
        if (!imported_identity(converted, selected)) { result = 4; goto done; }
    }
    fd = openat(dir, "selection", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) { result = 1; goto done; }
    receipt = fdopen(fd, "w");
    if (!receipt) { close(fd); fd = -1; result = 1; goto done; }
    fd = -1;
    fputs("format holy-apt-selection-1\nsource-name ", receipt); quote(receipt, index.source);
    fputs("\nbase-url ", receipt); quote(receipt, index.base);
    fputs("\nurl ", receipt); quote(receipt, url);
    fputs("\nname ", receipt); quote(receipt, name);
    fputs("\nversion ", receipt); quote(receipt, version);
    fputs("\narch ", receipt); quote(receipt, arch);
    fprintf(receipt, "\nindex-sha256 %s\nartifact-sha256 %s\nsize %llu\nverification %s\nimported %s\nstate complete\n",
            index.hash, selected->sha256, selected->size,
            index.release_verified ? "release-gpgv-user-key" : "pinned-unverified",
            import ? "yes" : "no");
    {
        int failed = ferror(receipt);
        if (fflush(receipt) || fsync(fileno(receipt))) failed = 1;
        if (fclose(receipt)) failed = 1;
        receipt = NULL;
        if (failed || fsync(dir)) { result = 1; goto done; }
    }
    printf("apt fetched %s %s %s sha256 %s%s\n", name, version, arch,
           downloaded, import ? " imported" : "");
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: APT fetch incomplete (status %d)\n", result);
    if (receipt) fclose(receipt);
    if (fd >= 0) close(fd);
    if (dir >= 0) close(dir);
    free(url); free(converted); free(original); free_index(&index);
    return result;
}
