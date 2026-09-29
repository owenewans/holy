#define _POSIX_C_SOURCE 200809L
#include "rpm-md.h"

#ifndef HOLY_HAVE_RPMMD
#include <stdio.h>
int holy_rpm_md_index(const char *a, const char *b, const char *c, const char *d,
                      const char *e, const char *f)
{ (void)a; (void)b; (void)c; (void)d; (void)e; (void)f;
  fputs("holypkg: rpm-md requires librpm and libxml2 at build time\n", stderr); return 6; }
int holy_rpm_md_sync(const char *a, const char *b, const char *c, const char *d, const char *e)
{ (void)a; (void)b; (void)c; (void)d; (void)e; return 6; }
int holy_rpm_md_query(const char *a, const char *b, int c)
{ (void)a; (void)b; (void)c; return 6; }
int holy_rpm_md_fetch(const char *a, const char *b, const char *c, const char *d,
                      const char *e, const char *f, int g)
{ (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; (void)g; return 6; }
#else

#include "rpm-version.h"
#include "../src/fetch.h"
#include "../src/import.h"

#include <archive.h>
#include <libxml/xmlreader.h>
#include <openssl/evp.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct rpmmd_row {
    char name[256], evr[256], arch[64], hash[65], href[1024];
    unsigned long long size;
};

struct rpmmd_catalog {
    FILE *file;
    char source[256], base[2048], repomd[65], primary[65], catalog[65];
};

static int digest(const char *value)
{
    return value && strlen(value) == 64 && strspn(value, "0123456789abcdef") == 64;
}

static int label(const char *value, size_t limit)
{
    const unsigned char *p = (const unsigned char *)value;
    size_t n = value ? strlen(value) : 0;
    if (!n || n >= limit || !isalnum(*p)) return 0;
    for (; *p; ++p)
        if (!isalnum(*p) && *p != '.' && *p != '_' && *p != '+' && *p != '-') return 0;
    return 1;
}

static int href_valid(const char *href)
{
    const char *p = href, *part = href;
    size_t n = href ? strlen(href) : 0;
    if (!n || n >= 1024 || *p == '/') return 0;
    for (; *p; ++p) {
        if (*p == '/') {
            size_t size = (size_t)(p - part);
            if (!size || (size == 1 && *part == '.') ||
                (size == 2 && !memcmp(part, "..", 2))) return 0;
            part = p + 1;
        } else if (!isalnum((unsigned char)*p) && *p != '.' && *p != '_' &&
                   *p != '-' && *p != '+') return 0;
    }
    return p != part && strcmp(part, ".") && strcmp(part, "..");
}

static int number(const char *value, unsigned long long *out)
{
    char *end;
    unsigned long long n;
    if (!value || !*value || *value == '-') return 0;
    errno = 0;
    n = strtoull(value, &end, 10);
    if (errno || *end) return 0;
    *out = n;
    return 1;
}

static int hash_file(const char *path, char hash[65], off_t limit)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    struct stat st;
    unsigned char bytes[65536], digest_bytes[32];
    unsigned digest_size;
    ssize_t got;
    size_t i;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK), ok = 0;
    if (!ctx || fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size < 0 || st.st_size > limit ||
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto done;
    while ((got = read(fd, bytes, sizeof bytes)) > 0)
        if (EVP_DigestUpdate(ctx, bytes, (size_t)got) != 1) goto done;
    if (got || EVP_DigestFinal_ex(ctx, digest_bytes, &digest_size) != 1 || digest_size != 32) goto done;
    for (i = 0; i < 32; ++i) snprintf(hash + i * 2, 3, "%02x", digest_bytes[i]);
    ok = 1;
done:
    if (fd >= 0) close(fd);
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int attr(xmlTextReaderPtr reader, const char *name, char *out, size_t capacity)
{
    xmlChar *value = xmlTextReaderGetAttribute(reader, (const xmlChar *)name);
    size_t length;
    if (!value) return 0;
    length = strlen((const char *)value);
    if (!length || length >= capacity) { xmlFree(value); return 0; }
    memcpy(out, value, length + 1);
    xmlFree(value);
    return 1;
}

static int element(xmlTextReaderPtr reader, const char *name)
{
    const xmlChar *current = xmlTextReaderConstLocalName(reader);
    return current && !xmlStrcmp(current, (const xmlChar *)name);
}

static int contents(xmlTextReaderPtr reader, char *out, size_t capacity)
{
    xmlChar *value = xmlTextReaderReadString(reader);
    size_t length;
    if (!value) return 0;
    length = strlen((const char *)value);
    if (!length || length >= capacity) { xmlFree(value); return 0; }
    memcpy(out, value, length + 1);
    xmlFree(value);
    return 1;
}

static int repomd_primary(const char *path, char href[1024], char hash[65])
{
    xmlTextReaderPtr reader = xmlReaderForFile(path, NULL, XML_PARSE_NONET | XML_PARSE_COMPACT |
                                              XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    int step, in_primary = 0, found = 0, root = 0, ok = 0;
    if (!reader) return 0;
    while ((step = xmlTextReaderRead(reader)) == 1) {
        int type = xmlTextReaderNodeType(reader), depth = xmlTextReaderDepth(reader);
        if (type == XML_READER_TYPE_DOCUMENT_TYPE) goto done;
        if (type == XML_READER_TYPE_ELEMENT && depth == 0) {
            if (root++ || !element(reader, "repomd")) goto done;
        } else if (type == XML_READER_TYPE_ELEMENT && depth == 1 && element(reader, "data")) {
            char kind[64] = {0};
            if (!attr(reader, "type", kind, sizeof kind)) goto done;
            in_primary = !strcmp(kind, "primary");
            if (in_primary && found++) goto done;
        } else if (in_primary && type == XML_READER_TYPE_ELEMENT && depth == 2) {
            if (element(reader, "checksum")) {
                char kind[32];
                if (hash[0] || !attr(reader, "type", kind, sizeof kind) ||
                    strcmp(kind, "sha256") || !contents(reader, hash, 65)) goto done;
            } else if (element(reader, "location")) {
                if (href[0] || !attr(reader, "href", href, 1024)) goto done;
            }
        } else if (type == XML_READER_TYPE_END_ELEMENT && depth == 1 &&
                   element(reader, "data")) in_primary = 0;
    }
    ok = step == 0 && root == 1 && found == 1 && digest(hash) && href_valid(href);
done:
    xmlFreeTextReader(reader);
    return ok;
}

static int unpack_primary(const char *path, FILE *out)
{
    struct archive *archive = archive_read_new();
    struct archive_entry *entry;
    char bytes[65536];
    la_ssize_t got;
    unsigned long long total = 0;
    int ok = 0;
    if (!archive) return 0;
    if (archive_read_support_filter_all(archive) != ARCHIVE_OK ||
        archive_read_support_format_raw(archive) != ARCHIVE_OK ||
        archive_read_open_filename(archive, path, 65536) != ARCHIVE_OK ||
        archive_read_next_header(archive, &entry) != ARCHIVE_OK) goto done;
    while ((got = archive_read_data(archive, bytes, sizeof bytes)) > 0) {
        if (total > 1024ULL * 1024 * 1024 - (unsigned long long)got ||
            fwrite(bytes, 1, (size_t)got, out) != (size_t)got) goto done;
        total += (unsigned long long)got;
    }
    if (got || !total || archive_read_next_header(archive, &entry) != ARCHIVE_EOF ||
        fflush(out) || fseeko(out, 0, SEEK_SET)) goto done;
    ok = 1;
done:
    archive_read_free(archive);
    return ok;
}

static int row_order(const void *a, const void *b)
{
    const struct rpmmd_row *left = a, *right = b;
    int result = strcmp(left->name, right->name);
    if (!result) result = strcmp(left->evr, right->evr);
    if (!result) result = strcmp(left->arch, right->arch);
    return result;
}

static int parse_primary(FILE *primary, struct rpmmd_row **result, size_t *count)
{
    xmlTextReaderPtr reader;
    struct rpmmd_row *rows = NULL, row = {0};
    size_t used = 0, capacity = 0;
    unsigned long long declared = 0;
    int fd = dup(fileno(primary)), step, root = 0, in_package = 0, ok = 0;
    if (fd < 0) return 0;
    reader = xmlReaderForFd(fd, NULL, NULL, XML_PARSE_NONET | XML_PARSE_COMPACT |
                           XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (!reader) { close(fd); return 0; }
    while ((step = xmlTextReaderRead(reader)) == 1) {
        int type = xmlTextReaderNodeType(reader), depth = xmlTextReaderDepth(reader);
        if (type == XML_READER_TYPE_DOCUMENT_TYPE) goto done;
        if (type == XML_READER_TYPE_ELEMENT && depth == 0) {
            char packages[32];
            if (root++ || !element(reader, "metadata") ||
                !attr(reader, "packages", packages, sizeof packages) ||
                !number(packages, &declared) || declared > 100000) goto done;
        } else if (type == XML_READER_TYPE_ELEMENT && depth == 1 && element(reader, "package")) {
            char kind[16];
            if (in_package || !attr(reader, "type", kind, sizeof kind) || strcmp(kind, "rpm")) goto done;
            memset(&row, 0, sizeof row);
            in_package = 1;
        } else if (in_package && type == XML_READER_TYPE_ELEMENT && depth == 2) {
            if (element(reader, "name")) {
                if (row.name[0] || !contents(reader, row.name, sizeof row.name)) goto done;
            } else if (element(reader, "arch")) {
                if (row.arch[0] || !contents(reader, row.arch, sizeof row.arch)) goto done;
            } else if (element(reader, "version")) {
                char epoch[32] = "0", version[128], release[64];
                unsigned long long epoch_number;
                int length;
                if (row.evr[0] || !attr(reader, "ver", version, sizeof version) ||
                    !attr(reader, "rel", release, sizeof release)) goto done;
                if (xmlTextReaderHasAttributes(reader)) {
                    xmlChar *value = xmlTextReaderGetAttribute(reader, (const xmlChar *)"epoch");
                    if (value) {
                        size_t n = strlen((const char *)value);
                        if (!n || n >= sizeof epoch) { xmlFree(value); goto done; }
                        memcpy(epoch, value, n + 1); xmlFree(value);
                    }
                }
                if (!number(epoch, &epoch_number)) goto done;
                length = epoch_number ? snprintf(row.evr, sizeof row.evr, "%llu:%s-%s",
                    epoch_number, version, release) :
                    snprintf(row.evr, sizeof row.evr, "%s-%s", version, release);
                if (length < 0 || (size_t)length >= sizeof row.evr ||
                    !holy_rpm_version_valid(row.evr)) goto done;
            } else if (element(reader, "checksum")) {
                char kind[32];
                if (row.hash[0] || !attr(reader, "type", kind, sizeof kind) ||
                    strcmp(kind, "sha256") || !contents(reader, row.hash, sizeof row.hash)) goto done;
            } else if (element(reader, "size")) {
                char size[32];
                if (row.size || !attr(reader, "package", size, sizeof size) ||
                    !number(size, &row.size)) goto done;
            } else if (element(reader, "location")) {
                if (row.href[0] || !attr(reader, "href", row.href, sizeof row.href)) goto done;
            }
        } else if (in_package && type == XML_READER_TYPE_END_ELEMENT && depth == 1 &&
                   element(reader, "package")) {
            struct rpmmd_row *grown;
            if (!label(row.name, sizeof row.name) || !label(row.arch, sizeof row.arch) ||
                !digest(row.hash) || !href_valid(row.href) ||
                !row.size || row.size > 1024ULL * 1024 * 1024 || used >= 100000) goto done;
            if (used == capacity) {
                size_t next = capacity ? capacity * 2 : 64;
                grown = realloc(rows, next * sizeof *rows);
                if (!grown) goto done;
                rows = grown; capacity = next;
            }
            rows[used++] = row;
            in_package = 0;
        }
    }
    if (step || root != 1 || in_package || used != declared) goto done;
    qsort(rows, used, sizeof *rows, row_order);
    for (size_t i = 1; i < used; ++i) if (!row_order(&rows[i-1], &rows[i])) goto done;
    *result = rows; *count = used; rows = NULL; ok = 1;
done:
    xmlFreeTextReader(reader);
    free(rows);
    return ok;
}

static char *path_join(const char *directory, const char *name)
{
    size_t a = strlen(directory), b = strlen(name);
    char *out;
    if (a > SIZE_MAX - b - 2 || !(out = malloc(a + b + 2))) return NULL;
    memcpy(out, directory, a);
    out[a] = '/'; memcpy(out + a + 1, name, b + 1);
    return out;
}

static char *child_url(const char *base, const char *href)
{
    char *copy = NULL, *save = NULL, *part, *current = NULL;
    if (!href_valid(href) || !(copy = strdup(href)) || !(current = strdup(base))) goto done;
    for (part = strtok_r(copy, "/", &save); part; part = strtok_r(NULL, "/", &save)) {
        char *next = holy_fetch_child_url(current, part);
        free(current); current = next;
        if (!current) goto done;
        if (save && *save) {
            size_t length = strlen(current);
            next = realloc(current, length + 2);
            if (!next) { free(current); current = NULL; goto done; }
            current = next; current[length] = '/'; current[length + 1] = 0;
        }
    }
done:
    free(copy);
    return current;
}

int holy_rpm_md_index(const char *repomd, const char *primary, const char *expected,
                      const char *source, const char *base, const char *output)
{
    struct rpmmd_row *rows = NULL;
    struct stat st;
    char href[1024] = {0}, primary_hash[65] = {0}, actual[65], catalog_hash[65];
    char staged[70], *repomd_path = NULL, *primary_path = NULL, *catalog_path = NULL;
    char *test_url = NULL;
    FILE *expanded = NULL, *catalog = NULL, *record = NULL;
    size_t count = 0, i;
    int dir = -1, result = 1;
    if (!repomd || !primary || !expected || !digest(expected) ||
        !source || !label(source, 256) || !strcmp(source, "local") ||
        !base || !output || !(test_url = child_url(base, "repodata/repomd.xml"))) {
        free(test_url); return 2;
    }
    free(test_url);
    if (mkdir(output, 0700)) return 1;
    dir = open(output, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || fstat(dir, &st) || st.st_uid != geteuid() ||
        (st.st_mode & 0777) != 0700 ||
        !holy_fetch_at(repomd, dir, expected, staged) ||
        renameat(dir, staged, dir, "repomd")) goto done;
    repomd_path = path_join(output, "repomd");
    primary_path = path_join(output, "primary");
    catalog_path = path_join(output, "catalog");
    result = 2;
    if (!repomd_path || !primary_path || !catalog_path ||
        !hash_file(repomd_path, actual, 16 * 1024 * 1024) || strcmp(actual, expected) ||
        !repomd_primary(repomd_path, href, primary_hash) ||
        !holy_fetch_at(primary, dir, primary_hash, staged) ||
        renameat(dir, staged, dir, "primary") ||
        !hash_file(primary_path, actual, 128 * 1024 * 1024) || strcmp(actual, primary_hash)) goto done;
    expanded = tmpfile();
    if (!expanded || !unpack_primary(primary_path, expanded) ||
        !parse_primary(expanded, &rows, &count)) goto done;
    result = 1;
    {
        int fd = openat(dir, "catalog", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) goto done;
        catalog = fdopen(fd, "w");
        if (!catalog) { close(fd); goto done; }
    }
    fputs("format holy-rpm-md-catalog-1\n", catalog);
    for (i = 0; i < count; ++i)
        fprintf(catalog, "package %s %s %s %s %llu %s\n", rows[i].name, rows[i].evr,
                rows[i].arch, rows[i].hash, rows[i].size, rows[i].href);
    if (ferror(catalog) || fflush(catalog) || fsync(fileno(catalog))) goto done;
    if (fclose(catalog)) { catalog = NULL; goto done; }
    catalog = NULL;
    if (!hash_file(catalog_path, catalog_hash, 256 * 1024 * 1024)) goto done;
    {
        int fd = openat(dir, "conversion", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) goto done;
        record = fdopen(fd, "w");
        if (!record) { close(fd); goto done; }
    }
    fprintf(record, "format holy-rpm-md-index-1\nsource %s\nbase %s\nrepomd-sha256 %s\nprimary-sha256 %s\ncatalog-sha256 %s\npackages %zu\nfile-coverage unavailable\ndependency-coverage partial\nstate complete\n",
            source, base, expected, primary_hash, catalog_hash, count);
    if (ferror(record) || fflush(record) || fsync(fileno(record))) goto done;
    if (fclose(record)) { record = NULL; goto done; }
    record = NULL;
    if (fsync(dir)) goto done;
    printf("indexed %zu RPM packages %s\n", count, expected);
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: rpm-md index incomplete (status %d)\n", result);
    if (catalog) fclose(catalog);
    if (record) fclose(record);
    if (expanded) fclose(expanded);
    if (dir >= 0) close(dir);
    free(rows); free(repomd_path); free(primary_path); free(catalog_path);
    return result;
}

static int open_catalog(const char *directory, struct rpmmd_catalog *state)
{
    char *record_path = path_join(directory, "conversion");
    char *catalog_path = path_join(directory, "catalog");
    char *repomd_path = path_join(directory, "repomd");
    char *primary_path = path_join(directory, "primary");
    char line[4096], actual[65];
    struct stat st;
    FILE *record = NULL;
    int dir = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int fd, complete = 0, ok = 0;
    memset(state, 0, sizeof *state);
    if (dir < 0 || !record_path || !catalog_path || !repomd_path || !primary_path ||
        fstat(dir, &st) || st.st_uid != geteuid() || (st.st_mode & 0022)) goto done;
    fd = openat(dir, "conversion", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) goto done;
    record = fdopen(fd, "r");
    if (!record) { close(fd); goto done; }
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size > 4096 ||
        !fgets(line, sizeof line, record) || strcmp(line, "format holy-rpm-md-index-1\n")) goto done;
    while (fgets(line, sizeof line, record)) {
        char *value, *target = NULL;
        size_t capacity = 0, length = strlen(line);
        if (!length || line[length-1] != '\n') goto done;
        line[length-1] = 0;
        value = strchr(line, ' ');
        if (value) *value++ = 0;
        if (!strcmp(line, "source")) { target = state->source; capacity = sizeof state->source; }
        else if (!strcmp(line, "base")) { target = state->base; capacity = sizeof state->base; }
        else if (!strcmp(line, "repomd-sha256")) { target = state->repomd; capacity = sizeof state->repomd; }
        else if (!strcmp(line, "primary-sha256")) { target = state->primary; capacity = sizeof state->primary; }
        else if (!strcmp(line, "catalog-sha256")) { target = state->catalog; capacity = sizeof state->catalog; }
        else if (!strcmp(line, "state") && value && !strcmp(value, "complete") && !complete) {
            complete = 1; continue;
        } else if (!strcmp(line, "packages") || !strcmp(line, "file-coverage") ||
                   !strcmp(line, "dependency-coverage")) continue;
        else goto done;
        if (!value || !*value || strlen(value) >= capacity || target[0]) goto done;
        strcpy(target, value);
    }
    if (ferror(record) || !complete || !label(state->source, sizeof state->source) ||
        !digest(state->repomd) || !digest(state->primary) || !digest(state->catalog) ||
        !hash_file(repomd_path, actual, 16 * 1024 * 1024) || strcmp(actual, state->repomd) ||
        !hash_file(primary_path, actual, 128 * 1024 * 1024) || strcmp(actual, state->primary) ||
        !hash_file(catalog_path, actual, 256 * 1024 * 1024) || strcmp(actual, state->catalog)) goto done;
    {
        char *url = child_url(state->base, "repodata/repomd.xml");
        if (!url) goto done;
        free(url);
    }
    fd = openat(dir, "catalog", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) goto done;
    state->file = fdopen(fd, "r");
    if (!state->file) { close(fd); goto done; }
    if (!fgets(line, sizeof line, state->file) || strcmp(line, "format holy-rpm-md-catalog-1\n")) goto done;
    ok = 1;
done:
    if (!ok && state->file) { fclose(state->file); state->file = NULL; }
    if (record) fclose(record);
    if (dir >= 0) close(dir);
    free(record_path); free(catalog_path); free(repomd_path); free(primary_path);
    return ok;
}

static int next_row(FILE *file, struct rpmmd_row *row)
{
    char line[2048], extra;
    int parsed;
    if (!fgets(line, sizeof line, file)) return ferror(file) ? -1 : 0;
    if (!strchr(line, '\n')) return -1;
    memset(row, 0, sizeof *row);
    parsed = sscanf(line, "package %255s %255s %63s %64s %llu %1023s %c",
                    row->name, row->evr, row->arch, row->hash, &row->size, row->href, &extra);
    return parsed == 6 && label(row->name, sizeof row->name) &&
           holy_rpm_version_valid(row->evr) && label(row->arch, sizeof row->arch) &&
           digest(row->hash) && href_valid(row->href) && row->size > 0 &&
           row->size <= 1024ULL * 1024 * 1024 ? 1 : -1;
}

int holy_rpm_md_query(const char *directory, const char *query, int info)
{
    struct rpmmd_catalog catalog;
    struct rpmmd_row row;
    size_t matches = 0;
    int status;
    if (!directory || !query || !*query) return 2;
    if (!open_catalog(directory, &catalog)) return 6;
    while ((status = next_row(catalog.file, &row)) > 0) {
        if ((info && !strcmp(query, row.name)) || (!info && strstr(row.name, query))) {
            ++matches;
            if (info) printf("package %s\nversion %s\narch %s\nsha256 %s\nsize %llu\npath %s\n",
                             row.name, row.evr, row.arch, row.hash, row.size, row.href);
            else printf("%s %s %s\n", row.name, row.evr, row.arch);
        }
    }
    fclose(catalog.file);
    return status < 0 ? 2 : !matches ? 4 : info && matches > 1 ? 3 : 0;
}

int holy_rpm_md_sync(const char *base, const char *expected, const char *source,
                     const char *output, const char *ca_file)
{
    char temporary[] = "/tmp/holy-rpm-md-XXXXXX", href[1024] = {0};
    char hash[65] = {0}, received[65] = {0};
    char *repomd_url = NULL, *primary_url = NULL, *repomd = NULL, *primary = NULL;
    int result = 2;
    if (!base || !digest(expected) || !source || !label(source, 256) || !output ||
        !(repomd_url = child_url(base, "repodata/repomd.xml"))) goto done;
    if (!mkdtemp(temporary)) { result = 1; goto done; }
    repomd = path_join(temporary, expected);
    if (!repomd) { result = 1; goto cleanup; }
    result = holy_fetch_https_data(repomd_url, expected, temporary, ca_file);
    if (result) goto cleanup;
    result = 2;
    if (!repomd_primary(repomd, href, hash) || !(primary_url = child_url(base, href))) goto cleanup;
    result = holy_fetch_https_foreign_limited(primary_url, temporary, ca_file, received,
                                              128ULL * 1024 * 1024);
    if (result) goto cleanup;
    if (strcmp(hash, received)) { result = 4; goto cleanup; }
    primary = path_join(temporary, hash);
    if (!primary) { result = 1; goto cleanup; }
    result = holy_rpm_md_index(repomd, primary, expected, source, base, output);
cleanup:
    if (primary) unlink(primary);
    if (repomd) unlink(repomd);
    rmdir(temporary);
done:
    free(repomd_url); free(primary_url); free(repomd); free(primary);
    return result;
}

int holy_rpm_md_fetch(const char *directory, const char *name, const char *evr,
                      const char *arch, const char *output, const char *ca_file,
                      int import)
{
    struct rpmmd_catalog catalog;
    struct rpmmd_row row, selected = {0};
    struct stat st;
    char digest_bytes[65] = {0};
    char *url = NULL, *download = NULL, *converted = NULL;
    size_t matches = 0;
    int status, result = 1;
    if (!directory || !label(name, 256) || !holy_rpm_version_valid(evr) ||
        !label(arch, 64) || !output) return 2;
    if (!open_catalog(directory, &catalog)) return 6;
    while ((status = next_row(catalog.file, &row)) > 0) {
        if (!strcmp(name, row.name) && !strcmp(evr, row.evr) && !strcmp(arch, row.arch)) {
            if (!matches) selected = row;
            ++matches;
        }
    }
    fclose(catalog.file);
    if (status < 0) return 2;
    if (!matches) return 4;
    if (matches > 1) return 3;
    url = child_url(catalog.base, selected.href);
    if (!url) { result = 2; goto done; }
    if (mkdir(output, 0700)) goto done;
    result = holy_fetch_https_foreign_limited(url, output, ca_file, digest_bytes, selected.size);
    if (result) goto done;
    if (strcmp(digest_bytes, selected.hash)) { result = 4; goto done; }
    download = path_join(output, digest_bytes);
    if (!download) { result = 1; goto done; }
    if (stat(download, &st) || !S_ISREG(st.st_mode) ||
        (unsigned long long)st.st_size != selected.size) { result = 4; goto done; }
    if (import) {
        converted = path_join(output, "converted");
        if (!converted) { result = 1; goto done; }
        result = holy_import_rpm(download, catalog.source, converted);
        if (result) goto done;
    }
    printf("fetched %s %s %s %s\n", selected.name, selected.evr, selected.arch, selected.hash);
    result = 0;
done:
    free(url); free(download); free(converted);
    return result;
}

#endif
