#define _POSIX_C_SOURCE 200809L
#include "apk.h"
#include "../src/config.h"
#include "../src/stage.h"

#include <archive.h>
#include <archive_entry.h>
#include <errno.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <zlib.h>

int holy_apk_gzip_parts(const char *snapshot, FILE *parts[3],
                        char digests[3][65], uint64_t max_expanded)
{
    unsigned char in[65536], out[65536], digest[32];
    struct stat st;
    off_t offset = 0;
    int fd = open(snapshot, O_RDONLY | O_CLOEXEC), count = 0, ok = 0;
    if (fd < 0 || fstat(fd, &st) || st.st_size <= 0) goto done;
    while (offset < st.st_size && count < 3) {
        z_stream z = {0};
        EVP_MD_CTX *hash = EVP_MD_CTX_new();
        unsigned length = 0;
        uint64_t expanded = 0;
        off_t begin = offset;
        int status = Z_OK;
        parts[count] = tmpfile();
        if (!parts[count] || !hash || EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1 ||
            inflateInit2(&z, 15 + 16) != Z_OK) {
            EVP_MD_CTX_free(hash); goto done;
        }
        while (status == Z_OK) {
            ssize_t got = pread(fd, in, sizeof in, offset);
            size_t used;
            if (got <= 0) break;
            z.next_in = in; z.avail_in = (uInt)got;
            while (z.avail_in && status == Z_OK) {
                uInt before = z.avail_in;
                z.next_out = out; z.avail_out = sizeof out;
                status = inflate(&z, Z_NO_FLUSH);
                used = before - z.avail_in;
                if (status != Z_OK && status != Z_STREAM_END) break;
                if (fwrite(in + (got - before), 1, used, parts[count]) != used ||
                    EVP_DigestUpdate(hash, in + (got - before), used) != 1) {
                    status = Z_ERRNO; break;
                }
                offset += (off_t)used;
                expanded += sizeof out - z.avail_out;
                if (expanded > max_expanded ||
                    (!used && z.avail_out == sizeof out)) { status = Z_DATA_ERROR; break; }
            }
        }
        inflateEnd(&z);
        if (status != Z_STREAM_END || offset == begin ||
            EVP_DigestFinal_ex(hash, digest, &length) != 1 || length != 32 ||
            fflush(parts[count])) { EVP_MD_CTX_free(hash); goto done; }
        EVP_MD_CTX_free(hash);
        {
            size_t i;
            for (i = 0; i < 32; ++i) snprintf(digests[count] + i * 2, 3, "%02x", digest[i]);
        }
        ++count;
    }
    ok = offset == st.st_size && count > 0;
done:
    if (fd >= 0) close(fd);
    if (!ok) { size_t i; for (i = 0; i < 3; ++i) { if (parts[i]) fclose(parts[i]); parts[i] = NULL; } }
    return ok ? count : 0;
}

struct apk_index_entry {
    char *name, *version, *arch, *checksum, *depends, *provides;
    unsigned long long size;
    unsigned mask;
};

struct apk_index {
    struct apk_index_entry *entries;
    size_t count, capacity;
};

static int digit(char c) { return c >= '0' && c <= '9'; }

static int package_name(const char *name)
{
    const unsigned char *p = (const unsigned char *)name;
    if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
          (*p >= '0' && *p <= '9'))) return 0;
    for (; *p; ++p)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '.' || *p == '_' ||
              *p == '+' || *p == '-')) return 0;
    return 1;
}

static void quote(FILE *out, const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    fputc('"', out);
    for (; *p; ++p)
        if (*p == '"' || *p == '\\') fprintf(out, "\\%c", *p);
        else if (*p < 32 || *p >= 127) fprintf(out, "\\x%02x", *p);
        else fputc(*p, out);
    fputc('"', out);
}

static void clear_index(struct apk_index *index)
{
    size_t i;
    for (i = 0; i < index->count; ++i) {
        struct apk_index_entry *e = &index->entries[i];
        free(e->name); free(e->version); free(e->arch); free(e->checksum);
        free(e->depends); free(e->provides);
    }
    free(index->entries);
}

static int entry_order(const void *left, const void *right)
{
    const struct apk_index_entry *a = left, *b = right;
    int result = strcmp(a->name, b->name);
    if (!result) result = strcmp(a->version, b->version);
    if (!result) result = strcmp(a->arch, b->arch);
    return result;
}

static int parse_index(char *data, size_t size, struct apk_index *index)
{
    size_t start = 0, line = 0;
    int new_record = 1;
    while (start < size) {
        char *end = memchr(data + start, '\n', size - start);
        size_t length = end ? (size_t)(end - data - start) : size - start;
        struct apk_index_entry *e;
        char code, *value, **slot = NULL;
        unsigned bit = 0;
        if (++line > 2000000 || length > 65536 || memchr(data + start, 0, length)) return 0;
        data[start + length] = 0;
        if (!length) { new_record = 1; start += length + (end != NULL); continue; }
        if (length < 3 || data[start + 1] != ':' || index->count > 100000) return 0;
        code = data[start]; value = data + start + 2;
        if (!*value || strchr(value, '\r')) return 0;
        if (new_record) {
            if (index->count == index->capacity) {
                size_t capacity = index->capacity ? index->capacity * 2 : 256;
                void *grown;
                if (capacity > 100000) capacity = 100000;
                if (capacity == index->capacity) return 0;
                grown = realloc(index->entries, capacity * sizeof *index->entries);
                if (!grown) return 0;
                index->entries = grown; index->capacity = capacity;
            }
            e = &index->entries[index->count++]; memset(e, 0, sizeof *e);
            new_record = 0;
        }
        e = &index->entries[index->count - 1];
        switch (code) {
        case 'P': slot = &e->name; bit = 1; break;
        case 'V': slot = &e->version; bit = 2; break;
        case 'A': slot = &e->arch; bit = 4; break;
        case 'C': slot = &e->checksum; bit = 8; break;
        case 'S': bit = 16; break;
        case 'D': slot = &e->depends; bit = 32; break;
        case 'p': slot = &e->provides; bit = 64; break;
        default: break;
        }
        if (bit && (e->mask & bit)) return 0;
        e->mask |= bit;
        if (slot) { *slot = strdup(value); if (!*slot) return 0; }
        if (code == 'S') {
            const char *p = value;
            for (; *p; ++p) {
                if (!digit(*p) || e->size > (1000000000000ULL - (unsigned)(*p - '0')) / 10) return 0;
                e->size = e->size * 10 + (unsigned)(*p - '0');
            }
        }
        start += length + (end != NULL);
    }
    if (!index->count) return 0;
    for (start = 0; start < index->count; ++start) {
        struct apk_index_entry *e = &index->entries[start];
        if ((e->mask & 31) != 31 || !package_name(e->name) ||
            !e->version[0] || !e->arch[0] || strlen(e->checksum) > 128) return 0;
    }
    qsort(index->entries, index->count, sizeof *index->entries, entry_order);
    for (start = 1; start < index->count; ++start)
        if (!entry_order(&index->entries[start - 1], &index->entries[start])) return 0;
    return 1;
}

static int read_index_tar(FILE *part, int signature, char **data, size_t *size)
{
    struct archive *ar = archive_read_new();
    struct archive_entry *entry;
    char descriptor[64];
    int status, ok = 0, seen = 0;
    if (!ar) return 0;
    snprintf(descriptor, sizeof descriptor, "/proc/self/fd/%d", fileno(part));
    if (archive_read_support_filter_gzip(ar) != ARCHIVE_OK ||
        archive_read_support_format_tar(ar) != ARCHIVE_OK ||
        archive_read_open_filename(ar, descriptor, 65536) != ARCHIVE_OK) goto done;
    while ((status = archive_read_next_header(ar, &entry)) == ARCHIVE_OK) {
        const char *name = archive_entry_pathname(entry);
        long long length = archive_entry_size(entry);
        if (!name || length < 0 || archive_entry_filetype(entry) != AE_IFREG ||
            archive_entry_hardlink(entry) || archive_entry_symlink(entry)) goto done;
        if (signature) {
            if (strncmp(name, ".SIGN.", 6) || length > 4096 ||
                archive_read_data_skip(ar) != ARCHIVE_OK) goto done;
            ++seen;
        } else if (!strcmp(name, "APKINDEX")) {
            size_t used = 0;
            if (seen++ || length > 32LL * 1024 * 1024) goto done;
            *data = malloc((size_t)length + 1);
            if (!*data) goto done;
            while (used < (size_t)length) {
                la_ssize_t got = archive_read_data(ar, *data + used, (size_t)length - used);
                if (got <= 0) goto done;
                used += (size_t)got;
            }
            (*data)[used] = 0; *size = used;
        } else if (!strcmp(name, "DESCRIPTION") && length <= 1024 * 1024) {
            if (archive_read_data_skip(ar) != ARCHIVE_OK) goto done;
        } else goto done;
    }
    ok = status == ARCHIVE_EOF && seen > 0;
done:
    archive_read_free(ar);
    return ok;
}

static int hash_fd(int fd, char output[65])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char digest[32], buffer[65536];
    unsigned length;
    size_t i;
    int ok = 0;
    ssize_t got;
    if (lseek(fd, 0, SEEK_SET) < 0 || !ctx ||
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto done;
    while ((got = read(fd, buffer, sizeof buffer)) != 0) {
        if (got < 0 && errno == EINTR) continue;
        if (got < 0 || EVP_DigestUpdate(ctx, buffer, (size_t)got) != 1) goto done;
    }
    if (EVP_DigestFinal_ex(ctx, digest, &length) != 1 || length != 32) goto done;
    for (i = 0; i < 32; ++i) snprintf(output + 2 * i, 3, "%02x", digest[i]);
    ok = lseek(fd, 0, SEEK_SET) >= 0;
done:
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int hash_file(const char *path, char output[65])
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC), ok;
    if (fd < 0) return 0;
    ok = hash_fd(fd, output);
    close(fd);
    return ok;
}

static int copy_original(const char *path, int output)
{
    int source = open(path, O_RDONLY | O_CLOEXEC);
    int target = openat(output, "original", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    char buffer[65536];
    ssize_t got;
    int ok = 0;
    if (source < 0 || target < 0) goto done;
    while ((got = read(source, buffer, sizeof buffer)) != 0) {
        size_t used = 0;
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) goto done;
        while (used < (size_t)got) {
            ssize_t n = write(target, buffer + used, (size_t)got - used);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) goto done;
            used += (size_t)n;
        }
    }
    ok = !fsync(target);
done:
    if (source >= 0) close(source);
    if (target >= 0) close(target);
    return ok;
}

static int base_url(const char *url)
{
    const char *host, *end;
    const unsigned char *p;
    if (!strncmp(url, "https://", 8)) host = url + 8;
    else if (!strncmp(url, "http://", 7)) host = url + 7;
    else return 0;
    end = strchr(host, '/');
    if (!end || end == host || url[strlen(url) - 1] != '/' ||
        memchr(host, '@', (size_t)(end - host)) || strchr(url, '?') || strchr(url, '#')) return 0;
    for (p = (const unsigned char *)url; *p; ++p) if (*p <= 32 || *p == 127) return 0;
    return 1;
}

int holy_apk_index(const char *input, const char *source, const char *base,
                   const char *output)
{
    struct apk_index index = {0};
    struct stat st;
    FILE *parts[3] = {0}, *catalog = NULL, *record = NULL;
    char digests[3][65] = {{0}}, digest[65], catalog_digest[65];
    char *snapshot = NULL, *bytes = NULL;
    size_t size = 0, i;
    int input_fd = -1, output_fd = -1, count, result = 1;
    if (!input || !source || !*source || !strcmp(source, "local") ||
        !base || !base_url(base) || !output) return 2;
    for (i = 0; source[i]; ++i)
        if ((unsigned char)source[i] <= 32 || source[i] == ':' || source[i] == '/' || source[i] == '@') return 2;
    input_fd = open(input, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (input_fd < 0 || fstat(input_fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size < 0 || st.st_size > 64LL * 1024 * 1024) { result = 6; goto done; }
    snapshot = holy_stage_fd(input_fd, "holy-apk-index");
    if (!snapshot || !hash_file(snapshot, digest) || mkdir(output, 0700)) goto done;
    output_fd = open(output, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (output_fd < 0 || fstat(output_fd, &st) || st.st_uid != geteuid() ||
        (st.st_mode & 0777) != 0700 || !copy_original(snapshot, output_fd)) goto done;
    result = 2;
    count = holy_apk_gzip_parts(snapshot, parts, digests, 64ULL * 1024 * 1024);
    if (count < 1 || count > 2 ||
        (count == 2 && !read_index_tar(parts[0], 1, &bytes, &size)) ||
        !read_index_tar(parts[count - 1], 0, &bytes, &size) ||
        !parse_index(bytes, size, &index)) goto done;
    result = 1;
    {
        int fd = openat(output_fd, "catalog", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) goto done;
        catalog = fdopen(fd, "w");
        if (!catalog) { close(fd); goto done; }
    }
    fputs("format holy-apk-catalog-1\n", catalog);
    for (i = 0; i < index.count; ++i) {
        const struct apk_index_entry *e = &index.entries[i];
        fputs("package ", catalog); quote(catalog, e->name); fputc(' ', catalog);
        quote(catalog, e->version); fputc(' ', catalog);
        quote(catalog, e->arch); fputc(' ', catalog);
        quote(catalog, e->checksum); fprintf(catalog, " %llu ", e->size);
        quote(catalog, e->depends ? e->depends : "-"); fputc(' ', catalog);
        quote(catalog, e->provides ? e->provides : "-"); fputc('\n', catalog);
    }
    {
        int failed = ferror(catalog);
        if (fflush(catalog) || fsync(fileno(catalog))) failed = 1;
        if (fclose(catalog)) failed = 1;
        catalog = NULL;
        if (failed) goto done;
    }
    {
        int fd = openat(output_fd, "catalog", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        int ok = fd >= 0 && hash_fd(fd, catalog_digest);
        if (fd >= 0) close(fd);
        if (!ok) goto done;
    }
    {
        int fd = openat(output_fd, "conversion", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) goto done;
        record = fdopen(fd, "w");
        if (!record) { close(fd); goto done; }
    }
    fputs("format holy-apk-index-record-1\nsource-name ", record); quote(record, source);
    fputs("\nbase-url ", record); quote(record, base);
    fprintf(record, "\noriginal-sha256 %s\ncatalog-sha256 %s\nverification unverified\npackage-coverage complete\nfile-coverage unavailable\npackages %zu\nstate complete\n",
            digest, catalog_digest, index.count);
    {
        int failed = ferror(record);
        if (fflush(record) || fsync(fileno(record))) failed = 1;
        if (fclose(record)) failed = 1;
        record = NULL;
        if (failed) goto done;
    }
    if (fsync(output_fd)) goto done;
    printf("indexed %zu packages original %s\n", index.count, digest);
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: APK index incomplete (status %d)\n", result);
    if (catalog) fclose(catalog);
    if (record) fclose(record);
    for (i = 0; i < 3; ++i) if (parts[i]) fclose(parts[i]);
    if (output_fd >= 0) close(output_fd);
    if (input_fd >= 0) close(input_fd);
    if (snapshot) { unlink(snapshot); free(snapshot); }
    free(bytes); clear_index(&index);
    return result;
}

int holy_apk_query(const char *directory, const char *query, int info)
{
    char *line = NULL;
    char expected[65] = {0}, actual[65];
    FILE *catalog = NULL, *record = NULL;
    struct stat st;
    size_t capacity = 0, matches = 0;
    int dir = -1, fd, result = 2;
    if (!directory || !query || !*query) return 2;
    dir = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) { result = 6; goto done; }
    fd = openat(dir, "conversion", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { result = 6; goto done; }
    record = fdopen(fd, "r");
    if (!record) { close(fd); goto done; }
    if (!record || fstat(fileno(record), &st) || !S_ISREG(st.st_mode) || st.st_size > 4096 ||
        getline(&line, &capacity, record) < 0 ||
        strcmp(line, "format holy-apk-index-record-1\n")) goto done;
    {
        int complete = 0;
        ssize_t got;
        while ((got = getline(&line, &capacity, record)) > 0) {
            if (got > 4096) goto done;
            if (!strncmp(line, "catalog-sha256 ", 15) && got == 80) {
                memcpy(expected, line + 15, 64); expected[64] = 0;
                if (strspn(expected, "0123456789abcdef") != 64) goto done;
            }
            if (!strcmp(line, "state complete\n")) complete = 1;
        }
        if (!complete || !expected[0]) { result = 6; goto done; }
    }
    fd = openat(dir, "catalog", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { result = 6; goto done; }
    catalog = fdopen(fd, "r");
    if (!catalog) { close(fd); goto done; }
    if (!catalog || fstat(fileno(catalog), &st) || !S_ISREG(st.st_mode) ||
        st.st_size < 27 || st.st_size > 64LL * 1024 * 1024 ||
        !hash_fd(fileno(catalog), actual) || strcmp(expected, actual) ||
        getline(&line, &capacity, catalog) < 0 ||
        strcmp(line, "format holy-apk-catalog-1\n")) goto done;
    while (1) {
        char **v = NULL, *error = NULL;
        size_t n = 0;
        ssize_t got = getline(&line, &capacity, catalog);
        if (got < 0) break;
        if (got > 65536 || !holy_lex(line, (size_t)got, &v, &n,
                                     "APK catalog", 0, &error) ||
            n != 8 || strcmp(v[0], "package")) {
            free(error); holy_tokens_free(v, n); goto done;
        }
        if ((info && !strcmp(v[1], query)) || (!info && strstr(v[1], query))) {
            ++matches;
            if (info) {
                printf("package %s\nversion %s\narch %s\nchecksum %s\nsize %s\ndepend %s\nprovides %s\n",
                       v[1], v[2], v[3], v[4], v[5], v[6], v[7]);
            } else printf("%s %s %s\n", v[1], v[2], v[3]);
        }
        free(error); holy_tokens_free(v, n);
    }
    if (ferror(catalog)) goto done;
    result = matches ? info && matches > 1 ? 3 : 0 : 4;
done:
    if (result == 2) fputs("holypkg: malformed APK catalog\n", stderr);
    if (catalog) fclose(catalog);
    if (record) fclose(record);
    if (dir >= 0) close(dir);
    free(line);
    return result;
}
