#define _XOPEN_SOURCE 700
#include "xbps.h"
#include "../src/fetch.h"
#include "../src/stage.h"
#include "../src/source.h"
#include "../src/state.h"

#include <archive.h>
#include <archive_entry.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#ifdef __TINYC__
#define __llvm__ 1
#endif
#include <plist/plist.h>
#ifdef __TINYC__
#undef __llvm__
#endif
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct xbps_row {
    char *name, *version, *arch, *hash;
    unsigned long long size;
};

static int label(const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    if (!p || !*p || strlen(value) > 255 || !isalnum(*p)) return 0;
    for (; *p; ++p)
        if (!isalnum(*p) && *p != '.' && *p != '_' && *p != '+' && *p != '-' && *p != '~') return 0;
    return 1;
}

static int digest_label(const char *value)
{
    return value && strlen(value) == 64 && strspn(value, "0123456789abcdef") == 64;
}

static int hash_fd(int fd, char result[65])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char digest[32], buffer[65536];
    unsigned length;
    ssize_t got;
    size_t i;
    int ok = 0;
    if (!ctx || lseek(fd, 0, SEEK_SET) < 0 || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto done;
    while ((got = read(fd, buffer, sizeof buffer)) > 0)
        if (EVP_DigestUpdate(ctx, buffer, (size_t)got) != 1) goto done;
    if (got || EVP_DigestFinal_ex(ctx, digest, &length) != 1 || length != 32) goto done;
    for (i = 0; i < 32; ++i) snprintf(result + i * 2, 3, "%02x", digest[i]);
    ok = 1;
done:
    EVP_MD_CTX_free(ctx);
    return ok;
}

static char *string(plist_t dict, const char *key)
{
    plist_t node = plist_dict_get_item(dict, key);
    char *value = NULL;
    if (node && plist_get_node_type(node) == PLIST_STRING) plist_get_string_val(node, &value);
    return value;
}

static EVP_PKEY *public_key_bytes(const char *data, size_t size)
{
    BIO *bio;
    EVP_PKEY *key;
    if (!data || !size || size > 16384) return NULL;
    bio = BIO_new_mem_buf(data, (int)size);
    if (!bio) return NULL;
    key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (key && EVP_PKEY_base_id(key) != EVP_PKEY_RSA) {
        EVP_PKEY_free(key); return NULL;
    }
    return key;
}

static EVP_PKEY *public_key_file(const char *path)
{
    struct stat st;
    char *data = NULL;
    EVP_PKEY *key = NULL;
    size_t used = 0;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        st.st_size > 16384) goto done;
    data = malloc((size_t)st.st_size);
    if (!data) goto done;
    while (used < (size_t)st.st_size) {
        ssize_t got = read(fd, data + used, (size_t)st.st_size - used);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) goto done;
        used += (size_t)got;
    }
    key = public_key_bytes(data, used);
done:
    if (fd >= 0) close(fd);
    free(data);
    return key;
}

static int key_digest(EVP_PKEY *key, char output[65])
{
    unsigned char *der = NULL, *cursor, hash[32];
    unsigned length;
    int size = i2d_PUBKEY(key, NULL), ok = 0;
    size_t i;
    if (size <= 0 || size > 16384 || !(der = malloc((size_t)size))) return 0;
    cursor = der;
    if (i2d_PUBKEY(key, &cursor) != size ||
        EVP_Digest(der, (size_t)size, hash, &length, EVP_sha256(), NULL) != 1 ||
        length != 32) goto done;
    for (i = 0; i < 32; ++i) snprintf(output + i * 2, 3, "%02x", hash[i]);
    ok = 1;
done:
    free(der);
    return ok;
}

int holy_xbps_key_fingerprint(const char *path, char output[65])
{
    EVP_PKEY *key = public_key_file(path);
    int ok = key && key_digest(key, output);
    EVP_PKEY_free(key);
    return ok;
}

static int index_key(const char *xml, size_t size, const char *trusted_path, char hash[65])
{
    plist_t root = NULL, node, bits_node;
    EVP_PKEY *advertised = NULL, *trusted = NULL;
    char *algorithm = NULL;
    const char *data;
    uint64_t length = 0, bits = 0;
    int ok = 0;
    if (size > UINT32_MAX || plist_from_xml(xml, (uint32_t)size, &root) != PLIST_ERR_SUCCESS ||
        !root || plist_get_node_type(root) != PLIST_DICT) goto done;
    node = plist_dict_get_item(root, "public-key");
    if (!node) { ok = !trusted_path; goto done; }
    if (plist_get_node_type(node) != PLIST_DATA) goto done;
    algorithm = string(root, "signature-type");
    bits_node = plist_dict_get_item(root, "public-key-size");
    if (bits_node && plist_get_node_type(bits_node) == PLIST_INT)
        plist_get_uint_val(bits_node, &bits);
    data = plist_get_data_ptr(node, &length);
    if (!algorithm || strcmp(algorithm, "rsa") || !data || length > 16384 ||
        !(advertised = public_key_bytes(data, (size_t)length)) ||
        !bits_node || bits != (uint64_t)EVP_PKEY_bits(advertised) ||
        !key_digest(advertised, hash)) goto done;
    if (!trusted_path) { ok = 1; goto done; }
    trusted = public_key_file(trusted_path);
    ok = trusted && EVP_PKEY_eq(advertised, trusted) == 1;
done:
    if (!ok) hash[0] = 0;
    free(algorithm); EVP_PKEY_free(advertised); EVP_PKEY_free(trusted); plist_free(root);
    return ok;
}

static int verify_signature(const char *package, const char *signature, EVP_PKEY *key)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    struct stat st;
    unsigned char *sig = NULL, buffer[65536];
    size_t used = 0;
    ssize_t got;
    int package_fd = -1, signature_fd = -1, ok = 0;
    signature_fd = open(signature, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    package_fd = open(package, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (!ctx || signature_fd < 0 || package_fd < 0 ||
        fstat(signature_fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size <= 0 || st.st_size > 16384 ||
        !(sig = malloc((size_t)st.st_size)) ||
        EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key) != 1) goto done;
    while (used < (size_t)st.st_size) {
        got = read(signature_fd, sig + used, (size_t)st.st_size - used);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) goto done;
        used += (size_t)got;
    }
    while ((got = read(package_fd, buffer, sizeof buffer)) > 0)
        if (EVP_DigestVerifyUpdate(ctx, buffer, (size_t)got) != 1) goto done;
    if (got || EVP_DigestVerifyFinal(ctx, sig, used) != 1) goto done;
    ok = 1;
done:
    if (signature_fd >= 0) close(signature_fd);
    if (package_fd >= 0) close(package_fd);
    EVP_MD_CTX_free(ctx); free(sig);
    return ok;
}

static void free_rows(struct xbps_row *rows, size_t count)
{
    size_t i;
    for (i = 0; i < count; ++i) {
        free(rows[i].name); free(rows[i].version);
        free(rows[i].arch); free(rows[i].hash);
    }
    free(rows);
}

static int row_order(const void *left, const void *right)
{
    const struct xbps_row *a = left, *b = right;
    int result = strcmp(a->name, b->name);
    if (!result) result = strcmp(a->version, b->version);
    if (!result) result = strcmp(a->arch, b->arch);
    return result;
}

static int parse_rows(const char *xml, size_t size, struct xbps_row **out, size_t *count)
{
    plist_t root = NULL, entry = NULL;
    plist_dict_iter iter = NULL;
    struct xbps_row *rows = NULL;
    char *key = NULL;
    size_t used = 0, capacity = 0, i;
    int ok = 0;
    if (size > UINT32_MAX || plist_from_xml(xml, (uint32_t)size, &root) != PLIST_ERR_SUCCESS ||
        !root || plist_get_node_type(root) != PLIST_DICT) goto done;
    plist_dict_new_iter(root, &iter);
    if (!iter) goto done;
    for (;;) {
        struct xbps_row *row;
        char *pkgver = NULL;
        plist_t bytes;
        uint64_t length = 0;
        plist_dict_next_item(root, iter, &key, &entry);
        if (!key) break;
        if (!label(key) || !entry || plist_get_node_type(entry) != PLIST_DICT || used == 100000) goto done;
        if (used == capacity) {
            size_t next = capacity ? capacity * 2 : 256;
            struct xbps_row *grown = realloc(rows, next * sizeof *rows);
            if (!grown) goto done;
            rows = grown; capacity = next;
        }
        row = &rows[used++]; memset(row, 0, sizeof *row);
        row->name = key; key = NULL;
        pkgver = string(entry, "pkgver");
        row->arch = string(entry, "architecture");
        row->hash = string(entry, "filename-sha256");
        bytes = plist_dict_get_item(entry, "filename-size");
        if (bytes && plist_get_node_type(bytes) == PLIST_INT) plist_get_uint_val(bytes, &length);
        if (!pkgver || strlen(pkgver) <= strlen(row->name) + 1 ||
            strncmp(pkgver, row->name, strlen(row->name)) ||
            pkgver[strlen(row->name)] != '-' ||
            !(row->version = strdup(pkgver + strlen(row->name) + 1)) ||
            !label(row->version) || !label(row->arch) || !digest_label(row->hash) ||
            !bytes || plist_get_node_type(bytes) != PLIST_INT || !length ||
            length > 1024ULL * 1024 * 1024 * 1024) { free(pkgver); goto done; }
        row->size = length;
        free(pkgver);
    }
    if (!used) goto done;
    qsort(rows, used, sizeof *rows, row_order);
    for (i = 1; i < used; ++i)
        if (!row_order(&rows[i-1], &rows[i])) goto done;
    *out = rows; *count = used; rows = NULL; used = 0; ok = 1;
done:
    free(key); free(iter); plist_free(root); free_rows(rows, used);
    return ok;
}

static int read_repodata(const char *path, char **xml, size_t *size,
                         char **meta, size_t *meta_size)
{
    struct archive *archive = archive_read_new();
    struct archive_entry *entry;
    int status, found = 0, metadata = 0, ok = 0;
    if (!archive) return 0;
    if (archive_read_support_filter_zstd(archive) != ARCHIVE_OK ||
        archive_read_support_filter_gzip(archive) != ARCHIVE_OK ||
        archive_read_support_filter_xz(archive) != ARCHIVE_OK ||
        archive_read_support_filter_bzip2(archive) != ARCHIVE_OK ||
        archive_read_support_filter_lz4(archive) != ARCHIVE_OK ||
        archive_read_support_format_tar(archive) != ARCHIVE_OK ||
        archive_read_open_filename(archive, path, 65536) != ARCHIVE_OK) goto done;
    while ((status = archive_read_next_header(archive, &entry)) == ARCHIVE_OK) {
        const char *name = archive_entry_pathname(entry);
        la_int64_t length = archive_entry_size(entry);
        if (!name || archive_entry_filetype(entry) != AE_IFREG ||
            archive_entry_hardlink(entry) || archive_entry_xattr_count(entry) ||
            archive_entry_acl_types(entry)) goto done;
        if (!strcmp(name, "index.plist")) {
            size_t used = 0;
            if (found || length <= 0 || length > 64LL * 1024 * 1024) goto done;
            *xml = malloc((size_t)length + 1);
            if (!*xml) goto done;
            while (used < (size_t)length) {
                la_ssize_t got = archive_read_data(archive, *xml + used, (size_t)length - used);
                if (got <= 0) goto done;
                used += (size_t)got;
            }
            if (memchr(*xml, 0, used)) goto done;
            (*xml)[used] = 0; *size = used; found = 1;
        } else if (!strcmp(name, "index-meta.plist")) {
            size_t used = 0;
            if (metadata++ || length <= 0 || length > 1024 * 1024) goto done;
            *meta = malloc((size_t)length + 1);
            if (!*meta) goto done;
            while (used < (size_t)length) {
                la_ssize_t got = archive_read_data(archive, *meta + used, (size_t)length - used);
                if (got <= 0) goto done;
                used += (size_t)got;
            }
            if (memchr(*meta, 0, used)) goto done;
            (*meta)[used] = 0; *meta_size = used;
        } else if (!strcmp(name, "stage.plist")) {
            if (length != 0 || archive_read_data_skip(archive) != ARCHIVE_OK) goto done;
        } else goto done;
    }
    ok = status == ARCHIVE_EOF && found && metadata == 1;
done:
    archive_read_free(archive);
    return ok;
}

static int package_identity(const char *path, const char *name,
                            const char *version, const char *arch)
{
    struct archive *archive = archive_read_new();
    struct archive_entry *entry;
    plist_t props = NULL;
    char *xml = NULL, *pkgname = NULL, *pkgver = NULL, *source_arch = NULL;
    int found = 0, status, ok = 0;
    if (!archive) return 0;
    if (archive_read_support_filter_gzip(archive) != ARCHIVE_OK ||
        archive_read_support_filter_zstd(archive) != ARCHIVE_OK ||
        archive_read_support_filter_xz(archive) != ARCHIVE_OK ||
        archive_read_support_filter_bzip2(archive) != ARCHIVE_OK ||
        archive_read_support_filter_lz4(archive) != ARCHIVE_OK ||
        archive_read_support_format_tar(archive) != ARCHIVE_OK ||
        archive_read_open_filename(archive, path, 65536) != ARCHIVE_OK) goto done;
    while ((status = archive_read_next_header(archive, &entry)) == ARCHIVE_OK) {
        const char *entry_name = archive_entry_pathname(entry);
        la_int64_t length = archive_entry_size(entry);
        if (entry_name && (!strcmp(entry_name, "props.plist") ||
                           !strcmp(entry_name, "./props.plist"))) {
            size_t used = 0;
            if (found || archive_entry_filetype(entry) != AE_IFREG ||
                length <= 0 || length > 1024 * 1024) goto done;
            xml = malloc((size_t)length + 1);
            if (!xml) goto done;
            while (used < (size_t)length) {
                la_ssize_t got = archive_read_data(archive, xml + used, (size_t)length - used);
                if (got <= 0) goto done;
                used += (size_t)got;
            }
            if (memchr(xml, 0, used) ||
                plist_from_xml(xml, (uint32_t)used, &props) != PLIST_ERR_SUCCESS ||
                !props || plist_get_node_type(props) != PLIST_DICT) goto done;
            found = 1;
        } else if (archive_read_data_skip(archive) != ARCHIVE_OK) goto done;
    }
    if (status != ARCHIVE_EOF || !found) goto done;
    pkgname = string(props, "pkgname");
    pkgver = string(props, "pkgver");
    source_arch = string(props, "architecture");
    if (pkgname && pkgver && source_arch && !strcmp(pkgname, name) &&
        !strcmp(source_arch, arch) && strlen(pkgver) == strlen(name) + strlen(version) + 1 &&
        !strncmp(pkgver, name, strlen(name)) && pkgver[strlen(name)] == '-' &&
        !strcmp(pkgver + strlen(name) + 1, version)) ok = 1;
done:
    free(pkgname); free(pkgver); free(source_arch); free(xml);
    plist_free(props); archive_read_free(archive);
    return ok;
}

int holy_xbps_index(const char *input, const char *source, const char *base,
                    const char *output, const char *expected, const char *public_key,
                    const char *source_id)
{
    struct xbps_row *rows = NULL;
    struct stat st;
    char *xml = NULL, *meta = NULL, *url = NULL;
    char filename[70], original[65], catalog_hash[65], key_hash[65] = {0};
    size_t size = 0, meta_size = 0, count = 0, i;
    FILE *catalog = NULL, *record = NULL;
    int dir = -1, fd = -1, result = 1;
    if (!input || !source || !label(source) || !strcmp(source, "local") || !base || !output ||
        !digest_label(expected) || (source_id && !digest_label(source_id)) ||
        !(url = holy_fetch_child_url(base, "repodata"))) {
        free(url); return 2;
    }
    free(url);
    if (mkdir(output, 0700)) return 1;
    dir = open(output, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || fstat(dir, &st) || st.st_uid != geteuid() ||
        (st.st_mode & 0777) != 0700 || !holy_fetch_at(input, dir, expected, filename) ||
        renameat(dir, filename, dir, "repodata")) goto done;
    fd = openat(dir, "repodata", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size > 64LL * 1024 * 1024 ||
        !hash_fd(fd, original) || strcmp(original, expected)) goto done;
    {
        char descriptor[64];
        snprintf(descriptor, sizeof descriptor, "/proc/self/fd/%d", fd);
        result = 2;
        if (!read_repodata(descriptor, &xml, &size, &meta, &meta_size) ||
            !parse_rows(xml, size, &rows, &count)) goto done;
    }
    free(xml); xml = NULL;
    if (!index_key(meta, meta_size, public_key, key_hash)) { result = 4; goto done; }
    result = 1;
    {
        int catalog_fd = openat(dir, "catalog", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (catalog_fd < 0) goto done;
        catalog = fdopen(catalog_fd, "w");
        if (!catalog) { close(catalog_fd); goto done; }
    }
    fputs("format holy-xbps-catalog-1\n", catalog);
    for (i = 0; i < count; ++i)
        fprintf(catalog, "package %s %s %s %s %llu\n", rows[i].name, rows[i].version,
                rows[i].arch, rows[i].hash, rows[i].size);
    if (ferror(catalog) || fflush(catalog) || fsync(fileno(catalog))) goto done;
    if (fclose(catalog)) { catalog = NULL; goto done; }
    catalog = NULL;
    {
        int catalog_fd = openat(dir, "catalog", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (catalog_fd < 0) goto done;
        result = hash_fd(catalog_fd, catalog_hash) ? 1 : 2;
        close(catalog_fd);
        if (!result) goto done;
    }
    {
        int record_fd = openat(dir, "conversion", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (record_fd < 0) goto done;
        record = fdopen(record_fd, "w");
        if (!record) { close(record_fd); goto done; }
    }
    fprintf(record, "format holy-xbps-index-record-1\nsource %s\nbase %s\noriginal-sha256 %s\ncatalog-sha256 %s\nverification %s\n",
            source, base, original, catalog_hash, public_key ? "key-matched" : "hash-pinned");
    if (source_id) fprintf(record, "source-id %s\n", source_id);
    if (key_hash[0]) fprintf(record, "public-key-sha256 %s\n", key_hash);
    fprintf(record, "package-coverage complete\nfile-coverage unavailable\npackages %zu\nstate complete\n", count);
    if (ferror(record) || fflush(record) || fsync(fileno(record))) goto done;
    if (fclose(record)) { record = NULL; goto done; }
    record = NULL;
    if (fsync(dir)) goto done;
    printf("indexed %zu XBPS packages %s\n", count, original);
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: XBPS index incomplete (status %d)\n", result);
    if (record) fclose(record);
    if (catalog) fclose(catalog);
    if (fd >= 0) close(fd);
    if (dir >= 0) close(dir);
    free(xml); free(meta); free_rows(rows, count);
    return result;
}

struct catalog_state {
    FILE *catalog;
    char source[256], base[2048], original[65], catalog_hash[65], key_hash[65], source_id[65];
};

static int open_catalog(const char *directory, struct catalog_state *state)
{
    struct stat st;
    FILE *record = NULL;
    char line[4096], actual[65];
    int dir = -1, fd, complete = 0, ok = 0;
    memset(state, 0, sizeof *state);
    dir = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || fstat(dir, &st) || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid() ||
        (st.st_mode & 0022)) goto done;
    fd = openat(dir, "conversion", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) goto done;
    record = fdopen(fd, "r");
    if (!record) { close(fd); goto done; }
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size > 4096 ||
        !fgets(line, sizeof line, record) ||
        strcmp(line, "format holy-xbps-index-record-1\n")) goto done;
    while (fgets(line, sizeof line, record)) {
        size_t length = strlen(line);
        if (!length || line[length - 1] != '\n') goto done;
        line[length - 1] = 0;
        if (!strncmp(line, "source ", 7)) {
            if (state->source[0] || strlen(line + 7) >= sizeof state->source) goto done;
            strcpy(state->source, line + 7);
        } else if (!strncmp(line, "source-id ", 10)) {
            if (state->source_id[0] || strlen(line + 10) >= sizeof state->source_id) goto done;
            strcpy(state->source_id, line + 10);
        } else if (!strncmp(line, "base ", 5)) {
            if (state->base[0] || strlen(line + 5) >= sizeof state->base) goto done;
            strcpy(state->base, line + 5);
        } else if (!strncmp(line, "original-sha256 ", 16)) {
            if (state->original[0] || strlen(line + 16) >= sizeof state->original) goto done;
            strcpy(state->original, line + 16);
        } else if (!strncmp(line, "catalog-sha256 ", 15)) {
            if (state->catalog_hash[0] || strlen(line + 15) >= sizeof state->catalog_hash) goto done;
            strcpy(state->catalog_hash, line + 15);
        } else if (!strncmp(line, "public-key-sha256 ", 18)) {
            if (state->key_hash[0] || strlen(line + 18) >= sizeof state->key_hash) goto done;
            strcpy(state->key_hash, line + 18);
        } else if (!strcmp(line, "state complete")) complete = 1;
    }
    if (ferror(record) || !complete || !label(state->source) ||
        !digest_label(state->original) || !digest_label(state->catalog_hash) ||
        (state->key_hash[0] && !digest_label(state->key_hash)) ||
        (state->source_id[0] && !digest_label(state->source_id))) goto done;
    {
        char *url = holy_fetch_child_url(state->base, "fixture.xbps");
        if (!url) goto done;
        free(url);
    }
    fd = openat(dir, "repodata", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || !hash_fd(fd, actual) || strcmp(actual, state->original)) {
        if (fd >= 0) close(fd);
        goto done;
    }
    close(fd);
    fd = openat(dir, "catalog", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) goto done;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size > 32LL * 1024 * 1024 ||
        !hash_fd(fd, actual) || strcmp(actual, state->catalog_hash) ||
        lseek(fd, 0, SEEK_SET) < 0) { close(fd); goto done; }
    state->catalog = fdopen(fd, "r");
    if (!state->catalog) { close(fd); goto done; }
    if (!fgets(line, sizeof line, state->catalog) ||
        strcmp(line, "format holy-xbps-catalog-1\n")) goto done;
    ok = 1;
done:
    if (!ok && state->catalog) { fclose(state->catalog); state->catalog = NULL; }
    if (record) fclose(record);
    if (dir >= 0) close(dir);
    return ok;
}

int holy_xbps_source_catalog(const char *directory, const char *id,
                             const char *base, const char *key)
{
    struct catalog_state state;
    int ok;
    if (!directory || !id || !base || !key ||
        !open_catalog(directory, &state)) return 6;
    ok = !strcmp(state.source_id, id) &&
         !strcmp(state.base, base) &&
         (!key[0] || !strcmp(state.key_hash, key));
    fclose(state.catalog);
    return ok ? 0 : 6;
}

static int xbps_binding_name(const char *id, const char *arch, char name[130])
{
    unsigned char digest[32];
    unsigned length;
    size_t i;
    if (!digest_label(id) || !label(arch) ||
        EVP_Digest(arch, strlen(arch), digest, &length, EVP_sha256(), NULL) != 1 ||
        length != 32) return 0;
    memcpy(name, id, 64);
    name[64] = '.';
    for (i = 0; i < 32; ++i) snprintf(name + 65 + 2 * i, 3, "%02x", digest[i]);
    return 1;
}

static int xbps_binding_dir(int database, int create)
{
    struct stat st;
    int dir;
    if (create && mkdirat(database, "xbps-catalogs", 0700) && errno != EEXIST) return -1;
    dir = openat(database, "xbps-catalogs", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) return -1;
    if (fstat(dir, &st) || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 0022)) { close(dir); return -1; }
    return dir;
}

int holy_xbps_bind(const char *root, const char *source, const char *arch,
                   const char *catalog)
{
    char id[65], key[65], name[130], digest[65], temporary[43] = {0};
    char *base = NULL, *trust = NULL, *path = NULL, *root_path = NULL, *record = NULL;
    const char *stored_path, *path_key;
    unsigned long long generation;
    size_t size, used = 0;
    int database = -1, dir = -1, fd = -1, catalog_dir = -1, result;
    result = holy_source_xbps(root, source, id, &base, &trust, key);
    if (result) goto done;
    if (!xbps_binding_name(id, arch, name) || !catalog ||
        !(path = realpath(catalog, NULL))) { result = 2; goto done; }
    if (strchr(path, '\n') || strlen(path) > 1024 * 1024) { result = 2; goto done; }
    result = holy_xbps_source_catalog(path, id, base, key);
    if (result) goto done;
    root_path = realpath(root, NULL);
    if (!root_path) { result = 6; goto done; }
    path_key = "path";
    stored_path = path;
    if (strcmp(root_path, "/") && !strncmp(path, root_path, strlen(root_path)) &&
        path[strlen(root_path)] == '/') {
        path_key = "root-path";
        stored_path = path + strlen(root_path);
    }
    catalog_dir = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    fd = catalog_dir < 0 ? -1 : openat(catalog_dir, "conversion", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || !hash_fd(fd, digest)) { result = 6; goto done; }
    close(fd); fd = -1;
    size = strlen(path) + strlen(arch) + 256;
    record = malloc(size);
    if (!record) { result = 1; goto done; }
    snprintf(record, size, "format holy-xbps-binding-1\nsource-id %s\narch %s\nconversion-sha256 %s\n%s %s\n",
             id, arch, digest, path_key, stored_path);
    size = strlen(record);
    database = holy_state_lock(root, 1, &generation, &result);
    if (database < 0) goto done;
    dir = xbps_binding_dir(database, 1);
    if (dir < 0 || (fd = holy_temporary_at(dir, temporary)) < 0) { result = 1; goto done; }
    while (used < size) {
        ssize_t written = write(fd, record + used, size - used);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) { result = 1; goto done; }
        used += (size_t)written;
    }
    if (fsync(fd) || renameat(dir, temporary, dir, name) || fsync(dir)) {
        result = 1; goto done;
    }
    result = 0;
done:
    if (fd >= 0) close(fd);
    if (dir >= 0) {
        if (temporary[0]) unlinkat(dir, temporary, 0);
        close(dir);
    }
    if (catalog_dir >= 0) close(catalog_dir);
    if (database >= 0) close(database);
    free(base); free(trust); free(path); free(root_path); free(record);
    return result;
}

int holy_xbps_catalog_path(const char *root, const char *source,
                           const char *arch, char **catalog)
{
    struct stat st;
    char id[65], key[65], name[130], saved_id[65], saved_arch[256];
    char saved_digest[65], actual[65], *base = NULL, *trust = NULL;
    char *line = NULL, *path = NULL, *root_path = NULL, *candidate = NULL;
    size_t capacity = 0;
    unsigned long long generation;
    FILE *record = NULL;
    int database = -1, dir = -1, fd = -1, catalog_dir = -1, result;
    *catalog = NULL;
    result = holy_source_xbps(root, source, id, &base, &trust, key);
    if (result) goto done;
    if (!xbps_binding_name(id, arch, name)) { result = 2; goto done; }
    database = holy_state_lock(root, 0, &generation, &result);
    if (database < 0) goto done;
    dir = xbps_binding_dir(database, 0);
    fd = dir < 0 ? -1 : openat(dir, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size <= 0 || st.st_size > 1024 * 1024 + 512 ||
        st.st_uid != geteuid() || (st.st_mode & 0022)) { result = 6; goto done; }
    record = fdopen(fd, "r");
    if (!record) { result = 1; goto done; }
    fd = -1;
    if (getline(&line, &capacity, record) < 0 ||
        strcmp(line, "format holy-xbps-binding-1\n") ||
        getline(&line, &capacity, record) < 0 ||
        sscanf(line, "source-id %64s\n", saved_id) != 1 || strcmp(saved_id, id) ||
        getline(&line, &capacity, record) < 0 ||
        sscanf(line, "arch %255s\n", saved_arch) != 1 || strcmp(saved_arch, arch) ||
        getline(&line, &capacity, record) < 0 ||
        sscanf(line, "conversion-sha256 %64s\n", saved_digest) != 1 ||
        !digest_label(saved_digest) || getline(&line, &capacity, record) < 0 ||
        (strncmp(line, "path ", 5) && strncmp(line, "root-path ", 10)) ||
        strlen(line) > 1024 * 1024 + 12 ||
        line[strlen(line) - 1] != '\n' ||
        fgetc(record) != EOF || ferror(record)) { result = 6; goto done; }
    line[strlen(line) - 1] = 0;
    if (!strncmp(line, "root-path ", 10)) {
        root_path = realpath(root, NULL);
        if (!root_path || line[10] != '/' ||
            strlen(root_path) > (size_t)-1 - strlen(line + 10) - 1) {
            result = 6; goto done;
        }
        candidate = malloc(strlen(root_path) + strlen(line + 10) + 1);
        if (!candidate) { result = 1; goto done; }
        if (!strcmp(root_path, "/")) strcpy(candidate, line + 10);
        else sprintf(candidate, "%s%s", root_path, line + 10);
    } else candidate = strdup(line + 5);
    if (!candidate) { result = 1; goto done; }
    path = realpath(candidate, NULL);
    if (!path || strcmp(path, candidate)) { result = 6; goto done; }
    catalog_dir = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    fd = catalog_dir < 0 ? -1 : openat(catalog_dir, "conversion", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || !hash_fd(fd, actual) || strcmp(actual, saved_digest)) {
        result = 6; goto done;
    }
    result = holy_xbps_source_catalog(path, id, base, key);
    if (!result) { *catalog = path; path = NULL; }
done:
    if (fd >= 0) close(fd);
    if (record) fclose(record);
    if (catalog_dir >= 0) close(catalog_dir);
    if (dir >= 0) close(dir);
    if (database >= 0) close(database);
    free(base); free(trust); free(line); free(path); free(root_path); free(candidate);
    return result;
}

static int next_row(FILE *catalog, struct xbps_row *row)
{
    char line[1024], name[256], version[256], arch[256], hash[65];
    unsigned long long size;
    int end = 0;
    if (!fgets(line, sizeof line, catalog)) return ferror(catalog) ? -1 : 0;
    if (sscanf(line, "package %255s %255s %255s %64s %llu%n",
               name, version, arch, hash, &size, &end) != 5 ||
        !end || line[end] != '\n' || line[end + 1] ||
        !label(name) || !label(version) || !label(arch) ||
        !digest_label(hash) || !size || size > 1024ULL * 1024 * 1024 * 1024) return -1;
    row->name = strdup(name); row->version = strdup(version);
    row->arch = strdup(arch); row->hash = strdup(hash); row->size = size;
    return row->name && row->version && row->arch && row->hash ? 1 : -1;
}

int holy_xbps_query(const char *directory, const char *query, int info)
{
    struct catalog_state state;
    struct xbps_row row = {0};
    size_t matches = 0;
    int status, result = 2;
    if (!directory || !query || !*query || !open_catalog(directory, &state)) return 6;
    while ((status = next_row(state.catalog, &row)) > 0) {
        if ((info && !strcmp(query, row.name)) || (!info && strstr(row.name, query))) {
            ++matches;
            if (info) printf("package %s\nversion %s\narch %s\nsha256 %s\nsize %llu\n",
                             row.name, row.version, row.arch, row.hash, row.size);
            else printf("%s %s %s\n", row.name, row.version, row.arch);
        }
        free(row.name); free(row.version); free(row.arch); free(row.hash);
        memset(&row, 0, sizeof row);
    }
    result = status < 0 ? 2 : !matches ? 4 : info && matches > 1 ? 3 : 0;
    free(row.name); free(row.version); free(row.arch); free(row.hash);
    fclose(state.catalog);
    return result;
}

int holy_xbps_fetch(const char *directory, const char *name, const char *version,
                    const char *arch, const char *output, const char *ca_file,
                    const char *public_key)
{
    struct catalog_state state;
    struct xbps_row row = {0}, selected = {0};
    EVP_PKEY *key = NULL;
    char digest[65] = {0}, signature_digest[65] = {0}, key_hash[65] = {0};
    char *filename = NULL, *url = NULL, *download = NULL;
    char *signature_name = NULL, *signature_url = NULL, *signature_path = NULL;
    FILE *record = NULL;
    struct stat st;
    size_t matches = 0, length;
    int status, result = 1, dir = -1;
    if (!directory || !label(name) || !label(version) || !label(arch) || !output ||
        !open_catalog(directory, &state)) return 6;
    while ((status = next_row(state.catalog, &row)) > 0) {
        if (!strcmp(row.name, name) && !strcmp(row.version, version) && !strcmp(row.arch, arch)) {
            if (!matches) { selected = row; memset(&row, 0, sizeof row); }
            ++matches;
        }
        free(row.name); free(row.version); free(row.arch); free(row.hash);
        memset(&row, 0, sizeof row);
        if (matches > 1) break;
    }
    fclose(state.catalog);
    if (status < 0) { result = 2; goto done; }
    if (!matches) { result = 4; goto done; }
    if (matches > 1) { result = 3; goto done; }
    if (public_key) {
        key = public_key_file(public_key);
        if (!key || !key_digest(key, key_hash) ||
            !state.key_hash[0] || strcmp(key_hash, state.key_hash)) {
            result = 4; goto done;
        }
    }
    if (selected.size > 1024ULL * 1024 * 1024) { result = 6; goto done; }
    length = strlen(name) + strlen(version) + strlen(arch) + 8;
    filename = malloc(length);
    if (!filename) goto done;
    snprintf(filename, length, "%s-%s.%s.xbps", name, version, arch);
    url = holy_fetch_child_url(state.base, filename);
    if (!url) { result = 2; goto done; }
    if (mkdir(output, 0700)) goto done;
    dir = open(output, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || fstat(dir, &st) || st.st_uid != geteuid() ||
        (st.st_mode & 0777) != 0700) goto done;
    result = holy_fetch_https_foreign_limited(url, output, ca_file, digest, selected.size);
    if (result) goto done;
    if (strcmp(digest, selected.hash)) { result = 4; goto done; }
    download = malloc(strlen(output) + 66);
    if (!download) { result = 1; goto done; }
    sprintf(download, "%s/%s", output, digest);
    if (stat(download, &st) || !S_ISREG(st.st_mode) ||
        (unsigned long long)st.st_size != selected.size ||
        !package_identity(download, name, version, arch)) {
        result = 4; goto done;
    }
    if (key) {
        signature_name = malloc(strlen(filename) + 6);
        signature_path = malloc(strlen(output) + 66);
        if (!signature_name || !signature_path) { result = 1; goto done; }
        sprintf(signature_name, "%s.sig2", filename);
        signature_url = holy_fetch_child_url(state.base, signature_name);
        if (!signature_url) { result = 2; goto done; }
        result = holy_fetch_https_foreign_limited(signature_url, output, ca_file,
                                                  signature_digest, 16384);
        if (result) goto done;
        sprintf(signature_path, "%s/%s", output, signature_digest);
        if (!verify_signature(download, signature_path, key)) {
            result = 4; goto done;
        }
    }
    {
        int fd = openat(dir, "conversion", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) { result = 1; goto done; }
        record = fdopen(fd, "w");
        if (!record) { close(fd); result = 1; goto done; }
    }
    fprintf(record, "format holy-xbps-fetch-record-1\nsource %s\nindex-sha256 %s\npackage %s\nversion %s\narch %s\nsha256 %s\nsize %llu\nverification %s\n",
            state.source, state.original, name, version, arch, digest, selected.size,
            key ? "rsa-sha256" : "hash-pinned");
    if (key) fprintf(record, "public-key-sha256 %s\nsignature-sha256 %s\n",
                     key_hash, signature_digest);
    fputs("state complete\n", record);
    if (ferror(record) || fflush(record) || fsync(fileno(record))) { result = 1; goto done; }
    if (fclose(record)) { record = NULL; result = 1; goto done; }
    record = NULL;
    if (fsync(dir)) { result = 1; goto done; }
    printf("fetched %s sha256 %s\n", filename, digest);
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: XBPS fetch incomplete (status %d)\n", result);
    if (record) fclose(record);
    if (dir >= 0) close(dir);
    free(selected.name); free(selected.version); free(selected.arch); free(selected.hash);
    EVP_PKEY_free(key);
    free(filename); free(url); free(download);
    free(signature_name); free(signature_url); free(signature_path);
    return result;
}

int holy_xbps_sync(const char *base, const char *arch, const char *source,
                   const char *output, const char *expected, const char *ca_file,
                   const char *public_key, const char *source_id)
{
    char template[] = "/tmp/holy-xbps-sync-XXXXXX";
    char *url = NULL, *path = NULL, *filename = NULL;
    int result;
    if (!base || !arch || !label(arch) || !source || !label(source) ||
        !strcmp(source, "local") || !output || !digest_label(expected)) return 2;
    filename = malloc(strlen(arch) + 10);
    if (!filename) return 1;
    sprintf(filename, "%s-repodata", arch);
    url = holy_fetch_child_url(base, filename);
    free(filename);
    if (!url) return 2;
    if (!mkdtemp(template)) { free(url); return 1; }
    result = holy_fetch_https_data(url, expected, template, ca_file);
    free(url);
    if (!result) {
        path = malloc(strlen(template) + 66);
        if (!path) result = 1;
        else {
            sprintf(path, "%s/%s", template, expected);
            result = holy_xbps_index(path, source, base, output, expected, public_key, source_id);
        }
    }
    if (path) { unlink(path); free(path); }
    rmdir(template);
    return result;
}
