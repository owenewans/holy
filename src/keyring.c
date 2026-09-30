/* named public keys in the target root. a source or a verification command takes a
   key file path, and repeating that path in every source is how a wrong key gets
   recorded twice. an enrolled name stores the key bytes with the digest recorded
   when it was enrolled, so one key file can back several sources and a key changed
   afterwards is refused with a named reason instead of being trusted. the store
   holds public material only, and var/lib/holypkg is reserved from payload
   ownership, so no package can place a file beside an enrolled key. */

#define _POSIX_C_SOURCE 200809L
#include "keyring.h"
#include "state.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define KEY_BYTES (1024 * 1024)

static const char keys_path[] = "var/lib/holypkg/keys";

int holy_keyring_name(const char *name)
{
    size_t i, length;
    if (!name) return 0;
    length = strlen(name);
    if (!length || length > 64 || !strcmp(name, ".") || !strcmp(name, "..") ||
        name[0] == '-') return 0;
    for (i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')) return 0;
    }
    return 1;
}

static int name_path(const char *name, const char *suffix, char *out, size_t size)
{
    size_t length = strlen(name), tail = suffix ? strlen(suffix) : 0;
    if (length + tail + 1 > size) return 0;
    memcpy(out, name, length);
    if (tail) memcpy(out + length, suffix, tail);
    out[length + tail] = 0;
    return 1;
}

static int read_bytes(const char *path, unsigned char **out, size_t *size)
{
    struct stat st;
    unsigned char *data = NULL;
    size_t used = 0;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC), ok = 0;
    if (fd < 0) return 0;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        st.st_size > KEY_BYTES || !(data = malloc((size_t)st.st_size + 1))) goto done;
    while (used < (size_t)st.st_size) {
        ssize_t got = read(fd, data + used, (size_t)st.st_size - used);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) goto done;
        used += (size_t)got;
    }
    if (memchr(data, 0, used)) goto done;
    data[used] = 0;
    *out = data;
    *size = used;
    ok = 1;
done:
    if (!ok) free(data);
    close(fd);
    return ok;
}

static int read_bytes_at(int dir, const char *path, unsigned char **out, size_t *size)
{
    struct stat st;
    unsigned char *data = NULL;
    size_t used = 0;
    int fd, ok = 0;
    if ((fd = openat(dir, path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)) < 0) return 0;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        st.st_size > KEY_BYTES || !(data = malloc((size_t)st.st_size + 1))) goto done;
    while (used < (size_t)st.st_size) {
        ssize_t got = read(fd, data + used, (size_t)st.st_size - used);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) goto done;
        used += (size_t)got;
    }
    if (memchr(data, 0, used)) goto done;
    data[used] = 0;
    *out = data;
    *size = used;
    ok = 1;
done:
    if (!ok) free(data);
    close(fd);
    return ok;
}

static int digest_of(const void *data, size_t size, char out[65])
{
    static const char hex[] = "0123456789abcdef";
    unsigned char bytes[32];
    unsigned int hashed = 0;
    size_t i;
    if (EVP_Digest(data, size, bytes, &hashed, EVP_sha256(), NULL) != 1 || hashed != 32) return 0;
    for (i = 0; i < 32; ++i) {
        out[i * 2] = hex[bytes[i] >> 4];
        out[i * 2 + 1] = hex[bytes[i] & 15];
    }
    out[64] = 0;
    return 1;
}

/* a PEM or DER public key, or an armored block, since the apk, apt and xbps
   families read keyrings the last two OpenSSL parsers cannot read */
static int armored(const unsigned char *data, size_t size)
{
    size_t i;
    if (size < 12 || memcmp(data, "-----BEGIN ", 11)) return 0;
    for (i = 11; i + 10 <= size; ++i)
        if (!memcmp(data + i, "\n-----END ", 10)) return 1;
    return 0;
}

static int is_key(const unsigned char *data, size_t size)
{
    BIO *bio = BIO_new_mem_buf(data, (int)size);
    EVP_PKEY *key = NULL;
    int ok = 0;
    if (bio && (key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL))) ok = 1;
    if (bio) BIO_free(bio);
    if (!ok && (bio = BIO_new_mem_buf(data, (int)size)) != NULL) {
        if ((key = d2i_PUBKEY_bio(bio, NULL))) ok = 1;
        BIO_free(bio);
    }
    if (key) EVP_PKEY_free(key);
    return ok || armored(data, size);
}

struct key_record {
    char digest[65];
    size_t bytes;
    int changed;
};

static int read_record(int keys, const char *name, struct key_record *record)
{
    char path[128], stored[80];
    unsigned char *data = NULL, *side = NULL;
    size_t size = 0, side_size = 0;
    memset(record, 0, sizeof *record);
    if (!name_path(name, NULL, path, sizeof path) ||
        !read_bytes_at(keys, path, &data, &size)) return 0;
    record->bytes = size;
    if (!digest_of(data, size, record->digest)) record->digest[0] = 0;
    free(data);
    if (!name_path(name, ".digest", path, sizeof path) ||
        !read_bytes_at(keys, path, &side, &side_size)) {
        record->changed = 1;
        return 1;
    }
    memcpy(stored, side, side_size < sizeof stored ? side_size : sizeof stored - 1);
    stored[side_size < sizeof stored ? side_size : sizeof stored - 1] = 0;
    free(side);
    stored[strcspn(stored, "\n\r \t")] = 0;
    if (strcmp(stored, record->digest)) record->changed = 1;
    return 1;
}

static int write_file(int keys, const char *name, const char *suffix,
                      const void *data, size_t size)
{
    char path[128], temporary[144];
    size_t written = 0;
    int fd, ok = 0;
    if (!name_path(name, suffix, path, sizeof path) ||
        !name_path(name, ".tmp", temporary, sizeof temporary)) return 0;
    if ((fd = openat(keys, temporary, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
                     0644)) < 0) return 0;
    while (written < size) {
        ssize_t got = write(fd, (const char *)data + written, size - written);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) goto done;
        written += (size_t)got;
    }
    if (fsync(fd) || close(fd)) { fd = -1; goto done; }
    fd = -1;
    if (renameat(keys, temporary, keys, path)) goto done;
    ok = 1;
done:
    if (fd >= 0) close(fd);
    if (!ok) unlinkat(keys, temporary, 0);
    return ok;
}

/* the locked database directory, so an enrollment is serialized with the
   transactions that read it */
static int open_keys(const char *root_path, int exclusive, int *status)
{
    int dir, keys;
    unsigned long long generation = 0;
    if (!root_path || !*root_path) { if (status) *status = 2; return -1; }
    dir = holy_state_lock(root_path, exclusive, &generation, status);
    if (dir < 0) return -1;
    keys = openat(dir, "keys", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (keys < 0) {
        fprintf(stderr, "holypkg: keyring unavailable: %s\n",
                errno == ENOENT ? "no-enrolled-keys" : "unreadable-key-directory");
        if (status) *status = 6;
        close(dir);
        return -1;
    }
    close(dir);
    return keys;
}

int holy_keyring_path(const char *root_path, const char *name, char *out, size_t size)
{
    int status = 0, keys, result = 0;
    struct key_record record;
    size_t root_length;
    if (!holy_keyring_name(name)) return -1;
    if (!root_path || !*root_path) return 0;
    keys = open_keys(root_path, 0, &status);
    if (keys < 0) return 0;
    if (read_record(keys, name, &record) && record.changed) {
        close(keys);
        return -2;
    }
    if (read_record(keys, name, &record) && !record.changed) {
        size_t tail = strlen(name);
        root_length = strlen(root_path);
        while (root_length > 1 && root_path[root_length - 1] == '/') --root_length;
        if (root_length + 1 + sizeof keys_path + tail + 1 <= size) {
            memcpy(out, root_path, root_length);
            out[root_length] = '/';
            memcpy(out + root_length + 1, keys_path, sizeof keys_path - 1);
            out[root_length + sizeof keys_path] = '/';
            memcpy(out + root_length + sizeof keys_path + 1, name, tail + 1);
            result = 1;
        }
    }
    close(keys);
    return result;
}

int holy_keyring_add(const char *root_path, const char *name, const char *file,
                     int replace)
{
    unsigned char *data = NULL;
    size_t size = 0;
    struct key_record record;
    char digest[65];
    int status = 0, keys, existing;
    if (!holy_keyring_name(name) || !file || !*file) return 2;
    if (!read_bytes(file, &data, &size) || !size) {
        fprintf(stderr, "holypkg: public key file unreadable: %s\n", file);
        return 4;
    }
    if (!is_key(data, size)) {
        fprintf(stderr, "holypkg: not a public key: %s\n", file);
        free(data);
        return 4;
    }
    if (!digest_of(data, size, digest)) { free(data); return 1; }
    keys = open_keys(root_path, 1, &status);
    if (keys < 0) { free(data); return status ? status : 6; }
    existing = read_record(keys, name, &record);
    if (existing && !record.changed && !strcmp(record.digest, digest)) {
        printf("key %s sha256 %s bytes %zu enrolled\n", name, digest, size);
        close(keys); free(data);
        return 0;
    }
    if (existing && !record.changed && !replace) {
        fprintf(stderr, "holypkg: decision-required key=%s recorded %s offered %s; "
                "--replace states the change\n", name, record.digest, digest);
        close(keys); free(data);
        return 3;
    }
    if (!write_file(keys, name, NULL, data, size) ||
        !write_file(keys, name, ".digest", digest, 64) || fsync(keys)) {
        unlinkat(keys, name, 0);
        fprintf(stderr, "holypkg: key not enrolled\n");
        close(keys); free(data);
        return 1;
    }
    printf("key %s sha256 %s bytes %zu %senrolled\n", name, digest, size,
           existing ? "replaced " : "");
    close(keys);
    free(data);
    return 0;
}

int holy_keyring_list(const char *root_path, int json)
{
    DIR *entries = NULL;
    struct dirent *entry;
    unsigned long long generation = 0;
    int status = 0, dir, keys, count = 0, ok = 0;
    dir = holy_state_lock(root_path, 0, &generation, &status);
    if (dir < 0) {
        fprintf(stderr, "holypkg: keyring unavailable: %s\n",
                status == 5 ? "incomplete-transaction" :
                status == 2 ? "invalid-root" : "no-database");
        return status == 5 ? 5 : 6;
    }
    if ((keys = openat(dir, "keys", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)) < 0) {
        fprintf(stderr, "holypkg: keyring unavailable: %s\n",
                errno == ENOENT ? "no-enrolled-keys" : "unreadable-key-directory");
        close(dir);
        return 6;
    }
    {
        int copy = dup(keys);
        if (copy >= 0 && (entries = fdopendir(copy))) ok = 1;
        else if (copy >= 0) close(copy);
    }
    if (entries) {
        errno = 0;
        while ((entry = readdir(entries))) {
            struct key_record record;
            const char *suffix = strrchr(entry->d_name, '.');
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
            if (suffix && !strcmp(suffix, ".digest")) continue;
            if (!holy_keyring_name(entry->d_name) ||
                !read_record(keys, entry->d_name, &record)) { errno = 0; continue; }
            if (json)
                printf("{\"schema\":\"holy-keyring-1\",\"type\":\"key\",\"name\":\"%s\","
                       "\"sha256\":\"%s\",\"bytes\":%zu,\"state\":\"%s\"}\n",
                       entry->d_name, record.digest[0] ? record.digest : "-",
                       record.bytes, record.changed ? "changed" : "intact");
            else
                printf("key %s sha256 %s bytes %zu %s\n", entry->d_name,
                       record.digest[0] ? record.digest : "-", record.bytes,
                       record.changed ? "changed" : "intact");
            ++count;
            errno = 0;
        }
        ok = ok && errno == 0;
        closedir(entries);
    }
    if (json)
        printf("{\"schema\":\"holy-keyring-1\",\"type\":\"summary\",\"generation\":%llu,"
               "\"keys\":%d}\n", generation, count);
    else
        printf("generation %llu keys %d read-only\n", generation, count);
    close(keys);
    close(dir);
    return ok ? 0 : 1;
}

int holy_keyring_show(const char *root_path, const char *name)
{
    int status = 0, keys;
    struct key_record record;
    if (!holy_keyring_name(name)) return 2;
    keys = open_keys(root_path, 0, &status);
    if (keys < 0) return status ? status : 6;
    if (!read_record(keys, name, &record)) {
        fprintf(stderr, "holypkg: no enrolled key: %s\n", name);
        close(keys);
        return 6;
    }
    close(keys);
    if (record.changed) {
        fprintf(stderr, "holypkg: enrolled key changed: %s recorded %s\n", name,
                record.digest[0] ? record.digest : "-");
        return 4;
    }
    printf("key %s sha256 %s bytes %zu intact\n", name, record.digest, record.bytes);
    return 0;
}

int holy_keyring_remove(const char *root_path, const char *name, int confirmed)
{
    char path[128], temporary[144];
    int status = 0, keys, removed = 0;
    struct key_record record;
    if (!holy_keyring_name(name)) return 2;
    keys = open_keys(root_path, 1, &status);
    if (keys < 0) return status ? status : 6;
    if (!read_record(keys, name, &record)) {
        fprintf(stderr, "holypkg: no enrolled key: %s\n", name);
        close(keys);
        return 6;
    }
    if (record.changed && !confirmed) {
        fprintf(stderr, "holypkg: decision-required changed key=%s; --yes removes it\n", name);
        close(keys);
        return 3;
    }
    if (!record.changed && !confirmed) {
        fprintf(stderr, "holypkg: decision-required remove key=%s; --yes removes it\n", name);
        close(keys);
        return 3;
    }
    if (!name_path(name, NULL, path, sizeof path) ||
        !name_path(name, ".digest", temporary, sizeof temporary) ||
        unlinkat(keys, path, 0) || unlinkat(keys, temporary, 0)) {
        fprintf(stderr, "holypkg: key not removed\n");
        close(keys);
        return 1;
    }
    removed = 1;
    if (name_path(name, ".tmp", path, sizeof path)) unlinkat(keys, path, 0);
    if (fsync(keys) || !removed) {
        fprintf(stderr, "holypkg: key not removed\n");
        close(keys);
        return 1;
    }
    printf("removed key %s\n", name);
    close(keys);
    return 0;
}
