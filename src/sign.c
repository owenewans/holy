#define _POSIX_C_SOURCE 200809L
#include "sign.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int names(const char *digest, char index[71], char signature[75])
{
    size_t i;
    if (!digest || strlen(digest) != 64) return 0;
    for (i = 0; i < 64; ++i)
        if (!((digest[i] >= '0' && digest[i] <= '9') ||
              (digest[i] >= 'a' && digest[i] <= 'f'))) return 0;
    snprintf(index, 71, "index.%s", digest);
    snprintf(signature, 75, "signature.%s", digest);
    return 1;
}

static unsigned char *index_data(int dir, const char *digest, size_t *size)
{
    char index[71], signature[75], actual[65];
    struct stat st;
    unsigned char *data = NULL, hash[32];
    unsigned int length;
    size_t i;
    int fd = -1;
    static const char hex[] = "0123456789abcdef";
    if (!names(digest, index, signature)) return NULL;
    fd = openat(dir, index, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size < 0 || st.st_size > 16 * 1024 * 1024) goto done;
    *size = (size_t)st.st_size;
    data = malloc(*size ? *size : 1);
    if (!data) goto done;
    for (i = 0; i < *size;) {
        ssize_t got = read(fd, data + i, *size - i);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) goto fail;
        i += (size_t)got;
    }
    if (read(fd, hash, 1) != 0 || fstat(fd, &st) || st.st_size != (off_t)*size ||
        EVP_Digest(data, *size, hash, &length, EVP_sha256(), NULL) != 1 || length != 32)
        goto fail;
    for (i = 0; i < 32; ++i) {
        actual[i * 2] = hex[hash[i] >> 4];
        actual[i * 2 + 1] = hex[hash[i] & 15];
    }
    actual[64] = 0;
    if (strcmp(actual, digest)) goto fail;
    close(fd);
    return data;
fail:
    free(data);
    data = NULL;
done:
    if (fd >= 0) close(fd);
    return data;
}

static int signature_data(int dir, const char *name, unsigned char signature[64])
{
    struct stat st;
    int fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    size_t used = 0;
    if (fd < 0) return 0;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size != 64) goto fail;
    while (used < 64) {
        ssize_t got = read(fd, signature + used, 64 - used);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) goto fail;
        used += (size_t)got;
    }
    if (fstat(fd, &st) || st.st_size != 64) goto fail;
    close(fd);
    return 1;
fail:
    close(fd);
    return 0;
}

static int verify_data(EVP_PKEY *key, const unsigned char *data, size_t size,
                       const unsigned char signature[64])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1 &&
             EVP_DigestVerify(ctx, signature, 64, data, size) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}

static EVP_PKEY *read_public_key(const char *spec)
{
    EVP_PKEY *key = NULL;
    FILE *stream;
    unsigned char raw[32];
    size_t i;
    if (!strncmp(spec, "raw:", 4)) {
        const char *hex = spec + 4;
        if (strlen(hex) != 64) return NULL;
        for (i = 0; i < sizeof raw; ++i) {
            unsigned a = (unsigned char)hex[i * 2], b = (unsigned char)hex[i * 2 + 1];
            a = a >= '0' && a <= '9' ? a - '0' :
                a >= 'a' && a <= 'f' ? a - 'a' + 10 : 256;
            b = b >= '0' && b <= '9' ? b - '0' :
                b >= 'a' && b <= 'f' ? b - 'a' + 10 : 256;
            if (a > 15 || b > 15) return NULL;
            raw[i] = (unsigned char)(a * 16 + b);
        }
        return EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, raw, sizeof raw);
    }
    stream = fopen(spec, "r");
    if (!stream) return NULL;
    key = PEM_read_PUBKEY(stream, NULL, NULL, NULL);
    fclose(stream);
    return key;
}

int holy_public_key_hex(const char *path, char output[65])
{
    EVP_PKEY *key = path ? read_public_key(path) : NULL;
    unsigned char raw[32];
    static const char hex[] = "0123456789abcdef";
    size_t size = sizeof raw, i;
    int ok = key && EVP_PKEY_base_id(key) == EVP_PKEY_ED25519 &&
             EVP_PKEY_get_raw_public_key(key, raw, &size) == 1 && size == 32;
    if (ok) {
        for (i = 0; i < 32; ++i) {
            output[i * 2] = hex[raw[i] >> 4];
            output[i * 2 + 1] = hex[raw[i] & 15];
        }
        output[64] = 0;
    }
    EVP_PKEY_free(key);
    return ok;
}

int holy_sign_index(int dir, const char *digest, const char *private_key)
{
    char index[71], name[75];
    unsigned char signature[64], existing[64], *data = NULL;
    size_t size = 0, length = sizeof signature, written = 0;
    FILE *stream = NULL;
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *ctx = NULL;
    int fd = -1, ok = 0;
    if (!names(digest, index, name) ||
        !(data = index_data(dir, digest, &size)) ||
        !(stream = fopen(private_key, "r")) ||
        !(key = PEM_read_PrivateKey(stream, NULL, NULL, NULL)) ||
        EVP_PKEY_base_id(key) != EVP_PKEY_ED25519 ||
        !(ctx = EVP_MD_CTX_new()) ||
        EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) != 1 ||
        EVP_DigestSign(ctx, signature, &length, data, size) != 1 || length != 64)
        goto done;
    fd = openat(dir, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0) {
        if (errno == EEXIST && signature_data(dir, name, existing) &&
            verify_data(key, data, size, existing)) ok = 1;
        goto done;
    }
    while (written < length) {
        ssize_t sent = write(fd, signature + written, length - written);
        if (sent < 0 && errno == EINTR) continue;
        if (sent <= 0) goto done;
        written += (size_t)sent;
    }
    if (!fsync(fd) && !close(fd)) { fd = -1; ok = !fsync(dir); }
done:
    if (fd >= 0) { close(fd); unlinkat(dir, name, 0); }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    if (stream) fclose(stream);
    free(data);
    return ok;
}

int holy_verify_index_bytes(int dir, const char *digest, const char *public_key,
                            const unsigned char signature[64], char key_hash[65])
{
    char index[71], name[75];
    unsigned char *data = NULL, raw[32], hash[32];
    static const char hex[] = "0123456789abcdef";
    size_t size = 0;
    size_t raw_size = sizeof raw, i;
    unsigned int hash_size;
    EVP_PKEY *key = NULL;
    int ok = 0;
    if (!names(digest, index, name) ||
        !(data = index_data(dir, digest, &size)) ||
        !(key = read_public_key(public_key)) ||
        EVP_PKEY_base_id(key) != EVP_PKEY_ED25519) goto done;
    ok = verify_data(key, data, size, signature);
    if (ok && key_hash) {
        ok = EVP_PKEY_get_raw_public_key(key, raw, &raw_size) == 1 && raw_size == 32 &&
             EVP_Digest(raw, raw_size, hash, &hash_size, EVP_sha256(), NULL) == 1 &&
             hash_size == 32;
        if (ok) {
            for (i = 0; i < 32; ++i) {
                key_hash[i * 2] = hex[hash[i] >> 4];
                key_hash[i * 2 + 1] = hex[hash[i] & 15];
            }
            key_hash[64] = 0;
        }
    }
done:
    EVP_PKEY_free(key);
    free(data);
    return ok;
}

int holy_verify_index_keyhash(int dir, const char *digest, const char *public_key,
                              char key_hash[65])
{
    char index[71], name[75];
    unsigned char signature[64];
    if (!names(digest, index, name) || !signature_data(dir, name, signature)) return 0;
    return holy_verify_index_bytes(dir, digest, public_key, signature, key_hash);
}

int holy_verify_index(int dir, const char *digest, const char *public_key)
{
    return holy_verify_index_keyhash(dir, digest, public_key, NULL);
}
