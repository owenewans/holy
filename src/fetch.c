#define _POSIX_C_SOURCE 200809L
#include "fetch.h"
#include "stage.h"
#include "verify.h"

#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static int hash_fd(int fd, unsigned char digest[32])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char buffer[65536];
    unsigned int n;
    ssize_t got;
    int ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    while (ok && (got = read(fd, buffer, sizeof buffer)) != 0) {
        if (got < 0) {
            if (errno == EINTR) continue;
            ok = 0;
            break;
        }
        ok = EVP_DigestUpdate(ctx, buffer, (size_t)got) == 1;
    }
    if (ok) ok = EVP_DigestFinal_ex(ctx, digest, &n) == 1 && n == 32;
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int copy_and_hash(int source, int target, unsigned char digest[32])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char buffer[65536];
    unsigned int n;
    ssize_t got;
    int ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    while (ok && (got = read(source, buffer, sizeof buffer)) != 0) {
        size_t written = 0;
        if (got < 0) {
            if (errno == EINTR) continue;
            ok = 0;
            break;
        }
        if (EVP_DigestUpdate(ctx, buffer, (size_t)got) != 1) { ok = 0; break; }
        while (written < (size_t)got) {
            ssize_t sent = write(target, buffer + written, (size_t)got - written);
            if (sent < 0 && errno == EINTR) continue;
            if (sent <= 0) { ok = 0; break; }
            written += (size_t)sent;
        }
    }
    if (ok) ok = EVP_DigestFinal_ex(ctx, digest, &n) == 1 && n == 32;
    EVP_MD_CTX_free(ctx);
    return ok;
}

int holy_fetch_at(const char *source, int dir, const char *expected,
                  char name[70])
{
    int input = -1, temp = -1, existing = -1, ok = 0;
    unsigned char digest[32], prior[32];
    char temporary[43];
    size_t i;
    struct stat st;

    input = open(source, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (input < 0 || fstat(input, &st) || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "holypkg: local input must be a regular file\n");
        goto done;
    }
    temp = holy_temporary_at(dir, temporary);
    if (temp < 0) { perror("holypkg: temporary file"); goto done; }
    if (!copy_and_hash(input, temp, digest) || fsync(temp)) {
        fprintf(stderr, "holypkg: local copy failed\n");
        goto done;
    }
    for (i = 0; i < 32; ++i) snprintf(name + i * 2, 3, "%02x", digest[i]);
    memcpy(name + 64, ".holy", 6);
    if (expected && (strlen(expected) != 64 || strncmp(name, expected, 64))) {
        fprintf(stderr, "holypkg: staged object differs from expected digest\n");
        goto done;
    }
    if (linkat(dir, temporary, dir, name, 0)) {
        if (errno != EEXIST) { perror("holypkg: link object"); goto done; }
        existing = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        if (existing < 0 || fstat(existing, &st) || !S_ISREG(st.st_mode) ||
            !hash_fd(existing, prior) || memcmp(prior, digest, sizeof digest)) {
            fprintf(stderr, "holypkg: existing object differs from its digest\n");
            goto done;
        }
    }
    if (fsync(dir)) { perror("holypkg: sync output"); goto done; }
    ok = 1;
done:
    if (existing >= 0) close(existing);
    if (temp >= 0) close(temp);
    if (temp >= 0) unlinkat(dir, temporary, 0);
    if (input >= 0) close(input);
    return ok;
}

int holy_fetch_local(const char *source, const char *output)
{
    char name[70];
    int dir = open(output, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int ok;
    if (dir < 0) { perror("holypkg: output directory"); return 0; }
    ok = holy_fetch_at(source, dir, NULL, name);
    close(dir);
    if (ok) printf("%s/%s\n", output, name);
    return ok;
}

struct download {
    int fd;
    EVP_MD_CTX *hash;
    curl_off_t bytes;
    curl_off_t limit;
};

static size_t receive(void *data, size_t size, size_t count, void *context)
{
    struct download *download = context;
    const unsigned char *cursor = data;
    size_t length, used = 0;
    if (size && count > (size_t)-1 / size) return 0;
    length = size * count;
    if (length > (size_t)(download->limit - download->bytes)) return 0;
    if (EVP_DigestUpdate(download->hash, data, length) != 1) return 0;
    while (used < length) {
        ssize_t sent = write(download->fd, cursor + used, length - used);
        if (sent < 0 && errno == EINTR) continue;
        if (sent <= 0) return 0;
        used += (size_t)sent;
    }
    download->bytes += (curl_off_t)length;
    return length;
}

static int secure_url(const char *url)
{
    CURLU *parts = curl_url();
    CURLUcode status;
    char *scheme = NULL, *user = NULL;
    int ok = 0;
    if (!parts) return 0;
    status = curl_url_set(parts, CURLUPART_URL, url, 0);
    if (status || curl_url_get(parts, CURLUPART_SCHEME, &scheme, 0) ||
        strcmp(scheme, "https")) goto done;
    if (curl_url_get(parts, CURLUPART_USER, &user, 0) == CURLUE_OK) goto done;
    if (curl_url_get(parts, CURLUPART_PASSWORD, &user, 0) == CURLUE_OK) goto done;
    ok = 1;
done:
    curl_free(user);
    curl_free(scheme);
    curl_url_cleanup(parts);
    return ok;
}

char *holy_fetch_child_url(const char *base, const char *filename)
{
    char *escaped, *url = NULL;
    size_t length = strlen(base), extra;
    if (!length || base[length - 1] != '/' || strchr(base, '?') || strchr(base, '#') ||
        !secure_url(base) || !*filename || strchr(filename, '/') ||
        !strcmp(filename, ".") || !strcmp(filename, "..")) return NULL;
    escaped = curl_easy_escape(NULL, filename, 0);
    if (!escaped) return NULL;
    extra = strlen(escaped);
    if (length < (size_t)-1 - extra && (url = malloc(length + extra + 1))) {
        memcpy(url, base, length);
        memcpy(url + length, escaped, extra + 1);
    }
    curl_free(escaped);
    return url;
}

static int https_object(const char *url, const char *expected,
                        const char *output, const char *ca_file, int native, int emit)
{
    struct download transfer = { .fd = -1, .hash = NULL, .bytes = 0,
                                .limit = native ? 1024 * 1024 * 1024 : 16 * 1024 * 1024 };
    CURL *curl = NULL;
    struct stat st;
    struct timespec started, now;
    unsigned char digest[32], prior[32];
    unsigned int digest_size;
    char name[70], temporary[43] = {0};
    char *path = NULL;
    size_t i, output_length;
    int dir = -1, previous = -1, result = 1, initialized = 0, redirect;
    if (!expected || strlen(expected) != 64) return 2;
    for (i = 0; i < 64; ++i)
        if (!((expected[i] >= '0' && expected[i] <= '9') ||
              (expected[i] >= 'a' && expected[i] <= 'f'))) return 2;
    if (!secure_url(url)) {
        fprintf(stderr, "holypkg: HTTPS URL must omit credentials\n");
        return 2;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &started) ||
        curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) return 1;
    initialized = 1;
    dir = open(output, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || fstat(dir, &st) || !S_ISDIR(st.st_mode) ||
        (st.st_uid != 0 && st.st_uid != geteuid()) || (st.st_mode & 0022)) goto done;
    transfer.fd = holy_temporary_at(dir, temporary);
    transfer.hash = EVP_MD_CTX_new();
    curl = curl_easy_init();
    if (transfer.fd < 0 || !transfer.hash || !curl ||
        EVP_DigestInit_ex(transfer.hash, EVP_sha256(), NULL) != 1) goto done;
    if (curl_easy_setopt(curl, CURLOPT_URL, url) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https") != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https") != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 20L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &transfer) != CURLE_OK ||
        (ca_file && curl_easy_setopt(curl, CURLOPT_CAINFO, ca_file) != CURLE_OK))
        goto done;
    result = 6;
    for (redirect = 0; ; ++redirect) {
        long response = 0;
        long remaining;
        char *target = NULL, *copy;
        if (clock_gettime(CLOCK_MONOTONIC, &now)) { result = 1; goto done; }
        if (now.tv_sec - started.tv_sec > 300) goto done;
        remaining = 300000L - (long)(now.tv_sec - started.tv_sec) * 1000L -
                    (long)(now.tv_nsec - started.tv_nsec) / 1000000L;
        if (remaining <= 0 ||
            curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, remaining) != CURLE_OK)
            goto done;
        if (curl_easy_perform(curl) != CURLE_OK ||
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response) != CURLE_OK)
            goto done;
        if (response >= 200 && response < 300) break;
        if (response < 300 || response >= 400 || redirect == 5 ||
            curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &target) != CURLE_OK ||
            !target || !secure_url(target)) goto done;
        copy = strdup(target);
        if (!copy) { result = 1; goto done; }
        if (curl_easy_setopt(curl, CURLOPT_URL, copy) != CURLE_OK ||
            ftruncate(transfer.fd, 0) || lseek(transfer.fd, 0, SEEK_SET) < 0 ||
            EVP_DigestInit_ex(transfer.hash, EVP_sha256(), NULL) != 1) {
            free(copy);
            goto done;
        }
        free(copy);
    }
    if (EVP_DigestFinal_ex(transfer.hash, digest, &digest_size) != 1 ||
        digest_size != 32 || fsync(transfer.fd)) goto done;
    for (i = 0; i < 32; ++i) snprintf(name + i * 2, 3, "%02x", digest[i]);
    if (native) memcpy(name + 64, ".holy", 6);
    else name[64] = 0;
    if (strncmp(name, expected, 64)) { result = 4; goto done; }
    output_length = strlen(output);
    if (output_length > (size_t)-1 - sizeof temporary - 2) { result = 1; goto done; }
    path = malloc(output_length + sizeof temporary + 2);
    if (!path) { result = 1; goto done; }
    snprintf(path, output_length + sizeof temporary + 2, "%s/%s", output, temporary);
    result = 2;
    if (native && !holy_verify_with_output(path, 0)) goto done;
    result = 1;
    if (linkat(dir, temporary, dir, name, 0)) {
        if (errno != EEXIST) goto done;
        previous = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        if (previous < 0 || fstat(previous, &st) || !S_ISREG(st.st_mode) ||
            (st.st_mode & 0022) || !hash_fd(previous, prior) ||
            memcmp(prior, digest, 32)) { result = 4; goto done; }
    }
    if (fsync(dir)) goto done;
    if (emit) printf("%s/%s\n", output, name);
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: pinned HTTPS fetch failed (status %d)\n", result);
    free(path);
    if (previous >= 0) close(previous);
    if (curl) curl_easy_cleanup(curl);
    EVP_MD_CTX_free(transfer.hash);
    if (transfer.fd >= 0) close(transfer.fd);
    if (temporary[0] && dir >= 0) unlinkat(dir, temporary, 0);
    if (dir >= 0) close(dir);
    if (initialized) curl_global_cleanup();
    return result;
}

int holy_fetch_https(const char *url, const char *expected,
                     const char *output, const char *ca_file, int emit)
{
    return https_object(url, expected, output, ca_file, 1, emit);
}

int holy_fetch_https_data(const char *url, const char *expected,
                          const char *output, const char *ca_file)
{
    return https_object(url, expected, output, ca_file, 0, 0);
}
