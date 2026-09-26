#define _POSIX_C_SOURCE 200809L
#include "fetch.h"
#include "stage.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
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
