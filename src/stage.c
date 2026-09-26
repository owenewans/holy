#define _POSIX_C_SOURCE 200809L
#include "stage.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int holy_temporary_at(int dir, char name[43])
{
    unsigned char random_bytes[16];
    size_t attempt, done, i;
    for (attempt = 0; attempt < 16; ++attempt) {
        done = 0;
        while (done < sizeof random_bytes) {
            ssize_t got = getrandom(random_bytes + done, sizeof random_bytes - done, 0);
            if (got < 0 && errno == EINTR) continue;
            if (got <= 0) return -1;
            done += (size_t)got;
        }
        memcpy(name, ".holy-tmp-", 10);
        for (i = 0; i < sizeof random_bytes; ++i)
            snprintf(name + 10 + i * 2, 3, "%02x", random_bytes[i]);
        name[42] = '\0';
        {
            int fd = openat(dir, name, O_WRONLY | O_CREAT | O_EXCL |
                            O_NOFOLLOW | O_CLOEXEC, 0600);
            if (fd >= 0 || errno != EEXIST) return fd;
        }
    }
    errno = EEXIST;
    return -1;
}

char *holy_stage_fd(int input, const char *prefix)
{
    const char *base = geteuid() ? getenv("TMPDIR") : NULL;
    char *path = NULL;
    char buffer[65536];
    struct stat st;
    int output = -1;
    ssize_t got;
    size_t length;
    off_t offset = 0;
    int ok = 0;
    if (!base || !*base) base = "/tmp";
    if (strlen(base) > (size_t)-1 - strlen(prefix) - sizeof "-XXXXXX" - 1)
        return NULL;
    length = strlen(base) + strlen(prefix) + sizeof "/-XXXXXX";
    path = malloc(length);
    if (!path) return NULL;
    snprintf(path, length, "%s/%s-XXXXXX", base, prefix);
    if (fstat(input, &st) || !S_ISREG(st.st_mode) || st.st_size < 0) goto done;
    output = mkstemp(path);
    if (output < 0) goto done;
    while (offset < st.st_size) {
        size_t amount = (uint64_t)(st.st_size - offset) < sizeof buffer ?
                        (size_t)(st.st_size - offset) : sizeof buffer;
        size_t written = 0;
        got = pread(input, buffer, amount, offset);
        if (got < 0) {
            if (errno == EINTR) continue;
            goto done;
        }
        if (!got) goto done;
        offset += got;
        while (written < (size_t)got) {
            ssize_t sent = write(output, buffer + written, (size_t)got - written);
            if (sent < 0 && errno == EINTR) continue;
            if (sent <= 0) goto done;
            written += (size_t)sent;
        }
    }
    if (fsync(output)) goto done;
    ok = 1;
done:
    if (output >= 0) close(output);
    if (!ok) { if (output >= 0) unlink(path); free(path); path = NULL; }
    return path;
}

char *holy_stage_local(const char *source, const char *prefix)
{
    int input = open(source, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    char *path;
    if (input < 0) return NULL;
    path = holy_stage_fd(input, prefix);
    close(input);
    return path;
}
