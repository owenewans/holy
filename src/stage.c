#define _POSIX_C_SOURCE 200809L
#include "stage.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

char *holy_stage_local(const char *source, const char *prefix)
{
    const char *base = geteuid() ? getenv("TMPDIR") : NULL;
    char *path = NULL;
    char buffer[65536];
    struct stat st;
    int input = -1, output = -1;
    ssize_t got;
    size_t length;
    int ok = 0;
    if (!base || !*base) base = "/tmp";
    if (strlen(base) > (size_t)-1 - strlen(prefix) - sizeof "-XXXXXX" - 1)
        return NULL;
    length = strlen(base) + strlen(prefix) + sizeof "/-XXXXXX";
    path = malloc(length);
    if (!path) return NULL;
    snprintf(path, length, "%s/%s-XXXXXX", base, prefix);
    input = open(source, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (input < 0 || fstat(input, &st) || !S_ISREG(st.st_mode)) goto done;
    output = mkstemp(path);
    if (output < 0) goto done;
    while ((got = read(input, buffer, sizeof buffer)) != 0) {
        size_t written = 0;
        if (got < 0) {
            if (errno == EINTR) continue;
            goto done;
        }
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
    if (input >= 0) close(input);
    if (!ok) { if (output >= 0) unlink(path); free(path); path = NULL; }
    return path;
}
