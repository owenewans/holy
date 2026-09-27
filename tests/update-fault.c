#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef HOLY_STATIC_FAULT
extern int __real_fsync(int);
extern int __real_renameat(int, const char *, int, const char *);
extern ssize_t __real_write(int, const void *, size_t);
#define next_fsync __real_fsync
#define next_renameat __real_renameat
#define next_write __real_write
#define fsync __wrap_fsync
#define renameat __wrap_renameat
#define write __wrap_write
#else
#include <dlfcn.h>
static int (*next_fsync)(int);
static int (*next_renameat)(int, const char *, int, const char *);
static ssize_t (*next_write)(int, const void *, size_t);
#endif

static int fault(const char *name)
{
    const char *mode = getenv("HOLY_UPDATE_FAULT");
    return mode && !strcmp(mode, name);
}

static void stop(void)
{
    kill(getpid(), SIGKILL);
    _exit(99);
}

static int fd_path(int fd, char path[4096])
{
    char proc[64];
    ssize_t length;
    snprintf(proc, sizeof proc, "/proc/self/fd/%d", fd);
    length = readlink(proc, path, 4095);
    if (length < 0) return 0;
    path[length] = 0;
    return 1;
}

int renameat(int from, const char *old, int to, const char *name)
{
    int result;
#ifndef HOLY_STATIC_FAULT
    if (!next_renameat) *(void **)(&next_renameat) = dlsym(RTLD_NEXT, "renameat");
#endif
    if (!strncmp(old, ".holy-update-", 13)) {
        if (fault("payload-before")) stop();
        if (fault("no-space")) { errno = ENOSPC; return -1; }
    }
    result = next_renameat(from, old, to, name);
    if (!result) {
        if (fault("payload-after") && !strncmp(old, ".holy-update-", 13)) stop();
        if (fault("intent-after") && !strcmp(name, "journal")) stop();
        if (fault("generation-after") && !strcmp(name, "generation")) stop();
    }
    return result;
}

int fsync(int fd)
{
    char path[4096], proc[64], text[256], child[96];
    const char *digest = getenv("HOLY_UPDATE_NEW");
    int result, copy;
    ssize_t length;
    struct stat st;
#ifndef HOLY_STATIC_FAULT
    if (!next_fsync) *(void **)(&next_fsync) = dlsym(RTLD_NEXT, "fsync");
#endif
    result = next_fsync(fd);
    if (result || !getenv("HOLY_UPDATE_FAULT") || !fd_path(fd, path)) return result;
    if (fault("database-before")) {
        snprintf(proc, sizeof proc, "/proc/self/fd/%d", fd);
        copy = open(proc, O_RDONLY | O_CLOEXEC);
        length = copy < 0 ? -1 : pread(copy, text, sizeof text - 1, 0);
        if (copy >= 0) close(copy);
        if (length > 0) {
            text[length] = 0;
            if (!strcmp(text, "stage publishing\n")) stop();
        }
    }
    if (fault("database-after") && digest && strlen(digest) == 64 &&
        strlen(path) >= 16 && !strcmp(path + strlen(path) - 16, "/var/lib/holypkg")) {
        snprintf(child, sizeof child, "installed/%s", digest);
        if (!fstatat(fd, child, &st, AT_SYMLINK_NOFOLLOW)) stop();
    }
    if (fault("committed") && strstr(path, "/transactions/update") &&
        !fstatat(fd, "committed", &st, AT_SYMLINK_NOFOLLOW)) stop();
    return result;
}

ssize_t write(int fd, const void *data, size_t size)
{
    char path[4096];
#ifndef HOLY_STATIC_FAULT
    if (!next_write) *(void **)(&next_write) = dlsym(RTLD_NEXT, "write");
#endif
    if (fault("staging-partial") && size && fd_path(fd, path) && strstr(path, "/.holy-update-")) {
        next_write(fd, data, size / 2);
        stop();
    }
    return next_write(fd, data, size);
}
