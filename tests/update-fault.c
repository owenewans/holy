#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <dirent.h>
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
extern int __real_linkat(int, const char *, int, const char *, int);
extern int __real_unlinkat(int, const char *, int);
#define next_fsync __real_fsync
#define next_renameat __real_renameat
#define next_write __real_write
#define next_linkat __real_linkat
#define next_unlinkat __real_unlinkat
#define fsync __wrap_fsync
#define renameat __wrap_renameat
#define write __wrap_write
#define linkat __wrap_linkat
#define unlinkat __wrap_unlinkat
#else
#include <dlfcn.h>
static int (*next_fsync)(int);
static int (*next_renameat)(int, const char *, int, const char *);
static ssize_t (*next_write)(int, const void *, size_t);
static int (*next_linkat)(int, const char *, int, const char *, int);
static int (*next_unlinkat)(int, const char *, int);
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

int linkat(int from, const char *old, int to, const char *name, int flags)
{
    int result;
#ifndef HOLY_STATIC_FAULT
    if (!next_linkat) *(void **)(&next_linkat) = dlsym(RTLD_NEXT, "linkat");
#endif
    if (fault("hardlink-before")) stop();
    if (fault("hardlink-no-space")) { errno = ENOSPC; return -1; }
    result = next_linkat(from, old, to, name, flags);
    if (!result && fault("hardlink-after")) stop();
    return result;
}

int unlinkat(int dir, const char *name, int flags)
{
    int result;
#ifndef HOLY_STATIC_FAULT
    if (!next_unlinkat) *(void **)(&next_unlinkat) = dlsym(RTLD_NEXT, "unlinkat");
#endif
    result = next_unlinkat(dir, name, flags);
    if (!result && fault("hardlink-remove") && !strcmp(name, "a-first")) stop();
    if (!result && fault("group-cleanup") && strlen(name) > 6 &&
        !strcmp(name + strlen(name) - 6, "-group")) stop();
    return result;
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
    if (fault("set-journal") && !fstatat(fd, "set-journal", &st, AT_SYMLINK_NOFOLLOW)) stop();
    if (fault("set-instance") && digest && strstr(path, "/installed/") && strstr(path, digest) &&
        !fstatat(fd, "state", &st, AT_SYMLINK_NOFOLLOW)) stop();
    if (fault("directory-ready") && strstr(path, "/.holy-dir-")) stop();
    if (fault("payload-written") && strstr(path, "/opt/apps/deep/data")) stop();
    if (getenv("HOLY_DIRECTORY_PARENT") && !strcmp(path, getenv("HOLY_DIRECTORY_PARENT"))) {
        if (fault("directory-created") && getenv("HOLY_DIRECTORY_NAME") &&
            !fstatat(fd, getenv("HOLY_DIRECTORY_NAME"), &st, AT_SYMLINK_NOFOLLOW)) stop();
        if (fault("directory-partial")) {
            int listing = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            DIR *stream = listing < 0 ? NULL : fdopendir(listing);
            struct dirent *entry;
            if (stream) {
                while ((entry = readdir(stream)))
                    if (!strncmp(entry->d_name, ".holy-dir-", 10)) stop();
                closedir(stream);
            } else if (listing >= 0) close(listing);
        }
    }
    if (getenv("HOLY_UPDATE_STEP") && strstr(path, "/transactions/update/")) {
        static unsigned long step;
        snprintf(proc, sizeof proc, "/proc/self/fd/%d", fd);
        copy = open(proc, O_RDONLY | O_CLOEXEC);
        length = copy < 0 ? -1 : pread(copy, text, sizeof text - 1, 0);
        if (copy >= 0) close(copy);
        if (length > 0) {
            text[length] = 0;
            if (!strncmp(text, "stage applying\n", 15) && strstr(text, "\nresult done\n") &&
                ++step == strtoul(getenv("HOLY_UPDATE_STEP"), NULL, 10)) stop();
        }
    }
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
