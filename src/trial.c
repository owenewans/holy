#define _GNU_SOURCE
#include "trial.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

/* a root trial is a decision about what the command can see, so the node set, the
   tmpfs sizes and the namespace set are fixed here rather than chosen per call. */
struct trial_node {
    const char *name;
    mode_t mode;
    unsigned int major, minor;
};

static const struct trial_node trial_nodes[] = {
    { "null", 0666, 1, 3 },
    { "zero", 0666, 1, 5 },
    { "full", 0666, 1, 7 },
    { "random", 0666, 1, 8 },
    { "urandom", 0666, 1, 9 },
    { "tty", 0666, 5, 0 }
};

static int write_kernel_file(const char *path, const char *value)
{
    size_t length = strlen(value), offset = 0;
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    while (offset < length) {
        ssize_t written = write(fd, value + offset, length - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) { close(fd); return 0; }
        offset += (size_t)written;
    }
    return !close(fd);
}

/* the process keeps its own identity, so the trial does not look like a setuid
   context, and the capabilities of the new user namespace still apply to the mounts
   that follow. */
static int enter_namespaces(int *namespaces)
{
    char mapping[80];
    uid_t uid = geteuid();
    gid_t gid = getegid();
    *namespaces = CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS;
    /* a root that may create namespaces without a user namespace still gets the rest */
    if (unshare(*namespaces) &&
        unshare(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS)) return 0;
    snprintf(mapping, sizeof mapping, "%lu %lu 1\n", (unsigned long)uid, (unsigned long)uid);
    if (!write_kernel_file("/proc/self/uid_map", mapping) ||
        !write_kernel_file("/proc/self/setgroups", "deny\n")) return 0;
    snprintf(mapping, sizeof mapping, "%lu %lu 1\n", (unsigned long)gid, (unsigned long)gid);
    if (!write_kernel_file("/proc/self/gid_map", mapping)) return 0;
    /* the user namespace is available but the pid one is not: keep the mount, ipc and
       uts isolation and say which set the trial got. */
    if (unshare(CLONE_NEWPID)) *namespaces &= ~CLONE_NEWPID;
    return 1;
}

static int mount_private(const char *source, const char *target, const char *type,
                         unsigned long flags, const char *options)
{
    struct stat st;
    if (stat(target, &st)) return 0;
    return !mount(source, target, type, flags, options);
}

/* a host that refuses device nodes inside a user namespace cannot have a controlled
   /dev, and a trial without one is not a trial, so the reason is the requirement the
   caller reports. */
static int device_node(const struct trial_node *node)
{
    char path[64];
    snprintf(path, sizeof path, "/dev/%s", node->name);
    if (mknod(path, S_IFCHR | node->mode, makedev(node->major, node->minor)))
        fprintf(stderr, "holypkg: root trial cannot create %s: %s\n", path, strerror(errno));
    else if (chmod(path, node->mode))
        fprintf(stderr, "holypkg: root trial cannot set %s: %s\n", path, strerror(errno));
    else return 1;
    return 0;
}

static int apply_trial(int *capability)
{
    size_t i;
    static const int links[] = { 0, 0, 1, 2 };
    /* a fresh procfs shows the pid namespace of the process that mounts it, so this
       runs inside the new one, which the exec will not leave */
    if (!mount_private("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL))
        return 0;
    if (!mount_private("tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV,
                       "mode=0755,size=16m") ||
        !mount_private("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV,
                       "mode=1777,size=64m") ||
        /* /dev is the one mount that must allow device nodes, which is the whole point
           of a controlled /dev */
        !mount_private("tmpfs", "/dev", "tmpfs", MS_NOSUID, "mode=0755,size=1m") ||
        !mount_private("tmpfs", "/home", "tmpfs", MS_NOSUID | MS_NODEV,
                       "mode=0755,size=1m"))
        return 0;
    for (i = 0; i < sizeof trial_nodes / sizeof *trial_nodes; ++i)
        if (!device_node(&trial_nodes[i])) { *capability = 1; return 0; }
    /* /dev/fd is the directory the links below live in, and the three standard
       streams are the same directory entries under their own names */
    for (i = 0; i < sizeof links / sizeof *links; ++i) {
        char path[64], target[64];
        snprintf(path, sizeof path, "/dev/fd/%d", links[i]);
        snprintf(target, sizeof target, "/proc/self/fd/%d", links[i]);
        if ((symlink(target, path) || symlink(target, path + 4)) && errno != EEXIST) {
            fprintf(stderr, "holypkg: root trial cannot link %s: %s\n", path, strerror(errno));
            *capability = 1;
            return 0;
        }
    }
    return 1;
}

static int wait_status(pid_t pid)
{
    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return 1;
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 1;
}

int holy_trial_command(char *const argv[])
{
    pid_t outer, inner = -1;
    int namespaces = 0, capability = 0;
    if (!argv || !argv[0] || !*argv[0]) return 2;
    outer = fork();
    if (outer < 0) {
        fputs("holypkg: could not start a root trial\n", stderr);
        return 1;
    }
    if (outer) return wait_status(outer);
    if (!enter_namespaces(&namespaces)) {
        fputs("holypkg: user, mount, pid, ipc or uts namespace unavailable\n", stderr);
        _exit(6);
    }
    /* private propagation keeps every later mount, and every mount the command makes,
       out of the running system */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) _exit(1);
    /* the pid namespace starts at the next child, so the command is that child, it
       mounts the trial it will run in, and this process only carries the namespaces. */
    inner = fork();
    if (inner < 0) _exit(1);
    if (!inner) {
        if (!apply_trial(&capability))
            _exit(capability ? 6 : 1);
        execv(argv[0], argv);
        fprintf(stderr, "holypkg: trial: %s: %s\n", argv[0], strerror(errno));
        _exit(errno == ENOENT ? 127 : 126);
    }
    _exit(wait_status(inner));
}
