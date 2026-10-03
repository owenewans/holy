#ifndef HOLY_TRIAL_H
#define HOLY_TRIAL_H

#include <stddef.h>

/* runs one command in a private root trial: private mount propagation, own /proc,
   /run and /tmp, PID, IPC and UTS namespaces, a user namespace when available and a
   controlled /dev. argv is passed through unchanged, without a hidden shell, and the
   command runs as PID 1 of its own PID namespace. Returns the command status, 128
   plus the signal for a killed command, 6 when a namespace is unavailable and 1 when
   a trial step fails. */
int holy_trial_command(char *const argv[]);

/* the same trial with a prepared root: the directories of ROOT are bound read-only
   over the host ones and the backend's new root is exactly those binds, so a command
   sees the copy the plan was applied to as its own filesystem rather than as a path
   under the running system. ROOT is an absolute path to a directory the caller owns. */
int holy_trial_command_at(char *const argv[], const char *root);

/* what a copy of a filesystem carried, and what it refused. a device node, a socket
   or a fifo is counted rather than carried, since a copy holding one would not be the
   filesystem it claims to be. */
struct holy_trial_copy {
    size_t files;
    size_t directories;
    size_t bytes;
    size_t refused;
};

/* an isolated copy of ROOT under WORK, which is created and must be outside ROOT. the
   volatile trees of a live system are left out, since a copy has no use for them. the
   caller owns the returned path and frees it. */
char *holy_trial_copy_root(const char *root, const char *work, struct holy_trial_copy *copy);

/* whether WORK is inside ROOT, which is a usage error rather than a copy: a copy made
   inside the tree it copies would read its own output. */
int holy_trial_work_inside(const char *work, const char *root);

#endif
