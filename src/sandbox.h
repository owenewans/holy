#ifndef HOLY_SANDBOX_H
#define HOLY_SANDBOX_H

#include <stddef.h>

/* the clean build environment: one user, mount and network namespace per step, a
   root holding read-only host directories, the declared mounts and the declared
   devices, and an explicit environment. every parameter is named on the command
   line and printed before the first step runs. */

struct holy_sandbox_mount {
    const char *source;      /* an absolute host path */
    const char *destination; /* an absolute path inside the root */
    int writable;
};

struct holy_sandbox_limit {
    const char *name;        /* cpu, memory, processes, file-size, open-files */
    unsigned long long value;
};

/* what a caller asked for, before any root exists */
struct holy_sandbox_request {
    unsigned long uid;
    int network;
    const char *const *devices;
    size_t device_count;
    const struct holy_sandbox_mount *mounts;
    size_t mount_count;
    const struct holy_sandbox_limit *limits;
    size_t limit_count;
    const char *const *env;
    size_t env_count;
};

struct holy_sandbox {
    unsigned long uid;       /* the uid the steps run as; zero means the caller */
    int network;             /* one keeps the host network inside the namespace */
    const char *const *devices;
    size_t device_count;
    const struct holy_sandbox_mount *mounts;
    size_t mount_count;
    const struct holy_sandbox_limit *limits;
    size_t limit_count;
    const char *const *env;  /* NAME=VALUE entries the caller declared */
    size_t env_count;
    const char *work;        /* the build root, writable at the same path inside */
    char *root;              /* the root directory, owned by the caller */
    char *record;            /* one line naming what the environment provides */
};

/* zero when this kernel gives a process an unprivileged user namespace, which is
   what the backend needs, and six otherwise. */
int holy_sandbox_probe(void);

/* creates the root under the build directory and writes the report line. two for a
   parameter this backend cannot serve, six for a missing capability. */
int holy_sandbox_prepare(struct holy_sandbox *sandbox);

/* runs one step in its own namespaces. argv carries no shell string and envp is a
   NULL terminated vector of NAME=VALUE entries. returns the exit status the step
   produced, 126 when the environment itself could not be built and 6 when the
   kernel refused the namespaces. */
int holy_sandbox_run(const struct holy_sandbox *sandbox, char *const argv[],
                     const char *cwd, char *const envp[]);

void holy_sandbox_free(struct holy_sandbox *sandbox);

#endif