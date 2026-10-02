/* the clean build environment. a user, mount and network namespace per step, a
   root with the host toolchain bound read-only, the build root writable at the same
   path, and a fixed environment. see man/holy-recipe.5 for what each parameter is */
/* _GNU_SOURCE for the namespace and mount declarations. the glibc strrchr
   overload needs C11, so the one use here is a plain scan */
#define _GNU_SOURCE 1
#include "sandbox.h"
#include "cache.h"
#include "state.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* the directories a step reads and never writes. a merged /usr tree reaches the same
   binaries through all of them, so each is bound rather than only /usr */
static const char *const read_only[] = {
    "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", NULL
};

/* the devices a step needs to read a terminal and run a compiler. a caller names more,
   never fewer */
static const char *const base_devices[] = {
    "/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", NULL
};

static char *under(const char *root, const char *absolute)
{
    size_t a = strlen(root), b = strlen(absolute);
    char *out;
    if (absolute[0] != '/' || a > SIZE_MAX - b - 1) return NULL;
    out = malloc(a + b + 1);
    if (!out) return NULL;
    memcpy(out, root, a);
    memcpy(out + a, absolute, b + 1);
    return out;
}

/* a path under a directory, where the name is relative rather than absolute */
static char *joined(const char *directory, const char *name)
{
    size_t a = strlen(directory), b = strlen(name);
    char *out;
    if (a > SIZE_MAX - b - 2) return NULL;
    out = malloc(a + b + 2);
    if (!out) return NULL;
    memcpy(out, directory, a);
    out[a] = '/';
    memcpy(out + a + 1, name, b + 1);
    return out;
}

/* the last separator of a path, scanned rather than taken from strrchr, whose glibc
   overload is a C11 generic selection */
static char *last_separator(char *path)
{
    char *found = NULL, *cursor;
    for (cursor = path; *cursor; ++cursor)
        if (*cursor == '/') found = cursor;
    return found;
}

/* a directory with its parents, since the root starts empty */
static int make_path(const char *path)
{
    char *copy, *slash;
    struct stat st;
    int ok = 0;
    if (!path || path[0] != '/' || strlen(path) >= 4096) return 0;
    if (!lstat(path, &st)) return S_ISDIR(st.st_mode);
    copy = strdup(path);
    if (!copy) return 0;
    for (slash = copy + 1; *slash; ++slash) {
        if (*slash != '/') continue;
        *slash = 0;
        if (mkdir(copy, 0755) && errno != EEXIST) goto done;
        *slash = '/';
    }
    ok = mkdir(copy, 0755) == 0 || errno == EEXIST;
done:
    free(copy);
    return ok;
}

/* a read-only bind of one host directory. a merged /usr tree has /bin and /lib as
   symlinks and a bind would follow them, so a symlink is recreated as it stands */
static int bind_read_only(const char *source, const char *root)
{
    struct stat st;
    char *target = under(root, source);
    int ok = 0;
    if (!target) return 0;
    if (lstat(source, &st)) goto done;
    if (S_ISLNK(st.st_mode)) {
        char link[4096];
        ssize_t length = readlink(source, link, sizeof link - 1);
        if (length < 0) goto done;
        link[length] = 0;
        if (!make_path(target)) goto done;
        unlink(target);
        ok = symlink(link, target) == 0;
        goto done;
    }
    if (!S_ISDIR(st.st_mode)) goto done;
    if (!make_path(target)) goto done;
    if (mount(source, target, NULL, MS_BIND | MS_REC, NULL)) goto done;
    /* the flags of a bind apply to the mount as a whole, so the read-only flag needs
       the second call rather than the first */
    ok = !mount(NULL, target, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
done:
    free(target);
    return ok;
}

/* a device node is a bind of the host node, since creating one inside a user namespace
   needs a privilege this build does not take */
static int bind_device(const char *source, const char *root)
{
    struct stat st;
    char *target = under(root, source), *directory = NULL, *slash;
    int ok = 0;
    if (!target) return 0;
    if (lstat(source, &st) || (!S_ISREG(st.st_mode) && !S_ISCHR(st.st_mode) &&
        !S_ISBLK(st.st_mode) && !S_ISFIFO(st.st_mode))) goto done;
    directory = strdup(target);
    if (!directory) goto done;
    slash = last_separator(directory);
    if (!slash || slash == directory) goto done;
    *slash = 0;
    if (!make_path(directory)) goto done;
    { int fd = open(target, O_CREAT | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0666);
      if (fd < 0) goto done;
      close(fd); }
    ok = mount(source, target, NULL, MS_BIND, NULL) == 0;
done:
    free(target);
    free(directory);
    return ok;
}

static int bind_mount(const struct holy_sandbox_mount *entry, const char *root)
{
    struct stat st;
    char *target = under(root, entry->destination);
    int ok = 0;
    if (!target) return 0;
    /* a directory a step writes into needs to exist inside the root as well */
    if (lstat(entry->source, &st)) goto done;
    if (S_ISDIR(st.st_mode) && !make_path(target)) goto done;
    if (!make_path(target)) goto done;
    unlink(target);
    if (mount(entry->source, target, NULL,
              MS_BIND | MS_REC | (entry->writable ? 0 : MS_RDONLY), NULL)) goto done;
    /* a read-only mount takes the flag on a second call, and a writable one is only
       writable because the caller wrote :rw after the destination */
    if (!entry->writable &&
        mount(NULL, target, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL))
        goto done;
    ok = 1;
done:
    free(target);
    return ok;
}

static int write_map(pid_t child, const char *name, const char *text)
{
    char path[64];
    int fd;
    ssize_t written;
    snprintf(path, sizeof path, "/proc/%d/%s", (int)child, name);
    fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    written = write(fd, text, strlen(text));
    return !close(fd) && written == (ssize_t)strlen(text);
}

/* the maps name one id, the caller's, so a step writes files that belong to an
   ordinary user and holds no privilege over the running system */
static int apply_maps(pid_t child)
{
    char text[65];
    unsigned long uid = getuid(), gid = getgid();
    snprintf(text, sizeof text, "0 %lu 1\n", uid);
    /* setgroups has to be denied before the gid map is writable */
    return write_map(child, "uid_map", text) && write_map(child, "setgroups", "deny") &&
           (snprintf(text, sizeof text, "0 %lu 1\n", gid),
            write_map(child, "gid_map", text));
}

static size_t count_entries(char *const *table)
{
    size_t n = 0;
    if (!table) return 0;
    while (table[n]) ++n;
    return n;
}

static int apply_limit(const struct holy_sandbox_limit *limit)
{
    struct rlimit value;
    unsigned long long number = limit->value;
    int resource;
    if (!strcmp(limit->name, "cpu")) resource = RLIMIT_CPU;
    else if (!strcmp(limit->name, "memory")) resource = RLIMIT_AS;
    else if (!strcmp(limit->name, "processes")) resource = RLIMIT_NPROC;
    else if (!strcmp(limit->name, "file-size")) resource = RLIMIT_FSIZE;
    else if (!strcmp(limit->name, "open-files")) resource = RLIMIT_NOFILE;
    else return 0;
    /* zero would be unlimited, which is the opposite of a limit, so a caller asking
       for one is refused rather than given no ceiling */
    if (!number) return 0;
    memset(&value, 0, sizeof value);
    if (getrlimit(resource, &value)) return 0;
    if (number > value.rlim_max && value.rlim_max != RLIM_INFINITY) {
        if (!value.rlim_max) return 0;
        number = value.rlim_max;
    }
    value.rlim_cur = number;
    value.rlim_max = number;
    return setrlimit(resource, &value) == 0;
}

static void complain(const char *what, const char *detail)
{
    fprintf(stderr, "holypkg: build environment cannot %s%s%s\n", what,
            detail ? ": " : "", detail ? detail : "");
}

/* the build root reaches the root at the same path the recipe exports, so the step
   directory and every HOLY_* path keep the values the report already showed */
static int bind_build_root(const struct holy_sandbox *sandbox)
{
    char *target = under(sandbox->root, sandbox->work);
    int ok = 0;
    if (!target) return 0;
    if (!make_path(target)) goto done;
    if (mount(sandbox->work, target, NULL, MS_BIND, NULL)) {
        complain("bind the build root", strerror(errno));
        goto done;
    }
    ok = 1;
done:
    free(target);
    return ok;
}

/* the declared mounts come after the read-only directories and the build root, so a
   mount a caller placed over either is the one the step sees */
/* the child runs this after the parent wrote the maps, with its namespaces in place.
   every failure is 126, since a step that never started is not a step result */
static void child_setup(const struct holy_sandbox *sandbox, char *const argv[],
                        const char *cwd, char *const envp[])
{
    size_t i;
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) { complain("isolate mounts", strerror(errno)); _exit(126); }
    for (i = 0; read_only[i]; ++i)
        if (!bind_read_only(read_only[i], sandbox->root)) {
            complain("bind a host directory read-only", read_only[i]);
            _exit(126);
        }
    if (!bind_build_root(sandbox)) _exit(126);
    /* the declared dependencies are reachable read-only, so a step uses a tool without
       being able to change the root it came from */
    if (sandbox->deps && !bind_read_only(sandbox->deps, sandbox->root)) {
        complain("reach the declared dependencies", sandbox->deps);
        _exit(126);
    }
    for (i = 0; base_devices[i]; ++i)
        if (!bind_device(base_devices[i], sandbox->root)) {
            complain("reach a device node", base_devices[i]);
            _exit(126);
        }
    for (i = 0; i < sandbox->device_count; ++i)
        if (!bind_device(sandbox->devices[i], sandbox->root)) {
            complain("reach a device node", sandbox->devices[i]);
            _exit(126);
        }
    for (i = 0; i < sandbox->mount_count; ++i)
        if (!bind_mount(&sandbox->mounts[i], sandbox->root)) {
            complain("place a declared mount", sandbox->mounts[i].source);
            _exit(126);
        }
    for (i = 0; i < sandbox->limit_count; ++i)
        if (!apply_limit(&sandbox->limits[i])) {
            complain("apply a resource limit", sandbox->limits[i].name);
            _exit(126);
        }
    if (chroot(sandbox->root)) { complain("enter the build root", strerror(errno)); _exit(126); }
    if (cwd && chdir(cwd)) { complain("enter the step directory", strerror(errno)); _exit(126); }
    /* a caller that captures the output names a file for it, since a pipe would be
       read by the parent while the child holds both ends */
    if (sandbox->output[0] >= 0) {
        if (dup2(sandbox->output[0], STDOUT_FILENO) < 0 ||
            dup2(sandbox->output[0], STDERR_FILENO) < 0) {
            complain("redirect the step output", strerror(errno));
            _exit(126);
        }
    }
    /* the caller names the environment, so a variable the host exports does not reach a
       step. building the vector here rather than through putenv is what keeps the
       inherited table out of it */
    {
        size_t declared = sandbox->env_count, e, used = 0;
        char **table = malloc((declared + count_entries(envp) + 1) * sizeof *table);
        if (!table) _exit(126);
        for (e = 0; e < declared; ++e)
            if (!(table[used++] = strdup(sandbox->env[e]))) _exit(126);
        for (e = 0; envp && envp[e]; ++e)
            if (!(table[used++] = strdup(envp[e]))) _exit(126);
        table[used] = NULL;
        execve(argv[0], argv, table);
    }
    fprintf(stderr, "holypkg: build step interpreter %s: %s\n", argv[0], strerror(errno));
    _exit(errno == ENOENT ? 127 : 126);
}

int holy_sandbox_probe(void)
{
    pid_t child = fork();
    int status = 0;
    if (child < 0) return 6;
    if (!child) _exit(unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWNET) ? 1 : 0);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) continue;
    if (!WIFEXITED(status) || WEXITSTATUS(status)) {
        complain("create a user namespace", strerror(errno));
        return 6;
    }
    return 0;
}

/* the declared dependencies become a private Holy root, installed through the same
   transaction an ordinary install uses, so a step finds them on the root PATH and their
   manifests, providers and hooks are the ones this manager wrote */
static int install_dependencies(struct holy_sandbox *sandbox,
                                const char *const *paths, size_t count)
{
    char (*storage)[65] = NULL;
    const char *digests[16];
    size_t i;
    char plan[65];
    int result = 1;
    if (!count) return 0;
    if (count > 16) return 2;
    sandbox->deps = joined(sandbox->work, "deps");
    if (!sandbox->deps) return 1;
    storage = calloc(count, sizeof *storage);
    if (!storage) return 1;
    /* the set engine takes one pointer per artifact, so the blocks are named rather
       than handed over as a packed array */
    for (i = 0; i < count; ++i) digests[i] = storage[i];
    /* the root is a plain directory first, since the state engine creates its layout
       under a path that already exists */
    if (mkdir(sandbox->deps, 0755) && errno != EEXIST) {
        complain("create the dependency root", strerror(errno));
        goto done;
    }
    if (!holy_state_init(sandbox->deps)) { complain("initialise the dependency root", NULL); goto done; }
    for (i = 0; i < count; ++i) {
        /* the paths carry the local: prefix the command line uses, and the cache takes
           the path itself */
        if (strncmp(paths[i], "local:", 6) ||
            !holy_cache_stage_local_digest(paths[i] + 6, sandbox->deps, storage[i])) {
            complain("stage a declared dependency", paths[i]);
            goto done;
        }
        printf("build-dependency %s staged\n", storage[i]);
    }
    /* the plan and the apply are two calls, since the set engine takes a plan hash as the
       approval of a review the command line already is */
    result = holy_state_set(digests, count, NULL, NULL,
                            sandbox->deps, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0,
                            plan);
    if (!result)
        result = holy_state_set(digests, count, NULL, plan,
                                sandbox->deps, NULL, 0, NULL, 0, NULL, 0, NULL, 0,
                                NULL, 0, NULL);
    if (result) { complain("install the declared dependencies", NULL); goto done; }
    for (i = 0; i < count; ++i) printf("build-dependency %s installed\n", storage[i]);
    result = 0;
done:
    free(storage);
    return result;
}

int holy_sandbox_prepare(struct holy_sandbox *sandbox)
{
    size_t i;
    int needed;
    if (!sandbox || !sandbox->work || sandbox->work[0] != '/') return 2;
    /* a caller that did not name an output leaves it inherited */
    if (sandbox->output[0] == 0 && sandbox->output[1] == 0)
        sandbox->output[0] = sandbox->output[1] = -1;
    for (i = 0; i < sandbox->device_count; ++i)
        if (sandbox->devices[i][0] != '/') return 2;
    if (sandbox->dependency_count > 16) return 2;
    for (i = 0; i < sandbox->mount_count; ++i) {
        if (sandbox->mounts[i].source[0] != '/' ||
            sandbox->mounts[i].destination[0] != '/') return 2;
        /* the build root is already writable at its own path, so a second writable
           mount of it would only name the same tree twice */
        if (sandbox->mounts[i].writable &&
            !strcmp(sandbox->mounts[i].source, sandbox->work)) return 2;
    }
    sandbox->root = joined(sandbox->work, "env");
    if (!sandbox->root) return 1;
    if (mkdir(sandbox->root, 0755) && errno != EEXIST) {
        complain("create the build environment root", strerror(errno));
        goto failed;
    }
    /* the declared dependencies are installed before the record is written, so the record
       and the step PATH describe the environment the step actually gets */
    if (sandbox->dependency_count &&
        install_dependencies(sandbox, sandbox->dependencies, sandbox->dependency_count))
        goto failed;
    needed = snprintf(NULL, 0,
                      "root %s uid %lu network %s read-only %zu mounts %zu devices %zu "
                      "limits %zu deps %s", sandbox->root,
                      sandbox->uid ? sandbox->uid : (unsigned long)getuid(),
                      sandbox->network ? "host" : "none",
                      (size_t)(sizeof read_only / sizeof *read_only - 1),
                      sandbox->mount_count,
                      (size_t)(sizeof base_devices / sizeof *base_devices - 1) +
                          sandbox->device_count,
                      sandbox->limit_count, sandbox->deps ? "declared" : "none");
    if (needed < 0) { free(sandbox->root); sandbox->root = NULL; return 1; }
    sandbox->record = malloc((size_t)needed + 1);
    if (!sandbox->record) { free(sandbox->root); sandbox->root = NULL; return 1; }
    snprintf(sandbox->record, (size_t)needed + 1,
             "root %s uid %lu network %s read-only %zu mounts %zu devices %zu limits %zu "
             "deps %s",
             sandbox->root, sandbox->uid ? sandbox->uid : (unsigned long)getuid(),
             sandbox->network ? "host" : "none",
             (size_t)(sizeof read_only / sizeof *read_only - 1), sandbox->mount_count,
             (size_t)(sizeof base_devices / sizeof *base_devices - 1) +
                 sandbox->device_count,
             sandbox->limit_count, sandbox->deps ? "declared" : "none");
    return 0;
failed:
    free(sandbox->root);
    free(sandbox->deps);
    free(sandbox->record);
    sandbox->root = NULL;
    sandbox->deps = NULL;
    sandbox->record = NULL;
    return 1;
}

int holy_sandbox_run(const struct holy_sandbox *sandbox, char *const argv[],
                     const char *cwd, char *const envp[])
{
    int sync[2] = {-1, -1};
    pid_t child;
    int status = 0;
    if (!sandbox || !sandbox->root || !argv || !argv[0]) return 2;
    /* a socket pair rather than a pipe, since the parent writes the maps between the
       two messages and one process must not read its own */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sync)) {
        complain("synchronise the build environment", strerror(errno));
        return 6;
    }
    child = fork();
    if (child < 0) {
        close(sync[0]);
        close(sync[1]);
        return 1;
    }
    if (!child) {
        char reply;
        close(sync[0]);
        if (unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWNET)) {
            complain("create its namespaces", strerror(errno));
            _exit(126);
        }
        if (write(sync[1], "x", 1) != 1) _exit(126);
        if (read(sync[1], &reply, 1) != 1) _exit(126);
        close(sync[1]);
        child_setup(sandbox, argv, cwd, envp);
    }
    close(sync[1]);
    sync[1] = -1;
    {
        char ready;
        ssize_t got = read(sync[0], &ready, 1);
        if (got == 1) {
            if (!apply_maps(child))
                complain("map the build user", NULL);
            if (write(sync[0], "y", 1) != 1) got = -1;
        }
        close(sync[0]);
        if (got != 1) {
            while (waitpid(child, &status, 0) < 0 && errno == EINTR) continue;
            return got < 0 ? 1 : status;
        }
    }
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) continue;
    if (!WIFEXITED(status)) return 1;
    return WEXITSTATUS(status);
}

void holy_sandbox_free(struct holy_sandbox *sandbox)
{
    if (!sandbox) return;
    free(sandbox->root);
    free(sandbox->deps);
    free(sandbox->record);
    sandbox->root = NULL;
    sandbox->deps = NULL;
    sandbox->record = NULL;
}