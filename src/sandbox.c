/* the clean build environment: one user, mount and network namespace per step, a
   root holding read-only host directories, the declared mounts and the declared
   devices, and an explicit environment. see man/holy-recipe.5 for what each parameter
   is. the isolation is bubblewrap's flags, so what a step gets is what this file
   asks for rather than what this code assembles mount by mount. */
#define _GNU_SOURCE 1
#include "sandbox.h"
#include "bwrap.h"
#include "cache.h"
#include "state.h"

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
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

/* glibc's strchr and strrchr are _Generic overloads, which C99 does not have, so the two
   scans this file needs are written out */
static const char *scan(const char *text, char wanted, int last)
{
    const char *found = NULL, *cursor;
    for (cursor = text; *cursor; ++cursor)
        if (*cursor == wanted) { found = cursor; if (!last) return found; }
    return found;
}

/* the last path component, which is where a dependency root appears inside the step */
static const char *final_name(const char *path)
{
    const char *slash = scan(path, '/', 1);
    return slash && slash[1] ? slash + 1 : path;
}

/* a resource limit is a property the step inherits, so it is set on the process that
   becomes the backend and reaches the step through it. rlimit_nproc is the one this
   backend cannot carry: it counts every process of the mapped id, and the backend's
   own namespace setup is refused before the step starts, so a caller asking for it
   gets the refusal this file's contract already defines rather than a limit that
   breaks the environment instead of the step. */
static int apply_limit(const struct holy_sandbox_limit *limit)
{
    struct rlimit value;
    unsigned long long number = limit->value;
    int resource;
    if (!strcmp(limit->name, "cpu")) resource = RLIMIT_CPU;
    else if (!strcmp(limit->name, "memory")) resource = RLIMIT_AS;
    else if (!strcmp(limit->name, "file-size")) resource = RLIMIT_FSIZE;
    else if (!strcmp(limit->name, "open-files")) resource = RLIMIT_NOFILE;
    else return 2;
    /* zero would be unlimited, which is the opposite of a limit, so a caller asking
       for one is refused rather than given no ceiling */
    if (!number) return 2;
    memset(&value, 0, sizeof value);
    if (getrlimit(resource, &value)) return 1;
    if (number > value.rlim_max && value.rlim_max != RLIM_INFINITY) {
        if (!value.rlim_max) return 2;
        number = value.rlim_max;
    }
    value.rlim_cur = number;
    value.rlim_max = number;
    return setrlimit(resource, &value) ? 1 : 0;
}

static void complain(const char *what, const char *detail)
{
    if (detail) fprintf(stderr, "holypkg: build step cannot %s: %s\n", what, detail);
    else fprintf(stderr, "holypkg: build step cannot %s\n", what);
}

static int is_device(const char *path)
{
    struct stat st;
    if (lstat(path, &st)) return 0;
    return S_ISREG(st.st_mode) || S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode) ||
           S_ISFIFO(st.st_mode);
}

static int is_directory(const char *path)
{
    struct stat st;
    /* a link is followed here: a merged /usr host reaches /bin through one, and the
       directory behind it is what a step needs to see */
    return !stat(path, &st) && S_ISDIR(st.st_mode);
}

/* the declared mounts come after the read-only directories and the build root, so a
   mount a caller placed over either is the one the step sees */
/* every failure here is 126, since a step that never started is not a step result */
static int build_isolation(const struct holy_sandbox *sandbox, struct holy_bwrap *bwrap)
{
    size_t i;
    char number[32];
    struct stat present;
    /* the isolation and the empty environment come first, since the backend reads its
       arguments in order and a --clearenv after a --setenv would drop the name */
    holy_bwrap_isolate(bwrap, sandbox->network, 0);
    for (i = 0; read_only[i]; ++i)
        if (is_directory(read_only[i]) &&
            holy_bwrap_bind(bwrap, 0, read_only[i], read_only[i])) return 1;
    /* the build root is writable at the same absolute path, so the variables the
       recipe exports keep the values the report already showed */
    if (holy_bwrap_bind(bwrap, 1, sandbox->work, sandbox->work)) return 1;
    /* the declared dependencies are reachable read-only, so a step uses a tool without
       being able to change the root it came from */
    if (sandbox->deps &&
        holy_bwrap_bind(bwrap, 0, sandbox->deps, final_name(sandbox->deps))) return 1;
    /* a tmpfs rather than --dev, because the node set is this file's list and a step
       that found a host socket or a pty would have a device the report never named */
    if (holy_bwrap_add(bwrap, "--tmpfs") || holy_bwrap_add(bwrap, "/dev")) return 1;
    for (i = 0; base_devices[i]; ++i)
        if (holy_bwrap_dev(bwrap, base_devices[i])) return 1;
    for (i = 0; i < sandbox->device_count; ++i)
        if (holy_bwrap_dev(bwrap, sandbox->devices[i])) return 1;
    for (i = 0; i < sandbox->mount_count; ++i) {
        /* a source that is not there is reported before the step rather than mounted
           as an empty directory, which is what the backend would make of it */
        if (lstat(sandbox->mounts[i].source, &present)) {
            complain("place a declared mount", sandbox->mounts[i].source);
            return 126;
        }
        if (holy_bwrap_bind(bwrap, sandbox->mounts[i].writable,
                            sandbox->mounts[i].source, sandbox->mounts[i].destination))
            return 126;
    }
    if (sandbox->uid) {
        snprintf(number, sizeof number, "%lu", sandbox->uid);
        if (holy_bwrap_add(bwrap, "--uid") || holy_bwrap_add(bwrap, "--gid") ||
            holy_bwrap_add(bwrap, number)) return 1;
    }
    for (i = 0; i < sandbox->env_count; ++i) {
        const char *equals = scan(sandbox->env[i], '=', 0);
        char *name;
        if (!equals || equals == sandbox->env[i]) return 1;
        name = strndup(sandbox->env[i], (size_t)(equals - sandbox->env[i]));
        if (!name) return 1;
        if (holy_bwrap_add(bwrap, "--setenv") || holy_bwrap_add(bwrap, name) ||
            holy_bwrap_add(bwrap, equals + 1)) { free(name); return 1; }
        free(name);
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
                            NULL, 0, plan);
    if (!result)
        result = holy_state_set(digests, count, NULL, plan,
                                sandbox->deps, NULL, 0, NULL, 0, NULL, 0, NULL, 0,
                                NULL, 0, NULL, 0, NULL);
    if (result) { complain("install the declared dependencies", NULL); goto done; }
    for (i = 0; i < count; ++i) printf("build-dependency %s installed\n", storage[i]);
    result = 0;
done:
    free(storage);
    return result;
}

int holy_sandbox_probe(void)
{
    char *program = holy_bwrap_program();
    int result;
    if (!program) {
        fputs("holypkg: no bubblewrap on the host\n", stderr);
        return 6;
    }
    result = holy_bwrap_probe(program);
    free(program);
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
        if (sandbox->devices[i][0] != '/' || !is_device(sandbox->devices[i])) return 2;
    if (sandbox->dependency_count > 16) return 2;
    for (i = 0; i < sandbox->mount_count; ++i) {
        if (sandbox->mounts[i].source[0] != '/' ||
            sandbox->mounts[i].destination[0] != '/') return 2;
        /* the build root is already writable at its own path, so a second writable
           mount of it would only name the same tree twice */
        if (sandbox->mounts[i].writable &&
            !strcmp(sandbox->mounts[i].source, sandbox->work)) return 2;
    }
    for (i = 0; i < sandbox->limit_count; ++i) {
        int applied = apply_limit(&sandbox->limits[i]);
        /* the limits are set on this process, so one this backend cannot carry is a
           refusal before the build starts rather than a build that runs unbounded */
        if (applied == 2) {
            complain("carry this resource limit", sandbox->limits[i].name);
            return 2;
        }
        if (applied) {
            complain("set a resource limit", sandbox->limits[i].name);
            return 1;
        }
    }
    /* the declared dependencies are installed before the record is written, so the record
       and the step PATH describe the environment the step actually gets */
    if (sandbox->dependency_count &&
        install_dependencies(sandbox, sandbox->dependencies, sandbox->dependency_count))
        return 1;
    needed = snprintf(NULL, 0,
                      "root %s uid %lu network %s read-only %zu mounts %zu devices %zu "
                      "limits %zu deps %s", sandbox->work,
                      sandbox->uid ? sandbox->uid : (unsigned long)getuid(),
                      sandbox->network ? "host" : "none",
                      (size_t)(sizeof read_only / sizeof *read_only - 1),
                      sandbox->mount_count,
                      (size_t)(sizeof base_devices / sizeof *base_devices - 1) +
                          sandbox->device_count,
                      sandbox->limit_count, sandbox->deps ? "declared" : "none");
    if (needed < 0) return 1;
    sandbox->record = malloc((size_t)needed + 1);
    if (!sandbox->record) return 1;
    snprintf(sandbox->record, (size_t)needed + 1,
             "root %s uid %lu network %s read-only %zu mounts %zu devices %zu limits %zu "
             "deps %s",
             sandbox->work, sandbox->uid ? sandbox->uid : (unsigned long)getuid(),
             sandbox->network ? "host" : "none",
             (size_t)(sizeof read_only / sizeof *read_only - 1), sandbox->mount_count,
             (size_t)(sizeof base_devices / sizeof *base_devices - 1) +
                 sandbox->device_count,
             sandbox->limit_count, sandbox->deps ? "declared" : "none");
    return 0;
}

int holy_sandbox_run(const struct holy_sandbox *sandbox, char *const argv[],
                     const char *cwd, char *const envp[])
{
    struct holy_bwrap bwrap;
    char *program;
    size_t i;
    int status;
    if (!sandbox || !sandbox->work || !argv || !argv[0]) return 2;
    program = holy_bwrap_program();
    if (!program) {
        fputs("holypkg: build step: no bubblewrap on the host\n", stderr);
        return 6;
    }
    holy_bwrap_init(&bwrap, program);
    free(program);
    {
        int built = build_isolation(sandbox, &bwrap);
        if (built) {
            holy_bwrap_free(&bwrap);
            if (built != 126) complain("describe the build environment", NULL);
            return built;
        }
    }
    if (cwd && (holy_bwrap_add(&bwrap, "--chdir") || holy_bwrap_add(&bwrap, cwd))) {
        holy_bwrap_free(&bwrap);
        return 1;
    }
    /* the caller names the environment and the backend clears the rest, so a variable
       the host exports does not reach a step the caller did not name. a table the
       caller passes explicitly is appended to the declared names rather than replacing
       them, since that is what the parameter means */
    for (i = 0; envp && envp[i]; ++i) {
        const char *equals = scan(envp[i], '=', 0);
        char *name;
        if (!equals || equals == envp[i]) continue;
        name = strndup(envp[i], (size_t)(equals - envp[i]));
        if (!name) { holy_bwrap_free(&bwrap); return 1; }
        if (holy_bwrap_add(&bwrap, "--setenv") || holy_bwrap_add(&bwrap, name) ||
            holy_bwrap_add(&bwrap, equals + 1)) { free(name); holy_bwrap_free(&bwrap); return 1; }
        free(name);
    }
    status = holy_bwrap_exec(&bwrap, argv, sandbox->output[0]);
    holy_bwrap_free(&bwrap);
    return status;
}

void holy_sandbox_free(struct holy_sandbox *sandbox)
{
    if (!sandbox) return;
    free(sandbox->deps);
    free(sandbox->record);
    sandbox->deps = NULL;
    sandbox->record = NULL;
}
