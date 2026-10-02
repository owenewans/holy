#define _GNU_SOURCE
#include "bwrap.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* where a package puts the program, and the two names a merged /usr tree reaches it
   through */
static const char *const program_paths[] = {
    "/usr/bin/bwrap", "/bin/bwrap", NULL
};

void holy_bwrap_init(struct holy_bwrap *bwrap, const char *program)
{
    bwrap->argv = NULL;
    bwrap->count = bwrap->capacity = 0;
    holy_bwrap_add(bwrap, program);
}

int holy_bwrap_add(struct holy_bwrap *bwrap, const char *value)
{
    char **grown;
    char *copy;
    if (!bwrap || !value) return 1;
    copy = strdup(value);
    if (!copy) return 1;
    if (bwrap->count + 2 > bwrap->capacity) {
        size_t want = bwrap->capacity ? bwrap->capacity * 2 : 32;
        grown = realloc(bwrap->argv, want * sizeof *grown);
        if (!grown) { free(copy); return 1; }
        bwrap->argv = grown;
        bwrap->capacity = want;
    }
    bwrap->argv[bwrap->count++] = copy;
    bwrap->argv[bwrap->count] = NULL;
    return 0;
}

int holy_bwrap_tmpfs(struct holy_bwrap *bwrap, const char *destination,
                     unsigned long long bytes)
{
    char size[32];
    /* bwrap reads --size as the option of the tmpfs that follows it, so the pair is
       the only order that carries a limit */
    snprintf(size, sizeof size, "%llu", bytes);
    return holy_bwrap_add(bwrap, "--size") || holy_bwrap_add(bwrap, size) ||
           holy_bwrap_add(bwrap, "--tmpfs") || holy_bwrap_add(bwrap, destination);
}

int holy_bwrap_bind(struct holy_bwrap *bwrap, int writable, const char *source,
                    const char *destination)
{
    return holy_bwrap_add(bwrap, writable ? "--bind" : "--ro-bind") ||
           holy_bwrap_add(bwrap, source) || holy_bwrap_add(bwrap, destination);
}

int holy_bwrap_dev(struct holy_bwrap *bwrap, const char *node)
{
    return holy_bwrap_add(bwrap, "--dev-bind") || holy_bwrap_add(bwrap, node) ||
           holy_bwrap_add(bwrap, node);
}

void holy_bwrap_isolate(struct holy_bwrap *bwrap, int network, int as_pid_1)
{
    holy_bwrap_add(bwrap, "--clearenv");
    holy_bwrap_add(bwrap, "--unshare-user");
    holy_bwrap_add(bwrap, "--unshare-pid");
    holy_bwrap_add(bwrap, "--unshare-ipc");
    holy_bwrap_add(bwrap, "--unshare-uts");
    /* a cgroup namespace keeps a step from seeing or changing the host's accounting,
       but a host that refuses one is not a host without isolation, so the failure is
       tolerated rather than reported as a missing capability */
    holy_bwrap_add(bwrap, "--unshare-cgroup-try");
    if (!network) holy_bwrap_add(bwrap, "--unshare-net");
    holy_bwrap_add(bwrap, "--new-session");
    holy_bwrap_add(bwrap, "--die-with-parent");
    /* a trial is not a privilege context: the payload keeps its own uid and gains
       nothing over the caller */
    holy_bwrap_add(bwrap, "--cap-drop");
    holy_bwrap_add(bwrap, "ALL");
    if (as_pid_1) holy_bwrap_add(bwrap, "--as-pid-1");
}

void holy_bwrap_free(struct holy_bwrap *bwrap)
{
    size_t i;
    if (!bwrap || !bwrap->argv) return;
    for (i = 0; i < bwrap->count; ++i) free(bwrap->argv[i]);
    free(bwrap->argv);
    bwrap->argv = NULL;
    bwrap->count = bwrap->capacity = 0;
}

static int runnable(const char *path)
{
    struct stat st;
    /* a link is followed here on purpose: the two names are the same program, and the
       one that answers is the one to run */
    return !stat(path, &st) && S_ISREG(st.st_mode) && !access(path, X_OK);
}

char *holy_bwrap_program(void)
{
    size_t i;
    for (i = 0; program_paths[i]; ++i)
        if (runnable(program_paths[i])) return strdup(program_paths[i]);
    return NULL;
}

int holy_bwrap_probe(const char *program)
{
    /* the smallest run that proves both halves: the program answers, and this host
       gives it the namespaces a trial is made of. a probe that only looked for the
       file would report a host that then refuses the unshare */
    char *const probe[] = {
        (char *)program, (char *)"--clearenv", (char *)"--unshare-user",
        (char *)"--unshare-pid", (char *)"--unshare-ipc", (char *)"--unshare-uts",
        (char *)"--new-session", (char *)"--ro-bind", (char *)"/", (char *)"/",
        (char *)"--", (char *)"/bin/true", NULL
    };
    pid_t child;
    int status = 0;
    if (!program) return 6;
    child = fork();
    if (child < 0) return 6;
    if (!child) {
        execv(probe[0], probe);
        _exit(errno == ENOENT ? 127 : 126);
    }
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) continue;
    if (WIFEXITED(status) && !WEXITSTATUS(status)) return 0;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 127)
        fprintf(stderr, "holypkg: %s: %s\n", program, strerror(ENOENT));
    else
        fprintf(stderr, "holypkg: %s cannot give a process its namespaces: %s\n",
                program, WIFEXITED(status) && WEXITSTATUS(status) == 126
                             ? "not executable" : "the host refused");
    return 6;
}

int holy_bwrap_exec(struct holy_bwrap *bwrap, char *const argv[], int output)
{
    pid_t child;
    int status = 0;
    size_t i;
    if (!bwrap || !bwrap->argv || !bwrap->count || !argv || !argv[0]) return 1;
    if (holy_bwrap_add(bwrap, "--")) return 1;
    for (i = 0; argv[i]; ++i)
        if (holy_bwrap_add(bwrap, argv[i])) return 1;
    /* whatever this process has printed belongs before the target's own output, and a
       buffered line flushed at exit would land after it instead */
    fflush(NULL);
    child = fork();
    if (child < 0) {
        fprintf(stderr, "holypkg: could not start the isolation backend\n");
        return 1;
    }
    if (!child) {
        /* the redirection belongs to the target, not to this process: a caller that
           captures a step's output still has to print its own report to its own stdout */
        if (output >= 0 && (dup2(output, STDOUT_FILENO) < 0 ||
                            dup2(output, STDERR_FILENO) < 0))
            _exit(126);
        execv(bwrap->argv[0], bwrap->argv);
        fprintf(stderr, "holypkg: %s: %s\n", bwrap->argv[0], strerror(errno));
        _exit(errno == ENOENT ? 127 : 126);
    }
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) continue;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 1;
}
