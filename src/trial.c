#define _GNU_SOURCE
#include "trial.h"
#include "bwrap.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* a root trial is a decision about what the command can see, so the node set, the
   tmpfs sizes and the namespace set are fixed here rather than chosen per call. the
   backend is bubblewrap, so the isolation is its flags and this file is the list of
   what the flags are asked for. */

/* the directories a command resolves its interpreter and its libraries through. a
   merged /usr tree reaches the same binaries through all of them, so each is bound
   rather than only /usr */
static const char *const trial_directories[] = {
    "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"
};

/* the sizes the man page states, which are the point at which a runaway command is a
   failed check rather than a full host */
static const struct { const char *path; unsigned long long bytes; } trial_volumes[] = {
    { "/run", 16ull * 1024 * 1024 },
    { "/tmp", 64ull * 1024 * 1024 },
    { "/home", 1ull * 1024 * 1024 }
};

static int is_directory(const char *path)
{
    struct stat st;
    return !lstat(path, &st) && S_ISDIR(st.st_mode);
}

/* a prepared root's own copy first, so the command resolves its interpreter and its
   libraries from the copy rather than from the host. a directory the copy does not
   have keeps the host one, which is what a trial without it needs. the backend builds
   its new root from exactly these binds, so / inside the trial is the copy's own
   filesystem and the command needs no directory of its own to begin in. */
static int bind_directories(struct holy_bwrap *bwrap, const char *root)
{
    char source[4096];
    size_t i;
    for (i = 0; i < sizeof trial_directories / sizeof *trial_directories; ++i) {
        const char *name = trial_directories[i];
        if (root && (size_t)snprintf(source, sizeof source, "%s%s", root, name) <
                      sizeof source && is_directory(source)) {
            if (holy_bwrap_bind(bwrap, 0, source, name)) return 1;
            continue;
        }
        if (!is_directory(name)) continue;
        if (holy_bwrap_bind(bwrap, 0, name, name)) return 1;
    }
    return 0;
}

int holy_trial_command(char *const argv[])
{
    return holy_trial_command_at(argv, NULL);
}

int holy_trial_command_at(char *const argv[], const char *root)
{
    struct holy_bwrap bwrap;
    char *program;
    size_t i;
    int status;
    if (!argv || !argv[0] || !*argv[0]) return 2;
    if (root && root[0] != '/') return 2;
    /* the host runs the backend. a target that has no bubblewrap of its own is a fact
       for check to report about the target, not a reason this trial cannot run */
    program = holy_bwrap_program();
    if (!program) {
        fputs("holypkg: root trial: no bubblewrap on the host\n", stderr);
        return 6;
    }
    holy_bwrap_init(&bwrap, program);
    free(program);
    /* the host network stack stays, since the man page promises a network only where
       the command makes one. the isolation and the empty environment come first, since
       the backend reads its arguments in order */
    holy_bwrap_isolate(&bwrap, 1, 1);
    if (bind_directories(&bwrap, root)) { holy_bwrap_free(&bwrap); return 1; }
    /* --dev brings the standard character nodes and the standard stream links, which
       is the /dev a controlled trial promises and the one a host that refuses mknod
       inside a user namespace still gives */
    if (holy_bwrap_add(&bwrap, "--dev") || holy_bwrap_add(&bwrap, "/dev") ||
        holy_bwrap_add(&bwrap, "--proc") || holy_bwrap_add(&bwrap, "/proc")) {
        holy_bwrap_free(&bwrap);
        return 1;
    }
    for (i = 0; i < sizeof trial_volumes / sizeof *trial_volumes; ++i)
        if (holy_bwrap_tmpfs(&bwrap, trial_volumes[i].path, trial_volumes[i].bytes)) {
            holy_bwrap_free(&bwrap);
            return 1;
        }
    /* a probe writes to the streams it was given, which are the caller's own */
    status = holy_bwrap_exec(&bwrap, argv, -1);
    holy_bwrap_free(&bwrap);
    return status;
}
