#define _GNU_SOURCE
#include "trial.h"
#include "bwrap.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
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

static int trial_run(char *const argv[], const char *root);

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
    return trial_run(argv, root);
}

static int trial_run(char *const argv[], const char *root)
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

/* the volatile trees of a live system, which a copy of the filesystem for a trial has
   no use for and cannot reproduce */
static const char *const skipped_trees[] = { "proc", "sys", "dev", "run" };

/* one directory level, with the entries a trial root needs and nothing that would
   escape it. */
static int copy_level(const char *from, const char *to, struct holy_trial_copy *copy)
{
    DIR *entries = opendir(from);
    struct dirent *entry;
    int ok = 1;
    if (!entries) return 0;
    errno = 0;
    while ((entry = readdir(entries)) != NULL) {
        char source[4096], target[4096];
        struct stat st;
        size_t i;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if ((size_t)snprintf(source, sizeof source, "%s/%s", from, entry->d_name) >= sizeof source ||
            (size_t)snprintf(target, sizeof target, "%s/%s", to, entry->d_name) >= sizeof source) {
            ++copy->refused;
            continue;
        }
        if (lstat(source, &st)) { ++copy->refused; continue; }
        for (i = 0; i < sizeof skipped_trees / sizeof *skipped_trees; ++i)
            if (!strcmp(entry->d_name, skipped_trees[i])) break;
        if (i < sizeof skipped_trees / sizeof *skipped_trees) continue;
        if (S_ISDIR(st.st_mode)) {
            if (mkdir(target, st.st_mode & 07777) && errno != EEXIST) { ++copy->refused; continue; }
            ++copy->directories;
            if (!copy_level(source, target, copy)) ok = 0;
        } else if (S_ISREG(st.st_mode)) {
            int in = open(source, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            int out = open(target, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                           st.st_mode & 07777);
            char buffer[65536];
            ssize_t got;
            if (in < 0 || out < 0 || (out >= 0 && fchmod(out, st.st_mode & 07777))) {
                ++copy->refused;
            } else {
                while ((got = read(in, buffer, sizeof buffer)) > 0) {
                    ssize_t at = 0;
                    copy->bytes += (size_t)got;
                    while (at < got) {
                        ssize_t written = write(out, buffer + at, (size_t)(got - at));
                        if (written < 0) { if (errno == EINTR) continue; break; }
                        at += written;
                    }
                    if (at < got) break;
                }
                ++copy->files;
            }
            if (in >= 0) close(in);
            if (out >= 0) close(out);
        } else if (S_ISLNK(st.st_mode)) {
            char link[4096];
            ssize_t length = readlink(source, link, sizeof link - 1);
            if (length < 0) ++copy->refused;
            else {
                link[length] = 0;
                if (symlink(link, target)) ++copy->refused;
                else ++copy->files;
            }
        } else {
            ++copy->refused;
        }
        errno = 0;
    }
    if (errno) ok = 0;
    closedir(entries);
    return ok;
}

int holy_trial_work_inside(const char *work, const char *root)
{
    size_t root_length;
    if (!work || !root) return 0;
    root_length = strlen(root);
    while (root_length > 1 && root[root_length - 1] == '/') --root_length;
    return !strncmp(work, root, root_length) &&
           (work[root_length] == '/' || work[root_length] == 0);
}

char *holy_trial_copy_root(const char *root, const char *work, struct holy_trial_copy *copy)
{
    char *path;
    struct stat st;
    size_t length;
    if (!root || !work || work[0] != '/' || !copy) return NULL;
    length = strlen(work) + 16;
    path = malloc(length);
    if (!path) return NULL;
    snprintf(path, length, "%s/trial-root", work);
    /* the caller named a work directory, so it is created rather than refused */
    if (mkdir(work, 0700) && errno != EEXIST) { free(path); return NULL; }
    if (mkdir(path, 0700) && errno != EEXIST) { free(path); return NULL; }
    if (lstat(root, &st) || !S_ISDIR(st.st_mode) ||
        !copy_level(root, path, copy)) { free(path); return NULL; }
    return path;
}
