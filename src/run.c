#define _GNU_SOURCE
#include "run.h"
#include "install.h"
#include "source.h"
#include "state.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#undef strchr

#define RUN_VIEW_LIMIT 32

struct run_view { char *public_path, *private_path; };

struct run_choice {
    const char *digest;
    const char *command;
    char *relative;
    int private_path;
    struct run_view views[RUN_VIEW_LIMIT];
    size_t view_count;
};

static char *join(const char *left, const char *right)
{
    size_t a = strlen(left), b = strlen(right);
    char *result;
    if (a > (size_t)-1 - b - 1) return NULL;
    result = malloc(a + b + 1);
    if (result) { memcpy(result, left, a); memcpy(result + a, right, b + 1); }
    return result;
}

static char *join_root(const char *root, const char *relative)
{
    char *prefix, *path;
    if (!strcmp(root, "/")) return join(root, relative);
    prefix = join(root, "/");
    if (!prefix) return NULL;
    path = join(prefix, relative);
    free(prefix);
    return path;
}

static int valid_name(const char *name)
{
    return name && *name && strcmp(name, ".") && strcmp(name, "..") &&
           !strchr(name, '/');
}

static int valid_public_view(const char *path)
{
    static const char *const roots[] = {"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/"};
    const char *p;
    size_t i;
    if (!path) return 0;
    for (i = 0; i < sizeof roots / sizeof roots[0]; ++i)
        if (!strncmp(path, roots[i], strlen(roots[i]))) break;
    if (i == sizeof roots / sizeof roots[0]) return 0;
    p = path + strlen(roots[i]);
    while (*p) {
        const char *end = strchr(p, '/');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        if (!n || (n == 1 && *p == '.') || (n == 2 && !memcmp(p, "..", 2))) return 0;
        if (!end) return 1;
        p = end + 1;
    }
    return 0;
}

static int add_view(struct run_choice *choice, const char *spec)
{
    const char *equals = strchr(spec, '=');
    struct run_view *view;
    size_t i;
    if (!equals || choice->view_count == RUN_VIEW_LIMIT) return 0;
    view = &choice->views[choice->view_count];
    view->public_path = strndup(spec, (size_t)(equals - spec));
    view->private_path = strdup(equals + 1);
    if (!view->public_path || !view->private_path ||
        !valid_public_view(view->public_path) ||
        strncmp(view->private_path, "/usr/lib/holy/private/", 22) ||
        !valid_public_view(view->private_path)) return 0;
    for (i = 0; i < choice->view_count; ++i)
        if (!strcmp(choice->views[i].public_path, view->public_path)) return 0;
    ++choice->view_count;
    return 1;
}

static int select_path(void *context, int root, int instance, const char *digest)
{
    static const char *const dirs[] = {"usr/bin/", "bin/", "usr/sbin/", "sbin/"};
    struct run_choice *choice = context;
    const char *name = choice->command;
    char *private_base = NULL, *public_path = NULL;
    size_t i, count = sizeof dirs / sizeof dirs[0];
    int files = -1, status = 0;
    if (strcmp(digest, choice->digest)) return 0;
    files = openat(instance, "files", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (files < 0) return 1;
    private_base = join("usr/lib/holy/private/", digest);
    if (private_base) {
        char *next = join(private_base, "/");
        free(private_base); private_base = next;
    }
    if (!private_base) { status = 1; goto done; }
    if (name[0] == '/') {
        const char *relative = name + 1;
        for (i = 0; i < count; ++i)
            if (!strncmp(relative, dirs[i], strlen(dirs[i])) &&
                valid_name(relative + strlen(dirs[i]))) break;
        if (i == count) { status = 2; goto done; }
        public_path = strdup(relative);
    } else {
        if (!valid_name(name)) { status = 2; goto done; }
    }
    if (name[0] == '/' && !public_path) { status = 1; goto done; }
    for (i = 0; i < (public_path ? 2 : count * 2); ++i) {
        char *candidate, *base;
        int private_candidate = public_path ? i == 0 : i < count;
        const char *suffix = public_path ? public_path : dirs[i % count];
        base = private_candidate ? private_base : "";
        candidate = join(base, suffix);
        if (candidate && !public_path) {
            char *next = join(candidate, name);
            free(candidate); candidate = next;
        }
        if (!candidate) { status = 1; goto done; }
        status = holy_install_manifest_executable(files, candidate);
        if (status > 0) {
            if (holy_install_check_manifest(files, root) != 1) {
                free(candidate); status = 4; goto done;
            }
            choice->relative = candidate;
            choice->private_path = private_candidate;
            for (i = 0; i < choice->view_count; ++i) {
                int owned = holy_install_manifest_owns(files, choice->views[i].private_path + 1);
                if (owned != 1) { status = owned < 0 ? 1 : 6; goto done; }
            }
            status = 0;
            goto done;
        }
        free(candidate);
        if (status < 0) { status = 1; goto done; }
    }
    status = 6;
done:
    free(private_base); free(public_path);
    close(files);
    return status;
}

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

static int enter_view_namespace(void)
{
    char mapping[80];
    uid_t uid = geteuid();
    gid_t gid = getegid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS)) return 0;
    snprintf(mapping, sizeof mapping, "%lu %lu 1\n", (unsigned long)uid, (unsigned long)uid);
    if (!write_kernel_file("/proc/self/uid_map", mapping) ||
        !write_kernel_file("/proc/self/setgroups", "deny\n")) return 0;
    snprintf(mapping, sizeof mapping, "%lu %lu 1\n", (unsigned long)gid, (unsigned long)gid);
    return write_kernel_file("/proc/self/gid_map", mapping) &&
           !mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
}

static int view_file(int root, const char *path, struct stat *st)
{
    struct open_how how = {0};
    int fd;
    how.flags = O_PATH | O_CLOEXEC;
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS;
    fd = (int)syscall(SYS_openat2, root, path + 1, &how, sizeof how);
    if (fd < 0) return -1;
    if (fstat(fd, st) || !S_ISREG(st->st_mode)) { close(fd); return -1; }
    return fd;
}

static int apply_views(const char *root, const struct run_choice *choice)
{
    size_t i;
    int rootfd = open(root, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (rootfd < 0) return 6;
    for (i = 0; i < choice->view_count; ++i) {
        struct stat original, replacement;
        int source = view_file(rootfd, choice->views[i].private_path, &replacement);
        int target = view_file(rootfd, choice->views[i].public_path, &original);
        char source_descriptor[64], target_descriptor[64];
        if (source < 0 || target < 0 ||
            (strncmp(choice->views[i].public_path, "/usr/lib/", 9) &&
             !(replacement.st_mode & 0111))) {
            if (source >= 0) close(source);
            if (target >= 0) close(target);
            close(rootfd); return 6;
        }
        snprintf(source_descriptor, sizeof source_descriptor, "/proc/self/fd/%d", source);
        snprintf(target_descriptor, sizeof target_descriptor, "/proc/self/fd/%d", target);
        if (mount(source_descriptor, target_descriptor, NULL, MS_BIND, NULL)) {
            perror("holypkg: view bind mount");
            close(source); close(target); close(rootfd); return 6;
        }
        close(source); close(target);
    }
    close(rootfd);
    return 0;
}

static int private_path_env(const char *root, const char *digest)
{
    static const char *const dirs[] = {"usr/bin", "bin", "usr/sbin", "sbin"};
    const char *old = getenv("PATH");
    char *base = join_root(root, "usr/lib/holy/private/");
    char *prefix = NULL, *value = NULL;
    size_t i, length = 0, old_length;
    int ok = 0;
    if (!old || !*old) old = "/usr/bin:/bin";
    old_length = strlen(old);
    if (!base) return 0;
    prefix = join(base, digest);
    free(base);
    if (!prefix) return 0;
    for (i = 0; i < sizeof dirs / sizeof dirs[0]; ++i)
        if (strlen(prefix) > (size_t)-1 - strlen(dirs[i]) - length - 2) goto done;
        else length += strlen(prefix) + strlen(dirs[i]) + 2;
    if (length > (size_t)-1 - old_length - 1) goto done;
    value = malloc(length + old_length + 1);
    if (!value) goto done;
    value[0] = 0;
    for (i = 0; i < sizeof dirs / sizeof dirs[0]; ++i) {
        strcat(value, prefix); strcat(value, "/"); strcat(value, dirs[i]); strcat(value, ":");
    }
    strcat(value, old);
    ok = !setenv("PATH", value, 1);
done:
    free(prefix); free(value);
    return ok;
}

int holy_run(int argc, char **argv)
{
    const char *root = "/", *arch = NULL, *libc = NULL, *separator;
    char source_id[65], digest[65], *alias = NULL, *name = NULL, *canonical = NULL;
    char *path = NULL;
    struct run_choice choice = {0};
    unsigned long long generation;
    int i, command = -1, result = 2;
    if (argc < 5 || !(separator = strchr(argv[2], ':')) || separator == argv[2] ||
        !separator[1] || strchr(separator + 1, ':')) goto done;
    alias = strndup(argv[2], (size_t)(separator - argv[2]));
    name = strdup(separator + 1);
    if (!alias || !name) { result = 1; goto done; }
    for (i = 3; i < argc; ++i) {
        if (!strcmp(argv[i], "--")) { command = i + 1; break; }
        if (!strcmp(argv[i], "--root") && i + 1 < argc && !strcmp(root, "/"))
            root = argv[++i];
        else if (!strcmp(argv[i], "--arch") && i + 1 < argc && !arch)
            arch = argv[++i];
        else if (!strcmp(argv[i], "--libc") && i + 1 < argc && !libc)
            libc = argv[++i];
        else if (!strcmp(argv[i], "--view") && i + 1 < argc && add_view(&choice, argv[i + 1])) ++i;
        else goto done;
    }
    if (command < 0 || command == argc || !argv[command][0]) goto done;
    canonical = realpath(root, NULL);
    if (!canonical) { result = 6; goto done; }
    if (!strcmp(alias, "local")) strcpy(source_id, "-");
    else {
        result = holy_source_known_id(canonical, alias, source_id);
        if (result) goto done;
    }
    result = holy_state_find_slot(canonical, source_id, name, arch, libc, digest);
    if (result) goto done;
    choice.digest = digest;
    choice.command = argv[command];
    result = holy_state_visit(canonical, select_path, &choice, &generation);
    if (result) goto done;
    if (!choice.relative) { result = 6; goto done; }
    path = join_root(choice.view_count ? "/" : canonical, choice.relative);
    if (!path) { result = 1; goto done; }
    if (choice.private_path && !private_path_env(choice.view_count ? "/" : canonical, digest)) {
        result = 1; goto done;
    }
    if (choice.view_count) {
        if (!enter_view_namespace()) {
            fputs("holypkg: user or mount namespace unavailable for path view\n", stderr);
            result = 6; goto done;
        }
        result = apply_views(canonical, &choice);
        if (result) goto done;
        if (chroot(canonical) || chdir("/")) {
            perror("holypkg: view target root");
            result = 6; goto done;
        }
    }
    execv(path, argv + command);
    perror("holypkg: run");
    result = 1;
done:
    if (result == 2)
        fputs("usage: holypkg run SOURCE:PACKAGE [--root DIRECTORY] [--arch ARCH] [--libc LIBC] [--view PUBLIC=PRIVATE ...] -- COMMAND [ARGS...]\n", stderr);
    else if (result == 6 && !choice.relative)
        fputs("holypkg: package command unavailable\n", stderr);
    else if (result == 4)
        fputs("holypkg: installed payload changed\n", stderr);
    free(alias); free(name); free(canonical); free(choice.relative); free(path);
    for (i = 0; i < RUN_VIEW_LIMIT; ++i) {
        free(choice.views[i].public_path);
        free(choice.views[i].private_path);
    }
    return result;
}
