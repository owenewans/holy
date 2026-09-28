#define _XOPEN_SOURCE 700
#include "run.h"
#include "install.h"
#include "source.h"
#include "state.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct run_choice {
    const char *digest;
    const char *command;
    char *relative;
    int private_path;
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
    path = join_root(canonical, choice.relative);
    if (!path) { result = 1; goto done; }
    if (choice.private_path && !private_path_env(canonical, digest)) {
        result = 1; goto done;
    }
    execv(path, argv + command);
    perror("holypkg: run");
    result = 1;
done:
    if (result == 2)
        fputs("usage: holypkg run SOURCE:PACKAGE [--root DIRECTORY] [--arch ARCH] [--libc LIBC] -- COMMAND [ARGS...]\n", stderr);
    else if (result == 6 && !choice.relative)
        fputs("holypkg: package command unavailable\n", stderr);
    else if (result == 4)
        fputs("holypkg: installed payload changed\n", stderr);
    free(alias); free(name); free(canonical); free(choice.relative); free(path);
    return result;
}
