#define _POSIX_C_SOURCE 200809L
#include "git.h"
#include "repo.h"
#include "sign.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int hex_id(const char *value)
{
    size_t length = value ? strlen(value) : 0;
    return (length == 40 || length == 64) &&
           strspn(value, "0123456789abcdef") == length;
}

static int digest(const char *value)
{
    return value && strlen(value) == 64 &&
           strspn(value, "0123456789abcdef") == 64;
}

static int git_command(char *const args[], const char *ca_file)
{
    pid_t child = fork();
    int status;
    if (child < 0) return 1;
    if (!child) {
        setenv("GIT_TERMINAL_PROMPT", "0", 1);
        setenv("GIT_CONFIG_NOSYSTEM", "1", 1);
        setenv("GIT_CONFIG_GLOBAL", "/dev/null", 1);
        if (ca_file) setenv("GIT_SSL_CAINFO", ca_file, 1);
        execvp("git", args);
        _exit(errno == ENOENT ? 127 : 126);
    }
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return 1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

static int read_commit(int dir, const char *path, char out[65])
{
    char text[66];
    struct stat st;
    int fd = openat(dir, path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    ssize_t got;
    if (fd < 0) return 0;
    got = fstat(fd, &st) ? -1 : read(fd, text, sizeof text);
    close(fd);
    if (got < 0 || !S_ISREG(st.st_mode) ||
        (got != 41 && got != 65) || text[got - 1] != '\n')
        return 0;
    text[got - 1] = 0;
    if (!hex_id(text)) return 0;
    memcpy(out, text, (size_t)got);
    return 1;
}

static int quote(FILE *out, const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    if (fputc('"', out) == EOF) return 0;
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') {
            if (fputc('\\', out) == EOF || fputc(*p, out) == EOF) return 0;
        } else if (*p <= 32 || *p >= 127) {
            if (fprintf(out, "\\x%02x", (unsigned int)*p) < 0) return 0;
        } else if (fputc(*p, out) == EOF) return 0;
    }
    return fputc('"', out) != EOF;
}

int holy_git_catalog_commit(const char *directory, const char *expected)
{
    char saved[65], head[65];
    int dir = -1, git = -1, ok = 0;
    dir = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || !read_commit(dir, "git-commit", saved)) goto done;
    git = openat(dir, ".git", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (git < 0 || !read_commit(git, "HEAD", head)) goto done;
    ok = !strcmp(saved, head) && (!expected || !strcmp(saved, expected));
done:
    if (git >= 0) close(git);
    if (dir >= 0) close(dir);
    return ok;
}

int holy_git_mirror_source(const char *url, const char *commit,
                           const char *index, const char *output,
                           const char *source_id, const char *public_key,
                           const char *ca_file)
{
    char actual[65], head[65], key_hash[65] = {0};
    char *clone[] = {"git", "clone", "--quiet", "--no-hardlinks", "--no-checkout",
                     "--", (char *)url, (char *)output, NULL};
    char *checkout[] = {"git", "-C", (char *)output, "checkout", "--quiet",
                        "--detach", "--force", (char *)commit, NULL};
    struct stat st;
    int dir = -1, git = -1, record_fd = -1, commit_fd = -1;
    int rc, result = 1;
    FILE *record = NULL;
    if (!url || !*url || !hex_id(commit) || !digest(index) ||
        !output || !*output || !digest(source_id)) return 2;
    if (!lstat(output, &st) || errno != ENOENT) return 2;
    rc = git_command(clone, ca_file);
    if (rc) return rc == 127 ? 6 : 1;
    dir = open(output, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || fstat(dir, &st) || st.st_uid != geteuid() ||
        (st.st_mode & 0022)) goto done;
    rc = git_command(checkout, ca_file);
    if (rc) { result = rc == 127 ? 6 : 4; goto done; }
    git = openat(dir, ".git", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (git < 0 || !read_commit(git, "HEAD", head) || strcmp(head, commit)) {
        result = 4; goto done;
    }
    if (!holy_repo_catalog_index(output, actual) || strcmp(actual, index)) {
        result = 4; goto done;
    }
    if (public_key && !holy_verify_index_keyhash(dir, index, public_key, key_hash)) {
        result = 4; goto done;
    }
    commit_fd = openat(dir, "git-commit", O_WRONLY | O_CREAT | O_EXCL |
                       O_NOFOLLOW | O_CLOEXEC, 0600);
    if (commit_fd < 0 || write(commit_fd, commit, strlen(commit)) != (ssize_t)strlen(commit) ||
        write(commit_fd, "\n", 1) != 1 || fsync(commit_fd)) goto done;
    if (close(commit_fd)) { commit_fd = -1; goto done; }
    commit_fd = -1;
    record_fd = openat(dir, "mirror-origin", O_WRONLY | O_CREAT | O_EXCL |
                       O_NOFOLLOW | O_CLOEXEC, 0600);
    if (record_fd < 0 || !(record = fdopen(record_fd, "w"))) goto done;
    fputs("format holy-mirror-1\nurl ", record);
    if (!quote(record, url) ||
        fprintf(record, "\nindex-sha256 %s\nverification %s\n", index,
                public_key ? "ed25519-pinned-key" : "digest-pinned-unsigned") < 0 ||
        (public_key && fprintf(record, "public-key-sha256 %s\n", key_hash) < 0) ||
        fprintf(record, "source-id %s\n", source_id) < 0 ||
        fflush(record) || fsync(record_fd)) goto done;
    if (fclose(record)) { record = NULL; record_fd = -1; goto done; }
    record = NULL; record_fd = -1;
    if (fsync(dir)) goto done;
    result = 0;
done:
    if (record) fclose(record);
    else if (record_fd >= 0) close(record_fd);
    if (commit_fd >= 0) close(commit_fd);
    if (git >= 0) close(git);
    if (dir >= 0) close(dir);
    if (result) fprintf(stderr, "holypkg: Git catalog mirror incomplete (status %d)\n", result);
    return result;
}
