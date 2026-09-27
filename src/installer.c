#define _XOPEN_SOURCE 700
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

struct install_input {
    char *root;
    char **artifacts;
    size_t count;
    struct stat root_stat;
    char hash[65];
};

static int digest_valid(const char *s)
{
    size_t i;
    if (strlen(s) != 64) return 0;
    for (i = 0; i < 64; ++i)
        if (!((s[i] >= '0' && s[i] <= '9') ||
              (s[i] >= 'a' && s[i] <= 'f'))) return 0;
    return 1;
}

static int hex_digest(const unsigned char *bytes, char output[65])
{
    static const char digits[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < 32; ++i) {
        output[i * 2] = digits[bytes[i] >> 4];
        output[i * 2 + 1] = digits[bytes[i] & 15];
    }
    output[64] = 0;
    return 1;
}

static int hash_string(EVP_MD_CTX *ctx, const char *s)
{
    size_t size = strlen(s), i;
    unsigned char length[8];
    if ((unsigned long long)size != size) return 0;
    for (i = 0; i < sizeof length; ++i)
        length[i] = (unsigned char)((unsigned long long)size >> (i * 8));
    return EVP_DigestUpdate(ctx, length, sizeof length) == 1 &&
           EVP_DigestUpdate(ctx, s, size) == 1;
}

static int config_hash(const struct holy_config *config, char output[65])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char bytes[32];
    unsigned length;
    size_t i, j;
    int ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    for (i = 0; i < config->count && ok; ++i) {
        const struct holy_entry *e = &config->entries[i];
        ok = hash_string(ctx, e->section) && hash_string(ctx, e->key);
        for (j = 0; j < e->count && ok; ++j) ok = hash_string(ctx, e->values[j]);
    }
    if (ok) ok = EVP_DigestFinal_ex(ctx, bytes, &length) == 1 && length == 32;
    EVP_MD_CTX_free(ctx);
    return ok && hex_digest(bytes, output);
}

static const char *field(const struct holy_config *config, const char *section,
                         const char *key)
{
    size_t i;
    for (i = 0; i < config->count; ++i)
        if (!strcmp(config->entries[i].section, section) &&
            !strcmp(config->entries[i].key, key))
            return config->entries[i].values[0];
    return NULL;
}

static int load_input(const char *path, struct holy_config *config,
                      struct install_input *input)
{
    const char *root;
    char *error = NULL;
    size_t i, j;
    if (!holy_config_load(path, config, &error)) {
        fprintf(stderr, "holyinstall: %s\n", error ? error : "invalid config");
        free(error);
        return 2;
    }
    root = field(config, "install", "root");
    if (!root) { fputs("holyinstall: [install] root is required\n", stderr); return 2; }
    input->root = realpath(root, NULL);
    if (!input->root || stat(input->root, &input->root_stat) ||
        !S_ISDIR(input->root_stat.st_mode)) {
        fputs("holyinstall: target root must be an existing directory\n", stderr);
        return 6;
    }
    if (!strcmp(input->root, "/")) {
        fputs("holyinstall: host / is not an installation target\n", stderr);
        return 2;
    }
    input->artifacts = calloc(config->count ? config->count : 1, sizeof *input->artifacts);
    if (!input->artifacts) return 1;
    for (i = 0; i < config->count; ++i) {
        const struct holy_entry *e = &config->entries[i];
        if (strcmp(e->section, "install") || strcmp(e->key, "artifact")) continue;
        if (input->count >= 1024) {
            fputs("holyinstall: at most 1024 artifacts are supported\n", stderr);
            return 2;
        }
        if (!digest_valid(e->values[0])) {
            fprintf(stderr, "holyinstall: invalid artifact at %s:%zu\n", e->file, e->line);
            return 2;
        }
        for (j = 0; j < input->count; ++j)
            if (!strcmp(input->artifacts[j], e->values[0])) {
                fprintf(stderr, "holyinstall: duplicate artifact at %s:%zu\n", e->file, e->line);
                return 2;
            }
        input->artifacts[input->count] = strdup(e->values[0]);
        if (!input->artifacts[input->count]) return 1;
        ++input->count;
    }
    if (!input->count) { fputs("holyinstall: [install] needs artifact entries\n", stderr); return 2; }
    if (!config_hash(config, input->hash)) return 1;
    return 0;
}

static int run_package_manager(const char *binary, const struct install_input *input,
                               const char *approved, char **output)
{
    char **args;
    size_t i, count = input->count + (approved ? 7 : 6), used = 0, capacity = 0;
    char *buffer = NULL;
    int pipefd[2] = {-1, -1}, status, rc = 1;
    pid_t child;
    args = calloc(count, sizeof *args);
    if (!args) return 1;
    args[0] = (char *)binary;
    args[1] = "db";
    args[2] = approved ? "apply-set" : "plan-set";
    i = 3;
    if (approved) args[i++] = (char *)approved;
    for (size_t j = 0; j < input->count; ++j) args[i++] = (char *)input->artifacts[j];
    args[i++] = "--root";
    args[i++] = input->root;
    if (pipe(pipefd)) goto done;
    child = fork();
    if (child < 0) goto done;
    if (!child) {
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(1);
        close(pipefd[1]);
        execv(binary, args);
        _exit(127);
    }
    close(pipefd[1]); pipefd[1] = -1;
    for (;;) {
        ssize_t got;
        char *next;
        if (used == capacity) {
            size_t new_capacity = capacity ? capacity * 2 : 4096;
            if (new_capacity > 16 * 1024 * 1024) { rc = 1; break; }
            next = realloc(buffer, new_capacity + 1);
            if (!next) { rc = 1; break; }
            buffer = next; capacity = new_capacity;
        }
        got = read(pipefd[0], buffer + used, capacity - used);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) { rc = 1; break; }
        if (!got) { rc = 0; break; }
        used += (size_t)got;
    }
    close(pipefd[0]); pipefd[0] = -1;
    while (waitpid(child, &status, 0) < 0) if (errno != EINTR) goto done;
    if (rc || !WIFEXITED(status)) { rc = 1; goto done; }
    rc = WEXITSTATUS(status);
    if (rc) goto done;
    if (!buffer) { rc = 1; goto done; }
    buffer[used] = 0;
    if (memchr(buffer, 0, used)) { rc = 1; goto done; }
    *output = buffer; buffer = NULL;
done:
    if (pipefd[0] >= 0) close(pipefd[0]);
    if (pipefd[1] >= 0) close(pipefd[1]);
    free(buffer); free(args);
    return rc;
}

static int set_hash(const char *output, char hash[65])
{
    const char *marker = " sha256 ", *line = output, *end;
    int found = 0;
    while (*line) {
        end = strchr(line, '\n');
        if (!end) return 0;
        if (!strncmp(line, "plan-set ", 9)) {
            const char *at = strstr(line, marker);
            if (!at || at >= end || end - at != 8 + 64 + 10 ||
                memcmp(at + 8 + 64, " read-only", 10)) return 0;
            memcpy(hash, at + 8, 64); hash[64] = 0;
            if (!digest_valid(hash) || ++found != 1) return 0;
        }
        line = end + 1;
    }
    return found == 1;
}

static int quote(FILE *stream, const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    if (fputc('"', stream) == EOF) return 0;
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') {
            if (fputc('\\', stream) == EOF) return 0;
            if (fputc(*p, stream) == EOF) return 0;
        } else if (*p == '\n' || *p == '\r' || *p == '\t') {
            if (fprintf(stream, "\\x%02x", *p) < 0) return 0;
        } else if (fputc(*p, stream) == EOF) return 0;
    }
    return fputc('"', stream) != EOF;
}

static int sync_parent(const char *path)
{
    const char *slash = strrchr(path, '/');
    char *directory = slash ? strndup(path, (size_t)(slash - path)) : strdup(".");
    int fd, ok;
    if (!directory) return 0;
    if (!*directory) { free(directory); directory = strdup("/"); }
    if (!directory) return 0;
    fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    free(directory);
    if (fd < 0) return 0;
    ok = !fsync(fd);
    if (close(fd)) ok = 0;
    return ok;
}

static int write_plan(const char *path, const struct install_input *input,
                      const char *hash)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    FILE *stream;
    size_t i;
    int ok = 1;
    if (fd < 0) { perror("holyinstall: plan"); return 1; }
    stream = fdopen(fd, "w");
    if (!stream) { close(fd); unlink(path); return 1; }
    if (fprintf(stream, "[install-plan]\nformat holy-install-plan-1\nroot ") < 0 ||
        !quote(stream, input->root) ||
        fprintf(stream, "\ndevice %ju\ninode %ju\nconfig-sha256 %s\nset-sha256 %s\n",
                (uintmax_t)input->root_stat.st_dev, (uintmax_t)input->root_stat.st_ino,
                input->hash, hash) < 0) ok = 0;
    for (i = 0; i < input->count && ok; ++i)
        if (fprintf(stream, "artifact %s\n", input->artifacts[i]) < 0) ok = 0;
    if (fflush(stream) || fsync(fd)) ok = 0;
    if (fclose(stream)) ok = 0;
    if (ok) ok = sync_parent(path);
    if (!ok) unlink(path);
    return ok ? 0 : 1;
}

static int check_plan(const char *path, struct install_input *input,
                      char hash[65])
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    FILE *stream;
    struct stat plan_stat;
    char *line = NULL, *resolved = NULL;
    size_t capacity = 0, row = 0;
    ssize_t length;
    int rc = 2;
    if (fd < 0) { perror("holyinstall: plan"); return 2; }
    if (fstat(fd, &plan_stat) || !S_ISREG(plan_stat.st_mode) ||
        plan_stat.st_size < 0 || plan_stat.st_size > 2 * 1024 * 1024) {
        close(fd); fputs("holyinstall: invalid plan file\n", stderr); return 2;
    }
    stream = fdopen(fd, "r");
    if (!stream) { close(fd); return 1; }
    while ((length = getline(&line, &capacity, stream)) >= 0) {
        char **v = NULL, *error = NULL;
        char expected[64];
        size_t count = 0;
        ++row;
        if (length > 1024 * 1024 || memchr(line, 0, (size_t)length) ||
            !holy_lex(line, (size_t)length, &v, &count, path, row, &error)) {
            free(error); holy_tokens_free(v, count); goto done;
        }
        if (row == 1) {
            if (count != 1 || strcmp(v[0], "[install-plan]")) {
                holy_tokens_free(v, count); goto done;
            }
        } else if (count != 2) {
            holy_tokens_free(v, count); goto done;
        } else if (row == 2) {
            if (strcmp(v[0], "format") || strcmp(v[1], "holy-install-plan-1")) {
                holy_tokens_free(v, count); goto done;
            }
        } else if (row == 3) {
            if (strcmp(v[0], "root") || !(input->root = strdup(v[1])) ||
                !(resolved = realpath(input->root, NULL)) ||
                strcmp(resolved, input->root) || !strcmp(input->root, "/") ||
                stat(input->root, &input->root_stat) ||
                !S_ISDIR(input->root_stat.st_mode)) {
                holy_tokens_free(v, count); goto done;
            }
        } else if (row == 4 || row == 5) {
            snprintf(expected, sizeof expected, "%ju", row == 4 ?
                (uintmax_t)input->root_stat.st_dev : (uintmax_t)input->root_stat.st_ino);
            if (strcmp(v[0], row == 4 ? "device" : "inode") || strcmp(v[1], expected)) {
                holy_tokens_free(v, count); goto done;
            }
        } else if (row == 6) {
            if (strcmp(v[0], "config-sha256") || !digest_valid(v[1])) {
                holy_tokens_free(v, count); goto done;
            }
            memcpy(input->hash, v[1], 65);
        } else if (row == 7) {
            if (strcmp(v[0], "set-sha256") || !digest_valid(v[1])) {
                holy_tokens_free(v, count); goto done;
            }
            memcpy(hash, v[1], 65);
        } else {
            char **next;
            size_t i;
            if (strcmp(v[0], "artifact") || !digest_valid(v[1]) ||
                input->count >= 1024) {
                holy_tokens_free(v, count); goto done;
            }
            for (i = 0; i < input->count; ++i)
                if (!strcmp(v[1], input->artifacts[i])) break;
            if (i != input->count || input->count == (size_t)-1 / sizeof *next ||
                !(next = realloc(input->artifacts, (input->count + 1) * sizeof *next))) {
                holy_tokens_free(v, count); goto done;
            }
            input->artifacts = next;
            input->artifacts[input->count] = strdup(v[1]);
            if (!input->artifacts[input->count]) { holy_tokens_free(v, count); goto done; }
            ++input->count;
        }
        holy_tokens_free(v, count);
    }
    if (ferror(stream) || row != 7 + input->count || !input->count) goto done;
    rc = 0;
done:
    free(line);
    free(resolved);
    fclose(stream);
    if (rc) fputs("holyinstall: plan inputs changed or invalid\n", stderr);
    return rc;
}

int main(int argc, char **argv)
{
    const char *config_path = NULL, *plan_path = NULL;
    const char *binary = "/usr/bin/holypkg";
    struct holy_config config = {0};
    struct install_input input = {0};
    char hash[65], *output = NULL;
    int i, apply = 0, rc;
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--config") && ++i < argc && !config_path)
            config_path = argv[i];
        else if (!strcmp(argv[i], "--plan") && ++i < argc && !plan_path && !apply)
            plan_path = argv[i];
        else if (!strcmp(argv[i], "--apply") && ++i < argc && !plan_path) {
            plan_path = argv[i]; apply = 1;
        } else if (!strcmp(argv[i], "--holypkg") && ++i < argc)
            binary = argv[i];
        else goto usage;
    }
    if (!plan_path || (apply ? config_path != NULL : config_path == NULL)) goto usage;
    if (apply) {
        rc = check_plan(plan_path, &input, hash);
        if (rc) goto done;
        rc = run_package_manager(binary, &input, hash, &output);
        if (!rc && fputs(output, stdout) == EOF) rc = 1;
    } else {
        rc = load_input(config_path, &config, &input);
        if (rc) goto done;
        rc = run_package_manager(binary, &input, NULL, &output);
        if (rc) goto done;
        if (!set_hash(output, hash)) { rc = 1; goto done; }
        if (fputs(output, stdout) == EOF) { rc = 1; goto done; }
        rc = write_plan(plan_path, &input, hash);
        if (!rc) printf("holyinstall plan %s set %s\n", plan_path, hash);
    }
done:
    for (size_t j = 0; j < input.count; ++j) free(input.artifacts[j]);
    free(output); free(input.root); free(input.artifacts); holy_config_free(&config);
    return rc;
usage:
    fputs("usage: holyinstall --config FILE --plan NEW_FILE [--holypkg FILE] | --apply PLAN [--holypkg FILE]\n", stderr);
    return 2;
}
