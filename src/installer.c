#define _XOPEN_SOURCE 700
#include "config.h"
#include "disk.h"

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

struct menu_state {
    char *root;
    char **artifacts;
    size_t count;
};

static void free_input(struct install_input *input)
{
    size_t i;
    for (i = 0; i < input->count; ++i) free(input->artifacts[i]);
    free(input->artifacts);
    free(input->root);
    memset(input, 0, sizeof *input);
}

static void free_menu(struct menu_state *menu)
{
    size_t i;
    for (i = 0; i < menu->count; ++i) free(menu->artifacts[i]);
    free(menu->artifacts);
    free(menu->root);
}

static int menu_load(const char *path, struct menu_state *menu)
{
    struct holy_config config = {0};
    char *error = NULL;
    size_t i;
    if (access(path, F_OK) && errno == ENOENT) return 0;
    if (!holy_config_load(path, &config, &error)) {
        fprintf(stderr, "holyinstall: %s\n", error ? error : "invalid config");
        free(error); return 2;
    }
    for (i = 0; i < config.count; ++i) {
        const struct holy_entry *e = &config.entries[i];
        char **next;
        if (strcmp(e->section, "install")) {
            fputs("holyinstall: text menu can edit only [install] configs\n", stderr);
            holy_config_free(&config); return 2;
        }
        if (!strcmp(e->key, "root")) {
            menu->root = strdup(e->values[0]);
            if (!menu->root) { holy_config_free(&config); return 1; }
        } else {
            next = realloc(menu->artifacts, (menu->count + 1) * sizeof *next);
            if (!next) { holy_config_free(&config); return 1; }
            menu->artifacts = next;
            menu->artifacts[menu->count] = strdup(e->values[0]);
            if (!menu->artifacts[menu->count]) { holy_config_free(&config); return 1; }
            ++menu->count;
        }
    }
    holy_config_free(&config);
    return 0;
}

static int menu_write(FILE *stream, const struct menu_state *menu)
{
    size_t i;
    if (fputs("[install]\n", stream) == EOF) return 0;
    if (menu->root && (fputs("root ", stream) == EOF ||
                       !quote(stream, menu->root) || fputc('\n', stream) == EOF)) return 0;
    for (i = 0; i < menu->count; ++i)
        if (fprintf(stream, "artifact %s\n", menu->artifacts[i]) < 0) return 0;
    return 1;
}

static int menu_config_file(const char *path, const struct menu_state *menu)
{
    size_t size = strlen(path);
    char *temporary;
    FILE *stream;
    int fd, ok;
    if (size > (size_t)-1 - 12) return 0;
    temporary = malloc(size + 12);
    if (!temporary) return 0;
    snprintf(temporary, size + 12, "%s.XXXXXX", path);
    fd = mkstemp(temporary);
    if (fd < 0) { free(temporary); return 0; }
    stream = fdopen(fd, "w");
    if (!stream) { close(fd); unlink(temporary); free(temporary); return 0; }
    ok = menu_write(stream, menu);
    if (fflush(stream) || fsync(fd)) ok = 0;
    if (fclose(stream)) ok = 0;
    if (ok) ok = !rename(temporary, path) && sync_parent(path);
    if (!ok) unlink(temporary);
    free(temporary);
    return ok;
}

static int menu_line(const char *prompt, char **answer)
{
    size_t capacity = 0;
    ssize_t n;
    fputs(prompt, stdout);
    if (fflush(stdout)) return 0;
    n = getline(answer, &capacity, stdin);
    if (n < 0) return 0;
    if (n && (*answer)[n - 1] == '\n') (*answer)[n - 1] = 0;
    return 1;
}

static void menu_path(const char *path)
{
    const unsigned char *p = (const unsigned char *)path;
    for (; *p; ++p)
        if (*p < 32 || *p == 127) printf("\\x%02x", *p);
        else putchar(*p);
}

static int menu_packages(struct menu_state *menu, int *dirty)
{
    for (;;) {
        char *answer = NULL;
        size_t i;
        int found = 0;
        puts("Packages: first entry is the explicit root package");
        for (i = 0; i < menu->count; ++i) printf("%zu %s\n", i + 1, menu->artifacts[i]);
        if (!menu_line("a add, d delete, b back > ", &answer)) { free(answer); return 0; }
        if (!strcmp(answer, "b")) { free(answer); return 1; }
        if (!strcmp(answer, "a")) {
            char *digest = NULL, **next;
            free(answer);
            if (!menu_line("SHA-256 > ", &digest)) { free(digest); return 0; }
            if (!digest_valid(digest) || menu->count >= 1024) {
                puts("Invalid SHA-256 or package limit reached"); free(digest); continue;
            }
            for (i = 0; i < menu->count; ++i)
                if (!strcmp(menu->artifacts[i], digest)) { found = 1; break; }
            if (found) { puts("Already selected"); free(digest); continue; }
            next = realloc(menu->artifacts, (menu->count + 1) * sizeof *next);
            if (!next) { free(digest); return 0; }
            menu->artifacts = next;
            menu->artifacts[menu->count++] = digest;
            *dirty = 1;
            continue;
        }
        if (!strcmp(answer, "d")) {
            char *number = NULL, *end;
            unsigned long long index;
            free(answer);
            if (!menu_line("Number > ", &number)) { free(number); return 0; }
            errno = 0;
            index = strtoull(number, &end, 10);
            if (errno || !number[0] || *end || !index || index > menu->count) {
                puts("Invalid number"); free(number); continue;
            }
            free(menu->artifacts[index - 1]);
            for (i = (size_t)index; i < menu->count; ++i)
                menu->artifacts[i - 1] = menu->artifacts[i];
            --menu->count;
            *dirty = 1;
            free(number);
            continue;
        }
        puts("Choose a, d or b");
        free(answer);
    }
}

static int menu_prepare(const char *plan_path,
                        const char *binary, const struct menu_state *menu,
                        int save_plan)
{
    struct holy_config config = {0};
    struct install_input input = {0};
    char temporary[] = "/tmp/holyinstall-menu-XXXXXX";
    char *output = NULL, hash[65];
    FILE *stream;
    int fd, rc, ok;
    fd = mkstemp(temporary);
    if (fd < 0) return 1;
    stream = fdopen(fd, "w");
    if (!stream) { close(fd); unlink(temporary); return 1; }
    ok = menu_write(stream, menu);
    if (fflush(stream) || fsync(fd)) ok = 0;
    if (fclose(stream)) ok = 0;
    if (!ok) { unlink(temporary); return 1; }
    rc = load_input(temporary, &config, &input);
    unlink(temporary);
    if (rc) goto done;
    rc = run_package_manager(binary, &input, NULL, &output);
    if (rc) goto done;
    if (!set_hash(output, hash)) { rc = 1; goto done; }
    if (fputs(output, stdout) == EOF) { rc = 1; goto done; }
    if (save_plan) {
        rc = write_plan(plan_path, &input, hash);
        if (!rc) printf("holyinstall plan %s set %s\n", plan_path, hash);
    }
done:
    free(output);
    free_input(&input);
    holy_config_free(&config);
    return rc;
}

static int menu_run(const char *config_path, const char *plan_path,
                    const char *binary)
{
    struct menu_state menu = {0};
    int rc, prepared = 0, dirty = access(config_path, F_OK) != 0;
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
        fputs("holyinstall: menu requires a terminal\n", stderr);
        return 3;
    }
    rc = menu_load(config_path, &menu);
    if (rc) goto done;
    for (;;) {
        char *answer = NULL;
        fputs("\nHoly installer: prepared root package stage\n1 Target root: ", stdout);
        menu_path(menu.root ? menu.root : "unset");
        printf("\n2 Packages: %zu\nConfig: %s\n"
               "3 Preview\n4 Save config\n5 Prepare plan\n6 Install prepared plan\n7 Abort\n",
               menu.count, dirty ? "modified" : "saved");
        if (!menu_line("Choice > ", &answer)) { free(answer); rc = 0; break; }
        if (!strcmp(answer, "1")) {
            char *root = NULL;
            free(answer);
            if (!menu_line("Target root > ", &root)) { free(root); rc = 0; break; }
            if (root[0]) { free(menu.root); menu.root = root; dirty = 1; prepared = 0; }
            else free(root);
            continue;
        }
        if (!strcmp(answer, "2")) {
            int changed = 0;
            free(answer);
            if (!menu_packages(&menu, &changed)) { rc = 0; break; }
            if (changed) { dirty = 1; prepared = 0; }
            continue;
        }
        if (!strcmp(answer, "3")) {
            free(answer);
            rc = menu_prepare(plan_path, binary, &menu, 0);
            if (rc) printf("Preview failed (status %d)\n", rc);
            continue;
        }
        if (!strcmp(answer, "4")) {
            free(answer);
            if (!menu_config_file(config_path, &menu)) puts("Save failed");
            else { dirty = 0; puts("Config saved"); }
            continue;
        }
        if (!strcmp(answer, "5")) {
            free(answer);
            rc = menu_prepare(plan_path, binary, &menu, 1);
            prepared = rc == 0;
            if (rc) printf("Plan failed (status %d)\n", rc);
            continue;
        }
        if (!strcmp(answer, "6")) {
            struct install_input input = {0};
            char hash[65], *confirm = NULL, *output = NULL;
            free(answer);
            if (!prepared) { puts("Prepare and review a plan first"); continue; }
            rc = check_plan(plan_path, &input, hash);
            if (rc) { free_input(&input); printf("Plan failed (status %d)\n", rc); prepared = 0; continue; }
            fputs("Root ", stdout);
            menu_path(input.root);
            printf("\nSet %s\nArtifacts %zu\n", hash, input.count);
            if (!menu_line("Type yes to install > ", &confirm)) {
                free(confirm); free_input(&input); rc = 0; break;
            }
            if (!strcmp(confirm, "yes")) {
                rc = run_package_manager(binary, &input, hash, &output);
                if (!rc) { fputs(output, stdout); puts("Package transaction complete"); }
                else printf("Install failed (status %d)\n", rc);
                prepared = 0;
            }
            free(confirm); free(output); free_input(&input);
            continue;
        }
        if (!strcmp(answer, "7")) { free(answer); rc = 0; break; }
        puts("Choose 1 through 7");
        free(answer);
    }
done:
    free_menu(&menu);
    return rc;
}

int main(int argc, char **argv)
{
    const char *config_path = NULL, *plan_path = NULL;
    const char *binary = "/usr/bin/holypkg";
    struct holy_config config = {0};
    struct install_input input = {0};
    char hash[65], *output = NULL;
    int i, apply = 0, menu = 0, rc;
    if (argc > 1 && !strcmp(argv[1], "disk"))
        return holy_disk_main(argc - 2, argv + 2);
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--config") && ++i < argc && !config_path)
            config_path = argv[i];
        else if (!strcmp(argv[i], "--plan") && ++i < argc && !plan_path && !apply)
            plan_path = argv[i];
        else if (!strcmp(argv[i], "--apply") && ++i < argc && !plan_path) {
            plan_path = argv[i]; apply = 1;
        } else if (!strcmp(argv[i], "--menu") && !menu) {
            menu = 1;
        } else if (!strcmp(argv[i], "--holypkg") && ++i < argc)
            binary = argv[i];
        else goto usage;
    }
    if (!plan_path || (apply ? config_path != NULL || menu : config_path == NULL)) goto usage;
    if (menu) return menu_run(config_path, plan_path, binary);
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
    free(output); free_input(&input); holy_config_free(&config);
    return rc;
usage:
    fputs("usage: holyinstall [--menu] --config FILE --plan NEW_FILE [--holypkg FILE] | --apply PLAN [--holypkg FILE]\n", stderr);
    return 2;
}
