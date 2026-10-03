#define _XOPEN_SOURCE 700
#include "config.h"
#include "disk.h"

#include <dirent.h>
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

/* defined below, next to the other target writers */
static int host_wireless(void);

struct install_input;

/* reads the disk plan a target root will name, with the other target writers */
static int read_disk_plan(struct install_input *input);

struct install_input {
    char *root;
    char **accounts;      /* the account lines as the config wrote them */
    size_t account_count;
    char *password_file;  /* a file holding the shadow hash for every account */
    char *disk_plan;      /* the disk plan whose labels the target root will name */
    char disk_plan_hash[65];
    char boot_label[17], root_label[17], filesystem[32];
    char *locale;         /* the locale the target boots with */
    char *timezone;       /* the zone the target boots with */
    char *network;        /* the network profile the target uses */
    char **network_packages;  /* the artifacts a network profile needs */
    size_t network_count;
    char **firmware;      /* the artifacts that carry wireless firmware */
    size_t firmware_count;
    char **artifacts;
    size_t count;
    char **accepted_arch;
    size_t accept_count;
    char **accepted_privileged;
    size_t privileged_count;
    char **accepted_service;   /* the service units the set is allowed to start */
    size_t service_count;
    char **sources;
    size_t source_count;
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

static char *source_binding(const char *artifact, const char *source)
{
    char *binding;
    if (!digest_valid(artifact) || !digest_valid(source)) return NULL;
    binding = malloc(130);
    if (binding) snprintf(binding, 130, "%s=%s", artifact, source);
    return binding;
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

/* the digest of a whole file, so a plan can bind the document it read */
static int digest_path(const char *path, char output[65])
{
    unsigned char buffer[65536], bytes[32];
    unsigned length = 0;
    EVP_MD_CTX *ctx;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK), ok = 1;
    if (fd < 0) return 0;
    ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) ok = 0;
    while (ok) {
        ssize_t got = read(fd, buffer, sizeof buffer);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) { ok = 0; break; }
        if (!got) break;
        ok = EVP_DigestUpdate(ctx, buffer, (size_t)got) == 1;
    }
    if (ok) ok = EVP_DigestFinal_ex(ctx, bytes, &length) == 1 && length == 32;
    EVP_MD_CTX_free(ctx);
    if (close(fd)) ok = 0;
    return ok && hex_digest(bytes, output);
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

/* a decimal field the plan and the target files both read the same way */
static int decimal(const char *text, unsigned long *value)
{
    unsigned long result = 0;
    size_t i, length = text ? strlen(text) : 0;
    if (!length || length > 10) return 1;
    for (i = 0; i < length; ++i) {
        if (text[i] < '0' || text[i] > '9') return 1;
        result = result * 10 + (unsigned long)(text[i] - '0');
    }
    if (result > 65535) return 1;
    if (value) *value = result;
    return 0;
}

/* a user name the target's passwd can hold: no path, no colon and no whitespace */
static int account_name_valid(const char *name)
{
    size_t i, length = strlen(name);
    if (!length || length > 32 || !((name[0] >= 'a' && name[0] <= 'z') || name[0] == '_'))
        return 0;
    for (i = 0; i < length; ++i) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' ||
              (c == '$' && i + 1 == length))) return 0;
    }
    return 1;
}

/* a locale name: language[_territory][.charset][@modifier], which is what the target's
   libc reads out of /etc/locale.conf */
static int locale_valid(const char *text)
{
    size_t i, length = strlen(text);
    if (!length || length > 32) return 0;
    for (i = 0; i < length; ++i) {
        char c = text[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9')) continue;
        if (c == '_' || c == '.' || c == '@' || c == '-') continue;
        return 0;
    }
    return 1;
}

/* a zone name: an area and a city under the target's zoneinfo, without a step upward */
static int timezone_valid(const char *text)
{
    const char *slash = strchr(text, '/');
    size_t length = strlen(text);
    if (!slash || slash == text || !slash[1] || length > 64) return 0;
    if (strstr(text, "..")) return 0;
    for (; *text; ++text) {
        char c = *text;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '/' || c == '_' || c == '-' || c == '+')
            continue;
        return 0;
    }
    return 1;
}

/* the account line as the plan carries it: name uid gid shell groups, with a dash for
   no extra groups, so the plan is one fixed shape */
static int account_line(const char *name, const char *uid, const char *gid,
                        const char *shell, const char *groups, char **line)
{
    char *joined = NULL;
    if (!account_name_valid(name) || !*shell || shell[0] != '/') return 0;
    if (decimal(uid, NULL) || decimal(gid, NULL)) return 0;
    if (!groups || !*groups) groups = "-";
    joined = calloc(strlen(name) + strlen(uid) + strlen(gid) + strlen(shell) +
                    strlen(groups) + 6, 1);
    if (!joined) return 0;
    sprintf(joined, "%s %s %s %s %s", name, uid, gid, shell, groups);
    *line = joined;
    return 1;
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
    input->accounts = calloc(config->count ? config->count : 1, sizeof *input->accounts);
    if (!input->accounts) return 1;
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
    /* the network profile names artifacts of this set, so it is read after them */
    for (i = 0; i < config->count; ++i) {
        const struct holy_entry *e = &config->entries[i];
        if (strcmp(e->section, "install")) continue;
        if (!strcmp(e->key, "locale") || !strcmp(e->key, "timezone") ||
            !strcmp(e->key, "network-profile")) {
            char **target = !strcmp(e->key, "locale") ? &input->locale :
                            !strcmp(e->key, "timezone") ? &input->timezone : &input->network;
            int valid = e->count == 1 &&
                        (!strcmp(e->key, "locale") ? locale_valid(e->values[0]) :
                         !strcmp(e->key, "timezone") ? timezone_valid(e->values[0]) :
                         !strcmp(e->values[0], "connman-iwd"));
            if (!valid || *target) {
                fprintf(stderr, "holyinstall: invalid %s at %s:%zu\n", e->key, e->file, e->line);
                return 2;
            }
            *target = strdup(e->values[0]);
            if (!*target) return 1;
            continue;
        }
        if (!strcmp(e->key, "disk-plan")) {
            if (e->count != 1 || input->disk_plan || e->values[0][0] != '/') {
                fprintf(stderr, "holyinstall: disk-plan takes one absolute path at %s:%zu\n",
                        e->file, e->line);
                return 2;
            }
            input->disk_plan = strdup(e->values[0]);
            if (!input->disk_plan) return 1;
            continue;
        }
        if (!strcmp(e->key, "network-package") || !strcmp(e->key, "firmware")) {
            char ***list = !strcmp(e->key, "network-package") ? &input->network_packages :
                           &input->firmware;
            size_t *count = !strcmp(e->key, "network-package") ? &input->network_count :
                            &input->firmware_count;
            size_t j;
            if (e->count != 1 || !digest_valid(e->values[0])) {
                fprintf(stderr, "holyinstall: %s needs one artifact SHA-256 at %s:%zu\n",
                        e->key, e->file, e->line);
                return 2;
            }
            for (j = 0; j < input->count; ++j)
                if (!strcmp(input->artifacts[j], e->values[0])) break;
            if (j == input->count) {
                fprintf(stderr, "holyinstall: %s %s is not a selected artifact at %s:%zu\n",
                        e->key, e->values[0], e->file, e->line);
                return 2;
            }
            if (*count >= input->count) return 2;
            for (j = 0; j < *count; ++j)
                if (!strcmp((*list)[j], e->values[0])) {
                    fprintf(stderr, "holyinstall: duplicate %s %s at %s:%zu\n", e->key,
                            e->values[0], e->file, e->line);
                    return 2;
                }
            *list = realloc(*list, (*count + 1) * sizeof **list);
            if (!*list) return 1;
            (*list)[*count] = strdup(e->values[0]);
            if (!(*list)[*count]) return 1;
            ++*count;
            continue;
        }
        if (!strcmp(e->key, "account")) {
            char *line = NULL;
            if (e->count != 5 ||
                !account_line(e->values[0], e->values[1], e->values[2], e->values[3],
                              e->values[4], &line)) {
                fprintf(stderr, "holyinstall: invalid account at %s:%zu\n", e->file, e->line);
                return 2;
            }
            /* the name decides, since one name is one account whatever its ids are */
            for (j = 0; j < input->account_count; ++j)
                if (!strncmp(input->accounts[j], line, strlen(e->values[0]))) {
                    fprintf(stderr, "holyinstall: duplicate account at %s:%zu\n",
                            e->file, e->line);
                    free(line);
                    return 2;
                }
            if (input->account_count >= config->count) { free(line); return 2; }
            input->accounts[input->account_count++] = line;
            continue;
        }
        if (!strcmp(e->key, "password-file")) {
            if (e->count != 1 || input->password_file) {
                fprintf(stderr, "holyinstall: password-file takes one path at %s:%zu\n",
                        e->file, e->line);
                return 2;
            }
            if (e->values[0][0] != '/') {
                fprintf(stderr, "holyinstall: password-file needs an absolute path at %s:%zu\n",
                        e->file, e->line);
                return 2;
            }
            input->password_file = strdup(e->values[0]);
            if (!input->password_file) return 1;
        }
    }
    if (input->network && !input->network_count) {
        fputs("holyinstall: [install] network-profile needs network-package lines\n", stderr);
        return 2;
    }
    if (input->password_file && !input->account_count) {
        fputs("holyinstall: [install] password-file needs an account\n", stderr);
        return 2;
    }
    if (input->disk_plan && read_disk_plan(input)) return 2;
    if (input->network && !input->firmware_count && host_wireless()) {
        fprintf(stderr, "holyinstall: this host has a wireless interface and %s has no"
                        " firmware lines; name the firmware artifacts\n", input->network);
        return 3;
    }
    input->accepted_arch = calloc(config->count ? config->count : 1,
                                  sizeof *input->accepted_arch);
    input->accepted_privileged = calloc(config->count ? config->count : 1,
                                        sizeof *input->accepted_privileged);
    if (!input->accepted_arch || !input->accepted_privileged) return 1;
    for (i = 0; i < config->count; ++i) {
        const struct holy_entry *e = &config->entries[i];
        char ***accepted;
        size_t *accepted_count;
        if (strcmp(e->section, "install")) continue;
        if (!strcmp(e->key, "accept-arch")) {
            accepted = &input->accepted_arch;
            accepted_count = &input->accept_count;
        } else if (!strcmp(e->key, "accept-privileged")) {
            accepted = &input->accepted_privileged;
            accepted_count = &input->privileged_count;
        } else continue;
        if (!digest_valid(e->values[0])) {
            fprintf(stderr, "holyinstall: invalid %s at %s:%zu\n", e->key, e->file, e->line);
            return 2;
        }
        for (j = 0; j < input->count; ++j)
            if (!strcmp(input->artifacts[j], e->values[0])) break;
        if (j == input->count) {
            fprintf(stderr, "holyinstall: %s needs a selected artifact at %s:%zu\n",
                    e->key, e->file, e->line);
            return 2;
        }
        for (j = 0; j < *accepted_count; ++j)
            if (!strcmp((*accepted)[j], e->values[0])) break;
        if (j != *accepted_count) {
            fprintf(stderr, "holyinstall: duplicate %s at %s:%zu\n", e->key, e->file, e->line);
            return 2;
        }
        (*accepted)[*accepted_count] = strdup(e->values[0]);
        if (!(*accepted)[*accepted_count]) return 1;
        ++*accepted_count;
    }
    input->sources = calloc(config->count ? config->count : 1, sizeof *input->sources);
    if (!input->sources) return 1;
    for (i = 0; i < config->count; ++i) {
        const struct holy_entry *e = &config->entries[i];
        char *binding;
        if (strcmp(e->section, "install") || strcmp(e->key, "source")) continue;
        for (j = 0; j < input->count; ++j)
            if (!strcmp(input->artifacts[j], e->values[0])) break;
        if (j == input->count || !(binding = source_binding(e->values[0], e->values[1]))) {
            fprintf(stderr, "holyinstall: invalid source binding at %s:%zu\n", e->file, e->line);
            return 2;
        }
        for (j = 0; j < input->source_count; ++j)
            if (!strncmp(input->sources[j], binding, 65)) break;
        if (j != input->source_count) {
            free(binding);
            fprintf(stderr, "holyinstall: duplicate source binding at %s:%zu\n", e->file, e->line);
            return 2;
        }
        input->sources[input->source_count++] = binding;
    }
    input->accepted_service = calloc(config->count ? config->count : 1,
                                     sizeof *input->accepted_service);
    if (!input->accepted_service) return 1;
    for (i = 0; i < config->count; ++i) {
        const struct holy_entry *e = &config->entries[i];
        if (strcmp(e->section, "install") || strcmp(e->key, "accept-service")) continue;
        if (!holy_unit_name_valid(e->values[0])) {
            fprintf(stderr, "holyinstall: invalid service unit at %s:%zu\n", e->file, e->line);
            return 2;
        }
        for (j = 0; j < input->service_count; ++j)
            if (!strcmp(input->accepted_service[j], e->values[0])) {
                fprintf(stderr, "holyinstall: duplicate accept-service at %s:%zu\n",
                        e->file, e->line);
                return 2;
            }
        input->accepted_service[input->service_count] = strdup(e->values[0]);
        if (!input->accepted_service[input->service_count]) return 1;
        ++input->service_count;
    }
    if (!config_hash(config, input->hash)) return 1;
    return 0;
}

static int run_package_manager(const char *binary, const struct install_input *input,
                               const char *approved, char **output)
{
    char **args;
    size_t i, count = input->count + (input->accept_count + input->privileged_count +
                                      input->source_count + input->service_count) * 2 +
                      (approved ? 7 : 6), used = 0, capacity = 0;
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
    for (size_t j = 0; j < input->accept_count; ++j) {
        args[i++] = "--accept-arch";
        args[i++] = input->accepted_arch[j];
    }
    for (size_t j = 0; j < input->privileged_count; ++j) {
        args[i++] = "--accept-privileged";
        args[i++] = input->accepted_privileged[j];
    }
    for (size_t j = 0; j < input->source_count; ++j) {
        args[i++] = "--source";
        args[i++] = input->sources[j];
    }
    for (size_t j = 0; j < input->service_count; ++j) {
        args[i++] = "--accept-service";
        args[i++] = input->accepted_service[j];
    }
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
        } else if (*p < 32 || *p == 127) {
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
    if (fprintf(stream, "[install-plan]\nformat holy-install-plan-%d\nroot ",
                input->service_count ? 8 : input->disk_plan ? 7 :
                input->locale || input->timezone || input->network ? 6 :
                input->account_count ? 5 : input->source_count ? 4 :
                input->privileged_count ? 3 : input->accept_count ? 2 : 1) < 0 ||
        !quote(stream, input->root) ||
        fprintf(stream, "\ndevice %ju\ninode %ju\nconfig-sha256 %s\nset-sha256 %s\n",
                (uintmax_t)input->root_stat.st_dev, (uintmax_t)input->root_stat.st_ino,
                input->hash, hash) < 0) ok = 0;
    for (i = 0; i < input->count && ok; ++i)
        if (fprintf(stream, "artifact %s\n", input->artifacts[i]) < 0) ok = 0;
    for (i = 0; i < input->accept_count && ok; ++i)
        if (fprintf(stream, "accept-arch %s\n", input->accepted_arch[i]) < 0) ok = 0;
    for (i = 0; i < input->privileged_count && ok; ++i)
        if (fprintf(stream, "accept-privileged %s\n", input->accepted_privileged[i]) < 0) ok = 0;
    for (i = 0; i < input->source_count && ok; ++i)
        if (fprintf(stream, "source %.64s %s\n", input->sources[i], input->sources[i] + 65) < 0) ok = 0;
    /* the disk plan comes first among the target decisions, since its labels are what a
       relocated root has to find */
    if (input->disk_plan &&
        (fprintf(stream, "disk-plan %s\n", input->disk_plan) < 0 ||
         fprintf(stream, "disk-plan-sha256 %s\n", input->disk_plan_hash) < 0 ||
         fprintf(stream, "boot-label %s\nroot-label %s\nroot-filesystem %s\n",
                 input->boot_label, input->root_label, input->filesystem) < 0)) ok = 0;
    /* the accounts come after the artifact lists, since that is the order a plan names
       them, and the password file is a path rather than a secret */
    for (i = 0; i < input->account_count && ok; ++i)
        if (fprintf(stream, "account %s\n", input->accounts[i]) < 0) ok = 0;
    if (input->password_file && fprintf(stream, "password-file %s\n",
                                        input->password_file) < 0) ok = 0;
    /* the target's identity and its network profile follow the accounts, which is the
       order a plan names them in */
    if (input->locale && fprintf(stream, "locale %s\n", input->locale) < 0) ok = 0;
    if (input->timezone && fprintf(stream, "timezone %s\n", input->timezone) < 0) ok = 0;
    if (input->network && fprintf(stream, "network-profile %s\n", input->network) < 0) ok = 0;
    for (i = 0; i < input->network_count && ok; ++i)
        if (fprintf(stream, "network-package %s\n", input->network_packages[i]) < 0) ok = 0;
    for (i = 0; i < input->firmware_count && ok; ++i)
        if (fprintf(stream, "firmware %s\n", input->firmware[i]) < 0) ok = 0;
    /* the service consents come last: they name what the set would start, which is only
       known once every artifact of the set has been named above */
    for (i = 0; i < input->service_count && ok; ++i)
        if (fprintf(stream, "accept-service %s\n", input->accepted_service[i]) < 0) ok = 0;
    if (fflush(stream) || fsync(fd)) ok = 0;
    if (fclose(stream)) ok = 0;
    if (ok) ok = sync_parent(path);
    if (!ok) unlink(path);
    return ok ? 0 : 1;
}

/* the shadow entry a password file holds: a lock marker or a hashed password. the file is
   read here and nowhere else, so the secret stays out of argv, the plan and any journal */
static int read_password_hash(const char *path, char hash[256])
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    char buffer[257];
    ssize_t got;
    size_t length, i;
    if (fd < 0) {
        fprintf(stderr, "holyinstall: password file unreadable: %s\n", strerror(errno));
        return 6;
    }
    got = read(fd, buffer, sizeof buffer - 1);
    close(fd);
    if (got <= 0) { fputs("holyinstall: password file is empty\n", stderr); return 6; }
    buffer[got] = 0;
    length = strcspn(buffer, "\r\n");
    if (!length || length > 255 || memchr(buffer, 0, length)) {
        fputs("holyinstall: password file holds one entry of at most 255 bytes\n", stderr);
        return 6;
    }
    for (i = 0; i < length; ++i)
        if (buffer[i] == ' ' || buffer[i] == '\t' || buffer[i] == ':') {
            fputs("holyinstall: password file entry has whitespace or a colon\n", stderr);
            return 6;
        }
    if (strcmp(buffer, "!") && strcmp(buffer, "*") && buffer[0] != '$') {
        fputs("holyinstall: password file entry is a lock marker or a hash\n", stderr);
        return 6;
    }
    memcpy(hash, buffer, length);
    hash[length] = 0;
    return 0;
}

/* appends one line to a file of the target root, creating it with that mode when the
   packages left none, and never following a name the target placed there */
static int append_line(int etc, const char *name, mode_t mode,
                       const char *line, int required)
{
    int fd = openat(etc, name, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    size_t length = strlen(line);
    ssize_t written;
    if (fd < 0) {
        if (!required && errno == ENOENT) fd = openat(etc, name, O_WRONLY | O_CREAT |
                                                      O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode);
        if (fd < 0) {
            fprintf(stderr, "holyinstall: %s/%s: %s\n", "etc", name, strerror(errno));
            return 1;
        }
    }
    written = write(fd, line, length);
    if (fsync(fd)) written = -1;
    close(fd);
    if (written < 0 || (size_t)written != length) {
        fprintf(stderr, "holyinstall: %s is not writable\n", name);
        return 1;
    }
    return 0;
}

/* rewrites one named line of a target file, since joining a group changes the line the
   target already has rather than adding a new one. the file is replaced atomically, so a
   crash leaves the previous one whole. */
static int replace_line(int etc, const char *file, const char *name, const char *line)
{
    int fd = openat(etc, file, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    char temporary[43] = {0}, *text = NULL, *cursor;
    struct stat st;
    FILE *in = NULL, *out = NULL;
    size_t used = 0;
    int temp = -1, ok = 0, attempt;
    if (fd < 0) {
        fprintf(stderr, "holyinstall: %s is unreadable: %s\n", file, strerror(errno));
        return 1;
    }
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        st.st_size > 1024 * 1024) goto done;
    if (!(in = fdopen(fd, "r"))) goto done;
    text = malloc((size_t)st.st_size + 2);
    if (!text) goto done;
    while (used <= (size_t)st.st_size &&
           fgets(cursor = text + used, (int)((size_t)st.st_size + 2 - used), in)) {
        size_t length = strlen(cursor);
        used += length;
        if (!length || length > 1024 || cursor[length - 1] != '\n') break;
    }
    if (ferror(in) || used > (size_t)st.st_size) goto done;
    fclose(in); in = NULL;
    /* a name of its own, created exclusively, so a second install cannot share it */
    for (attempt = 0; attempt < 64; ++attempt) {
        snprintf(temporary, sizeof temporary, ".holy-install-%ld-%d", (long)getpid(), attempt);
        temp = openat(etc, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                      st.st_mode & 07777);
        if (temp >= 0) break;
        if (errno != EEXIST) break;
    }
    if (temp < 0 || !(out = fdopen(temp, "w"))) goto done;
    temp = -1;
    /* every line that names the group is replaced, and the rest is copied as it was */
    for (cursor = text; cursor && *cursor; ) {
        char *next = strchr(cursor, '\n');
        int names = !strncmp(cursor, name, strlen(name)) && cursor[strlen(name)] == ':';
        /* each line is copied as it stands, and the one the caller replaced already
           carries its own newline */
        if (fputs(names ? line : cursor, out) == EOF) goto done;
        if (!next) break;
        cursor = next + 1;
    }
    if (fflush(out) || fsync(fileno(out)) || fclose(out)) { out = NULL; goto done; }
    out = NULL;
    ok = !renameat(etc, temporary, etc, file) && !fsync(etc);
done:
    if (in) fclose(in);
    if (out) fclose(out);
    if (temp >= 0) close(temp);
    if (!ok && temporary[0]) unlinkat(etc, temporary, 0);
    free(text);
    return ok ? 0 : 1;
}

/* whether the target's group file already names that group, since the install joins
   groups it finds rather than inventing system groups */
static int group_present(int etc, const char *name, char **members, char gid[16])
{
    int fd = openat(etc, "group", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    char *line = NULL;
    size_t capacity = 0;
    ssize_t got;
    FILE *stream;
    int found = 0;
    /* a caller that only needs to know whether the group is there passes no members */
    if (members) *members = NULL;
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    if (!(stream = fdopen(fd, "r"))) { close(fd); return -1; }
    /* a group line is name:password:gid:members, and an empty field is a field */
    while (!found && (got = getline(&line, &capacity, stream)) > 0) {
        char *fields[4] = {NULL, NULL, NULL, NULL}, *cursor = line;
        size_t field, seen = 0;
        if (line[got - 1] == '\n') line[got - 1] = 0;
        for (field = 0; field < 4 && cursor; ++field) {
            char *colon;
            fields[field] = cursor;
            if (field < 3 && (colon = strchr(cursor, ':'))) {
                *colon = 0;
                cursor = colon + 1;
            } else {
                cursor = NULL;
            }
            ++seen;
        }
        for (field = 0; field < seen && !found; ++field)
            if (!strcmp(fields[field], name)) found = 1;
        if (!found) continue;
        if (gid && seen > 2) snprintf(gid, 16, "%s", fields[2]);
        if (members) {
            /* an empty membership field is a field, so the caller always gets a string */
            *members = strdup(seen > 3 ? fields[3] : "");
            if (!*members) { fclose(stream); free(line); return -1; }
        }
    }
    fclose(stream);
    free(line);
    return found;
}

/* creates the accounts the plan names in the target root: an account is a passwd entry,
   a group of its own, the groups it joins, a shadow entry and the doas permit. the
   password entry is the hash the caller supplied, or a locked one. */
static int apply_accounts(const struct install_input *input)
{
    char hash[256] = "!";
    size_t i;
    int root = -1, etc = -1, rc = 0;
    if (!input->account_count) return 0;
    if (input->password_file && (rc = read_password_hash(input->password_file, hash)))
        return rc;
    root = open(input->root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0 || (etc = openat(root, "etc", O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                   O_CLOEXEC)) < 0) {
        fprintf(stderr, "holyinstall: target root has no /etc: %s\n", strerror(errno));
        rc = 6;
        goto done;
    }
    for (i = 0; i < input->account_count && !rc; ++i) {
        char **fields = NULL, *error = NULL;
        size_t count = 0, field;
        char line[1024];
        int written;
        if (!holy_lex(input->accounts[i], strlen(input->accounts[i]), &fields, &count,
                      "account", i + 1, &error) || count != 5) {
            fprintf(stderr, "holyinstall: account %zu is malformed\n", i + 1);
            free(error);
            rc = 2;
            goto done;
        }
        free(error);
        /* the group of its own and the passwd entry must not exist yet, since a name the
           target already uses is a decision rather than an install */
        if (group_present(etc, fields[0], NULL, NULL) != 0) {
            fprintf(stderr, "holyinstall: group %s already exists\n", fields[0]);
            rc = 6;
        }
        written = snprintf(line, sizeof line, "%s:x:%s:%s:Holy user:/root:%s\n",
                           fields[0], fields[1], fields[2], fields[3]);
        if (!rc && (written < 0 || (size_t)written >= sizeof line)) rc = 1;
        if (!rc) rc = append_line(etc, "passwd", 0644, line, 0);
        if (!rc && (written = snprintf(line, sizeof line, "%s:x:%s:\n", fields[0],
                                       fields[2])) < 0) rc = 1;
        if (!rc) rc = append_line(etc, "group", 0644, line, 0);
        for (field = 4; !rc && field < 5; ++field) {
            char *cursor = fields[field], *comma;
            if (!strcmp(fields[field], "-")) break;
            while (!rc && cursor && *cursor) {
                char *members = NULL, gid[16], group[65];
                if (!(comma = strchr(cursor, ','))) comma = cursor + strlen(cursor);
                if ((size_t)(comma - cursor) >= sizeof group) { rc = 2; break; }
                memcpy(group, cursor, (size_t)(comma - cursor));
                group[comma - cursor] = 0;
                if (!account_name_valid(group)) { rc = 2; break; }
                /* the install joins a group the target already has, so the line is that
                   group with the account added to its members */
                if (group_present(etc, group, &members, gid) != 1) {
                    fprintf(stderr, "holyinstall: group %s is not in the target\n", group);
                    free(members);
                    rc = 6;
                    break;
                }
                written = snprintf(line, sizeof line, "%s:x:%s:%s%s%s\n", group, gid, members,
                                   *members ? "," : "", fields[0]);
                free(members);
                if (written < 0 || (size_t)written >= sizeof line) { rc = 1; break; }
                rc = replace_line(etc, "group", group, line);
                cursor = *comma ? comma + 1 : NULL;
            }
        }
        if (!rc && (written = snprintf(line, sizeof line, "%s:%s:0:99999:7:::\n",
                                       fields[0], hash)) < 0) rc = 1;
        if (!rc) rc = append_line(etc, "shadow", 0600, line, 0);
        if (!rc && (written = snprintf(line, sizeof line, "permit persist %s\n", fields[0])) < 0)
            rc = 1;
        if (!rc) rc = append_line(etc, "doas.conf", 0640, line, 0);
        holy_tokens_free(fields, count);
    }
    if (!rc) {
        printf("accounts %zu created in %s\n", input->account_count, input->root);
        for (i = 0; i < input->account_count; ++i) printf("account %s\n", input->accounts[i]);
    }
done:
    if (etc >= 0) close(etc);
    if (root >= 0) close(root);
    return rc;
}

/* whether this host has a wireless interface, since an install that needs Wi-Fi has to
   name the firmware before the plan is written */
static int host_wireless(void)
{
    DIR *listing = opendir("/sys/class/net");
    struct dirent *entry;
    int found = 0;
    char path[256];
    if (!listing) return 0;
    while (!found && (entry = readdir(listing))) {
        if (entry->d_name[0] == '.') continue;
        if (snprintf(path, sizeof path, "/sys/class/net/%s/wireless", entry->d_name) >=
            (int)sizeof path) continue;
        {
            struct stat st;
            if (!lstat(path, &st) && S_ISDIR(st.st_mode)) found = 1;
        }
    }
    closedir(listing);
    return found;
}

/* creates one directory of the target root, with its mode when the packages left none */
static int make_directory(int root, const char *path, mode_t mode)
{
    char *copy = strdup(path), *slash;
    int fd = root, ok = 1;
    if (!copy) return 1;
    for (slash = copy + 1; *slash; ++slash) {
        if (*slash != '/') continue;
        *slash = 0;
        if (mkdirat(fd, copy, mode) && errno != EEXIST) { ok = 0; break; }
        *slash = '/';
    }
    if (ok && mkdirat(fd, path, mode) && errno != EEXIST) ok = 0;
    free(copy);
    return ok ? 0 : 1;
}

/* writes a symlink in the target root through a temporary name, so a crash leaves the
   previous link whole */
static int link_in_root(int etc, const char *name, const char *target)
{
    char temporary[64];
    int attempt;
    for (attempt = 0; attempt < 64; ++attempt) {
        snprintf(temporary, sizeof temporary, ".holy-localtime-%ld-%d", (long)getpid(),
                 attempt);
        unlinkat(etc, temporary, 0);
        if (!symlinkat(target, etc, temporary) &&
            !renameat(etc, temporary, etc, name) && !fsync(etc)) return 0;
        if (errno != EEXIST) return 1;
    }
    return 1;
}

/* the labels and the filesystem a disk plan fixes. the install names them in the target
   root so a root copied to another path still finds its filesystems, and the plan binds
   the digest of the disk plan it read. */
static int read_disk_plan(struct install_input *input)
{
    struct holy_config c = {0};
    char *error = NULL;
    const char *label, *root_label, *filesystem;
    if (access(input->disk_plan, R_OK)) {
        fprintf(stderr, "holyinstall: disk plan %s: %s\n", input->disk_plan, strerror(errno));
        return 2;
    }
    if (!holy_config_load_plan(input->disk_plan, &c, &error)) {
        fprintf(stderr, "holyinstall: %s\n", error ? error : "invalid disk plan");
        free(error);
        return 2;
    }
    free(error);
    label = field(&c, "disk-plan", "label");
    root_label = field(&c, "disk-plan", "root-label");
    filesystem = field(&c, "disk-plan", "filesystem");
    if (!label || !root_label ||
        strlen(label) >= sizeof input->boot_label ||
        strlen(root_label) >= sizeof input->root_label) {
        holy_config_free(&c);
        fputs("holyinstall: the disk plan states no filesystem labels\n", stderr);
        return 2;
    }
    snprintf(input->boot_label, sizeof input->boot_label, "%s", label);
    snprintf(input->root_label, sizeof input->root_label, "%s", root_label);
    snprintf(input->filesystem, sizeof input->filesystem, "%s",
             filesystem && filesystem[0] ? filesystem : "ext4");
    holy_config_free(&c);
    return digest_path(input->disk_plan, input->disk_plan_hash) ? 0 : 2;
}

/* the target boots with the locale, zone and network profile the plan names. these are
   the files the packages read, so a profile is configuration and nothing more */
static int apply_target_identity(const struct install_input *input)
{
    char line[512];
    int root = -1, etc = -1, rc = 0;
    size_t i;
    if (!input->locale && !input->timezone && !input->network && !input->disk_plan) return 0;
    root = open(input->root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0 || (etc = openat(root, "etc", O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                   O_CLOEXEC)) < 0) {
        fprintf(stderr, "holyinstall: target root has no /etc: %s\n", strerror(errno));
        rc = 6;
        goto done;
    }
    if (input->timezone) {
        char zone[128];
        int zoneinfo;
        if (snprintf(zone, sizeof zone, "usr/share/zoneinfo/%s", input->timezone) >=
            (int)sizeof zone) { rc = 1; goto done; }
        zoneinfo = openat(root, "usr/share/zoneinfo", O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                          O_CLOEXEC);
        if (zoneinfo < 0) {
            fputs("holyinstall: target has no zoneinfo; the timezone data is a package\n",
                  stderr);
            rc = 6;
            goto done;
        }
        if (faccessat(zoneinfo, input->timezone, F_OK, 0)) {
            fprintf(stderr, "holyinstall: timezone %s is not in the target\n", input->timezone);
            rc = 6;
        }
        close(zoneinfo);
        if (rc) goto done;
        if (snprintf(line, sizeof line, "%s\n", input->timezone) < 0 ||
            append_line(etc, "timezone", 0644, line, 0)) { rc = 1; goto done; }
        snprintf(line, sizeof line, "/usr/share/zoneinfo/%s", input->timezone);
        if (link_in_root(etc, "localtime", line)) { rc = 1; goto done; }
        printf("timezone %s\n", input->timezone);
    }
    if (input->locale) {
        if (snprintf(line, sizeof line, "LANG=%s\n", input->locale) < 0 ||
            append_line(etc, "locale.conf", 0644, line, 0)) { rc = 1; goto done; }
        printf("locale %s\n", input->locale);
    }
    if (input->disk_plan) {
        /* the labels name the volumes, so a root copied to another path boots without a
           device path; nothing else here depends on where the root lives */
        char table[512];
        int length = snprintf(table, sizeof table,
            "LABEL=%s / %s defaults 0 1\nLABEL=%s /boot/efi vfat umask=0077 0 1\n",
            input->root_label, input->filesystem, input->boot_label);
        if (length < 0 || (size_t)length >= sizeof table) { rc = 1; goto done; }
        if (append_line(etc, "fstab", 0644, table, 0)) { rc = 1; goto done; }
        printf("fstab root label %s filesystem %s boot label %s\n", input->root_label,
               input->filesystem, input->boot_label);
    }
    if (input->network) {
        static const char settings[] = "[Settings]\nAutoConnect=true\nOfflineMode=false\n";
        if (strcmp(input->network, "connman-iwd")) { rc = 2; goto done; }
        if (make_directory(root, "var/lib/connman", 0700) ||
            make_directory(root, "var/lib/iwd", 0700) ||
            make_directory(root, "etc/connman", 0755)) { rc = 1; goto done; }
        if (append_line(etc, "connman/connman.conf", 0644, settings, 0)) { rc = 1; goto done; }
        printf("network %s packages %zu firmware %zu\n", input->network,
               input->network_count, input->firmware_count);
        for (i = 0; i < input->network_count; ++i)
            printf("network-package %s\n", input->network_packages[i]);
        for (i = 0; i < input->firmware_count; ++i)
            printf("firmware %s\n", input->firmware[i]);
    }
done:
    if (etc >= 0) close(etc);
    if (root >= 0) close(root);
    return rc;
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
    int rc = 2, version = 0, phase = 0;
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
        } else if (count != 2 && !(count == 3 && !strcmp(v[0], "source")) &&
                   !(count == 6 && !strcmp(v[0], "account"))) {
            holy_tokens_free(v, count); goto done;
        } else if (row == 2) {
            if (strcmp(v[0], "format") ||
                (strcmp(v[1], "holy-install-plan-1") &&
                 strcmp(v[1], "holy-install-plan-2") &&
                 strcmp(v[1], "holy-install-plan-3") &&
                 strcmp(v[1], "holy-install-plan-4") &&
                 strcmp(v[1], "holy-install-plan-5") &&
                 strcmp(v[1], "holy-install-plan-6") &&
                 strcmp(v[1], "holy-install-plan-7") &&
                  strcmp(v[1], "holy-install-plan-8"))) {
                holy_tokens_free(v, count); goto done;
            }
            version = !strcmp(v[1], "holy-install-plan-8") ? 8 :
                      !strcmp(v[1], "holy-install-plan-7") ? 7 :
                      !strcmp(v[1], "holy-install-plan-6") ? 6 :
                      !strcmp(v[1], "holy-install-plan-5") ? 5 :
                      !strcmp(v[1], "holy-install-plan-4") ? 4 :
                      !strcmp(v[1], "holy-install-plan-3") ? 3 :
                      !strcmp(v[1], "holy-install-plan-2") ? 2 : 1;
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
        } else if (!strcmp(v[0], "accept-arch") ||
                   !strcmp(v[0], "accept-privileged")) {
            char **next;
            char ***accepted;
            size_t *accepted_count;
            size_t i;
            int privileged = !strcmp(v[0], "accept-privileged");
            if (privileged) {
                if (version < 3 || phase >= 3) { holy_tokens_free(v, count); goto done; }
                phase = 2;
                accepted = &input->accepted_privileged;
                accepted_count = &input->privileged_count;
            } else {
                if (phase >= 2 || version < 2) { holy_tokens_free(v, count); goto done; }
                phase = 1;
                accepted = &input->accepted_arch;
                accepted_count = &input->accept_count;
            }
            if (!digest_valid(v[1]) || *accepted_count >= input->count) {
                holy_tokens_free(v, count); goto done;
            }
            for (i = 0; i < input->count; ++i)
                if (!strcmp(v[1], input->artifacts[i])) break;
            if (i == input->count) { holy_tokens_free(v, count); goto done; }
            for (i = 0; i < *accepted_count; ++i)
                if (!strcmp(v[1], (*accepted)[i])) break;
            if (i != *accepted_count ||
                !(next = realloc(*accepted,
                                 (*accepted_count + 1) * sizeof *next))) {
                holy_tokens_free(v, count); goto done;
            }
            *accepted = next;
            (*accepted)[*accepted_count] = strdup(v[1]);
            if (!(*accepted)[*accepted_count]) {
                holy_tokens_free(v, count); goto done;
            }
            ++*accepted_count;
        } else if (!strcmp(v[0], "source")) {
            char *binding, **next;
            size_t i;
            if (version != 4 || count != 3 ||
                !(binding = source_binding(v[1], v[2]))) {
                holy_tokens_free(v, count); goto done;
            }
            phase = 3;
            for (i = 0; i < input->count; ++i)
                if (!strcmp(input->artifacts[i], v[1])) break;
            if (i == input->count || input->source_count >= input->count) {
                free(binding); holy_tokens_free(v, count); goto done;
            }
            for (i = 0; i < input->source_count; ++i)
                if (!strncmp(input->sources[i], binding, 65)) break;
            if (i != input->source_count ||
                !(next = realloc(input->sources,
                                 (input->source_count + 1) * sizeof *next))) {
                free(binding); holy_tokens_free(v, count); goto done;
            }
            input->sources = next;
            input->sources[input->source_count++] = binding;
        } else if (!strcmp(v[0], "account")) {
            char **next;
            size_t i;
            char *joined = NULL;
            if (version < 5 || phase >= 4 ||
                !account_line(v[1], v[2], v[3], v[4], v[5], &joined) ||
                input->account_count >= input->count + 64 ||
                !(next = realloc(input->accounts,
                                 (input->account_count + 1) * sizeof *next))) {
                free(joined); holy_tokens_free(v, count); goto done;
            }
            phase = 4;
            for (i = 0; i < input->account_count; ++i)
                if (!strcmp(input->accounts[i], joined)) break;
            if (i != input->account_count) {
                free(joined); holy_tokens_free(v, count); goto done;
            }
            input->accounts = next;
            input->accounts[input->account_count++] = joined;
        } else if (!strcmp(v[0], "disk-plan")) {
            if (version < 7 || phase >= 5 || input->disk_plan || count != 2 ||
                v[1][0] != '/' || strlen(v[1]) >= 4096) {
                holy_tokens_free(v, count); goto done;
            }
            phase = 5;
            input->disk_plan = strdup(v[1]);
            if (!input->disk_plan) { holy_tokens_free(v, count); goto done; }
        } else if (!strcmp(v[0], "disk-plan-sha256") || !strcmp(v[0], "boot-label") ||
                   !strcmp(v[0], "root-label") || !strcmp(v[0], "root-filesystem")) {
            if (version < 7 || !input->disk_plan || count != 2) {
                holy_tokens_free(v, count); goto done;
            }
            if (!strcmp(v[0], "disk-plan-sha256")) {
                if (strlen(v[1]) != 64) { holy_tokens_free(v, count); goto done; }
                memcpy(input->disk_plan_hash, v[1], 65);
                phase = 6;
            } else if (!strcmp(v[0], "boot-label")) {
                if (strlen(v[1]) >= sizeof input->boot_label) { holy_tokens_free(v, count); goto done; }
                snprintf(input->boot_label, sizeof input->boot_label, "%s", v[1]);
                phase = 7;
            } else if (!strcmp(v[0], "root-label")) {
                if (strlen(v[1]) >= sizeof input->root_label) { holy_tokens_free(v, count); goto done; }
                snprintf(input->root_label, sizeof input->root_label, "%s", v[1]);
                phase = 8;
            } else {
                /* the disk plan names its filesystem only for a block device, and an
                   image plan carries ext4, so a name the target can mount is required */
                size_t i;
                static const char *const filesystems[] = {"ext4", "btrfs", "xfs",
                                                          "f2fs", NULL};
                for (i = 0; filesystems[i]; ++i) if (!strcmp(filesystems[i], v[1])) break;
                if (!filesystems[i]) { holy_tokens_free(v, count); goto done; }
                snprintf(input->filesystem, sizeof input->filesystem, "%s", v[1]);
                phase = 11;
            }
        } else if (!strcmp(v[0], "password-file")) {
            if (version < 5 || phase >= 12 || input->password_file || v[1][0] != '/') {
                holy_tokens_free(v, count); goto done;
            }
            phase = 12;
            input->password_file = strdup(v[1]);
            if (!input->password_file) { holy_tokens_free(v, count); goto done; }
        } else if (!strcmp(v[0], "locale") || !strcmp(v[0], "timezone") ||
                   !strcmp(v[0], "network-profile")) {
            char **target = !strcmp(v[0], "locale") ? &input->locale :
                            !strcmp(v[0], "timezone") ? &input->timezone : &input->network;
            int valid = version < 6 ? 0 : count == 2 &&
                        (!strcmp(v[0], "locale") ? locale_valid(v[1]) :
                         !strcmp(v[0], "timezone") ? timezone_valid(v[1]) :
                         !strcmp(v[1], "connman-iwd"));
            if (!valid || *target || phase > 13) { holy_tokens_free(v, count); goto done; }
            phase = 13;
            *target = strdup(v[1]);
            if (!*target) { holy_tokens_free(v, count); goto done; }
        } else if (!strcmp(v[0], "network-package") || !strcmp(v[0], "firmware")) {
            char ***list = !strcmp(v[0], "network-package") ? &input->network_packages :
                           &input->firmware;
            size_t *total = !strcmp(v[0], "network-package") ? &input->network_count :
                            &input->firmware_count;
            char **next;
            size_t i;
            /* the network packages come before the firmware, which is the order the
               writer names them */
            int wanted = !strcmp(v[0], "network-package") ? 14 : 15;
            if (version < 6 || phase > wanted || phase + 1 < wanted ||
                count != 2 || !digest_valid(v[1]) || *total >= input->count + 64) {
                holy_tokens_free(v, count); goto done;
            }
            phase = wanted;
            for (i = 0; i < *total; ++i) if (!strcmp((*list)[i], v[1])) {
                holy_tokens_free(v, count); goto done;
            }
            for (i = 0; i < input->count; ++i)
                if (!strcmp(input->artifacts[i], v[1])) break;
            if (i == input->count) { holy_tokens_free(v, count); goto done; }
            next = realloc(*list, (*total + 1) * sizeof *next);
            if (!next) { holy_tokens_free(v, count); goto done; }
            *list = next;
            (*list)[*total] = strdup(v[1]);
            if (!(*list)[*total]) { holy_tokens_free(v, count); goto done; }
            ++*total;
        } else if (!strcmp(v[0], "accept-service")) {
            char **next;
            size_t i;
            /* the consents are the last lines a plan carries, so a plan that names one
               before the network block is not this writer's plan */
            if (version < 8 || phase > 16 || count != 2 ||
                !holy_unit_name_valid(v[1]) || input->service_count >= input->count + 64) {
                holy_tokens_free(v, count); goto done;
            }
            phase = 16;
            for (i = 0; i < input->service_count; ++i)
                if (!strcmp(input->accepted_service[i], v[1])) {
                    holy_tokens_free(v, count); goto done;
                }
            next = realloc(input->accepted_service,
                           (input->service_count + 1) * sizeof *next);
            if (!next) { holy_tokens_free(v, count); goto done; }
            input->accepted_service = next;
            input->accepted_service[input->service_count] = strdup(v[1]);
            if (!input->accepted_service[input->service_count]) {
                holy_tokens_free(v, count); goto done;
            }
            ++input->service_count;
        } else {
            char **next;
            size_t i;
            if (phase || strcmp(v[0], "artifact") || !digest_valid(v[1]) ||
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
    if (ferror(stream) || row != 7 + input->count + input->accept_count +
                                (input->disk_plan ? 5u : 0u) +
                                input->privileged_count + input->source_count +
                                input->account_count + (input->password_file ? 1u : 0u) +
                                (input->locale ? 1u : 0u) + (input->timezone ? 1u : 0u) +
                                (input->network ? 1u : 0u) + input->network_count +
                                input->firmware_count + input->service_count ||
        (input->password_file && !input->account_count) ||
        (input->network && (!input->network_count || version < 6)) ||
        ((input->network_count || input->firmware_count) && !input->network) ||
        (version == 6 && (!input->locale && !input->timezone && !input->network)) ||
        !input->count || (version == 1 && input->accept_count) ||
        (version == 2 && (!input->accept_count || input->privileged_count)) ||
        (version == 3 && !input->privileged_count) ||
        (version == 4 && !input->source_count) ||
        (version < 8 && input->service_count)) goto done;
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
    char *disk_image;
    char *disk_layout;      /* the filesystem profile the disk stage will format */
    char *disk_swap;        /* the swap size in mebibytes, or unset */
    char *disk_key_file;    /* the luks2 key file, never its contents */
    char *disk_volume;      /* the luks2 label and mapper name */
    char **accounts;            /* the account lines the plan carries */
    size_t account_count;
    char *password_file;
    char *locale;
    char *timezone;
    char *network;
    char **network_packages;
    size_t network_count;
    char **firmware;
    size_t firmware_count;
    char **artifacts;
    size_t count;
    char **accepted_arch;
    size_t accept_count;
    char **accepted_privileged;
    size_t privileged_count;
    char **sources;
    size_t source_count;
};

static void free_input(struct install_input *input)
{
    size_t i;
    for (i = 0; i < input->account_count; ++i) free(input->accounts[i]);
    free(input->accounts);
    free(input->password_file);
    free(input->disk_plan);
    free(input->locale);
    free(input->timezone);
    free(input->network);
    for (i = 0; i < input->network_count; ++i) free(input->network_packages[i]);
    free(input->network_packages);
    for (i = 0; i < input->firmware_count; ++i) free(input->firmware[i]);
    free(input->firmware);
    for (i = 0; i < input->count; ++i) free(input->artifacts[i]);
    free(input->artifacts);
    for (i = 0; i < input->accept_count; ++i) free(input->accepted_arch[i]);
    free(input->accepted_arch);
    for (i = 0; i < input->privileged_count; ++i) free(input->accepted_privileged[i]);
    free(input->accepted_privileged);
    for (i = 0; i < input->service_count; ++i) free(input->accepted_service[i]);
    free(input->accepted_service);
    for (i = 0; i < input->source_count; ++i) free(input->sources[i]);
    free(input->sources);
    free(input->root);
    memset(input, 0, sizeof *input);
}

static void free_menu(struct menu_state *menu)
{
    size_t j;
    for (j = 0; j < menu->account_count; ++j) free(menu->accounts[j]);
    free(menu->accounts);
    for (j = 0; j < menu->network_count; ++j) free(menu->network_packages[j]);
    free(menu->network_packages);
    for (j = 0; j < menu->firmware_count; ++j) free(menu->firmware[j]);
    free(menu->firmware);
    free(menu->locale);
    free(menu->timezone);
    free(menu->network);
    free(menu->password_file);
    size_t i;
    for (i = 0; i < menu->count; ++i) free(menu->artifacts[i]);
    free(menu->artifacts);
    for (i = 0; i < menu->accept_count; ++i) free(menu->accepted_arch[i]);
    free(menu->accepted_arch);
    for (i = 0; i < menu->privileged_count; ++i) free(menu->accepted_privileged[i]);
    free(menu->accepted_privileged);
    for (i = 0; i < menu->source_count; ++i) free(menu->sources[i]);
    free(menu->sources);
    free(menu->root);
    free(menu->disk_image);
    free(menu->disk_layout);
    free(menu->disk_swap);
    free(menu->disk_key_file);
    free(menu->disk_volume);
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
        if (strcmp(e->section, "install") && strcmp(e->section, "disk")) {
            fputs("holyinstall: text menu accepts [install] and [disk] only\n", stderr);
            holy_config_free(&config); return 2;
        }
        if (!strcmp(e->section, "disk")) {
            char **target = !strcmp(e->key, "image") ? &menu->disk_image :
                            !strcmp(e->key, "layout") ? &menu->disk_layout :
                            !strcmp(e->key, "swap") ? &menu->disk_swap :
                            !strcmp(e->key, "key-file") ? &menu->disk_key_file :
                            !strcmp(e->key, "device") ? &menu->disk_image : NULL;
            if (!target || *target || e->count != 1 ||
                (!strcmp(e->key, "key-file") && e->values[0][0] != '/')) {
                holy_config_free(&config); return 2;
            }
            *target = strdup(e->values[0]);
            if (!*target) { holy_config_free(&config); return 1; }
            continue;
        }
        if (!strcmp(e->key, "root")) {
            menu->root = strdup(e->values[0]);
            if (!menu->root) { holy_config_free(&config); return 1; }
        } else if (!strcmp(e->key, "account")) {
            char *line = NULL;
            if (e->count != 5 ||
                !account_line(e->values[0], e->values[1], e->values[2], e->values[3],
                              e->values[4], &line)) {
                fprintf(stderr, "holyinstall: invalid account at %s:%zu\n", e->file, e->line);
                holy_config_free(&config); return 2;
            }
            next = realloc(menu->accounts, (menu->account_count + 1) * sizeof *next);
            if (!next) { free(line); holy_config_free(&config); return 1; }
            menu->accounts = next;
            menu->accounts[menu->account_count++] = line;
        } else if (!strcmp(e->key, "password-file")) {
            if (e->count != 1 || menu->password_file || e->values[0][0] != '/') {
                fprintf(stderr, "holyinstall: password-file takes one absolute path at %s:%zu\n",
                        e->file, e->line);
                holy_config_free(&config); return 2;
            }
            menu->password_file = strdup(e->values[0]);
            if (!menu->password_file) { holy_config_free(&config); return 1; }
        } else if (!strcmp(e->key, "locale") || !strcmp(e->key, "timezone") ||
                   !strcmp(e->key, "network-profile")) {
            char **target = !strcmp(e->key, "locale") ? &menu->locale :
                            !strcmp(e->key, "timezone") ? &menu->timezone : &menu->network;
            int valid = e->count == 1 &&
                        (!strcmp(e->key, "locale") ? locale_valid(e->values[0]) :
                         !strcmp(e->key, "timezone") ? timezone_valid(e->values[0]) :
                         !strcmp(e->values[0], "connman-iwd"));
            if (!valid || *target) {
                fprintf(stderr, "holyinstall: invalid %s at %s:%zu\n", e->key, e->file, e->line);
                holy_config_free(&config); return 2;
            }
            *target = strdup(e->values[0]);
            if (!*target) { holy_config_free(&config); return 1; }
        } else if (!strcmp(e->key, "network-package") || !strcmp(e->key, "firmware")) {
            char ***list = !strcmp(e->key, "network-package") ? &menu->network_packages :
                           &menu->firmware;
            size_t *total = !strcmp(e->key, "network-package") ? &menu->network_count :
                            &menu->firmware_count;
            size_t j;
            if (e->count != 1 || !digest_valid(e->values[0]) || *total >= menu->count) {
                fprintf(stderr, "holyinstall: %s needs one artifact SHA-256 at %s:%zu\n",
                        e->key, e->file, e->line);
                holy_config_free(&config); return 2;
            }
            for (j = 0; j < menu->count; ++j)
                if (!strcmp(menu->artifacts[j], e->values[0])) break;
            if (j == menu->count) {
                fprintf(stderr, "holyinstall: %s %s is not a selected artifact at %s:%zu\n",
                        e->key, e->values[0], e->file, e->line);
                holy_config_free(&config); return 2;
            }
            *list = realloc(*list, (*total + 1) * sizeof **list);
            if (!*list) { holy_config_free(&config); return 1; }
            (*list)[*total] = strdup(e->values[0]);
            if (!(*list)[*total]) { holy_config_free(&config); return 1; }
            ++*total;
        } else if (!strcmp(e->key, "artifact")) {
            next = realloc(menu->artifacts, (menu->count + 1) * sizeof *next);
            if (!next) { holy_config_free(&config); return 1; }
            menu->artifacts = next;
            menu->artifacts[menu->count] = strdup(e->values[0]);
            if (!menu->artifacts[menu->count]) { holy_config_free(&config); return 1; }
            ++menu->count;
        }
    }
    if (menu->disk_image && !menu->disk_layout) menu->disk_layout = strdup("gpt-ext4");
    if (menu->disk_image && !menu->disk_layout) { holy_config_free(&config); return 1; }
    if (menu->disk_image && (menu->disk_swap || menu->disk_key_file || menu->disk_volume) &&
        strncmp(menu->disk_image, "/dev/", 5)) {
        /* an image file carries no swap device and no mapper */
        fputs("holyinstall: swap and encryption need a block device\n", stderr);
        holy_config_free(&config); return 2;
    }
    if (!!menu->disk_key_file != !!menu->disk_volume) {
        fputs("holyinstall: encryption needs a volume and a key file\n", stderr);
        holy_config_free(&config); return 2;
    }
    if (!menu->disk_image && (menu->disk_layout || menu->disk_swap ||
                              menu->disk_key_file || menu->disk_volume)) {
        fputs("holyinstall: [disk] needs an image or a device\n", stderr);
        holy_config_free(&config); return 2;
    }
    for (i = 0; i < config.count; ++i) {
        const struct holy_entry *e = &config.entries[i];
        size_t j;
        char **next;
        char ***accepted;
        size_t *accepted_count;
        if (strcmp(e->section, "install")) continue;
        if (!strcmp(e->key, "source")) {
            char *binding = source_binding(e->values[0], e->values[1]);
            for (j = 0; j < menu->count; ++j)
                if (!strcmp(e->values[0], menu->artifacts[j])) break;
            if (!binding || j == menu->count) {
                free(binding); holy_config_free(&config); return 2;
            }
            for (j = 0; j < menu->source_count; ++j)
                if (!strncmp(menu->sources[j], binding, 65)) break;
            if (j != menu->source_count ||
                !(next = realloc(menu->sources,
                                 (menu->source_count + 1) * sizeof *next))) {
                free(binding); holy_config_free(&config); return 2;
            }
            menu->sources = next;
            menu->sources[menu->source_count++] = binding;
            continue;
        }
        if (!strcmp(e->key, "accept-arch")) {
            accepted = &menu->accepted_arch;
            accepted_count = &menu->accept_count;
        } else if (!strcmp(e->key, "accept-privileged")) {
            accepted = &menu->accepted_privileged;
            accepted_count = &menu->privileged_count;
        } else continue;
        for (j = 0; j < menu->count; ++j)
            if (!strcmp(e->values[0], menu->artifacts[j])) break;
        if (!digest_valid(e->values[0]) || j == menu->count) {
            fprintf(stderr, "holyinstall: %s needs a selected artifact\n", e->key);
            holy_config_free(&config); return 2;
        }
        for (j = 0; j < *accepted_count; ++j)
            if (!strcmp(e->values[0], (*accepted)[j])) break;
        if (j != *accepted_count) {
            fprintf(stderr, "holyinstall: duplicate %s\n", e->key);
            holy_config_free(&config); return 2;
        }
        next = realloc(*accepted, (*accepted_count + 1) * sizeof *next);
        if (!next) { holy_config_free(&config); return 1; }
        *accepted = next;
        (*accepted)[*accepted_count] = strdup(e->values[0]);
        if (!(*accepted)[*accepted_count]) {
            holy_config_free(&config); return 1;
        }
        ++*accepted_count;
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
    /* the accounts and the target's identity come before the artifacts, since a plan
       names them first */
    for (i = 0; i < menu->account_count; ++i)
        if (fprintf(stream, "account %s\n", menu->accounts[i]) < 0) return 0;
    if (menu->password_file &&
        (fputs("password-file ", stream) == EOF ||
         !quote(stream, menu->password_file) || fputc('\n', stream) == EOF)) return 0;
    if (menu->locale && fprintf(stream, "locale %s\n", menu->locale) < 0) return 0;
    if (menu->timezone && fprintf(stream, "timezone %s\n", menu->timezone) < 0) return 0;
    if (menu->network && fprintf(stream, "network-profile %s\n", menu->network) < 0) return 0;
    for (i = 0; i < menu->network_count; ++i)
        if (fprintf(stream, "network-package %s\n", menu->network_packages[i]) < 0) return 0;
    for (i = 0; i < menu->firmware_count; ++i)
        if (fprintf(stream, "firmware %s\n", menu->firmware[i]) < 0) return 0;
    for (i = 0; i < menu->count; ++i)
        if (fprintf(stream, "artifact %s\n", menu->artifacts[i]) < 0) return 0;
    for (i = 0; i < menu->accept_count; ++i)
        if (fprintf(stream, "accept-arch %s\n", menu->accepted_arch[i]) < 0) return 0;
    for (i = 0; i < menu->privileged_count; ++i)
        if (fprintf(stream, "accept-privileged %s\n", menu->accepted_privileged[i]) < 0) return 0;
    for (i = 0; i < menu->source_count; ++i)
        if (fprintf(stream, "source %.64s %s\n", menu->sources[i], menu->sources[i] + 65) < 0) return 0;
    if (menu->disk_image && (fputs("[disk]\nimage ", stream) == EOF ||
                             !quote(stream, menu->disk_image) ||
                             fprintf(stream, "\nlayout %s\n", menu->disk_layout) < 0)) return 0;
    if (menu->disk_swap && fprintf(stream, "swap %s\n", menu->disk_swap) < 0) return 0;
    if (menu->disk_volume && fprintf(stream, "volume %s\n", menu->disk_volume) < 0) return 0;
    if (menu->disk_key_file && (fputs("key-file ", stream) == EOF ||
                                !quote(stream, menu->disk_key_file) ||
                                fputc('\n', stream) == EOF)) return 0;
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
        for (i = 0; i < menu->count; ++i) {
            size_t j, k, s;
            for (j = 0; j < menu->accept_count; ++j)
                if (!strcmp(menu->artifacts[i], menu->accepted_arch[j])) break;
            for (k = 0; k < menu->privileged_count; ++k)
                if (!strcmp(menu->artifacts[i], menu->accepted_privileged[k])) break;
            for (s = 0; s < menu->source_count; ++s)
                if (!strncmp(menu->artifacts[i], menu->sources[s], 64)) break;
            printf("%zu %s%s%s%s\n", i + 1, menu->artifacts[i],
                   j < menu->accept_count ? " [arch override]" : "",
                   k < menu->privileged_count ? " [setuid approved]" : "",
                   s < menu->source_count ? " [source assigned]" : "");
        }
        if (!menu_line("a add, d delete, x arch override, p setuid approval, s source, b back > ", &answer)) {
            free(answer); return 0;
        }
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
        if (!strcmp(answer, "d") || !strcmp(answer, "x") ||
            !strcmp(answer, "p") || !strcmp(answer, "s")) {
            char *number = NULL, *end;
            unsigned long long index;
            int remove = !strcmp(answer, "d");
            int source_choice = !strcmp(answer, "s");
            char ***accepted = !strcmp(answer, "p") ? &menu->accepted_privileged :
                                &menu->accepted_arch;
            size_t *accepted_count = !strcmp(answer, "p") ? &menu->privileged_count :
                                     &menu->accept_count;
            free(answer);
            if (!menu_line("Number > ", &number)) { free(number); return 0; }
            errno = 0;
            index = strtoull(number, &end, 10);
            if (errno || !number[0] || *end || !index || index > menu->count) {
                puts("Invalid number"); free(number); continue;
            }
            if (source_choice) {
                char *id = NULL, *binding = NULL;
                size_t j;
                free(number);
                if (!menu_line("Source ID SHA-256 (empty clears) > ", &id)) {
                    free(id); return 0;
                }
                if (*id && !(binding = source_binding(menu->artifacts[index - 1], id))) {
                    puts("Invalid source ID"); free(id); continue;
                }
                free(id);
                for (j = 0; j < menu->source_count; ++j)
                    if (!strncmp(menu->sources[j], menu->artifacts[index - 1], 64)) break;
                if (j < menu->source_count) {
                    free(menu->sources[j]);
                    for (++j; j < menu->source_count; ++j)
                        menu->sources[j - 1] = menu->sources[j];
                    --menu->source_count;
                }
                if (binding) {
                    char **next = realloc(menu->sources,
                                          (menu->source_count + 1) * sizeof *next);
                    if (!next) { free(binding); return 0; }
                    menu->sources = next;
                    menu->sources[menu->source_count++] = binding;
                }
                *dirty = 1;
                continue;
            }
            for (i = 0; i < *accepted_count; ++i)
                if (!strcmp((*accepted)[i], menu->artifacts[index - 1])) break;
            if (i < *accepted_count) {
                free((*accepted)[i]);
                for (++i; i < *accepted_count; ++i)
                    (*accepted)[i - 1] = (*accepted)[i];
                --*accepted_count;
            } else if (!remove) {
                char **next = realloc(*accepted, (*accepted_count + 1) * sizeof *next);
                if (!next) { free(number); return 0; }
                *accepted = next;
                (*accepted)[*accepted_count] = strdup(menu->artifacts[index - 1]);
                if (!(*accepted)[*accepted_count]) { free(number); return 0; }
                ++*accepted_count;
            }
            if (remove) {
                for (i = 0; i < menu->source_count; ++i)
                    if (!strncmp(menu->sources[i], menu->artifacts[index - 1], 64)) break;
                if (i < menu->source_count) {
                    free(menu->sources[i]);
                    for (++i; i < menu->source_count; ++i)
                        menu->sources[i - 1] = menu->sources[i];
                    --menu->source_count;
                }
                char **other = menu->accepted_privileged;
                size_t *other_count = &menu->privileged_count;
                if (accepted == &menu->accepted_privileged) {
                    other = menu->accepted_arch;
                    other_count = &menu->accept_count;
                }
                for (i = 0; i < *other_count; ++i)
                    if (!strcmp(other[i], menu->artifacts[index - 1])) break;
                if (i < *other_count) {
                    free(other[i]);
                    for (++i; i < *other_count; ++i) other[i - 1] = other[i];
                    --*other_count;
                }
                free(menu->artifacts[index - 1]);
                for (i = (size_t)index; i < menu->count; ++i)
                    menu->artifacts[i - 1] = menu->artifacts[i];
                --menu->count;
            }
            *dirty = 1;
            free(number);
            continue;
        }
        puts("Choose a, d, x, p, s or b");
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

static int menu_disk_plan(const char *plan_path, const struct menu_state *menu)
{
    char temporary[] = "/tmp/holyinstall-disk-menu-XXXXXX";
    char *args[] = {"plan", "--config", temporary, "--output", (char *)plan_path};
    FILE *stream;
    int fd, ok, rc;
    if (!menu->disk_image) { puts("Select a disk image first"); return 3; }
    fd = mkstemp(temporary);
    if (fd < 0) return 1;
    stream = fdopen(fd, "w");
    if (!stream) { close(fd); unlink(temporary); return 1; }
    ok = menu_write(stream, menu);
    if (fflush(stream) || fsync(fd)) ok = 0;
    if (fclose(stream)) ok = 0;
    if (!ok) { unlink(temporary); return 1; }
    rc = holy_disk_main(5, args);
    unlink(temporary);
    return rc;
}

static int menu_disk_apply(const char *plan_path, const struct menu_state *menu)
{
    char *show[] = {"show", "--plan", (char *)plan_path};
    char *apply[] = {"apply", "--plan", (char *)plan_path, "--confirm", NULL};
    char *answer = NULL, *canonical = NULL;
    int rc;
    if (!menu->disk_image) { puts("Select a disk image first"); return 3; }
    rc = holy_disk_main(3, show);
    if (rc) return rc;
    canonical = realpath(menu->disk_image, NULL);
    if (!canonical) return 6;
    if (!menu_line("Type the exact disk image path to erase > ", &answer)) {
        free(canonical); free(answer); return 3;
    }
    if (strcmp(answer, canonical)) {
        puts("Confirmation does not match the selected image");
        free(canonical); free(answer); return 3;
    }
    apply[4] = answer;
    rc = holy_disk_main(5, apply);
    free(canonical); free(answer);
    return rc;
}

static int menu_run(const char *config_path, const char *plan_path,
                    const char *binary)
{
    struct menu_state menu = {0};
    char *disk_plan_path;
    int rc, prepared = 0, dirty = access(config_path, F_OK) != 0;
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
        fputs("holyinstall: menu requires a terminal\n", stderr);
        return 3;
    }
    if (strlen(plan_path) > (size_t)-1 - 6) return 2;
    disk_plan_path = malloc(strlen(plan_path) + 6);
    if (!disk_plan_path) return 1;
    sprintf(disk_plan_path, "%s.disk", plan_path);
    rc = menu_load(config_path, &menu);
    if (rc) goto done;
    for (;;) {
        char *answer = NULL;
        fputs("\nHoly installer: prepared root package stage\n1 Target root: ", stdout);
        menu_path(menu.root ? menu.root : "unset");
        printf("\n2 Packages: %zu\nDisk: ", menu.count);
        menu_path(menu.disk_image ? menu.disk_image : "unset");
        printf(" profile %s swap %s encryption %s\n",
               menu.disk_layout ? menu.disk_layout : "unset",
               menu.disk_swap ? menu.disk_swap : "none",
               menu.disk_volume ? menu.disk_volume : "none");
        printf("Config: %s\n"
               "3 Preview packages\n4 Save config\n5 Prepare package plan\n"
               "6 Install prepared packages\n7 Abort\n"
               "8 Select disk image\n9 Prepare disk plan\n10 Apply disk plan\n"
               "11 Disk filesystem, swap and encryption\n",
               dirty ? "modified" : "saved");
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
            if (input.account_count)
                printf("Accounts %zu\n", input.account_count);
            fputs("Root ", stdout);
            menu_path(input.root);
            printf("\nSet %s\nArtifacts %zu\nArchitecture overrides %zu\nSetuid approvals %zu\n",
                   hash, input.count, input.accept_count, input.privileged_count);
            for (size_t j = 0; j < input.accept_count; ++j)
                printf("accept-arch %s\n", input.accepted_arch[j]);
            for (size_t j = 0; j < input.privileged_count; ++j)
                printf("accept-privileged %s\n", input.accepted_privileged[j]);
            if (!menu_line("Type yes to install > ", &confirm)) {
                free(confirm); free_input(&input); rc = 0; break;
            }
            if (!strcmp(confirm, "yes")) {
                rc = run_package_manager(binary, &input, hash, &output);
                if (!rc) { fputs(output, stdout); puts("Package transaction complete"); }
                /* the accounts and the target's identity land after the packages, since
                   the payload that carries PAM, NSS, doas, zoneinfo and the managers is
                   what makes them usable */
                if (!rc && (rc = apply_accounts(&input)))
                    printf("Accounts failed (status %d)\n", rc);
                if (!rc && (rc = apply_target_identity(&input)))
                    printf("Target identity failed (status %d)\n", rc);
                prepared = 0;
            }
            free(confirm); free(output); free_input(&input);
            continue;
        }
        if (!strcmp(answer, "7")) { free(answer); rc = 0; break; }
        if (!strcmp(answer, "8")) {
            char *image = NULL;
            free(answer);
            if (!menu_line("Disk image (blank clears selection) > ", &image)) {
                free(image); rc = 0; break;
            }
            free(menu.disk_image);
            menu.disk_image = *image ? image : NULL;
            if (!*image) free(image);
            /* a selected disk carries a profile, and the default one is ext4 */
            if (menu.disk_image && !menu.disk_layout) menu.disk_layout = strdup("gpt-ext4");
            if (menu.disk_image && !menu.disk_layout) { rc = 1; break; }
            dirty = 1;
            prepared = 0;
            continue;
        }
        if (!strcmp(answer, "11")) {
            char *line = NULL;
            size_t index;
            free(answer);
            for (index = 0; holy_disk_layout_word(index); ++index)
                printf("%zu %s\n", index + 1, holy_disk_layout_word(index));
            printf("Number of the disk layout, 0 to keep > ");
            fflush(stdout);
            if (!menu_line("", &line)) { free(line); rc = 0; break; }
            index = (size_t)atoi(line);
            free(line);
            if (index) {
                if (index > 8) { puts("Choose 1 through 8"); continue; }
                free(menu.disk_layout);
                menu.disk_layout = strdup(holy_disk_layout_word(index - 1));
                if (!menu.disk_layout) { rc = 1; break; }
                if (strstr(menu.disk_layout, "luks2") && !menu.disk_key_file) {
                    puts("An encrypted layout needs a key file, set with option 11 again");
                    menu.disk_layout = strdup("gpt-ext4");
                    if (!menu.disk_layout) { rc = 1; break; }
                }
                dirty = 1;
                prepared = 0;
            }
            if (!menu_line("Swap in mebibytes, 0 for none > ", &line)) { free(line); rc = 0; break; }
            free(menu.disk_swap);
            menu.disk_swap = *line && strcmp(line, "0") ? line : NULL;
            if (!menu.disk_swap && *line) free(line);
            dirty = 1;
            prepared = 0;
            if (!menu_line("Luks2 volume name, blank for none > ", &line)) { free(line); rc = 0; break; }
            free(menu.disk_volume);
            menu.disk_volume = *line ? line : NULL;
            if (!*line) free(line);
            dirty = 1;
            prepared = 0;
            if (!menu_line("Luks2 key file path, blank for none > ", &line)) { free(line); rc = 0; break; }
            if (*line && line[0] != '/') { puts("The key file path is absolute"); free(line); continue; }
            free(menu.disk_key_file);
            menu.disk_key_file = *line ? line : NULL;
            if (!*line) free(line);
            dirty = 1;
            prepared = 0;
            continue;
        }
        if (!strcmp(answer, "9")) {
            free(answer);
            rc = menu_disk_plan(disk_plan_path, &menu);
            if (rc) printf("Disk plan failed (status %d)\n", rc);
            else printf("Disk plan %s ready for review\n", disk_plan_path);
            continue;
        }
        if (!strcmp(answer, "10")) {
            free(answer);
            rc = menu_disk_apply(disk_plan_path, &menu);
            if (rc) printf("Disk apply failed (status %d)\n", rc);
            else puts("Disk image prepared");
            continue;
        }
        puts("Choose 1 through 11, or 7 to abort");
        free(answer);
    }
done:
    free_menu(&menu);
    free(disk_plan_path);
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
        /* the disk plan is a document the caller reviewed, so a plan that changed after
           the review is refused before the package manager touches the root */
        if (input.disk_plan) {
            char digest[65];
            if (!digest_path(input.disk_plan, digest)) { rc = 2; goto done; }
            if (strcmp(digest, input.disk_plan_hash)) {
                fputs("holyinstall: disk plan changed since plan\n", stderr);
                rc = 3; goto done;
            }
        }
        rc = run_package_manager(binary, &input, hash, &output);
        if (!rc && fputs(output, stdout) == EOF) rc = 1;
        /* the accounts and the target's identity land after the packages, since the
           payload that carries PAM, NSS, doas, zoneinfo and the managers is what makes
           them usable */
        if (!rc) rc = apply_accounts(&input);
        if (!rc) rc = apply_target_identity(&input);
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
