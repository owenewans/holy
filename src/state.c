#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "state.h"
#include "stage.h"
#include "cache.h"
#include "preview.h"
#include "verify.h"
#include "extract.h"
#include "package.h"
#include "install.h"
#include "conflict.h"
#include "override.h"
#include "config.h"
#include "resolve.h"
#include "scan.h"
#include "deps.h"
#include "provides.h"
#include "script.h"
#include "source.h"
#include "change.h"

#include <archive.h>
#include <archive_entry.h>
#include <openssl/evp.h>
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef O_PATH
#define O_PATH 010000000
#endif

static int set_journal_present(int dir);
static int update_pending(int dir);
static int completed_transaction(int transactions, const char *name);
static int remove_record(int transactions, const char *digest,
                         unsigned long long generation, int broken, int create);
static int remove_workdir(int transactions, const char *digest,
                          unsigned long long generation, int broken);
static int commit_remove_record(int transactions, const char *digest,
                                unsigned long long generation, int broken);
static char *update_record(int dir, const char *name);
static int installed_fields(int item, const char *const *keys,
                             const char *const *values, size_t fields);
static int valid_owner_path(const char *path);
struct install_set;
static int set_override_records(struct install_set *,
                                const struct holy_override_record_info *, size_t);
static int loader_directories(const struct holy_elf_info *elf, const char *consumer,
                              char ***directories, size_t *count);
static int default_loader_directories(const char *machine, char ***directories, size_t *count);
static int search_directories(const struct holy_elf_info *elf, const char *consumer,
                              char ***directories, size_t *count);
static void free_loader_directories(char **directories, size_t count);
static int loader_file_match(const char *directory, const char *path,
                             const char *name);
static int write_all(int fd, const void *data, size_t length);
static int set_generation(int dir, unsigned long long generation);

static int native_architecture(const char *host, const char *target)
{
    return !strcmp(target, "noarch") ||
        (!strcmp(target, "x86_64") && !strcmp(host, "x86_64")) ||
        (!strcmp(target, "x86") && !strcmp(host, "i686"));
}

static int architecture_valid(const char *text)
{
    const char *space = strchr(text, ' ');
    size_t length;
    if (!space || space == text || (length = (size_t)(space - text)) > 64 ||
        strspn(text, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != length) return 0;
    return !strcmp(space + 1, "x86") || !strcmp(space + 1, "x86_64");
}

static int state_architecture(const char *state, char output[96])
{
    const char *start = strstr(state, "\narchitecture "), *end;
    output[0] = 0;
    if (!start) return 1;
    start += 14;
    end = strchr(start, '\n');
    if (!end || end == start || end - start >= 96) return 0;
    memcpy(output, start, (size_t)(end - start));
    output[end - start] = 0;
    return architecture_valid(output);
}

static int instance_architecture(int item, char output[96])
{
    char state[1024];
    ssize_t got;
    int fd = openat(item, "state", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return 0;
    got = read(fd, state, sizeof state - 1);
    close(fd);
    if (got < 1 || got == (ssize_t)sizeof state - 1 || memchr(state, 0, (size_t)got)) return 0;
    state[got] = 0;
    return state_architecture(state, output);
}

static int instance_architecture_matches(int item, const char *expected)
{
    char actual[96];
    return instance_architecture(item, actual) && !strcmp(actual, expected);
}

static int safe_directory(int fd)
{
    struct stat st;
    return !fstat(fd, &st) && S_ISDIR(st.st_mode) &&
           (st.st_uid == 0 || st.st_uid == geteuid()) &&
           !(st.st_mode & 0022);
}

static int valid_digest(const char *digest)
{
    size_t i;
    if (!digest || strlen(digest) != 64) return 0;
    for (i = 0; i < 64; ++i)
        if (!((digest[i] >= '0' && digest[i] <= '9') ||
              (digest[i] >= 'a' && digest[i] <= 'f'))) return 0;
    return 1;
}

static int child_dir(int parent, const char *name, int create)
{
    int fd;
    if (create) {
        if (mkdirat(parent, name, 0700)) {
            if (errno != EEXIST) return -1;
        } else if (fsync(parent)) return -1;
    }
    fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    if (!safe_directory(fd)) { close(fd); errno = EPERM; return -1; }
    return fd;
}

static DIR *directory_stream(int fd)
{
    int copy = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    DIR *stream;
    if (copy < 0) return NULL;
    stream = fdopendir(copy);
    if (!stream) close(copy);
    return stream;
}

static int state_dir_at(int root, int create)
{
    static const char *const path[] = { "var", "lib", "holypkg" };
    int fd = dup(root);
    size_t i;
    if (fd < 0) return -1;
    if (!safe_directory(fd)) { close(fd); errno = EPERM; return -1; }
    for (i = 0; i < sizeof path / sizeof *path; ++i) {
        int next = child_dir(fd, path[i], create);
        close(fd);
        if (next < 0) return -1;
        fd = next;
    }
    return fd;
}

static int state_dir(const char *root_path, int create)
{
    int root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int dir = root < 0 ? -1 : state_dir_at(root, create);
    if (root >= 0) close(root);
    return dir;
}

static int read_generation(int dir, unsigned long long *generation)
{
    char buffer[32];
    struct stat st;
    ssize_t got;
    size_t i;
    unsigned long long n = 0;
    int fd = openat(dir, "generation", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return 0;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 2 ||
        st.st_size > 21 || (st.st_mode & 0022) ||
        (st.st_uid != 0 && st.st_uid != geteuid())) { close(fd); return 0; }
    got = read(fd, buffer, sizeof buffer);
    close(fd);
    if (got != st.st_size || buffer[got - 1] != '\n' ||
        (got > 2 && buffer[0] == '0')) return 0;
    for (i = 0; i + 1 < (size_t)got; ++i) {
        unsigned digit = (unsigned char)buffer[i] - '0';
        if (digit > 9 || n > (ULLONG_MAX - digit) / 10) return 0;
        n = n * 10 + digit;
    }
    *generation = n;
    return 1;
}

static int state_layout(int dir, int create)
{
    static const char *const names[] = { "installed", "transactions", "index", "keys" };
    size_t i;
    for (i = 0; i < sizeof names / sizeof *names; ++i) {
        int child = child_dir(dir, names[i], create);
        if (child < 0) return 0;
        close(child);
    }
    return 1;
}

static int empty_child(int dir, const char *name)
{
    int fd = child_dir(dir, name, 0);
    DIR *entries;
    struct dirent *entry;
    int empty = 1;
    if (fd < 0) return 0;
    entries = fdopendir(fd);
    if (!entries) { close(fd); return 0; }
    errno = 0;
    while ((entry = readdir(entries)) != NULL) {
        if (!strcmp(name, "transactions") && completed_transaction(fd, entry->d_name)) {
            errno = 0; continue;
        }
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
            empty = 0;
            break;
        }
        errno = 0;
    }
    if (!entry && errno) empty = 0;
    if (closedir(entries)) empty = 0;
    if (!empty) fprintf(stderr, "holypkg: unrecognized database entries in %s\n", name);
    return empty;
}

static int instance_record_digest(int item, const char *name, char output[65])
{
    unsigned char buffer[8192], digest[32];
    unsigned int length;
    size_t total = 0, i;
    ssize_t got;
    struct stat st;
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    int fd = openat(item, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    int ok = 0;
    if (fd < 0 || !hash || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        (st.st_mode & 0022) || (st.st_uid != 0 && st.st_uid != geteuid()) ||
        (st.st_size < 1 && strcmp(name, "provides")) || st.st_size < 0 || st.st_size > 16 * 1024 * 1024 ||
        EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1) goto done;
    while ((got = read(fd, buffer, sizeof buffer)) != 0) {
        if (got < 0) { if (errno == EINTR) continue; goto done; }
        total += (size_t)got;
        if (total > 16 * 1024 * 1024 ||
            EVP_DigestUpdate(hash, buffer, (size_t)got) != 1) goto done;
    }
    if (total != (size_t)st.st_size ||
        EVP_DigestFinal_ex(hash, digest, &length) != 1 || length != 32) goto done;
    for (i = 0; i < 32; ++i) snprintf(output + i * 2, 3, "%02x", digest[i]);
    ok = 1;
done:
    if (fd >= 0) close(fd);
    EVP_MD_CTX_free(hash);
    return ok;
}

static int config_state_valid(int item, const char *artifact)
{
    char source[65], raw[65], installed[65], plan[65], actual[65];
    char *record = update_record(item, "config-state");
    int ok = 0;
    if (!record) return 0;
    if (sscanf(record,
               "format holy-config-transform-1\nsource %64[0-9a-f]\nraw %64[0-9a-f]\ninstalled %64[0-9a-f]\nplan %64[0-9a-f]\n",
               source, raw, installed, plan) != 4 ||
        !valid_digest(source) || !valid_digest(raw) || !valid_digest(installed) ||
        !valid_digest(plan) ||
        strcmp(source, artifact) ||
        !instance_record_digest(item, "package-files", actual) || strcmp(actual, raw) ||
        !instance_record_digest(item, "files", actual) || strcmp(actual, installed)) goto done;
    ok = 1;
done:
    free(record);
    return ok;
}

static int graph_digest(int item, char output[65])
{
    return instance_record_digest(item, "graph", output);
}

static int instance_state_generation(int item, const char *digest,
                                     unsigned long long *recorded)
{
    char buffer[1024], prefix[960], graph[65], source[65], source_hash[65], claims[65], architecture[96], *end;
    struct stat st;
    unsigned long long generation;
    ssize_t got;
    size_t length;
    const char *reason = "explicit";
    int version, fd = openat(item, "state", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return 0;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        (st.st_mode & 0022) || (st.st_uid != 0 && st.st_uid != geteuid()) ||
        st.st_size < 24 || st.st_size >= (off_t)sizeof buffer) {
        close(fd);
        return 0;
    }
    got = read(fd, buffer, sizeof buffer - 1);
    close(fd);
    if (got != st.st_size || buffer[got - 1] != '\n' || memchr(buffer, 0, (size_t)got)) return 0;
    buffer[got] = '\0';
    version = !strncmp(buffer, "format holy-instance-7\n", 23) ? 7 :
              !strncmp(buffer, "format holy-instance-6\n", 23) ? 6 :
              !strncmp(buffer, "format holy-instance-5\n", 23) ? 5 :
              !strncmp(buffer, "format holy-instance-4\n", 23) ? 4 :
              !strncmp(buffer, "format holy-instance-3\n", 23) ? 3 :
              !strncmp(buffer, "format holy-instance-2\n", 23) ? 2 : 1;
    if (strstr(buffer, "\nreason dependency\n")) reason = "dependency";
    if (version < 3 && (!fstatat(item, "source", &st, AT_SYMLINK_NOFOLLOW) || errno != ENOENT)) return 0;
    if (version < 4 && (!fstatat(item, "provides", &st, AT_SYMLINK_NOFOLLOW) || errno != ENOENT)) return 0;
    if (version >= 4) {
        if (!graph_digest(item, graph) || !instance_record_digest(item, "provides", claims)) return 0;
        if (!fstatat(item, "source", &st, AT_SYMLINK_NOFOLLOW)) {
            if (!holy_source_instance(item, source, source_hash)) return 0;
        } else {
            if (errno != ENOENT) return 0;
            strcpy(source, "-"); strcpy(source_hash, "-");
        }
        if (!state_architecture(buffer, architecture) ||
            (version == 5 || version == 7) != !!architecture[0]) return 0;
        if (architecture[0]) {
            const char *keys[] = {"arch"}, *values[] = {strchr(architecture, ' ') + 1};
            if (installed_fields(item, keys, values, 1) != 1) return 0;
        }
        length = (size_t)snprintf(prefix, sizeof prefix,
            "format holy-instance-%d\nsource-id %s\nsource-record %s\ndelivery local\nreason %s\nartifact %s\ngraph %s\nprovides %s\n%s%s%s%s%s%sgeneration ",
            version, source, source_hash, reason, digest, graph, claims,
            architecture[0] ? "architecture " : "", architecture, architecture[0] ? "\n" : "",
            version >= 6 ? "privileged " : "", version >= 6 ? digest : "",
            version >= 6 ? "\n" : "");
    } else if (version == 3) {
        if (!graph_digest(item, graph) || !holy_source_instance(item, source, source_hash)) return 0;
        length = (size_t)snprintf(prefix, sizeof prefix,
            "format holy-instance-3\nsource-id %s\nsource-record %s\ndelivery local\nreason %s\nartifact %s\ngraph %s\ngeneration ",
            source, source_hash, reason, digest, graph);
    } else if (version == 2) {
        if (!graph_digest(item, graph)) return 0;
        length = (size_t)snprintf(prefix, sizeof prefix,
            "format holy-instance-2\nsource-id -\ndelivery local\nreason %s\nartifact %s\ngraph %s\ngeneration ",
            reason, digest, graph);
    } else {
        if (!fstatat(item, "graph", &st, AT_SYMLINK_NOFOLLOW) || errno != ENOENT) return 0;
        length = (size_t)snprintf(prefix, sizeof prefix,
            "format holy-instance-1\nsource-id -\ndelivery local\nreason explicit\nartifact %s\ngeneration ", digest);
    }
    if (length >= sizeof prefix || (size_t)got <= length + 1 ||
        memcmp(buffer, prefix, length)) return 0;
    buffer[got - 1] = '\0';
    if (buffer[length] < '0' || buffer[length] > '9') return 0;
    errno = 0;
    generation = strtoull(buffer + length, &end, 10);
    if (errno || *end || (buffer[length] == '0' && buffer[length + 1])) return 0;
    if (recorded) *recorded = generation;
    return 1;
}

static int installed_valid(int dir)
{
    static const char *const required[] = { "meta", "files", "deps", "origin", "state", "graph", "source", "provides", "hooks", "transform", "hooks-state", "package-files", "config-state" };
    int installed = child_dir(dir, "installed", 0), ok = 1;
    DIR *list;
    struct dirent *entry;
    if (installed < 0) return 0;
    list = directory_stream(installed);
    if (!list) { close(installed); return 0; }
    errno = 0;
    while ((entry = readdir(list))) {
        int item;
        size_t i;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (!valid_digest(entry->d_name)) { ok = 0; break; }
        item = child_dir(installed, entry->d_name, 0);
        if (item < 0) { ok = 0; break; }
        for (i = 0; i < 5; ++i) {
            struct stat st;
            if (fstatat(item, required[i], &st, AT_SYMLINK_NOFOLLOW) ||
                !S_ISREG(st.st_mode) || (st.st_mode & 0022) ||
                (st.st_uid != 0 && st.st_uid != geteuid())) { ok = 0; break; }
        }
        if (ok && !instance_state_generation(item, entry->d_name, NULL)) ok = 0;
        if (ok) {
            struct stat transformed, source;
            int has_transform, has_source;
            errno = 0;
            has_transform = !fstatat(item, "config-state", &transformed, AT_SYMLINK_NOFOLLOW);
            if (!has_transform && errno != ENOENT) ok = 0;
            errno = 0;
            has_source = !fstatat(item, "package-files", &source, AT_SYMLINK_NOFOLLOW);
            if (!has_source && errno != ENOENT) ok = 0;
            if (has_transform != has_source || (has_transform &&
                (!S_ISREG(transformed.st_mode) || !S_ISREG(source.st_mode) ||
                 !config_state_valid(item, entry->d_name)))) ok = 0;
        }
        if (ok) {
            DIR *members = fdopendir(dup(item));
            struct dirent *member;
            unsigned seen = 0;
            if (!members) ok = 0;
            else {
                errno = 0;
                while ((member = readdir(members))) {
                    if (!strcmp(member->d_name, ".") ||
                        !strcmp(member->d_name, "..")) continue;
                    for (i = 0; i < sizeof required / sizeof *required; ++i)
                        if (!strcmp(member->d_name, required[i])) break;
                    if (i == sizeof required / sizeof *required ||
                        (seen & (1u << i))) { ok = 0; break; }
                    seen |= 1u << i;
                    errno = 0;
                }
                if (!member && errno) ok = 0;
                {
                    unsigned base = seen & ((1u << 8) - 1u);
                    if (base != (1u << 5) - 1u && base != (1u << 6) - 1u &&
                        base != (1u << 7) - 1u && base != ((1u << 6) - 1u + (1u << 7)) &&
                        base != (1u << 8) - 1u) ok = 0;
                }
                closedir(members);
            }
        }
        if (ok && (fstatat(item, "hooks", &(struct stat){0}, AT_SYMLINK_NOFOLLOW) == 0 ||
                   fstatat(item, "hooks-state", &(struct stat){0}, AT_SYMLINK_NOFOLLOW) == 0)) {
            char expected[96], completed[96], actual[96], digest[65];
            struct stat hooks_stat, state_stat;
            int fd;
            if (fstatat(item, "hooks", &hooks_stat, AT_SYMLINK_NOFOLLOW) ||
                !S_ISREG(hooks_stat.st_mode) || (hooks_stat.st_mode & 0022) ||
                (hooks_stat.st_uid != 0 && hooks_stat.st_uid != geteuid()) ||
                (fstatat(item, "hooks-state", &state_stat, AT_SYMLINK_NOFOLLOW) == 0) !=
                (hooks_stat.st_size > 0)) ok = 0;
            if (ok && hooks_stat.st_size > 0) {
                if (!instance_record_digest(item, "hooks", digest)) ok = 0;
                if (ok) {
                    int length = snprintf(expected, sizeof expected, "skipped sha256 %s\n", digest);
                    int completed_length = snprintf(completed, sizeof completed,
                                                    "completed sha256 %s\n", digest);
                    ssize_t got;
                    fd = openat(item, "hooks-state", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
                    if (fd < 0 || fstat(fd, &state_stat) || !S_ISREG(state_stat.st_mode) ||
                        (state_stat.st_mode & 0022) ||
                        (state_stat.st_uid != 0 && state_stat.st_uid != geteuid()) ||
                        length >= (int)sizeof expected ||
                        completed_length >= (int)sizeof completed) ok = 0;
                    else {
                        got = read(fd, actual, sizeof actual);
                        if ((got != length || memcmp(actual, expected, (size_t)length)) &&
                            (got != completed_length ||
                             memcmp(actual, completed, (size_t)completed_length))) ok = 0;
                    }
                    if (fd >= 0) close(fd);
                }
            }
        }
        if (ok && !fstatat(item, "transform", &(struct stat){0}, AT_SYMLINK_NOFOLLOW)) {
            struct stat transform_stat;
            if (fstatat(item, "transform", &transform_stat, AT_SYMLINK_NOFOLLOW) ||
                !S_ISREG(transform_stat.st_mode) || (transform_stat.st_mode & 0022) ||
                (transform_stat.st_uid != 0 && transform_stat.st_uid != geteuid())) ok = 0;
        }
        close(item);
        if (!ok) break;
        errno = 0;
    }
    if (!entry && errno) ok = 0;
    closedir(list);
    close(installed);
    if (!ok) fprintf(stderr, "holypkg: invalid installed entries\n");
    return ok;
}

static int hook_skipped(int item)
{
    char prefix[8];
    int fd = openat(item, "hooks-state", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    ssize_t got;
    if (fd < 0) return 0;
    got = read(fd, prefix, sizeof prefix);
    close(fd);
    return got == (ssize_t)sizeof prefix && !memcmp(prefix, "skipped ", sizeof prefix);
}

static int journal_exists(int dir)
{
    int transactions = child_dir(dir, "transactions", 0);
    struct stat st;
    int present;
    if (transactions < 0) return -1;
    present = fstatat(transactions, "journal", &st, AT_SYMLINK_NOFOLLOW) == 0;
    if (present && (!S_ISREG(st.st_mode) || (st.st_mode & 0022) ||
                    (st.st_uid != 0 && st.st_uid != geteuid()))) present = -1;
    if (!present && errno != ENOENT) present = -1;
    close(transactions);
    return present;
}

static int update_replace(int dir, const char *name, const char *record);

/* the phases a removal passes through, in order. the journal states the one it reached,
   so recovery finishes there rather than re-deriving where the crash fell. */
static const char *const remove_phases[] = { "files", "retired", "generation" };

/* the phases a single-artifact apply passes through, in order */
static const char *const apply_phases[] = { "payload", "instance", "generation" };

static int apply_phase_valid(const char *phase)
{
    size_t i;
    for (i = 0; i < sizeof apply_phases / sizeof *apply_phases; ++i)
        if (!strcmp(phase, apply_phases[i])) return 1;
    return 0;
}
/* a repair restores the packaged bytes, proves them and publishes the generation */
static const char *const repair_phases[] = { "payload", "generation" };

static int remove_phase_valid(const char *phase)
{
    size_t i;
    for (i = 0; i < sizeof remove_phases / sizeof *remove_phases; ++i)
        if (!strcmp(phase, remove_phases[i])) return 1;
    return 0;
}

static int repair_phase_valid(const char *phase)
{
    size_t i;
    for (i = 0; i < sizeof repair_phases / sizeof *repair_phases; ++i)
        if (!strcmp(phase, repair_phases[i])) return 1;
    return 0;
}

static int journal_valid(int dir, unsigned long long generation,
                         unsigned long long *original,
                         char artifact[65], char plan_digest[65], int *removing,
                         char phase[16])
{
    int transactions = child_dir(dir, "transactions", 0), fd = -1, result = -1;
    struct stat st;
    char buffer[256], prefix[96], digest[65], plan[65];
    ssize_t got;
    size_t length;
    unsigned long long recorded = 0;
    int is_removing = 0, attempt;
    if (transactions < 0) return -1;
    fd = openat(transactions, "journal", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) { result = errno == ENOENT ? 0 : -1; goto done; }
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 140 ||
        st.st_size > (off_t)sizeof buffer || (st.st_mode & 0022) ||
        (st.st_uid != 0 && st.st_uid != geteuid())) goto done;
    got = read(fd, buffer, sizeof buffer);
    if (got != st.st_size) goto done;
    for (attempt = 0; attempt < 6; ++attempt) {
        if (attempt >= 3 && !generation) break;
        recorded = generation - (unsigned long long)(attempt / 3);
        is_removing = attempt % 3;
        length = (size_t)snprintf(prefix, sizeof prefix,
            "format holy-journal-1\nstage %s\ngeneration %llu\nartifact ",
            is_removing == 2 ? "repairing" : is_removing ? "removing" : "applying", recorded);
        if (length >= sizeof prefix) goto done;
        if (!memcmp(buffer, prefix, length)) break;
    }
    if (attempt == 6 || (attempt >= 3 && !generation)) goto done;
    if (st.st_size < (off_t)(length + 65 + 5 + 65) ||
        buffer[length + 64] != '\n' ||
        memcmp(buffer + length + 65, "plan ", 5) ||
        buffer[length + 65 + 5 + 64] != '\n') goto done;
    /* a removal journal states its phase as a last line; one written before phases
       existed ends at the plan and leaves the phase for the recovery to infer */
    if (st.st_size != (off_t)(length + 65 + 5 + 65)) {
        size_t tail = length + 65 + 5 + 65;
        size_t name_length = (size_t)st.st_size - tail;
        char name[16];
        if (name_length < 8 || name_length > 22 ||
            memcmp(buffer + tail, "phase ", 6)) goto done;
        name_length -= 7;                       /* the phrase and the newline */
        if (name_length >= sizeof name) goto done;
        memcpy(name, buffer + tail + 6, name_length);
        name[name_length] = 0;
        /* the phase words belong to the stage that wrote them */
        if (is_removing == 2 ? !repair_phase_valid(name) :
            is_removing ? !remove_phase_valid(name) : !apply_phase_valid(name)) goto done;
        if (phase) memcpy(phase, name, name_length + 1);
    } else if (phase) phase[0] = 0;
    memcpy(digest, buffer + length, 64);
    digest[64] = '\0';
    memcpy(plan, buffer + length + 70, 64);
    plan[64] = '\0';
    if (!valid_digest(digest) || !valid_digest(plan)) goto done;
    if (original) *original = recorded;
    if (artifact) memcpy(artifact, digest, 65);
    if (plan_digest) memcpy(plan_digest, plan, 65);
    if (removing) *removing = is_removing;
    result = 1;
done:
    if (fd >= 0) close(fd);
    close(transactions);
    return result;
}

static int transaction_pending(int dir, unsigned long long generation)
{
    int transactions = child_dir(dir, "transactions", 0);
    struct stat hook;
    int hook_pending;
    if (transactions < 0) return -1;
    hook_pending = !fstatat(transactions, "hook-journal", &hook, AT_SYMLINK_NOFOLLOW);
    if (!hook_pending && errno != ENOENT) hook_pending = -1;
    if (hook_pending > 0 && (!S_ISREG(hook.st_mode) || (hook.st_mode & 0022) ||
        (hook.st_uid != 0 && hook.st_uid != geteuid()))) hook_pending = -1;
    close(transactions);
    if (hook_pending) return hook_pending;
    int result = update_pending(dir);
    if (result) return result;
    result = set_journal_present(dir);
    return result ? result : journal_valid(dir, generation, NULL, NULL, NULL, NULL, NULL);
}

static int read_reservation(int transactions, const char *name,
                            unsigned long long generation, char digest[65],
                            char approved[65])
{
    char buffer[256], prefix[96];
    struct stat st;
    ssize_t got;
    size_t length, i;
    int is_approved = 0;
    int fd = openat(transactions, name, O_RDONLY | O_NOFOLLOW |
                    O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    length = (size_t)snprintf(prefix, sizeof prefix,
        "format holy-reservation-1\nstage prepared\ngeneration %llu\nartifact ",
        generation);
    if (length >= sizeof prefix || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        (st.st_size != (off_t)(length + 65) &&
         st.st_size != (off_t)(length + 65 + 70)) || (st.st_mode & 0022) ||
        (st.st_uid != 0 && st.st_uid != geteuid())) { close(fd); return -1; }
    got = read(fd, buffer, sizeof buffer);
    close(fd);
    if (got != st.st_size || buffer[length + 64] != '\n') return -1;
    if (memcmp(buffer, prefix, length)) {
        is_approved = 1;
        length = (size_t)snprintf(prefix, sizeof prefix,
            "format holy-reservation-1\nstage approved\ngeneration %llu\nartifact ",
            generation);
        if (length >= sizeof prefix || memcmp(buffer, prefix, length) ||
            st.st_size != (off_t)(length + 65 + 70)) return -1;
    }
    for (i = 0; i < 64; ++i)
        if (!((buffer[length + i] >= '0' && buffer[length + i] <= '9') ||
              (buffer[length + i] >= 'a' && buffer[length + i] <= 'f')))
            return -1;
    memcpy(digest, buffer + length, 64);
    digest[64] = '\0';
    approved[0] = '\0';
    if (is_approved != (st.st_size != (off_t)(length + 65))) return -1;
    if (st.st_size != (off_t)(length + 65)) {
        if (memcmp(buffer + length + 65, "plan ", 5) ||
            buffer[length + 65 + 5 + 64] != '\n') return -1;
        memcpy(approved, buffer + length + 70, 64);
        approved[64] = '\0';
        if (!valid_digest(approved)) return -1;
    }
    return 1;
}

static int pending_child(int dir, unsigned long long generation, char digest[65],
                         char approved[65])
{
    int child = child_dir(dir, "transactions", 0), result = -1;
    DIR *listing;
    struct dirent *entry;
    size_t count = 0;
    if (child < 0) return -1;
    listing = directory_stream(child);
    if (!listing) { close(child); return -1; }
    errno = 0;
    while ((entry = readdir(listing))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        if (completed_transaction(child, entry->d_name)) { errno = 0; continue; }
        if (strcmp(entry->d_name, "pending") || ++count > 1) break;
        errno = 0;
    }
    if (!entry && !errno && count <= 1)
        result = read_reservation(child, "pending", generation, digest, approved);
    closedir(listing);
    close(child);
    if (result < 0) fprintf(stderr, "holypkg: unrecognized database entries in transactions\n");
    return result;
}

int holy_state_init(const char *root_path)
{
    char temp_name[43];
    unsigned long long generation;
    struct stat st;
    int dir = state_dir(root_path, 1), temp = -1, ok = 0;
    if (dir < 0) goto done;
    if (flock(dir, LOCK_EX)) goto done;
    if (!state_layout(dir, 1) ||
        !empty_child(dir, "installed") ||
        !empty_child(dir, "transactions") ||
        !empty_child(dir, "index")) goto done;
    if (fstatat(dir, "generation", &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!read_generation(dir, &generation)) goto done;
    } else if (errno != ENOENT) goto done;
    temp = holy_temporary_at(dir, temp_name);
    if (temp < 0) goto done;
    if (write(temp, "0\n", 2) != 2 || fsync(temp)) goto done;
    if (linkat(dir, temp_name, dir, "generation", 0) && errno != EEXIST)
        goto done;
    if (fsync(dir) || !read_generation(dir, &generation)) goto done;
    printf("generation %llu\n", generation);
    ok = 1;
done:
    if (!ok) fprintf(stderr, "holypkg: database init failed\n");
    if (temp >= 0) { close(temp); unlinkat(dir, temp_name, 0); }
    if (dir >= 0) close(dir);
    return ok;
}

int holy_state_status(const char *root_path, int json)
{
    unsigned long long generation;
    char digest[65], approved[65];
    int dir = state_dir(root_path, 0), pending, result = 1;
    if (dir < 0) goto done;
    if (flock(dir, LOCK_SH) || !state_layout(dir, 0) ||
        !empty_child(dir, "index") || !read_generation(dir, &generation)) goto done;
    pending = transaction_pending(dir, generation);
    if (pending < 0) goto done;
    if (pending) {
        if (json) printf("{\"schema\":\"holy-db-status-1\",\"type\":\"incomplete\",\"generation\":%llu}\n", generation);
        else printf("generation %llu\nincomplete transaction; inspect journal\n", generation);
        result = 5;
        goto done;
    }
    if (!installed_valid(dir)) goto done;
    pending = pending_child(dir, generation, digest, approved);
    if (pending < 0) goto done;
    if (json) {
        printf("{\"schema\":\"holy-db-status-1\",\"type\":\"state\",\"generation\":%llu,\"pending\":",
               generation);
        if (pending) {
            printf("{\"stage\":\"%s\",\"sha256\":\"%s\"",
                   approved[0] ? "approved" : "prepared", digest);
            if (approved[0]) printf(",\"plan\":\"%s\"", approved);
            putchar('}');
        }
        else fputs("null", stdout);
        puts("}");
    } else {
        printf("generation %llu\n", generation);
        if (pending) printf("pending %s%s%s\n", digest,
                            approved[0] ? " approved " : "", approved);
    }
    if (pending) {
        result = 5;
    } else result = 0;
done:
    if (result == 1) {
        fprintf(stderr, "holypkg: database status unavailable\n");
        if (json) puts("{\"schema\":\"holy-db-status-1\",\"type\":\"error\",\"code\":\"invalid-state\"}");
    }
    if (dir >= 0) close(dir);
    return result;
}

static int compare_instance_names(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

int holy_state_lock(const char *root_path, int exclusive,
                     unsigned long long *generation, int *status)
{
    unsigned long long current;
    char digest[65], approved[65];
    int dir = state_dir(root_path, 0), pending;
    *status = 1;
    if (dir < 0 || flock(dir, exclusive ? LOCK_EX : LOCK_SH) ||
        !state_layout(dir, 0) || !read_generation(dir, &current)) goto failed;
    pending = transaction_pending(dir, current);
    if (pending < 0) goto failed;
    if (pending) { *status = 5; goto failed; }
    pending = pending_child(dir, current, digest, approved);
    if (pending < 0) goto failed;
    if (pending) { *status = 5; goto failed; }
    if (!installed_valid(dir)) goto failed;
    *generation = current;
    *status = 0;
    return dir;
failed:
    if (dir >= 0) close(dir);
    return -1;
}

int holy_state_visit(const char *root_path, holy_instance_visit visit, void *context,
                     unsigned long long *generation)
{
    int root = -1, dir = -1, installed = -1, result = 1, pending;
    char **names = NULL, digest[65], approved[65];
    size_t count = 0, i;
    DIR *list = NULL;
    struct dirent *entry;
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0 || (dir = state_dir_at(root, 0)) < 0 || flock(dir, LOCK_SH) ||
        !state_layout(dir, 0) || !read_generation(dir, generation)) goto done;
    pending = transaction_pending(dir, *generation);
    if (pending < 0) goto done;
    if (pending) { result = 5; goto done; }
    pending = pending_child(dir, *generation, digest, approved);
    if (pending < 0) goto done;
    if (pending) { result = 5; goto done; }
    if (!installed_valid(dir) || (installed = child_dir(dir, "installed", 0)) < 0 ||
        !(list = directory_stream(installed))) goto done;
    errno = 0;
    while ((entry = readdir(list))) {
        char **grown;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (count >= SIZE_MAX / sizeof *names ||
            !(grown = realloc(names, (count + 1) * sizeof *names))) goto done;
        names = grown;
        names[count] = strdup(entry->d_name);
        if (!names[count]) goto done;
        ++count;
        errno = 0;
    }
    if (errno) goto done;
    if (count) qsort(names, count, sizeof *names, compare_instance_names);
    for (i = 0; i < count; ++i) {
        int item = child_dir(installed, names[i], 0), rc;
        if (item < 0) goto done;
        rc = visit(context, root, item, names[i]);
        close(item);
        if (rc) { result = rc; goto done; }
    }
    result = 0;
done:
    for (i = 0; i < count; ++i) free(names[i]);
    free(names);
    if (list) closedir(list);
    if (installed >= 0) close(installed);
    if (dir >= 0) close(dir);
    if (root >= 0) close(root);
    return result;
}

int holy_state_reserve(const char *digest, const char *root_path)
{
    unsigned long long generation;
    char existing[65], approved[65], temp_name[43] = {0}, record[192];
    int dir = -1, transactions = -1, temp = -1, result = 1;
    size_t length;
    if (!valid_digest(digest)) {
        fprintf(stderr, "holypkg: expected a lowercase SHA-256 digest\n");
        return 2;
    }
    dir = state_dir(root_path, 0);
    if (!holy_cache_object(digest, root_path)) { result = 6; goto done; }
    if (dir < 0 || flock(dir, LOCK_EX) || !state_layout(dir, 1) ||
        !installed_valid(dir) || !empty_child(dir, "index") ||
        !read_generation(dir, &generation)) goto done;
    result = update_pending(dir);
    if (result) { result = result > 0 ? 5 : 1; goto done; }
    result = 1;
    result = pending_child(dir, generation, existing, approved);
    if (result < 0) { result = 1; goto done; }
    if (result) { result = 5; goto done; }
    result = 1;
    transactions = child_dir(dir, "transactions", 0);
    if (transactions < 0) goto done;
    length = (size_t)snprintf(record, sizeof record,
        "format holy-reservation-1\nstage prepared\ngeneration %llu\nartifact %s\n",
        generation, digest);
    if (length >= sizeof record) goto done;
    temp = holy_temporary_at(transactions, temp_name);
    if (temp < 0 || write(temp, record, length) != (ssize_t)length || fsync(temp) ||
        linkat(transactions, temp_name, transactions, "pending", 0)) goto done;
    if (close(temp)) { temp = -1; goto done; }
    temp = -1;
    if (unlinkat(transactions, temp_name, 0) || fsync(transactions)) goto done;
    printf("reserved %s generation %llu\n", digest, generation);
    result = 0;
done:
    if (result && result != 5) fprintf(stderr, "holypkg: reservation failed\n");
    if (temp >= 0) { close(temp); unlinkat(transactions, temp_name, 0); }
    if (transactions >= 0) close(transactions);
    if (dir >= 0) close(dir);
    return result;
}

int holy_state_cancel(const char *root_path)
{
    unsigned long long generation;
    char digest[65], approved[65];
    int dir = state_dir(root_path, 0), transactions = -1, result = 1;
    if (dir < 0 || flock(dir, LOCK_EX) || !state_layout(dir, 1) ||
        !installed_valid(dir) || !empty_child(dir, "index") ||
        !read_generation(dir, &generation)) goto done;
    result = update_pending(dir);
    if (result) { result = result > 0 ? 5 : 1; goto done; }
    result = 1;
    if (pending_child(dir, generation, digest, approved) != 1) goto done;
    transactions = child_dir(dir, "transactions", 0);
    if (transactions < 0 || unlinkat(transactions, "pending", 0) ||
        fsync(transactions)) goto done;
    printf("cancelled %s\n", digest);
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: reservation cancellation failed\n");
    if (transactions >= 0) close(transactions);
    if (dir >= 0) close(dir);
    return result;
}

static int temporary_name(const char *name)
{
    size_t i;
    if (strlen(name) != 42 || strncmp(name, ".holy-tmp-", 10)) return 0;
    for (i = 10; i < 42; ++i)
        if (!((name[i] >= '0' && name[i] <= '9') ||
              (name[i] >= 'a' && name[i] <= 'f'))) return 0;
    return 1;
}

int holy_state_recover(const char *root_path)
{
    unsigned long long generation;
    char temp_name[43] = {0}, pending_digest[65], temp_digest[65];
    char pending_approved[65], temp_approved[65];
    struct stat pending_st, temp_st;
    DIR *listing = NULL;
    struct dirent *entry;
    int dir = state_dir(root_path, 0), transactions = -1;
    int has_pending = 0, result = 1;
    if (dir < 0 || flock(dir, LOCK_EX) || !state_layout(dir, 1) ||
        !empty_child(dir, "index") || !read_generation(dir, &generation)) goto done;
    result = transaction_pending(dir, generation);
    if (result < 0) { result = 1; goto done; }
    if (result) {
        fprintf(stderr, "holypkg: incomplete file transaction requires manual inspection\n");
        result = 5;
        goto done;
    }
    result = 1;
    if (!installed_valid(dir)) goto done;
    transactions = child_dir(dir, "transactions", 0);
    if (transactions < 0) goto done;
    listing = directory_stream(transactions);
    if (!listing) goto done;
    errno = 0;
    while ((entry = readdir(listing))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        if (completed_transaction(transactions, entry->d_name)) { errno = 0; continue; }
        if (!strcmp(entry->d_name, "pending")) {
            if (has_pending++) goto done;
        } else if (temporary_name(entry->d_name) && !temp_name[0]) {
            memcpy(temp_name, entry->d_name, 43);
        } else goto done;
        errno = 0;
    }
    if (errno) goto done;
    if (has_pending && (read_reservation(transactions, "pending", generation,
                                        pending_digest, pending_approved) != 1 ||
                        fstatat(transactions, "pending", &pending_st,
                                AT_SYMLINK_NOFOLLOW))) goto done;
    if (!temp_name[0]) { result = has_pending ? 5 : 0; goto done; }
    if (read_reservation(transactions, temp_name, generation,
                         temp_digest, temp_approved) != 1 ||
        fstatat(transactions, temp_name, &temp_st, AT_SYMLINK_NOFOLLOW)) goto done;
    if (has_pending && (strcmp(pending_digest, temp_digest) ||
        ((pending_st.st_dev != temp_st.st_dev ||
          pending_st.st_ino != temp_st.st_ino) &&
         !(temp_approved[0] && !pending_approved[0])))) goto done;
    if (unlinkat(transactions, temp_name, 0) || fsync(transactions)) goto done;
    printf("recovered temporary reservation %s\n", temp_digest);
    result = has_pending ? 5 : 0;
done:
    if (result == 1) fprintf(stderr, "holypkg: reservation recovery failed\n");
    if (listing) closedir(listing);
    if (transactions >= 0) close(transactions);
    if (dir >= 0) close(dir);
    return result;
}

int holy_state_preflight(const char *root_path, int json)
{
    unsigned long long generation;
    char digest[65], approved[65], *snapshot = NULL;
    int dir = state_dir(root_path, 0), pending, result = 1;
    int inspected = 0;
    const char *code = "invalid-state";
    if (dir < 0 || flock(dir, LOCK_SH) || !state_layout(dir, 0) ||
        !installed_valid(dir) || !empty_child(dir, "index") ||
        !read_generation(dir, &generation)) goto done;
    result = update_pending(dir);
    if (result) { code = "incomplete-transaction"; result = result > 0 ? 5 : 1; goto done; }
    result = 1;
    pending = pending_child(dir, generation, digest, approved);
    if (pending < 0) goto done;
    if (!pending) { result = 6; code = "unavailable-reservation"; goto done; }
    snapshot = holy_cache_snapshot(digest, root_path);
    if (!snapshot) { result = 6; code = "unavailable-artifact"; goto done; }
    inspected = 1;
    result = holy_preview_local_format(snapshot, root_path, json);
    if (result == 0 || result == 3 || result == 4) {
        if (json)
            printf("{\"schema\":\"holy-preview-1\",\"type\":\"reservation\",\"generation\":%llu,\"artifact\":\"%s\"}\n",
                   generation, digest);
        else printf("reservation generation %llu artifact %s\n", generation, digest);
    }
done:
    if (result == 6) fprintf(stderr, "holypkg: reservation preflight unavailable\n");
    if (json && !inspected && result != 0)
        printf("{\"schema\":\"holy-preview-1\",\"type\":\"error\",\"code\":\"%s\"}\n", code);
    if (snapshot) { unlink(snapshot); free(snapshot); }
    if (dir >= 0) close(dir);
    return result;
}

struct plan_hash {
    int completed;
    int accepted_privileged;
    EVP_MD_CTX *hash;
    size_t count;
    int dir;
    int claim_error;
};

static int path_available(int dir, const char *path, int directory)
{
    int installed = child_dir(dir, "installed", 0), result = -1;
    DIR *list;
    struct dirent *entry;
    if (installed < 0) return -1;
    list = directory_stream(installed);
    if (!list) { close(installed); return -1; }
    errno = 0;
    while ((entry = readdir(list))) {
        int item, files, kind;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        item = child_dir(installed, entry->d_name, 0);
        if (item < 0) goto done;
        files = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        close(item);
        if (files < 0) goto done;
        kind = holy_install_manifest_owns(files, path);
        close(files);
        if (kind < 0) goto done;
        if (kind && (kind == 1 || !directory)) {
            fprintf(stderr, "holypkg: path already claimed by %s\n", entry->d_name);
            result = 0;
            goto done;
        }
        errno = 0;
    }
    if (!errno) result = 1;
done:
    closedir(list);
    close(installed);
    return result;
}

static int hash_text(EVP_MD_CTX *hash, const char *text)
{
    char length[32];
    size_t size = strlen(text);
    int written = snprintf(length, sizeof length, "%zu:", size);
    return written > 0 && (size_t)written < sizeof length &&
           EVP_DigestUpdate(hash, length, (size_t)written) == 1 &&
           EVP_DigestUpdate(hash, text, size) == 1;
}

static int plan_entry(void *context, const struct holy_manifest_entry *entry)
{
    struct plan_hash *plan = context;
    char attributes[128];
    int written, available;
    if ((entry->link && (entry->mode != 0777 || entry->link[0] == '/')) ||
        !entry->path[0] || entry->path[0] == '/' ||
        !strcmp(entry->path, "var/lib/holypkg") ||
        !strncmp(entry->path, "var/lib/holypkg/", 16) ||
        !strcmp(entry->path, "var/cache/holypkg") ||
        !strncmp(entry->path, "var/cache/holypkg/", 18) ||
        ((entry->mode & 07000) &&
         (!plan->accepted_privileged || entry->directory || entry->link ||
          entry->hardlink || (entry->mode & 03000))) ||
        entry->uid != (long long)geteuid() ||
        entry->gid != (long long)getegid()) {
        fprintf(stderr, "holypkg: plan requires files or relative symlinks and local ownership; unsupported path: %s\n",
                entry->path);
        return 0;
    }
    available = plan->completed ? 1 : path_available(plan->dir, entry->path, entry->directory);
    if (available != 1) {
        plan->claim_error = available == 0 ? 4 : 1;
        return 0;
    }
    written = snprintf(attributes, sizeof attributes, "%c:%o:%lld:%lld:%lld:",
                       entry->directory ? 'd' : entry->link ? 'l' : entry->hardlink ? 'h' : 'f', entry->mode,
                       entry->uid, entry->gid, entry->size);
    if (written <= 0 || (size_t)written >= sizeof attributes ||
        !hash_text(plan->hash, entry->path) ||
        !hash_text(plan->hash, attributes) ||
        (entry->link && !hash_text(plan->hash, entry->link)) ||
        (entry->hardlink && !hash_text(plan->hash, entry->hardlink)) ||
        (entry->group && !hash_text(plan->hash, entry->group)) ||
        (!entry->directory && !entry->link &&
         EVP_DigestUpdate(plan->hash, entry->hash, 32) != 1)) return 0;
    ++plan->count;
    return 1;
}

static int recorded_transform(const char *snapshot)
{
    struct archive *archive = archive_read_new();
    struct archive_entry *entry;
    int status, ok = 0, found = 0;
    if (!archive) return 0;
    if (archive_read_support_filter_lz4(archive) != ARCHIVE_OK ||
        archive_read_support_format_tar(archive) != ARCHIVE_OK ||
        archive_read_open_filename(archive, snapshot, 8192) != ARCHIVE_OK)
        goto done;
    while ((status = archive_read_next_header(archive, &entry)) == ARCHIVE_OK) {
        if (!strcmp(archive_entry_pathname(entry), "HOLY/transform")) {
            if (found++ || archive_entry_filetype(entry) != AE_IFREG) goto done;
        }
        if (archive_read_data_skip(archive) != ARCHIVE_OK) goto done;
    }
    ok = status == ARCHIVE_EOF && found == 1;
done:
    archive_read_free(archive);
    return ok;
}

static int same_root(const char *root_path, const struct stat *before)
{
    struct stat after;
    int fd = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int ok = fd >= 0 && !fstat(fd, &after) &&
             before->st_dev == after.st_dev && before->st_ino == after.st_ino;
    if (fd >= 0) close(fd);
    return ok;
}

static int installed_fields(int item, const char *const *keys,
                             const char *const *values, size_t fields)
{
    struct stat st;
    char *line = NULL;
    size_t capacity = 0, number = 0;
    ssize_t length;
    int fd = openat(item, "meta", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    unsigned seen = 0;
    int matches = 1, result = -1;
    FILE *input;
    if (fd < 0) return -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        st.st_size > 16 * 1024 * 1024) { close(fd); return -1; }
    input = fdopen(fd, "r");
    if (!input) { close(fd); return -1; }
    while ((length = getline(&line, &capacity, input)) >= 0) {
        char **v = NULL, *error = NULL;
        size_t count = 0;
        ++number;
        if (memchr(line, '\0', (size_t)length) ||
            !holy_lex(line, (size_t)length, &v, &count, "installed/meta", number, &error)) {
            free(error);
            goto done;
        }
        if (count && count != 2) { holy_tokens_free(v, count); goto done; }
        if (count) {
            size_t i;
            for (i = 0; i < fields; ++i) if (!strcmp(v[0], keys[i])) {
                if (seen & (1u << i)) { holy_tokens_free(v, count); goto done; }
                seen |= 1u << i;
                if (strcmp(v[1], values[i])) matches = 0;
            }
        }
        holy_tokens_free(v, count);
    }
    if (!ferror(input) && seen == (1u << fields) - 1u && ftello(input) == st.st_size) result = matches;
done:
    free(line);
    fclose(input);
    return result;
}

/* the instance meta is the package meta the instance was installed from, so its arch,
   libc and name records are the ones the payload was proven against */
static int installed_field(int item, const char *key, char *out, size_t size)
{
    struct stat st;
    char *line = NULL;
    size_t capacity = 0, number = 0;
    ssize_t length;
    int fd = openat(item, "meta", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    int found = 0;
    FILE *input;
    if (fd < 0) return 0;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        st.st_size > 16 * 1024 * 1024) { close(fd); return 0; }
    input = fdopen(fd, "r");
    if (!input) { close(fd); return 0; }
    while (!found && (length = getline(&line, &capacity, input)) >= 0) {
        char **v = NULL, *error = NULL;
        size_t count = 0;
        ++number;
        if (memchr(line, '\0', (size_t)length) ||
            !holy_lex(line, (size_t)length, &v, &count, "installed/meta", number, &error)) {
            free(error);
            goto done;
        }
        free(error);
        if (count == 2 && !strcmp(v[0], key)) {
            if (strlen(v[1]) + 1 > size) { holy_tokens_free(v, count); goto done; }
            strcpy(out, v[1]);
            found = 1;
        }
        holy_tokens_free(v, count);
    }
    if (ferror(input)) found = 0;
done:
    free(line);
    fclose(input);
    return found;
}

int holy_state_instance_field(int instance, const char *key, char *out, size_t size)
{
    return key && out && size && installed_field(instance, key, out, size);
}

static int installed_name(int item, const char *name)
{
    const char *keys[] = {"name"}, *values[] = {name};
    return installed_fields(item, keys, values, 1);
}

static int installed_source_id(int item, char source[65])
{
    struct stat st;
    char digest[65];
    if (!fstatat(item, "source", &st, AT_SYMLINK_NOFOLLOW))
        return holy_source_instance(item, source, digest);
    if (errno != ENOENT) return 0;
    strcpy(source, "-");
    return 1;
}

int holy_state_instance_source(int instance, char source[65])
{
    return instance && source && installed_source_id(instance, source);
}

int holy_state_find_slot(const char *root_path, const char *source_id,
                         const char *name, const char *arch, const char *libc,
                         char digest[65])
{
    unsigned long long generation;
    int database = -1, installed = -1, result = 1;
    DIR *list = NULL;
    struct dirent *entry;
    size_t found = 0;
    digest[0] = 0;
    if ((!valid_digest(source_id) && strcmp(source_id, "-")) || !name || !*name ||
        (arch && !*arch) || (libc && !*libc)) return 2;
    database = holy_state_lock(root_path, 0, &generation, &result);
    if (database < 0) return result;
    result = 1;
    installed = child_dir(database, "installed", 0);
    list = installed < 0 ? NULL : directory_stream(installed);
    if (!list) goto done;
    errno = 0;
    while ((entry = readdir(list))) {
        const char *arch_key[] = {"arch"}, *libc_key[] = {"libc"};
        const char *arch_value[] = {arch}, *libc_value[] = {libc};
        char actual[65];
        int item, match;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        item = child_dir(installed, entry->d_name, 0);
        if (item < 0) goto done;
        match = installed_name(item, name);
        if (match > 0 && arch) match = installed_fields(item, arch_key, arch_value, 1);
        if (match > 0 && libc) match = installed_fields(item, libc_key, libc_value, 1);
        if (match > 0) match = installed_source_id(item, actual) ?
            !strcmp(actual, source_id) : -1;
        close(item);
        if (match < 0) goto done;
        if (match) {
            if (!valid_digest(entry->d_name)) goto done;
            ++found;
            if (found == 1) strcpy(digest, entry->d_name);
        }
        errno = 0;
    }
    if (errno) goto done;
    result = found > 1 ? 3 : found ? 0 : 6;
done:
    if (result) fprintf(stderr, "holypkg: installed source slot %s for %s\n",
                        result == 3 ? "requires arch/libc choice" : "unavailable", name);
    if (list) closedir(list);
    if (installed >= 0) close(installed);
    if (database >= 0) close(database);
    if (result) digest[0] = 0;
    return result;
}

struct hook_step {
    char *interpreter;
    char *path;
    char *body;
    size_t length;
};

struct hook_plan {
    struct hook_step steps[64];
    size_t count;
    char hash[65];
};

static void free_hook_plan(struct hook_plan *plan)
{
    size_t i;
    for (i = 0; i < plan->count; ++i) {
        free(plan->steps[i].interpreter);
        free(plan->steps[i].path);
        free(plan->steps[i].body);
    }
}

static int hook_body(int root, int files, const char *path, const char *expected,
                     char **body, size_t *length)
{
    struct open_how how = {0};
    struct stat st;
    unsigned char digest[32];
    unsigned int n;
    char actual[65];
    int fd = -1, ok = 0;
    size_t used = 0, i;
    if (!valid_owner_path(path) || holy_install_manifest_owns(files, path) != 1 ||
        holy_install_check_path(files, root, path) != 1) return 0;
    how.flags = O_RDONLY | O_CLOEXEC;
    how.resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS;
    fd = (int)syscall(SYS_openat2, root, path, &how, sizeof how);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        st.st_size > 1024 * 1024) goto done;
    *body = malloc((size_t)st.st_size + 1);
    if (!*body) goto done;
    while (used < (size_t)st.st_size) {
        ssize_t got = read(fd, *body + used, (size_t)st.st_size - used);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) goto done;
        used += (size_t)got;
    }
    for (i = 0; i < used; ++i)
        if (((unsigned char)(*body)[i] < 32 && (*body)[i] != '\n' && (*body)[i] != '\t') ||
            (unsigned char)(*body)[i] == 127) goto done;
    (*body)[used] = 0;
    if (EVP_Digest(*body, used, digest, &n, EVP_sha256(), NULL) != 1 || n != 32) goto done;
    for (i = 0; i < 32; ++i) snprintf(actual + i * 2, 3, "%02x", digest[i]);
    if (strcmp(actual, expected)) goto done;
    *length = used;
    ok = 1;
done:
    if (!ok) { free(*body); *body = NULL; }
    if (fd >= 0) close(fd);
    return ok;
}

static int hook_interpreter_digest(int root, const char *path, char output[65])
{
    struct open_how how = {0};
    struct stat st;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char buffer[8192], digest[32];
    unsigned int size;
    ssize_t got;
    int fd, ok = 0;
    size_t i;
    if (!ctx) return 0;
    how.flags = O_RDONLY | O_CLOEXEC;
    how.resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS;
    fd = (int)syscall(SYS_openat2, root, path, &how, sizeof how);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || !(st.st_mode & 0111) ||
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto done;
    for (;;) {
        got = read(fd, buffer, sizeof buffer);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) goto done;
        if (!got) break;
        if (EVP_DigestUpdate(ctx, buffer, (size_t)got) != 1) goto done;
    }
    if (EVP_DigestFinal_ex(ctx, digest, &size) != 1 || size != 32) goto done;
    for (i = 0; i < 32; ++i) snprintf(output + i * 2, 3, "%02x", digest[i]);
    ok = 1;
done:
    if (fd >= 0) close(fd);
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int prepare_hook_plan(int root, int item, const char *artifact,
                             unsigned long long generation, struct hook_plan *plan)
{
    char *hooks = update_record(item, "hooks"), *cursor;
    char number[32], device[96];
    struct stat st;
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    unsigned char bytes[32];
    unsigned int n;
    int files = -1, ok = 0;
    size_t i, line = 0;
    if (!hooks || !*hooks || !hash || fstat(root, &st)) goto done;
    files = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (files < 0) goto done;
    snprintf(device, sizeof device, "%ju:%ju", (uintmax_t)st.st_dev, (uintmax_t)st.st_ino);
    snprintf(number, sizeof number, "%llu", generation);
    if (EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1 ||
        !hash_text(hash, "holy-hook-plan-1") || !hash_text(hash, device) ||
        !hash_text(hash, number) || !hash_text(hash, artifact) || !hash_text(hash, hooks)) goto done;
    for (cursor = hooks; *cursor; ) {
        char *end = strchr(cursor, '\n'), **v = NULL, *error = NULL;
        char interpreter_hash[65];
        size_t count = 0;
        struct hook_step *step;
        if (!end || plan->count >= 64 ||
            !holy_lex(cursor, (size_t)(end - cursor), &v, &count,
                      "installed/hooks", ++line, &error)) {
            free(error); holy_tokens_free(v, count); goto done;
        }
        if (!count) { holy_tokens_free(v, count); cursor = end + 1; continue; }
        if (count != 6 || strcmp(v[0], "hook") || strcmp(v[1], "postinstall") ||
            v[2][0] != '/' || !valid_owner_path(v[2] + 1) ||
            !valid_owner_path(v[3]) || strcmp(v[4], "sha256") ||
            !valid_digest(v[5])) {
            holy_tokens_free(v, count); goto done;
        }
        step = &plan->steps[plan->count];
        step->interpreter = strdup(v[2]);
        step->path = strdup(v[3]);
        if (!step->interpreter || !step->path ||
            !hook_interpreter_digest(root, step->interpreter, interpreter_hash) ||
            !hook_body(root, files, step->path, v[5], &step->body, &step->length) ||
            !hash_text(hash, v[2]) || !hash_text(hash, v[3]) ||
            !hash_text(hash, v[5]) || !hash_text(hash, interpreter_hash) ||
            !hash_text(hash, step->body)) {
            free(step->interpreter); free(step->path); free(step->body);
            memset(step, 0, sizeof *step);
            holy_tokens_free(v, count); goto done;
        }
        ++plan->count;
        holy_tokens_free(v, count);
        cursor = end + 1;
    }
    if (!plan->count || EVP_DigestFinal_ex(hash, bytes, &n) != 1 || n != 32) goto done;
    for (i = 0; i < 32; ++i) snprintf(plan->hash + i * 2, 3, "%02x", bytes[i]);
    ok = 1;
done:
    if (files >= 0) close(files);
    EVP_MD_CTX_free(hash);
    free(hooks);
    return ok;
}

static int hook_journal_write(int transactions, unsigned long long generation,
                              const char *artifact, const char *plan,
                              const char *stage, size_t next)
{
    char record[320], temporary[43] = {0};
    int fd, ok = 0;
    int length = snprintf(record, sizeof record,
        "format holy-hook-journal-1\ngeneration %llu\nartifact %s\nplan %s\nstage %s\nnext %zu\n",
        generation, artifact, plan, stage, next);
    if (length < 0 || length >= (int)sizeof record) return 0;
    fd = holy_temporary_at(transactions, temporary);
    if (fd < 0) return 0;
    if (write_all(fd, record, (size_t)length) && !fsync(fd) && !close(fd)) {
        fd = -1;
        if (!renameat(transactions, temporary, transactions, "hook-journal") &&
            !fsync(transactions)) ok = 1;
    }
    if (fd >= 0) close(fd);
    if (!ok) unlinkat(transactions, temporary, 0);
    return ok;
}

static int hook_journal_read(int transactions, unsigned long long *generation,
                             char artifact[65], char plan[65],
                             char stage[8], size_t *next)
{
    char *record = update_record(transactions, "hook-journal"), canonical[320];
    unsigned long long saved;
    unsigned long index;
    char digest[65], checksum[65], phase[8], extra;
    int n, result = 0;
    if (!record || strlen(record) > 319 ||
        sscanf(record, "format holy-hook-journal-1\ngeneration %llu\nartifact %64[0-9a-f]\nplan %64[0-9a-f]\nstage %7[a-z]\nnext %lu\n%c",
               &saved, digest, checksum, phase, &index, &extra) != 5 ||
        !valid_digest(digest) || !valid_digest(checksum) ||
        (strcmp(phase, "ready") && strcmp(phase, "running"))) goto done;
    n = snprintf(canonical, sizeof canonical,
        "format holy-hook-journal-1\ngeneration %llu\nartifact %s\nplan %s\nstage %s\nnext %lu\n",
        saved, digest, checksum, phase, index);
    if (n < 0 || n >= (int)sizeof canonical || strcmp(record, canonical)) goto done;
    *generation = saved; *next = (size_t)index;
    strcpy(artifact, digest); strcpy(plan, checksum); strcpy(stage, phase);
    result = 1;
done:
    free(record);
    return result;
}

static int hook_journal_clean_temps(int transactions)
{
    DIR *list = directory_stream(transactions);
    struct dirent *entry;
    int ok = 1;
    if (!list) return 0;
    errno = 0;
    while ((entry = readdir(list))) {
        struct stat st;
        if (!temporary_name(entry->d_name)) { errno = 0; continue; }
        if (fstatat(transactions, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) ||
            !S_ISREG(st.st_mode) || (st.st_mode & 0022) ||
            (st.st_uid != 0 && st.st_uid != geteuid()) ||
            unlinkat(transactions, entry->d_name, 0)) { ok = 0; break; }
        errno = 0;
    }
    if (!entry && errno) ok = 0;
    closedir(list);
    return ok && !fsync(transactions);
}

static int run_hook_step(int root, const struct hook_step *step, int *exit_status)
{
    pid_t child;
    int status;
    char *script = malloc(strlen(step->path) + 2);
    *exit_status = -1;
    if (!script) return 0;
    script[0] = '/';
    strcpy(script + 1, step->path);
    child = fork();
    if (child < 0) { free(script); return 0; }
    if (!child) {
        char *const argv[] = {step->interpreter, script, NULL};
        char *const env[] = {"PATH=/usr/bin:/bin", "HOME=/", "LANG=C", NULL};
        if (fchdir(root) || chroot(".") || chdir("/")) _exit(127);
        execve(step->interpreter, argv, env);
        _exit(127);
    }
    free(script);
    while (waitpid(child, &status, 0) < 0) if (errno != EINTR) return 0;
    if (WIFEXITED(status)) *exit_status = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) *exit_status = 128 + WTERMSIG(status);
    return *exit_status == 0;
}

static int complete_hooks(int item, int transactions, int dir,
                          unsigned long long generation)
{
    char hooks_hash[65], completed[96], existing[96];
    struct stat st;
    int fd, n;
    if (!instance_record_digest(item, "hooks", hooks_hash)) return 0;
    n = snprintf(completed, sizeof completed, "completed sha256 %s\n", hooks_hash);
    if (n < 0 || n >= (int)sizeof completed) return 0;
    fd = openat(transactions, "hook-state-new", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd >= 0) {
        int written = write_all(fd, completed, (size_t)n) && !fsync(fd);
        if (close(fd)) written = 0;
        if (!written || fsync(transactions)) return 0;
    } else if (errno == EEXIST) {
        fd = openat(transactions, "hook-state-new", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
            st.st_size != n || (st.st_mode & 0022) ||
            (st.st_uid != 0 && st.st_uid != geteuid()) ||
            read(fd, existing, (size_t)n) != n || memcmp(existing, completed, (size_t)n)) {
            if (fd >= 0) close(fd);
            return 0;
        }
        close(fd);
    } else return 0;
    if (renameat(transactions, "hook-state-new", item, "hooks-state") ||
        fsync(transactions) || fsync(item)) return 0;
    if (!set_generation(dir, generation + 1) ||
        unlinkat(transactions, "hook-journal", 0) || fsync(transactions)) return 0;
    return 1;
}

int holy_state_configure(const char *digest, const char *approved,
                         const char *root_path, int retry)
{
    struct hook_plan plan = {0};
    unsigned long long generation = 0, saved_generation = 0;
    char saved_artifact[65], saved_plan[65], stage[8];
    int root = -1, dir = -1, installed = -1, item = -1, transactions = -1;
    int result = 1;
    size_t i, next = 0;
    if (!valid_digest(digest) || (approved && !valid_digest(approved))) return 2;
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) goto done;
    if (!retry) {
        dir = holy_state_lock(root_path, approved != NULL, &generation, &result);
        if (dir < 0) goto done;
    } else {
        dir = state_dir_at(root, 0);
        if (dir < 0 || flock(dir, LOCK_EX) || !state_layout(dir, 1) ||
            !read_generation(dir, &generation) || !installed_valid(dir)) goto done;
    }
    result = 1;
    installed = child_dir(dir, "installed", 0);
    transactions = child_dir(dir, "transactions", 0);
    item = installed < 0 ? -1 : child_dir(installed, digest, 0);
    if (transactions < 0 || item < 0) { result = 6; goto done; }
    if (retry) {
        if (!hook_journal_read(transactions, &saved_generation, saved_artifact,
                               saved_plan, stage, &next) ||
            (saved_generation != generation && saved_generation + 1 != generation) ||
            strcmp(saved_artifact, digest)) {
            result = 5; goto done;
        }
        if (!hook_journal_clean_temps(transactions)) { result = 5; goto done; }
        if (saved_generation + 1 == generation) {
            char *record = update_record(item, "hooks-state");
            int completed = record && !strncmp(record, "completed sha256 ", 17) &&
                !strcmp(stage, "ready");
            free(record);
            if (!completed || unlinkat(transactions, "hook-journal", 0) || fsync(transactions)) {
                result = 5; goto done;
            }
            printf("configured %s generation %llu recovered\n", digest, generation);
            result = 0; goto done;
        }
    } else if (!hook_skipped(item)) { result = 6; goto done; }
    result = 6;
    if (!prepare_hook_plan(root, item, digest, generation, &plan)) goto done;
    if (retry) {
        if (strcmp(saved_plan, plan.hash) || next > plan.count) { result = 5; goto done; }
    } else if (!approved) {
        /* the specification says a service action has to be visible before a hook runs,
           and an allowed hook keeps the powers of a root shell, so the review names the
           service tools the body spells out instead of deciding what they do */
        struct holy_script_command commands[16];
        size_t service_commands = 0;
        printf("configure-plan generation %llu artifact %s hooks %zu sha256 %s read-only\n",
               generation, digest, plan.count, plan.hash);
        for (i = 0; i < plan.count; ++i) {
            size_t found = 0, j;
            printf("hook %zu postinstall interpreter %s script /%s uid 0 root %s\n",
                   i, plan.steps[i].interpreter, plan.steps[i].path, root_path);
            fwrite(plan.steps[i].body, 1, plan.steps[i].length, stdout);
            if (!plan.steps[i].length || plan.steps[i].body[plan.steps[i].length - 1] != '\n') putchar('\n');
            holy_script_service_commands(plan.steps[i].body, plan.steps[i].length,
                                         commands, 16, &found);
            for (j = 0; j < found && j < 16; ++j)
                printf("hook %zu service-command line %zu tool %s\n",
                       i, commands[j].line, commands[j].tool);
            service_commands += found;
        }
        printf("script-review generation %llu artifact %s hooks %zu service-commands %zu read-only\n",
               generation, digest, plan.count, service_commands);
        result = ferror(stdout) ? 1 : 0;
        goto done;
    } else if (strcmp(approved, plan.hash)) { result = 3; goto done; }
    if (geteuid() != 0) { result = 6; goto done; }
    if (!retry) {
        if (!hook_journal_write(transactions, generation, digest, plan.hash, "ready", 0)) {
            result = 1; goto done;
        }
    } else if (!strcmp(stage, "running")) {
        fprintf(stderr, "holypkg: retrying hook %zu after unknown result by explicit request\n", next);
    }
    result = 5;
    for (i = next; i < plan.count; ++i) {
        int succeeded, exit_status;
        if (!hook_journal_write(transactions, generation, digest, plan.hash, "running", i)) goto done;
        if (flock(dir, LOCK_UN)) goto done;
        succeeded = run_hook_step(root, &plan.steps[i], &exit_status);
        if (flock(dir, LOCK_EX)) goto done;
        {
            unsigned long long current;
            if (!read_generation(dir, &current) || current != generation ||
                !installed_valid(dir)) goto done;
        }
        if (!succeeded) {
            fprintf(stderr, "holypkg: hook %zu exit=%d, external effects unknown; explicit retry required\n",
                    i, exit_status);
            goto done;
        }
        if (!hook_journal_write(transactions, generation, digest, plan.hash, "ready", i + 1)) goto done;
    }
    if (!complete_hooks(item, transactions, dir, generation)) goto done;
    printf("configured %s generation %llu hooks %zu\n", digest, generation + 1, plan.count);
    result = 0;
done:
    if (result && result != 3 && result != 6 && result != 5)
        fprintf(stderr, "holypkg: hook configuration failed (status %d)\n", result);
    free_hook_plan(&plan);
    if (item >= 0) close(item);
    if (transactions >= 0) close(transactions);
    if (installed >= 0) close(installed);
    if (dir >= 0) close(dir);
    if (root >= 0) close(root);
    return result;
}

static int same_slot(const struct holy_package_identity *a, const char *a_source,
                     const struct holy_package_identity *b, const char *b_source)
{
    return !strcmp(a_source, b_source) && !strcmp(a->name, b->name) &&
           !strcmp(a->os, b->os) && !strcmp(a->arch, b->arch) && !strcmp(a->libc, b->libc);
}

static int slot_available_except(int dir, const struct holy_package_identity *identity,
                                 const char *source_id, const char *replaced)
{
    const char *keys[] = {"name", "os", "arch", "libc"};
    const char *values[] = {identity->name, identity->os, identity->arch, identity->libc};
    int installed = child_dir(dir, "installed", 0), available = -1;
    DIR *list;
    struct dirent *entry;
    if (installed < 0) return -1;
    list = directory_stream(installed);
    if (!list) { close(installed); return -1; }
    errno = 0;
    while ((entry = readdir(list))) {
        int item, match;
        char source[65];
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (replaced && !strcmp(entry->d_name, replaced)) { errno = 0; continue; }
        if (!strcmp(entry->d_name, identity->digest)) { available = 0; goto done; }
        item = child_dir(installed, entry->d_name, 0);
        if (item < 0) goto done;
        match = installed_fields(item, keys, values, 4);
        if (match > 0) {
            if (!installed_source_id(item, source)) match = -1;
            else match = !strcmp(source_id, source);
        }
        close(item);
        if (match < 0) goto done;
        if (match) { available = 0; goto done; }
        errno = 0;
    }
    if (!errno) available = 1;
done:
    closedir(list);
    close(installed);
    return available;
}

static int slot_available(int dir, const struct holy_package_identity *identity,
                          const char *source_id)
{
    return slot_available_except(dir, identity, source_id, NULL);
}

static int inspect_plan(const char *root_path, int root, int dir,
                        unsigned long long generation, const char *digest,
                        char output[65], size_t *paths, char **graph_output, size_t *graph_length)
{
    struct holy_package_identity identity = {0};
    struct plan_hash plan = {0};
    struct holy_resolution resolution = {0};
    char *graph = NULL;
    size_t graph_size = 0;
    char generation_text[32], root_id[128];
    unsigned char checksum[32];
    unsigned int checksum_size;
    size_t i;
    struct stat root_st;
    struct utsname host;
    int result = 1;
    char *snapshot = NULL;
    if (fstat(root, &root_st)) goto done;
    snapshot = holy_cache_snapshot(digest, root_path);
    if (!snapshot) { result = 6; goto done; }
    result = holy_preview_local_format(snapshot, root_path, -1);
    if (result) goto done;
    result = 6;
    if (!holy_extract_preflight(snapshot) || !recorded_transform(snapshot) ||
        !holy_package_identity(snapshot, &identity) ||
        strcmp(identity.os, "linux") ||
        strcmp(identity.libc, "nolibc") || strcmp(identity.digest, digest)) goto done;
    if (strcmp(identity.arch, "noarch") &&
        (uname(&host) ||
         !((!strcmp(identity.arch, "x86_64") && !strcmp(host.machine, "x86_64")) ||
           (!strcmp(identity.arch, "x86") && !strcmp(host.machine, "i686"))))) {
        fprintf(stderr, "holypkg: plan requires native host architecture for static executables\n");
        goto done;
    }
    {
        const char *inputs[] = {snapshot};
        result = holy_resolve_collect(inputs, 1, NULL, &resolution);
        if (result) goto done;
        result = 1;
        if (!holy_resolution_record(&resolution, &graph, &graph_size)) goto done;
    }
    plan.hash = EVP_MD_CTX_new();
    plan.dir = dir;
    if (!plan.hash) { result = 1; goto done; }
    snprintf(generation_text, sizeof generation_text, "%llu", generation);
    if (snprintf(root_id, sizeof root_id, "%ju:%ju",
                 (uintmax_t)root_st.st_dev, (uintmax_t)root_st.st_ino) >=
        (int)sizeof root_id) { result = 1; goto done; }
    result = 6;
    if (EVP_DigestInit_ex(plan.hash, EVP_sha256(), NULL) != 1 ||
        !hash_text(plan.hash, "holy-readonly-plan-2") ||
        !hash_text(plan.hash, root_id) ||
        !hash_text(plan.hash, generation_text) || !hash_text(plan.hash, digest) ||
        !hash_text(plan.hash, graph) ||
        !holy_verify_visit(snapshot, plan_entry, &plan)) {
        if (plan.claim_error) result = plan.claim_error;
        goto done;
    }
    if (!holy_install_preflight(snapshot, root, 0)) { result = 4; goto done; }
    result = slot_available(dir, &identity, "-");
    if (result < 0) { result = 1; goto done; }
    if (!result) {
        fprintf(stderr, "holypkg: installed package slot already active: %s\n", identity.name);
        result = 4;
        goto done;
    }
    if (EVP_DigestFinal_ex(plan.hash, checksum, &checksum_size) != 1 ||
        checksum_size != sizeof checksum) { result = 1; goto done; }
    if (!same_root(root_path, &root_st)) { result = 4; goto done; }
    for (i = 0; i < sizeof checksum; ++i)
        snprintf(output + i * 2, 3, "%02x", checksum[i]);
    output[64] = '\0';
    *paths = plan.count;
    if (graph_output) {
        *graph_output = graph;
        *graph_length = graph_size;
        graph = NULL;
    }
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: cannot form install plan (status %d)\n", result);
    free(graph);
    holy_resolution_free(&resolution);
    EVP_MD_CTX_free(plan.hash);
    holy_package_identity_free(&identity);
    if (snapshot) { unlink(snapshot); free(snapshot); }
    return result;
}

int holy_state_plan(const char *root_path)
{
    struct stat root_st;
    unsigned long long generation;
    char digest[65], hash[65], approved[65];
    size_t paths;
    int root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int dir = root < 0 ? -1 : state_dir_at(root, 0), pending, result = 1;
    if (root < 0 || dir < 0 || flock(dir, LOCK_SH) ||
        !state_layout(dir, 0) || !installed_valid(dir) ||
        !empty_child(dir, "index") || !read_generation(dir, &generation)) goto done;
    result = update_pending(dir);
    if (result) { result = result > 0 ? 5 : 1; goto done; }
    result = 1;
    pending = pending_child(dir, generation, digest, approved);
    if (pending < 0) goto done;
    if (!pending) { result = 6; goto done; }
    result = inspect_plan(root_path, root, dir, generation, digest, hash, &paths, NULL, NULL);
    if (result) goto done;
    if (fstat(root, &root_st)) { result = 1; goto done; }
    printf("plan root %ju:%ju generation %llu artifact %s paths %zu sha256 %s read-only\n",
           (uintmax_t)root_st.st_dev, (uintmax_t)root_st.st_ino,
           generation, digest, paths, hash);
done:
    if (dir >= 0) close(dir);
    if (root >= 0) close(root);
    return result;
}

int holy_state_approve(const char *hash, const char *root_path)
{
    unsigned long long generation;
    char digest[65], approved[65], actual[65], record[256];
    char temp_name[43] = {0};
    size_t paths, length;
    int root, dir = -1, transactions = -1, temp = -1, result = 1;
    if (!valid_digest(hash)) return 2;
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) goto done;
    dir = state_dir_at(root, 0);
    if (dir < 0 || flock(dir, LOCK_EX) || !state_layout(dir, 1) ||
        !installed_valid(dir) || !empty_child(dir, "index") ||
        !read_generation(dir, &generation)) goto done;
    result = update_pending(dir);
    if (result) { result = result > 0 ? 5 : 1; goto done; }
    result = 1;
    result = pending_child(dir, generation, digest, approved);
    if (result < 0) { result = 1; goto done; }
    if (!result) { result = 6; goto done; }
    if (approved[0]) { result = 5; goto done; }
    result = inspect_plan(root_path, root, dir, generation, digest, actual, &paths, NULL, NULL);
    if (result) goto done;
    if (strcmp(hash, actual)) { result = 3; goto done; }
    result = 1;
    transactions = child_dir(dir, "transactions", 0);
    if (transactions < 0) goto done;
    length = (size_t)snprintf(record, sizeof record,
        "format holy-reservation-1\nstage approved\ngeneration %llu\nartifact %s\nplan %s\n",
        generation, digest, actual);
    if (length >= sizeof record) goto done;
    temp = holy_temporary_at(transactions, temp_name);
    if (temp < 0 || write(temp, record, length) != (ssize_t)length ||
        fsync(temp)) goto done;
    if (close(temp)) { temp = -1; goto done; }
    temp = -1;
    if (renameat(transactions, temp_name, transactions, "pending") ||
        fsync(transactions)) goto done;
    printf("approved %s generation %llu artifact %s\n", actual, generation, digest);
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: plan approval failed (status %d)\n", result);
    if (temp >= 0) close(temp);
    if (temp_name[0] && transactions >= 0) unlinkat(transactions, temp_name, 0);
    if (transactions >= 0) close(transactions);
    if (dir >= 0) close(dir);
    if (root >= 0) close(root);
    return result;
}

int holy_state_recheck(const char *root_path)
{
    unsigned long long generation;
    char digest[65], approved[65], actual[65];
    size_t paths;
    int root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int dir = root < 0 ? -1 : state_dir_at(root, 0), pending, result = 1;
    if (dir < 0 || flock(dir, LOCK_SH) || !state_layout(dir, 0) ||
        !installed_valid(dir) || !empty_child(dir, "index") ||
        !read_generation(dir, &generation)) goto done;
    result = update_pending(dir);
    if (result) { result = result > 0 ? 5 : 1; goto done; }
    result = 1;
    pending = pending_child(dir, generation, digest, approved);
    if (pending < 0) goto done;
    if (!pending || !approved[0]) { result = 5; goto done; }
    result = inspect_plan(root_path, root, dir, generation, digest, actual, &paths, NULL, NULL);
    if (result) goto done;
    if (strcmp(approved, actual)) { result = 3; goto done; }
    printf("rechecked %s generation %llu artifact %s paths %zu\n",
           approved, generation, digest, paths);
done:
    if (result) fprintf(stderr, "holypkg: approved plan recheck failed (status %d)\n", result);
    if (dir >= 0) close(dir);
    if (root >= 0) close(root);
    return result;
}

static int write_all(int fd, const void *data, size_t length)
{
    const char *p = data;
    while (length) {
        ssize_t sent = write(fd, p, length);
        if (sent < 0 && errno == EINTR) continue;
        if (sent <= 0) return 0;
        p += sent;
        length -= (size_t)sent;
    }
    return 1;
}

static int record_file(int dir, const char *name, const void *data, size_t length)
{
    int fd = openat(dir, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    int ok;
    if (fd < 0) return 0;
    ok = write_all(fd, data, length) && !fsync(fd);
    if (close(fd)) ok = 0;
    return ok && !fsync(dir);
}

static int instance_preflight(const char *snapshot)
{
    static const char *const names[] = {
        "HOLY/meta", "HOLY/files", "HOLY/deps", "HOLY/origin", "HOLY/provides"
    };
    struct archive *archive = archive_read_new();
    struct archive_entry *entry;
    int status, ok = 0;
    unsigned seen = 0;
    size_t i;
    if (!archive) return 0;
    if (archive_read_support_filter_lz4(archive) != ARCHIVE_OK ||
        archive_read_support_format_tar(archive) != ARCHIVE_OK ||
        archive_read_open_filename(archive, snapshot, 8192) != ARCHIVE_OK) goto done;
    while ((status = archive_read_next_header(archive, &entry)) == ARCHIVE_OK) {
        const char *path = archive_entry_pathname(entry);
        for (i = 0; i < sizeof names / sizeof *names; ++i)
            if (path && !strcmp(path, names[i])) break;
        if (i < sizeof names / sizeof *names) {
            if (seen & (1u << i) || archive_entry_filetype(entry) != AE_IFREG ||
                archive_entry_size(entry) < 0 ||
                archive_entry_size(entry) > 16 * 1024 * 1024) goto done;
            seen |= 1u << i;
        }
        if (archive_read_data_skip(archive) != ARCHIVE_OK) goto done;
    }
    ok = status == ARCHIVE_EOF && seen == (1u << 5) - 1u;
done:
    archive_read_free(archive);
    return ok;
}

static char *read_hooks(const char *snapshot, size_t *length)
{
    struct archive *archive = archive_read_new();
    struct archive_entry *entry;
    char *text = NULL;
    int status;
    *length = 0;
    if (!archive || archive_read_support_filter_lz4(archive) != ARCHIVE_OK ||
        archive_read_support_format_tar(archive) != ARCHIVE_OK ||
        archive_read_open_filename(archive, snapshot, 8192) != ARCHIVE_OK) goto done;
    while ((status = archive_read_next_header(archive, &entry)) == ARCHIVE_OK) {
        const char *path = archive_entry_pathname(entry);
        la_int64_t size = archive_entry_size(entry);
        if (!path || strcmp(path, "HOLY/hooks")) {
            if (archive_read_data_skip(archive) != ARCHIVE_OK) goto done;
            continue;
        }
        if (text || archive_entry_filetype(entry) != AE_IFREG || size < 0 ||
            size > 1024 * 1024) goto done;
        text = malloc((size_t)size + 1);
        if (!text) goto done;
        {
            size_t used = 0;
            while (used < (size_t)size) {
                la_ssize_t got = archive_read_data(archive, text + used, (size_t)size - used);
                if (got <= 0) goto done;
                used += (size_t)got;
            }
        }
        {
            size_t i;
            for (i = 0; i < (size_t)size; ++i)
                if (((unsigned char)text[i] < 32 && text[i] != '\n' && text[i] != '\t') ||
                    (unsigned char)text[i] == 127) goto done;
        }
        text[size] = 0;
        *length = (size_t)size;
    }
    if (status == ARCHIVE_EOF && text) {
        archive_read_free(archive);
        return text;
    }
done:
    free(text);
    if (archive) archive_read_free(archive);
    return NULL;
}

static int save_instance(int installed, const char *digest, const char *snapshot,
                         unsigned long long generation, const char *graph, size_t graph_length,
                         const char *reason, const char *source_record,
                         const char *architecture, int privileged, int skip_hooks)
{
    static const char *const names[] = { "meta", "files", "deps", "origin", "provides", "hooks", "transform" };
    struct archive *archive = NULL;
    struct archive_entry *entry;
    char buffer[65536], state[1024], graph_hash[65], source[65], source_hash[65], claims[65];
    int item = -1, status, ok = 0;
    unsigned seen = 0;
    size_t i;
    if (architecture && !architecture_valid(architecture)) return 0;
    if (mkdirat(installed, digest, 0700)) return 0;
    if (fsync(installed)) return 0;
    item = child_dir(installed, digest, 0);
    if (item < 0) goto done;
    archive = archive_read_new();
    if (!archive || archive_read_support_filter_lz4(archive) != ARCHIVE_OK ||
        archive_read_support_format_tar(archive) != ARCHIVE_OK ||
        archive_read_open_filename(archive, snapshot, 8192) != ARCHIVE_OK) goto done;
    while ((status = archive_read_next_header(archive, &entry)) == ARCHIVE_OK) {
        const char *path = archive_entry_pathname(entry);
        int fd;
        la_ssize_t got;
        la_int64_t count = 0;
        for (i = 0; i < sizeof names / sizeof *names; ++i)
            if (path && !strncmp(path, "HOLY/", 5) && !strcmp(path + 5, names[i])) break;
        if (i == sizeof names / sizeof *names) {
            if (archive_read_data_skip(archive) != ARCHIVE_OK) goto done;
            continue;
        }
        if (seen & (1u << i) || archive_entry_filetype(entry) != AE_IFREG ||
            archive_entry_size(entry) < 0 || archive_entry_size(entry) > 16 * 1024 * 1024)
            goto done;
        fd = openat(item, names[i], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) goto done;
        while ((got = archive_read_data(archive, buffer, sizeof buffer)) > 0) {
            if (count > archive_entry_size(entry) - got ||
                !write_all(fd, buffer, (size_t)got)) break;
            count += got;
        }
        if (got != 0 || count != archive_entry_size(entry) || fsync(fd)) {
            close(fd);
            goto done;
        }
        if (close(fd)) goto done;
        seen |= 1u << i;
    }
    if (status != ARCHIVE_EOF || seen != (1u << 7) - 1u) goto done;
    {
        char hooks_hash[65], hook_state[96];
        struct stat hooks_stat;
        int hooks = openat(item, "hooks", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        int has_hooks = hooks >= 0 && !fstat(hooks, &hooks_stat) && hooks_stat.st_size > 0;
        if (hooks >= 0) close(hooks);
        if (has_hooks != !!skip_hooks) goto done;
        if (has_hooks) {
            size_t n;
            if (!instance_record_digest(item, "hooks", hooks_hash)) goto done;
            n = (size_t)snprintf(hook_state, sizeof hook_state, "skipped sha256 %s\n", hooks_hash);
            if (n >= sizeof hook_state || !record_file(item, "hooks-state", hook_state, n)) goto done;
        }
    }
    if (!record_file(item, "graph", graph, graph_length) ||
        !graph_digest(item, graph_hash)) goto done;
    if (!instance_record_digest(item, "provides", claims)) goto done;
    strcpy(source, "-"); strcpy(source_hash, "-");
    if (source_record && (!record_file(item, "source", source_record, strlen(source_record)) ||
        !holy_source_instance(item, source, source_hash))) goto done;
    i = (size_t)snprintf(state, sizeof state,
        "format holy-instance-%d\nsource-id %s\nsource-record %s\ndelivery local\nreason %s\nartifact %s\ngraph %s\nprovides %s\n%s%s%s%s%s%sgeneration %llu\n",
        privileged ? architecture ? 7 : 6 : architecture ? 5 : 4,
        source, source_hash, reason, digest, graph_hash, claims,
        architecture ? "architecture " : "", architecture ? architecture : "", architecture ? "\n" : "",
        privileged ? "privileged " : "", privileged ? digest : "", privileged ? "\n" : "",
        generation + 1);
    if (i >= sizeof state || !record_file(item, "state", state, i) || fsync(item)) goto done;
    ok = 1;
done:
    if (archive) archive_read_free(archive);
    if (item >= 0) close(item);
    return ok;
}

/* the journal a single-artifact transaction writes: one stage, one generation, one
   artifact, one plan and the phase it reached as the last line */
static size_t repair_journal_text(char *out, size_t size, const char *stage,
                                  unsigned long long generation, const char *digest,
                                  const char *plan, const char *phase)
{
    int length = snprintf(out, size,
        "format holy-journal-1\nstage %s\ngeneration %llu\nartifact %s\nplan %s\n"
        "phase %s\n", stage, generation, digest, plan, phase);
    return length < 0 || (size_t)length >= size ? 0 : (size_t)length;
}

/* the generation a finished transaction publishes, written through a temporary name so
   a crash leaves the previous generation whole */
static int publish_generation(int dir, unsigned long long generation)
{
    char record[32], temp_name[43] = {0};
    size_t length = (size_t)snprintf(record, sizeof record, "%llu\n", generation + 1);
    int temp;
    if (length >= sizeof record) return 0;
    temp = holy_temporary_at(dir, temp_name);
    if (temp < 0 || !write_all(temp, record, length) || fsync(temp)) goto done;
    if (close(temp)) { temp = -1; goto done; }
    temp = -1;
    if (renameat(dir, temp_name, dir, "generation") || fsync(dir)) goto done;
    return 1;
done:
    if (temp >= 0) close(temp);
    if (temp_name[0]) unlinkat(dir, temp_name, 0);
    return 0;
}

int holy_state_apply(const char *root_path)
{
    char digest[65], approved[65], actual[65], journal[256];
    char temp_name[43] = {0};
    char *snapshot = NULL, *graph = NULL;
    size_t graph_length = 0;
    unsigned long long generation;
    struct stat st;
    size_t paths, length;
    int root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int dir = root < 0 ? -1 : state_dir_at(root, 0);
    int transactions = -1, installed = -1, temp = -1, journaled = 0, result = 1;
    if (dir < 0 || flock(dir, LOCK_EX) || !state_layout(dir, 1) ||
        !installed_valid(dir) || !empty_child(dir, "index") ||
        !read_generation(dir, &generation) || generation == ULLONG_MAX) goto done;
    result = update_pending(dir);
    if (result) { result = result > 0 ? 5 : 1; goto done; }
    result = 1;
    result = pending_child(dir, generation, digest, approved);
    if (result < 0) { result = 1; goto done; }
    if (!result || !approved[0]) { result = 5; goto done; }
    result = inspect_plan(root_path, root, dir, generation, digest, actual, &paths, &graph, &graph_length);
    if (result) goto done;
    if (strcmp(actual, approved)) { result = 3; goto done; }
    snapshot = holy_cache_snapshot(digest, root_path);
    if (!snapshot) { result = 6; goto done; }
    if (!instance_preflight(snapshot)) { result = 6; goto done; }
    if (!holy_install_preflight(snapshot, root, 0)) { result = 4; goto done; }
    installed = child_dir(dir, "installed", 0);
    transactions = child_dir(dir, "transactions", 0);
    if (installed < 0 || transactions < 0 ||
        !fstatat(installed, digest, &st, AT_SYMLINK_NOFOLLOW) ||
        errno != ENOENT) { result = 4; goto done; }
    length = repair_journal_text(journal, sizeof journal, "applying", generation,
                                 digest, approved, apply_phases[0]);
    if (!length || !record_file(transactions, "journal", journal, length)) {
        result = journal_exists(dir) ? 5 : 1;
        goto done;
    }
    journaled = 1;
    result = 5;
    if (!holy_install_payload(snapshot, root, 0) ||
        !save_instance(installed, digest, snapshot, generation, graph, graph_length, "explicit", NULL, NULL, 0, 0)) goto done;
    length = repair_journal_text(journal, sizeof journal, "applying", generation,
                                 digest, approved, apply_phases[1]);
    if (!length || !update_replace(transactions, "journal", journal)) goto done;
    if (!publish_generation(dir, generation)) goto done;
    length = repair_journal_text(journal, sizeof journal, "applying", generation,
                                 digest, approved, apply_phases[2]);
    if (!length || !update_replace(transactions, "journal", journal) ||
        unlinkat(transactions, "pending", 0) || fsync(transactions) ||
        unlinkat(transactions, "journal", 0) || fsync(transactions)) goto done;
    printf("installed %s generation %llu paths %zu\n", digest, generation + 1, paths);
    result = 0;
done:
    free(graph);
    if (result) fprintf(stderr, "holypkg: apply failed (status %d)%s\n", result,
                        journaled ? "; inspect incomplete transaction" : "");
    if (temp >= 0) close(temp);
    if (temp_name[0] && dir >= 0) unlinkat(dir, temp_name, 0);
    if (snapshot) { unlink(snapshot); free(snapshot); }
    if (installed >= 0) close(installed);
    if (transactions >= 0) close(transactions);
    if (dir >= 0) close(dir);
    if (root >= 0) close(root);
    return result;
}

int holy_state_abort_empty(const char *root_path)
{
    unsigned long long generation, recorded;
    char digest[65], plan[65], reserved[65], approved[65];
    struct stat st, root_st;
    char *snapshot = NULL;
    int root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int dir = root < 0 ? -1 : state_dir_at(root, 0);
    int transactions = -1, installed = -1, result = 1, removing = 0;
    if (dir < 0 || fstat(root, &root_st) || flock(dir, LOCK_EX) || !state_layout(dir, 1) ||
        !empty_child(dir, "index") || !read_generation(dir, &generation)) goto done;
    result = journal_valid(dir, generation, &recorded, digest, plan, &removing, NULL);
    if (result < 0) { result = 1; goto done; }
    if (!result) { result = 5; goto done; }
    result = 5;
    if (removing || recorded != generation || !installed_valid(dir)) goto done;
    transactions = child_dir(dir, "transactions", 0);
    installed = child_dir(dir, "installed", 0);
    if (transactions < 0 || installed < 0 ||
        read_reservation(transactions, "pending", generation, reserved, approved) != 1 ||
        strcmp(reserved, digest) || strcmp(approved, plan) ||
        !fstatat(installed, digest, &st, AT_SYMLINK_NOFOLLOW) || errno != ENOENT) goto done;
    snapshot = holy_cache_snapshot(digest, root_path);
    if (!snapshot || !holy_install_preflight(snapshot, root, 0) ||
        !same_root(root_path, &root_st)) goto done;
    if (unlinkat(transactions, "journal", 0) || fsync(transactions)) goto done;
    printf("aborted empty apply %s; approval retained\n", digest);
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: cannot abort incomplete transaction without manual review\n");
    if (snapshot) { unlink(snapshot); free(snapshot); }
    if (installed >= 0) close(installed);
    if (transactions >= 0) close(transactions);
    if (dir >= 0) close(dir);
    if (root >= 0) close(root);
    return result;
}

struct check_finding {
    char *path;
    char *code;
    char *target;
};

struct check_result {
    char digest[65];
    char architecture[96];
    int intact;
    struct check_finding *findings;
    size_t count;
};

static void free_check_result(struct check_result *record)
{
    size_t i;
    for (i = 0; i < record->count; ++i) {
        free(record->findings[i].path);
        free(record->findings[i].code);
        free(record->findings[i].target);
    }
    free(record->findings);
}

static int collect_finding(void *context, const char *path, const char *code,
                           const char *target)
{
    struct check_result *record = context;
    struct check_finding *grown;
    char *copy, *code_copy, *target_copy = target ? strdup(target) : NULL;
    if (record->count >= SIZE_MAX / sizeof *grown) return 0;
    if (target && !target_copy) return 0;
    copy = strdup(path);
    if (!copy) { free(target_copy); return 0; }
    code_copy = strdup(code);
    if (!code_copy) { free(copy); free(target_copy); return 0; }
    grown = realloc(record->findings, (record->count + 1) * sizeof *grown);
    if (!grown) { free(copy); free(code_copy); free(target_copy); return 0; }
    record->findings = grown;
    grown[record->count].path = copy;
    grown[record->count].code = code_copy;
    grown[record->count++].target = target_copy;
    return 1;
}

static int check_status(int checked, const struct check_result *record)
{
    size_t i;
    if (checked > 0) return 1;
    if (checked < 0 || !record->count) return checked;
    for (i = 0; i < record->count; ++i)
        if (strcmp(record->findings[i].code, "unknown-interpreter") &&
            strcmp(record->findings[i].code, "unavailable-path-resolution") &&
            strcmp(record->findings[i].code, "unknown-loader-context")) return 0;
    return 2;
}

static int check_unavailable(const struct check_result *record)
{
    size_t i;
    for (i = 0; i < record->count; ++i)
        if (!strcmp(record->findings[i].code, "unavailable-path-resolution")) return 1;
    return 0;
}

static void print_check_string(const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    putchar('"');
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') printf("\\%c", *p);
        else if (*p < 32 || *p >= 127) printf("\\u%04x", (unsigned)*p);
        else putchar(*p);
    }
    putchar('"');
}

static int print_check_result(const struct check_result *record,
                               unsigned long long generation)
{
    size_t i, primary = 0;
    if (record->intact == 0)
        for (i = 0; i < record->count; ++i)
            if (strcmp(record->findings[i].code, "unknown-interpreter") &&
                strcmp(record->findings[i].code, "unavailable-path-resolution")) {
                primary = i;
                break;
            }
    printf("{\"schema\":\"holy-installed-check-1\",\"type\":\"artifact\",\"artifact\":\"%s\",\"state\":\"%s\",\"code\":",
           record->digest, record->intact == 1 ? "pass" : record->intact == 2 ? "unknown" : "fail");
    if (record->intact == 1 || !record->count) fputs("null", stdout);
    else print_check_string(record->findings[primary].code);
    printf(",\"generation\":%llu,\"findings\":[", generation);
    for (i = 0; i < record->count; ++i) {
        const struct check_finding *finding = &record->findings[i];
        int unknown = !strcmp(finding->code, "unknown-interpreter") ||
                      !strcmp(finding->code, "unavailable-path-resolution") ||
                      !strcmp(finding->code, "unknown-loader-context") ||
                      !strcmp(finding->code, "skipped-hook");
        printf("%s{\"code\":\"%s\",\"severity\":\"%s\",\"path\":",
               i ? "," : "", finding->code, unknown ? "warning" : "error");
        print_check_string(finding->path);
        if (finding->target) {
            fputs(",\"target\":", stdout);
            print_check_string(finding->target);
        }
        fputs("}", stdout);
    }
    fputs("]", stdout);
    if (record->architecture[0]) {
        const char *space = strchr(record->architecture, ' ');
        printf(",\"architecture\":{\"code\":\"accepted-arch-mismatch\",\"host\":\"%.*s\",\"target\":\"%s\",\"execution\":\"unverified\",\"scope\":\"artifact\"}",
               (int)(space - record->architecture), record->architecture, space + 1);
    }
    puts("}");
    return !ferror(stdout);
}

static int compare_check_result(const void *a, const void *b)
{
    const struct check_result *left = a, *right = b;
    return strcmp(left->digest, right->digest);
}

struct graph_elf {
    struct holy_elf_info info;
    int seen;
};

struct graph_soname {
    const struct holy_elf_info *consumer;
    const char *consumer_path;
    const char *name;
    int root, files;
    int found, arch, versions, path_ok;
};

/* the alias names the provider file when the opened path through the root is that
   file, which is a device and inode fact rather than a manifest path, so a searched
   directory reached through a merged-/usr link still matches its own file */
static int graph_alias_match(int root, const char *directory, const char *name,
                             int regular)
{
    struct open_how how = {0};
    struct stat source, target;
    size_t prefix = strlen(directory + 1), n = strlen(name);
    char *path;
    int alias, ok = 0;
    if (prefix > SIZE_MAX - n - 2) return 0;
    path = malloc(prefix + n + 2);
    if (!path) return 0;
    memcpy(path, directory + 1, prefix);
    path[prefix] = '/';
    memcpy(path + prefix + 1, name, n + 1);
    how.flags = O_PATH | O_CLOEXEC;
    how.resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS;
    alias = (int)syscall(SYS_openat2, root, path, &how, sizeof how);
    if (alias < 0) goto done;
    ok = !fstat(alias, &target) && !fstat(regular, &source) &&
         S_ISREG(target.st_mode) && target.st_dev == source.st_dev &&
         target.st_ino == source.st_ino;
    close(alias);
done:
    free(path);
    return ok;
}

static int graph_consumer_elf(void *context, const char *path, int fd)
{
    struct graph_elf *captured = context;
    (void)path;
    if (captured->seen || holy_elf_read_fd(fd, &captured->info)) return 0;
    captured->seen = 1;
    return 1;
}

static int graph_provider_elf(void *context, const char *path, int fd)
{
    struct graph_soname *match = context;
    struct holy_elf_info info = {0};
    size_t i, j;
    int status = holy_elf_read_fd(fd, &info), versions = 1;
    if (status == 1) { holy_elf_free(&info); return 1; }
    if (status) { holy_elf_free(&info); return 0; }
    if (info.type != ET_DYN || (info.flags1 & DF_1_PIE) ||
        !info.soname || strcmp(info.soname, match->name)) goto done;
    match->found = 1;
    if (!match->consumer) { match->arch = 1; match->versions = 1; goto done; }
    if (info.elf_class != match->consumer->elf_class ||
        info.machine != match->consumer->machine) goto done;
    match->arch = 1;
    for (i = 0; i < match->consumer->version_count; ++i) {
        const struct holy_elf_version *want = &match->consumer->versions[i];
        if (want->weak || strcmp(want->provider, match->name)) continue;
        for (j = 0; j < info.defined_version_count; ++j)
            if (!strcmp(info.defined_versions[j].name, want->name)) break;
        if (j == info.defined_version_count) { versions = 0; break; }
    }
    if (versions) {
        char **directories = NULL;
        size_t count = 0, directory;
        match->versions = 1;
        if (search_directories(match->consumer, match->consumer_path,
                               &directories, &count)) {
            for (directory = 0; directory < count; ++directory) {
                struct open_how how = {0};
                char *alias;
                int opened;
                size_t a = strlen(directories[directory] + 1), b = strlen(match->name);
                if (a > SIZE_MAX - b - 2) break;
                alias = malloc(a + b + 2);
                if (!alias) break;
                memcpy(alias, directories[directory] + 1, a);
                alias[a] = '/';
                memcpy(alias + a + 1, match->name, b + 1);
                how.flags = O_PATH | O_CLOEXEC;
                how.resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS;
                opened = (int)syscall(SYS_openat2, match->root, alias, &how, sizeof how);
                free(alias);
                if (opened < 0) continue;
                close(opened);
                if (loader_file_match(directories[directory], path, match->name) ||
                    graph_alias_match(match->root, directories[directory],
                                      match->name, fd))
                    match->path_ok = 1;
                break;
            }
        }
        free_loader_directories(directories, count);
    }
done:
    holy_elf_free(&info);
    return 1;
}

static int check_soname_edge(int installed, int root, const char *consumer,
                             int provider, const char *path, const char *name,
                             const char **code)
{
    struct graph_elf captured = {0};
    struct graph_soname match = {0};
    int item = -1, files = -1, provider_files = -1, status, result = -1;
    size_t i;
    *code = "broken-provider";
    if (strcmp(path, "-")) {
        item = child_dir(installed, consumer, 0);
        files = item < 0 ? -1 : openat(item, "files", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        if (files < 0) goto done;
        status = holy_install_visit_regular(files, root, path, graph_consumer_elf, &captured);
        if (status < 0) goto done;
        if (!status || !captured.seen) { result = 0; goto done; }
        for (i = 0; i < captured.info.needed_count; ++i)
            if (!strcmp(captured.info.needed[i], name)) break;
        if (i == captured.info.needed_count) goto done;
        match.consumer = &captured.info;
        match.consumer_path = path;
    }
    match.name = name;
    provider_files = openat(provider, "files", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (provider_files < 0) goto done;
    match.root = root;
    match.files = provider_files;
    status = holy_install_visit_regular(provider_files, root, NULL, graph_provider_elf, &match);
    if (status < 0) goto done;
    if (!status) { result = 0; goto done; }
    if (!match.found || !match.arch) {
        *code = "missing-soname";
        result = 0;
    } else if (!match.versions) {
        *code = "missing-symbol-version";
        result = 0;
    } else {
        *code = "unknown-loader-context";
        result = match.consumer && !match.path_ok ? 2 : 1;
    }
done:
    holy_elf_free(&captured.info);
    if (provider_files >= 0) close(provider_files);
    if (files >= 0) close(files);
    if (item >= 0) close(item);
    return result;
}

static int check_graph(int installed, int root, const char *digest,
                        struct check_result *record)
{
    int item = child_dir(installed, digest, 0), fd, result = 1;
    FILE *stream;
    char *line = NULL;
    size_t capacity = 0, number = 0;
    ssize_t length;
    if (item < 0) return -1;
    fd = openat(item, "graph", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    close(item);
    if (fd < 0) return errno == ENOENT ? 1 : -1;
    stream = fdopen(fd, "r");
    if (!stream) { close(fd); return -1; }
    while ((length = getline(&line, &capacity, stream)) >= 0) {
        char **v = NULL, *error = NULL;
        size_t count = 0;
        int provider, intact = 1, detailed = 0;
        ++number;
        if (memchr(line, 0, (size_t)length) ||
            !holy_lex(line, (size_t)length, &v, &count, "installed/graph", number, &error)) {
            free(error); result = -1; break;
        }
        if (!count || strcmp(v[0], "edge")) { holy_tokens_free(v, count); continue; }
        if (count != 7 || !valid_digest(v[1]) || !valid_digest(v[3])) {
            holy_tokens_free(v, count); result = -1; break;
        }
        if (strcmp(v[1], digest)) { holy_tokens_free(v, count); continue; }
        provider = child_dir(installed, v[3], 0);
        if (provider < 0) intact = errno == ENOENT ? 0 : -1;
        else if (!strcmp(v[5], "soname")) {
            const char *code;
            intact = check_soname_edge(installed, root, digest, provider,
                                       v[4], v[6], &code);
            if (intact == 2) {
                if (record && !collect_finding(record, v[4], code, v[6])) result = -1;
                else if (record && result == 1) result = 0;
            } else if (!intact && record) {
                if (!collect_finding(record, v[4], code, v[6])) result = -1;
                else detailed = 1;
            }
        } else if (!strcmp(v[5], "interpreter") || !strcmp(v[5], "needed-path") ||
                 !strcmp(v[5], "shebang") || !strcmp(v[5], "path-alias")) {
            int files = openat(provider, "files", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
            intact = files < 0 || v[6][0] != '/' ? -1 : holy_install_check_path(files, root, v[6] + 1);
            if (files >= 0) close(files);
        }
        if (provider >= 0) close(provider);
        if (intact < 0) result = -1;
        else if (!intact) {
            fprintf(stderr, "holypkg: broken-provider consumer=%s requirement=%s provider=%s target=%s\n",
                    digest, v[2], v[3], v[6]);
            if (result == 1) result = 0;
            if (record && !detailed &&
                !collect_finding(record, v[6], "broken-provider", NULL)) result = -1;
        }
        holy_tokens_free(v, count);
        if (result < 0) break;
    }
    if (ferror(stream)) result = -1;
    free(line);
    fclose(stream);
    return result;
}

static int check_all(int installed, int root, unsigned long long generation, int json)
{
    struct check_result *records = NULL;
    DIR *list = NULL;
    struct dirent *entry;
    size_t count = 0, capacity = 0, i, passed = 0, failed = 0, unknown = 0;
    int result = 1, unavailable = 0;
    list = directory_stream(installed);
    if (!list) return 1;
    errno = 0;
    while ((entry = readdir(list))) {
        int item, files, status, skipped = 0;
        struct check_result *grown;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (count == capacity) {
            size_t next = capacity ? capacity * 2 : 8;
            if (next < capacity || next > SIZE_MAX / sizeof *records) goto done;
            grown = realloc(records, next * sizeof *records);
            if (!grown) goto done;
            records = grown;
            capacity = next;
        }
        item = child_dir(installed, entry->d_name, 0);
        if (item < 0) goto done;
        files = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        memset(&records[count], 0, sizeof records[count]);
        if (files < 0 || !instance_architecture(item, records[count].architecture)) {
            if (files >= 0) close(files);
            close(item); goto done;
        }
        skipped = hook_skipped(item);
        if (skipped && !collect_finding(&records[count], "HOLY/hooks", "skipped-hook", NULL)) {
            close(files); close(item); goto done;
        }
        close(item);
        memcpy(records[count].digest, entry->d_name, 65);
        ++count;
        status = holy_install_check_report(files, root,
                    collect_finding, &records[count - 1]);
        close(files);
        if (status < 0) goto done;
        if (skipped) status = 0;
        {
            int graph = check_graph(installed, root, entry->d_name, &records[count - 1]);
            if (graph < 0) goto done;
            if (!graph) status = 0;
        }
        records[count - 1].intact = check_status(status, &records[count - 1]);
        if (check_unavailable(&records[count - 1])) unavailable = 1;
        errno = 0;
    }
    if (errno) goto done;
    if (count) qsort(records, count, sizeof *records, compare_check_result);
    result = 0;
    for (i = 0; i < count; ++i) {
        int written;
        if (records[i].intact == 1) ++passed;
        else if (records[i].intact == 2) { ++unknown; result = 4; }
        else { ++failed; result = 4; }
        if (json)
            written = print_check_result(&records[i], generation) ? 0 : -1;
        else
            written = printf("%s %s generation %llu\n",
                             records[i].intact == 1 ? "intact" :
                             records[i].intact == 2 ? "unknown" : "changed",
                             records[i].digest, generation);
        if (written < 0) { result = 1; break; }
        if (!json && records[i].architecture[0] &&
            printf("accepted-arch-mismatch %s %s execution unverified scope artifact\n",
                   records[i].digest, records[i].architecture) < 0) { result = 1; break; }
        if (!json) {
            size_t j;
            for (j = 0; j < records[i].count; ++j)
                if (!strcmp(records[i].findings[j].code, "skipped-hook") &&
                    printf("skipped-hook %s installed-unconfigured\n", records[i].digest) < 0) {
                    result = 1; break;
                }
            if (result == 1) break;
        }
    }
    if (result != 1) {
        if (json) {
            if (printf("{\"schema\":\"holy-installed-check-1\",\"type\":\"summary\",\"pass\":%zu,\"fail\":%zu,\"unknown\":%zu,\"coverage\":\"data-manifest-and-direct-shebang\"}\n",
                       passed, failed, unknown) < 0) result = 1;
        } else if (count == 0 && puts("checked 0 installed packages") == EOF)
            result = 1;
    }
    if (result == 4 && unavailable) result = 6;
done:
    for (i = 0; i < count; ++i) free_check_result(&records[i]);
    free(records);
    closedir(list);
    return result;
}

int holy_state_check(const char *digest, const char *root_path, int json)
{
    struct check_result record = {0};
    unsigned long long generation;
    int root, dir = -1, installed = -1, item = -1, files = -1, result = 1, reported = 0;
    int checked, all = !strcmp(digest, "--all");
    if (!all && !valid_digest(digest)) {
        if (json) puts("{\"schema\":\"holy-installed-check-1\",\"type\":\"error\",\"code\":\"invalid-argument\",\"status\":2}");
        return 2;
    }
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) goto done;
    dir = state_dir_at(root, 0);
    if (dir < 0 || flock(dir, LOCK_SH) || !state_layout(dir, 0) ||
        !empty_child(dir, "index") || !read_generation(dir, &generation)) goto done;
    checked = transaction_pending(dir, generation);
    if (checked < 0) goto done;
    if (checked) { result = 5; goto done; }
    if (!installed_valid(dir)) goto done;
    installed = child_dir(dir, "installed", 0);
    if (installed < 0) goto done;
    if (all) {
        result = check_all(installed, root, generation, json);
        reported = result == 0 || result == 4 || result == 6;
        goto done;
    }
    item = child_dir(installed, digest, 0);
    if (item < 0) { result = 6; goto done; }
    if (!instance_architecture(item, record.architecture)) goto done;
    if (hook_skipped(item) &&
        !collect_finding(&record, "HOLY/hooks", "skipped-hook", NULL)) goto done;
    files = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (files < 0) goto done;
    checked = holy_install_check_report(files, root,
                collect_finding, &record);
    if (checked >= 0) {
        int graph = check_graph(installed, root, digest, &record);
        if (graph < 0) checked = -1;
        else if (!graph) checked = 0;
    }
    if (checked > 0 && record.count) checked = 0;
    checked = check_status(checked, &record);
    result = checked > 0 && checked != 2 ? 0 : checked >= 0 ? 4 : 1;
    if (result == 4 && check_unavailable(&record)) result = 6;
    if (json && checked >= 0) {
        memcpy(record.digest, digest, 65);
        record.intact = checked;
        if (!print_check_result(&record, generation)) { result = 1; goto done; }
        printf("{\"schema\":\"holy-installed-check-1\",\"type\":\"summary\",\"pass\":%d,\"fail\":%d,\"unknown\":%d,\"coverage\":\"data-manifest-and-direct-shebang\"}\n",
               checked == 1, checked == 0, checked == 2);
        reported = 1;
    } else if (checked >= 0 && !json)
        printf("%s %s generation %llu\n",
               checked == 1 ? "intact" : checked == 2 ? "unknown" : "changed", digest, generation);
    if (!json && (result == 0 || result == 4) && record.architecture[0])
        printf("accepted-arch-mismatch %s %s execution unverified scope artifact\n", digest, record.architecture);
    if (!json && (result == 0 || result == 4) && record.count) {
        size_t i;
        for (i = 0; i < record.count; ++i)
            if (!strcmp(record.findings[i].code, "skipped-hook"))
                printf("skipped-hook %s installed-unconfigured\n", digest);
    }
done:
    free_check_result(&record);
    if (result) fprintf(stderr, "holypkg: installed check failed (status %d)\n", result);
    if (json && result != 0 && !reported) {
        const char *code = result == 5 ? "incomplete-transaction" :
                           result == 6 ? "unavailable-instance" : "invalid-state";
        printf("{\"schema\":\"holy-installed-check-1\",\"type\":\"error\",\"code\":\"%s\",\"status\":%d}\n",
               code, result);
    }
    if (files >= 0) close(files);
    if (item >= 0) close(item);
    if (installed >= 0) close(installed);
    if (dir >= 0) close(dir);
    if (root >= 0) close(root);
    return result;
}

static int compare_installed_path(const void *left, const void *right)
{
    const char *const *a = left, *const *b = right;
    return strcmp(*a, *b);
}

int holy_state_files(const char *digest, const char *root_path)
{
    unsigned long long generation;
    char **paths = NULL, *line = NULL;
    size_t count = 0, capacity = 0, length = 0, number = 0, i;
    int database = -1, installed = -1, item = -1, fd = -1, result = 1;
    struct stat st;
    FILE *input = NULL;
    ssize_t got;
    if (!valid_digest(digest)) return 2;
    database = holy_state_lock(root_path, 0, &generation, &result);
    if (database < 0) return result;
    result = 1;
    if (!installed_valid(database) ||
        (installed = child_dir(database, "installed", 0)) < 0 ||
        (item = child_dir(installed, digest, 0)) < 0) {
        if (item < 0 && installed >= 0 && errno == ENOENT) result = 6;
        goto done;
    }
    fd = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size < 0 || st.st_size > 16 * 1024 * 1024) goto done;
    input = fdopen(fd, "r");
    if (!input) goto done;
    fd = -1;
    while ((got = getline(&line, &length, input)) >= 0) {
        char **fields = NULL, *error = NULL, *copy;
        size_t fields_count = 0;
        ++number;
        if (memchr(line, '\0', (size_t)got) ||
            !holy_lex(line, (size_t)got, &fields, &fields_count,
                      "installed/files", number, &error)) {
            free(error); holy_tokens_free(fields, fields_count); goto done;
        }
        if (fields_count) {
            int link = !strcmp(fields[0], "symlink") ||
                       !strcmp(fields[0], "hardlink");
            if ((link && fields_count != 13) ||
                (!link && fields_count != 12) ||
                (!link && strcmp(fields[0], "dir") && strcmp(fields[0], "file")) ||
                !valid_owner_path(fields[1]) || count >= 100000) {
                holy_tokens_free(fields, fields_count); goto done;
            }
            copy = strdup(fields[1]);
            if (!copy) { holy_tokens_free(fields, fields_count); goto done; }
            if (count == capacity) {
                size_t next = capacity ? capacity * 2 : 32;
                char **grown = realloc(paths, next * sizeof *grown);
                if (!grown) { free(copy); holy_tokens_free(fields, fields_count); goto done; }
                paths = grown; capacity = next;
            }
            paths[count++] = copy;
        }
        holy_tokens_free(fields, fields_count);
    }
    if (ferror(input) || ftello(input) != st.st_size) goto done;
    qsort(paths, count, sizeof *paths, compare_installed_path);
    for (i = 1; i < count; ++i) if (!strcmp(paths[i - 1], paths[i])) goto done;
    for (i = 0; i < count; ++i) {
        char *absolute = malloc(strlen(paths[i]) + 2);
        if (!absolute) goto done;
        absolute[0] = '/';
        strcpy(absolute + 1, paths[i]);
        print_check_string(absolute);
        putchar('\n');
        free(absolute);
    }
    if (ferror(stdout)) goto done;
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: installed file list failed (status %d)\n", result);
    for (i = 0; i < count; ++i) free(paths[i]);
    free(paths); free(line);
    if (input) fclose(input);
    if (fd >= 0) close(fd);
    if (item >= 0) close(item);
    if (installed >= 0) close(installed);
    if (database >= 0) close(database);
    return result;
}

/* the journal an apply keeps in transactions, with the phase it reaches */
static int record_phase(int transactions, unsigned long long generation,
                        const char *digest, const char *plan, const char *phase)
{
    char journal[256];
    size_t length = repair_journal_text(journal, sizeof journal, "applying", generation,
                                        digest, plan, phase);
    return length && update_replace(transactions, "journal", journal);
}

static size_t remove_journal_text(char *out, size_t size, unsigned long long generation,
                                  const char *digest, int broken, const char *phase)
{
    char plan[70];
    snprintf(plan, sizeof plan, "%064d", broken ? 1 : 0);
    return repair_journal_text(out, size, "removing", generation, digest, plan, phase);
}

static int finish_remove_record(int dir, int installed, int item, int transactions,
                                const char *digest, unsigned long long generation,
                                int broken, int retired)
{
    char generation_record[32], journal[256], temp_name[43] = {0};
    size_t length;
    int temp = -1, work = -1, ok = 0;
    struct stat old, observed;
    work = remove_workdir(transactions, digest, generation, broken);
    if (work < 0 || fstat(item, &old)) goto done;
    if (!retired) {
        if (!fstatat(work, "old-instance", &observed, AT_SYMLINK_NOFOLLOW) ||
            errno != ENOENT || fsync(item) ||
            renameat(installed, digest, work, "old-instance")) goto done;
    }
    if (fstatat(work, "old-instance", &observed, AT_SYMLINK_NOFOLLOW) ||
        !S_ISDIR(observed.st_mode) || old.st_dev != observed.st_dev ||
        old.st_ino != observed.st_ino || fsync(work) || fsync(installed) ||
        fsync(transactions)) goto done;
    /* the instance is retired, so a crash from here leaves the journal naming that phase
       and recovery publishes the generation instead of retiring a second time */
    length = remove_journal_text(journal, sizeof journal, generation, digest, broken,
                                 remove_phases[1]);
    if (!length || !update_replace(transactions, "journal", journal)) goto done;
    length = (size_t)snprintf(generation_record, sizeof generation_record,
                              "%llu\n", generation + 1);
    if (length >= sizeof generation_record) goto done;
    temp = holy_temporary_at(dir, temp_name);
    if (temp < 0 || !write_all(temp, generation_record, length) || fsync(temp)) goto done;
    if (close(temp)) { temp = -1; goto done; }
    temp = -1;
    if (renameat(dir, temp_name, dir, "generation") || fsync(dir)) goto done;
    /* the generation is published, so the journal says so before the record is
       committed and the journal is dropped */
    length = remove_journal_text(journal, sizeof journal, generation, digest, broken,
                                 remove_phases[2]);
    if (!length || !update_replace(transactions, "journal", journal)) goto done;
    if (!commit_remove_record(transactions, digest, generation, broken) ||
        unlinkat(transactions, "journal", 0) || fsync(transactions)) goto done;
    ok = 1;
done:
    if (work >= 0) close(work);
    if (temp >= 0) close(temp);
    if (temp_name[0]) unlinkat(dir, temp_name, 0);
    return ok;
}

static int exclusive_claims(int installed, const char *digest, int files)
{
    DIR *list = directory_stream(installed);
    struct dirent *entry;
    int result = -1;
    if (!list) return -1;
    errno = 0;
    while ((entry = readdir(list))) {
        int item, other, conflict;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..") ||
            !strcmp(entry->d_name, digest)) continue;
        item = child_dir(installed, entry->d_name, 0);
        if (item < 0) goto done;
        other = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        close(item);
        if (other < 0) goto done;
        conflict = holy_install_manifests_conflict(files, other);
        close(other);
        if (conflict < 0) goto done;
        if (conflict) {
            fprintf(stderr, "holypkg: conflicting installed ownership with %s\n", entry->d_name);
            result = 0;
            goto done;
        }
        errno = 0;
    }
    if (!errno) result = 1;
done:
    closedir(list);
    return result;
}

/* a consumer that is removed in the same group is not a broken dependent: it goes with
   the artifact it needs, so only a consumer outside the group blocks the removal. */
static int dependent_consumer(int installed, const char *digest,
                              const char *const *group, size_t group_count)
{
    DIR *list = directory_stream(installed);
    struct dirent *entry;
    int result = 0, found = 0;
    if (!list) return -1;
    errno = 0;
    while ((entry = readdir(list))) {
        FILE *stream;
        char *line = NULL;
        size_t capacity = 0, number = 0;
        ssize_t length;
        int item, fd;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        item = child_dir(installed, entry->d_name, 0);
        if (item < 0) { result = -1; break; }
        fd = openat(item, "graph", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        close(item);
        if (fd < 0) {
            if (errno == ENOENT) { errno = 0; continue; }
            result = -1; break;
        }
        stream = fdopen(fd, "r");
        if (!stream) { close(fd); result = -1; break; }
        while ((length = getline(&line, &capacity, stream)) >= 0) {
            char **v = NULL, *error = NULL;
            size_t count = 0;
            struct stat st;
            ++number;
            if (memchr(line, 0, (size_t)length) ||
                !holy_lex(line, (size_t)length, &v, &count, "installed/graph", number, &error)) {
                free(error); result = -1; break;
            }
            if (count && !strcmp(v[0], "edge")) {
                size_t member;
                int inside = 0;
                for (member = 0; member < group_count; ++member)
                    if (!strcmp(v[1], group[member])) { inside = 1; break; }
                if (count != 7 || !valid_digest(v[1]) || !valid_digest(v[3])) result = -1;
                else if (!strcmp(v[3], digest) && strcmp(v[1], digest) && !inside) {
                    if (!fstatat(installed, v[1], &st, AT_SYMLINK_NOFOLLOW)) {
                        if (!S_ISDIR(st.st_mode)) result = -1;
                        else {
                            fprintf(stderr, "holypkg: provider %s still required by %s requirement %s\n",
                                    digest, v[1], v[2]);
                            found = 1;
                        }
                    } else if (errno != ENOENT) result = -1;
                }
            }
            holy_tokens_free(v, count);
            if (result) break;
        }
        if (ferror(stream)) result = -1;
        free(line);
        fclose(stream);
        if (result) break;
        errno = 0;
    }
    if (!entry && errno) result = -1;
    closedir(list);
    return result < 0 ? -1 : found;
}

/* one artifact before anything is removed: its consumers, its manifest and its claims.
   the group runs this for every artifact before the first one is touched, so a
   conflict in the last one leaves the installed set exactly as it was. */
static int remove_precheck(int installed, int root, const char *digest, int accept_broken,
                           const char *const *group, size_t group_count, int *broken)
{
    int item, files, pending;
    pending = dependent_consumer(installed, digest, group, group_count);
    if (pending < 0) return 1;
    if (pending && !accept_broken) return 3;
    *broken = pending;
    item = child_dir(installed, digest, 0);
    if (item < 0) return 6;
    files = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (files < 0) { close(item); return 6; }
    pending = holy_install_check_manifest(files, root);
    if (pending == 1) pending = exclusive_claims(installed, digest, files);
    close(files);
    close(item);
    if (pending == 1) return 0;
    return pending == 0 ? 4 : 1;
}

/* several artifacts in one command. each removal is its own journalled transaction, so a
   crash between two of them leaves one transaction pending that db recover finishes,
   and each publishes the generation it published alone. what the group adds is that
   every artifact is checked before the first one is removed. */
int holy_state_remove_group(const char *const *digests, size_t count,
                            const char *root_path, int accept_broken)
{
    unsigned long long generation;
    char journal[256], reserved[65], approved[65];
    size_t length, i;
    int root, dir = -1, installed = -1;
    int transactions = -1, result = 1, pending;
    size_t removed = 0;
    int *broken = NULL;
    if (!count || count > 10000) return 2;
    broken = calloc(count, sizeof *broken);
    if (!broken) return 1;
    for (i = 0; i < count; ++i) if (!valid_digest(digests[i])) { free(broken); return 2; }
    for (i = 0; i < count; ++i)
        for (size_t j = 0; j < i; ++j)
            if (!strcmp(digests[i], digests[j])) { free(broken); return 2; }
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) goto done;
    dir = state_dir_at(root, 0);
    if (dir < 0 || flock(dir, LOCK_EX) || !state_layout(dir, 1) ||
        !empty_child(dir, "index") || !read_generation(dir, &generation) ||
        generation == ULLONG_MAX) goto done;
    pending = transaction_pending(dir, generation);
    if (pending < 0) goto done;
    if (pending) { result = 5; goto done; }
    if (!installed_valid(dir)) goto done;
    pending = pending_child(dir, generation, reserved, approved);
    if (pending < 0) goto done;
    if (pending) { result = 5; goto done; }
    installed = child_dir(dir, "installed", 0);
    transactions = child_dir(dir, "transactions", 0);
    if (installed < 0 || transactions < 0) goto done;
    for (i = 0; i < count; ++i) {
        result = remove_precheck(installed, root, digests[i], accept_broken, digests, count,
                                 &broken[i]);
        if (result) {
            fprintf(stderr, "holypkg: %s is not removable (status %d); nothing was removed\n",
                    digests[i], result);
            goto done;
        }
    }
    for (i = 0; i < count; ++i) {
        int item = child_dir(installed, digests[i], 0);
        int files = item < 0 ? -1 :
            openat(item, "files", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        int status = 5;
        if (item < 0 || files < 0) {
            if (item >= 0) close(item);
            result = 6;
            goto done;
        }
        if (broken[i]) fprintf(stderr, "holypkg: accepted broken dependents for %s\n",
                               digests[i]);
        length = remove_journal_text(journal, sizeof journal,
                                     generation + (unsigned long long)removed,
                                     digests[i], broken[i], remove_phases[0]);
        if (!length ||
            !record_file(transactions, "journal", journal, length) ||
            !remove_record(transactions, digests[i], generation + (unsigned long long)removed,
                           broken[i], 1) ||
            !holy_install_remove_manifest(files, root) || close(files) ||
            !finish_remove_record(dir, installed, item, transactions, digests[i],
                                  generation + (unsigned long long)removed, broken[i], 0)) {
            fprintf(stderr, "holypkg: remove failed at %s (status %d); the transactions"
                            " before it are complete\n", digests[i], status);
            files = -1;
            close(item);
            result = 5;
            goto done;
        }
        files = -1;
        printf("removed %s generation %llu\n", digests[i],
               generation + (unsigned long long)removed + 1);
        ++removed;
        close(item);
    }
    printf("removed-group artifacts %zu generation %llu\n", removed,
           generation + (unsigned long long)removed);
    result = ferror(stdout) ? 1 : 0;
done:
    if (result) fprintf(stderr, "holypkg: remove failed (status %d)\n", result);
    free(broken);
    if (installed >= 0) close(installed);
    if (transactions >= 0) close(transactions);
    if (dir >= 0) close(dir);
    if (root >= 0) close(root);
    return result;
}

int holy_state_remove(const char *digest, const char *root_path, int accept_broken)
{
    const char *digests[1] = {digest};
    return holy_state_remove_group(digests, 1, root_path, accept_broken);
}

int holy_state_continue_remove(const char *root_path)
{
    unsigned long long generation, recorded;
    char digest[65], plan[65], reserved[65], approved[65];
    int root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int dir = root < 0 ? -1 : state_dir_at(root, 0);
    int installed = -1, item = -1, transactions = -1, files = -1;
    char phase[16] = {0};
    int result = 5, removing = 0, found, retired = 0, work = -1, phased;
    struct stat removed_st;
    if (dir < 0 || flock(dir, LOCK_EX) || !state_layout(dir, 1) ||
        !empty_child(dir, "index") || !read_generation(dir, &generation) ||
        generation == ULLONG_MAX) { result = 1; goto done; }
    found = journal_valid(dir, generation, &recorded, digest, plan, &removing, phase);
    if (found < 0) { result = 1; goto done; }
    if (!found || removing != 1 ||
        (strspn(plan, "0") != 64 && strcmp(plan,
         "0000000000000000000000000000000000000000000000000000000000000001")) ||
        !installed_valid(dir)) goto done;
    transactions = child_dir(dir, "transactions", 0);
    installed = child_dir(dir, "installed", 0);
    if (transactions < 0 || installed < 0) { result = 1; goto done; }
    if (read_reservation(transactions, "pending", generation, reserved, approved) != 0)
        goto done;
    /* a journal that states a phase is finished from that phase, and one that does not
       keeps the inference the recovery has always made */
    phased = phase[0] != 0;
    if (phased) printf("resumed-phase %s\n", phase);
    if ((phased && !strcmp(phase, "generation")) || recorded != generation) {
        if (generation != recorded + 1 || !remove_record(transactions, digest, recorded,
            plan[63] == '1', 0) || fstatat(installed, digest, &removed_st, AT_SYMLINK_NOFOLLOW) == 0 ||
            errno != ENOENT || !commit_remove_record(transactions, digest, recorded,
            plan[63] == '1') || unlinkat(transactions, "journal", 0) || fsync(transactions)) goto done;
        printf("recovered removal %s generation %llu phase %s\n", digest, generation,
               phase[0] ? phase : "inferred");
        result = 0;
        goto done;
    }
    item = child_dir(installed, digest, 0);
    if (item < 0) {
        if (errno != ENOENT || !remove_record(transactions, digest, generation,
                                              plan[63] == '1', 0)) goto done;
        work = remove_workdir(transactions, digest, generation, plan[63] == '1');
        item = work < 0 ? -1 : child_dir(work, "old-instance", 0);
        if (item < 0) goto done;
        retired = 1;
    }
    files = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (files < 0 || exclusive_claims(installed, digest, files) != 1) goto done;
    /* a journal that names the retired phase has the record and the payload done, so
       recovery publishes the generation instead of removing a second time */
    if (phased && !strcmp(phase, "retired")) {
        if (!finish_remove_record(dir, installed, item, transactions, digest, generation,
                                  plan[63] == '1', 1)) goto done;
    } else if (!remove_record(transactions, digest, generation, plan[63] == '1', 1) ||
               !holy_install_finish_remove_manifest(files, root) ||
               !finish_remove_record(dir, installed, item, transactions, digest, generation,
                                     plan[63] == '1', retired)) goto done;
    printf("recovered removal %s generation %llu phase %s\n", digest, generation + 1,
           phase[0] ? phase : "inferred");
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: removal recovery requires manual inspection (status %d)\n", result);
    if (files >= 0) close(files);
    if (item >= 0) close(item);
    if (work >= 0) close(work);
    if (installed >= 0) close(installed);
    if (transactions >= 0) close(transactions);
    if (dir >= 0) close(dir);
    if (root >= 0) close(root);
    return result;
}

int holy_state_finish_apply(const char *root_path)
{
    unsigned long long generation, recorded, instance_generation;
    char digest[65], plan[65], reserved[65], approved[65], phase[16] = {0};
    int root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int dir = root < 0 ? -1 : state_dir_at(root, 0);
    int transactions = -1, installed = -1, item = -1, files = -1;
    int result = 5, removing = 0, found, unpublished = 0;
    if (dir < 0 || flock(dir, LOCK_EX) || !state_layout(dir, 1) ||
        !empty_child(dir, "index") || !read_generation(dir, &generation)) {
        result = 1;
        goto done;
    }
    found = journal_valid(dir, generation, &recorded, digest, plan, &removing, phase);
    if (found < 0) { result = 1; goto done; }
    if (!found || removing || !generation || !installed_valid(dir)) goto done;
    if (phase[0]) printf("resumed-phase %s\n", phase);
    transactions = child_dir(dir, "transactions", 0);
    installed = child_dir(dir, "installed", 0);
    if (transactions < 0 || installed < 0) { result = 1; goto done; }
    /* the instance phase proved the payload and the record, so the generation is what
       the recovery publishes; the generation phase leaves only the records to drop */
    unpublished = phase[0] && !strcmp(phase, apply_phases[1]);
    if (!unpublished && recorded != generation - 1) goto done;
    found = read_reservation(transactions, "pending", recorded, reserved, approved);
    if (found < 0 || (found && (strcmp(reserved, digest) || strcmp(approved, plan))))
        goto done;
    item = child_dir(installed, digest, 0);
    /* the record names the generation it was written against, which is the recorded one
       until the transaction publishes the next */
    if (item < 0 || !instance_state_generation(item, digest, &instance_generation) ||
        instance_generation != (unpublished ? recorded : recorded + 1)) goto done;
    files = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (files < 0 || holy_install_check_manifest(files, root) != 1) goto done;
    if (unpublished && (!publish_generation(dir, recorded) ||
        !record_phase(transactions, recorded, digest, plan, apply_phases[2])))
        goto done;
    if (found && (unlinkat(transactions, "pending", 0) || fsync(transactions))) goto done;
    if (unlinkat(transactions, "journal", 0) || fsync(transactions)) goto done;
    printf("recovered install %s generation %llu phase %s\n", digest,
           unpublished ? recorded + 1 : generation, phase[0] ? phase : "inferred");
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: install recovery requires manual inspection (status %d)\n", result);
    if (files >= 0) close(files);
    if (item >= 0) close(item);
    if (installed >= 0) close(installed);
    if (transactions >= 0) close(transactions);
    if (dir >= 0) close(dir);
    if (root >= 0) close(root);
    return result;
}

static int valid_owner_path(const char *path)
{
    const char *part = path;
    if (!*path) return 0;
    while (*part) {
        const char *end = strchr(part, '/');
        size_t length = end ? (size_t)(end - part) : strlen(part), i;
        if (!length || (length == 1 && part[0] == '.') ||
            (length == 2 && part[0] == '.' && part[1] == '.')) return 0;
        for (i = 0; i < length; ++i)
            if ((unsigned char)part[i] < 32 ||
                (unsigned char)part[i] == 127) return 0;
        if (!end) break;
        part = end + 1;
    }
    return 1;
}

static int compare_owner(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/* one committed transaction, as the record holds it: its kind, the facts its own record
   states, and the decisions that record keeps. */
struct transaction {
    char identity[65];
    char kind[8];
    /* a grouped replacement names every slot it replaced, so the facts carry them all */
    char facts[1024];
    char **decisions;
    size_t decision_count;
};

static void transaction_forget(struct transaction *one)
{
    size_t j;
    for (j = 0; j < one->decision_count; ++j) free(one->decisions[j]);
    free(one->decisions);
    one->decisions = NULL;
    one->decision_count = 0;
}

static void transaction_free(struct transaction *list, size_t count)
{
    size_t i;
    for (i = 0; i < count; ++i) transaction_forget(&list[i]);
    free(list);
}

/* the lines of a record that state a decision, in the order the record states them. a
   set keeps the journal it used, a removal one decision line, a replacement the journal
   it committed with. the lines are reported as the record holds them, so nothing is
   restated by this reader. */
static const char *const decision_keys[] = {
    "artifact ", "binding ", "catalog-index ", "accept-arch ", "accept-privileged ",
    "skip-hooks ", "service ", "accept-broken ", NULL
};

static size_t transaction_decisions(const char *record, char ***lines)
{
    size_t count = 0, capacity = 8, i;
    const char *cursor = record;
    char **list = malloc(capacity * sizeof *list);
    *lines = NULL;
    if (!list) return 0;
    while (*cursor) {
        const char *end = strchr(cursor, '\n');
        size_t length = end ? (size_t)(end - cursor) : strlen(cursor), key;
        if (!length) { cursor += length + (end ? 1 : 0); continue; }
        for (key = 0; decision_keys[key]; ++key)
            if (length > strlen(decision_keys[key]) &&
                !strncmp(cursor, decision_keys[key], strlen(decision_keys[key]))) break;
        if (decision_keys[key] && count + 1 < capacity) {
            list[count] = strndup(cursor, length);
            if (!list[count]) break;
            ++count;
        }
        cursor += length + (end ? 1 : 0);
    }
    if (count) {
        *lines = list;
        return count;
    }
    for (i = 0; i < count; ++i) free(list[i]);
    free(list);
    return 0;
}

/* the facts a record states, in the record's own words, so this reader restates
   nothing. the value is what follows one key on its line. */
static void record_value(const char *record, const char *key, char *out, size_t size)
{
    const char *cursor = record;
    size_t used = 0;
    out[0] = 0;
    while (*cursor && used + 1 < size) {
        const char *end = strchr(cursor, '\n');
        size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
        if (length > strlen(key) && !strncmp(cursor, key, strlen(key))) {
            int written = snprintf(out + used, size - used, "%.*s",
                                   (int)(length - strlen(key)), cursor + strlen(key));
            if (written < 0 || (size_t)written >= size - used) return;
            used += (size_t)written;
        }
        cursor += length + (end ? 1 : 0);
    }
}

static void record_line(const char *record, const char *key, char *out, size_t size)
{
    const char *cursor = record;
    size_t used = 0;
    out[0] = 0;
    while (*cursor && used + 1 < size) {
        const char *end = strchr(cursor, '\n');
        size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
        if (length > strlen(key) && !strncmp(cursor, key, strlen(key))) {
            int written = snprintf(out + used, size - used, "%s%.*s", used ? " " : "",
                                   (int)length, cursor);
            if (written < 0 || (size_t)written >= size - used) return;
            used += (size_t)written;
        }
        cursor += length + (end ? 1 : 0);
    }
}

static size_t transaction_count_lines(const char *record, const char *key)
{
    size_t count = 0;
    const char *cursor = record;
    while (*cursor) {
        const char *end = strchr(cursor, '\n');
        size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
        if (length > strlen(key) && !strncmp(cursor, key, strlen(key))) ++count;
        cursor += length + (end ? 1 : 0);
    }
    return count;
}

/* a transaction the root keeps is one of three shapes, and the shape is what says which
   record holds its decisions. */
static int transaction_load(const char *name, int transactions, struct transaction *out)
{
    int child = child_dir(transactions, name, 0), ok = 0;
    char *plan = NULL, *decisions = NULL, *cursor;
    if (child < 0) return 0;
    if (!completed_transaction(transactions, name)) { close(child); return 0; }
    plan = update_record(child, "plan");
    if (plan && !strncmp(plan, "format holy-remove-1\n",
                         sizeof "format holy-remove-1\n" - 1)) {
        snprintf(out->kind, sizeof out->kind, "remove");
        record_line(plan, "generation ", out->facts, sizeof out->facts);
        {
            char artifact[65] = {0};
            record_value(plan, "artifact ", artifact, sizeof artifact);
            if (artifact[0])
                snprintf(out->facts + strlen(out->facts), sizeof out->facts - strlen(out->facts),
                         " artifact %s", artifact);
        }
        decisions = update_record(child, "decisions");
        ok = 1;
    } else if (plan && (!strncmp(plan, "[update]\nformat holy-update-plan-1\n",
                                 sizeof "[update]\nformat holy-update-plan-1\n" - 1) ||
                        !strncmp(plan, "[update]\nformat holy-update-plan-2\n",
                                 sizeof "[update]\nformat holy-update-plan-2\n" - 1))) {
        char old[65] = {0}, next[65] = {0}, number[32] = {0};
        snprintf(out->kind, sizeof out->kind, "update");
        record_line(plan, "generation ", out->facts, sizeof out->facts);
        if (!strncmp(plan, "[update]\nformat holy-update-plan-2\n",
                     sizeof "[update]\nformat holy-update-plan-2\n" - 1)) {
            /* a group states every slot it replaces, so the report names them all */
            record_value(plan, "replacement ", number, sizeof number);
            if (number[0])
                snprintf(out->facts + strlen(out->facts),
                         sizeof out->facts - strlen(out->facts), " replacements %s", number);
            for (cursor = strstr(plan, "\npair "); cursor;) {
                size_t length;
                ++cursor;
                length = strcspn(cursor, "\n");
                if (length && strlen(out->facts) + length + 2 < sizeof out->facts)
                    snprintf(out->facts + strlen(out->facts),
                             sizeof out->facts - strlen(out->facts), " %.*s",
                             (int)length, cursor);
                cursor = strstr(cursor, "\npair ");
            }
        } else {
            record_value(plan, "old ", old, sizeof old);
            record_value(plan, "new ", next, sizeof next);
            if (old[0] && next[0])
                snprintf(out->facts + strlen(out->facts),
                         sizeof out->facts - strlen(out->facts),
                         " old %s new %s", old, next);
        }
        decisions = update_record(child, "journal");
        ok = 1;
    } else {
        char number[32] = {0};
        decisions = update_record(child, "decisions");
        if (decisions && !strncmp(decisions, "format holy-set-journal-",
                                  sizeof "format holy-set-journal-" - 1)) {
            snprintf(out->kind, sizeof out->kind, "set");
            record_line(decisions, "generation ", out->facts, sizeof out->facts);
            snprintf(number, sizeof number, "%zu",
                     transaction_count_lines(decisions, "artifact "));
            if (out->facts[0])
                snprintf(out->facts + strlen(out->facts),
                         sizeof out->facts - strlen(out->facts), " artifacts %s", number);
            else
                snprintf(out->facts, sizeof out->facts, "artifacts %s", number);
            ok = 1;
        }
    }
    if (ok) {
        out->decision_count = decisions ? transaction_decisions(decisions, &out->decisions) : 0;
        memcpy(out->identity, name, 65);
    }
    free(plan); free(decisions);
    close(child);
    return ok;
}

int holy_state_transactions(const char *root_path, int json)
{
    struct transaction *list = NULL;
    unsigned long long generation;
    size_t count = 0, capacity = 0, i;
    int root = -1, dir = -1, transactions = -1, result = 1;
    DIR *entries = NULL;
    struct dirent *entry;
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0 || (dir = state_dir_at(root, 0)) < 0) {
        fputs("holypkg: database unavailable\n", stderr);
        result = 6;
        goto done;
    }
    if (flock(dir, LOCK_SH) || !state_layout(dir, 0) ||
        !read_generation(dir, &generation) || !installed_valid(dir)) {
        fputs("holypkg: database unavailable\n", stderr);
        result = 6;
        goto done;
    }
    if ((transactions = child_dir(dir, "transactions", 0)) < 0 ||
        !(entries = directory_stream(transactions))) goto done;
    errno = 0;
    while ((entry = readdir(entries))) {
        struct transaction grown;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (count == capacity) {
            struct transaction *next;
            size_t size = capacity ? capacity * 2 : 16;
            if (size > SIZE_MAX / sizeof *list) goto done;
            next = realloc(list, size * sizeof *list);
            if (!next) goto done;
            list = next;
            capacity = size;
        }
        memset(&grown, 0, sizeof grown);
        if (transaction_load(entry->d_name, transactions, &grown)) list[count++] = grown;
        else transaction_forget(&grown);
        errno = 0;
    }
    if (errno) goto done;
    if (count > 1) qsort(list, count, sizeof *list, compare_owner);
    if (!count && empty_child(dir, "transactions")) {
        fprintf(stderr, "holypkg: no committed transactions\n");
        result = 6;
        goto done;
    }
    for (i = 0; i < count; ++i) {
        size_t j;
        if (json) {
            printf("{\"schema\":\"holy-transactions-1\",\"type\":\"transaction\",\"identity\":");
            print_check_string(list[i].identity);
            printf(",\"kind\":");
            print_check_string(list[i].kind);
            printf(",\"facts\":");
            print_check_string(list[i].facts);
            printf(",\"decisions\":%zu}\n", list[i].decision_count);
        } else {
            printf("transaction %s kind %s %s decisions %zu\n",
                   list[i].identity, list[i].kind, list[i].facts, list[i].decision_count);
            for (j = 0; j < list[i].decision_count; ++j)
                printf("transaction-decision %s %s\n", list[i].identity,
                       list[i].decisions[j]);
        }
    }
    if (json)
        printf("{\"schema\":\"holy-transactions-1\",\"type\":\"summary\","
               "\"generation\":%llu,\"transactions\":%zu}\n", generation, count);
    else
        printf("summary transactions %zu read-only\n", count);
    result = ferror(stdout) ? 1 : 0;
done:
    if (entries) closedir(entries);
    transaction_free(list, count);
    if (transactions >= 0) close(transactions);
    if (dir >= 0) close(dir);
    if (root >= 0) close(root);
    return result;
}

int holy_state_owner(const char *input, const char *root_path)
{
    const char *path = *input == '/' ? input + 1 : input;
    int root = -1, dir = -1, installed = -1, result = 1, found = 0;
    unsigned long long generation;
    char (*owners)[65] = NULL;
    size_t count = 0, capacity = 0, i;
    DIR *list = NULL;
    struct dirent *entry;
    if (!valid_owner_path(path)) return 2;
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) goto done;
    dir = state_dir_at(root, 0);
    if (dir < 0 || flock(dir, LOCK_SH) || !state_layout(dir, 0) ||
        !empty_child(dir, "index") || !read_generation(dir, &generation)) goto done;
    found = transaction_pending(dir, generation);
    if (found < 0) goto done;
    if (found) { result = 5; goto done; }
    if (!installed_valid(dir)) goto done;
    found = 0;
    installed = child_dir(dir, "installed", 0);
    if (installed < 0) goto done;
    list = directory_stream(installed);
    if (!list) goto done;
    errno = 0;
    while ((entry = readdir(list))) {
        int item, files, kind;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        item = child_dir(installed, entry->d_name, 0);
        if (item < 0) goto done;
        files = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        close(item);
        if (files < 0) goto done;
        kind = holy_install_manifest_owns(files, path);
        close(files);
        if (kind < 0) goto done;
        if (kind) {
            char (*grown)[65];
            if (found && (found == 1 || kind == 1)) {
                fprintf(stderr, "holypkg: conflicting installed owners for %s\n", path);
                result = 4;
                goto done;
            }
            if (count == capacity) {
                size_t next = capacity ? capacity * 2 : 4;
                if (next < capacity || next > SIZE_MAX / sizeof *owners) goto done;
                grown = realloc(owners, next * sizeof *owners);
                if (!grown) goto done;
                owners = grown;
                capacity = next;
            }
            memcpy(owners[count], entry->d_name, 65);
            ++count;
            found = kind;
        }
        errno = 0;
    }
    if (errno) goto done;
    result = found ? 0 : 6;
    if (!result) {
        qsort(owners, count, sizeof *owners, compare_owner);
        for (i = 0; i < count; ++i)
            if (printf("%s %s %s\n", owners[i],
                       found == 1 ? "file" : "directory", path) < 0) {
                result = 1;
                break;
            }
    }
done:
    free(owners);
    if (list) closedir(list);
    if (installed >= 0) close(installed);
    if (dir >= 0) close(dir);
    if (root >= 0) close(root);
    return result;
}

struct set_item {
    char *snapshot, *source_record;
    char source_id[65];
    char architecture[96];
    struct holy_package_identity identity;
    int reused;
    int privileged;
    int skipped_hooks;
};

struct privileged_scan {
    char *first;
    unsigned mode;
    size_t count;
    int unsupported;
};

static int scan_privileged(void *context, const struct holy_manifest_entry *entry)
{
    struct privileged_scan *scan = context;
    if (!(entry->mode & 07000)) return 1;
    if (entry->directory || entry->link || entry->hardlink || entry->group ||
        (entry->mode & 03000) || !(entry->mode & 0111)) {
        scan->unsupported = 1;
        return 0;
    }
    if (!scan->first) {
        scan->first = strdup(entry->path);
        if (!scan->first) return 0;
        scan->mode = entry->mode;
    }
    ++scan->count;
    return 1;
}

struct set_claim {
    char *path;
    unsigned mode;
    long long uid, gid;
    int directory;
};

/* a service unit is a file the boot profile starts on its own: dinit starts every
   service in its services directory, so placing one there is enabling it and starting
   it, which the spec says takes a consent of its own. the plan states every unit a set
   would place, so the review document names what would start at the next boot. */
struct set_service {
    char *path;
    char *artifact;
};

struct service_list {
    struct set_service *items;
    size_t count;
};

struct install_set {
    struct holy_resolution resolution;
    struct set_item *items;
    size_t count, paths;
    struct holy_conflict_claims capabilities;
    size_t capability_findings;
    struct set_claim *claims;
    size_t claim_count;
    char *graph;
    size_t graph_length;
    char **bindings;
    size_t binding_count;
    struct holy_override_record_info *overrides;
    size_t override_count;
    struct service_list services;
    char hash[65];
    char host[65];
    char catalog_index[65];
};

struct set_journal {
    unsigned long long generation;
    char hash[65], root[65];
    char catalog_index[65];
    char phase[32];              /* the mutation phase this transaction reached */
    char *choice;
    char **digests, **bindings;
    size_t count, binding_count;
    char **accepted_arch, host[65];
    size_t accepted_count;
    char **accepted_privileged;
    size_t privileged_count;
    char **skipped_hooks;
    size_t skipped_count;
    char **accepted_service;
    size_t service_count;
};

static void service_list_free(struct service_list *list)
{
    size_t i;
    for (i = 0; i < list->count; ++i) {
        free(list->items[i].path);
        free(list->items[i].artifact);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
}

static void free_set(struct install_set *set)
{
    size_t i;
    for (i = 0; i < set->count; ++i) {
        if (set->items[i].snapshot) unlink(set->items[i].snapshot);
        free(set->items[i].snapshot);
        free(set->items[i].source_record);
        holy_package_identity_free(&set->items[i].identity);
    }
    for (i = 0; i < set->claim_count; ++i) free(set->claims[i].path);
    free(set->claims);
    holy_conflict_claims_free(&set->capabilities);
    free(set->items);
    free(set->graph);
    for (i = 0; i < set->binding_count; ++i) free(set->bindings[i]);
    free(set->bindings);
    holy_override_records_free(set->overrides, set->override_count);
    service_list_free(&set->services);
    holy_resolution_free(&set->resolution);
    memset(set, 0, sizeof *set);
}

static int set_claim(void *context, const struct holy_manifest_entry *entry)
{
    struct install_set *set = context;
    struct set_claim *claims;
    size_t length = strlen(entry->path);
    if (set->claim_count >= 1000000) return 0;
    claims = realloc(set->claims, (set->claim_count + 1) * sizeof *claims);
    if (!claims) return 0;
    set->claims = claims;
    if (length && entry->path[length - 1] == '/') --length;
    claims = &set->claims[set->claim_count];
    claims->path = strndup(entry->path, length);
    if (!claims->path) return 0;
    claims->directory = entry->directory;
    claims->mode = entry->mode;
    claims->uid = entry->uid;
    claims->gid = entry->gid;
    ++set->claim_count;
    return 1;
}

/* the service directory the boot profile starts from, in the manifest form the claims
   use. a unit below it is a file dinit starts without anything else being asked. */
static const char service_directory[] = "etc/dinit.d/";

static int service_unit(const char *path)
{
    size_t length = strlen(path), tail;
    if (strncmp(path, service_directory, sizeof service_directory - 1)) return 0;
    tail = length - (sizeof service_directory - 1);
    return tail > 0 && path[length - 1] != '/';
}

static int service_list_add(struct service_list *list, const char *artifact, const char *path)
{
    struct set_service *items;
    size_t i;
    if (list->count >= 65536) return 0;
    for (i = 0; i < list->count; ++i)
        if (!strcmp(list->items[i].path, path)) return 1;
    items = realloc(list->items, (list->count + 1) * sizeof *items);
    if (!items) return 0;
    list->items = items;
    items[list->count].path = strdup(path);
    items[list->count].artifact = strdup(artifact);
    if (!items[list->count].path || !items[list->count].artifact) {
        free(items[list->count].path);
        free(items[list->count].artifact);
        return 0;
    }
    ++list->count;
    return 1;
}

struct service_scan {
    struct service_list *list;
    const char *artifact;
    int failed;
};

static int service_entry(void *context, const struct holy_manifest_entry *entry)
{
    struct service_scan *scan = context;
    size_t length = strlen(entry->path);
    if (entry->directory || entry->link || entry->hardlink ||
        length < sizeof service_directory || entry->path[length - 1] == '/') return 1;
    if (!service_unit(entry->path)) return 1;
    if (!service_list_add(scan->list, scan->artifact, entry->path)) {
        scan->failed = 1;
        return 0;
    }
    return 1;
}

static int service_scan(const char *snapshot, struct service_list *list, const char *artifact)
{
    struct service_scan scan = {list, artifact, 0};
    return holy_verify_visit(snapshot, service_entry, &scan) && !scan.failed;
}

/* the unit name a manifest path carries, which is the last component */
static const char *service_name_of(const char *path)
{
    return path + sizeof service_directory - 1;
}

/* placing a unit in the services directory is both enabling and starting it, so a unit
   the selection ships needs its own consent before anything is staged */
static int set_service_consent(const struct install_set *set,
                               const char *const *consented, size_t count)
{
    size_t i, j;
    for (i = 0; i < set->services.count; ++i) {
        const char *unit = service_name_of(set->services.items[i].path);
        for (j = 0; j < count; ++j)
            if (!strcmp(unit, consented[j])) break;
        if (j == count) {
            fprintf(stderr, "holypkg: %s ships the service unit /%s; a set that starts"
                            " a service needs --accept-service %s\n",
                    set->services.items[i].artifact, set->services.items[i].path, unit);
            return 0;
        }
    }
    return 1;
}

static void print_service_list(const struct service_list *list)
{
    size_t i;
    for (i = 0; i < list->count; ++i)
        printf("service %s %s path /%s state starts-at-next-boot\n",
               list->items[i].artifact, service_name_of(list->items[i].path),
               list->items[i].path);
}

static int claim_order(const void *left, const void *right)
{
    return strcmp(((const struct set_claim *)left)->path,
                  ((const struct set_claim *)right)->path);
}

static int set_claims_valid(struct install_set *set)
{
    size_t i;
    if (set->claim_count) qsort(set->claims, set->claim_count,
                               sizeof *set->claims, claim_order);
    for (i = 1; i < set->claim_count; ++i) {
        const struct set_claim *a = &set->claims[i - 1], *b = &set->claims[i];
        if (!strcmp(a->path, b->path) &&
            (!a->directory || !b->directory || a->mode != b->mode ||
             a->uid != b->uid || a->gid != b->gid)) {
            fprintf(stderr, "holypkg: selected packages claim the same path: %s\n", a->path);
            return 0;
        }
    }
    return 1;
}

static int loader_directories(const struct holy_elf_info *elf, const char *consumer,
                              char ***directories, size_t *count)
{
    const char *path = elf->runpath ? elf->runpath : elf->rpath;
    const char *start, *end;
    char **list = NULL;
    size_t length, used = 0, capacity = 0;
    *directories = NULL;
    *count = 0;
    if (!path || !*path) return 0;
    for (start = path; ; start = end + 1) {
        char *directory;
        end = strchr(start, ':');
        length = end ? (size_t)(end - start) : strlen(start);
        if (length < 2 || start[length - 1] == '/') goto fail;
        if (start[0] == '/') {
            if (memchr(start, '$', length)) goto fail;
            directory = strndup(start, length);
            if (!directory) goto fail;
            if (!valid_owner_path(directory + 1)) { free(directory); goto fail; }
        } else if (length >= 7 && !memcmp(start, "$ORIGIN", 7) &&
                   (length == 7 || start[7] == '/') && consumer && *consumer) {
            char *relative;
            const char *suffix = start + 7;
            size_t prefix = 0, k;
            for (k = 0; consumer[k]; ++k) if (consumer[k] == '/') prefix = k + 1;
            if (!prefix) goto fail;
            if (length == 7) relative = strndup(consumer, prefix - 1);
            else {
                char *tail = strndup(suffix + 1, length - 8);
                relative = tail ? holy_relative_link_path(consumer, strlen(consumer),
                                                          tail, "") : NULL;
                free(tail);
            }
            if (!relative || !valid_owner_path(relative)) { free(relative); goto fail; }
            directory = malloc(strlen(relative) + 2);
            if (!directory) { free(relative); goto fail; }
            directory[0] = '/';
            strcpy(directory + 1, relative);
            free(relative);
        } else goto fail;
        if (used == capacity) {
            size_t next = capacity ? capacity * 2 : 4;
            char **grown;
            if (next < capacity || next > 1024) { free(directory); goto fail; }
            grown = realloc(list, next * sizeof *list);
            if (!grown) { free(directory); goto fail; }
            list = grown; capacity = next;
        }
        list[used++] = directory;
        if (!end) break;
    }
    *directories = list;
    *count = used;
    return 1;
fail:
    while (used) free(list[--used]);
    free(list);
    return 0;
}

static void free_loader_directories(char **directories, size_t count)
{
    while (count) free(directories[--count]);
    free(directories);
}

/* the directories a dynamic loader searches when a consumer states no runpath, in
   the order glibc searches them for the machine. a provider has to own the soname in
   one of them, since that is the only way the loader would find it. the multiarch
   triplet directories are absent, because a Holy payload records no triplet. */
static int default_loader_directories(const char *machine, char ***directories, size_t *count)
{
    static const char *const wide[] = { "/lib64", "/usr/lib64", "/lib", "/usr/lib", NULL };
    static const char *const narrow[] = { "/lib", "/usr/lib", NULL };
    const char *const *list = NULL;
    char **built = NULL;
    size_t i, used = 0;
    if (machine && !strcmp(machine, "x86_64")) list = wide;
    else list = narrow;
    while (list[used]) ++used;
    built = calloc(used ? used : 1, sizeof *built);
    if (!built) return 0;
    for (i = 0; i < used; ++i) {
        built[i] = strdup(list[i]);
        if (!built[i]) { free_loader_directories(built, i); return 0; }
    }
    *directories = built;
    *count = used;
    return 1;
}

/* the search list of one consumer: its own runpath when it states one, and the
   loader default otherwise */
static int search_directories(const struct holy_elf_info *elf, const char *consumer,
                              char ***directories, size_t *count)
{
    *directories = NULL;
    *count = 0;
    if (loader_directories(elf, consumer, directories, count)) return 1;
    return default_loader_directories(holy_elf_machine(elf), directories, count);
}

static int loader_file_match(const char *directory, const char *path,
                             const char *name)
{
    size_t length = strlen(directory + 1);
    return !strncmp(path, directory + 1, length) && path[length] == '/' &&
           !strcmp(path + length + 1, name);
}

static int scan_loader_alias(const struct holy_scan_result *scan,
                             const char *directory, const char *name,
                             const char *regular)
{
    size_t prefix = strlen(directory + 1), n = strlen(name), hop, i;
    char *current;
    if (prefix > SIZE_MAX - n - 2) return 0;
    current = malloc(prefix + n + 2);
    if (!current) return 0;
    memcpy(current, directory + 1, prefix);
    current[prefix] = '/';
    memcpy(current + prefix + 1, name, n + 1);
    for (hop = 0; hop < 16; ++hop) {
        const char *target = NULL;
        char *next;
        if (!strcmp(current, regular)) { free(current); return 1; }
        for (i = 0; i < scan->symlink_count; ++i)
            if (!strcmp(scan->symlinks[i].path, current)) {
                target = scan->symlinks[i].target; break;
            }
        if (!target) break;
        next = holy_relative_link_path(current, strlen(current), target, "");
        if (!next) break;
        free(current);
        current = next;
    }
    free(current);
    return 0;
}

/* what a payload states about itself: an interpreter the loader cannot name absolutely
   and a script whose interpreter is not decided are refusals here. a bare DT_NEEDED is
   not, since the loader searches its default for it. the provider has to own that name
   in a searched directory, which only a selected set can answer, so it is checked in
   selected_soname_paths. */
static int explicit_elf_paths(const char *snapshot)
{
    struct holy_scan_result scan = {0};
    size_t i;
    int result = 6;
    if (!holy_scan_collect(snapshot, &scan)) return 6;
    result = 0;
    for (i = 0; i < scan.count; ++i) {
        const struct holy_scanned_file *file = &scan.files[i];
        if (file->elf.interpreter && file->elf.interpreter[0] != '/') { result = 3; break; }
    }
    for (i = 0; !result && i < scan.script_count; ++i)
        if (scan.scripts[i].kind != 1) {
            fprintf(stderr, "holypkg: script-interpreter-decision consumer=%s interpreter=%s\n",
                    scan.scripts[i].path, scan.scripts[i].interpreter);
            result = 3;
        }
    holy_scan_free(&scan);
    return result;
}

/* an alias path is the provider's own file when the opened path through the root is
   that file, which a merged-/usr directory link does not change. a path the provider
   has not placed yet cannot be its own file. */
static int alias_is_provider(int root, const char *alias, const char *own)
{
    struct open_how how = {0};
    struct stat alias_state, own_state;
    int alias_fd, own_fd, ok = 0;
    how.flags = O_PATH | O_CLOEXEC;
    how.resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS;
    alias_fd = (int)syscall(SYS_openat2, root, alias, &how, sizeof how);
    if (alias_fd < 0) return 0;
    own_fd = (int)syscall(SYS_openat2, root, own, &how, sizeof how);
    if (own_fd >= 0) {
        ok = !fstat(alias_fd, &alias_state) && !fstat(own_fd, &own_state) &&
             S_ISREG(alias_state.st_mode) && alias_state.st_dev == own_state.st_dev &&
             alias_state.st_ino == own_state.st_ino;
        close(own_fd);
    }
    close(alias_fd);
    return ok;
}

static int selected_soname_paths(const struct holy_resolution *resolution,
                                  const char *const *digests,
                                  const char *const *snapshots, size_t count, int root,
                                  const struct set_claim *claims, size_t claim_count)
{
    size_t i, j, k;
    for (i = 0; i < resolution->edge_count; ++i) {
        const struct holy_resolved_edge *edge = &resolution->edges[i];
        struct holy_scan_result consumer = {0}, provider = {0};
        const struct holy_scanned_file *file = NULL;
        char **directories = NULL;
        const char *own = NULL;
        size_t directory_count = 0, d;
        int found = 0, ok = 0;
        char search[1024] = "none";
        if (strcmp(edge->kind, "soname") || !strcmp(edge->path, "-")) continue;
        for (j = 0; j < count; ++j)
            if (!strcmp(digests[j], edge->consumer)) break;
        if (j == count || !holy_scan_collect(snapshots[j], &consumer)) goto edge_done;
        for (k = 0; k < consumer.count; ++k)
            if (!strcmp(consumer.files[k].path, edge->path)) {
                file = &consumer.files[k]; break;
            }
        if (!file || !search_directories(&file->elf, file->path,
                                         &directories, &directory_count)) goto edge_done;
        for (j = 0; j < count; ++j)
            if (!strcmp(digests[j], edge->provider)) break;
        if (j == count || !holy_scan_collect(snapshots[j], &provider)) goto edge_done;
        for (d = 0; d < directory_count; ++d) {
            struct open_how how = {0};
            char *alias;
            size_t a = strlen(directories[d] + 1), b = strlen(edge->target);
            int opened, occupied = 0;
            if (a > SIZE_MAX - b - 2) break;
            alias = malloc(a + b + 2);
            if (!alias) break;
            memcpy(alias, directories[d] + 1, a);
            alias[a] = '/';
            memcpy(alias + a + 1, edge->target, b + 1);
            for (k = 0; k < provider.count; ++k) {
                const struct holy_scanned_file *candidate = &provider.files[k];
                if (candidate->elf.type == ET_DYN && !(candidate->elf.flags1 & DF_1_PIE) &&
                    candidate->elf.soname && !strcmp(candidate->elf.soname, edge->target) &&
                    candidate->elf.elf_class == file->elf.elf_class &&
                    candidate->elf.machine == file->elf.machine &&
                    !strcmp(candidate->runtime, file->runtime)) {
                    if (!own) own = candidate->path;
                    if (scan_loader_alias(&provider, directories[d], edge->target,
                                          candidate->path)) { found = 1; break; }
                }
            }
            if (found) { free(alias); break; }
            {
                struct set_claim key = {0};
                key.path = alias;
                occupied = bsearch(&key, claims, claim_count,
                                   sizeof *claims, claim_order) != NULL;
            }
            how.flags = O_PATH | O_CLOEXEC;
            how.resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS;
            if (!occupied) {
                opened = (int)syscall(SYS_openat2, root, alias, &how, sizeof how);
                if (opened >= 0) {
                    occupied = !own || !alias_is_provider(root, alias, own);
                    close(opened);
                } else if (errno != ENOENT) occupied = 1;
            }
            free(alias);
            if (occupied) break;
        }
        ok = found;
        search[0] = 0;
        for (d = 0; d < directory_count; ++d) {
            size_t used = strlen(search);
            int n = snprintf(search + used, sizeof search - used, "%s%s",
                             d ? ":" : "", directories[d]);
            if (n < 0 || (size_t)n >= sizeof search - used) { search[0] = 0; break; }
        }
        if (directory_count && !search[0]) strcpy(search, "truncated");
edge_done:
        free_loader_directories(directories, directory_count);
        holy_scan_free(&consumer);
        holy_scan_free(&provider);
        if (!ok) {
            fprintf(stderr, "holypkg: unknown-loader-search consumer=%s requirement=%s "
                    "provider=%s search=%s\n", edge->path, edge->target, edge->provider, search);
            return 0;
        }
    }
    return 1;
}

static int set_soname_paths(const struct install_set *set, int root)
{
    const char **digests = calloc(set->count, sizeof *digests);
    const char **snapshots = calloc(set->count, sizeof *snapshots);
    size_t i;
    int ok = 0;
    if (!digests || !snapshots) goto done;
    for (i = 0; i < set->count; ++i) {
        digests[i] = set->items[i].identity.digest;
        snapshots[i] = set->items[i].snapshot;
    }
    ok = selected_soname_paths(&set->resolution, digests, snapshots, set->count,
                               root, set->claims, set->claim_count);
done:
    free(digests); free(snapshots);
    return ok;
}

static int instance_matches_snapshot(int item, const char *snapshot);

static int reuse_instance(int dir, int root, struct set_item *candidate,
                          unsigned long long generation, int completed,
                          const char *graph, EVP_MD_CTX *hash)
{
    int installed = child_dir(dir, "installed", 0), item = -1, files = -1, fd = -1;
    int result = -1;
    unsigned long long recorded;
    char state[640], prefix[80], *line = NULL;
    size_t capacity = 0, old_count = 0, new_count = 0;
    ssize_t got;
    FILE *stream = NULL;
    const char *part;
    if (installed < 0) goto done;
    item = child_dir(installed, candidate->identity.digest, 0);
    if (item < 0) { if (errno == ENOENT) result = 0; goto done; }
    if (!instance_state_generation(item, candidate->identity.digest, &recorded)) goto done;
    if (recorded > generation) {
        if (completed && recorded == generation + 1) result = 0;
        goto done;
    }
    files = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (files < 0 || !instance_matches_snapshot(item, candidate->snapshot) ||
        exclusive_claims(installed, candidate->identity.digest, files) != 1 ||
        holy_install_check_manifest(files, root) != 1 ||
        check_graph(installed, root, candidate->identity.digest, NULL) != 1) goto done;
    fd = openat(item, "graph", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0 || !(stream = fdopen(fd, "r"))) goto done;
    fd = -1;
    snprintf(prefix, sizeof prefix, "edge \"%s\" ", candidate->identity.digest);
    for (part = graph; *part; ) {
        if (!strncmp(part, prefix, strlen(prefix))) ++new_count;
        part = strchr(part, '\n');
        if (!part) goto done;
        ++part;
    }
    while ((got = getline(&line, &capacity, stream)) >= 0) {
        const char *match;
        if (strncmp(line, prefix, strlen(prefix))) continue;
        ++old_count;
        match = strstr(graph, line);
        if (!match || (match != graph && match[-1] != '\n')) goto done;
    }
    if (ferror(stream) || old_count != new_count) goto done;
    fd = openat(item, "state", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0 || (got = read(fd, state, sizeof state - 1)) <= 0) goto done;
    state[got] = 0;
    if (!hash_text(hash, "reuse-installed") || !hash_text(hash, state)) goto done;
    {
        char marker[96];
        snprintf(marker, sizeof marker, "\nprivileged %s\n", candidate->identity.digest);
        candidate->privileged = strstr(state, marker) != NULL;
    }
    if (!installed_source_id(item, candidate->source_id)) goto done;
    candidate->reused = 1;
    result = 1;
done:
    if (stream) fclose(stream);
    free(line);
    if (fd >= 0) close(fd);
    if (files >= 0) close(files);
    if (item >= 0) close(item);
    if (installed >= 0) close(installed);
    return result;
}

struct installed_candidates {
    int installed;
    int root_fd;
    char **digests;
    size_t count;
    const char *root;
};

struct named_claim { const char *name; int matched; };

static int match_named_claim(void *opaque, const char *kind, const char *name,
    const char *arch, const char *libc, const char *version, const char *evidence)
{
    struct named_claim *claim = opaque;
    (void)arch; (void)libc; (void)version; (void)evidence;
    if (!strcmp(kind, "package") && !strcmp(name, claim->name)) claim->matched = 1;
    return 1;
}

static int installed_package_claim(struct installed_candidates *catalog, int item,
                                    const char *digest, const char *name)
{
    struct named_claim claim = {name, 0};
    int fd, ok, matches = installed_name(item, name);
    if (matches) return matches;
    fd = openat(item, "provides", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd >= 0) {
        ok = holy_provides_visit_fd(fd, match_named_claim, &claim);
        close(fd);
    } else {
        char *snapshot;
        if (errno != ENOENT) return -1;
        snapshot = holy_cache_snapshot(digest, catalog->root);
        if (!snapshot) {
            fprintf(stderr, "holypkg: legacy capability metadata needs cached artifact %s\n", digest);
            return -1;
        }
        ok = holy_provides_visit(snapshot, match_named_claim, &claim);
        unlink(snapshot); free(snapshot);
    }
    return ok ? claim.matched : -1;
}

static int installed_command_claim(int item, const char *name)
{
    static const char *const dirs[] = {"usr/bin/", "bin/", "usr/sbin/", "sbin/"};
    size_t i, length = strlen(name);
    int files = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    int result = 0;
    if (files < 0) return -1;
    for (i = 0; i < sizeof dirs / sizeof *dirs; ++i) {
        size_t prefix = strlen(dirs[i]);
        char *path;
        if (length > SIZE_MAX - prefix - 1) { result = -1; break; }
        path = malloc(prefix + length + 1);
        if (!path) { result = -1; break; }
        memcpy(path, dirs[i], prefix);
        memcpy(path + prefix, name, length + 1);
        result = holy_install_manifest_executable(files, path);
        free(path);
        if (result) break;
    }
    close(files);
    return result;
}

/* one matching file is a provider: a shared object that is not a PIE, with the exact
   DT_SONAME and the arch and runtime the consumer needs. the same match runs over a
   cached archive and over the installed payload, so both give the same answer. */
static int scan_soname_claim(const struct holy_scan_result *scan, const char *name,
                             const char *arch, const char *libc)
{
    size_t i;
    for (i = 0; i < scan->count; ++i) {
        const struct holy_scanned_file *file = &scan->files[i];
        if (file->elf.type == ET_DYN && !(file->elf.flags1 & DF_1_PIE) &&
            file->elf.soname && !strcmp(file->elf.soname, name) &&
            (!strcmp(arch, "any") || !strcmp(arch, holy_elf_machine(&file->elf))) &&
            (!strcmp(libc, "any") || !strcmp(libc, file->runtime)))
            return 1;
    }
    return 0;
}

/* the installed payload is the same evidence the archive gave, read through the target
   root, so a deleted cache object does not hide a provider. only an intact regular
   file counts, since a changed one is not the payload the manifest recorded. */
static int installed_payload_scan(int catalog_root, int item, struct holy_scan_result *scan)
{
    char arch[96], libc[96];
    int files = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    int result;
    if (files < 0) return 0;
    result = installed_field(item, "arch", arch, sizeof arch) &&
             installed_field(item, "libc", libc, sizeof libc);
    if (result) result = holy_scan_installed(files, catalog_root, arch, libc, scan);
    close(files);
    return result;
}

/* the requirement record the instance was installed with, read from the instance
   directory, which is what the closure walk needs when no cached object remains */
static int instance_requirements(int item, holy_requirement_visit visitor, void *opaque)
{
    struct stat st;
    char *data = NULL;
    size_t used = 0;
    ssize_t got;
    int fd = openat(item, "deps", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    int ok = 0;
    if (fd < 0) return 0;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || (st.st_mode & 0022) || st.st_size < 0 ||
        st.st_size > 16 * 1024 * 1024 || !(data = malloc((size_t)st.st_size + 1))) goto done;
    while (used < (size_t)st.st_size) {
        got = read(fd, data + used, (size_t)st.st_size - used);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) goto done;
        used += (size_t)got;
    }
    ok = used == (size_t)st.st_size && holy_deps_buffer_visit(data, used, visitor, opaque);
done:
    free(data);
    close(fd);
    return ok;
}

static int installed_soname_claim(struct installed_candidates *catalog,
                                  int item, const char *digest, const char *name,
                                  const char *arch, const char *libc)
{
    struct holy_scan_result scan = {0};
    const char *keys[] = {"arch", "libc"}, *values[] = {arch, libc};
    char *snapshot;
    size_t fields = 0;
    int result = -1;
    if (strcmp(arch, "any")) { keys[fields] = "arch"; values[fields++] = arch; }
    if (strcmp(libc, "any")) { keys[fields] = "libc"; values[fields++] = libc; }
    if (fields && (result = installed_fields(item, keys, values, fields)) <= 0) return result;
    snapshot = holy_cache_snapshot(digest, catalog->root);
    if (snapshot) {
        int collected = holy_scan_collect(snapshot, &scan);
        unlink(snapshot);
        free(snapshot);
        if (!collected) goto done;
        result = scan_soname_claim(&scan, name, arch, libc);
        goto done;
    }
    if (!installed_payload_scan(catalog->root_fd, item, &scan)) goto done;
    result = scan_soname_claim(&scan, name, arch, libc);
done:
    holy_scan_free(&scan);
    return result;
}

enum installed_query { QUERY_PACKAGE, QUERY_PATH, QUERY_COMMAND, QUERY_SONAME };

static int add_installed_candidates(struct installed_candidates *catalog,
                                    enum installed_query query, const char *needle,
                                    const char *arch, const char *libc)
{
    DIR *list = directory_stream(catalog->installed);
    struct dirent *entry;
    int ok = 0;
    if (!list) return 0;
    errno = 0;
    while ((entry = readdir(list))) {
        int item, matches;
        size_t i;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        for (i = 0; i < catalog->count; ++i)
            if (!strcmp(entry->d_name, catalog->digests[i])) break;
        if (i != catalog->count) { errno = 0; continue; }
        item = child_dir(catalog->installed, entry->d_name, 0);
        if (item < 0) goto done;
        if (query == QUERY_PACKAGE)
            matches = installed_package_claim(catalog, item, entry->d_name, needle);
        else if (query == QUERY_COMMAND)
            matches = installed_command_claim(item, needle);
        else if (query == QUERY_SONAME)
            matches = installed_soname_claim(catalog, item, entry->d_name, needle, arch, libc);
        else {
            int files = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
            matches = files < 0 ? -1 : holy_install_manifest_owns(files, needle);
            if (files >= 0) close(files);
        }
        close(item);
        if (matches < 0) goto done;
        if (matches) {
            if (catalog->count == 10000 ||
                !(catalog->digests[catalog->count] = strdup(entry->d_name))) goto done;
            ++catalog->count;
        }
        errno = 0;
    }
    ok = errno == 0;
done:
    closedir(list);
    return ok;
}

static int installed_or_provider(void *context, const char *name,
                                 const char *relation, const char *version)
{
    (void)relation; (void)version;
    return add_installed_candidates(context, QUERY_PACKAGE, name, NULL, NULL);
}

static int installed_requirement(void *context, const char *id,
    const char *consumer, const char *kind, const char *name,
    const char *arch, const char *libc, const char *relation,
    const char *version, const char *original, const char *evidence)
{
    (void)id; (void)consumer; (void)relation;
    (void)version; (void)original; (void)evidence;
    if (!strcmp(kind, "package"))
        return add_installed_candidates(context, QUERY_PACKAGE, name, NULL, NULL);
    if (!strcmp(kind, "package-or"))
        return holy_package_or_each(name, installed_or_provider, context);
    if (!strcmp(kind, "file") && name[0] == '/')
        return add_installed_candidates(context, QUERY_PATH, name + 1, NULL, NULL);
    if (!strcmp(kind, "command"))
        return add_installed_candidates(context, QUERY_COMMAND, name, NULL, NULL);
    if (!strcmp(kind, "soname") && !strcmp(relation, "any"))
        return add_installed_candidates(context, QUERY_SONAME, name, arch, libc);
    return 1;
}

static int installed_link_step(int root, const char *path, size_t *alias_length,
                               char **target)
{
    const char *end = path;
    struct open_how how = {0};
    *target = NULL;
    how.flags = O_PATH | O_NOFOLLOW | O_CLOEXEC;
    how.resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS;
    while (*end) {
        char *prefix;
        struct stat st;
        int fd;
        ssize_t length;
        end = strchr(end, '/');
        if (!end) end = path + strlen(path);
        prefix = strndup(path, (size_t)(end - path));
        if (!prefix) return 1;
        fd = (int)syscall(SYS_openat2, root, prefix, &how, sizeof how);
        free(prefix);
        if (fd < 0) return errno == ENOENT ? 0 : errno == ENOSYS ? 6 : 1;
        if (fstat(fd, &st)) { close(fd); return 1; }
        if (S_ISLNK(st.st_mode)) {
            *target = malloc(65537);
            if (!*target) { close(fd); return 1; }
            length = readlinkat(fd, "", *target, 65536);
            close(fd);
            if (length <= 0 || length == 65536) {
                free(*target); *target = NULL; return 3;
            }
            (*target)[length] = 0;
            *alias_length = (size_t)(end - path);
            return 2;
        }
        close(fd);
        if (!*end) break;
        ++end;
    }
    return 0;
}

static int candidate_link_step(const struct holy_scan_result *scans, size_t count,
                                const char *path, size_t *alias_length,
                                const char **target)
{
    size_t i, j;
    *alias_length = 0;
    *target = NULL;
    for (i = 0; i < count; ++i) for (j = 0; j < scans[i].symlink_count; ++j) {
        const struct holy_scanned_symlink *link = &scans[i].symlinks[j];
        size_t length = strlen(link->path);
        if (strncmp(path, link->path, length) ||
            (path[length] && path[length] != '/')) continue;
        if (length > *alias_length) {
            *alias_length = length;
            *target = link->target;
        } else if (length == *alias_length && strcmp(*target, link->target)) {
            return 3;
        }
    }
    return *target ? 2 : 0;
}

static int installed_script_candidates(struct installed_candidates *catalog,
                                        int root, const char *interpreter,
                                        const struct holy_scan_result *initial,
                                        size_t initial_count)
{
    char *path = strdup(interpreter + 1), *visited[16] = {0};
    size_t hop, i;
    int result = 1;
    if (!path) return 1;
    for (hop = 0; hop < 16; ++hop) {
        size_t alias_length = 0;
        char *target = NULL, *next;
        const char *candidate_target = NULL;
        size_t candidate_length = 0;
        int step, candidate_step;
        for (i = 0; i < hop; ++i) if (!strcmp(visited[i], path)) {
            result = 3; goto done;
        }
        visited[hop] = strdup(path);
        if (!visited[hop]) goto done;
        step = installed_link_step(root, path, &alias_length, &target);
        if (step == 6 || step == 3 || step == 1) { result = step; goto done; }
        candidate_step = candidate_link_step(initial, initial_count, path,
                                             &candidate_length, &candidate_target);
        if (candidate_step == 3) { free(target); result = 3; goto done; }
        if (step == 0 && candidate_step == 2) {
            next = holy_relative_link_path(path, candidate_length,
                                            candidate_target, path + candidate_length);
            if (!next) { result = 3; goto done; }
            free(path);
            path = next;
            continue;
        }
        if (step == 0) {
            result = add_installed_candidates(catalog, QUERY_PATH, path, NULL, NULL) ? 0 : 1;
            break;
        }
        next = holy_relative_link_path(path, alias_length, target,
                                       path + alias_length);
        free(target);
        if (!next) { result = 3; goto done; }
        path[alias_length] = 0;
        if (!add_installed_candidates(catalog, QUERY_PATH, path, NULL, NULL)) {
            free(next); goto done;
        }
        free(path);
        path = next;
    }
    if (hop == 16) result = 3;
done:
    for (i = 0; i < 16; ++i) free(visited[i]);
    free(path);
    return result;
}

static int discover_installed(const char *root_path, int dir,
                              const char *const *digests, size_t *count, char ***output)
{
    struct installed_candidates catalog = {-1, -1, NULL, 0, root_path};
    struct holy_scan_result *initial = NULL;
    size_t i, j, k, initial_count = *count;
    int root = -1, result = 1;
    catalog.digests = calloc(10000, sizeof *catalog.digests);
    if (!catalog.digests) return 1;
    catalog.installed = child_dir(dir, "installed", 0);
    if (catalog.installed < 0) goto done;
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) goto done;
    catalog.root_fd = root;
    initial = calloc(initial_count, sizeof *initial);
    if (!initial) goto done;
    for (i = 0; i < *count; ++i) {
        char *snapshot;
        catalog.digests[i] = strdup(digests[i]);
        if (!catalog.digests[i]) goto done;
        ++catalog.count;
        snapshot = holy_cache_snapshot(catalog.digests[i], root_path);
        if (!snapshot) { result = 6; goto done; }
        j = holy_scan_collect(snapshot, &initial[i]);
        unlink(snapshot); free(snapshot);
        if (!j) { result = 6; goto done; }
    }
    for (i = 0; i < catalog.count; ++i) {
        struct holy_scan_result extra = {0};
        struct holy_scan_result *scan = i < initial_count ? &initial[i] : &extra;
        char *snapshot = holy_cache_snapshot(catalog.digests[i], root_path);
        int item = -1, ok = 0;
        if (!snapshot && i < initial_count) { result = 6; goto done; }
        if (i >= initial_count)
            item = child_dir(catalog.installed, catalog.digests[i], 0);
        if (snapshot) {
            ok = holy_deps_visit(snapshot, installed_requirement, &catalog) &&
                 (i < initial_count || holy_scan_collect(snapshot, scan));
        } else {
            /* a discovered provider whose cached object is gone is described from the
               records it was installed with and the payload it still owns */
            ok = item >= 0 &&
                 instance_requirements(item, installed_requirement, &catalog) &&
                 installed_payload_scan(root, item, scan);
        }
        if (item >= 0) close(item);
        unlink(snapshot);
        free(snapshot);
        for (j = 0; ok && j < scan->count; ++j) {
            const struct holy_elf_info *elf = &scan->files[j].elf;
            if (elf->interpreter && elf->interpreter[0] == '/')
                ok = add_installed_candidates(&catalog, QUERY_PATH, elf->interpreter + 1, NULL, NULL);
            for (k = 0; ok && k < elf->needed_count; ++k)
                if (elf->needed[k][0] == '/')
                    ok = add_installed_candidates(&catalog, QUERY_PATH, elf->needed[k] + 1, NULL, NULL);
                else
                    ok = add_installed_candidates(&catalog, QUERY_SONAME, elf->needed[k],
                        holy_elf_machine(elf), scan->files[j].runtime);
        }
        for (j = 0; ok && j < scan->script_count; ++j)
            if (scan->scripts[j].kind == 1) {
                int status = installed_script_candidates(&catalog, root,
                                                         scan->scripts[j].interpreter,
                                                         initial, initial_count);
                if (status) { result = status; ok = 0; }
            }
        if (i >= initial_count) holy_scan_free(&extra);
        if (!ok) { if (result == 1) result = 6; goto done; }
    }
    result = 0;
done:
    if (initial) {
        for (i = 0; i < initial_count; ++i) holy_scan_free(&initial[i]);
        free(initial);
    }
    if (root >= 0) close(root);
    if (catalog.installed >= 0) close(catalog.installed);
    *count = catalog.count;
    *output = catalog.digests;
    return result;
}

static int binding_valid(const char *binding)
{
    return strlen(binding) == 129 && binding[64] == '=' &&
           strspn(binding, "0123456789abcdef") == 64 && valid_digest(binding + 65);
}

static int instance_source_matches(int instance, const char *record)
{
    char id[65], actual[65], expected[65];
    unsigned char bytes[32];
    unsigned int size;
    size_t i;
    struct stat st;
    if (!record) return fstatat(instance, "source", &st, AT_SYMLINK_NOFOLLOW) && errno == ENOENT;
    if (!holy_source_instance(instance, id, actual) ||
        EVP_Digest(record, strlen(record), bytes, &size, EVP_sha256(), NULL) != 1 || size != 32) return 0;
    for (i = 0; i < 32; ++i) snprintf(expected + i * 2, 3, "%02x", bytes[i]);
    return !strcmp(expected, actual);
}

static int build_set(const char *root_path, int root, int dir,
                      unsigned long long generation, const char *const *digests,
                      size_t count, const char *choice, int completed,
                      const char *const *bindings, size_t binding_count,
                      const char *default_source_id,
                      const char *catalog_index,
                      const char *const *accepted_arch, size_t accepted_count,
                      const char *const *accepted_privileged, size_t privileged_count,
                      const char *const *skipped_hooks, size_t skipped_count,
                      const struct holy_override_record_info *override_records,
                      size_t override_record_count,
                      struct install_set *set)
{
    char **snapshots = NULL;
    char **candidates = NULL;
    struct plan_hash plan = {0};
    struct stat st;
    struct utsname host;
    char number[128];
    unsigned char digest[32];
    unsigned int length;
    size_t i, j, initial_count = count;
    int result = 1;
    if (!count || count > 10000 || binding_count > 10000 ||
        accepted_count > 10000 || privileged_count > 10000 || skipped_count > 10000) return 2;
    if ((default_source_id && !valid_digest(default_source_id)) ||
        (catalog_index && (!valid_digest(catalog_index) ||
                           (!default_source_id && !completed)))) return 2;
    for (i = 0; i < accepted_count; ++i) {
        if (!valid_digest(accepted_arch[i])) return 2;
        for (j = 0; j < i; ++j) if (!strcmp(accepted_arch[i], accepted_arch[j])) return 2;
    }
    for (i = 0; i < privileged_count; ++i) {
        if (!valid_digest(accepted_privileged[i])) return 2;
        for (j = 0; j < i; ++j)
            if (!strcmp(accepted_privileged[i], accepted_privileged[j])) return 2;
    }
    for (i = 0; i < skipped_count; ++i) {
        if (!valid_digest(skipped_hooks[i])) return 2;
        for (j = 0; j < i; ++j) if (!strcmp(skipped_hooks[i], skipped_hooks[j])) return 2;
    }
    for (i = 0; i < count; ++i) if (!valid_digest(digests[i])) return 2;
    for (i = 0; i < binding_count; ++i) {
        if (!binding_valid(bindings[i])) return 2;
        for (j = 0; j < i; ++j) if (!strncmp(bindings[i], bindings[j], 64)) return 2;
        for (j = 0; j < count; ++j)
            if (!strncmp(bindings[i], digests[j], 64)) break;
        if (j == count) return 2;
    }
    if (!completed) {
        result = discover_installed(root_path, dir, digests, &count, &candidates);
        if (result) goto done;
        digests = (const char *const *)candidates;
        result = 1;
    }
    snapshots = calloc(count, sizeof *snapshots);
    if (!snapshots || fstat(root, &st) || uname(&host)) goto done;
    if (strlen(host.machine) >= sizeof set->host) goto done;
    strcpy(set->host, host.machine);
    for (i = 0; i < count; ++i) {
        snapshots[i] = holy_cache_snapshot(digests[i], root_path);
        if (!snapshots[i]) {
            /* a set resolves and hashes the archive it stages, so an installed
               artifact whose cached object is gone is a cache requirement, not a
               discovery result. the name is the actionable part. */
            int installed = child_dir(dir, "installed", 0), instance = -1;
            if (installed >= 0) instance = child_dir(installed, digests[i], 0);
            if (instance >= 0)
                fprintf(stderr, "holypkg: installed artifact needs its cached archive: %s\n",
                        digests[i]);
            if (instance >= 0) close(instance);
            if (installed >= 0) close(installed);
            result = 6;
            goto done;
        }
    }
    result = holy_resolve_collect((const char *const *)snapshots, count, choice,
                                  &set->resolution);
    if (result) goto done;
    for (i = 0; i < accepted_count; ++i) {
        for (j = 0; j < set->resolution.artifact_count; ++j)
            if (!strcmp(accepted_arch[i], set->resolution.artifacts[j])) break;
        if (j == set->resolution.artifact_count) { result = 3; goto done; }
    }
    for (i = 0; i < privileged_count; ++i) {
        for (j = 0; j < set->resolution.artifact_count; ++j)
            if (!strcmp(accepted_privileged[i], set->resolution.artifacts[j])) break;
        if (j == set->resolution.artifact_count) { result = 3; goto done; }
    }
    for (i = 0; i < skipped_count; ++i) {
        for (j = 0; j < set->resolution.artifact_count; ++j)
            if (!strcmp(skipped_hooks[i], set->resolution.artifacts[j])) break;
        if (j == set->resolution.artifact_count) { result = 3; goto done; }
    }
    /* a caller binding is a decision about one artifact, so it must land in the set.
       a source binding instead offers every staged candidate, and the resolver may
       drop one, so those are not checked here. */
    if (!catalog_index)
        for (i = 0; i < binding_count; ++i) {
            for (j = 0; j < set->resolution.artifact_count; ++j)
                if (!strncmp(bindings[i], set->resolution.artifacts[j], 64)) break;
            if (j == set->resolution.artifact_count) { result = 3; goto done; }
        }
    result = 1;
    set->items = calloc(set->resolution.artifact_count, sizeof *set->items);
    if (!set->items || !holy_resolution_record(&set->resolution, &set->graph,
                                               &set->graph_length)) goto done;
    set->count = set->resolution.artifact_count;
    plan.hash = EVP_MD_CTX_new();
    plan.dir = dir;
    plan.completed = completed;
    if (!plan.hash || EVP_DigestInit_ex(plan.hash, EVP_sha256(), NULL) != 1 ||
        !hash_text(plan.hash, "holy-set-plan-1") ||
        !hash_text(plan.hash, choice ? choice : "-") ||
        !hash_text(plan.hash, set->graph)) goto done;
    if (catalog_index) {
        memcpy(set->catalog_index, catalog_index, 65);
        if (!hash_text(plan.hash, "catalog-index") ||
            !hash_text(plan.hash, catalog_index)) goto done;
    }
    snprintf(number, sizeof number, "%ju:%ju", (uintmax_t)st.st_dev, (uintmax_t)st.st_ino);
    if (!hash_text(plan.hash, number)) goto done;
    snprintf(number, sizeof number, "%llu", generation);
    if (!hash_text(plan.hash, number)) goto done;
    for (i = 0; i < set->count; ++i) {
        struct set_item *item = &set->items[i];
        for (j = 0; j < count; ++j)
            if (!strcmp(digests[j], set->resolution.artifacts[i])) break;
        if (j == count) goto done;
        item->snapshot = snapshots[j];
        snapshots[j] = NULL;
        result = 6;
        if (!holy_package_identity(item->snapshot, &item->identity) ||
            strcmp(item->identity.digest, set->resolution.artifacts[i]) ||
            strcmp(item->identity.os, "linux") ||
            (strcmp(item->identity.libc, "nolibc") && strcmp(item->identity.libc, "glibc") &&
             strcmp(item->identity.libc, "musl")) ||
            !recorded_transform(item->snapshot) || !instance_preflight(item->snapshot)) goto done;
        strcpy(item->source_id, "-");
        result = explicit_elf_paths(item->snapshot);
        if (result) goto done;
        result = reuse_instance(dir, root, item, generation, completed, set->graph, plan.hash);
        if (result < 0) { result = 4; goto done; }
        {
            size_t hook_length;
            char *hooks = read_hooks(item->snapshot, &hook_length);
            int accepted = 0;
            if (!hooks) { result = 6; goto done; }
            for (j = 0; j < skipped_count; ++j)
                if (!strcmp(skipped_hooks[j], item->identity.digest)) accepted = 1;
            if (item->reused) result = accepted ? 3 : 0;
            else if (accepted && !hook_length) result = 2;
            else if (hook_length && !accepted) {
                fprintf(stderr, "holypkg: decision-required hooks artifact=%s; --skip-hooks %s records installed-unconfigured\n",
                        item->identity.digest, item->identity.digest);
                fwrite(hooks, 1, hook_length, stderr);
                if (hooks[hook_length - 1] != '\n') fputc('\n', stderr);
                result = 3;
            } else {
                item->skipped_hooks = accepted;
                result = 0;
                if (accepted && (!hash_text(plan.hash, "skipped-hooks") ||
                                 !hash_text(plan.hash, item->identity.digest) ||
                                 !hash_text(plan.hash, hooks))) result = 1;
            }
            free(hooks);
            if (result) goto done;
        }
        {
            struct privileged_scan scan = {0};
            int accepted = 0, scanned = holy_verify_visit(item->snapshot, scan_privileged, &scan);
            for (j = 0; j < privileged_count; ++j)
                if (!strcmp(accepted_privileged[j], item->identity.digest)) accepted = 1;
            if (!scanned) {
                result = scan.unsupported ? 6 : 1;
                free(scan.first); goto done;
            }
            if (item->reused) {
                result = accepted ? 3 : item->privileged != !!scan.count ? 4 : 0;
            } else if (accepted && !scan.count) result = 2;
            else if (scan.count && !accepted) {
                fprintf(stderr, "holypkg: decision-required privileged artifact=%s path=%s mode=%04o; --accept-privileged %s permits setuid placement\n",
                        item->identity.digest, scan.first, scan.mode, item->identity.digest);
                result = 3;
            } else {
                item->privileged = accepted;
                result = 0;
                if (accepted && (!hash_text(plan.hash, "accepted-privileged") ||
                                 !hash_text(plan.hash, item->identity.digest))) result = 1;
            }
            free(scan.first);
            if (result) goto done;
        }
        for (j = 0; j < accepted_count; ++j)
            if (!strcmp(accepted_arch[j], item->identity.digest)) break;
        if (j < accepted_count) {
            if (item->reused) { result = 3; goto done; }
            if (native_architecture(host.machine, item->identity.arch)) { result = 2; goto done; }
            snprintf(item->architecture, sizeof item->architecture, "%s %s", host.machine, item->identity.arch);
            if (!architecture_valid(item->architecture)) { result = 2; goto done; }
            if (!hash_text(plan.hash, "accepted-architecture") ||
                !hash_text(plan.hash, item->identity.digest) ||
                !hash_text(plan.hash, item->architecture)) { result = 1; goto done; }
        } else if (item->reused) {
            int installed = child_dir(dir, "installed", 0);
            int existing = installed < 0 ? -1 : child_dir(installed, item->identity.digest, 0);
            int valid = existing >= 0 && instance_architecture(existing, item->architecture);
            if (existing >= 0) close(existing);
            if (installed >= 0) close(installed);
            if (!valid) { result = 4; goto done; }
        }
        if (!native_architecture(host.machine, item->identity.arch)) {
            char expected[96];
            snprintf(expected, sizeof expected, "%s %s", host.machine, item->identity.arch);
            if (strcmp(expected, item->architecture)) {
                fprintf(stderr, "holypkg: decision-required architecture artifact=%s host=%s target=%s; --accept-arch %s permits placement without proving execution\n",
                        item->identity.digest, host.machine, item->identity.arch, item->identity.digest);
                result = 3; goto done;
            }
        }
        for (j = 0; j < binding_count; ++j) if (!strncmp(bindings[j], item->identity.digest, 64)) {
            char registry[65];
            if (item->reused) { result = 3; goto done; }
            result = holy_source_record(dir, bindings[j] + 65, &item->source_record, registry);
            if (result) goto done;
            memcpy(item->source_id, bindings[j] + 65, 65);
            if (!hash_text(plan.hash, "source-binding") || !hash_text(plan.hash, registry) ||
                !hash_text(plan.hash, item->source_record)) { result = 1; goto done; }
            break;
        }
        if (default_source_id && j == binding_count && !item->reused) {
            char registry[65];
            for (j = 0; j < initial_count; ++j)
                if (!strcmp(digests[j], item->identity.digest)) break;
            if (j == initial_count) { result = 6; goto done; }
            result = holy_source_record(dir, default_source_id,
                                        &item->source_record, registry);
            if (result) goto done;
            memcpy(item->source_id, default_source_id, 65);
            if (!hash_text(plan.hash, "source-binding") || !hash_text(plan.hash, registry) ||
                !hash_text(plan.hash, item->source_record)) { result = 1; goto done; }
        }
        if (item->reused && !strcmp(item->identity.digest, set->resolution.root)) {
            result = 3; goto done;
        }
        result = holy_preview_resolved(item->snapshot, root_path, completed || item->reused,
                                       item->privileged, item->skipped_hooks || item->reused);
        if (result) goto done;
        for (j = 0; j < i; ++j)
            if (same_slot(&set->items[j].identity, set->items[j].source_id,
                          &item->identity, item->source_id)) {
                result = 4; goto done;
            }
        if (!completed && !item->reused) {
            result = slot_available(dir, &item->identity, item->source_id);
            if (result != 1) { result = result < 0 ? 1 : 4; goto done; }
            if (!holy_install_preflight(item->snapshot, root, item->privileged)) { result = 4; goto done; }
        }
        result = 6;
        plan.completed = completed || item->reused;
        plan.accepted_privileged = item->privileged;
        if (!hash_text(plan.hash, item->identity.digest) ||
            !holy_verify_visit(item->snapshot, plan_entry, &plan)) {
            if (plan.claim_error) result = plan.claim_error;
            goto done;
        }
        result = 1;
        if (!holy_verify_visit(item->snapshot, set_claim, set)) goto done;
        if (!service_scan(item->snapshot, &set->services, item->identity.digest)) goto done;
    }
    if (!set_claims_valid(set)) { result = 4; goto done; }
    for (i = 0; i < set->count; ++i)
        if (!holy_conflict_claims_package(&set->capabilities, set->items[i].snapshot,
                                          set->items[i].identity.digest)) { result = 6; goto done; }
    set->capability_findings = holy_conflict_claims_findings(&set->capabilities);
    if (!set_soname_paths(set, root)) { result = 3; goto done; }
    if (!same_root(root_path, &st)) { result = 4; goto done; }
    set->bindings = calloc(set->count, sizeof *set->bindings);
    if (!set->bindings) goto done;
    for (i = 0; i < set->count; ++i) if (set->items[i].source_record) {
        char *binding = malloc(130);
        if (!binding) goto done;
        snprintf(binding, 130, "%s=%s", set->items[i].identity.digest,
                 set->items[i].source_id);
        set->bindings[set->binding_count++] = binding;
    }
    if (!set_override_records(set, override_records, override_record_count)) goto done;
    for (i = 0; i < set->override_count; ++i) {
        char line[512];
        int length = snprintf(line, sizeof line, "override %s %s %s %s\n",
                              set->overrides[i].name, set->overrides[i].path,
                              set->overrides[i].file, set->overrides[i].patch);
        if (length < 0 || (size_t)length >= sizeof line ||
            !hash_text(plan.hash, line)) goto done;
    }
    if (EVP_DigestFinal_ex(plan.hash, digest, &length) != 1 || length != 32) goto done;
    for (i = 0; i < 32; ++i) snprintf(set->hash + i * 2, 3, "%02x", digest[i]);
    set->paths = plan.count;
    result = 0;
done:
    if (snapshots) for (i = 0; i < count; ++i) {
        if (snapshots[i]) unlink(snapshots[i]);
        free(snapshots[i]);
    }
    free(snapshots);
    if (candidates) {
        for (i = 0; i < count; ++i) free(candidates[i]);
        free(candidates);
    }
    EVP_MD_CTX_free(plan.hash);
    return result;
}

static void free_set_journal(struct set_journal *journal)
{
    size_t i;
    for (i = 0; i < journal->count; ++i) free(journal->digests[i]);
    free(journal->digests);
    for (i = 0; i < journal->binding_count; ++i) free(journal->bindings[i]);
    free(journal->bindings);
    free(journal->choice);
    for (i = 0; i < journal->accepted_count; ++i) free(journal->accepted_arch[i]);
    free(journal->accepted_arch);
    for (i = 0; i < journal->privileged_count; ++i) free(journal->accepted_privileged[i]);
    free(journal->accepted_privileged);
    for (i = 0; i < journal->skipped_count; ++i) free(journal->skipped_hooks[i]);
    free(journal->skipped_hooks);
    for (i = 0; i < journal->service_count; ++i) free(journal->accepted_service[i]);
    free(journal->accepted_service);
    memset(journal, 0, sizeof *journal);
}

/* a consented unit is named, not a path: the consent names what dinit would start */
int holy_unit_name_valid(const char *name)
{
    size_t i, length;
    if (!name || !*name) return 0;
    length = strlen(name);
    if (length > 255 || !strcmp(name, ".") || !strcmp(name, "..")) return 0;
    for (i = 0; i < length; ++i)
        if (!((name[i] >= 'a' && name[i] <= 'z') ||
              (name[i] >= 'A' && name[i] <= 'Z') ||
              (name[i] >= '0' && name[i] <= '9') ||
              name[i] == '-' || name[i] == '_' || name[i] == '.' || name[i] == '@'))
            return 0;
    return 1;
}

static int set_choice_valid(const char *choice)
{
    const char *equal;
    size_t i;
    if (!strcmp(choice, "-")) return 1;
    equal = strchr(choice, '=');
    if (!equal || equal == choice || !valid_digest(equal + 1) ||
        (size_t)(equal - choice) > 65536) return 0;
    for (i = 0; choice + i < equal; ++i)
        if (!((choice[i] >= 'a' && choice[i] <= 'z') ||
              (choice[i] >= 'A' && choice[i] <= 'Z') ||
              (choice[i] >= '0' && choice[i] <= '9') ||
              choice[i] == '-' || choice[i] == '_' || choice[i] == '.')) return 0;
    return 1;
}

/* the phases a set transaction passes through, in order. the journal states the one it
   reached, so recovery resumes there instead of re-deriving where the crash fell. */
static const char *const set_phases[] = { "applying", "instances", "record", "generation" };

static int phase_valid(const char *phase)
{
    size_t i;
    for (i = 0; i < sizeof set_phases / sizeof *set_phases; ++i)
        if (!strcmp(phase, set_phases[i])) return 1;
    return 0;
}

static size_t phase_index(const char *phase)
{
    size_t i;
    for (i = 0; i < sizeof set_phases / sizeof *set_phases; ++i)
        if (!strcmp(phase, set_phases[i])) return i;
    return sizeof set_phases / sizeof *set_phases;
}

/* the phase is the last line of the journal, so the version states it as well as the
   decisions the review named */
static int write_set_journal(int transactions, unsigned long long generation,
                             const struct install_set *set, const char *choice,
                             const char *const *accepted_arch, size_t accepted_count,
                             const char *const *accepted_privileged, size_t privileged_count,
                             const char *const *skipped_hooks, size_t skipped_count,
                             const char *const *accepted_service, size_t service_count,
                             const char *phase)
{
    char *record = NULL;
    size_t length = 0, i;
    FILE *stream = open_memstream(&record, &length);
    int ok = 1;
    if (!stream || !phase_valid(phase)) return 0;
    if (fprintf(stream, "format holy-set-journal-%d\ngeneration %llu\nplan %s\nroot %s\nchoice %s\n",
                service_count ? 7 : skipped_count ? 6 : set->catalog_index[0] ? 5 :
                privileged_count ? 4 : accepted_count ? 3 : set->binding_count ? 2 : 1,
                generation, set->hash, set->resolution.root, choice ? choice : "-") < 0) ok = 0;
    if ((accepted_count || privileged_count || skipped_count || service_count ||
         set->catalog_index[0]) &&
        fprintf(stream, "host %s\n", set->host) < 0) ok = 0;
    if (set->catalog_index[0] &&
        fprintf(stream, "catalog-index %s\n", set->catalog_index) < 0) ok = 0;
    for (i = 0; i < set->count && ok; ++i)
        if (fprintf(stream, "artifact %s\n", set->items[i].identity.digest) < 0) ok = 0;
    for (i = 0; i < set->binding_count && ok; ++i)
        if (fprintf(stream, "binding %s\n", set->bindings[i]) < 0) ok = 0;
    for (i = 0; i < accepted_count && ok; ++i)
        if (fprintf(stream, "accept-arch %s\n", accepted_arch[i]) < 0) ok = 0;
    for (i = 0; i < privileged_count && ok; ++i)
        if (fprintf(stream, "accept-privileged %s\n", accepted_privileged[i]) < 0) ok = 0;
    for (i = 0; i < skipped_count && ok; ++i)
        if (fprintf(stream, "skip-hooks %s\n", skipped_hooks[i]) < 0) ok = 0;
    for (i = 0; i < service_count && ok; ++i)
        if (fprintf(stream, "service %s\n", accepted_service[i]) < 0) ok = 0;
    if (fprintf(stream, "phase %s\n", phase) < 0) ok = 0;
    if (fclose(stream)) ok = 0;
    /* the journal is rewritten as the transaction advances, so it is replaced rather
       than created, and a replacement that fails leaves the earlier phase in place */
    if (ok) ok = update_replace(transactions, "set-journal", record);
    free(record);
    return ok;
}

/* a record the transaction had already started when the crash came: the committed
   marker names its own directory, so it is that plan's record rather than an entry this
   root does not recognise. recovery writes the rest of it from the journal. */
static int record_started(int transactions, const char *name)
{
    int child = child_dir(transactions, name, 0), ok = 0;
    char *record = child < 0 ? NULL : update_record(child, "committed");
    if (record && strlen(record) == 65 && !memcmp(record, name, 64) && record[64] == '\n')
        ok = 1;
    free(record);
    if (child >= 0) close(child);
    return ok;
}

static int read_set_journal(int dir, struct set_journal *journal)
{
    int transactions = child_dir(dir, "transactions", 0), fd = -1, result = -1, version = 1;
    struct stat st;
    FILE *stream = NULL;
    char *line = NULL;
    size_t capacity = 0, number = 0, bytes = 0, roots = 0;
    ssize_t got;
    if (transactions < 0) return -1;
    {
        DIR *list = directory_stream(transactions);
        struct dirent *entry;
        int valid = 1;
        if (!list) goto done;
        errno = 0;
        while ((entry = readdir(list))) {
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
            if (completed_transaction(transactions, entry->d_name) ||
                record_started(transactions, entry->d_name)) { errno = 0; continue; }
            if (strcmp(entry->d_name, "set-journal")) { valid = 0; break; }
            errno = 0;
        }
        if (!entry && errno) valid = 0;
        closedir(list);
        if (!valid) {
            struct stat other;
            if (fstatat(transactions, "set-journal", &other, AT_SYMLINK_NOFOLLOW) &&
                errno == ENOENT) result = 0;
            goto done;
        }
    }
    fd = openat(transactions, "set-journal", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) { result = errno == ENOENT ? 0 : -1; goto done; }
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 1 ||
        st.st_size > 4 * 1024 * 1024 || (st.st_mode & 0022) ||
        (st.st_uid != 0 && st.st_uid != geteuid())) goto done;
    stream = fdopen(fd, "r");
    if (!stream) goto done;
    fd = -1;
    while ((got = getline(&line, &capacity, stream)) >= 0) {
        char *end;
        bytes += (size_t)got;
        if (bytes > 4 * 1024 * 1024 || !got || line[got - 1] != '\n' ||
            memchr(line, 0, (size_t)got)) goto done;
        line[got - 1] = 0;
        if (number == 0) {
            if (!strcmp(line, "format holy-set-journal-7")) version = 7;
            else if (!strcmp(line, "format holy-set-journal-6")) version = 6;
            else if (!strcmp(line, "format holy-set-journal-5")) version = 5;
            else if (!strcmp(line, "format holy-set-journal-4")) version = 4;
            else if (!strcmp(line, "format holy-set-journal-3")) version = 3;
            else if (!strcmp(line, "format holy-set-journal-2")) version = 2;
            else if (strcmp(line, "format holy-set-journal-1")) goto done;
        } else if (number == 1) {
            if (strncmp(line, "generation ", 11) || line[11] < '0' || line[11] > '9' ||
                (line[11] == '0' && line[12])) goto done;
            errno = 0;
            journal->generation = strtoull(line + 11, &end, 10);
            if (errno || *end || journal->generation == ULLONG_MAX) goto done;
        } else if (number == 2) {
            if (strncmp(line, "plan ", 5) || !valid_digest(line + 5)) goto done;
            memcpy(journal->hash, line + 5, 65);
        } else if (number == 3) {
            if (strncmp(line, "root ", 5) || !valid_digest(line + 5)) goto done;
            memcpy(journal->root, line + 5, 65);
        } else if (number == 4) {
            if (strncmp(line, "choice ", 7) || !set_choice_valid(line + 7)) goto done;
            journal->choice = strdup(line + 7);
            if (!journal->choice) goto done;
        } else if (version >= 3 && number == 5) {
            char architecture[96];
            if (strncmp(line, "host ", 5) || strlen(line + 5) > 64) goto done;
            snprintf(architecture, sizeof architecture, "%s x86", line + 5);
            if (!architecture_valid(architecture)) goto done;
            strcpy(journal->host, line + 5);
        } else if (version >= 5 && number == 6 &&
                   !strncmp(line, "catalog-index ", 14)) {
            if (strncmp(line, "catalog-index ", 14) ||
                !valid_digest(line + 14)) goto done;
            memcpy(journal->catalog_index, line + 14, 65);
        } else if (version >= 3 && !strncmp(line, "accept-arch ", 12)) {
            char **next;
            size_t i;
            if (!valid_digest(line + 12) || journal->accepted_count >= journal->count) goto done;
            for (i = 0; i < journal->count; ++i) if (!strcmp(line + 12, journal->digests[i])) break;
            if (i == journal->count) goto done;
            for (i = 0; i < journal->accepted_count; ++i)
                if (!strcmp(line + 12, journal->accepted_arch[i])) goto done;
            next = realloc(journal->accepted_arch, (journal->accepted_count + 1) * sizeof *next);
            if (!next) goto done;
            journal->accepted_arch = next;
            next[journal->accepted_count] = strdup(line + 12);
            if (!next[journal->accepted_count]) goto done;
            ++journal->accepted_count;
        } else if (version >= 4 && !strncmp(line, "accept-privileged ", 18)) {
            char **next;
            size_t i;
            if (!valid_digest(line + 18) || journal->privileged_count >= journal->count) goto done;
            for (i = 0; i < journal->count; ++i)
                if (!strcmp(line + 18, journal->digests[i])) break;
            if (i == journal->count) goto done;
            for (i = 0; i < journal->privileged_count; ++i)
                if (!strcmp(line + 18, journal->accepted_privileged[i])) goto done;
            next = realloc(journal->accepted_privileged,
                           (journal->privileged_count + 1) * sizeof *next);
            if (!next) goto done;
            journal->accepted_privileged = next;
            next[journal->privileged_count] = strdup(line + 18);
            if (!next[journal->privileged_count]) goto done;
            ++journal->privileged_count;
        } else if (version == 6 && !strncmp(line, "skip-hooks ", 11)) {
            char **next;
            size_t i;
            if (!valid_digest(line + 11) || journal->skipped_count >= journal->count) goto done;
            for (i = 0; i < journal->count; ++i)
                if (!strcmp(line + 11, journal->digests[i])) break;
            if (i == journal->count) goto done;
            for (i = 0; i < journal->skipped_count; ++i)
                if (!strcmp(line + 11, journal->skipped_hooks[i])) goto done;
            next = realloc(journal->skipped_hooks, (journal->skipped_count + 1) * sizeof *next);
            if (!next) goto done;
            journal->skipped_hooks = next;
            next[journal->skipped_count] = strdup(line + 11);
            if (!next[journal->skipped_count]) goto done;
            ++journal->skipped_count;
        } else if (version == 7 && !strncmp(line, "service ", 8)) {
            char **next;
            size_t i;
            if (journal->accepted_count || journal->privileged_count || journal->skipped_count ||
                !holy_unit_name_valid(line + 8) || journal->service_count >= journal->count)
                goto done;
            for (i = 0; i < journal->service_count; ++i)
                if (!strcmp(line + 8, journal->accepted_service[i])) goto done;
            next = realloc(journal->accepted_service,
                           (journal->service_count + 1) * sizeof *next);
            if (!next) goto done;
            journal->accepted_service = next;
            next[journal->service_count] = strdup(line + 8);
            if (!next[journal->service_count]) goto done;
            ++journal->service_count;
        } else if (!strncmp(line, "phase ", 6)) {
            /* the phase closes the journal, so a record that named one twice or named
               an unknown one is not a journal this root wrote */
            if (journal->phase[0] || strlen(line) < 7 || strlen(line) >= sizeof journal->phase ||
                !phase_valid(line + 6)) goto done;
            memcpy(journal->phase, line + 6, strlen(line + 6) + 1);
        } else if (version >= 2 && !strncmp(line, "binding ", 8)) {
            char **next;
            size_t i;
            if (journal->accepted_count || journal->privileged_count || journal->skipped_count ||
                journal->service_count ||
                !binding_valid(line + 8) || journal->binding_count >= journal->count) goto done;
            for (i = 0; i < journal->count; ++i)
                if (!strncmp(line + 8, journal->digests[i], 64)) break;
            if (i == journal->count) goto done;
            for (i = 0; i < journal->binding_count; ++i)
                if (!strncmp(line + 8, journal->bindings[i], 64)) goto done;
            next = realloc(journal->bindings, (journal->binding_count + 1) * sizeof *next);
            if (!next) goto done;
            journal->bindings = next;
            next[journal->binding_count] = strdup(line + 8);
            if (!next[journal->binding_count]) goto done;
            ++journal->binding_count;
        } else {
            char **next;
            if (journal->binding_count || journal->accepted_count || journal->privileged_count ||
                journal->skipped_count || journal->service_count || journal->service_count ||
                strncmp(line, "artifact ", 9) || !valid_digest(line + 9) ||
                journal->count >= 10000 ||
                (journal->count && strcmp(journal->digests[journal->count - 1], line + 9) >= 0))
                goto done;
            next = realloc(journal->digests, (journal->count + 1) * sizeof *next);
            if (!next) goto done;
            journal->digests = next;
            next[journal->count] = strdup(line + 9);
            if (!next[journal->count]) goto done;
            ++journal->count;
            if (!strcmp(line + 9, journal->root)) ++roots;
        }
        ++number;
    }
    if (!ferror(stream) && bytes == (size_t)st.st_size && number >= 6 && roots == 1 &&
        (version == 1 || (version == 2 && journal->binding_count) ||
         (version == 3 && journal->accepted_count) ||
         (version == 4 && journal->privileged_count) ||
         (version == 5 && journal->catalog_index[0] && journal->binding_count) ||
         (version == 6 && journal->skipped_count) ||
         (version == 7 && journal->service_count))) result = 1;
done:
    free(line);
    if (stream) fclose(stream);
    if (fd >= 0) close(fd);
    close(transactions);
    if (result != 1) free_set_journal(journal);
    return result;
}

static int set_journal_present(int dir)
{
    struct set_journal journal = {0};
    unsigned long long generation;
    int result = read_set_journal(dir, &journal);
    if (result == 1 && (!read_generation(dir, &generation) ||
        (generation != journal.generation && generation != journal.generation + 1))) result = -1;
    free_set_journal(&journal);
    return result;
}

/* a record that is already there is compared rather than written again, so the same plan
   retried after a crash leaves the same record and not a refusal. */
static int record_write(int dir, const char *name, const char *text)
{
    char *saved = update_record(dir, name);
    int ok;
    if (saved) { ok = !strcmp(saved, text); free(saved); return ok; }
    if (errno != ENOENT || !record_file(dir, name, text, strlen(text))) return 0;
    saved = update_record(dir, name);
    ok = saved && !strcmp(saved, text);
    free(saved);
    return ok;
}

/* a committed set leaves the journal it used as its decisions record under its own plan
   hash, and the same plan writes the same record twice. */
static int retain_set_record(int transactions, const struct install_set *set)
{
    char line[66];
    char *journal = update_record(transactions, "set-journal"), *decisions = NULL;
    int child = -1, ok = 0;
    if (!journal) return 0;
    /* the record keeps the decisions the set was reviewed with. the phase line is where
       the transaction stopped, not a decision, so it does not belong to the record and
       a transaction that advances past it still finds the same record. */
    decisions = strdup(journal);
    if (!decisions) { free(journal); return 0; }
    {
        char *phase = strstr(decisions, "\nphase ");
        if (phase) *phase = 0;
    }
    if (mkdirat(transactions, set->hash, 0700) && errno != EEXIST) goto done;
    child = child_dir(transactions, set->hash, 0);
    if (child < 0) goto done;
    snprintf(line, sizeof line, "%s\n", set->hash);
    ok = record_write(child, "committed", line) &&
         record_write(child, "decisions", decisions) &&
         !fsync(child) && !fsync(transactions);
done:
    if (child >= 0) close(child);
    free(decisions);
    free(journal);
    return ok;
}

static int set_generation(int dir, unsigned long long generation)
{
    char record[32], temp_name[43] = {0};
    size_t length = (size_t)snprintf(record, sizeof record, "%llu\n", generation);
    int fd = holy_temporary_at(dir, temp_name), ok = 0;
    if (fd < 0) return 0;
    if (length < sizeof record && write_all(fd, record, length) && !fsync(fd) &&
        !renameat(dir, temp_name, dir, "generation") && !fsync(dir)) ok = 1;
    close(fd);
    if (!ok) unlinkat(dir, temp_name, 0);
    return ok;
}

/* a user override record whose path this set writes is part of what the plan fixed, so
   it is stated with the plan and bound into the plan hash. a store that changed between
   the plan and the apply moves the hash, which is the check the plan needs. the records
   are read before the database lock, since the store walk takes no lock at all. */
static int set_override_records(struct install_set *set,
                                const struct holy_override_record_info *records,
                                size_t record_count)
{
    struct holy_override_record_info *covered = NULL;
    size_t i, count = 0;
    for (i = 0; i < record_count; ++i) {
        struct set_claim key = {0};
        struct holy_override_record_info *grown;
        key.path = records[i].path + 1;
        if (!bsearch(&key, set->claims, set->claim_count, sizeof *set->claims, claim_order))
            continue;
        grown = realloc(covered, (count + 1) * sizeof *grown);
        if (!grown) goto fail;
        covered = grown;
        covered[count] = records[i];
        covered[count].name = strdup(records[i].name);
        covered[count].path = strdup(records[i].path);
        covered[count].file = strdup(records[i].file);
        covered[count].patch = strdup(records[i].patch);
        if (!covered[count].name || !covered[count].path || !covered[count].file ||
            !covered[count].patch) { ++count; goto fail; }
        ++count;
    }
    set->overrides = covered;
    set->override_count = count;
    return 1;
fail:
    holy_override_records_free(covered, count);
    return 0;
}

static void print_set_overrides(const struct install_set *set)
{
    size_t i;
    for (i = 0; i < set->override_count; ++i)
        printf("override %s path %s file %s patch %s\n",
               set->overrides[i].name, set->overrides[i].path,
               set->overrides[i].file, set->overrides[i].patch);
}

/* the capabilities the selection itself offers twice, stated before a file is staged
   and in the plan that asked for it */
static void print_set_conflicts(const struct install_set *set, unsigned long long generation)
{
    holy_conflict_claims_print(&set->capabilities, 0);
    printf("set-conflicts generation %llu artifacts %zu capabilities %zu conflicts %zu read-only\n",
           generation, set->count, set->capabilities.count, set->capability_findings);
}

static int state_set(const char *const *digests, size_t count, const char *choice,
                     const char *approved, const char *root_path,
                     const char *const *bindings, size_t binding_count,
                     const char *default_source_id,
                     const char *catalog_index,
                     const char *const *accepted_arch, size_t accepted_count,
                     const char *const *accepted_privileged, size_t privileged_count,
                     const char *const *skipped_hooks, size_t skipped_count,
                     const char *const *accepted_service, size_t service_count,
                     char plan_hash[65], int quiet)
{
    struct install_set set = {0};
    struct holy_override_record_info *override_records = NULL;
    size_t override_record_count = 0;
    unsigned long long generation;
    int root = -1, dir = -1, installed = -1, transactions = -1, result = 1, journaled = 0;
    size_t i;
    if (plan_hash) plan_hash[0] = 0;
    if ((approved && !valid_digest(approved)) || (choice && !set_choice_valid(choice))) return 2;
    if (service_count > 10000) return 2;
    for (i = 0; i < service_count; ++i) {
        size_t j;
        if (!holy_unit_name_valid(accepted_service[i])) return 2;
        for (j = 0; j < i; ++j)
            if (!strcmp(accepted_service[i], accepted_service[j])) return 2;
    }
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    dir = root < 0 ? -1 : state_dir_at(root, 0);
    /* the override store is read before the database lock, since the plan binds what
       the store says and the read must not wait for a lock this call takes */
    if (dir >= 0 && holy_override_records(root_path, &override_records,
                                           &override_record_count)) {
        result = 1;
        goto done;
    }
    if (dir < 0 || flock(dir, approved ? LOCK_EX : LOCK_SH) ||
        !state_layout(dir, 0) || !read_generation(dir, &generation) ||
        generation == ULLONG_MAX || !empty_child(dir, "index")) goto done;
    if (!empty_child(dir, "transactions")) { result = 5; goto done; }
    if (!installed_valid(dir)) goto done;
    result = build_set(root_path, root, dir, generation, digests, count, choice, 0, bindings, binding_count,
                       default_source_id, catalog_index,
                       accepted_arch, accepted_count, accepted_privileged, privileged_count,
                       skipped_hooks, skipped_count, override_records,
                       override_record_count, &set);
    if (result) goto done;
    if (!quiet && !set_service_consent(&set, accepted_service, service_count))
        result = 3;
    if (result) goto done;
    if (!approved) {
        if (plan_hash) memcpy(plan_hash, set.hash, 65);
        if (quiet) goto done;
        printf("plan-set generation %llu root %s artifacts %zu paths %zu sha256 %s read-only\n",
               generation, set.resolution.root, set.count, set.paths, set.hash);
        if (set.catalog_index[0]) printf("catalog-index %s\n", set.catalog_index);
        print_set_conflicts(&set, generation);
        print_set_overrides(&set);
        print_service_list(&set.services);
        for (i = 0; i < set.count; ++i)
            printf("selected %s %s %s\n", set.items[i].identity.digest,
                   set.items[i].identity.name,
                   set.items[i].reused ? "installed" :
                   strcmp(set.items[i].identity.digest, set.resolution.root) ? "dependency" : "explicit");
        for (i = 0; i < set.resolution.edge_count; ++i) {
            const struct holy_resolved_edge *edge = &set.resolution.edges[i];
            printf("requirement %s consumer %s provider %s %s %s\n",
                   edge->id, edge->consumer, edge->provider, edge->kind, edge->target);
        }
        for (i = 0; i < set.count; ++i) if (set.items[i].source_record)
            printf("binding %s %s", set.items[i].identity.digest, set.items[i].source_record);
        for (i = 0; i < set.count; ++i) if (set.items[i].architecture[0])
            printf("architecture %s %s accepted-unverified scope artifact\n",
                   set.items[i].identity.digest, set.items[i].architecture);
        for (i = 0; i < set.count; ++i) if (set.items[i].privileged)
            printf("privileged %s setuid accepted scope artifact\n",
                   set.items[i].identity.digest);
        for (i = 0; i < set.count; ++i) if (set.items[i].skipped_hooks)
            printf("hooks %s skipped installed-unconfigured scope artifact\n",
                   set.items[i].identity.digest);
        goto done;
    }
    if (strcmp(set.hash, approved)) { result = 3; goto done; }
    print_set_conflicts(&set, generation);
    print_set_overrides(&set);
    print_service_list(&set.services);
    installed = child_dir(dir, "installed", 0);
    transactions = child_dir(dir, "transactions", 0);
    if (installed < 0 || transactions < 0) { result = 1; goto done; }
    if (!write_set_journal(transactions, generation, &set, choice,
                           accepted_arch, accepted_count,
                           accepted_privileged, privileged_count,
                           skipped_hooks, skipped_count,
                           accepted_service, service_count, "applying")) {
        struct stat st;
        result = fstatat(transactions, "set-journal", &st, AT_SYMLINK_NOFOLLOW) ? 1 : 5;
        goto done;
    }
    journaled = 1;
    result = 5;
    for (i = 0; i < set.count; ++i) {
        struct set_item *item = &set.items[i];
        if (item->reused) continue;
        if (!holy_install_payload(item->snapshot, root, item->privileged) ||
            !save_instance(installed, item->identity.digest, item->snapshot, generation,
                           set.graph, set.graph_length,
                           strcmp(item->identity.digest, set.resolution.root) ? "dependency" : "explicit",
                           item->source_record, item->architecture[0] ? item->architecture : NULL,
                           item->privileged, item->skipped_hooks))
            goto done;
        printf("applied %s\n", item->identity.digest);
    }
    /* every instance is in place, which is the phase a crash after this point resumes
       from: recovery checks them and finishes the transaction */
    if (!write_set_journal(transactions, generation, &set, choice,
                           accepted_arch, accepted_count,
                           accepted_privileged, privileged_count,
                           skipped_hooks, skipped_count,
                           accepted_service, service_count, "instances")) goto done;
    /* the journal the transaction used becomes its decisions record, and the directory
       name is the plan it was made with, so the root keeps what the set was reviewed
       with. the record is written before the journal is dropped, so a crash leaves the
       transaction recoverable and the record already there to write again. */
    if (!retain_set_record(transactions, &set) ||
        !write_set_journal(transactions, generation, &set, choice,
                           accepted_arch, accepted_count,
                           accepted_privileged, privileged_count,
                           skipped_hooks, skipped_count,
                           accepted_service, service_count, "record") ||
        !set_generation(dir, generation + 1) ||
        !write_set_journal(transactions, generation, &set, choice,
                           accepted_arch, accepted_count,
                           accepted_privileged, privileged_count,
                           skipped_hooks, skipped_count,
                           accepted_service, service_count, "generation") ||
        unlinkat(transactions, "set-journal", 0) || fsync(transactions)) goto done;
    printf("committed-set %s generation %llu artifacts %zu\n", set.hash, generation + 1, set.count);
    result = 0;
done:
    if (result && !quiet) fprintf(stderr, "holypkg: package set failed (status %d)%s\n", result,
                        journaled ? "; incomplete set journal retained" : "");
    free_set(&set);
    holy_override_records_free(override_records, override_record_count);
    if (transactions >= 0) close(transactions);
    if (installed >= 0) close(installed);
    if (dir >= 0) close(dir);
    if (root >= 0) close(root);
    return result;
}

int holy_state_set(const char *const *digests, size_t count, const char *choice,
                   const char *approved, const char *root_path,
                   const char *const *bindings, size_t binding_count,
                   const char *const *accepted_arch, size_t accepted_count,
                   const char *const *accepted_privileged, size_t privileged_count,
                   const char *const *skipped_hooks, size_t skipped_count,
                   const char *const *accepted_service, size_t service_count,
                   char plan_hash[65])
{
    return state_set(digests, count, choice, approved, root_path, bindings,
                     binding_count, NULL, NULL, accepted_arch, accepted_count,
                     accepted_privileged, privileged_count, skipped_hooks, skipped_count,
                     accepted_service, service_count, plan_hash, 0);
}

int holy_state_set_source(const char *const *digests, size_t count,
                          const char *source_id, const char *catalog_index,
                          const char *choice,
                          const char *approved, const char *root_path,
                          const char *const *accepted_arch, size_t accepted_count,
                          const char *const *accepted_privileged, size_t privileged_count,
                          const char *const *accepted_service, size_t service_count,
                          char plan_hash[65])
{
    if (!source_id || !catalog_index) return 2;
    return state_set(digests, count, choice, approved, root_path, NULL, 0,
                     source_id, catalog_index, accepted_arch, accepted_count,
                     accepted_privileged, privileged_count, NULL, 0,
                     accepted_service, service_count, plan_hash, 0);
}

int holy_state_set_source_bindings(const char *const *digests, size_t count,
                                  const char *source_id, const char *catalog_index,
                                  const char *const *bindings, size_t binding_count,
                                  const char *choice, const char *approved,
                                  const char *root_path,
                                  const char *const *accepted_arch, size_t accepted_count,
                                  const char *const *accepted_privileged, size_t privileged_count,
                                  const char *const *accepted_service, size_t service_count,
                                  char plan_hash[65])
{
    if (!source_id || !catalog_index) return 2;
    return state_set(digests, count, choice, approved, root_path,
                     bindings, binding_count, source_id, catalog_index,
                     accepted_arch, accepted_count,
                     accepted_privileged, privileged_count, NULL, 0,
                     accepted_service, service_count, plan_hash, 0);
}

int holy_state_probe_source_bindings(const char *const *digests, size_t count,
                                    const char *source_id, const char *catalog_index,
                                    const char *const *bindings, size_t binding_count,
                                    const char *choice, const char *root_path,
                                    const char *const *accepted_arch, size_t accepted_count,
                                    const char *const *accepted_privileged,
                                    size_t privileged_count,
                                    const char *const *accepted_service,
                                    size_t service_count)
{
    if (!source_id || !catalog_index) return 2;
    return state_set(digests, count, choice, NULL, root_path,
                     bindings, binding_count, source_id, catalog_index,
                     accepted_arch, accepted_count,
                     accepted_privileged, privileged_count, NULL, 0,
                     accepted_service, service_count, NULL, 1);
}

static int instance_matches_snapshot(int item, const char *snapshot)
{
    static const char *const names[] = {"meta", "files", "deps", "origin", "provides", "hooks", "transform"};
    struct archive *archive = archive_read_new();
    struct archive_entry *entry;
    struct holy_package_identity identity = {0};
    unsigned seen = 0;
    char incoming[8192], installed[8192];
    int status, ok = 0, has_claims, has_hooks, has_transform, has_config;
    struct stat claims_stat;
    size_t i;
    has_claims = !fstatat(item, "provides", &claims_stat, AT_SYMLINK_NOFOLLOW);
    if (!has_claims && errno != ENOENT) goto done;
    has_hooks = !fstatat(item, "hooks", &claims_stat, AT_SYMLINK_NOFOLLOW);
    if (!has_hooks && errno != ENOENT) goto done;
    has_transform = !fstatat(item, "transform", &claims_stat, AT_SYMLINK_NOFOLLOW);
    if (!has_transform && errno != ENOENT) goto done;
    has_config = !fstatat(item, "config-state", &claims_stat, AT_SYMLINK_NOFOLLOW);
    if (!has_config && errno != ENOENT) goto done;
    if (has_config && (!holy_package_identity(snapshot, &identity) ||
                       !config_state_valid(item, identity.digest))) goto done;
    if (!archive || archive_read_support_filter_lz4(archive) != ARCHIVE_OK ||
        archive_read_support_format_tar(archive) != ARCHIVE_OK ||
        archive_read_open_filename(archive, snapshot, 8192) != ARCHIVE_OK) goto done;
    while ((status = archive_read_next_header(archive, &entry)) == ARCHIVE_OK) {
        const char *path = archive_entry_pathname(entry);
        struct stat st;
        la_ssize_t got;
        int fd;
        for (i = 0; i < sizeof names / sizeof *names; ++i)
            if (path && !strncmp(path, "HOLY/", 5) && !strcmp(path + 5, names[i])) break;
        if (i == sizeof names / sizeof *names || (i == 4 && !has_claims) ||
            (i == 5 && !has_hooks) || (i == 6 && !has_transform)) {
            if (archive_read_data_skip(archive) != ARCHIVE_OK) goto done;
            continue;
        }
        if (seen & (1u << i)) goto done;
        fd = openat(item, i == 1 && has_config ? "package-files" : names[i],
                    O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0) goto done;
        if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size != archive_entry_size(entry)) {
            close(fd); goto done;
        }
        while ((got = archive_read_data(archive, incoming, sizeof incoming)) > 0) {
            size_t used = 0;
            while (used < (size_t)got) {
                ssize_t read_count = read(fd, installed + used, (size_t)got - used);
                if (read_count < 0 && errno == EINTR) continue;
                if (read_count <= 0) { close(fd); goto done; }
                used += (size_t)read_count;
            }
            if (memcmp(incoming, installed, (size_t)got)) { close(fd); goto done; }
        }
        close(fd);
        if (got) goto done;
        seen |= 1u << i;
    }
    ok = status == ARCHIVE_EOF &&
         seen == ((1u << 4) - 1u) + (has_claims ? (1u << 4) : 0) +
                 (has_hooks ? (1u << 5) : 0) + (has_transform ? (1u << 6) : 0);
done:
    holy_package_identity_free(&identity);
    archive_read_free(archive);
    return ok;
}

static int instance_reason_matches(int item, const char *reason)
{
    char buffer[1024], expected[64];
    ssize_t got;
    int fd = openat(item, "state", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return 0;
    got = read(fd, buffer, sizeof buffer - 1);
    close(fd);
    if (got <= 0) return 0;
    buffer[got] = 0;
    snprintf(expected, sizeof expected, "\nreason %s\n", reason);
    return strstr(buffer, expected) != NULL;
}

static int recover_set(const char *root_path, int resume)
{
    struct install_set set = {0};
    struct set_journal journal = {0};
    struct holy_override_record_info *override_records = NULL;
    size_t override_record_count = 0;
    unsigned long long generation, recorded;
    const char **digests = NULL;
    unsigned char *present = NULL;
    size_t i, j, phase = 0;
    struct utsname host;
    int root = -1, dir = -1, installed = -1, transactions = -1, result = 5, phased = 0;
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    dir = root < 0 ? -1 : state_dir_at(root, 0);
    if (dir >= 0 && holy_override_records(root_path, &override_records,
                                           &override_record_count)) goto done;
    if (dir < 0 || flock(dir, LOCK_EX) || !state_layout(dir, 1) ||
        !empty_child(dir, "index") || !read_generation(dir, &generation)) { result = 1; goto done; }
    if (read_set_journal(dir, &journal) != 1 ||
        (generation != journal.generation && generation != journal.generation + 1) ||
        !installed_valid(dir)) goto done;
    /* a journal written before phases existed states none, and the phase it names is
       where the transaction stopped: the root may already carry the generation the
       publication would have written, since that is the phase before the journal line */
    phased = journal.phase[0] != 0;
    if (!phased) strcpy(journal.phase, "applying");
    phase = phase_index(journal.phase);
    printf("resumed-phase %s\n", journal.phase);
    if (journal.host[0] && (uname(&host) || strcmp(host.machine, journal.host))) goto done;
    digests = calloc(journal.count, sizeof *digests);
    present = calloc(journal.count, 1);
    if (!digests || !present) { result = 1; goto done; }
    digests[0] = journal.root;
    for (i = 0, j = 1; i < journal.count; ++i)
        if (strcmp(journal.root, journal.digests[i])) digests[j++] = journal.digests[i];
    if (build_set(root_path, root, dir, journal.generation, digests, journal.count,
                  strcmp(journal.choice, "-") ? journal.choice : NULL, 1,
                  (const char *const *)journal.bindings, journal.binding_count,
                  NULL, journal.catalog_index[0] ? journal.catalog_index : NULL,
                  (const char *const *)journal.accepted_arch, journal.accepted_count,
                  (const char *const *)journal.accepted_privileged, journal.privileged_count,
                  (const char *const *)journal.skipped_hooks, journal.skipped_count,
                  override_records, override_record_count, &set) ||
        set.count != journal.count || strcmp(set.hash, journal.hash)) goto done;
    /* a journal names the consent it was reviewed with; a set that starts a service
       without one is refused here too, so a hand edited journal places no unit */
    if (!set_service_consent(&set, (const char *const *)journal.accepted_service,
                             journal.service_count)) {
        result = 3;
        goto done;
    }
    installed = child_dir(dir, "installed", 0);
    transactions = child_dir(dir, "transactions", 0);
    if (installed < 0 || transactions < 0) goto done;
    for (i = 0; i < set.count; ++i) {
        char graph[65], expected[65];
        unsigned char hash[32];
        unsigned int length;
        size_t k;
        struct stat st;
        int item, files, ok;
        const struct set_item *candidate = &set.items[i];
        if (candidate->reused) { present[i] = 1; continue; }
        if (fstatat(installed, candidate->identity.digest, &st, AT_SYMLINK_NOFOLLOW)) {
            struct plan_hash claims = {0};
            if (errno != ENOENT || !resume || generation != journal.generation ||
                slot_available(dir, &candidate->identity, candidate->source_id) != 1 ||
                !holy_install_preflight_resume(candidate->snapshot, root, candidate->privileged)) goto done;
            claims.dir = dir;
            claims.hash = EVP_MD_CTX_new();
            ok = claims.hash && EVP_DigestInit_ex(claims.hash, EVP_sha256(), NULL) == 1 &&
                 holy_verify_visit(candidate->snapshot, plan_entry, &claims);
            EVP_MD_CTX_free(claims.hash);
            if (!ok) goto done;
            continue;
        }
        present[i] = 1;
        item = child_dir(installed, candidate->identity.digest, 0);
        files = item < 0 ? -1 : openat(item, "files", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        ok = files >= 0 && instance_state_generation(item, candidate->identity.digest, &recorded) &&
             instance_source_matches(item, candidate->source_record) &&
             instance_architecture_matches(item, candidate->architecture) &&
             recorded == journal.generation + 1 && graph_digest(item, graph) &&
             instance_reason_matches(item, strcmp(candidate->identity.digest, set.resolution.root) ?
                                     "dependency" : "explicit") &&
             instance_matches_snapshot(item, candidate->snapshot) &&
             EVP_Digest(set.graph, set.graph_length, hash, &length, EVP_sha256(), NULL) == 1 &&
             length == 32;
        if (ok) {
            for (k = 0; k < 32; ++k) snprintf(expected + k * 2, 3, "%02x", hash[k]);
            ok = !strcmp(expected, graph) && exclusive_claims(installed, candidate->identity.digest, files) == 1 &&
                 holy_install_check_manifest(files, root) == 1;
        }
        if (files >= 0) close(files);
        if (item >= 0) close(item);
        if (!ok) goto done;
    }
    for (i = 0; i < set.count; ++i) if (!present[i]) {
        const struct set_item *item = &set.items[i];
        /* a phase past the instances cannot be missing one, since the phase line is
           written after the last instance the transaction saved */
        if (phase >= 1 || !holy_install_payload_missing(item->snapshot, root) ||
            !save_instance(installed, item->identity.digest, item->snapshot, journal.generation,
                           set.graph, set.graph_length,
                           strcmp(item->identity.digest, set.resolution.root) ? "dependency" : "explicit",
                           item->source_record, item->architecture[0] ? item->architecture : NULL,
                           item->privileged, item->skipped_hooks))
            goto done;
        printf("resumed %s\n", item->identity.digest);
    }
    /* a recovered set leaves the same record a committed one does, with the generation
       it resumed from, so the root keeps what both were reviewed with. a phase that got
       past the record has it already, and writing it again must find the same text. */
    if (!retain_set_record(transactions, &set)) goto done;
    if (generation == journal.generation && !set_generation(dir, generation + 1)) goto done;
    if (fsync(dir) || unlinkat(transactions, "set-journal", 0) || fsync(transactions)) goto done;
    printf("recovered-set %s generation %llu artifacts %zu phase %s\n",
           set.hash, journal.generation + 1, set.count, journal.phase);
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: set recovery requires inspection (status %d)\n", result);
    free(present);
    free(digests);
    free_set(&set);
    holy_override_records_free(override_records, override_record_count);
    free_set_journal(&journal);
    if (transactions >= 0) close(transactions);
    if (installed >= 0) close(installed);
    if (dir >= 0) close(dir);
    if (root >= 0) close(root);
    return result;
}

int holy_state_finish_set(const char *root_path)
{
    return recover_set(root_path, 0);
}

int holy_state_continue_set(const char *root_path)
{
    return recover_set(root_path, 1);
}

/* a missing file an override record covers: a repair brings the packaged bytes back, so
   the record is stated in the plan and the statement is part of what the approval
   covers. the record path is absolute and the manifest path is not. */
struct repair_override {
    char *name;
    char *path;
};

struct repair_overrides {
    struct repair_override *statements;
    size_t count;
    const struct holy_override_record_info *records;
    size_t record_count;
};

static void repair_overrides_free(struct repair_overrides *wanted)
{
    size_t i;
    for (i = 0; i < wanted->count; ++i) {
        free(wanted->statements[i].name);
        free(wanted->statements[i].path);
    }
    free(wanted->statements);
    wanted->statements = NULL;
    wanted->count = 0;
}

static int repair_statement(struct repair_overrides *wanted, const char *name,
                            const char *path)
{
    struct repair_override *statements;
    size_t i;
    for (i = 0; i < wanted->count; ++i)
        if (!strcmp(wanted->statements[i].path, path) &&
            !strcmp(wanted->statements[i].name, name)) return 1;
    if (wanted->count >= 65536) return 0;
    statements = realloc(wanted->statements,
                         (wanted->count + 1) * sizeof *statements);
    if (!statements) return 0;
    wanted->statements = statements;
    statements[wanted->count].name = strdup(name);
    statements[wanted->count].path = strdup(path);
    if (!statements[wanted->count].name || !statements[wanted->count].path) return 0;
    ++wanted->count;
    return 1;
}

static int repair_override_finding(void *context, const char *path, const char *code,
                                   const char *target)
{
    struct repair_overrides *wanted = context;
    size_t i;
    (void)target;
    if (strcmp(code, "missing-file")) return 1;
    for (i = 0; i < wanted->record_count; ++i)
        if (wanted->records[i].path[0] == '/' && !strcmp(wanted->records[i].path + 1, path))
            if (!repair_statement(wanted, wanted->records[i].name,
                                  wanted->records[i].path)) return 0;
    return 1;
}

static int repair_hash(int root, unsigned long long generation, const char *digest,
                       const char *graph, const char *manifest,
                       const struct repair_overrides *wanted, char output[65])
{
    struct stat st;
    char identity[128], line[1024];
    unsigned char hash[32];
    unsigned int length;
    size_t i;
    int used;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = 0;
    if (!ctx || fstat(root, &st) || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        !hash_text(ctx, "holy-repair-missing-3") || !hash_text(ctx, digest) ||
        !hash_text(ctx, graph) || !hash_text(ctx, manifest)) goto done;
    for (i = 0; i < wanted->count; ++i) {
        used = snprintf(line, sizeof line, "override %s %s\n",
                        wanted->statements[i].name, wanted->statements[i].path);
        if (used < 0 || (size_t)used >= sizeof line || !hash_text(ctx, line)) goto done;
    }
    snprintf(identity, sizeof identity, "%ju:%ju:%llu", (uintmax_t)st.st_dev,
             (uintmax_t)st.st_ino, generation);
    if (!hash_text(ctx, identity) || EVP_DigestFinal_ex(ctx, hash, &length) != 1 || length != 32) goto done;
    for (i = 0; i < 32; ++i) snprintf(output + i * 2, 3, "%02x", hash[i]);
    ok = 1;
done:
    EVP_MD_CTX_free(ctx);
    return ok;
}

int holy_state_repair(const char *digest, const char *approved, const char *root_path)
{
    int root = -1, dir = -1, installed = -1, item = -1, files = -1, transactions = -1;
    int result = 1, stage = 0, journaled = 0, resume = digest == NULL, transformed = 0;
    char repaired_phase[16] = {0};
    int published = 0;
    char artifact[65], expected[65], actual[65], graph[65], manifest[65], journal[256];
    char *snapshot = NULL;
    unsigned long long generation, recorded;
    struct stat root_st;
    size_t length, i;
    struct repair_overrides wanted = {0};
    struct holy_override_record_info *records = NULL;
    size_t record_count = 0;
    if (!resume && (!valid_digest(digest) || (approved && !valid_digest(approved)))) return 2;
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    /* the override store is read before the database lock, since the store walk takes
       no lock of its own and the plan states what it says */
    if (root >= 0 && holy_override_records(root_path, &records, &record_count)) {
        result = 1;
        goto done;
    }
    wanted.records = records;
    wanted.record_count = record_count;
    dir = root < 0 ? -1 : state_dir_at(root, 0);
    if (dir < 0 || fstat(root, &root_st) || flock(dir, approved || resume ? LOCK_EX : LOCK_SH) ||
        !state_layout(dir, 0) || !empty_child(dir, "index") ||
        !read_generation(dir, &generation) || generation == ULLONG_MAX) goto done;
    recorded = generation;
    if (resume) {
        result = 5;
        if (set_journal_present(dir) ||
            journal_valid(dir, generation, &recorded, artifact, expected, &stage,
                          repaired_phase) != 1 ||
            stage != 2) goto done;
        published = !strcmp(repaired_phase, repair_phases[1]);
        if (repaired_phase[0]) printf("resumed-phase %s\n", repaired_phase);
        {
            DIR *list;
            struct dirent *entry;
            int valid = 1, journal_dir = child_dir(dir, "transactions", 0);
            if (journal_dir < 0) goto done;
            list = directory_stream(journal_dir);
            if (!list) { close(journal_dir); goto done; }
            errno = 0;
            while ((entry = readdir(list))) {
                if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
                if (completed_transaction(journal_dir, entry->d_name)) { errno = 0; continue; }
                if (strcmp(entry->d_name, "journal")) { valid = 0; break; }
                errno = 0;
            }
            if (!entry && errno) valid = 0;
            closedir(list);
            close(journal_dir);
            if (!valid) goto done;
        }
        journaled = 1;
        digest = artifact;
        approved = expected;
    } else if (!empty_child(dir, "transactions")) { result = 5; goto done; }
    if (!installed_valid(dir)) goto done;
    installed = child_dir(dir, "installed", 0);
    item = installed < 0 ? -1 : child_dir(installed, digest, 0);
    if (item < 0) { result = 6; goto done; }
    {
        struct stat st;
        transformed = !fstatat(item, "config-state", &st, AT_SYMLINK_NOFOLLOW);
        if (!transformed && errno != ENOENT) goto done;
    }
    files = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    snapshot = holy_cache_snapshot(digest, root_path);
    if (!snapshot) { result = 6; goto done; }
    if (files < 0 || !instance_matches_snapshot(item, snapshot) ||
        !graph_digest(item, graph) || !instance_record_digest(item, "files", manifest)) goto done;
    /* 0 is the repair case: a file is missing or changed. -1 is an unreadable manifest */
    if (record_count &&
        holy_install_check_report(files, root, repair_override_finding, &wanted) == -1)
        goto done;
    if (!repair_hash(root, recorded, digest, graph, manifest, &wanted, actual)) goto done;
    {
        struct plan_hash claims = {0};
        int valid;
        claims.completed = 1;
        claims.hash = EVP_MD_CTX_new();
        valid = claims.hash && EVP_DigestInit_ex(claims.hash, EVP_sha256(), NULL) == 1 &&
                holy_verify_visit(snapshot, plan_entry, &claims);
        EVP_MD_CTX_free(claims.hash);
        if (!valid) { result = resume ? 5 : 4; goto done; }
    }
    if (approved && strcmp(approved, actual)) { result = 3; goto done; }
    if (exclusive_claims(installed, digest, files) != 1 ||
        (transformed ? holy_install_check_repair_transformed(files, root) :
                       holy_install_check_or_missing(files, root)) != 1) {
        result = resume ? 5 : 4; goto done;
    }
    if (!same_root(root_path, &root_st)) { result = 4; goto done; }
    if (!approved) {
        printf("repair-plan generation %llu artifact %s sha256 %s missing-only read-only\n",
               generation, digest, actual);
        for (i = 0; i < wanted.count; ++i)
            printf("repair-override %s path %s state packaged-bytes-restored\n",
                   wanted.statements[i].name, wanted.statements[i].path);
        result = ferror(stdout) ? 1 : 0;
        goto done;
    }
    transactions = child_dir(dir, "transactions", 0);
    if (transactions < 0) goto done;
    result = 5;
    if (!resume) {
        length = repair_journal_text(journal, sizeof journal, "repairing", recorded,
                                     digest, actual, repair_phases[0]);
        if (!length || !record_file(transactions, "journal", journal, length)) goto done;
        journaled = 1;
    }
    /* a journal that names the generation phase proved the payload, so the recovery
       checks the manifest instead of restoring the same bytes again */
    if (!published && !(transformed ? holy_install_payload_missing_mapped(snapshot, root, files) :
                                      holy_install_payload_missing(snapshot, root)))
        goto done;
    if (holy_install_check_manifest(files, root) != 1) goto done;
    length = repair_journal_text(journal, sizeof journal, "repairing", recorded,
                                 digest, actual, repair_phases[1]);
    if (!length || !update_replace(transactions, "journal", journal)) goto done;
    if ((generation == recorded && !set_generation(dir, recorded + 1)) || fsync(dir) ||
        unlinkat(transactions, "journal", 0) || fsync(transactions)) goto done;
    printf("repaired %s generation %llu missing-only phase %s\n", digest, recorded + 1,
           repair_phases[1]);
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: missing-file repair failed (status %d)%s\n", result,
                        journaled ? "; repair journal retained" : "");
    repair_overrides_free(&wanted);
    holy_override_records_free(records, record_count);
    if (snapshot) { unlink(snapshot); free(snapshot); }
    if (files >= 0) close(files);
    if (item >= 0) close(item);
    if (installed >= 0) close(installed);
    if (transactions >= 0) close(transactions);
    if (dir >= 0) close(dir);
    if (root >= 0) close(root);
    return result;
}

struct update_journal {
    unsigned long long generation;
    char old[65], next[65], plan[65];
    int arch_decision, priv_decision;    /* the single slot a v1..5 journal names */
    size_t pair_count;
    char (*olds)[65];
    char (*news)[65];
    int *architecture;                   /* per slot, the arch decision that slot needs */
    int *privileged;                     /* per slot, the privileged decision */
    char **services;      /* the unit names the plan was reviewed with */
    size_t service_count;
    char phase[16];       /* the phase the transaction proved, empty in an old journal */
};

/* the phases a replacement passes through, in order. the journal states the one it
   reached, so recovery resumes there instead of re-deriving where the crash fell. */
static const char *const update_phases[] = {
    "instances", "files", "swapped", "generation", "committed"
};

static int update_phase_valid(const char *phase)
{
    size_t i;
    for (i = 0; i < sizeof update_phases / sizeof *update_phases; ++i)
        if (!strcmp(phase, update_phases[i])) return 1;
    return 0;
}

/* the phase is the last line of the journal, so the replace rewrites the journal in
   place and a replace that fails leaves the earlier phase standing */
static int update_journal_phase(int work, const char *phase)
{
    char *record = update_record(work, "journal"), *line = NULL, *next = NULL;
    size_t length = 0;
    int ok = 0;
    if (!record || !update_phase_valid(phase)) { free(record); return 0; }
    length = strlen(record);
    if (length && record[length - 1] == '\n') record[--length] = 0;
    line = strrchr(record, '\n');
    if (line && !strncmp(line + 1, "phase ", 6)) *line = 0;
    if (asprintf(&next, "%s\nphase %s\n", record, phase) < 0) {
        free(record);
        return 0;
    }
    ok = update_replace(work, "journal", next);
    free(next);
    free(record);
    return ok;
}

static void update_journal_forget(struct update_journal *journal)
{
    size_t i;
    for (i = 0; i < journal->service_count; ++i) free(journal->services[i]);
    free(journal->services);
    free(journal->olds); free(journal->news);
    free(journal->architecture); free(journal->privileged);
    memset(journal, 0, sizeof *journal);
}

static char *update_record(int dir, const char *name)
{
    struct stat st;
    int fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    char *bytes = NULL;
    size_t used = 0;
    if (fd < 0) return NULL;
    errno = 0;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        st.st_size > 64 * 1024 * 1024 || (st.st_mode & 0022) ||
        (st.st_uid != 0 && st.st_uid != geteuid())) goto done;
    bytes = malloc((size_t)st.st_size + 1);
    if (!bytes) goto done;
    while (used < (size_t)st.st_size) {
        ssize_t got = read(fd, bytes + used, (size_t)st.st_size - used);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { free(bytes); bytes = NULL; goto done; }
        used += (size_t)got;
    }
    if (memchr(bytes, 0, used)) { free(bytes); bytes = NULL; goto done; }
    bytes[used] = 0;
done:
    close(fd);
    return bytes;
}

static int remove_identity(const char *digest, unsigned long long generation,
                           int broken, char plan[192], char identity[65])
{
    static const char digits[] = "0123456789abcdef";
    unsigned char hash[32];
    unsigned length = 0;
    size_t i;
    int n = snprintf(plan, 192,
        "format holy-remove-1\ngeneration %llu\nartifact %s\naccept-broken %s\n",
        generation, digest, broken ? "yes" : "no");
    if (n < 0 || n >= 192 || EVP_Digest(plan, (size_t)n, hash, &length,
        EVP_sha256(), NULL) != 1 || length != 32) return 0;
    for (i = 0; i < 32; ++i) {
        identity[i * 2] = digits[hash[i] >> 4];
        identity[i * 2 + 1] = digits[hash[i] & 15];
    }
    identity[64] = 0;
    return 1;
}

static int remove_workdir(int transactions, const char *digest,
                          unsigned long long generation, int broken)
{
    char plan[192], identity[65];
    if (!remove_identity(digest, generation, broken, plan, identity)) return -1;
    return child_dir(transactions, identity, 0);
}

static int remove_record(int transactions, const char *digest,
                         unsigned long long generation, int broken, int create)
{
    char plan[192], identity[65], decisions[32];
    char *saved = NULL;
    int child = -1, ok = 0;
    if (!remove_identity(digest, generation, broken, plan, identity)) return 0;
    if (create && mkdirat(transactions, identity, 0700) && errno != EEXIST) return 0;
    child = child_dir(transactions, identity, 0);
    if (child < 0) return 0;
    saved = update_record(child, "plan");
    if (!saved && create && errno == ENOENT) {
        if (!record_file(child, "plan", plan, strlen(plan))) goto done;
        saved = update_record(child, "plan");
    }
    if (!saved || strcmp(saved, plan)) goto done;
    free(saved); saved = NULL;
    snprintf(decisions, sizeof decisions, "accept-broken %s\n", broken ? "yes" : "no");
    saved = update_record(child, "decisions");
    if (!saved && create && errno == ENOENT) {
        if (!record_file(child, "decisions", decisions, strlen(decisions))) goto done;
        saved = update_record(child, "decisions");
    }
    ok = saved && !strcmp(saved, decisions) && !fsync(child) && !fsync(transactions);
done:
    free(saved);
    close(child);
    return ok;
}

static int commit_remove_record(int transactions, const char *digest,
                                unsigned long long generation, int broken)
{
    char plan[192], identity[65], line[66];
    char *saved;
    int child, ok;
    if (!remove_identity(digest, generation, broken, plan, identity) ||
        !remove_record(transactions, digest, generation, broken, 0)) return 0;
    child = child_dir(transactions, identity, 0);
    if (child < 0) return 0;
    snprintf(line, sizeof line, "%s\n", identity);
    saved = update_record(child, "committed");
    if (!saved && errno == ENOENT) {
        if (!record_file(child, "committed", line, strlen(line))) {
            close(child); return 0;
        }
        saved = update_record(child, "committed");
    }
    ok = saved && !strcmp(saved, line) && !fsync(transactions);
    free(saved);
    close(child);
    return ok;
}

/* a committed removal keeps the plan it was made from, whose canonical form names the
   directory, and the one decision it was reviewed with. */
static int remove_record_valid(int transactions, const char *name)
{
    int child = child_dir(transactions, name, 0), ok = 0;
    char *plan = child < 0 ? NULL : update_record(child, "plan");
    if (plan && !strncmp(plan, "format holy-remove-1\n", 21)) {
        unsigned long long generation;
        char artifact[65], choice[4], canonical[192], identity[65];
        char *decision = update_record(child, "decisions");
        ok = sscanf(plan,
            "format holy-remove-1\ngeneration %llu\nartifact %64[0-9a-f]\naccept-broken %3s",
            &generation, artifact, choice) == 3 && valid_digest(artifact) &&
            (!strcmp(choice, "yes") || !strcmp(choice, "no")) &&
            remove_identity(artifact, generation, !strcmp(choice, "yes"),
                            canonical, identity) && !strcmp(plan, canonical) &&
            !strcmp(name, identity) && decision &&
            !strcmp(decision, !strcmp(choice, "yes") ?
                    "accept-broken yes\n" : "accept-broken no\n");
        free(decision);
    }
    free(plan);
    if (child >= 0) close(child);
    return ok;
}

/* a committed set leaves the journal it used as its decisions record, and the directory
   name is the plan that journal states, so the pair is what the root keeps. */
static int set_record_valid(int transactions, const char *name)
{
    int child = child_dir(transactions, name, 0), ok = 0;
    char *decisions = child < 0 ? NULL : update_record(child, "decisions");
    unsigned long long generation = 0;
    char plan[65];
    if (decisions &&
        sscanf(decisions, "format holy-set-journal-%*d\ngeneration %llu\nplan %64[0-9a-f]\n",
               &generation, plan) == 2 && generation != ULLONG_MAX &&
        !strcmp(plan, name)) ok = 1;
    free(decisions);
    if (child >= 0) close(child);
    return ok;
}

/* a committed replacement keeps the plan document whose digest names the directory. */
static int update_record_valid(int transactions, const char *name)
{
    int child = child_dir(transactions, name, 0), ok = 0;
    unsigned char digest[32];
    unsigned int length;
    char *plan = child < 0 ? NULL : update_record(child, "plan");
    if (plan && (!strncmp(plan, "[update]\nformat holy-update-plan-1\n",
                          sizeof "[update]\nformat holy-update-plan-1\n" - 1) ||
                 !strncmp(plan, "[update]\nformat holy-update-plan-2\n",
                          sizeof "[update]\nformat holy-update-plan-2\n" - 1)) &&
        EVP_Digest(plan, strlen(plan), digest, &length, EVP_sha256(), NULL) == 1 &&
        length == 32) {
        char computed[65];
        size_t i;
        for (i = 0; i < 32; ++i) snprintf(computed + 2 * i, 3, "%02x", digest[i]);
        ok = !strcmp(computed, name);
    }
    free(plan);
    if (child >= 0) close(child);
    return ok;
}

/* three shapes of committed transaction live in the transactions directory: a removal,
   a set and a replacement. a directory that is none of them is not a completed
   transaction, so it blocks other work rather than being ignored. */
static int completed_transaction(int transactions, const char *name)
{
    int child, ok;
    char *record;
    if (!valid_digest(name)) return 0;
    child = child_dir(transactions, name, 0);
    if (child < 0) return 0;
    record = update_record(child, "committed");
    ok = record && strlen(record) == 65 && !memcmp(record, name, 64) && record[64] == '\n';
    free(record);
    if (ok && !remove_record_valid(transactions, name) &&
        !update_record_valid(transactions, name) && !set_record_valid(transactions, name)) ok = 0;
    close(child);
    return ok;
}

static int update_pending(int dir)
{
    struct stat st;
    int transactions = child_dir(dir, "transactions", 0), result = -1;
    if (transactions < 0) return -1;
    if (fstatat(transactions, "update", &st, AT_SYMLINK_NOFOLLOW)) {
        if (errno == ENOENT) result = 0;
    } else if (S_ISDIR(st.st_mode) && !(st.st_mode & 0022) &&
               (st.st_uid == 0 || st.st_uid == geteuid())) result = 1;
    close(transactions);
    return result;
}

static int update_replace(int dir, const char *name, const char *record)
{
    char temporary[43] = {0};
    int fd = holy_temporary_at(dir, temporary), ok = 0;
    if (fd < 0) return 0;
    if (!write_all(fd, record, strlen(record)) || fsync(fd)) goto done;
    if (renameat(dir, temporary, dir, name) || fsync(dir)) goto done;
    ok = 1;
done:
    close(fd);
    if (!ok) unlinkat(dir, temporary, 0);
    return ok;
}

/* the journal states the decisions the plan was reviewed with. version 1 is none,
   2 adds accept-privileged, 3 adds accept-arch, 4 both, and 5 carries the consented
   unit names after them. a generation one back is the journal of an operation that had
   already published when the crash came. */
/* a group names every slot it replaces as a pair, so its journal carries a list of
   them rather than one old/new pair, and each decision names the slot it belongs to */
static int read_update_group_journal(const char *record, unsigned long long generation,
                                     struct update_journal *journal)
{
    FILE *stream;
    char *line = NULL;
    size_t capacity = 0, number = 0, declared = 0, count = 0, i;
    ssize_t got;
    int planned = 0, ok = 0;
    stream = fmemopen((void *)record, strlen(record), "r");
    if (!stream) return 0;
    while ((got = getline(&line, &capacity, stream)) >= 0) {
        char *end;
        unsigned long long stated;
        if (++number > 8 + 65536 || got < 2 || line[got - 1] != '\n' ||
            memchr(line, 0, (size_t)got)) break;
        line[got - 1] = 0;
        if (number == 1) {
            if (strcmp(line, "format holy-update-journal-7") &&
                strcmp(line, "format holy-update-journal-6")) break;
            continue;
        }
        if (number == 2) {
            errno = 0;
            stated = strtoull(line + 11, &end, 10);
            if (strncmp(line, "generation ", 11) || errno || *end ||
                stated == ULLONG_MAX || stated != generation) break;
            journal->generation = stated;
            continue;
        }
        if (number == 3) {
            errno = 0;
            declared = strtoul(line + 12, &end, 10);
            if (strncmp(line, "replacement ", 12) || errno || *end || !declared ||
                declared > 4096) break;
            journal->olds = calloc(declared, sizeof *journal->olds);
            journal->news = calloc(declared, sizeof *journal->news);
            journal->architecture = calloc(declared, sizeof *journal->architecture);
            journal->privileged = calloc(declared, sizeof *journal->privileged);
            if (!journal->olds || !journal->news || !journal->architecture ||
                !journal->privileged) break;
            journal->pair_count = declared;
            continue;
        }
        /* the plan digest closes the journal, and a phase line may follow it as the
           last line of the record */
        if (planned) {
            if (strncmp(line, "phase ", 6) || strlen(line) > 22) break;
            memcpy(journal->phase, line + 6, strlen(line + 6) + 1);
            if (!update_phase_valid(journal->phase)) break;
            continue;
        }
        if (!strncmp(line, "pair ", 5) && strlen(line) == 134 && count < declared) {
            memcpy(journal->olds[count], line + 5, 64);
            memcpy(journal->news[count], line + 70, 64);
            ++count;
            continue;
        }
        if (!strncmp(line, "accept-arch ", 12) && strlen(line) == 76) {
            for (i = 0; i < declared; ++i)
                if (!journal->architecture[i] &&
                    !memcmp(line + 12, journal->news[i], 64)) break;
            if (i == declared) break;
            journal->architecture[i] = 1;
            continue;
        }
        if (!strncmp(line, "accept-privileged ", 18) && strlen(line) == 82) {
            for (i = 0; i < declared; ++i)
                if (!journal->privileged[i] &&
                    !memcmp(line + 18, journal->news[i], 64)) break;
            if (i == declared) break;
            journal->privileged[i] = 1;
            continue;
        }
        if (!strncmp(line, "service ", 8)) {
            char **grown;
            if (!holy_unit_name_valid(line + 8)) break;
            for (i = 0; i < journal->service_count; ++i)
                if (!strcmp(line + 8, journal->services[i])) break;
            if (i != journal->service_count || journal->service_count >= 65536) break;
            grown = realloc(journal->services, (journal->service_count + 1) * sizeof *grown);
            if (!grown) break;
            journal->services = grown;
            grown[journal->service_count] = strdup(line + 8);
            if (!grown[journal->service_count]) break;
            ++journal->service_count;
            continue;
        }
        if (!strncmp(line, "plan ", 5) && strlen(line) == 69) {
            memcpy(journal->plan, line + 5, 65);
            planned = 1;
            continue;
        }
        break;
    }
    free(line);
    fclose(stream);
    ok = planned && number >= 5 && count == declared && valid_digest(journal->plan);
    /* every pair names two different artifacts, no artifact is a slot twice and no new
       artifact is another slot's old one */
    for (i = 0; ok && i < declared; ++i) {
        size_t j;
        if (!valid_digest(journal->olds[i]) || !valid_digest(journal->news[i]) ||
            !strcmp(journal->olds[i], journal->news[i])) { ok = 0; break; }
        for (j = 0; ok && j < i; ++j)
            if (!strcmp(journal->olds[i], journal->olds[j]) ||
                !strcmp(journal->news[i], journal->news[j]) ||
                !strcmp(journal->news[i], journal->olds[j])) ok = 0;
    }
    if (ok) {
        memcpy(journal->old, journal->olds[0], 65);
        memcpy(journal->next, journal->news[0], 65);
        journal->arch_decision = journal->architecture[0];
        journal->priv_decision = journal->privileged[0];
    } else {
        update_journal_forget(journal);
    }
    return ok;
}

/* a group names its slots as pairs and a single slot as one old/new line, and version 6
   is a group written before phases existed as well as the single slot that carries a
   phase, so the third line says which one this is */
static int update_journal_is_group(const char *record)
{
    const char *line;
    if (!strncmp(record, "format holy-update-journal-7\n",
                 sizeof "format holy-update-journal-7\n" - 1)) return 1;
    if (strncmp(record, "format holy-update-journal-6\n",
                sizeof "format holy-update-journal-6\n" - 1)) return 0;
    line = strchr(record, '\n');
    if (line && (line = strchr(line + 1, '\n')))
        return !strncmp(line + 1, "replacement ", 12);
    return 0;
}

static int read_update_journal(int work, unsigned long long current,
                               struct update_journal *journal)
{
    char *record = update_record(work, "journal"), *line = NULL;
    size_t capacity = 0, number = 0;
    int version = 0, ok = 0, attempt;
    if (!record) return 0;
    if (update_journal_is_group(record)) {
        for (attempt = 0; attempt < 2 && !ok; ++attempt) {
            if (attempt && !current) break;
            update_journal_forget(journal);
            if (!current || current - (unsigned)attempt == ULLONG_MAX) continue;
            ok = read_update_group_journal(record, current - (unsigned)attempt, journal);
        }
        free(record);
        return ok;
    }
    for (attempt = 0; attempt < 2 && !ok; ++attempt) {
        if (attempt && !current) break;
        journal->generation = current - (unsigned)attempt;
        free(line);
        line = NULL;
        capacity = 0;
        number = 0;
        version = 0;
        if (journal->generation == ULLONG_MAX) continue;
        {
            FILE *stream = fmemopen(record, strlen(record), "r");
            ssize_t got;
            if (!stream) break;
            while ((got = getline(&line, &capacity, stream)) >= 0) {
                char *end;
                if (++number > 4 + 65536 || got < 2 || line[got - 1] != '\n' ||
                    memchr(line, 0, (size_t)got)) break;
                line[got - 1] = 0;
                if (number == 1) {
                    if (sscanf(line, "format holy-update-journal-%d", &version) != 1 ||
                        version < 1 || version > 6) break;
                    continue;
                }
                if (number == 2) {
                    unsigned long long stated;
                    errno = 0;
                    stated = strtoull(line + 11, &end, 10);
                    if (strncmp(line, "generation ", 11) || errno || *end ||
                        stated == ULLONG_MAX) break;
                    journal->generation = stated;
                    continue;
                }
                if (number == 3 && !strncmp(line, "old ", 4) && strlen(line) == 68) {
                    memcpy(journal->old, line + 4, 65);
                    continue;
                }
                if (number == 4 && !strncmp(line, "new ", 4) && strlen(line) == 68) {
                    memcpy(journal->next, line + 4, 65);
                    continue;
                }
                if (number == 5 && !strncmp(line, "plan ", 5) && strlen(line) == 69) {
                    memcpy(journal->plan, line + 5, 65);
                    continue;
                }
                if (!journal->phase[0] && version >= 2 && !strncmp(line, "phase ", 6) &&
                    strlen(line) <= 22) {
                    memcpy(journal->phase, line + 6, strlen(line + 6) + 1);
                    if (!update_phase_valid(journal->phase)) break;
                    continue;
                }
                if (version >= 3 && !journal->arch_decision &&
                    !strncmp(line, "accept-arch ", 12) && strlen(line) == 76 &&
                    !memcmp(line + 12, journal->next, 64)) {
                    journal->arch_decision = 1;
                    continue;
                }
                if (version >= 2 && !journal->priv_decision &&
                    !strncmp(line, "accept-privileged ", 18) && strlen(line) == 82 &&
                    !memcmp(line + 18, journal->next, 64)) {
                    journal->priv_decision = 1;
                    continue;
                }
                if (version >= 5 && !strncmp(line, "service ", 8)) {
                    char **next;
                    size_t i;
                    if (!holy_unit_name_valid(line + 8)) break;
                    for (i = 0; i < journal->service_count; ++i)
                        if (!strcmp(line + 8, journal->services[i])) break;
                    if (i != journal->service_count) break;
                    if (journal->service_count >= 65536) break;
                    next = realloc(journal->services,
                                   (journal->service_count + 1) * sizeof *next);
                    if (!next) break;
                    journal->services = next;
                    next[journal->service_count] = strdup(line + 8);
                    if (!next[journal->service_count]) break;
                    ++journal->service_count;
                    continue;
                }
                break;
            }
            fclose(stream);
        }
        /* the generation is the one this root can still be in: the recorded one, or
           the one before it for an operation that had already published */
        /* each version states exactly which decisions it carries, so a journal cannot
           claim one it does not hold */
        ok = version >= 1 && number >= 5 && valid_digest(journal->old) &&
             valid_digest(journal->next) && valid_digest(journal->plan) &&
             strcmp(journal->old, journal->next) &&
             journal->generation == current - (unsigned)attempt &&
             /* a journal that states a phase is one version above the journal with the
                same decisions, so the version and the decisions have to agree */
             (journal->phase[0] ?
              (version == 2 ? !journal->arch_decision && !journal->priv_decision &&
                               !journal->service_count :
               version == 3 ? !journal->arch_decision && journal->priv_decision &&
                               !journal->service_count :
               version == 4 ? journal->arch_decision && !journal->priv_decision &&
                               !journal->service_count :
               version == 5 ? journal->arch_decision && journal->priv_decision &&
                               !journal->service_count :
               version == 6 && journal->service_count != 0) &&
               update_phase_valid(journal->phase) :
              version <= 1 ? !journal->arch_decision && !journal->priv_decision &&
                              !journal->service_count :
              version <= 2 ? !journal->arch_decision && journal->priv_decision &&
                              !journal->service_count :
              version <= 3 ? journal->arch_decision && !journal->priv_decision &&
                              !journal->service_count :
              version <= 4 ? journal->arch_decision && journal->priv_decision &&
                              !journal->service_count :
              journal->service_count != 0);
        if (ok) {
            /* the single slot this journal names is the one pair every caller works
               with, whatever the journal version is */
            journal->olds = calloc(1, sizeof *journal->olds);
            journal->news = calloc(1, sizeof *journal->news);
            journal->architecture = calloc(1, sizeof *journal->architecture);
            journal->privileged = calloc(1, sizeof *journal->privileged);
            if (!journal->olds || !journal->news || !journal->architecture ||
                !journal->privileged) ok = 0;
            else {
                memcpy(journal->olds[0], journal->old, 65);
                memcpy(journal->news[0], journal->next, 65);
                journal->architecture[0] = journal->arch_decision;
                journal->privileged[0] = journal->priv_decision;
                journal->pair_count = 1;
            }
        }
        if (!ok) update_journal_forget(journal);
    }
    free(line);
    free(record);
    return ok;
}

static int instance_graph(const struct holy_resolution *full, const char *digest,
                           char **record, size_t *length)
{
    struct holy_resolution part = {0};
    size_t i, j, count = 1;
    int ok = 0;
    memcpy(part.root, digest, 65);
    part.artifacts = calloc(full->artifact_count, sizeof *part.artifacts);
    part.edges = calloc(full->edge_count ? full->edge_count : 1, sizeof *part.edges);
    if (!part.artifacts || !part.edges) goto done;
    part.artifacts[0] = (char *)digest;
    for (i = 0; i < full->edge_count; ++i) if (!strcmp(full->edges[i].consumer, digest)) {
        part.edges[part.edge_count++] = full->edges[i];
        for (j = 0; j < count; ++j)
            if (!strcmp(part.artifacts[j], full->edges[i].provider)) break;
        if (j == count) {
            if (count == full->artifact_count) goto done;
            part.artifacts[count++] = full->edges[i].provider;
        }
    }
    part.artifact_count = count;
    qsort(part.artifacts, count, sizeof *part.artifacts, compare_instance_names);
    ok = holy_resolution_record(&part, record, length);
done:
    free(part.artifacts); free(part.edges);
    return ok;
}

static int clear_update_installed(int parent, const struct holy_resolution *resolution)
{
    static const char *const files[] = {"meta", "files", "deps", "origin", "graph", "state", "source", "provides", "hooks", "transform", "hooks-state", "package-files", "config-state"};
    int installed = child_dir(parent, "installed", 1), item = -1, ok = 0;
    DIR *list = NULL, *members = NULL;
    struct dirent *entry;
    size_t i;
    if (installed < 0 || !(list = directory_stream(installed))) goto done;
    errno = 0;
    while ((entry = readdir(list))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        for (i = 0; i < resolution->artifact_count; ++i)
            if (!strcmp(entry->d_name, resolution->artifacts[i])) break;
        if (i == resolution->artifact_count || (item = child_dir(installed, entry->d_name, 0)) < 0 ||
            !(members = directory_stream(item))) goto done;
        errno = 0;
        for (;;) {
            struct stat st;
            struct dirent *member = readdir(members);
            if (!member) { if (errno) goto done; break; }
            if (!strcmp(member->d_name, ".") || !strcmp(member->d_name, "..")) continue;
            for (i = 0; i < sizeof files / sizeof *files; ++i)
                if (!strcmp(member->d_name, files[i])) break;
            if (i == sizeof files / sizeof *files || fstatat(item, member->d_name, &st, AT_SYMLINK_NOFOLLOW) ||
                !S_ISREG(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 0022)) goto done;
            errno = 0;
        }
        closedir(members); members = NULL;
        for (i = 0; i < sizeof files / sizeof *files; ++i)
            if (unlinkat(item, files[i], 0) && errno != ENOENT) goto done;
        if (fsync(item)) goto done;
        close(item); item = -1;
        if (unlinkat(installed, entry->d_name, AT_REMOVEDIR) || fsync(installed)) goto done;
        errno = 0;
    }
    ok = errno == 0;
done:
    if (members) closedir(members);
    if (list) closedir(list);
    if (item >= 0) close(item);
    if (installed >= 0) close(installed);
    return ok;
}

static int update_config_manifest(int old_item, int proposed,
                                  const struct holy_file_plan *plan,
                                  const char *digest, const char *transaction,
                                  int replaced)
{
    char *raw = NULL, *installed = NULL, *state = NULL;
    char raw_hash[65], installed_hash[65], record[360];
    size_t length = 0, i;
    int transformed = 0, result = 0;
    if (replaced) {
        for (i = 0; i < plan->count; ++i)
            if (plan->changes[i].keep_config) { transformed = 1; break; }
    } else {
        struct stat st;
        transformed = !fstatat(old_item, "config-state", &st, AT_SYMLINK_NOFOLLOW);
        if (!transformed && errno != ENOENT) return 0;
    }
    if (!transformed) return 1;
    raw = update_record(proposed, "files");
    if (!raw || !instance_record_digest(proposed, "files", raw_hash)) goto done;
    if (replaced) {
        if (!holy_file_plan_installed_manifest(plan, raw, strlen(raw),
                                               &installed, &length)) goto done;
    } else {
        char previous_hash[65];
        if (!config_state_valid(old_item, digest) ||
            !instance_record_digest(old_item, "package-files", previous_hash) ||
            strcmp(previous_hash, raw_hash)) goto done;
        installed = update_record(old_item, "files");
        state = update_record(old_item, "config-state");
        if (!installed || !state) goto done;
        length = strlen(installed);
    }
    if (renameat(proposed, "files", proposed, "package-files") || fsync(proposed) ||
        !record_file(proposed, "files", installed, length) ||
        !instance_record_digest(proposed, "files", installed_hash)) goto done;
    if (replaced) {
        int written = snprintf(record, sizeof record,
            "format holy-config-transform-1\nsource %s\nraw %s\ninstalled %s\nplan %s\n",
            digest, raw_hash, installed_hash, transaction);
        if (written < 0 || (size_t)written >= sizeof record ||
            !record_file(proposed, "config-state", record, (size_t)written)) goto done;
    } else if (!record_file(proposed, "config-state", state, strlen(state))) goto done;
    result = config_state_valid(proposed, digest);
done:
    free(raw); free(installed); free(state);
    return result;
}

/* the slots one update transaction replaces, each with the file plan and the decisions
   its new artifact needs, so a group of replacements is one transaction */
struct update_slot {
    size_t index;                 /* the installed index of the artifact it replaces */
    char old[65], next[65];
    char source[65];              /* the source id the slot is installed from */
    char *source_record;          /* the source line the plan carries for it */
    char target[96];              /* host and target when the arch decision was made */
    int architecture, privileged, was_privileged;
    char *old_snapshot;           /* the snapshot path its file plan needs */
    struct holy_file_plan changes;
    char *file_record;            /* its file plan as the plan body carries it */
    size_t file_size;
};

static struct update_slot *update_slot_of(struct update_slot *slots, size_t count,
                                          size_t index)
{
    size_t i;
    for (i = 0; i < count; ++i) if (slots[i].index == index) return &slots[i];
    return NULL;
}

static void update_slots_free(struct update_slot *slots, size_t count)
{
    size_t i;
    if (!slots) return;
    for (i = 0; i < count; ++i) {
        free(slots[i].source_record);
        free(slots[i].file_record);
        if (slots[i].old_snapshot) { unlink(slots[i].old_snapshot); free(slots[i].old_snapshot); }
        holy_file_plan_free(&slots[i].changes);
    }
    free(slots);
}

static int update_instances(int next_db, int before, char **names, char **snapshots,
                            size_t count, struct update_slot *slots, size_t slot_count,
                            unsigned long long generation,
                            const struct holy_resolution *resolution,
                            const char *transaction, int create)
{
    int installed = -1, item = -1, proposed = -1, ok = 0;
    char *source = NULL, *graph = NULL;
    size_t i, length = 0;
    if (create && !clear_update_installed(next_db, resolution)) return 0;
    installed = child_dir(next_db, "installed", 0);
    if (installed < 0) goto done;
    for (i = 0; i < count; ++i) {
        struct update_slot *slot = update_slot_of(slots, slot_count, i);
        const char *digest = slot ? slot->next : names[i], *reason;
        /* the instance keeps the source record the plan carries, not its id alone */
        const char *new_source = slot && slot->source_record ? slot->source_record : NULL;
        unsigned long long recorded;
        char expected[65], actual[65], architecture[96];
        unsigned char hash[32];
        unsigned hash_size;
        size_t j;
        item = child_dir(before, names[i], 0);
        if (item < 0) goto done;
        if (!instance_architecture(item, architecture)) goto done;
        if (slot) {
            if (slot->architecture && !architecture_valid(slot->target)) goto done;
            snprintf(architecture, sizeof architecture, "%s", slot->target);
        }
        reason = instance_reason_matches(item, "dependency") ? "dependency" : "explicit";
        if (new_source) source = strdup(new_source);
        else source = update_record(item, "source");
        if (!source && (new_source || errno != ENOENT)) goto done;
        if (!instance_graph(resolution, digest, &graph, &length)) goto done;
        if (create) {
            char *state_record = update_record(item, "state");
            int privileged;
            if (!state_record) goto done;
            privileged = slot ? slot->privileged :
                         strstr(state_record, "\nprivileged ") != NULL;
            free(state_record);
            if (!save_instance(installed, digest, snapshots[i], generation, graph, length,
                               reason, source, architecture[0] ? architecture : NULL,
                               privileged, 0)) goto done;
        }
        proposed = child_dir(installed, digest, 0);
        if (proposed >= 0 && create &&
            !update_config_manifest(item, proposed, slot ? &slot->changes : NULL,
                                    digest, transaction, !!slot)) goto done;
        if (proposed < 0 || !instance_state_generation(proposed, digest, &recorded) || recorded != generation + 1 ||
            !instance_reason_matches(proposed, reason) || !instance_source_matches(proposed, source) ||
            !instance_architecture_matches(proposed, architecture) ||
            !instance_matches_snapshot(proposed, snapshots[i]) || !graph_digest(proposed, actual) ||
            EVP_Digest(graph, length, hash, &hash_size, EVP_sha256(), NULL) != 1 || hash_size != 32) goto done;
        if (slot) {
            char marker[96], *state_record = update_record(proposed, "state");
            int observed_privileged;
            if (!state_record) goto done;
            snprintf(marker, sizeof marker, "\nprivileged %s\n", digest);
            observed_privileged = strstr(state_record, marker) != NULL;
            free(state_record);
            if (observed_privileged != slot->privileged) goto done;
        }
        for (j = 0; j < 32; ++j) snprintf(expected + j * 2, 3, "%02x", hash[j]);
        if (strcmp(expected, actual)) goto done;
        free(source); source = NULL; free(graph); graph = NULL;
        close(item); item = -1; close(proposed); proposed = -1;
    }
    {
        DIR *list = directory_stream(installed);
        struct dirent *entry;
        size_t found = 0;
        if (!list) goto done;
        errno = 0;
        while ((entry = readdir(list))) {
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
            for (i = 0; i < resolution->artifact_count; ++i)
                if (!strcmp(entry->d_name, resolution->artifacts[i])) break;
            if (i == resolution->artifact_count) break;
            ++found; errno = 0;
        }
        ok = !entry && !errno && found == count;
        closedir(list);
    }
    ok = ok && installed_valid(next_db) && !fsync(installed);
done:
    free(source); free(graph);
    if (item >= 0) close(item);
    if (proposed >= 0) close(proposed);
    if (installed >= 0) close(installed);
    return ok;
}

struct update_progress {
    int work;
    const struct holy_file_plan *files;
};

static int update_exchange_available(int work)
{
    int a = child_dir(work, "exchange-a", 1), b = child_dir(work, "exchange-b", 1), ok = 0;
    if (a < 0 || b < 0) goto done;
#ifdef SYS_renameat2
    if (syscall(SYS_renameat2, work, "exchange-a", work, "exchange-b", 2u)) {
        fputs("holypkg: renameat2(RENAME_EXCHANGE) unavailable for installed database\n", stderr);
        goto done;
    }
    ok = !fsync(work) && !unlinkat(work, "exchange-a", AT_REMOVEDIR) &&
         !unlinkat(work, "exchange-b", AT_REMOVEDIR) && !fsync(work);
#else
    fputs("holypkg: renameat2(RENAME_EXCHANGE) unavailable\n", stderr);
#endif
done:
    if (a >= 0) close(a);
    if (b >= 0) close(b);
    return ok;
}

static int update_progress(void *context, size_t index, int completed)
{
    struct update_progress *p = context;
    char record[160];
    snprintf(record, sizeof record, "stage applying\nchange %s\nresult %s\n",
             p->files->changes[index].id, completed ? "done" : "intent");
    return update_replace(p->work, "progress", record);
}

static int finish_update(int root, int db, int transactions, int work, int before,
                         char **names, char **snapshots, size_t count,
                         struct update_slot *slots, size_t slot_count,
                         const struct update_journal *journal,
                         const struct holy_resolution *resolution,
                         int resume, int swapped, unsigned long long current)
{
    int next_db = -1, result = 5;
    size_t failed = 0, k;
    char committed[66];
    struct update_progress progress = {work, NULL};
    struct stat expected, observed;
    next_db = child_dir(work, "next-db", !swapped);
    if (next_db < 0) goto done;
    if (!swapped) {
        if (current != journal->generation || !update_exchange_available(work) ||
            !update_instances(next_db, before, names, snapshots, count, slots, slot_count,
                              journal->generation, resolution, journal->plan, 1) ||
            !update_journal_phase(work, update_phases[0]) ||
            !update_replace(work, "progress", "stage prepared\n")) goto done;
        /* the plans name disjoint paths, so each slot stages and applies its own */
        for (k = 0; k < slot_count; ++k) {
            progress.files = &slots[k].changes;
            /* the plan stages from the new archive, which is what the slot carries */
            if (holy_file_plan_stage(&slots[k].changes, snapshots[slots[k].index], root,
                                     resume, &failed) ||
                holy_file_plan_apply(&slots[k].changes, root, update_progress,
                                     &progress, &failed)) {
                fprintf(stderr, "holypkg: incomplete update at file change %zu; inspect reserved staging objects\n", failed);
                goto done;
            }
        }
        if (!update_journal_phase(work, update_phases[1])) goto done;
        if (fstat(before, &expected) || fstatat(db, "installed", &observed, AT_SYMLINK_NOFOLLOW) ||
            expected.st_dev != observed.st_dev || expected.st_ino != observed.st_ino ||
            !update_replace(work, "progress", "stage publishing\n")) goto done;
#ifdef SYS_renameat2
        if (syscall(SYS_renameat2, db, "installed", next_db, "installed", 2u)) {
            if (errno == ENOSYS || errno == EINVAL || errno == EOPNOTSUPP)
                fputs("holypkg: renameat2(RENAME_EXCHANGE) unavailable; update remains incomplete\n", stderr);
            goto done;
        }
        if (!update_journal_phase(work, update_phases[2])) goto done;
#else
        fputs("holypkg: renameat2(RENAME_EXCHANGE) unavailable; update remains incomplete\n", stderr);
        goto done;
#endif
    }
    if (fsync(next_db) || fsync(db)) goto done;
    for (k = 0; k < slot_count; ++k)
        if (holy_file_plan_finished(&slots[k].changes, root)) goto done;
    if (!update_instances(db, before, names, snapshots, count, slots, slot_count,
                          journal->generation, resolution, journal->plan, 0) ||
        (current == journal->generation && !set_generation(db, journal->generation + 1)) || fsync(db) ||
        !update_journal_phase(work, update_phases[3])) goto done;
    snprintf(committed, sizeof committed, "%s\n", journal->plan);
    for (k = 0; k < slot_count; ++k)
        if (holy_file_plan_cleanup(&slots[k].changes, root)) goto done;
    if (!update_replace(work, "progress", "stage committed\n") ||
        !update_journal_phase(work, update_phases[4]) ||
        !update_replace(work, "committed", committed)) goto done;
#ifdef SYS_renameat2
    if (syscall(SYS_renameat2, transactions, "update", transactions, journal->plan, 1u) || fsync(transactions)) goto done;
#else
    goto done;
#endif
    for (k = 0; k < slot_count; ++k)
        printf("updated %s to %s generation %llu plan %s\n", slots[k].old, slots[k].next,
               journal->generation + 1, journal->plan);
    if (slot_count > 1)
        printf("updated-group slots %zu generation %llu plan %s\n", slot_count,
               journal->generation + 1, journal->plan);
    result = 0;
done:
    if (next_db >= 0) close(next_db);
    return result;
}

/* a decision names one artifact of the group, and an artifact one decision */
static int accepted_pair(const char *const *accepted, size_t count, const char *digest)
{
    size_t i;
    for (i = 0; i < count; ++i) if (!strcmp(accepted[i], digest)) return 1;
    return 0;
}

/* one replacement transaction over the group of slots a request names. every slot is
   checked, staged and published inside one journal, one database swap and one
   generation, so a group is one decision rather than several */
static int state_update_group(const struct holy_update_request *request,
                              const char *expected, const char *root_path, int resume,
                              char prepared_hash[65], char **prepared_record)
{
    int root = -1, dir = -1, installed = -1, item = -1, files = -1, result = 1, pending;
    int transactions = -1, work = -1, old_db = -1, reference_db = -1, swapped = 0, journaled = 0;
    int registry_known = 0;
    struct update_journal journal = {0};
    struct update_slot *slots = NULL;
    size_t pair_count = 0, k, count = 0, i, graph_size = 0, record_size = 0, failed;
    int record_failed = 0;
    const char *const *olds = NULL, *const *news = NULL, **owned_olds = NULL, **owned_news = NULL;
    const char *const *accept_arch = NULL, *const *accept_privileged = NULL;
    const char *const *accept_service = NULL, **owned_arch = NULL, **owned_privileged = NULL;
    size_t arch_count = 0, privileged_count = 0, service_count = 0;
    char *saved = NULL, *graph_record = NULL, *record = NULL;
    char **names = NULL, **snapshots = NULL, **states = NULL;
    const char **selected_ids = NULL;
    char registry[65], existing[65], approved[65], checksum[65];
    unsigned long long generation = 0, recorded, current_generation;
    struct stat root_st, db_st;
    struct holy_resolution resolution = {0};
    struct install_set claims = {0};
    struct service_list services = {0};
    struct holy_override_record_info *override_records = NULL;
    size_t override_record_count = 0;
    struct plan_hash validation = {0};
    DIR *list = NULL;
    struct dirent *entry;
    FILE *out = NULL;
    unsigned char bytes[32];
    unsigned length;
    if (prepared_record) *prepared_record = NULL;
    if (prepared_hash) prepared_hash[0] = 0;
    /* a resume names no pairs of its own: the journal it recovers holds them */
    if (resume && request) return 2;
    if (!resume) {
        if (!request || !request->olds || !request->news) return 2;
        olds = request->olds;
        news = request->news;
        pair_count = request->pair_count;
        accept_arch = request->accept_arch;
        arch_count = request->arch_count;
        accept_privileged = request->accept_privileged;
        privileged_count = request->privileged_count;
        accept_service = request->accept_service;
        service_count = request->service_count;
    }
    for (i = 0; i < service_count; ++i) {
        size_t j;
        if (!holy_unit_name_valid(accept_service[i])) return 2;
        for (j = 0; j < i; ++j)
            if (!strcmp(accept_service[i], accept_service[j])) return 2;
    }
    if (!resume) {
        if (!pair_count || pair_count > 4096 || (expected && !valid_digest(expected)))
            return 2;
        for (k = 0; k < pair_count; ++k) {
            size_t j;
            if (!valid_digest(olds[k]) || !valid_digest(news[k])) return 2;
            /* a slot that replaces itself is a decision, not a malformed pair */
            if (!strcmp(olds[k], news[k])) return 3;
            /* one slot per installed artifact, and no slot takes another slot's old
               artifact as its new one */
            for (j = 0; j < k; ++j)
                if (!strcmp(olds[k], olds[j]) || !strcmp(news[k], news[j]) ||
                    !strcmp(news[k], olds[j])) return 2;
        }
        /* a decision names one artifact of the group, and that artifact once */
        for (i = 0; i < arch_count; ++i) {
            size_t j;
            if (!valid_digest(accept_arch[i])) return 2;
            for (k = 0; k < pair_count; ++k) if (!strcmp(accept_arch[i], news[k])) break;
            if (k == pair_count) return 2;
            for (j = 0; j < i; ++j) if (!strcmp(accept_arch[i], accept_arch[j])) return 2;
        }
        for (i = 0; i < privileged_count; ++i) {
            size_t j;
            if (!valid_digest(accept_privileged[i])) return 2;
            for (k = 0; k < pair_count; ++k) if (!strcmp(accept_privileged[i], news[k])) break;
            if (k == pair_count) return 2;
            for (j = 0; j < i; ++j)
                if (!strcmp(accept_privileged[i], accept_privileged[j])) return 2;
        }
    }
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    /* the override store is read before the lock, since the plan binds what it says and
       the read must not wait for a lock this call takes */
    if (root >= 0 && holy_override_records(root_path, &override_records,
                                           &override_record_count)) goto done;
    if (root < 0 || fstat(root, &root_st) || (dir = state_dir_at(root, 0)) < 0 ||
        flock(dir, expected || resume ? LOCK_EX : LOCK_SH) || fstat(dir, &db_st) ||
        !state_layout(dir, 0) || !read_generation(dir, &generation)) goto done;
    current_generation = generation;
    reference_db = dir;
    if (resume) {
        struct stat a, b;
        int live, pair_swapped = 0;
        result = 6;
        transactions = child_dir(dir, "transactions", 0);
        work = transactions < 0 ? -1 : child_dir(transactions, "update", 0);
        if (work < 0) goto done;
        journaled = 1; result = 5;
        if (!read_update_journal(work, generation, &journal) || !journal.pair_count) goto done;
        /* the journal states the phase the transaction proved, so the recovery names it
           rather than leaving the operator to read the record */
        if (journal.phase[0]) printf("resumed-phase %s\n", journal.phase);
        pair_count = journal.pair_count;
        owned_olds = calloc(pair_count, sizeof *owned_olds);
        owned_news = calloc(pair_count, sizeof *owned_news);
        owned_arch = calloc(pair_count, sizeof *owned_arch);
        owned_privileged = calloc(pair_count, sizeof *owned_privileged);
        if (!owned_olds || !owned_news || !owned_arch || !owned_privileged) goto done;
        for (k = 0; k < pair_count; ++k) {
            owned_olds[k] = journal.olds[k];
            owned_news[k] = journal.news[k];
            if (journal.architecture[k]) accept_arch = NULL;   /* rebuilt below */
        }
        olds = (const char *const *)owned_olds;
        news = (const char *const *)owned_news;
        arch_count = privileged_count = 0;
        for (k = 0; k < pair_count; ++k) {
            if (journal.architecture[k]) owned_arch[arch_count++] = news[k];
            if (journal.privileged[k]) owned_privileged[privileged_count++] = news[k];
        }
        accept_arch = (const char *const *)owned_arch;
        accept_privileged = (const char *const *)owned_privileged;
        expected = journal.plan;
        accept_service = (const char *const *)journal.services;
        service_count = journal.service_count;
        generation = journal.generation;
        saved = update_record(work, "plan");
        if (!saved && errno != ENOENT) goto done;
        live = child_dir(dir, "installed", 0);
        if (live < 0) goto done;
        /* the swap publishes every slot at once, so the slots agree on it */
        for (k = 0; k < pair_count; ++k) {
            int old_present = !fstatat(live, olds[k], &a, AT_SYMLINK_NOFOLLOW);
            int new_present = !fstatat(live, news[k], &b, AT_SYMLINK_NOFOLLOW);
            if (old_present == new_present) { close(live); goto done; }
            if (!k) pair_swapped = new_present;
            else if (new_present != pair_swapped) { close(live); goto done; }
        }
        close(live);
        swapped = pair_swapped;
        /* a journal that states a phase has to agree with the database it left: a
           swapped phase without the exchange, or an unswapped one with it, means the
           journal describes another operation */
        if (journal.phase[0] && (strcmp(journal.phase, "swapped") &&
                                 strcmp(journal.phase, "generation") &&
                                 strcmp(journal.phase, "committed")) == swapped) {
            fputs("holypkg: update phase does not match the installed database\n", stderr);
            goto done;
        }
        if (swapped) {
            old_db = child_dir(work, "next-db", 0);
            if (old_db < 0) goto done;
            reference_db = old_db;
        } else if (current_generation != generation) goto done;
    } else {
        pending = transaction_pending(dir, generation);
        if (pending < 0) goto done;
        if (pending) { result = 5; goto done; }
        pending = pending_child(dir, generation, existing, approved);
        if (pending < 0) goto done;
        if (pending) { result = 5; goto done; }
    }
    result = 1;
    if (!installed_valid(reference_db) || (installed = child_dir(reference_db, "installed", 0)) < 0 ||
        !(list = directory_stream(installed))) goto done;
    names = calloc(10000, sizeof *names);
    snapshots = calloc(10000, sizeof *snapshots);
    states = calloc(10000, sizeof *states);
    slots = calloc(pair_count ? pair_count : 1, sizeof *slots);
    if (!names || !snapshots || !states || !slots) goto done;
    errno = 0;
    while ((entry = readdir(list))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (count == 10000) { result = 6; goto done; }
        names[count] = strdup(entry->d_name);
        if (!names[count]) goto done;
        ++count;
        errno = 0;
    }
    if (errno) goto done;
    if (count) qsort(names, count, sizeof *names, compare_instance_names);
    /* every slot resolves to one installed artifact */
    for (k = 0; k < pair_count; ++k) {
        size_t index;
        for (index = 0; index < count; ++index)
            if (!strcmp(names[index], olds[k])) break;
        if (index == count) { result = 6; goto done; }
        slots[k].index = index;
        memcpy(slots[k].old, olds[k], 65);
        memcpy(slots[k].next, news[k], 65);
        strcpy(slots[k].source, "-");
    }
    /* a new artifact that is installed under any name is a conflict, not a replacement */
    for (k = 0; k < pair_count; ++k)
        for (i = 0; i < count; ++i)
            if (!strcmp(names[i], slots[k].next)) { result = 4; goto done; }
    for (i = 0; i < count; ++i) {
        struct update_slot *slot = update_slot_of(slots, pair_count, i);
        char state[65], architecture[96];
        snapshots[i] = holy_cache_snapshot(names[i], root_path);
        if (!snapshots[i]) { result = 6; goto done; }
        item = child_dir(installed, names[i], 0);
        if (item < 0) goto done;
        if (!instance_architecture(item, architecture)) goto done;
        files = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        if (files < 0 || !instance_state_generation(item, names[i], &recorded) ||
            recorded > generation || !instance_matches_snapshot(item, snapshots[i]) ||
            !instance_record_digest(item, "state", state)) goto done;
        if (slot) {
            char *state_record = update_record(item, "state");
            if (!state_record) goto done;
            slot->was_privileged = strstr(state_record, "\nprivileged ") != NULL;
            free(state_record);
            if (!installed_source_id(item, slot->source)) goto done;
        }
        states[i] = strdup(state);
        if (!states[i]) goto done;
        if (exclusive_claims(installed, names[i], files) != 1 ||
            ((!resume || !slot) &&
             (slot ? holy_install_check_manifest_except_configs(files, root) :
                    holy_install_check_manifest(files, root)) != 1) ||
            (!resume && check_graph(installed, root, names[i], NULL) != 1)) { result = 4; goto done; }
        close(files); files = -1;
        close(item); item = -1;
    }
    strcpy(registry, "-");
    for (k = 0; k < pair_count; ++k) {
        char digest[65];
        if (!strcmp(slots[k].source, "-")) continue;
        result = holy_source_record(dir, slots[k].source, &slots[k].source_record, digest);
        if (result) goto done;
        if (!registry_known) { memcpy(registry, digest, 65); registry_known = 1; }
    }
    validation.hash = EVP_MD_CTX_new();
    result = 6;
    if (!validation.hash) goto done;
    for (k = 0; k < pair_count; ++k) {
        struct holy_package_identity old = {0}, next = {0};
        struct utsname host;
        struct privileged_scan scan = {0};
        char *new_snapshot = NULL;
        int scanned, privileged_accepted, architecture_accepted;
        result = 6;
        slots[k].old_snapshot = strdup(snapshots[slots[k].index]);
        if (!slots[k].old_snapshot) goto done;
        new_snapshot = holy_cache_snapshot(slots[k].next, root_path);
        if (!new_snapshot || !holy_package_identity(slots[k].old_snapshot, &old) ||
            !holy_package_identity(new_snapshot, &next) ||
            !recorded_transform(new_snapshot) || !instance_preflight(new_snapshot)) goto pair_done;
        if (!same_slot(&old, slots[k].source, &next, slots[k].source)) { result = 4; goto pair_done; }
        scanned = holy_verify_visit(new_snapshot, scan_privileged, &scan);
        if (!scanned) {
            result = scan.unsupported ? 6 : 1;
            free(scan.first);
            goto pair_done;
        }
        slots[k].privileged = scan.count != 0;
        privileged_accepted = accepted_pair(accept_privileged, privileged_count, slots[k].next);
        if (slots[k].privileged && !privileged_accepted) {
            fprintf(stderr, "holypkg: decision-required privileged update artifact=%s path=%s mode=%04o; --accept-privileged %s permits setuid placement\n",
                    slots[k].next, scan.first ? scan.first : "", scan.mode, slots[k].next);
            result = 3;
            free(scan.first);
            goto pair_done;
        }
        free(scan.first);
        if (privileged_accepted && !slots[k].privileged) { result = 2; goto pair_done; }
        result = 6;
        if (uname(&host)) goto pair_done;
        architecture_accepted = accepted_pair(accept_arch, arch_count, slots[k].next);
        if (!native_architecture(host.machine, next.arch)) {
            if (!architecture_accepted) {
                fprintf(stderr, "holypkg: decision-required architecture artifact=%s host=%s target=%s; --accept-arch %s permits placement without proving execution\n",
                        slots[k].next, host.machine, next.arch, slots[k].next);
                result = 3;
                goto pair_done;
            }
            snprintf(slots[k].target, sizeof slots[k].target, "%s %s", host.machine, next.arch);
            if (!architecture_valid(slots[k].target)) { result = 2; goto pair_done; }
            slots[k].architecture = 1;
        } else if (architecture_accepted) {
            result = 2;
            goto pair_done;
        }
        pending = slot_available_except(reference_db, &next, slots[k].source, slots[k].old);
        if (pending != 1) { result = pending < 0 ? 1 : 4; goto pair_done; }
        result = holy_preview_resolved(new_snapshot, root_path, 1, slots[k].privileged, 0);
        if (result) goto pair_done;
        result = explicit_elf_paths(new_snapshot);
        if (result) goto pair_done;
        validation.completed = 1;
        validation.accepted_privileged = slots[k].privileged;
        result = 6;
        if (EVP_DigestInit_ex(validation.hash, EVP_sha256(), NULL) != 1 ||
            !holy_verify_visit(new_snapshot, plan_entry, &validation)) goto pair_done;
        result = 6;
        if (!holy_file_plan_collect(slots[k].old_snapshot, new_snapshot, &slots[k].changes)) goto pair_done;
        result = holy_file_plan_preserve_configs(&slots[k].changes, root, resume ? saved : NULL);
        if (result) goto pair_done;
        result = 6;
        if (!holy_file_plan_record(&slots[k].changes, &slots[k].file_record, &slots[k].file_size))
            goto pair_done;
        slots[k].changes.before_privileged = slots[k].was_privileged;
        slots[k].changes.after_privileged = slots[k].privileged;
        result = holy_file_plan_check(&slots[k].changes, root, resume, &failed);
        if (result) {
            fprintf(stderr, "holypkg: update file preflight failed at change %zu\n", failed);
            goto pair_done;
        }
        result = 0;
        free(snapshots[slots[k].index]);
        snapshots[slots[k].index] = new_snapshot;
        new_snapshot = NULL;
        result = 0;
pair_done:
        if (new_snapshot) { unlink(new_snapshot); free(new_snapshot); }
        holy_package_identity_free(&old);
        holy_package_identity_free(&next);
        if (result) goto done;
    }
    for (i = 0; i < count; ++i)
        if (!holy_verify_visit(snapshots[i], set_claim, &claims)) { result = 6; goto done; }
    for (k = 0; k < pair_count; ++k)
        for (i = 0; i < slots[k].changes.count; ++i)
            if (slots[k].changes.changes[i].keep_config &&
                !set_claim(&claims, slots[k].changes.changes[i].after)) { result = 1; goto done; }
    if (!set_claims_valid(&claims)) { result = 4; goto done; }
    /* one replacement dropping a file another replacement still claims would take the
       file that artifact needs away, which no single-slot check sees */
    for (k = 0; k < pair_count; ++k)
        for (i = 0; i < slots[k].changes.count; ++i) {
            const struct holy_file_change *change = &slots[k].changes.changes[i];
            struct set_claim key = {0};
            if (change->kind != HOLY_REMOVE || !change->before) continue;
            key.path = (char *)change->before->path;
            if (bsearch(&key, claims.claims, claims.claim_count, sizeof *claims.claims,
                        claim_order)) {
                fprintf(stderr, "holypkg: %s drops %s, which the replacement set still claims\n",
                        slots[k].old, change->before->path);
                result = 4;
                goto done;
            }
        }
    result = holy_resolve_collect_set((const char *const *)snapshots, count, &resolution);
    if (result) goto done;
    selected_ids = calloc(count, sizeof *selected_ids);
    if (!selected_ids) { result = 1; goto done; }
    for (i = 0; i < count; ++i) selected_ids[i] = names[i];
    for (k = 0; k < pair_count; ++k) selected_ids[slots[k].index] = slots[k].next;
    if (!selected_soname_paths(&resolution, selected_ids,
                               (const char *const *)snapshots, count, root,
                               claims.claims, claims.claim_count)) {
        result = 3;
        goto done;
    }
    result = 1;
    if (!holy_resolution_record(&resolution, &graph_record, &graph_size)) goto done;
    out = open_memstream(&record, &record_size);
    if (!out) goto done;
    fprintf(out, "[update]\nformat holy-update-plan-%d\ngeneration %llu\n"
            "root %ju %ju\ndatabase %ju %ju\n",
            pair_count > 1 ? 2 : 1, generation,
            (uintmax_t)root_st.st_dev, (uintmax_t)root_st.st_ino,
            (uintmax_t)db_st.st_dev, (uintmax_t)db_st.st_ino);
    if (pair_count > 1) {
        fprintf(out, "replacement %zu\n", pair_count);
        for (k = 0; k < pair_count; ++k)
            fprintf(out, "pair %s %s\n", slots[k].old, slots[k].next);
    } else {
        fprintf(out, "old %s\nnew %s\n", slots[0].old, slots[0].next);
    }
    for (k = 0; k < pair_count; ++k) {
        if (slots[k].architecture)
            fprintf(out, "accept-arch %s\narchitecture %s\n", slots[k].next, slots[k].target);
        if (slots[k].privileged)
            fprintf(out, "accept-privileged %s\n", slots[k].next);
    }
    fprintf(out, "registry %s\n", registry);
    if (!registry_known) fputs("source - local\n", out);
    else
        for (k = 0; k < pair_count; ++k) {
            size_t j;
            if (!slots[k].source_record) continue;
            for (j = 0; j < k; ++j)
                if (!strcmp(slots[j].source_record, slots[k].source_record)) break;
            if (j == k && fputs(slots[k].source_record, out) == EOF) { record_failed = 1; break; }
        }
    fputs("delivery local\n[installed]\n", out);
    for (i = 0; i < count; ++i) fprintf(out, "instance %s %s\n", names[i], states[i]);
    fputs("[files]\n", out);
    for (k = 0; k < pair_count; ++k)
        if (fwrite(slots[k].file_record, 1, slots[k].file_size, out) != slots[k].file_size) {
            record_failed = 1;
            break;
        }
    fputs("[graph]\n", out);
    fwrite(graph_record, 1, graph_size, out);
    fputs("[overrides]\n", out);
    for (i = 0; i < override_record_count; ++i) {
        struct set_claim key = {0};
        key.path = override_records[i].path + 1;
        if (!bsearch(&key, claims.claims, claims.claim_count, sizeof *claims.claims,
                     claim_order)) continue;
        if (fprintf(out, "override %s %s %s %s\n", override_records[i].name,
                    override_records[i].path, override_records[i].file,
                    override_records[i].patch) < 0) { record_failed = 1; break; }
    }
    if (!record_failed)
        for (k = 0; k < pair_count; ++k)
            if (!service_scan(snapshots[slots[k].index], &services, slots[k].next)) {
                result = 6;
                goto done;
            }
    fputs("[services]\n", out);
    for (i = 0; i < services.count; ++i)
        if (fprintf(out, "service %s\n", services.items[i].path) < 0) {
            record_failed = 1;
            break;
        }
    for (i = 0; i < services.count && !record_failed; ++i) {
        const char *unit = service_name_of(services.items[i].path);
        size_t j;
        for (j = 0; j < service_count; ++j)
            if (!strcmp(unit, accept_service[j])) break;
        if (j == service_count) {
            fprintf(stderr, "holypkg: %s ships the service unit /%s; a replacement that"
                            " starts a service needs --accept-service %s\n",
                    services.items[i].artifact, services.items[i].path, unit);
            result = 3;
            goto done;
        }
    }
    pending = ferror(out) || record_failed;
    if (fclose(out)) pending = 1;
    out = NULL;
    if (pending || !same_root(root_path, &root_st) ||
        EVP_Digest(record, record_size, bytes, &length, EVP_sha256(), NULL) != 1 || length != 32)
        goto done;
    for (i = 0; i < 32; ++i) snprintf(checksum + i * 2, 3, "%02x", bytes[i]);
    if (!expected) {
        if (prepared_record) {
            if (prepared_hash) memcpy(prepared_hash, checksum, 65);
            *prepared_record = record;
            record = NULL;
            result = 0;
            goto done;
        }
        if (printf("plan-update sha256 %s read-only\n", checksum) < 0 ||
            fwrite(record, 1, record_size, stdout) != record_size) goto done;
        print_service_list(&services);
        result = ferror(stdout) ? 1 : 0;
        goto done;
    }
    if (strcmp(expected, checksum) || (saved && strcmp(saved, record))) { result = 3; goto done; }
    if (generation == ULLONG_MAX || record_size > 64 * 1024 * 1024) { result = 6; goto done; }
    if (!resume) {
        char *header = NULL;
        size_t header_size = 0;
        FILE *header_stream = open_memstream(&header, &header_size);
        for (k = 0; k < pair_count; ++k) {
            result = holy_file_plan_reservations(&slots[k].changes, root);
            if (result) goto done;
        }
        result = 1;
        transactions = child_dir(dir, "transactions", 0);
        if (transactions < 0 || mkdirat(transactions, "update", 0700)) goto done;
        journaled = 1;
        if (fsync(transactions) || (work = child_dir(transactions, "update", 0)) < 0) goto done;
        journal.generation = generation;
        memcpy(journal.plan, checksum, 65);
        journal.pair_count = pair_count;
        journal.olds = calloc(pair_count ? pair_count : 1, sizeof *journal.olds);
        journal.news = calloc(pair_count ? pair_count : 1, sizeof *journal.news);
        journal.architecture = calloc(pair_count ? pair_count : 1, sizeof *journal.architecture);
        journal.privileged = calloc(pair_count ? pair_count : 1, sizeof *journal.privileged);
        if (!journal.olds || !journal.news || !journal.architecture || !journal.privileged)
            goto done;
        memcpy(journal.old, slots[0].old, 65);
        memcpy(journal.next, slots[0].next, 65);
        for (k = 0; k < pair_count; ++k) {
            memcpy(journal.olds[k], slots[k].old, 65);
            memcpy(journal.news[k], slots[k].next, 65);
            journal.architecture[k] = slots[k].architecture;
            journal.privileged[k] = slots[k].privileged;
        }
        if (!header_stream) goto done;
        /* a journal written by this command states the phase it starts in, which is the
           version above the one that carried the same decisions without it */
        if (pair_count > 1) {
            fprintf(header_stream, "format holy-update-journal-7\ngeneration %llu\n"
                    "replacement %zu\n", generation, pair_count);
            for (k = 0; k < pair_count; ++k)
                fprintf(header_stream, "pair %s %s\n", slots[k].old, slots[k].next);
            for (k = 0; k < pair_count; ++k) {
                if (slots[k].architecture)
                    fprintf(header_stream, "accept-arch %s\n", slots[k].next);
                if (slots[k].privileged)
                    fprintf(header_stream, "accept-privileged %s\n", slots[k].next);
            }
            for (i = 0; i < service_count; ++i)
                fprintf(header_stream, "service %s\n", accept_service[i]);
            fprintf(header_stream, "plan %s\nphase %s\n", checksum, update_phases[0]);
        } else {
            fprintf(header_stream, "format holy-update-journal-%d\ngeneration %llu\nold %s\nnew %s\nplan %s\n",
                    service_count ? 6 : slots[0].architecture ? (slots[0].privileged ? 5 : 4) :
                    (slots[0].privileged ? 3 : 2),
                    generation, slots[0].old, slots[0].next, checksum);
            if (slots[0].architecture)
                fprintf(header_stream, "accept-arch %s\n", slots[0].next);
            if (slots[0].privileged)
                fprintf(header_stream, "accept-privileged %s\n", slots[0].next);
            for (i = 0; i < service_count; ++i)
                fprintf(header_stream, "service %s\n", accept_service[i]);
            fprintf(header_stream, "phase %s\n", update_phases[0]);
        }
        if (ferror(header_stream) || fclose(header_stream) ||
            !update_replace(work, "journal", header)) {
            free(header);
            goto done;
        }
        free(header);
    }
    if (!saved && !update_replace(work, "plan", record)) goto done;
    result = finish_update(root, dir, transactions, work, installed, names, snapshots,
                           count, slots, pair_count, &journal, &resolution,
                           resume, swapped, current_generation);
done:
    if (result) {
        fprintf(stderr, "holypkg: update failed (status %d)%s\n", result, journaled ? "; update journal retained" : "");
        if (journaled) result = 5;
    }
    if (out) fclose(out);
    if (list) closedir(list);
    if (files >= 0) close(files);
    if (item >= 0) close(item);
    if (installed >= 0) close(installed);
    if (old_db >= 0) close(old_db);
    if (work >= 0) close(work);
    if (transactions >= 0) close(transactions);
    free(saved);
    free(owned_olds); free(owned_news); free(owned_arch); free(owned_privileged);
    free(selected_ids);
    if (dir >= 0) close(dir);
    if (root >= 0) close(root);
    for (i = 0; i < count; ++i) {
        free(names[i]);
        if (snapshots && snapshots[i]) { unlink(snapshots[i]); free(snapshots[i]); }
        if (states) free(states[i]);
    }
    free(names); free(snapshots); free(states);
    free(graph_record); free(record);
    update_slots_free(slots, pair_count);
    holy_override_records_free(override_records, override_record_count);
    holy_resolution_free(&resolution); free_set(&claims);
    service_list_free(&services);
    update_journal_forget(&journal);
    EVP_MD_CTX_free(validation.hash);
    return result;
}
int holy_state_update_plan(const struct holy_update_request *request,
                           const char *root_path)
{
    return state_update_group(request, NULL, root_path, 0, NULL, NULL);
}

int holy_state_update_prepare(const struct holy_update_request *request,
                              const char *root_path, char hash[65], char **record)
{
    if (!hash || !record) return 2;
    return state_update_group(request, NULL, root_path, 0, hash, record);
}

int holy_state_apply_update(const char *plan, const struct holy_update_request *request,
                            const char *root_path)
{
    if (!plan || !valid_digest(plan)) return 2;
    return state_update_group(request, plan, root_path, 0, NULL, NULL);
}

int holy_state_recover_update(const char *root_path)
{
    return state_update_group(NULL, NULL, root_path, 1, NULL, NULL);
}

/* the reverse of a committed set: an artifact the set installed comes out, and an
   artifact it removed goes back in from the cache. the review states every operation
   and whether the cache still holds that artifact, since a missing object is what
   makes a reverse incomplete. applying the list is a different command, so this states
   the operations and the hash a reverse plan would need. */
struct rollback_operation {
    char digest[65];
    char name[128];
    char version[96];
    char direction[10];     /* remove or reinstall */
    int available;
};

struct rollback_plan {
    char **members;
    size_t member_count;
    struct rollback_operation *operations;
    size_t count, capacity;
    int failed;
};

static void rollback_plan_free(struct rollback_plan *plan)
{
    size_t i;
    for (i = 0; i < plan->member_count; ++i) free(plan->members[i]);
    free(plan->members);
    free(plan->operations);
    memset(plan, 0, sizeof *plan);
}

/* the line ends at the newline, so a digest is taken by its length rather than by a
   terminator the record does not have there. */
static int rollback_member(void *context, const char *line, size_t length)
{
    struct rollback_plan *plan = context;
    char **grown;
    if (length != 64 || plan->member_count >= 10000) return 0;
    for (size_t i = 0; i < length; ++i)
        if (!((line[i] >= '0' && line[i] <= '9') || (line[i] >= 'a' && line[i] <= 'f')))
            return 0;
    grown = realloc(plan->members, (plan->member_count + 1) * sizeof *grown);
    if (!grown) return 0;
    plan->members = grown;
    plan->members[plan->member_count] = malloc(length + 1);
    if (!plan->members[plan->member_count]) return 0;
    memcpy(plan->members[plan->member_count], line, length);
    plan->members[plan->member_count][length] = 0;
    ++plan->member_count;
    return 1;
}

/* one line of a record, given to the caller with the key that named it and the value
   that follows. a key the caller does not ask about is skipped. */
static int record_each(const char *record, const char *key,
                       int (*take)(void *, const char *, size_t), void *context)
{
    size_t length = strlen(key);
    const char *cursor = record;
    int ok = 1;
    while (*cursor && ok) {
        const char *end = strchr(cursor, '\n');
        size_t used = end ? (size_t)(end - cursor) : strlen(cursor);
        if (used > length && !strncmp(cursor, key, length) && cursor[length] == ' ')
            if (!take(context, cursor + length + 1, used - length - 1)) ok = 0;
        cursor += used + (end ? 1 : 0);
    }
    return ok;
}

static int rollback_installed(void *context, int root, int instance, const char *digest)
{
    struct rollback_plan *plan = context;
    struct rollback_operation *operations;
    size_t i;
    (void)root;
    for (i = 0; i < plan->member_count; ++i)
        if (!strcmp(plan->members[i], digest)) break;
    if (i == plan->member_count) return 0;
    if (plan->count >= 4096) { plan->failed = 1; return 0; }
    if (plan->count == plan->capacity) {
        size_t size = plan->capacity ? plan->capacity * 2 : 16;
        operations = realloc(plan->operations, size * sizeof *operations);
        if (!operations) { plan->failed = 1; return 0; }
        plan->operations = operations;
        plan->capacity = size;
    }
    memset(&plan->operations[plan->count], 0, sizeof plan->operations[plan->count]);
    memcpy(plan->operations[plan->count].digest, digest, 65);
    snprintf(plan->operations[plan->count].direction,
             sizeof plan->operations[plan->count].direction, "remove");
    if (!holy_state_instance_field(instance, "name", plan->operations[plan->count].name,
                                    sizeof plan->operations[plan->count].name) ||
        !holy_state_instance_field(instance, "version", plan->operations[plan->count].version,
                                   sizeof plan->operations[plan->count].version)) {
        plan->failed = 1;
        return 0;
    }
    ++plan->count;
    return 0;
}

struct rollback_decisions {
    char choice[65537];
    char arch[65];
    char privileged[65];
    char **hooks;
    size_t hook_count;
    char **services;
    size_t service_count;
};

static void rollback_decisions_free(struct rollback_decisions *decisions)
{
    size_t i;
    for (i = 0; i < decisions->hook_count; ++i) free(decisions->hooks[i]);
    for (i = 0; i < decisions->service_count; ++i) free(decisions->services[i]);
    free(decisions->hooks);
    free(decisions->services);
    memset(decisions, 0, sizeof *decisions);
}

static int rollback_push(char ***list, size_t *count, const char *value, size_t length)
{
    char **grown = realloc(*list, (*count + 1) * sizeof *grown);
    char *copy;
    if (!grown) return 0;
    *list = grown;
    copy = malloc(length + 1);
    if (!copy) return 0;
    memcpy(copy, value, length);
    copy[length] = 0;
    (*list)[*count] = copy;
    ++*count;
    return 1;
}

static int rollback_digest_line(const char *line, size_t length, size_t key, char out[65])
{
    if (length - key != 64) return 0;
    memcpy(out, line + key, 64);
    out[64] = 0;
    return valid_digest(out);
}

static int rollback_decisions_read(const char *record, struct rollback_decisions *decisions)
{
    const char *cursor = record;
    char value[256];
    snprintf(decisions->choice, sizeof decisions->choice, "-");
    while (*cursor) {
        const char *end = strchr(cursor, '\n');
        size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
        if (length > 7 && !strncmp(cursor, "choice ", 7)) {
            if (length - 7 >= sizeof decisions->choice) return 0;
            memcpy(decisions->choice, cursor + 7, length - 7);
            decisions->choice[length - 7] = 0;
            if (!set_choice_valid(decisions->choice)) return 0;
        } else if (length > 12 && !strncmp(cursor, "accept-arch ", 12)) {
            if (!rollback_digest_line(cursor, length, 12, decisions->arch)) return 0;
        } else if (length > 18 && !strncmp(cursor, "accept-privileged ", 18)) {
            if (!rollback_digest_line(cursor, length, 18, decisions->privileged)) return 0;
        } else if (length > 11 && !strncmp(cursor, "skip-hooks ", 11)) {
            char digest[65];
            if (!rollback_digest_line(cursor, length, 11, digest) ||
                !rollback_push(&decisions->hooks, &decisions->hook_count, digest, 64)) return 0;
        } else if (length > 8 && !strncmp(cursor, "service ", 8)) {
            size_t name = length - 8;
            if (name >= sizeof value) return 0;
            memcpy(value, cursor + 8, name);
            value[name] = 0;
            if (!holy_unit_name_valid(value) ||
                !rollback_push(&decisions->services, &decisions->service_count, value, name))
                return 0;
        }
        cursor += length + (end ? 1 : 0);
    }
    return 1;
}/* the reverse of a set that removed artifacts is an ordinary set transaction with the
   artifacts the record names and the decisions that record holds, so it is planned and
   applied through the same path as any other set. the approval is that plan hash. */
static int rollback_set_review(const char *transaction, char **digests, size_t count,
                               const char *record, const char *root_path)
{
    struct rollback_decisions decisions = {0};
    const char **hooks = NULL, **services = NULL;
    const char *arch, *privileged;
    size_t i;
    char plan[65];
    int result;
    if (!rollback_decisions_read(record, &decisions)) {
        rollback_decisions_free(&decisions);
        fprintf(stderr, "holypkg: %s is not a set record this command can reverse\n",
                transaction);
        return 2;
    }
    for (i = 0; i < decisions.hook_count; ++i) {
        const char **grown = realloc(hooks, (i + 1) * sizeof *grown);
        if (!grown) { free(hooks); rollback_decisions_free(&decisions); return 1; }
        hooks = grown;
        hooks[i] = decisions.hooks[i];
    }
    for (i = 0; i < decisions.service_count; ++i) {
        const char **grown = realloc(services, (i + 1) * sizeof *grown);
        if (!grown) { free(hooks); free(services); rollback_decisions_free(&decisions); return 1; }
        services = grown;
        services[i] = decisions.services[i];
    }
    const char *arch_list[1] = {NULL}, *privileged_list[1] = {NULL};
    arch = decisions.arch[0] ? decisions.arch : NULL;
    privileged = decisions.privileged[0] ? decisions.privileged : NULL;
    arch_list[0] = arch;
    privileged_list[0] = privileged;
    result = holy_state_set((const char *const *)digests, count,
                            strcmp(decisions.choice, "-") ? decisions.choice : NULL,
                            NULL, root_path, NULL, 0,
                            arch_list, arch ? 1 : 0, privileged_list, privileged ? 1 : 0,
                            hooks, decisions.hook_count,
                            services, decisions.service_count, plan);
    free(hooks);
    free(services);
    rollback_decisions_free(&decisions);
    return result;
}

static int rollback_set_apply(const char *transaction, const char *approved,
                              char **digests, size_t count, const char *record,
                              const char *root_path)
{
    struct rollback_decisions decisions = {0};
    const char **hooks = NULL, **services = NULL;
    const char *arch, *privileged;
    size_t i;
    int result;
    if (!rollback_decisions_read(record, &decisions)) {
        rollback_decisions_free(&decisions);
        return 2;
    }
    for (i = 0; i < decisions.hook_count; ++i) {
        const char **grown = realloc(hooks, (i + 1) * sizeof *grown);
        if (!grown) { free(hooks); rollback_decisions_free(&decisions); return 1; }
        hooks = grown;
        hooks[i] = decisions.hooks[i];
    }
    for (i = 0; i < decisions.service_count; ++i) {
        const char **grown = realloc(services, (i + 1) * sizeof *grown);
        if (!grown) { free(hooks); free(services); rollback_decisions_free(&decisions); return 1; }
        services = grown;
        services[i] = decisions.services[i];
    }
    const char *arch_list[1] = {NULL}, *privileged_list[1] = {NULL};
    arch = decisions.arch[0] ? decisions.arch : NULL;
    privileged = decisions.privileged[0] ? decisions.privileged : NULL;
    arch_list[0] = arch;
    privileged_list[0] = privileged;
    result = holy_state_set((const char *const *)digests, count,
                            strcmp(decisions.choice, "-") ? decisions.choice : NULL,
                            approved, root_path, NULL, 0,
                            arch_list, arch ? 1 : 0, privileged_list, privileged ? 1 : 0,
                            hooks, decisions.hook_count,
                            services, decisions.service_count, NULL);
    free(hooks);
    free(services);
    rollback_decisions_free(&decisions);
    if (!result) printf("rollback %s restored %zu artifacts\n", transaction, count);
    return result;
}

/* the hash a removal review is approved with: the transaction, the generation the list
   was read at and every operation in it, so a review made against another state is
   another review. */
static int rollback_set_hash(const char *transaction, unsigned long long generation,
                             const struct rollback_plan *plan, char out[65])
{
    unsigned char digest[32];
    unsigned int length;
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    char line[512];
    size_t i;
    int ok = 0;
    if (!hash || EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1 ||
        !hash_text(hash, "holy-rollback-remove-1") || !hash_text(hash, transaction))
        goto done;
    if (snprintf(line, sizeof line, "generation %llu artifacts %zu\n",
                 generation, plan->count) < 0 || !hash_text(hash, line)) goto done;
    for (i = 0; i < plan->count; ++i) {
        if (snprintf(line, sizeof line, "%s %s %s %s %d\n", plan->operations[i].direction,
                     plan->operations[i].digest, plan->operations[i].name,
                     plan->operations[i].version, plan->operations[i].available) < 0 ||
            !hash_text(hash, line)) goto done;
    }
    if (EVP_DigestFinal_ex(hash, digest, &length) != 1 || length != 32) goto done;
    for (i = 0; i < 32; ++i) snprintf(out + 2 * i, 3, "%02x", digest[i]);
    out[64] = 0;
    ok = 1;
done:
    EVP_MD_CTX_free(hash);
    return ok;
}

static int rollback_set_report(const char *transaction, const char *approved,
                             int accept_broken, const char *root_path)
{
    struct rollback_plan plan = {0};
    unsigned long long generation = 0;
    char *record = NULL, review[65];
    char line[256];
    int root = -1, dir = -1, transactions = -1, child = -1, result = 1;
    size_t j, removed = 0, reinstalled = 0, unavailable = 0;

    if (!valid_digest(transaction)) return 2;
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0 || (dir = state_dir_at(root, 0)) < 0) {
        fputs("holypkg: database unavailable\n", stderr);
        result = 6;
        goto done;
    }
    if (flock(dir, LOCK_SH) || !state_layout(dir, 0) ||
        !read_generation(dir, &generation) || generation == ULLONG_MAX ||
        !installed_valid(dir)) goto done;
    if ((transactions = child_dir(dir, "transactions", 0)) < 0 ||
        (child = child_dir(transactions, transaction, 0)) < 0) { result = 6; goto done; }
    record = update_record(child, "decisions");
    if (!record || strncmp(record, "format holy-set-journal-",
                           sizeof "format holy-set-journal-" - 1) ||
        !record_each(record, "artifact", rollback_member, &plan) || !plan.member_count) {
        fprintf(stderr, "holypkg: %s is not a set transaction\n", transaction);
        result = 2;
        goto done;
    }
    if (holy_state_visit(root_path, rollback_installed, &plan, &generation) || plan.failed) {
        fputs("holypkg: installed set unavailable\n", stderr);
        result = 6;
        goto done;
    }
    /* an artifact this set touched that is not installed any more goes back in, and the
       cache is what says whether it can. */
    for (j = 0; j < plan.member_count; ++j) {
        struct rollback_operation *operation, *operations;
        size_t k;
        for (k = 0; k < plan.count; ++k)
            if (!strcmp(plan.operations[k].digest, plan.members[j])) break;
        if (k < plan.count || plan.count >= 4096) continue;
        operations = realloc(plan.operations, (plan.count + 1) * sizeof *operations);
        if (!operations) { result = 1; goto done; }
        plan.operations = operations;
        plan.capacity = plan.count + 1;
        operation = &plan.operations[plan.count];
        memset(operation, 0, sizeof *operation);
        memcpy(operation->digest, plan.members[j], 65);
        snprintf(operation->direction, sizeof operation->direction, "reinstall");
        operation->available = holy_cache_object(operation->digest, root_path);
        ++plan.count;
    }
    for (j = 0; j < plan.count; ++j) {
        if (!strcmp(plan.operations[j].direction, "remove")) ++removed;
        else { ++reinstalled; if (!plan.operations[j].available) ++unavailable; }
    }
    /* the set transaction takes its own lock, an exclusive one for an apply, so the read
       lock this held is dropped first. the apply re-derives the set plan under that lock
       and compares the approved hash, which is what keeps the two steps one decision. */
    if (child >= 0) { close(child); child = -1; }
    if (transactions >= 0) { close(transactions); transactions = -1; }
    if (dir >= 0) { close(dir); dir = -1; }
    if (root >= 0) { close(root); root = -1; }
    (void)line;
    if (!approved && ferror(stdout)) result = 1;
    if (!rollback_set_hash(transaction, generation, &plan, review)) { result = 1; goto done; }
    if (approved && removed) {
        /* a removal review is approved with its own hash, and the removal runs as one
           grouped transaction that checks every artifact again under its own lock. */
        const char **digests;
        size_t removal_count = 0, k = 0;
        if (strcmp(approved, review)) {
            fprintf(stderr, "holypkg: the prepared removal changed before the apply\n");
            result = 3;
            goto done;
        }
        for (j = 0; j < plan.count; ++j)
            if (!strcmp(plan.operations[j].direction, "remove")) ++removal_count;
        digests = calloc(removal_count, sizeof *digests);
        if (!digests) { result = 1; goto done; }
        for (j = 0; j < plan.count; ++j)
            if (!strcmp(plan.operations[j].direction, "remove"))
                digests[k++] = plan.operations[j].digest;
        result = holy_state_remove_group(digests, removal_count, root_path, accept_broken);
        if (!result) printf("rollback %s removed %zu artifacts\n", transaction, removal_count);
        free(digests);
        goto done;
    }
    if (approved) {
        /* the reinstall direction is approved with the set plan the review printed */
        if (unavailable) {
            fprintf(stderr, "holypkg: %s removed %zu artifacts and the cache holds %zu"
                            " of them\n", transaction, reinstalled,
                    reinstalled - unavailable);
            result = 6;
            goto done;
        }
        result = rollback_set_apply(transaction, approved, plan.members,
                                    plan.member_count, record, root_path);
        goto done;
    }
    printf("rollback-set-plan transaction %s generation %llu remove %zu reinstall %zu"
           " unavailable %zu\n", transaction, generation, removed, reinstalled, unavailable);
    for (j = 0; j < plan.count; ++j)
        printf("rollback-set %s %s %s %s %s %s\n", transaction,
               plan.operations[j].direction, plan.operations[j].digest,
               plan.operations[j].name[0] ? plan.operations[j].name : "-",
               plan.operations[j].version[0] ? plan.operations[j].version : "-",
               !strcmp(plan.operations[j].direction, "remove") ? "installed" :
               plan.operations[j].available ? "cached" : "unavailable");
    if (removed) {
        /* the review is the operation list and the hash under it is its approval */
        printf("rollback-set-sha256 %s read-only\n", review);
        result = ferror(stdout) ? 1 : 0;
        goto done;
    }
    printf("rollback-set-plan is an ordinary set plan for the artifacts it names\n");
    result = rollback_set_review(transaction, plan.members, plan.member_count, record,
                                 root_path);
    goto done;
done:
    free(record);
    if (child >= 0) close(child);
    if (transactions >= 0) close(transactions);
    if (dir >= 0) close(dir);
    if (root >= 0) close(root);
    rollback_plan_free(&plan);
    return result;
}

/* the decisions a retained set journal holds, in the form a set transaction takes them.
   the reverse set needs the same decisions, since it installs the same artifacts. */

int holy_state_rollback(const char *transaction, const char *approved, int accept_broken,
                        const char *const *accepted_arch, size_t arch_count,
                        const char *const *accepted_privileged, size_t privileged_count,
                        const char *const *accepted_service, size_t service_count,
                        const char *root_path)
{
    struct update_journal journal = {0};
    struct holy_update_request request = {0};
    unsigned long long generation;
    unsigned char digest[32];
    unsigned digest_size;
    char computed[65], hash[65], lineage[192], generation_line[64];
    char *committed = NULL, *source_plan = NULL, *installed_section;
    char *record = NULL, *marker = NULL, **reverse_olds = NULL, **reverse_news = NULL;
    int root = -1, db = -1, transactions = -1, work = -1, result = 1, grouped;
    size_t i, k;
    if (!valid_digest(transaction) || (approved && !valid_digest(approved))) return 2;
    for (i = 0; i < arch_count; ++i) if (!valid_digest(accepted_arch[i])) return 2;
    for (i = 0; i < privileged_count; ++i) if (!valid_digest(accepted_privileged[i])) return 2;
    for (i = 0; i < service_count; ++i) {
        size_t j;
        if (!holy_unit_name_valid(accepted_service[i])) return 2;
        for (j = 0; j < i; ++j)
            if (!strcmp(accepted_service[i], accepted_service[j])) return 2;
    }
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0 || (db = state_dir_at(root, 0)) < 0 || flock(db, LOCK_SH) ||
        !state_layout(db, 0) || (transactions = child_dir(db, "transactions", 0)) < 0) {
        fputs("holypkg: database unavailable\n", stderr);
        result = 6;
        goto done;
    }
    if ((work = child_dir(transactions, transaction, 0)) < 0) {
        fprintf(stderr, "holypkg: no transaction %s in this root\n", transaction);
        result = 6;
        goto done;
    }
    committed = update_record(work, "committed");
    source_plan = update_record(work, "plan");
    marker = update_record(work, "journal");
    if (committed && strlen(committed) == 65 && !memcmp(committed, transaction, 64) &&
        committed[64] == '\n' && !source_plan) {
        /* a set keeps no plan document, so its transaction names a set and the review
           is the reverse operation list with the set plan it needs behind it. */
        free(committed); free(source_plan); free(marker);
        close(work); close(transactions); close(db); close(root);
        return rollback_set_report(transaction, approved, accept_broken, root_path);
    }
    if (!committed || strlen(committed) != 65 ||
        memcmp(committed, transaction, 64) || committed[64] != '\n' ||
        !source_plan || !marker ||
        sscanf(marker, "format holy-update-journal-%*d\ngeneration %llu\n", &generation) != 1 ||
        generation == ULLONG_MAX ||
        !read_update_journal(work, generation + 1, &journal) ||
        strcmp(journal.plan, transaction) ||
        EVP_Digest(source_plan, strlen(source_plan), digest, &digest_size,
                   EVP_sha256(), NULL) != 1 || digest_size != 32) {
        result = 2; goto done;
    }
    grouped = journal.pair_count > 1;
    for (i = 0; i < 32; ++i) snprintf(computed + i * 2, 3, "%02x", digest[i]);
    if (strcmp(computed, transaction) ||
        (grouped ? strncmp(source_plan, "[update]\nformat holy-update-plan-2\n",
                           sizeof "[update]\nformat holy-update-plan-2\n" - 1) :
                   strncmp(source_plan, "[update]\nformat holy-update-plan-1\n",
                           sizeof "[update]\nformat holy-update-plan-1\n" - 1))) {
        result = 2; goto done;
    }
    snprintf(generation_line, sizeof generation_line, "\ngeneration %llu\n",
             journal.generation);
    installed_section = strstr(source_plan, "\n[installed]\n");
    if (!installed_section || !strstr(source_plan, generation_line) ||
        strstr(source_plan, generation_line) >= installed_section) {
        result = 2; goto done;
    }
    /* every slot the plan replaced is named in its header, before the installed list */
    for (k = 0; k < journal.pair_count; ++k) {
        char *named;
        if (grouped)
            snprintf(lineage, sizeof lineage, "\npair %s %s\n", journal.olds[k], journal.news[k]);
        else
            snprintf(lineage, sizeof lineage, "\nold %s\nnew %s\n", journal.old, journal.next);
        named = strstr(source_plan, lineage);
        if (!named || named >= installed_section) { result = 2; goto done; }
    }
    /* the reverse replaces what the update installed with what it replaced */
    reverse_olds = calloc(journal.pair_count, sizeof *reverse_olds);
    reverse_news = calloc(journal.pair_count, sizeof *reverse_news);
    if (!reverse_olds || !reverse_news) { result = 1; goto done; }
    for (k = 0; k < journal.pair_count; ++k) {
        reverse_olds[k] = journal.news[k];
        reverse_news[k] = journal.olds[k];
    }
    request.olds = (const char *const *)reverse_olds;
    request.news = (const char *const *)reverse_news;
    request.pair_count = journal.pair_count;
    request.accept_arch = accepted_arch;
    request.arch_count = arch_count;
    request.accept_privileged = accepted_privileged;
    request.privileged_count = privileged_count;
    request.accept_service = accepted_service;
    request.service_count = service_count;
    result = 0;
done:
    free(committed); free(source_plan); free(marker);
    if (work >= 0) close(work);
    if (transactions >= 0) close(transactions);
    if (db >= 0) close(db);
    if (root >= 0) close(root);
    /* the reverse names the journal's own digests, so the journal outlives the request */
    if (result) {
        free(reverse_olds); free(reverse_news);
        update_journal_forget(&journal);
        return result;
    }
    if (approved) {
        result = holy_state_apply_update(approved, &request, root_path);
        if (!result && !grouped)
            printf("rollback %s restored %s\n", transaction, journal.old);
        else if (!result)
            printf("rollback %s restored %zu artifacts\n", transaction, journal.pair_count);
        free(reverse_olds); free(reverse_news);
        update_journal_forget(&journal);
        return result;
    }
    result = holy_state_update_prepare(&request, root_path, hash, &record);
    if (!result && grouped) {
        /* the journal is the record of what the transaction did, so the review names it
           before the request it built is released */
        for (k = 0; k < journal.pair_count; ++k)
            printf("rollback-pair transaction %s current %s target %s\n", transaction,
                   journal.news[k], journal.olds[k]);
        if (printf("rollback-plan transaction %s slots %zu generation %llu sha256 %s read-only\n",
                   transaction, journal.pair_count, journal.generation, hash) < 0) result = 1;
    } else if (!result &&
               printf("rollback-plan transaction %s current %s target %s sha256 %s read-only\n",
                      transaction, journal.next, journal.old, hash) < 0) {
        result = 1;
    }
    if (!result && fputs(record, stdout) == EOF) result = 1;
    free(record);
    free(reverse_olds); free(reverse_news);
    update_journal_forget(&journal);
    return result;
}
