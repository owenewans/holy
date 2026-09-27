#define _POSIX_C_SOURCE 200809L
#include "state.h"
#include "stage.h"
#include "cache.h"
#include "preview.h"
#include "verify.h"
#include "extract.h"
#include "package.h"
#include "install.h"
#include "config.h"
#include "resolve.h"
#include "scan.h"
#include "deps.h"
#include "source.h"

#include <archive.h>
#include <archive_entry.h>
#include <openssl/evp.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

static int set_journal_present(int dir);

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
    static const char *const names[] = { "installed", "transactions", "index" };
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

static int graph_digest(int item, char output[65])
{
    unsigned char buffer[8192], digest[32];
    unsigned int length;
    size_t total = 0, i;
    ssize_t got;
    struct stat st;
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    int fd = openat(item, "graph", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    int ok = 0;
    if (fd < 0 || !hash || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        (st.st_mode & 0022) || (st.st_uid != 0 && st.st_uid != geteuid()) ||
        st.st_size < 1 || st.st_size > 16 * 1024 * 1024 ||
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

static int instance_state_generation(int item, const char *digest,
                                     unsigned long long *recorded)
{
    char buffer[640], prefix[560], graph[65], source[65], source_hash[65], *end;
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
    version = !strncmp(buffer, "format holy-instance-3\n", 23) ? 3 :
              !strncmp(buffer, "format holy-instance-2\n", 23) ? 2 : 1;
    if (strstr(buffer, "\nreason dependency\n")) reason = "dependency";
    if (version < 3 && (!fstatat(item, "source", &st, AT_SYMLINK_NOFOLLOW) || errno != ENOENT)) return 0;
    if (version == 3) {
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
    static const char *const required[] = { "meta", "files", "deps", "origin", "state", "graph", "source" };
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
                if (seen != (1u << 5) - 1u && seen != (1u << 6) - 1u &&
                    seen != (1u << 7) - 1u) ok = 0;
                closedir(members);
            }
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

static int journal_valid(int dir, unsigned long long generation,
                         unsigned long long *original,
                         char artifact[65], char plan_digest[65], int *removing)
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
    if (st.st_size != (off_t)(length + 65 + 5 + 65) ||
        buffer[length + 64] != '\n' ||
        memcmp(buffer + length + 65, "plan ", 5) ||
        buffer[length + 65 + 5 + 64] != '\n') goto done;
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
    int result = set_journal_present(dir);
    return result ? result : journal_valid(dir, generation, NULL, NULL, NULL, NULL);
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
    if (dir < 0 || flock(dir, LOCK_EX) || !state_layout(dir, 0) ||
        !installed_valid(dir) || !empty_child(dir, "index") ||
        !read_generation(dir, &generation)) goto done;
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
    if (dir < 0 || flock(dir, LOCK_EX) || !state_layout(dir, 0) ||
        !installed_valid(dir) || !empty_child(dir, "index") ||
        !read_generation(dir, &generation) ||
        pending_child(dir, generation, digest, approved) != 1) goto done;
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
    if (dir < 0 || flock(dir, LOCK_EX) || !state_layout(dir, 0) ||
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
    if (entry->hardlink || entry->group ||
        (entry->link && (entry->mode != 0777 || entry->link[0] == '/')) ||
        !entry->path[0] || entry->path[0] == '/' ||
        !strcmp(entry->path, "var/lib/holypkg") ||
        !strncmp(entry->path, "var/lib/holypkg/", 16) ||
        !strcmp(entry->path, "var/cache/holypkg") ||
        !strncmp(entry->path, "var/cache/holypkg/", 18) ||
        (entry->mode & 07000) ||
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
                       entry->directory ? 'd' : entry->link ? 'l' : 'f', entry->mode,
                       entry->uid, entry->gid, entry->size);
    if (written <= 0 || (size_t)written >= sizeof attributes ||
        !hash_text(plan->hash, entry->path) ||
        !hash_text(plan->hash, attributes) ||
        (entry->link && !hash_text(plan->hash, entry->link)) ||
        (!entry->directory && !entry->link &&
         EVP_DigestUpdate(plan->hash, entry->hash, 32) != 1)) return 0;
    ++plan->count;
    return 1;
}

static int empty_transform(const char *snapshot)
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
            if (found++ || archive_entry_size(entry) != 0) goto done;
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

static int installed_name(int item, const char *name)
{
    struct stat st;
    char *line = NULL;
    size_t capacity = 0, number = 0;
    ssize_t length;
    int fd = openat(item, "meta", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    int found = 0, result = -1;
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
        if (count && !strcmp(v[0], "name")) {
            if (found) { holy_tokens_free(v, count); goto done; }
            found = !strcmp(v[1], name) ? 2 : 1;
        }
        holy_tokens_free(v, count);
    }
    if (!ferror(input) && found && ftello(input) == st.st_size) result = found == 2;
done:
    free(line);
    fclose(input);
    return result;
}

static int name_available(int dir, const char *name)
{
    int installed = child_dir(dir, "installed", 0), available = -1;
    DIR *list;
    struct dirent *entry;
    if (installed < 0) return -1;
    list = directory_stream(installed);
    if (!list) { close(installed); return -1; }
    errno = 0;
    while ((entry = readdir(list))) {
        int item, match;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        item = child_dir(installed, entry->d_name, 0);
        if (item < 0) goto done;
        match = installed_name(item, name);
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
    if (!holy_extract_preflight(snapshot) || !empty_transform(snapshot) ||
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
    result = name_available(dir, identity.name);
    if (result < 0) { result = 1; goto done; }
    if (!result) {
        fprintf(stderr, "holypkg: installed package name already active: %s\n", identity.name);
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
    if (dir < 0 || flock(dir, LOCK_EX) || !state_layout(dir, 0) ||
        !installed_valid(dir) || !empty_child(dir, "index") ||
        !read_generation(dir, &generation)) goto done;
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
        "HOLY/meta", "HOLY/files", "HOLY/deps", "HOLY/origin"
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
    ok = status == ARCHIVE_EOF && seen == (1u << 4) - 1u;
done:
    archive_read_free(archive);
    return ok;
}

static int save_instance(int installed, const char *digest, const char *snapshot,
                         unsigned long long generation, const char *graph, size_t graph_length,
                         const char *reason, const char *source_record)
{
    static const char *const names[] = { "meta", "files", "deps", "origin" };
    struct archive *archive = NULL;
    struct archive_entry *entry;
    char buffer[65536], state[640], graph_hash[65], source[65], source_hash[65];
    int item = -1, status, ok = 0;
    unsigned seen = 0;
    size_t i;
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
    if (status != ARCHIVE_EOF || seen != (1u << 4) - 1u) goto done;
    if (!record_file(item, "graph", graph, graph_length) ||
        !graph_digest(item, graph_hash)) goto done;
    if (source_record) {
        if (!record_file(item, "source", source_record, strlen(source_record)) ||
            !holy_source_instance(item, source, source_hash)) goto done;
        i = (size_t)snprintf(state, sizeof state,
            "format holy-instance-3\nsource-id %s\nsource-record %s\ndelivery local\nreason %s\nartifact %s\ngraph %s\ngeneration %llu\n",
            source, source_hash, reason, digest, graph_hash, generation + 1);
    } else i = (size_t)snprintf(state, sizeof state,
        "format holy-instance-2\nsource-id -\ndelivery local\nreason %s\nartifact %s\ngraph %s\ngeneration %llu\n",
        reason, digest, graph_hash, generation + 1);
    if (i >= sizeof state || !record_file(item, "state", state, i) || fsync(item)) goto done;
    ok = 1;
done:
    if (archive) archive_read_free(archive);
    if (item >= 0) close(item);
    return ok;
}

int holy_state_apply(const char *root_path)
{
    char digest[65], approved[65], actual[65], journal[256], generation_record[32];
    char temp_name[43] = {0};
    char *snapshot = NULL, *graph = NULL;
    size_t graph_length = 0;
    unsigned long long generation;
    struct stat st;
    size_t paths, length;
    int root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int dir = root < 0 ? -1 : state_dir_at(root, 0);
    int transactions = -1, installed = -1, temp = -1, journaled = 0, result = 1;
    if (dir < 0 || flock(dir, LOCK_EX) || !state_layout(dir, 0) ||
        !installed_valid(dir) || !empty_child(dir, "index") ||
        !read_generation(dir, &generation) || generation == ULLONG_MAX) goto done;
    result = pending_child(dir, generation, digest, approved);
    if (result < 0) { result = 1; goto done; }
    if (!result || !approved[0]) { result = 5; goto done; }
    result = inspect_plan(root_path, root, dir, generation, digest, actual, &paths, &graph, &graph_length);
    if (result) goto done;
    if (strcmp(actual, approved)) { result = 3; goto done; }
    snapshot = holy_cache_snapshot(digest, root_path);
    if (!snapshot) { result = 6; goto done; }
    if (!instance_preflight(snapshot)) { result = 6; goto done; }
    if (!holy_install_preflight(snapshot, root)) { result = 4; goto done; }
    installed = child_dir(dir, "installed", 0);
    transactions = child_dir(dir, "transactions", 0);
    if (installed < 0 || transactions < 0 ||
        !fstatat(installed, digest, &st, AT_SYMLINK_NOFOLLOW) ||
        errno != ENOENT) { result = 4; goto done; }
    length = (size_t)snprintf(journal, sizeof journal,
        "format holy-journal-1\nstage applying\ngeneration %llu\nartifact %s\nplan %s\n",
        generation, digest, approved);
    if (length >= sizeof journal || !record_file(transactions, "journal", journal, length)) {
        result = journal_exists(dir) ? 5 : 1;
        goto done;
    }
    journaled = 1;
    result = 5;
    if (!holy_install_payload(snapshot, root) ||
        !save_instance(installed, digest, snapshot, generation, graph, graph_length, "explicit", NULL)) goto done;
    length = (size_t)snprintf(generation_record, sizeof generation_record,
                              "%llu\n", generation + 1);
    if (length >= sizeof generation_record) goto done;
    temp = holy_temporary_at(dir, temp_name);
    if (temp < 0 || !write_all(temp, generation_record, length) || fsync(temp)) goto done;
    if (close(temp)) { temp = -1; goto done; }
    temp = -1;
    if (renameat(dir, temp_name, dir, "generation") || fsync(dir) ||
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
    if (dir < 0 || fstat(root, &root_st) || flock(dir, LOCK_EX) || !state_layout(dir, 0) ||
        !empty_child(dir, "index") || !read_generation(dir, &generation)) goto done;
    result = journal_valid(dir, generation, &recorded, digest, plan, &removing);
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
    if (!snapshot || !holy_install_preflight(snapshot, root) ||
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
};

struct check_result {
    char digest[65];
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
    }
    free(record->findings);
}

static int collect_finding(void *context, const char *path, const char *code)
{
    struct check_result *record = context;
    struct check_finding *grown;
    char *copy, *code_copy;
    if (record->count >= SIZE_MAX / sizeof *grown) return 0;
    copy = strdup(path);
    if (!copy) return 0;
    code_copy = strdup(code);
    if (!code_copy) { free(copy); return 0; }
    grown = realloc(record->findings, (record->count + 1) * sizeof *grown);
    if (!grown) { free(copy); free(code_copy); return 0; }
    record->findings = grown;
    grown[record->count].path = copy;
    grown[record->count++].code = code_copy;
    return 1;
}

static int print_check_result(const struct check_result *record,
                               unsigned long long generation)
{
    size_t i;
    printf("{\"schema\":\"holy-installed-check-1\",\"type\":\"artifact\",\"artifact\":\"%s\",\"state\":\"%s\",\"code\":%s,\"generation\":%llu,\"findings\":[",
           record->digest, record->intact ? "pass" : "fail",
           record->intact ? "null" : "\"changed-file\"", generation);
    for (i = 0; i < record->count; ++i) {
        const unsigned char *p = (const unsigned char *)record->findings[i].path;
        printf("%s{\"code\":\"%s\",\"severity\":\"error\",\"path\":\"",
               i ? "," : "", record->findings[i].code);
        for (; *p; ++p) {
            if (*p == '"' || *p == '\\') printf("\\%c", *p);
            else if (*p < 32 || *p >= 127) printf("\\u%04x", (unsigned)*p);
            else putchar(*p);
        }
        fputs("\"}", stdout);
    }
    puts("]}");
    return !ferror(stdout);
}

static int compare_check_result(const void *a, const void *b)
{
    const struct check_result *left = a, *right = b;
    return strcmp(left->digest, right->digest);
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
        int provider, intact = 1;
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
        else if (!strcmp(v[5], "interpreter") || !strcmp(v[5], "needed-path")) {
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
            if (record && !collect_finding(record, v[6], "broken-provider")) result = -1;
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
    size_t count = 0, capacity = 0, i, passed = 0, failed = 0;
    int result = 1;
    list = directory_stream(installed);
    if (!list) return 1;
    errno = 0;
    while ((entry = readdir(list))) {
        int item, files, status;
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
        close(item);
        if (files < 0) goto done;
        memset(&records[count], 0, sizeof records[count]);
        memcpy(records[count].digest, entry->d_name, 65);
        ++count;
        status = holy_install_check_report(files, root,
                    json ? collect_finding : NULL, &records[count - 1]);
        close(files);
        if (status < 0) goto done;
        {
            int graph = check_graph(installed, root, entry->d_name, json ? &records[count - 1] : NULL);
            if (graph < 0) goto done;
            if (!graph) status = 0;
        }
        records[count - 1].intact = status;
        errno = 0;
    }
    if (errno) goto done;
    if (count) qsort(records, count, sizeof *records, compare_check_result);
    result = 0;
    for (i = 0; i < count; ++i) {
        int written;
        if (records[i].intact) ++passed;
        else { ++failed; result = 4; }
        if (json)
            written = print_check_result(&records[i], generation) ? 0 : -1;
        else
            written = printf("%s %s generation %llu\n",
                             records[i].intact ? "intact" : "changed",
                             records[i].digest, generation);
        if (written < 0) { result = 1; break; }
    }
    if (result != 1) {
        if (json) {
            if (printf("{\"schema\":\"holy-installed-check-1\",\"type\":\"summary\",\"pass\":%zu,\"fail\":%zu,\"coverage\":\"data-manifest\"}\n",
                       passed, failed) < 0) result = 1;
        } else if (count == 0 && puts("checked 0 installed packages") == EOF)
            result = 1;
    }
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
    int root, dir = -1, installed = -1, item = -1, files = -1, result = 1;
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
    if (all) { result = check_all(installed, root, generation, json); goto done; }
    item = child_dir(installed, digest, 0);
    if (item < 0) { result = 6; goto done; }
    files = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (files < 0) goto done;
    checked = holy_install_check_report(files, root,
                json ? collect_finding : NULL, &record);
    if (checked >= 0) {
        int graph = check_graph(installed, root, digest, json ? &record : NULL);
        if (graph < 0) checked = -1;
        else if (!graph) checked = 0;
    }
    result = checked > 0 ? 0 : checked == 0 ? 4 : 1;
    if (json && (result == 0 || result == 4)) {
        memcpy(record.digest, digest, 65);
        record.intact = !result;
        if (!print_check_result(&record, generation)) { result = 1; goto done; }
        printf("{\"schema\":\"holy-installed-check-1\",\"type\":\"summary\",\"pass\":%d,\"fail\":%d,\"coverage\":\"data-manifest\"}\n",
               result ? 0 : 1, result ? 1 : 0);
    } else if (!result) printf("intact %s generation %llu\n", digest, generation);
done:
    free_check_result(&record);
    if (result) fprintf(stderr, "holypkg: installed check failed (status %d)\n", result);
    if (json && result != 0 && result != 4) {
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

static int finish_remove_record(int dir, int installed, int item, int transactions,
                                const char *digest, unsigned long long generation)
{
    static const char *const names[] = { "meta", "files", "deps", "origin", "state" };
    char generation_record[32], temp_name[43] = {0};
    size_t length, i;
    int temp = -1, ok = 0;
    for (i = 0; i < sizeof names / sizeof *names; ++i)
        if (unlinkat(item, names[i], 0)) goto done;
    if (unlinkat(item, "graph", 0) && errno != ENOENT) goto done;
    if (unlinkat(item, "source", 0) && errno != ENOENT) goto done;
    if (fsync(item) || unlinkat(installed, digest, AT_REMOVEDIR) ||
        fsync(installed)) goto done;
    length = (size_t)snprintf(generation_record, sizeof generation_record,
                              "%llu\n", generation + 1);
    if (length >= sizeof generation_record) goto done;
    temp = holy_temporary_at(dir, temp_name);
    if (temp < 0 || !write_all(temp, generation_record, length) || fsync(temp)) goto done;
    if (close(temp)) { temp = -1; goto done; }
    temp = -1;
    if (renameat(dir, temp_name, dir, "generation") || fsync(dir) ||
        unlinkat(transactions, "journal", 0) || fsync(transactions)) goto done;
    ok = 1;
done:
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

static int dependent_consumer(int installed, const char *digest)
{
    DIR *list = directory_stream(installed);
    struct dirent *entry;
    int result = 0;
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
                if (count != 7 || !valid_digest(v[1]) || !valid_digest(v[3])) result = -1;
                else if (!strcmp(v[3], digest) && strcmp(v[1], digest)) {
                    if (!fstatat(installed, v[1], &st, AT_SYMLINK_NOFOLLOW)) {
                        if (!S_ISDIR(st.st_mode)) result = -1;
                        else {
                            fprintf(stderr, "holypkg: provider %s still required by %s requirement %s\n",
                                    digest, v[1], v[2]);
                            result = 1;
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
    return result;
}

int holy_state_remove(const char *digest, const char *root_path)
{
    unsigned long long generation;
    char journal[256];
    char reserved[65], approved[65];
    size_t length;
    int root, dir = -1, installed = -1, item = -1, files = -1;
    int transactions = -1, journaled = 0, result = 1, pending;
    if (!valid_digest(digest)) return 2;
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) goto done;
    dir = state_dir_at(root, 0);
    if (dir < 0 || flock(dir, LOCK_EX) || !state_layout(dir, 0) ||
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
    pending = dependent_consumer(installed, digest);
    if (pending) { result = pending < 0 ? 1 : 3; goto done; }
    item = child_dir(installed, digest, 0);
    if (item < 0) { result = 6; goto done; }
    files = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (files < 0) goto done;
    pending = holy_install_check_manifest(files, root);
    if (pending != 1) { result = pending == 0 ? 4 : 1; goto done; }
    pending = exclusive_claims(installed, digest, files);
    if (pending != 1) { result = pending == 0 ? 4 : 1; goto done; }
    length = (size_t)snprintf(journal, sizeof journal,
        "format holy-journal-1\nstage removing\ngeneration %llu\nartifact %s\nplan %064d\n",
        generation, digest, 0);
    if (length >= sizeof journal || !record_file(transactions, "journal", journal, length)) {
        result = journal_exists(dir) ? 5 : 1;
        goto done;
    }
    journaled = 1;
    result = 5;
    if (!holy_install_remove_manifest(files, root)) goto done;
    if (close(files)) { files = -1; goto done; }
    files = -1;
    if (!finish_remove_record(dir, installed, item, transactions, digest, generation)) goto done;
    printf("removed %s generation %llu\n", digest, generation + 1);
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: remove failed (status %d)%s\n", result,
                        journaled ? "; inspect incomplete transaction" : "");
    if (files >= 0) close(files);
    if (item >= 0) close(item);
    if (installed >= 0) close(installed);
    if (transactions >= 0) close(transactions);
    if (dir >= 0) close(dir);
    if (root >= 0) close(root);
    return result;
}

int holy_state_continue_remove(const char *root_path)
{
    unsigned long long generation, recorded;
    char digest[65], plan[65], reserved[65], approved[65];
    int root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int dir = root < 0 ? -1 : state_dir_at(root, 0);
    int installed = -1, item = -1, transactions = -1, files = -1;
    int result = 5, removing = 0, found;
    if (dir < 0 || flock(dir, LOCK_EX) || !state_layout(dir, 0) ||
        !empty_child(dir, "index") || !read_generation(dir, &generation) ||
        generation == ULLONG_MAX) { result = 1; goto done; }
    found = journal_valid(dir, generation, &recorded, digest, plan, &removing);
    if (found < 0) { result = 1; goto done; }
    if (!found || removing != 1 || recorded != generation ||
        strspn(plan, "0") != 64 || !installed_valid(dir)) goto done;
    transactions = child_dir(dir, "transactions", 0);
    installed = child_dir(dir, "installed", 0);
    if (transactions < 0 || installed < 0) { result = 1; goto done; }
    if (read_reservation(transactions, "pending", generation, reserved, approved) != 0)
        goto done;
    item = child_dir(installed, digest, 0);
    if (item < 0) goto done;
    files = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (files < 0 || exclusive_claims(installed, digest, files) != 1 ||
        !holy_install_finish_remove_manifest(files, root) ||
        !finish_remove_record(dir, installed, item, transactions, digest, generation)) goto done;
    printf("recovered removal %s generation %llu\n", digest, generation + 1);
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: removal recovery requires manual inspection (status %d)\n", result);
    if (files >= 0) close(files);
    if (item >= 0) close(item);
    if (installed >= 0) close(installed);
    if (transactions >= 0) close(transactions);
    if (dir >= 0) close(dir);
    if (root >= 0) close(root);
    return result;
}

int holy_state_finish_apply(const char *root_path)
{
    unsigned long long generation, recorded, instance_generation;
    char digest[65], plan[65], reserved[65], approved[65];
    int root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int dir = root < 0 ? -1 : state_dir_at(root, 0);
    int transactions = -1, installed = -1, item = -1, files = -1;
    int result = 5, removing = 0, found;
    if (dir < 0 || flock(dir, LOCK_EX) || !state_layout(dir, 0) ||
        !empty_child(dir, "index") || !read_generation(dir, &generation)) {
        result = 1;
        goto done;
    }
    found = journal_valid(dir, generation, &recorded, digest, plan, &removing);
    if (found < 0) { result = 1; goto done; }
    if (!found || removing || !generation || recorded != generation - 1 ||
        !installed_valid(dir)) goto done;
    transactions = child_dir(dir, "transactions", 0);
    installed = child_dir(dir, "installed", 0);
    if (transactions < 0 || installed < 0) { result = 1; goto done; }
    found = read_reservation(transactions, "pending", recorded, reserved, approved);
    if (found < 0 || (found && (strcmp(reserved, digest) || strcmp(approved, plan))))
        goto done;
    item = child_dir(installed, digest, 0);
    if (item < 0 || !instance_state_generation(item, digest, &instance_generation) ||
        instance_generation != generation) goto done;
    files = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (files < 0 || holy_install_check_manifest(files, root) != 1) goto done;
    if (found && (unlinkat(transactions, "pending", 0) || fsync(transactions))) goto done;
    if (unlinkat(transactions, "journal", 0) || fsync(transactions)) goto done;
    printf("recovered install %s generation %llu\n", digest, generation);
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
    struct holy_package_identity identity;
    int reused;
};

struct set_claim {
    char *path;
    unsigned mode;
    long long uid, gid;
    int directory;
};

struct install_set {
    struct holy_resolution resolution;
    struct set_item *items;
    size_t count, paths;
    struct set_claim *claims;
    size_t claim_count;
    char *graph;
    size_t graph_length;
    char hash[65];
};

struct set_journal {
    unsigned long long generation;
    char hash[65], root[65];
    char *choice;
    char **digests, **bindings;
    size_t count, binding_count;
};

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
    free(set->items);
    free(set->graph);
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

static int explicit_elf_paths(const char *snapshot)
{
    struct holy_scan_result scan = {0};
    size_t i, j;
    int result = 6;
    if (!holy_scan_collect(snapshot, &scan)) return 6;
    result = 0;
    for (i = 0; i < scan.count; ++i) {
        const struct holy_scanned_file *file = &scan.files[i];
        if (file->elf.interpreter && file->elf.interpreter[0] != '/') { result = 3; break; }
        for (j = 0; j < file->elf.needed_count; ++j)
            if (file->elf.needed[j][0] != '/') {
                fprintf(stderr, "holypkg: unknown-loader-search consumer=%s requirement=%s\n",
                        file->path, file->elf.needed[j]);
                result = 3;
                break;
            }
        if (result) break;
    }
    holy_scan_free(&scan);
    return result;
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
    char **digests;
    size_t count;
};

static int add_installed_candidates(struct installed_candidates *catalog,
                                    const char *name, const char *path)
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
        if (name) matches = installed_name(item, name);
        else {
            int files = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
            matches = files < 0 ? -1 : holy_install_manifest_owns(files, path);
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

static int installed_requirement(void *context, const char *id,
    const char *consumer, const char *kind, const char *name,
    const char *arch, const char *libc, const char *relation,
    const char *version, const char *original, const char *evidence)
{
    (void)id; (void)consumer; (void)arch; (void)libc; (void)relation;
    (void)version; (void)original; (void)evidence;
    return strcmp(kind, "package") || add_installed_candidates(context, name, NULL);
}

static int discover_installed(const char *root_path, int dir,
                              const char *const *digests, size_t *count, char ***output)
{
    struct installed_candidates catalog = {-1, NULL, 0};
    size_t i, j, k;
    int result = 1;
    catalog.digests = calloc(10000, sizeof *catalog.digests);
    if (!catalog.digests) return 1;
    catalog.installed = child_dir(dir, "installed", 0);
    if (catalog.installed < 0) goto done;
    for (i = 0; i < *count; ++i) {
        catalog.digests[i] = strdup(digests[i]);
        if (!catalog.digests[i]) goto done;
        ++catalog.count;
    }
    for (i = 0; i < catalog.count; ++i) {
        struct holy_scan_result scan = {0};
        char *snapshot = holy_cache_snapshot(catalog.digests[i], root_path);
        int ok;
        if (!snapshot) { result = 6; goto done; }
        ok = holy_deps_visit(snapshot, installed_requirement, &catalog) &&
             holy_scan_collect(snapshot, &scan);
        unlink(snapshot);
        free(snapshot);
        for (j = 0; ok && j < scan.count; ++j) {
            const struct holy_elf_info *elf = &scan.files[j].elf;
            if (elf->interpreter && elf->interpreter[0] == '/')
                ok = add_installed_candidates(&catalog, NULL, elf->interpreter + 1);
            for (k = 0; ok && k < elf->needed_count; ++k)
                if (elf->needed[k][0] == '/')
                    ok = add_installed_candidates(&catalog, NULL, elf->needed[k] + 1);
        }
        holy_scan_free(&scan);
        if (!ok) { result = 6; goto done; }
    }
    result = 0;
done:
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
    size_t i, j;
    int result = 1;
    if (!count || count > 10000 || binding_count > 10000) return 2;
    for (i = 0; i < count; ++i) if (!valid_digest(digests[i])) return 2;
    for (i = 0; i < binding_count; ++i) {
        if (!binding_valid(bindings[i])) return 2;
        for (j = 0; j < i; ++j) if (!strncmp(bindings[i], bindings[j], 64)) return 2;
    }
    if (!completed) {
        result = discover_installed(root_path, dir, digests, &count, &candidates);
        if (result) goto done;
        digests = (const char *const *)candidates;
        result = 1;
    }
    snapshots = calloc(count, sizeof *snapshots);
    if (!snapshots || fstat(root, &st) || uname(&host)) goto done;
    for (i = 0; i < count; ++i) {
        snapshots[i] = holy_cache_snapshot(digests[i], root_path);
        if (!snapshots[i]) { result = 6; goto done; }
    }
    result = holy_resolve_collect((const char *const *)snapshots, count, choice,
                                  &set->resolution);
    if (result) goto done;
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
            (strcmp(item->identity.arch, "noarch") &&
             !((!strcmp(item->identity.arch, "x86_64") && !strcmp(host.machine, "x86_64")) ||
               (!strcmp(item->identity.arch, "x86") && !strcmp(host.machine, "i686")))) ||
            !empty_transform(item->snapshot) || !instance_preflight(item->snapshot)) goto done;
        result = explicit_elf_paths(item->snapshot);
        if (result) goto done;
        result = reuse_instance(dir, root, item, generation, completed, set->graph, plan.hash);
        if (result < 0) { result = 4; goto done; }
        for (j = 0; j < binding_count; ++j) if (!strncmp(bindings[j], item->identity.digest, 64)) {
            char registry[65];
            if (item->reused) { result = 3; goto done; }
            result = holy_source_record(dir, bindings[j] + 65, &item->source_record, registry);
            if (result) goto done;
            if (!hash_text(plan.hash, "source-binding") || !hash_text(plan.hash, registry) ||
                !hash_text(plan.hash, item->source_record)) { result = 1; goto done; }
            break;
        }
        if (item->reused && !strcmp(item->identity.digest, set->resolution.root)) {
            result = 3; goto done;
        }
        result = holy_preview_resolved(item->snapshot, root_path, completed || item->reused);
        if (result) goto done;
        for (j = 0; j < i; ++j)
            if (!strcmp(set->items[j].identity.name, item->identity.name)) {
                result = 4; goto done;
            }
        if (!completed && !item->reused) {
            result = name_available(dir, item->identity.name);
            if (result != 1) { result = result < 0 ? 1 : 4; goto done; }
            if (!holy_install_preflight(item->snapshot, root)) { result = 4; goto done; }
        }
        result = 6;
        plan.completed = completed || item->reused;
        if (!hash_text(plan.hash, item->identity.digest) ||
            !holy_verify_visit(item->snapshot, plan_entry, &plan)) {
            if (plan.claim_error) result = plan.claim_error;
            goto done;
        }
        result = 1;
        if (!holy_verify_visit(item->snapshot, set_claim, set)) goto done;
    }
    if (!set_claims_valid(set)) { result = 4; goto done; }
    if (!same_root(root_path, &st)) { result = 4; goto done; }
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
    memset(journal, 0, sizeof *journal);
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
            if (!strcmp(line, "format holy-set-journal-2")) version = 2;
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
        } else if (version == 2 && !strncmp(line, "binding ", 8)) {
            char **next;
            size_t i;
            if (!binding_valid(line + 8) || journal->binding_count >= journal->count) goto done;
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
            if (journal->binding_count || strncmp(line, "artifact ", 9) || !valid_digest(line + 9) ||
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
        (version == 1 || journal->binding_count)) result = 1;
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

static int write_set_journal(int transactions, unsigned long long generation,
                             const struct install_set *set, const char *choice,
                             const char *const *bindings, size_t binding_count)
{
    char *record = NULL;
    size_t length = 0, i;
    FILE *stream = open_memstream(&record, &length);
    int ok = 1;
    if (!stream) return 0;
    if (fprintf(stream, "format holy-set-journal-%d\ngeneration %llu\nplan %s\nroot %s\nchoice %s\n",
                binding_count ? 2 : 1, generation, set->hash, set->resolution.root, choice ? choice : "-") < 0) ok = 0;
    for (i = 0; i < set->count && ok; ++i)
        if (fprintf(stream, "artifact %s\n", set->items[i].identity.digest) < 0) ok = 0;
    for (i = 0; i < binding_count && ok; ++i)
        if (fprintf(stream, "binding %s\n", bindings[i]) < 0) ok = 0;
    if (fclose(stream)) ok = 0;
    if (ok) ok = record_file(transactions, "set-journal", record, length);
    free(record);
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

int holy_state_set(const char *const *digests, size_t count, const char *choice,
                   const char *approved, const char *root_path,
                   const char *const *bindings, size_t binding_count)
{
    struct install_set set = {0};
    unsigned long long generation;
    int root = -1, dir = -1, installed = -1, transactions = -1, result = 1, journaled = 0;
    size_t i;
    if ((approved && !valid_digest(approved)) || (choice && !set_choice_valid(choice))) return 2;
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    dir = root < 0 ? -1 : state_dir_at(root, 0);
    if (dir < 0 || flock(dir, approved ? LOCK_EX : LOCK_SH) ||
        !state_layout(dir, 0) || !read_generation(dir, &generation) ||
        generation == ULLONG_MAX || !empty_child(dir, "index")) goto done;
    if (!empty_child(dir, "transactions")) { result = 5; goto done; }
    if (!installed_valid(dir)) goto done;
    result = build_set(root_path, root, dir, generation, digests, count, choice, 0, bindings, binding_count, &set);
    if (result) goto done;
    if (!approved) {
        printf("plan-set generation %llu root %s artifacts %zu paths %zu sha256 %s read-only\n",
               generation, set.resolution.root, set.count, set.paths, set.hash);
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
        goto done;
    }
    if (strcmp(set.hash, approved)) { result = 3; goto done; }
    installed = child_dir(dir, "installed", 0);
    transactions = child_dir(dir, "transactions", 0);
    if (installed < 0 || transactions < 0) { result = 1; goto done; }
    if (!write_set_journal(transactions, generation, &set, choice, bindings, binding_count)) {
        struct stat st;
        result = fstatat(transactions, "set-journal", &st, AT_SYMLINK_NOFOLLOW) ? 1 : 5;
        goto done;
    }
    journaled = 1;
    result = 5;
    for (i = 0; i < set.count; ++i) {
        struct set_item *item = &set.items[i];
        if (item->reused) continue;
        if (!holy_install_payload(item->snapshot, root) ||
            !save_instance(installed, item->identity.digest, item->snapshot, generation,
                           set.graph, set.graph_length,
                           strcmp(item->identity.digest, set.resolution.root) ? "dependency" : "explicit",
                           item->source_record))
            goto done;
        printf("applied %s\n", item->identity.digest);
    }
    if (!set_generation(dir, generation + 1) ||
        unlinkat(transactions, "set-journal", 0) || fsync(transactions)) goto done;
    printf("committed-set %s generation %llu artifacts %zu\n", set.hash, generation + 1, set.count);
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: package set failed (status %d)%s\n", result,
                        journaled ? "; incomplete set journal retained" : "");
    free_set(&set);
    if (transactions >= 0) close(transactions);
    if (installed >= 0) close(installed);
    if (dir >= 0) close(dir);
    if (root >= 0) close(root);
    return result;
}

static int instance_matches_snapshot(int item, const char *snapshot)
{
    static const char *const names[] = {"meta", "files", "deps", "origin"};
    struct archive *archive = archive_read_new();
    struct archive_entry *entry;
    unsigned seen = 0;
    char incoming[8192], installed[8192];
    int status, ok = 0;
    size_t i;
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
        if (i == sizeof names / sizeof *names) {
            if (archive_read_data_skip(archive) != ARCHIVE_OK) goto done;
            continue;
        }
        if (seen & (1u << i)) goto done;
        fd = openat(item, names[i], O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
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
    ok = status == ARCHIVE_EOF && seen == (1u << 4) - 1u;
done:
    archive_read_free(archive);
    return ok;
}

static int instance_reason_matches(int item, const char *reason)
{
    char buffer[640], expected[64];
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
    unsigned long long generation, recorded;
    const char **digests = NULL;
    unsigned char *present = NULL;
    size_t i, j;
    int root = -1, dir = -1, installed = -1, transactions = -1, result = 5;
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    dir = root < 0 ? -1 : state_dir_at(root, 0);
    if (dir < 0 || flock(dir, LOCK_EX) || !state_layout(dir, 0) ||
        !empty_child(dir, "index") || !read_generation(dir, &generation)) { result = 1; goto done; }
    if (read_set_journal(dir, &journal) != 1 ||
        (generation != journal.generation && generation != journal.generation + 1) ||
        !installed_valid(dir)) goto done;
    digests = calloc(journal.count, sizeof *digests);
    present = calloc(journal.count, 1);
    if (!digests || !present) { result = 1; goto done; }
    digests[0] = journal.root;
    for (i = 0, j = 1; i < journal.count; ++i)
        if (strcmp(journal.root, journal.digests[i])) digests[j++] = journal.digests[i];
    if (build_set(root_path, root, dir, journal.generation, digests, journal.count,
                  strcmp(journal.choice, "-") ? journal.choice : NULL, 1,
                  (const char *const *)journal.bindings, journal.binding_count, &set) ||
        set.count != journal.count || strcmp(set.hash, journal.hash)) goto done;
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
                name_available(dir, candidate->identity.name) != 1 ||
                !holy_install_preflight(candidate->snapshot, root)) goto done;
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
        if (!holy_install_payload(item->snapshot, root) ||
            !save_instance(installed, item->identity.digest, item->snapshot, journal.generation,
                           set.graph, set.graph_length,
                           strcmp(item->identity.digest, set.resolution.root) ? "dependency" : "explicit",
                           item->source_record))
            goto done;
        printf("resumed %s\n", item->identity.digest);
    }
    if (generation == journal.generation && !set_generation(dir, generation + 1)) goto done;
    if (fsync(dir) || unlinkat(transactions, "set-journal", 0) || fsync(transactions)) goto done;
    printf("recovered-set %s generation %llu artifacts %zu\n",
           set.hash, journal.generation + 1, set.count);
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: set recovery requires inspection (status %d)\n", result);
    free(present);
    free(digests);
    free_set(&set);
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

static int repair_hash(int root, unsigned long long generation, const char *digest,
                        const char *graph, char output[65])
{
    struct stat st;
    char identity[128];
    unsigned char hash[32];
    unsigned int length;
    size_t i;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = 0;
    if (!ctx || fstat(root, &st) || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        !hash_text(ctx, "holy-repair-missing-1") || !hash_text(ctx, digest) ||
        !hash_text(ctx, graph)) goto done;
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
    int result = 1, stage = 0, journaled = 0, resume = digest == NULL;
    char artifact[65], expected[65], actual[65], graph[65], journal[256];
    char *snapshot = NULL;
    unsigned long long generation, recorded;
    struct stat root_st;
    size_t length;
    if (!resume && (!valid_digest(digest) || (approved && !valid_digest(approved)))) return 2;
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    dir = root < 0 ? -1 : state_dir_at(root, 0);
    if (dir < 0 || fstat(root, &root_st) || flock(dir, approved || resume ? LOCK_EX : LOCK_SH) ||
        !state_layout(dir, 0) || !empty_child(dir, "index") ||
        !read_generation(dir, &generation) || generation == ULLONG_MAX) goto done;
    recorded = generation;
    if (resume) {
        result = 5;
        if (set_journal_present(dir) ||
            journal_valid(dir, generation, &recorded, artifact, expected, &stage) != 1 ||
            stage != 2) goto done;
        {
            DIR *list;
            struct dirent *entry;
            int valid = 1, journal_dir = child_dir(dir, "transactions", 0);
            if (journal_dir < 0) goto done;
            list = directory_stream(journal_dir);
            close(journal_dir);
            if (!list) goto done;
            errno = 0;
            while ((entry = readdir(list))) {
                if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
                if (strcmp(entry->d_name, "journal")) { valid = 0; break; }
                errno = 0;
            }
            if (!entry && errno) valid = 0;
            closedir(list);
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
    files = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    snapshot = holy_cache_snapshot(digest, root_path);
    if (!snapshot) { result = 6; goto done; }
    if (files < 0 || !instance_matches_snapshot(item, snapshot) ||
        !graph_digest(item, graph) || !repair_hash(root, recorded, digest, graph, actual)) goto done;
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
        holy_install_check_or_missing(files, root) != 1) { result = resume ? 5 : 4; goto done; }
    if (!same_root(root_path, &root_st)) { result = 4; goto done; }
    if (!approved) {
        printf("repair-plan generation %llu artifact %s sha256 %s missing-only read-only\n",
               generation, digest, actual);
        result = 0;
        goto done;
    }
    transactions = child_dir(dir, "transactions", 0);
    if (transactions < 0) goto done;
    result = 5;
    if (!resume) {
        length = (size_t)snprintf(journal, sizeof journal,
            "format holy-journal-1\nstage repairing\ngeneration %llu\nartifact %s\nplan %s\n",
            recorded, digest, actual);
        if (length >= sizeof journal || !record_file(transactions, "journal", journal, length)) goto done;
        journaled = 1;
    }
    if (!holy_install_payload_missing(snapshot, root) ||
        holy_install_check_manifest(files, root) != 1 ||
        (generation == recorded && !set_generation(dir, recorded + 1)) || fsync(dir) ||
        unlinkat(transactions, "journal", 0) || fsync(transactions)) goto done;
    printf("repaired %s generation %llu missing-only\n", digest, recorded + 1);
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: missing-file repair failed (status %d)%s\n", result,
                        journaled ? "; repair journal retained" : "");
    if (snapshot) { unlink(snapshot); free(snapshot); }
    if (files >= 0) close(files);
    if (item >= 0) close(item);
    if (installed >= 0) close(installed);
    if (transactions >= 0) close(transactions);
    if (dir >= 0) close(dir);
    if (root >= 0) close(root);
    return result;
}
