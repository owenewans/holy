#define _POSIX_C_SOURCE 200809L
#include "state.h"
#include "stage.h"
#include "cache.h"
#include "preview.h"
#include "verify.h"
#include "extract.h"
#include "package.h"

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
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

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
    listing = fdopendir(dup(child));
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
        !empty_child(dir, "installed") ||
        !empty_child(dir, "index") ||
        !read_generation(dir, &generation)) goto done;
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
        !empty_child(dir, "installed") || !empty_child(dir, "index") ||
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
        !empty_child(dir, "installed") || !empty_child(dir, "index") ||
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
        !empty_child(dir, "installed") || !empty_child(dir, "index") ||
        !read_generation(dir, &generation)) goto done;
    transactions = child_dir(dir, "transactions", 0);
    if (transactions < 0) goto done;
    listing = fdopendir(dup(transactions));
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
        !empty_child(dir, "installed") || !empty_child(dir, "index") ||
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
    EVP_MD_CTX *hash;
    size_t count;
};

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
    int written;
    if (entry->link || entry->hardlink || entry->group ||
        !entry->path[0] || entry->path[0] == '/' ||
        !strcmp(entry->path, "var/lib/holypkg") ||
        !strncmp(entry->path, "var/lib/holypkg/", 16) ||
        !strcmp(entry->path, "var/cache/holypkg") ||
        !strncmp(entry->path, "var/cache/holypkg/", 18) ||
        (entry->mode & 07000) ||
        (!entry->directory && (entry->mode & 0111)) ||
        entry->uid != (long long)geteuid() ||
        entry->gid != (long long)getegid()) {
        fprintf(stderr, "holypkg: plan requires ordinary files and local ownership; unsupported path: %s\n",
                entry->path);
        return 0;
    }
    written = snprintf(attributes, sizeof attributes, "%c:%o:%lld:%lld:%lld:",
                       entry->directory ? 'd' : 'f', entry->mode,
                       entry->uid, entry->gid, entry->size);
    if (written <= 0 || (size_t)written >= sizeof attributes ||
        !hash_text(plan->hash, entry->path) ||
        !hash_text(plan->hash, attributes) ||
        (!entry->directory &&
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

static int inspect_plan(const char *root_path, int root,
                        unsigned long long generation, const char *digest,
                        char output[65], size_t *paths)
{
    struct holy_package_identity identity = {0};
    struct plan_hash plan = {0};
    char generation_text[32], root_id[128];
    unsigned char checksum[32];
    unsigned int checksum_size;
    size_t i;
    struct stat root_st;
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
        strcmp(identity.os, "linux") || strcmp(identity.arch, "noarch") ||
        strcmp(identity.libc, "nolibc") || strcmp(identity.digest, digest)) goto done;
    plan.hash = EVP_MD_CTX_new();
    if (!plan.hash) { result = 1; goto done; }
    snprintf(generation_text, sizeof generation_text, "%llu", generation);
    if (snprintf(root_id, sizeof root_id, "%ju:%ju",
                 (uintmax_t)root_st.st_dev, (uintmax_t)root_st.st_ino) >=
        (int)sizeof root_id) { result = 1; goto done; }
    if (EVP_DigestInit_ex(plan.hash, EVP_sha256(), NULL) != 1 ||
        !hash_text(plan.hash, "holy-readonly-plan-1") ||
        !hash_text(plan.hash, root_id) ||
        !hash_text(plan.hash, generation_text) || !hash_text(plan.hash, digest) ||
        !holy_verify_visit(snapshot, plan_entry, &plan)) goto done;
    if (EVP_DigestFinal_ex(plan.hash, checksum, &checksum_size) != 1 ||
        checksum_size != sizeof checksum) { result = 1; goto done; }
    if (!same_root(root_path, &root_st)) { result = 4; goto done; }
    for (i = 0; i < sizeof checksum; ++i)
        snprintf(output + i * 2, 3, "%02x", checksum[i]);
    output[64] = '\0';
    *paths = plan.count;
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: cannot form install plan (status %d)\n", result);
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
        !state_layout(dir, 0) || !empty_child(dir, "installed") ||
        !empty_child(dir, "index") || !read_generation(dir, &generation)) goto done;
    pending = pending_child(dir, generation, digest, approved);
    if (pending < 0) goto done;
    if (!pending) { result = 6; goto done; }
    result = inspect_plan(root_path, root, generation, digest, hash, &paths);
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
        !empty_child(dir, "installed") || !empty_child(dir, "index") ||
        !read_generation(dir, &generation)) goto done;
    result = pending_child(dir, generation, digest, approved);
    if (result < 0) { result = 1; goto done; }
    if (!result) { result = 6; goto done; }
    if (approved[0]) { result = 5; goto done; }
    result = inspect_plan(root_path, root, generation, digest, actual, &paths);
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
