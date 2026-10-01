/* a user override is a file in the target root, under etc/holy/overrides, whose header
   records what it patches and the conditions it applies under, followed by the patch
   body. this command reads the store and reports every record against the installed
   set, so a record that no longer matches a newer package is named for review instead
   of being applied quietly: the scope and the conditions decide which artifact the
   record is for, and the recorded source and result digests say what the file on disk
   has to be. the store holds no secret and no plan, and nothing here changes. */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "override.h"
#include "config.h"
#include "install.h"
#include "stage.h"
#include "state.h"

#include <dirent.h>
#include <linux/openat2.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define OVERRIDE_BYTES (1024 * 1024)
#define OVERRIDE_LIMIT 4096

struct override_record {
    char *name;
    char *scope;
    char *subject;
    char *source;        /* the source id the scope belongs to, or NULL for any */
    char *path;
    char *arch;
    char *libc;
    char *source_digest;
    char *patch_digest;
    char *result_digest;
    char *owner;
    char *owner_name;
    char *owner_version;
    char *owner_arch;
    char *owner_source;
    char *state;
    char *file;
    char *detail;
    char *body;          /* the patch body, the bytes after the result line */
    size_t body_length;
    int whole_file;      /* the body is the replacement content, not a diff */
};

/* the artifact that owns one path, as the installed records state it. */
struct override_owner {
    const char *path;        /* absolute, as the record states it */
    const char *relative;    /* the installed manifest form of the same path */
    char source[65];         /* the installed source, "-" when it has none */
    char digest[65];
    char name[256];
    char version[256];
    char arch[96];
    char libc[96];
    int found;
    int intact;              /* the installed payload file still matches its manifest */
};

struct override_store {
    struct override_record *records;
    size_t count;
    size_t capacity;
};

static const char overrides_path[] = "etc/holy/overrides";

/* a record names a path of the target root, so it is absolute, has no empty, dot or
   dot-dot component and no trailing slash. an archive entry name is a different form
   and is not what a record holds. */
static int safe_path(const char *path)
{
    const char *part;
    if (!path || path[0] != '/' || strlen(path) > 4096) return 0;
    part = path + 1;
    while (*part) {
        const char *end = strchr(part, '/');
        size_t length = end ? (size_t)(end - part) : strlen(part);
        size_t i;
        if (!length) return 0;
        if (length == 1 && part[0] == '.') return 0;
        if (length == 2 && part[0] == '.' && part[1] == '.') return 0;
        for (i = 0; i < length; ++i)
            if ((unsigned char)part[i] < 32 || (unsigned char)part[i] == 127) return 0;
        if (!end) break;
        part = end + 1;
    }
    return 1;
}

static int valid_digest(const char *value)
{
    size_t i;
    if (!value || strlen(value) != 64) return 0;
    for (i = 0; i < 64; ++i)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f'))) return 0;
    return 1;
}

static int digest_bytes(const void *data, size_t size, char output[65])
{
    unsigned char bytes[32];
    unsigned int length;
    size_t i;
    if (EVP_Digest(data, size, bytes, &length, EVP_sha256(), NULL) != 1 || length != 32)
        return 0;
    for (i = 0; i < 32; ++i) snprintf(output + 2 * i, 3, "%02x", bytes[i]);
    output[64] = 0;
    return 1;
}

/* the file is read through the root, so a record is compared with the bytes the running
   system would use and never with a path of the host running the report. */
static int root_digest(int root, const char *path, char output[65])
{
    struct open_how how = {0};
    unsigned char buffer[65536], bytes[32];
    unsigned int length;
    EVP_MD_CTX *hash = NULL;
    size_t total = 0, i;
    int fd = -1, ok = 0;
    how.flags = O_RDONLY | O_CLOEXEC;
    how.resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS;
    fd = (int)syscall(SYS_openat2, root, path, &how, sizeof how);
    if (fd < 0 || !(hash = EVP_MD_CTX_new()) ||
        EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1) goto done;
    for (;;) {
        ssize_t got = read(fd, buffer, sizeof buffer);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0 || (got == 0 && total > 64 * 1024 * 1024)) goto done;
        if (got && EVP_DigestUpdate(hash, buffer, (size_t)got) != 1) goto done;
        total += (size_t)got;
        if (!got) break;
    }
    if (EVP_DigestFinal_ex(hash, bytes, &length) != 1 || length != 32) goto done;
    for (i = 0; i < 32; ++i) snprintf(output + 2 * i, 3, "%02x", bytes[i]);
    output[64] = 0;
    ok = 1;
done:
    if (hash) EVP_MD_CTX_free(hash);
    if (fd >= 0) close(fd);
    return ok;
}

static int owner_visit(void *context, int root, int instance, const char *digest)
{
    struct override_owner *owner = context;
    int files = openat(instance, "files", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    int owns;
    if (files < 0) return 0;
    owns = holy_install_manifest_owns(files, owner->relative) == 1;
    if (owns) owner->intact = holy_install_check_path(files, root, owner->relative);
    close(files);
    if (!owns) return 0;
    (void)root;
    if (!holy_state_instance_field(instance, "name", owner->name, sizeof owner->name) ||
        !holy_state_instance_field(instance, "version", owner->version, sizeof owner->version) ||
        !holy_state_instance_field(instance, "arch", owner->arch, sizeof owner->arch) ||
        !holy_state_instance_field(instance, "libc", owner->libc, sizeof owner->libc))
        return 0;
    if (!holy_state_instance_source(instance, owner->source)) owner->source[0] = 0;
    memcpy(owner->digest, digest, 65);
    owner->found = 1;
    return 0;
}

/* one header line of the fixed order. the body starts after the result line. */
static int take_field(char **cursor, const char *key, char **value, char **message)
{
    char *end = strchr(*cursor, '\n'), **tokens = NULL, *lex_error = NULL;
    size_t count = 0;
    int ok = 0;
    *value = NULL;
    if (!end || end - *cursor > 64 * 1024 ||
        !holy_lex(*cursor, (size_t)(end - *cursor), &tokens, &count,
                  "override", 0, &lex_error)) {
        if (lex_error) {
            if (message) { free(*message); *message = lex_error; }
            else free(lex_error);
        }
        goto done;
    }
    if (count == 2 && !strcmp(tokens[0], key) && (*value = strdup(tokens[1])))
        ok = (*cursor = end + 1) != NULL;
done:
    free(lex_error);
    holy_tokens_free(tokens, count);
    return ok;
}

static void optional_field(char **cursor, const char *key, char **value)
{
    size_t length = strlen(key);
    char *end = strchr(*cursor, '\n');
    if (!end || (size_t)(end - *cursor) <= length || strncmp(*cursor, key, length) ||
        (*cursor)[length] != ' ') return;
    take_field(cursor, key, value, NULL);
}

static int record_parse(const char *name, const char *data, size_t size,
                        struct override_record *record, char **message)
{
    char *cursor, *scope = NULL, *value = NULL, *arch = NULL, *libc = NULL;
    char *path = NULL, *source = NULL, *patch = NULL, *result = NULL, *copy;
    char *source_id = NULL;
    char computed[65];
    int whole_file = 0, ok = 0;
    *message = NULL;
    memset(record, 0, sizeof *record);
    if (!(copy = malloc(size + 1))) return 0;
    memcpy(copy, data, size);
    copy[size] = 0;
    cursor = copy;
    if (!take_field(&cursor, "format", &value, message) ||
        (strcmp(value, "holy-override-1") && strcmp(value, "holy-override-2"))) {
        *message = strdup("unsupported override format");
        goto done;
    }
    free(value);
    value = NULL;
    if (!take_field(&cursor, "scope", &scope, message)) goto done;
    if (!strcmp(scope, "artifact")) {
        if (!take_field(&cursor, "digest", &value, message)) goto done;
    } else if (!strcmp(scope, "version")) {
        char *package_name = NULL, *package_version = NULL;
        size_t length;
        if (!take_field(&cursor, "name", &package_name, message) ||
            !take_field(&cursor, "version", &package_version, message)) {
            free(package_name);
            free(package_version);
            goto done;
        }
        length = strlen(package_name) + strlen(package_version) + 2;
        value = malloc(length);
        if (value) snprintf(value, length, "%s@%s", package_name, package_version);
        free(package_name);
        free(package_version);
        if (!value) goto done;
    } else if (!strcmp(scope, "package")) {
        if (!take_field(&cursor, "package", &value, message)) goto done;
    } else {
        *message = strdup("unknown override scope");
        goto done;
    }
    /* holy-override-2 narrows the scope to one source, which is what the package
       scope needs to name a package of one source rather than a name several sources
       carry */
    optional_field(&cursor, "source", &source_id);
    if (source_id && strspn(source_id, "0123456789abcdef") != 64) {
        *message = strdup("override record has an invalid source id");
        goto done;
    }
    if (!take_field(&cursor, "path", &path, message)) goto done;
    optional_field(&cursor, "arch", &arch);
    optional_field(&cursor, "libc", &libc);
    if (!take_field(&cursor, "sha256", &source, message) ||
        !take_field(&cursor, "patch", &patch, message) ||
        !take_field(&cursor, "result", &result, message)) goto done;
    if (!safe_path(path) ||
        !valid_digest(source) || !valid_digest(patch) || !valid_digest(result)) {
        *message = strdup("override record has an invalid path or digest");
        goto done;
    }
    if (!digest_bytes(cursor, strlen(cursor), computed) || strcmp(computed, patch)) {
        *message = strdup("override patch body does not match its digest");
        goto done;
    }
    /* a body that is the whole replacement file carries one digest for itself and one
       for the result, so this manager knows what it would write. a record that states
       two digests is diff shaped, and a diff this format does not describe is not
       something to guess at. */
    whole_file = !strcmp(patch, result);
    record->name = strdup(name);
    record->scope = scope;
    record->subject = value;
    record->source = source_id;
    record->path = path;
    record->arch = arch ? arch : strdup("any");
    record->libc = libc ? libc : strdup("any");
    record->source_digest = source;
    record->patch_digest = patch;
    record->result_digest = result;
    record->whole_file = whole_file;
    record->body_length = strlen(cursor);
    record->body = malloc(record->body_length + 1);
    if (!record->body) goto done;
    memcpy(record->body, cursor, record->body_length + 1);
    scope = value = path = arch = libc = source = patch = result = NULL;
    source_id = NULL;
    if (!record->name || !record->scope || !record->subject || !record->path ||
        !record->arch || !record->libc) goto done;
    ok = 1;
done:
    if (!ok && !*message) *message = strdup("override record is incomplete");
    free(scope); free(value); free(path); free(arch); free(libc);
    free(source); free(patch); free(result); free(source_id);
    free(copy);
    return ok;
}

static int record_read(int listing, const char *name, unsigned char **data, size_t *size)
{
    struct stat st;
    unsigned char *buffer = NULL;
    size_t used = 0;
    int fd, ok = 0;
    fd = openat(listing, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 0;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 1 ||
        st.st_size > OVERRIDE_BYTES || !(buffer = malloc((size_t)st.st_size + 1))) goto done;
    while (used < (size_t)st.st_size) {
        ssize_t got = read(fd, buffer + used, (size_t)st.st_size - used);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) goto done;
        used += (size_t)got;
    }
    if (memchr(buffer, 0, used)) goto done;
    buffer[used] = 0;
    *data = buffer;
    *size = used;
    buffer = NULL;
    ok = 1;
done:
    free(buffer);
    close(fd);
    return ok;
}

static int record_push(struct override_store *store, struct override_record *record)
{
    struct override_record *grown;
    if (store->count >= OVERRIDE_LIMIT) return 0;
    if (store->count >= store->capacity) {
        size_t capacity = store->capacity ? store->capacity * 2 : 16;
        grown = realloc(store->records, capacity * sizeof *grown);
        if (!grown) return 0;
        store->records = grown;
        store->capacity = capacity;
    }
    store->records[store->count++] = *record;
    memset(record, 0, sizeof *record);
    return 1;
}

/* the conditions a record states, compared with the artifact that owns the file. an
   arch or libc the record leaves out is any, and a scope naming another artifact,
   version or package is out of scope rather than a match. */
static int scope_source_mismatch(const struct override_record *record,
                                 const struct override_owner *owner)
{
    return record->source && (!owner->source[0] ||
                              strcmp(record->source, owner->source));
}

static int scope_matches(const struct override_record *record,
                         const struct override_owner *owner)
{
    if (scope_source_mismatch(record, owner)) return 0;
    if (strcmp(record->arch, "any") && strcmp(record->arch, owner->arch)) return 0;
    if (strcmp(record->libc, "any") && strcmp(record->libc, owner->libc)) return 0;
    if (!strcmp(record->scope, "artifact"))
        return !strcmp(record->subject, owner->digest);
    if (!strcmp(record->scope, "package"))
        return !strcmp(record->subject, owner->name);
    if (!strcmp(record->scope, "version")) {
        size_t length = strlen(owner->name) + strlen(owner->version) + 2;
        char *joined = malloc(length);
        int same;
        if (!joined) return 0;
        snprintf(joined, length, "%s@%s", owner->name, owner->version);
        same = !strcmp(record->subject, joined);
        free(joined);
        return same;
    }
    return 0;
}

static void record_state(struct override_record *record, int root,
                         const struct override_owner *owner)
{
    char digest[65];
    if (!owner->found) {
        record->state = strdup("not-installed");
        record->detail = strdup("no installed artifact owns this path");
        return;
    }
    record->owner = strdup(owner->digest);
    record->owner_name = strdup(owner->name);
    record->owner_version = strdup(owner->version);
    record->owner_arch = strdup(owner->arch);
    record->owner_source = strdup(owner->source[0] ? owner->source : "-");
    if (scope_source_mismatch(record, owner)) {
        record->state = strdup("review");
        record->detail = strdup("the record names another source");
        return;
    }
    if (!scope_matches(record, owner)) {
        record->state = strdup("review");
        record->detail = strdup("scope or conditions name another artifact");
        return;
    }
    if (!root_digest(root, record->path, digest)) {
        record->state = strdup("unreadable");
        record->detail = strdup("the file is not readable through the root");
        return;
    }
    if (!strcmp(digest, record->result_digest)) record->state = strdup("applied");
    else if (!strcmp(digest, record->source_digest)) record->state = strdup("pending");
    else {
        record->state = strdup("review");
        record->detail = strdup("the file is neither the recorded source nor its result");
    }
}

static int needs_review(const char *state)
{
    return !strcmp(state, "review") || !strcmp(state, "unreadable");
}

static void print_string(const char *value)
{
    const unsigned char *p = (const unsigned char *)(value ? value : "");
    putchar('"');
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p < 32 || *p >= 127) printf("\\u%04x", (unsigned int)*p);
        else putchar(*p);
    }
    putchar('"');
}

static void record_print(const struct override_record *record, int json)
{
    if (json) {
        printf("{\"schema\":\"holy-override-report-1\",\"type\":\"override\",\"name\":");
        print_string(record->name);
        printf(",\"scope\":");
        print_string(record->scope);
        printf(",\"subject\":");
        print_string(record->subject);
        if (record->source) {
            printf(",\"source\":");
            print_string(record->source);
        }
        printf(",\"path\":");
        print_string(record->path);
        printf(",\"arch\":");
        print_string(record->arch);
        printf(",\"libc\":");
        print_string(record->libc);
        printf(",\"source_sha256\":");
        print_string(record->source_digest);
        printf(",\"result_sha256\":");
        print_string(record->result_digest);
        if (record->owner) {
            printf(",\"owner\":");
            print_string(record->owner);
            printf(",\"owner_name\":");
            print_string(record->owner_name);
            printf(",\"owner_version\":");
            print_string(record->owner_version);
        }
        printf(",\"state\":");
        print_string(record->state);
        printf(",\"form\":");
        print_string(record->patch_digest ? (record->whole_file ? "whole-file" : "diff") :
                    "none");
        if (record->detail) {
            printf(",\"detail\":");
            print_string(record->detail);
        }
        printf("}\n");
        return;
    }
    printf("override %s state %s", record->name, record->state);
    if (record->scope) printf(" scope %s %s", record->scope, record->subject);
    if (record->source) printf(" source %s", record->source);
    if (record->path) printf(" path %s", record->path);
    if (record->arch) printf(" arch %s", record->arch);
    if (record->libc) printf(" libc %s", record->libc);
    putchar('\n');
    if (record->owner)
        printf("override-owner %s %s %s %s %s source %s\n", record->name, record->owner,
               record->owner_name, record->owner_version, record->owner_arch,
               record->owner_source[0] ? record->owner_source : "-");
    if (record->patch_digest)
        printf("override-form %s %s\n", record->name,
               record->whole_file ? "whole-file" : "diff");
    if (record->detail) printf("override-detail %s %s\n", record->name, record->detail);
}

static void store_free(struct override_store *store)
{
    size_t i;
    for (i = 0; i < store->count; ++i) {
        struct override_record *record = &store->records[i];
        free(record->name); free(record->scope); free(record->subject);
        free(record->source); free(record->path); free(record->arch); free(record->libc);
        free(record->source_digest); free(record->patch_digest);
        free(record->result_digest); free(record->owner); free(record->owner_name);
        free(record->owner_version); free(record->owner_arch); free(record->owner_source);
        free(record->state); free(record->file); free(record->detail);
        free(record->body);
    }
    free(store->records);
    memset(store, 0, sizeof *store);
}

/* the database is checked before the store is read, so a root that cannot say which
   artifact owns a path has no answer to give at all, not even an empty one. */
static int database_visit(void *context, int root, int instance, const char *digest)
{
    (void)context; (void)root; (void)instance; (void)digest;
    return 0;
}

static int names_order(const void *left, const void *right)
{
    return strcmp(*(char *const *)left, *(char *const *)right);
}

static void summary(size_t records, size_t applied, size_t pending, size_t absent,
                    size_t review, size_t invalid, size_t whole_file, int json)
{
    if (json)
        printf("{\"schema\":\"holy-override-report-1\",\"type\":\"summary\",\"records\":%zu,\"applied\":%zu,\"pending\":%zu,\"not-installed\":%zu,\"review\":%zu,\"invalid\":%zu,\"whole-file\":%zu,\"diff\":%zu}\n",
               records, applied, pending, absent, review, invalid, whole_file,
               records - invalid - whole_file);
    else
        printf("override-summary records %zu applied %zu pending %zu not-installed %zu review %zu invalid %zu whole-file %zu diff %zu read-only\n",
               records, applied, pending, absent, review, invalid, whole_file,
               records - invalid - whole_file);
}

/* loads every record of the store in name order. a record that is not one is kept with
   its own state, so a report names it instead of dropping it. */
static int store_load(int listing, struct override_store *store, size_t *invalid)
{
    char **names = NULL;
    size_t count = 0, i;
    DIR *directory;
    int ok = 1;
    if (!(directory = fdopendir(dup(listing)))) return 0;
    errno = 0;
    while (names == NULL || count < OVERRIDE_LIMIT) {
        struct dirent *entry = readdir(directory);
        char **grown;
        size_t length;
        if (!entry) break;
        length = strlen(entry->d_name);
        if (length < 10 || strcmp(entry->d_name + length - 9, ".override")) continue;
        grown = realloc(names, (count + 1) * sizeof *grown);
        if (!grown || !(grown[count] = strdup(entry->d_name))) { ok = 0; goto done; }
        names = grown;
        ++count;
    }
    if (count) qsort(names, count, sizeof *names, names_order);
    for (i = 0; i < count; ++i) {
        struct override_record record;
        unsigned char *data = NULL;
        size_t size = 0;
        char *message = NULL;
        if (!record_read(listing, names[i], &data, &size)) {
            struct override_record unreadable = {0};
            unreadable.name = strdup(names[i]);
            unreadable.state = strdup("unreadable");
            unreadable.detail = strdup("override file is not a readable regular file");
            if (!record_push(store, &unreadable)) { ok = 0; goto done; }
            ++*invalid;
            continue;
        }
        if (!record_parse(names[i], (const char *)data, size, &record, &message)) {
            struct override_record broken = {0};
            broken.name = strdup(names[i]);
            broken.state = strdup("invalid");
            broken.detail = message ? message : strdup("not a valid holy-override-1 record");
            free(data);
            if (!record_push(store, &broken)) { ok = 0; goto done; }
            ++*invalid;
            continue;
        }
        free(data);
        if (!record_push(store, &record)) { ok = 0; goto done; }
    }
done:
    for (i = 0; i < count; ++i) free(names[i]);
    free(names);
    return ok;
}

/* the state of one record against the installed set. an absent store has no record. */
static int store_state(struct override_store *store, const char *root_path, int root,
                       unsigned long long *generation)
{
    size_t i;
    for (i = 0; i < store->count; ++i) {
        struct override_record *record = &store->records[i];
        struct override_owner owner;
        int visit;
        if (!record->path) continue;
        memset(&owner, 0, sizeof owner);
        owner.path = record->path;
        owner.relative = record->path + 1;
        visit = holy_state_visit(root_path, owner_visit, &owner, generation);
        if (visit) {
            free(record->state);
            record->state = strdup("unreadable");
            free(record->detail);
            record->detail = strdup(visit == 5 ? "unfinished transaction" :
                                    "the installed set could not be read");
            continue;
        }
        record_state(record, root, &owner);
    }
    return 0;
}

int holy_override_list(const char *root_path, int json)
{
    struct override_store store = {0};
    unsigned long long generation = 0;
    size_t i, applied = 0, pending = 0, absent = 0, review = 0, invalid = 0, whole_file = 0;
    int status = 1, root = -1, listing = -1, visit = 0;

    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) {
        fputs("holypkg: target root unavailable\n", stderr);
        return 6;
    }
    visit = holy_state_visit(root_path, database_visit, NULL, &generation);
    if (visit == 5) {
        fputs("holypkg: unfinished transaction; resolve it before reading overrides\n", stderr);
        return 5;
    }
    if (visit) {
        fputs("holypkg: installed set unavailable\n", stderr);
        return 6;
    }
    listing = openat(root, overrides_path,
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (listing < 0) {
        if (errno == ENOENT) {
            summary(0, 0, 0, 0, 0, 0, 0, json);
            status = ferror(stdout) ? 1 : 0;
            goto done;
        }
        fputs("holypkg: override store unavailable\n", stderr);
        status = 6;
        goto done;
    }
    if (!store_load(listing, &store, &invalid) ||
        store_state(&store, root_path, root, &generation)) {
        status = 1;
        goto done;
    }
    for (i = 0; i < store.count; ++i) {
        struct override_record *record = &store.records[i];
        record_print(record, json);
        if (record->whole_file) ++whole_file;
        if (!strcmp(record->state, "applied")) ++applied;
        else if (!strcmp(record->state, "pending")) ++pending;
        else if (!strcmp(record->state, "not-installed")) ++absent;
        else if (needs_review(record->state)) ++review;
    }
    summary(store.count, applied, pending, absent, review, invalid, whole_file, json);
    if (ferror(stdout)) status = 1;
    else if (invalid) status = 2;
    else if (review) status = 3;
    else status = 0;
done:
    if (listing >= 0) close(listing);
    if (root >= 0) close(root);
    store_free(&store);
    return status;
}

/* the state of the file a record names, read through the root. it needs no database
   lock, so a plan and the apply that follows it read the same bytes. */
static void record_file_state(struct override_record *record, int root)
{
    char digest[65];
    if (!root_digest(root, record->path, digest)) {
        record->file = strdup("absent");
        return;
    }
    if (!strcmp(digest, record->result_digest)) record->file = strdup("applied");
    else if (!strcmp(digest, record->source_digest)) record->file = strdup("pending");
    else record->file = strdup("review");
}

void holy_override_records_free(struct holy_override_record_info *records, size_t count)
{
    size_t i;
    for (i = 0; i < count; ++i) {
        free(records[i].name);
        free(records[i].path);
        free(records[i].file);
        free(records[i].patch);
    }
    free(records);
}

int holy_override_records(const char *root_path, struct holy_override_record_info **records,
                          size_t *record_count)
{
    struct override_store store = {0};
    struct holy_override_record_info *found = NULL;
    size_t invalid = 0, count = 0, i;
    int status = 1, root = -1, listing = -1;

    *records = NULL;
    *record_count = 0;
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) return 1;
    listing = openat(root, overrides_path,
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (listing < 0) {
        status = errno == ENOENT ? 0 : 1;
        goto done;
    }
    if (!store_load(listing, &store, &invalid)) goto done;
    for (i = 0; i < store.count; ++i) {
        struct override_record *record = &store.records[i];
        struct holy_override_record_info info = {0};
        struct holy_override_record_info *grown;
        if (!record->path || !record->patch_digest) continue;
        record_file_state(record, root);
        info.name = strdup(record->name);
        info.path = strdup(record->path);
        info.file = record->file ? strdup(record->file) : NULL;
        info.patch = strdup(record->patch_digest);
        if (!info.name || !info.path || !info.file || !info.patch) {
            free(info.name); free(info.path); free(info.file); free(info.patch);
            goto done;
        }
        grown = realloc(found, (count + 1) * sizeof *grown);
        if (!grown) {
            free(info.name); free(info.path); free(info.file); free(info.patch);
            goto done;
        }
        found = grown;
        found[count++] = info;
    }
    *records = found;
    *record_count = count;
    status = 0;
done:
    if (listing >= 0) close(listing);
    if (root >= 0) close(root);
    store_free(&store);
    if (status) holy_override_records_free(found, count);
    return status;
}

static int plan_name_valid(const char *name)
{
    size_t length;
    if (!name || !*name) return 0;
    length = strlen(name);
    if (length < 10 || length > 255 || strcmp(name + length - 9, ".override")) return 0;
    if (strchr(name, '/')) return 0;
    return 1;
}

/* what applying one record would write, derived from the record, the artifact that
   owns the path and the identity of the target root. every refusal is a decision this
   manager will not make, and a record whose result is already in place is the work
   already done, which the apply reports as done and the plan reports as a decision. */
struct override_plan {
    struct override_record record;
    struct override_owner owner;
    unsigned long long generation;
    int applied;
    char hash[65];
};

static void plan_forget(struct override_plan *plan)
{
    struct override_record *record = &plan->record;
    free(record->name); free(record->scope); free(record->subject);
    free(record->source); free(record->path); free(record->arch); free(record->libc);
    free(record->source_digest); free(record->patch_digest);
    free(record->result_digest); free(record->body);
    memset(plan, 0, sizeof *plan);
}

static int plan_derive(const char *name, const char *root_path, struct override_plan *plan,
                       char current[65])
{
    char observed[65], *file = current ? current : observed;
    struct stat root_state;
    unsigned char digest[32];
    unsigned int length;
    EVP_MD_CTX *hash = NULL;
    char *message = NULL;
    int root = -1, listing = -1, status = 1, visit, i;

    memset(plan, 0, sizeof *plan);
    observed[0] = 0;
    if (!plan_name_valid(name)) return 2;
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0 || fstat(root, &root_state)) {
        fputs("holypkg: target root unavailable\n", stderr);
        return 6;
    }
    listing = openat(root, overrides_path,
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (listing < 0) {
        fprintf(stderr, "holypkg: no override record %s in the store\n", name);
        status = 6;
        goto done;
    }
    {
        unsigned char *data = NULL;
        size_t size = 0;
        if (!record_read(listing, name, &data, &size)) {
            fprintf(stderr, "holypkg: override %s is not a readable record\n", name);
            status = 2;
            goto done;
        }
        if (!record_parse(name, (const char *)data, size, &plan->record, &message)) {
            fprintf(stderr, "holypkg: override %s: %s\n", name,
                    message ? message : "not a valid record");
            status = 2;
            goto done;
        }
        free(data);
    }
    if (!plan->record.whole_file) {
        fprintf(stderr, "holypkg: override %s is a diff record; this manager does not"
                        " apply a diff it does not describe\n", name);
        status = 3;
        goto done;
    }
    plan->owner.path = plan->record.path;
    plan->owner.relative = plan->record.path + 1;
    visit = holy_state_visit(root_path, owner_visit, &plan->owner, &plan->generation);
    if (visit) {
        fputs("holypkg: installed set unavailable\n", stderr);
        status = visit == 5 ? 5 : 6;
        goto done;
    }
    if (!plan->owner.found) {
        fprintf(stderr, "holypkg: no installed artifact owns %s\n", plan->record.path);
        status = 3;
        goto done;
    }
    /* the report calls a record whose scope names another artifact a review, and the
       plan holds to the same fact: a record scoped to one version does not write over
       the file of another, while one scoped to the package reaches every version it
       does not name */
    if (!scope_matches(&plan->record, &plan->owner)) {
        fprintf(stderr, "holypkg: override %s is scoped to %s %s%s%s; the artifact owning"
                        " %s is %s %s source %s\n", name, plan->record.scope,
                plan->record.subject, plan->record.source ? " source " : "",
                plan->record.source ? plan->record.source : "", plan->record.path,
                plan->owner.name, plan->owner.version,
                plan->owner.source[0] ? plan->owner.source : "none");
        status = 3;
        goto done;
    }
    if (plan->owner.intact != 1) {
        fprintf(stderr, "holypkg: the installed payload file %s drifted\n", plan->record.path);
        status = 3;
        goto done;
    }
    if (!root_digest(root, plan->record.path, file)) {
        fprintf(stderr, "holypkg: %s is not readable through the target root\n",
                plan->record.path);
        status = 6;
        goto done;
    }
    if (!strcmp(file, plan->record.result_digest)) plan->applied = 1;
    else if (strcmp(file, plan->record.source_digest)) {
        fprintf(stderr, "holypkg: override %s does not apply to the file in place\n", name);
        status = 3;
        goto done;
    }
    if (!(hash = EVP_MD_CTX_new()) ||
        EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1) { status = 1; goto done; }
    {
        char line[1024];
        int used = snprintf(line, sizeof line,
                            "format holy-override-plan-1\nname %s\npath %s\n"
                            "owner %s\nsource %s\nresult %s\npatch %s\nroot %ju %ju\n"
                            "generation %llu\n",
                            plan->record.name, plan->record.path, plan->owner.digest,
                            plan->record.source_digest, plan->record.result_digest,
                            plan->record.patch_digest, (uintmax_t)root_state.st_dev,
                            (uintmax_t)root_state.st_ino, plan->generation);
        if (used < 0 || (size_t)used >= sizeof line ||
            EVP_DigestUpdate(hash, line, (size_t)used) != 1) { status = 1; goto done; }
    }
    if (EVP_DigestFinal_ex(hash, digest, &length) != 1 || length != 32) {
        status = 1;
        goto done;
    }
    for (i = 0; i < 32; ++i) snprintf(plan->hash + 2 * i, 3, "%02x", digest[i]);
    plan->hash[64] = 0;
    status = 0;
done:
    if (hash) EVP_MD_CTX_free(hash);
    free(message);
    if (listing >= 0) close(listing);
    if (root >= 0) close(root);
    if (status) plan_forget(plan);
    return status;
}

int holy_override_plan(const char *name, const char *root_path, int json)
{
    struct override_plan plan = {0};
    int status = plan_derive(name, root_path, &plan, NULL);
    if (status) return status;
    if (plan.applied) {
        fprintf(stderr, "holypkg: override %s is already applied\n", name);
        plan_forget(&plan);
        return 3;
    }
    if (json)
        printf("{\"schema\":\"holy-override-plan-1\",\"type\":\"plan\",\"name\":");
    else
        printf("override-plan %s path %s owner %s %s %s source %s result %s patch %s form whole-file\n",
               plan.record.name, plan.record.path, plan.owner.digest, plan.owner.name,
               plan.owner.version, plan.record.source_digest, plan.record.result_digest,
               plan.record.patch_digest);
    if (json) {
        print_string(plan.record.name);
        printf(",\"path\":");
        print_string(plan.record.path);
        printf(",\"owner\":");
        print_string(plan.owner.digest);
        printf(",\"owner_name\":");
        print_string(plan.owner.name);
        printf(",\"owner_version\":");
        print_string(plan.owner.version);
        printf(",\"source_sha256\":");
        print_string(plan.record.source_digest);
        printf(",\"result_sha256\":");
        print_string(plan.record.result_digest);
        printf(",\"patch_sha256\":");
        print_string(plan.record.patch_digest);
        printf(",\"form\":\"whole-file\",\"generation\":%llu,\"sha256\":",
                plan.generation);
        print_string(plan.hash);
        printf("}\n");
    } else
        printf("override-plan-sha256 %s read-only\n", plan.hash);
    status = ferror(stdout) ? 1 : 0;
    plan_forget(&plan);
    return status;
}

/* the body is written beside the file it replaces and renamed over it, so the path
   keeps its name and the content is never half written. the mode of the file that is
   there now is the mode the replacement keeps, since a record changes content and not
   permissions. */
static int apply_write(int root, const char *path, const char *body, size_t size,
                       const char **reason)
{
    struct open_how how = {0};
    struct stat current;
    char *parent = strdup(path), *slash, temporary[43], base[64];
    size_t used = 0;
    int dir = -1, existing = -1, fd = -1, ok = 0;

    if (!parent) return 0;
    if (!(slash = strrchr(parent, '/'))) { *reason = "path has no parent"; goto done; }
    snprintf(base, sizeof base, "%s", slash + 1);
    *slash = 0;
    how.flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC;
    how.resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS;
    dir = (int)syscall(SYS_openat2, root, parent, &how, sizeof how);
    if (dir < 0) { *reason = "parent directory is not readable through the root"; goto done; }
    how.flags = O_RDONLY | O_CLOEXEC;
    existing = (int)syscall(SYS_openat2, root, path, &how, sizeof how);
    if (existing < 0 || fstat(existing, &current) || !S_ISREG(current.st_mode)) {
        *reason = "the file is not a regular file through the root";
        goto done;
    }
    fd = holy_spool_at(dir, temporary);
    if (fd < 0) { *reason = "could not create a temporary file beside the target"; goto done; }
    while (used < size) {
        ssize_t written = write(fd, body + used, size - used);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) { *reason = "could not write the replacement"; goto done; }
        used += (size_t)written;
    }
    if (fchmod(fd, current.st_mode & 07777) || fsync(fd) ||
        renameat(dir, temporary, dir, base) || fsync(dir)) {
        *reason = "could not publish the replacement";
        goto done;
    }
    temporary[0] = 0;
    ok = 1;
done:
    if (!ok && temporary[0]) unlinkat(dir, temporary, 0);
    if (fd >= 0) close(fd);
    if (existing >= 0) close(existing);
    if (dir >= 0) close(dir);
    free(parent);
    return ok;
}

int holy_override_apply(const char *name, const char *approved, const char *root_path,
                        int json)
{
    struct override_plan plan = {0};
    const char *reason = "the write failed";
    char current[65];
    int root = -1, dir = -1, status, state = 1;
    unsigned long long locked = 0;

    if (!approved || strlen(approved) != 64 ||
        strspn(approved, "0123456789abcdef") != 64) return 2;
    status = plan_derive(name, root_path, &plan, current);
    if (status) return status;
    if (strcmp(plan.hash, approved)) {
        fprintf(stderr, "holypkg: the prepared plan changed before the apply\n");
        plan_forget(&plan);
        return 3;
    }
    if (plan.applied) {
        if (json)
            printf("{\"schema\":\"holy-override-apply-1\",\"type\":\"applied\",\"name\":");
        else
            printf("override-applied %s path %s result %s already\n", plan.record.name,
                   plan.record.path, plan.record.result_digest);
        if (json) {
            print_string(plan.record.name);
            printf(",\"result_sha256\":");
            print_string(plan.record.result_digest);
            printf(",\"state\":\"already\"}\n");
        }
        status = ferror(stdout) ? 1 : 0;
        plan_forget(&plan);
        return status;
    }
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) { plan_forget(&plan); return 6; }
    /* the file is written under the database writer lock, so no set, update or removal
       is halfway while a record replaces a file one of them owns */
    dir = holy_state_lock(root_path, 1, &locked, &state);
    if (dir < 0) { status = state; goto done; }
    /* the writer lock makes the installed set what the plan derived: every mutation
       publishes a new generation, so an unchanged generation is the proof. the shared
       walk the derivation used cannot be repeated here, since it would wait for the
       lock this call holds. */
    if (locked != plan.generation) {
        fprintf(stderr, "holypkg: the installed generation changed under the plan\n");
        status = 3;
        goto done;
    }
    if (!root_digest(root, plan.record.path, current) ||
        strcmp(current, plan.record.source_digest)) {
        fprintf(stderr, "holypkg: %s no longer is what the record applies to\n",
                plan.record.path);
        status = 3;
        goto done;
    }
    if (!apply_write(root, plan.record.path, plan.record.body, plan.record.body_length,
                     &reason)) {
        fprintf(stderr, "holypkg: override %s: %s\n", name, reason);
        status = 1;
        goto done;
    }
    if (json)
        printf("{\"schema\":\"holy-override-apply-1\",\"type\":\"applied\",\"name\":");
    else
        printf("override-applied %s path %s result %s owner %s generation %llu\n",
               plan.record.name, plan.record.path, plan.record.result_digest,
               plan.owner.digest, locked);
    if (json) {
        print_string(plan.record.name);
        printf(",\"path\":");
        print_string(plan.record.path);
        printf(",\"result_sha256\":");
        print_string(plan.record.result_digest);
        printf(",\"owner\":");
        print_string(plan.owner.digest);
        printf(",\"generation\":%llu,\"state\":\"written\"}\n", locked);
    }
    status = ferror(stdout) ? 1 : 0;
done:
    if (dir >= 0) close(dir);
    if (root >= 0) close(root);
    plan_forget(&plan);
    return status;
}
