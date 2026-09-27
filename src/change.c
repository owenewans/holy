#define _POSIX_C_SOURCE 200809L
#include "change.h"
#include "install.h"
#include "package.h"

#include <archive.h>
#include <archive_entry.h>
#include <errno.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct entries {
    struct holy_manifest_entry *items;
    size_t count, capacity;
};

static void free_entry(struct holy_manifest_entry *e)
{
    free((char *)e->path); free((char *)e->link);
    free((char *)e->hardlink); free((char *)e->group); free((unsigned char *)e->hash);
}

void holy_file_plan_free(struct holy_file_plan *plan)
{
    size_t i;
    for (i = 0; i < plan->old_count; ++i) free_entry(&plan->old_entries[i]);
    for (i = 0; i < plan->new_count; ++i) free_entry(&plan->new_entries[i]);
    free(plan->old_entries); free(plan->new_entries); free(plan->changes);
    memset(plan, 0, sizeof *plan);
}

static int collect(void *context, const struct holy_manifest_entry *entry)
{
    struct entries *entries = context;
    struct holy_manifest_entry *copy;
    if (entries->count == entries->capacity) {
        size_t capacity = entries->capacity ? entries->capacity * 2 : 32;
        void *next;
        if (capacity < entries->capacity || capacity > SIZE_MAX / sizeof *copy) return 0;
        next = realloc(entries->items, capacity * sizeof *copy);
        if (!next) return 0;
        entries->items = next; entries->capacity = capacity;
    }
    copy = &entries->items[entries->count++];
    memset(copy, 0, sizeof *copy);
    copy->path = strdup(entry->path);
    copy->link = entry->link ? strdup(entry->link) : NULL;
    copy->hardlink = entry->hardlink ? strdup(entry->hardlink) : NULL;
    copy->group = entry->group ? strdup(entry->group) : NULL;
    copy->hash = entry->hash ? malloc(32) : NULL;
    if (copy->hash) memcpy((unsigned char *)copy->hash, entry->hash, 32);
    copy->size = entry->size; copy->mode = entry->mode;
    copy->uid = entry->uid; copy->gid = entry->gid; copy->directory = entry->directory;
    return copy->path && (!entry->link || copy->link) && (!entry->hardlink || copy->hardlink) &&
           (!entry->group || copy->group) && (!entry->hash || copy->hash);
}

static int entry_order(const void *left, const void *right)
{
    return strcmp(((const struct holy_manifest_entry *)left)->path,
                  ((const struct holy_manifest_entry *)right)->path);
}

static int same_string(const char *a, const char *b)
{
    return a && b ? !strcmp(a, b) : a == b;
}

static int same_entry(const struct holy_manifest_entry *a, const struct holy_manifest_entry *b)
{
    return a->directory == b->directory && a->mode == b->mode && a->uid == b->uid &&
           a->gid == b->gid && a->size == b->size && same_string(a->link, b->link) &&
           same_string(a->hardlink, b->hardlink) && same_string(a->group, b->group) &&
           (a->directory || a->link || (a->hash && b->hash && !memcmp(a->hash, b->hash, 32)));
}

static int change_id(const struct holy_file_plan *plan, const char *path, char output[65])
{
    unsigned char bytes[32];
    unsigned length;
    size_t i;
    int ok;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
         EVP_DigestUpdate(ctx, "holy-file-change-1", sizeof "holy-file-change-1") == 1 &&
         EVP_DigestUpdate(ctx, plan->old_artifact, 65) == 1 &&
         EVP_DigestUpdate(ctx, plan->new_artifact, 65) == 1 &&
         EVP_DigestUpdate(ctx, path, strlen(path) + 1) == 1 &&
         EVP_DigestFinal_ex(ctx, bytes, &length) == 1 && length == 32;
    if (ok) for (i = 0; i < 32; ++i) snprintf(output + i * 2, 3, "%02x", bytes[i]);
    EVP_MD_CTX_free(ctx);
    return ok;
}

int holy_file_plan_collect(const char *old_snapshot, const char *new_snapshot,
                           struct holy_file_plan *plan)
{
    struct holy_package_identity old = {0}, next = {0};
    struct entries before = {0}, after = {0};
    size_t i = 0, j = 0, maximum;
    int ok = 0;
    memset(plan, 0, sizeof *plan);
    if (!holy_package_identity(old_snapshot, &old) || !holy_package_identity(new_snapshot, &next) ||
        !holy_verify_visit(old_snapshot, collect, &before) ||
        !holy_verify_visit(new_snapshot, collect, &after)) goto done;
    memcpy(plan->old_artifact, old.digest, 65); memcpy(plan->new_artifact, next.digest, 65);
    if (before.count) qsort(before.items, before.count, sizeof *before.items, entry_order);
    if (after.count) qsort(after.items, after.count, sizeof *after.items, entry_order);
    if (before.count > SIZE_MAX - after.count) goto done;
    maximum = before.count + after.count;
    if (maximum > SIZE_MAX / sizeof *plan->changes) goto done;
    plan->changes = calloc(maximum ? maximum : 1, sizeof *plan->changes);
    if (!plan->changes) goto done;
    while (i < before.count || j < after.count) {
        struct holy_file_change *change = &plan->changes[plan->count++];
        int order = i == before.count ? 1 : j == after.count ? -1 :
                    strcmp(before.items[i].path, after.items[j].path);
        if (order <= 0) change->before = &before.items[i++];
        if (order >= 0) change->after = &after.items[j++];
        change->kind = !change->before ? HOLY_ADD : !change->after ? HOLY_REMOVE :
                       same_entry(change->before, change->after) ? HOLY_RETAIN : HOLY_REPLACE;
        if (!change_id(plan, change->after ? change->after->path : change->before->path, change->id)) goto done;
    }
    ok = 1;
done:
    plan->old_entries = before.items; plan->old_count = before.count;
    plan->new_entries = after.items; plan->new_count = after.count;
    holy_package_identity_free(&old); holy_package_identity_free(&next);
    return ok;
}

static void quote(FILE *out, const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    fputc('"', out);
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') fprintf(out, "\\%c", *p);
        else if (*p < 32 || *p >= 127) fprintf(out, "\\x%02x", *p);
        else fputc(*p, out);
    }
    fputc('"', out);
}

static void entry_record(FILE *out, const char *side, const struct holy_manifest_entry *e)
{
    size_t i;
    fprintf(out, "%s ", side);
    if (!e) { fputs("absent\n", out); return; }
    fprintf(out, "%s ", e->directory ? "dir" : e->link ? "symlink" : e->hardlink ? "hardlink" : "file");
    quote(out, e->path);
    fprintf(out, " %o %lld %lld %lld ", e->mode, e->uid, e->gid, e->size);
    if (e->directory || e->link) fputc('-', out);
    else for (i = 0; i < 32; ++i) fprintf(out, "%02x", e->hash[i]);
    fputc(' ', out); quote(out, e->link ? e->link : e->hardlink ? e->hardlink : "-");
    fputc(' ', out); quote(out, e->group ? e->group : "-"); fputc('\n', out);
}

int holy_file_plan_record(const struct holy_file_plan *plan, char **record, size_t *size)
{
    static const char *const names[] = {"retain", "add", "replace", "remove"};
    FILE *out;
    size_t i;
    int ok;
    *record = NULL; *size = 0;
    out = open_memstream(record, size);
    if (!out) return 0;
    fprintf(out, "format holy-file-plan-1\nold %s\nnew %s\n", plan->old_artifact, plan->new_artifact);
    for (i = 0; i < plan->count; ++i) {
        const struct holy_file_change *change = &plan->changes[i];
        fprintf(out, "change %s %s\n", change->id, names[change->kind]);
        entry_record(out, "before", change->before); entry_record(out, "after", change->after);
    }
    ok = !ferror(out);
    if (fclose(out)) ok = 0;
    if (!ok) { free(*record); *record = NULL; *size = 0; }
    return ok;
}

static int supported(const struct holy_manifest_entry *entry)
{
    return !entry || (!entry->hardlink && !entry->group && !(entry->mode & 07000) &&
                     entry->uid == (long long)geteuid() && entry->gid == (long long)getegid() &&
                     (!entry->link || entry->link[0] != '/'));
}

int holy_file_plan_check(const struct holy_file_plan *plan, int root, int recovering, size_t *failed)
{
    size_t i;
    for (i = 0; i < plan->count; ++i) {
        const struct holy_file_change *c = &plan->changes[i];
        int result = 0;
        if (failed) *failed = i;
        if (!supported(c->before) || !supported(c->after)) return 6;
        if ((c->before && c->before->directory) || (c->after && c->after->directory)) {
            const struct holy_manifest_entry *e = c->before ? c->before : c->after;
            if (c->kind == HOLY_REPLACE) return 6;
            result = holy_install_check_entry(root, e);
            if (result != 1) return c->kind == HOLY_ADD && result == 2 ? 6 : 4;
        } else if (!holy_install_transition_check(root, c->before, c->after, recovering)) return 4;
    }
    if (failed) *failed = plan->count;
    return 0;
}

static void temporary_name(const struct holy_file_change *change, char name[78])
{
    snprintf(name, 78, ".holy-update-%s", change->id);
}

int holy_file_plan_reservations(const struct holy_file_plan *plan, int root)
{
    size_t i;
    for (i = 0; i < plan->count; ++i) {
        const struct holy_file_change *c = &plan->changes[i];
        char name[78];
        if (!c->after || c->after->directory || c->kind == HOLY_RETAIN) continue;
        temporary_name(c, name);
        if (holy_install_temporary_state(root, c->after, name) != 2) return 4;
    }
    return 0;
}

static size_t find_change(const struct holy_file_plan *plan, const char *path)
{
    size_t low = 0, high = plan->count;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        const struct holy_file_change *c = &plan->changes[middle];
        const char *name = c->after ? c->after->path : c->before->path;
        int order = strcmp(name, path);
        if (!order) return middle;
        if (order < 0) low = middle + 1;
        else high = middle;
    }
    return plan->count;
}

int holy_file_plan_stage(const struct holy_file_plan *plan, const char *snapshot,
                         int root, int recovering, size_t *failed)
{
    struct archive *archive = NULL;
    struct archive_entry *entry;
    struct holy_package_identity identity = {0};
    FILE *content = NULL;
    unsigned char *seen = NULL;
    int result = 1, status;
    size_t i;
    result = holy_file_plan_check(plan, root, recovering, failed);
    if (result) return result;
    if (!recovering && (result = holy_file_plan_reservations(plan, root))) return result;
    result = 6;
    if (!holy_package_identity(snapshot, &identity) || strcmp(identity.digest, plan->new_artifact)) goto done;
    result = 1;
    seen = calloc(plan->count ? plan->count : 1, 1);
    archive = archive_read_new();
    if (!seen || !archive || archive_read_support_filter_lz4(archive) != ARCHIVE_OK ||
        archive_read_support_format_tar(archive) != ARCHIVE_OK ||
        archive_read_open_filename(archive, snapshot, 65536) != ARCHIVE_OK) goto done;
    while ((status = archive_read_next_header(archive, &entry)) == ARCHIVE_OK) {
        const char *path = archive_entry_pathname(entry);
        const struct holy_file_change *c;
        char name[78];
        int prepared;
        if (!path || strncmp(path, "DATA/", 5)) {
            if (archive_read_data_skip(archive) != ARCHIVE_OK) goto done;
            continue;
        }
        i = find_change(plan, path + 5);
        if (i == plan->count || !(c = &plan->changes[i])->after ||
            c->after->directory || c->kind == HOLY_RETAIN) {
            if (archive_read_data_skip(archive) != ARCHIVE_OK) goto done;
            continue;
        }
        if (failed) *failed = i;
        if (seen[i]++) goto done;
        temporary_name(c, name);
        prepared = holy_install_temporary_state(root, c->after, name);
        if (prepared == 0 || (prepared == 1 && !recovering)) {
            fputs("holypkg: reserved update object requires inspection: ", stderr);
            quote(stderr, c->after->path);
            fprintf(stderr, " (%s)\n", name);
            result = 4; goto done;
        }
        if (prepared == 1 || (recovering && holy_install_check_entry(root, c->after) == 1)) {
            if (archive_read_data_skip(archive) != ARCHIVE_OK) goto done;
            continue;
        }
        if (!c->after->link) {
            char buffer[65536];
            la_ssize_t got;
            long long total = 0;
            content = tmpfile();
            if (!content) goto done;
            while ((got = archive_read_data(archive, buffer, sizeof buffer)) > 0) {
                if (got > c->after->size - total || fwrite(buffer, 1, (size_t)got, content) != (size_t)got) goto done;
                total += got;
            }
            if (got < 0 || total != c->after->size || fflush(content) || fsync(fileno(content))) goto done;
        }
        if (!holy_install_prepare_file(root, c->after, content ? fileno(content) : -1, name)) goto done;
        if (content) { fclose(content); content = NULL; }
    }
    if (status != ARCHIVE_EOF) goto done;
    for (i = 0; i < plan->count; ++i) {
        const struct holy_file_change *c = &plan->changes[i];
        if (c->after && !c->after->directory && c->kind != HOLY_RETAIN && !seen[i]) goto done;
    }
    if (failed) *failed = plan->count;
    result = 0;
done:
    if (content) fclose(content);
    if (archive) archive_read_free(archive);
    holy_package_identity_free(&identity);
    free(seen);
    return result;
}

int holy_file_plan_finished(const struct holy_file_plan *plan, int root)
{
    size_t i;
    for (i = 0; i < plan->count; ++i) {
        const struct holy_file_change *c = &plan->changes[i];
        const struct holy_manifest_entry *e = c->after ? c->after : c->before;
        int expected = c->after || e->directory ? 1 : 2;
        if (holy_install_check_entry(root, e) != expected) return 4;
    }
    return 0;
}

int holy_file_plan_apply(const struct holy_file_plan *plan, int root,
                         holy_change_progress progress, void *context, size_t *failed)
{
    size_t i;
    int result = holy_file_plan_check(plan, root, 1, failed);
    if (result) return result;
    for (i = 0; i < plan->count; ++i) {
        const struct holy_file_change *c = &plan->changes[i];
        char name[78];
        int staged;
        if (!c->after || c->after->directory || c->kind == HOLY_RETAIN) continue;
        temporary_name(c, name);
        staged = holy_install_temporary_state(root, c->after, name);
        if (staged == 0 || (staged == 2 && holy_install_check_entry(root, c->after) != 1)) {
            if (failed) *failed = i;
            return 4;
        }
    }
    for (i = 0; i < plan->count; ++i) {
        const struct holy_file_change *c = &plan->changes[i];
        char name[78];
        if (failed) *failed = i;
        if (c->kind == HOLY_RETAIN || (c->after && c->after->directory) ||
            (c->before && c->before->directory)) continue;
        temporary_name(c, name);
        if (progress && !progress(context, i, 0)) return 1;
        if (!holy_install_transition(root, c->before, c->after, name)) return 4;
        if (progress && !progress(context, i, 1)) return 1;
    }
    if (failed) *failed = plan->count;
    return holy_file_plan_finished(plan, root);
}
