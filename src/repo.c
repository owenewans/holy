#define _POSIX_C_SOURCE 200809L
#include "repo.h"
#include "config.h"
#include "fetch.h"
#include "cache.h"
#include "deps.h"
#include "extract.h"
#include "provides.h"
#include "resolve.h"
#include "package.h"
#include "scan.h"
#include "stage.h"
#include "verify.h"
#include "sign.h"
#include "version.h"
#include "../backends/rpm-version.h"
#include "../backends/pacman.h"
#include "../backends/deb-version.h"
#include "../backends/apk-version.h"
#include "../backends/xbps-version.h"

#include <dirent.h>
#include <errno.h>
#include <elf.h>
#include <fcntl.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int same_identity(const struct holy_package_identity *a,
                         const struct holy_package_identity *b)
{
    return !strcmp(a->name, b->name) && !strcmp(a->version, b->version) &&
           !strcmp(a->release, b->release) && !strcmp(a->os, b->os) &&
           !strcmp(a->arch, b->arch) && !strcmp(a->libc, b->libc);
}

static int same_slot(const struct holy_package_identity *a,
                     const struct holy_package_identity *b)
{
    return !strcmp(a->name, b->name) && !strcmp(a->os, b->os) &&
           !strcmp(a->arch, b->arch) && !strcmp(a->libc, b->libc);
}

struct claim {
    char *kind, *name, *arch, *libc, *version, *evidence;
};

struct indexed_requirement { char *fields[10]; };
struct soname_fact { char *name, *arch, *libc, *path; };
struct version_fact { char *path, *name; };
struct export_fact {
    char *path, *name, *version;
    unsigned binding, type, visibility, hidden;
};

struct object {
    char *filename;
    struct holy_package_identity identity;
    int provider_match;
    struct claim *claims;
    size_t claim_count;
    struct indexed_requirement *requirements;
    size_t requirement_count;
    struct soname_fact *sonames;
    size_t soname_count;
    struct version_fact *versions;
    size_t version_count;
    struct export_fact *exports;
    size_t export_count;
    char **files;
    size_t file_count;
};

static void free_files(struct object *object)
{
    size_t i;
    for (i = 0; i < object->file_count; ++i) free(object->files[i]);
    free(object->files);
}

static int add_file(struct object *object, const char *path)
{
    char **next;
    char *copy;
    if (object->file_count == (size_t)-1 / sizeof *object->files) return 0;
    copy = strdup(path);
    if (!copy) return 0;
    next = realloc(object->files, (object->file_count + 1) * sizeof *object->files);
    if (!next) { free(copy); return 0; }
    object->files = next;
    object->files[object->file_count++] = copy;
    return 1;
}

static int collect_file(void *opaque, const struct holy_manifest_entry *entry)
{
    return entry->directory || add_file(opaque, entry->path);
}

struct file_cursor { struct object *object; size_t index; };

static int compare_file(void *opaque, const struct holy_manifest_entry *entry)
{
    struct file_cursor *cursor = opaque;
    if (entry->directory) return 1;
    return cursor->index < cursor->object->file_count &&
           !strcmp(cursor->object->files[cursor->index++], entry->path);
}

static void free_claims(struct object *object)
{
    size_t i;
    for (i = 0; i < object->claim_count; ++i) {
        struct claim *c = &object->claims[i];
        free(c->kind); free(c->name); free(c->arch);
        free(c->libc); free(c->version); free(c->evidence);
    }
    free(object->claims);
}

static int add_claim(struct object *object, const char *kind, const char *name,
                     const char *arch, const char *libc, const char *version,
                     const char *evidence)
{
    struct claim c = {0}, *next;
    if (object->claim_count == (size_t)-1 / sizeof *object->claims) return 0;
    c.kind = strdup(kind); c.name = strdup(name); c.arch = strdup(arch);
    c.libc = strdup(libc); c.version = strdup(version);
    c.evidence = strdup(evidence);
    if (!c.kind || !c.name || !c.arch || !c.libc || !c.version || !c.evidence) {
        free(c.kind); free(c.name); free(c.arch);
        free(c.libc); free(c.version); free(c.evidence);
        return 0;
    }
    next = realloc(object->claims,
                   (object->claim_count + 1) * sizeof *object->claims);
    if (!next) {
        free(c.kind); free(c.name); free(c.arch);
        free(c.libc); free(c.version); free(c.evidence);
        return 0;
    }
    object->claims = next;
    object->claims[object->claim_count++] = c;
    return 1;
}

static int collect_claim(void *opaque, const char *kind, const char *name,
                         const char *arch, const char *libc,
                         const char *version, const char *evidence)
{
    return add_claim(opaque, kind, name, arch, libc, version, evidence);
}

struct claim_cursor { struct object *object; size_t index; };

static int compare_claim(void *opaque, const char *kind, const char *name,
                         const char *arch, const char *libc,
                         const char *version, const char *evidence)
{
    struct claim_cursor *cursor = opaque;
    struct claim *c;
    if (cursor->index == cursor->object->claim_count) return 0;
    c = &cursor->object->claims[cursor->index++];
    return !strcmp(c->kind, kind) && !strcmp(c->name, name) &&
           !strcmp(c->arch, arch) && !strcmp(c->libc, libc) &&
           !strcmp(c->version, version) && !strcmp(c->evidence, evidence);
}

static void free_requirements(struct object *object)
{
    size_t i, j;
    for (i = 0; i < object->requirement_count; ++i)
        for (j = 0; j < 10; ++j) free(object->requirements[i].fields[j]);
    free(object->requirements);
}

static int add_requirement(struct object *object, const char *fields[10])
{
    struct indexed_requirement item = {{0}}, *next;
    size_t i;
    if (object->requirement_count >= 1024 * 1024 / 11) return 0;
    for (i = 0; i < 10; ++i) {
        item.fields[i] = strdup(fields[i]);
        if (!item.fields[i]) goto fail;
    }
    next = realloc(object->requirements,
                   (object->requirement_count + 1) * sizeof *next);
    if (!next) goto fail;
    object->requirements = next;
    object->requirements[object->requirement_count++] = item;
    return 1;
fail:
    for (i = 0; i < 10; ++i) free(item.fields[i]);
    return 0;
}

static int collect_requirement(void *opaque, const char *id,
    const char *consumer, const char *kind, const char *name,
    const char *arch, const char *libc, const char *relation,
    const char *version, const char *original, const char *evidence)
{
    const char *fields[] = {id, consumer, kind, name, arch, libc,
                            relation, version, original, evidence};
    return add_requirement(opaque, fields);
}

struct requirement_cursor { struct object *object; size_t index; };

static int compare_requirement(void *opaque, const char *id,
    const char *consumer, const char *kind, const char *name,
    const char *arch, const char *libc, const char *relation,
    const char *version, const char *original, const char *evidence)
{
    struct requirement_cursor *cursor = opaque;
    const char *fields[] = {id, consumer, kind, name, arch, libc,
                            relation, version, original, evidence};
    size_t i;
    if (cursor->index == cursor->object->requirement_count) return 0;
    for (i = 0; i < 10; ++i)
        if (strcmp(cursor->object->requirements[cursor->index].fields[i], fields[i]))
            return 0;
    ++cursor->index;
    return 1;
}

static void free_sonames(struct object *object)
{
    size_t i;
    for (i = 0; i < object->soname_count; ++i) {
        free(object->sonames[i].name); free(object->sonames[i].arch);
        free(object->sonames[i].libc); free(object->sonames[i].path);
    }
    free(object->sonames);
}

static int add_soname(struct object *object, const char *name,
                      const char *arch, const char *libc, const char *path)
{
    struct soname_fact fact = {0}, *next;
    if (object->soname_count >= 100000) return 0;
    fact.name = strdup(name); fact.arch = strdup(arch);
    fact.libc = strdup(libc); fact.path = strdup(path);
    if (!fact.name || !fact.arch || !fact.libc || !fact.path) goto fail;
    next = realloc(object->sonames, (object->soname_count + 1) * sizeof *next);
    if (!next) goto fail;
    object->sonames = next;
    object->sonames[object->soname_count++] = fact;
    return 1;
fail:
    free(fact.name); free(fact.arch); free(fact.libc); free(fact.path);
    return 0;
}

static int soname_order(const void *left, const void *right)
{
    const struct soname_fact *a = left, *b = right;
    int cmp = strcmp(a->path, b->path);
    return cmp ? cmp : strcmp(a->name, b->name);
}

static void free_versions(struct object *object)
{
    size_t i;
    for (i = 0; i < object->version_count; ++i) {
        free(object->versions[i].path);
        free(object->versions[i].name);
    }
    free(object->versions);
}

static int version_order(const void *left, const void *right)
{
    const struct version_fact *a = left, *b = right;
    int order = strcmp(a->path, b->path);
    return order ? order : strcmp(a->name, b->name);
}

static int add_version(struct object *object, const char *path, const char *name)
{
    struct version_fact fact = {0}, *next;
    if (object->version_count >= 100000) return 0;
    fact.path = strdup(path); fact.name = strdup(name);
    if (!fact.path || !fact.name) goto fail;
    next = realloc(object->versions, (object->version_count + 1) * sizeof *next);
    if (!next) goto fail;
    object->versions = next;
    object->versions[object->version_count++] = fact;
    return 1;
fail:
    free(fact.path); free(fact.name);
    return 0;
}

static void free_exports(struct object *object)
{
    size_t i;
    for (i = 0; i < object->export_count; ++i) {
        free(object->exports[i].path);
        free(object->exports[i].name);
        free(object->exports[i].version);
    }
    free(object->exports);
}

static int export_order(const void *left, const void *right)
{
    const struct export_fact *a = left, *b = right;
    int order = strcmp(a->path, b->path);
    if (!order) order = strcmp(a->name, b->name);
    if (!order) order = strcmp(a->version, b->version);
    if (!order && a->binding != b->binding) order = a->binding < b->binding ? -1 : 1;
    if (!order && a->type != b->type) order = a->type < b->type ? -1 : 1;
    if (!order && a->visibility != b->visibility)
        order = a->visibility < b->visibility ? -1 : 1;
    if (!order && a->hidden != b->hidden) order = a->hidden < b->hidden ? -1 : 1;
    return order;
}

static int add_export(struct object *object, const char *path,
                      const struct holy_elf_symbol *symbol)
{
    struct export_fact fact = {0}, *next;
    if (object->export_count >= 500000) return 0;
    fact.path = strdup(path);
    fact.name = strdup(symbol->name);
    fact.version = strdup(symbol->version ? symbol->version : "");
    fact.binding = symbol->binding; fact.type = symbol->type;
    fact.visibility = symbol->visibility;
    fact.hidden = !!symbol->version_hidden;
    if (!fact.path || !fact.name || !fact.version) goto fail;
    next = realloc(object->exports, (object->export_count + 1) * sizeof *next);
    if (!next) goto fail;
    object->exports = next;
    object->exports[object->export_count++] = fact;
    return 1;
fail:
    free(fact.path); free(fact.name); free(fact.version);
    return 0;
}

static int collect_sonames(const char *snapshot, struct object *object)
{
    struct holy_scan_result scan = {0};
    size_t i;
    int ok = holy_scan_collect(snapshot, &scan);
    for (i = 0; ok && i < scan.count; ++i) {
        const struct holy_scanned_file *file = &scan.files[i];
        if (file->elf.type == ET_DYN && !(file->elf.flags1 & DF_1_PIE) &&
            file->elf.soname) {
            size_t j;
            ok = add_soname(object, file->elf.soname,
                            holy_elf_machine(&file->elf), file->runtime,
                            file->path);
            for (j = 0; ok && j < file->elf.defined_version_count; ++j)
                ok = add_version(object, file->path,
                                 file->elf.defined_versions[j].name);
            for (j = 0; ok && j < file->elf.symbol_count; ++j) {
                const struct holy_elf_symbol *s = &file->elf.symbols[j];
                if (s->section && s->name[0] &&
                    (s->binding == STB_GLOBAL || s->binding == STB_WEAK ||
                     s->binding == STB_GNU_UNIQUE) &&
                    (s->visibility == STV_DEFAULT || s->visibility == STV_PROTECTED))
                    ok = add_export(object, file->path, s);
            }
        }
    }
    holy_scan_free(&scan);
    if (ok && object->soname_count)
        qsort(object->sonames, object->soname_count,
              sizeof *object->sonames, soname_order);
    if (ok && object->version_count) {
        qsort(object->versions, object->version_count,
              sizeof *object->versions, version_order);
        for (i = 1; i < object->version_count; ++i)
            if (!version_order(&object->versions[i - 1], &object->versions[i])) return 0;
    }
    if (ok && object->export_count)
        qsort(object->exports, object->export_count,
              sizeof *object->exports, export_order);
    return ok;
}

static int compare_sonames(const char *snapshot, struct object *object,
                           int versions, int exports)
{
    struct object actual = {0};
    size_t i;
    int ok = collect_sonames(snapshot, &actual) &&
             actual.soname_count == object->soname_count;
    for (i = 0; ok && i < actual.soname_count; ++i) {
        const struct soname_fact *a = &actual.sonames[i], *b = &object->sonames[i];
        ok = !strcmp(a->name, b->name) && !strcmp(a->arch, b->arch) &&
             !strcmp(a->libc, b->libc) && !strcmp(a->path, b->path);
    }
    if (versions && actual.version_count != object->version_count) ok = 0;
    for (i = 0; ok && versions && i < actual.version_count; ++i)
        ok = !strcmp(actual.versions[i].path, object->versions[i].path) &&
             !strcmp(actual.versions[i].name, object->versions[i].name);
    if (exports && actual.export_count != object->export_count) ok = 0;
    for (i = 0; ok && exports && i < actual.export_count; ++i)
        ok = !export_order(&actual.exports[i], &object->exports[i]);
    free_sonames(&actual);
    free_versions(&actual);
    free_exports(&actual);
    return ok;
}

static int compare_names(const void *left, const void *right)
{
    const struct object *a = left, *b = right;
    return strcmp(a->filename, b->filename);
}

static int quote(FILE *fp, const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    if (fputc('"', fp) == EOF) return 0;
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') {
            if (fputc('\\', fp) == EOF || fputc(*p, fp) == EOF) return 0;
        } else if (*p <= 32 || *p >= 127) {
            if (fprintf(fp, "\\x%02x", (unsigned int)*p) < 0) return 0;
        } else if (fputc(*p, fp) == EOF) return 0;
    }
    return fputc('"', fp) != EOF;
}

static void json_string(const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    putchar('"');
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p >= 32 && *p < 127) putchar(*p);
        else printf("\\u%04x", (unsigned int)*p);
    }
    putchar('"');
}

static void candidate_json(const struct object *object)
{
    const struct holy_package_identity *id = &object->identity;
    fputs("{\"schema\":\"holy-repo-candidates-1\",\"type\":\"candidate\",\"name\":", stdout);
    json_string(id->name);
    fputs(",\"version\":", stdout);
    json_string(id->version);
    fputs(",\"release\":", stdout);
    json_string(id->release);
    fputs(",\"os\":", stdout);
    json_string(id->os);
    fputs(",\"arch\":", stdout);
    json_string(id->arch);
    fputs(",\"libc\":", stdout);
    json_string(id->libc);
    fputs(",\"filename\":", stdout);
    json_string(object->filename);
    printf(",\"sha256\":\"%s\",\"size\":%" PRIu64 "}\n", id->digest, id->size);
}

static int record(FILE *fp, const struct object *object)
{
    const struct holy_package_identity *id = &object->identity;
    const char *values[] = {id->name, id->version, id->release, id->os,
                            id->arch, id->libc, object->filename};
    size_t i;
    if (fputs("package", fp) == EOF) return 0;
    for (i = 0; i < sizeof values / sizeof *values; ++i) {
        if (fputc(' ', fp) == EOF || !quote(fp, values[i])) return 0;
    }
    if (fprintf(fp, " %s %" PRIu64 " ", id->digest, id->size) < 0) return 0;
    return quote(fp, id->version_family ? id->version_family : "-") &&
           fputc('\n', fp) != EOF;
}

static int claim_record(FILE *fp, const struct object *object,
                        const struct claim *claim)
{
    const char *values[] = {claim->kind, claim->name, claim->arch,
                            claim->libc, claim->version, claim->evidence};
    size_t i;
    if (fprintf(fp, "claim %s", object->identity.digest) < 0) return 0;
    for (i = 0; i < sizeof values / sizeof *values; ++i)
        if (fputc(' ', fp) == EOF || !quote(fp, values[i])) return 0;
    return fputc('\n', fp) != EOF;
}

static int requirement_record(FILE *fp, const struct object *object,
                              const struct indexed_requirement *requirement)
{
    size_t i;
    if (fprintf(fp, "require %s", object->identity.digest) < 0) return 0;
    for (i = 0; i < 10; ++i)
        if (fputc(' ', fp) == EOF || !quote(fp, requirement->fields[i])) return 0;
    return fputc('\n', fp) != EOF;
}

static int soname_record(FILE *fp, const struct object *object,
                         const struct soname_fact *fact)
{
    const char *values[] = {fact->name, fact->arch, fact->libc, fact->path};
    size_t i;
    if (fprintf(fp, "soname %s", object->identity.digest) < 0) return 0;
    for (i = 0; i < 4; ++i)
        if (fputc(' ', fp) == EOF || !quote(fp, values[i])) return 0;
    return fputc('\n', fp) != EOF;
}

static int version_record(FILE *fp, const struct object *object,
                          const struct version_fact *fact)
{
    return fprintf(fp, "elf-version %s ", object->identity.digest) >= 0 &&
           quote(fp, fact->path) && fputc(' ', fp) != EOF &&
           quote(fp, fact->name) && fputc('\n', fp) != EOF;
}

static int export_record(FILE *fp, const struct object *object,
                         const struct export_fact *fact)
{
    return fprintf(fp, "elf-export %s ", object->identity.digest) >= 0 &&
           quote(fp, fact->path) && fputc(' ', fp) != EOF &&
           quote(fp, fact->name) && fputc(' ', fp) != EOF &&
           quote(fp, fact->version) &&
           fprintf(fp, " %u %u %u %u\n", fact->binding, fact->type,
                   fact->visibility, fact->hidden) >= 0;
}

static int file_record(FILE *fp, const struct object *object, const char *path)
{
    return fprintf(fp, "file %s ", object->identity.digest) >= 0 &&
           quote(fp, path) && fputc('\n', fp) != EOF;
}

static int digest_file(const char *path, char hex[65])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char hash[32], buffer[65536];
    unsigned int length;
    size_t n, i;
    FILE *fp = fopen(path, "rb");
    int ok = fp && ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    while (ok && (n = fread(buffer, 1, sizeof buffer, fp)) > 0)
        ok = EVP_DigestUpdate(ctx, buffer, n) == 1;
    if (ok) ok = !ferror(fp) && EVP_DigestFinal_ex(ctx, hash, &length) == 1 &&
                 length == sizeof hash;
    if (ok) {
        for (i = 0; i < sizeof hash; ++i)
            snprintf(hex + i * 2, 3, "%02x", hash[i]);
        hex[64] = '\0';
    }
    if (fp) fclose(fp);
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int read_current(int dir, char digest[65])
{
    char line[72];
    struct stat st;
    size_t i;
    int fd = openat(dir, "current", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size != sizeof line ||
        pread(fd, line, sizeof line, 0) != sizeof line ||
        memcmp(line, "sha256 ", 7) || line[71] != '\n') {
        close(fd);
        return -1;
    }
    close(fd);
    for (i = 0; i < 64; ++i)
        if (!((line[i + 7] >= '0' && line[i + 7] <= '9') ||
              (line[i + 7] >= 'a' && line[i + 7] <= 'f'))) return -1;
    memcpy(digest, line + 7, 64);
    digest[64] = '\0';
    return 1;
}

int holy_repo_index(const char *directory)
{
    struct object *objects = NULL;
    DIR *listing = NULL;
    struct dirent *entry;
    struct stat st;
    size_t count = 0, i, j;
    int dir = -1, temp = -1, ok = 0;
    FILE *stream = NULL;
    char temporary[43] = {0};

    dir = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || flock(dir, LOCK_EX) < 0) goto done;
    listing = fdopendir(dup(dir));
    if (!listing) goto done;
    errno = 0;
    while ((entry = readdir(listing)) != NULL) {
        size_t length = strlen(entry->d_name);
        struct object *next;
        if (length < 6 || strcmp(entry->d_name + length - 5, ".holy")) continue;
        if (count == (size_t)-1 / sizeof *objects) goto done;
        next = realloc(objects, (count + 1) * sizeof *objects);
        if (!next) goto done;
        objects = next;
        memset(&objects[count], 0, sizeof *objects);
        objects[count].filename = strdup(entry->d_name);
        if (!objects[count].filename) goto done;
        ++count;
        errno = 0;
    }
    if (errno) goto done;
    closedir(listing);
    listing = NULL;
    if (count) qsort(objects, count, sizeof *objects, compare_names);
    for (i = 0; i < count; ++i) {
        int input = openat(dir, objects[i].filename,
                           O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        char *snapshot;
        if (input < 0) goto done;
        snapshot = holy_stage_fd(input, "holy-index");
        close(input);
        if (!snapshot) goto done;
        if (!holy_verify_with_output(snapshot, 0) ||
            !holy_scan_local_with_output(snapshot, 0) ||
            !holy_deps_local_with_output(snapshot, 0) ||
            !holy_provides_local(snapshot, 0) ||
            !holy_package_identity(snapshot, &objects[i].identity) ||
            !holy_provides_visit(snapshot, collect_claim, &objects[i]) ||
            !holy_deps_visit(snapshot, collect_requirement, &objects[i]) ||
            !collect_sonames(snapshot, &objects[i]) ||
            !holy_verify_visit(snapshot, collect_file, &objects[i])) {
            unlink(snapshot);
            free(snapshot);
            goto done;
        }
        unlink(snapshot);
        free(snapshot);
        for (j = 0; j < i; ++j) {
            struct holy_package_identity *a = &objects[i].identity;
            struct holy_package_identity *b = &objects[j].identity;
            if (same_identity(a, b)) {
                fprintf(stderr, "holypkg: duplicate package identity\n");
                goto done;
            }
        }
    }
    if (fstatat(dir, "index", &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!S_ISREG(st.st_mode)) {
            fprintf(stderr, "holypkg: index is not a regular file\n");
            goto done;
        }
    } else if (errno != ENOENT) {
        goto done;
    }
    temp = holy_temporary_at(dir, temporary);
    if (temp < 0) goto done;
    stream = fdopen(temp, "w");
    if (!stream) goto done;
    temp = -1;
    if (fputs("format holy-index-prototype-8\ncoverage files complete\ncoverage dependencies complete\ncoverage elf-sonames complete\ncoverage elf-versions complete\ncoverage elf-exports complete\n", stream) == EOF) goto done;
    for (i = 0; i < count; ++i) {
        if (!record(stream, &objects[i])) goto done;
        for (j = 0; j < objects[i].claim_count; ++j)
            if (!claim_record(stream, &objects[i], &objects[i].claims[j])) goto done;
        for (j = 0; j < objects[i].requirement_count; ++j)
            if (!requirement_record(stream, &objects[i], &objects[i].requirements[j])) goto done;
        for (j = 0; j < objects[i].soname_count; ++j)
            if (!soname_record(stream, &objects[i], &objects[i].sonames[j])) goto done;
        for (j = 0; j < objects[i].version_count; ++j)
            if (!version_record(stream, &objects[i], &objects[i].versions[j])) goto done;
        for (j = 0; j < objects[i].export_count; ++j)
            if (!export_record(stream, &objects[i], &objects[i].exports[j])) goto done;
        for (j = 0; j < objects[i].file_count; ++j)
            if (!file_record(stream, &objects[i], objects[i].files[j])) goto done;
    }
    if (fflush(stream) || ftello(stream) < 0 ||
        ftello(stream) > 128LL * 1024 * 1024 ||
        fchmod(fileno(stream), 0644) || fsync(fileno(stream)))
        goto done;
    if (fclose(stream)) { stream = NULL; goto done; }
    stream = NULL;
    if (renameat(dir, temporary, dir, "index") || fsync(dir)) goto done;
    temporary[0] = '\0';
    printf("indexed %zu packages\n", count);
    ok = 1;
done:
    if (!ok) fprintf(stderr, "holypkg: repository index incomplete\n");
    if (stream) fclose(stream);
    if (temp >= 0) close(temp);
    if (temporary[0] && dir >= 0) unlinkat(dir, temporary, 0);
    if (listing) closedir(listing);
    for (i = 0; i < count; ++i) {
        free(objects[i].filename);
        holy_package_identity_free(&objects[i].identity);
        free_claims(&objects[i]);
        free_requirements(&objects[i]);
        free_sonames(&objects[i]);
        free_versions(&objects[i]);
        free_exports(&objects[i]);
        free_files(&objects[i]);
    }
    free(objects);
    if (dir >= 0) close(dir);
    return ok;
}

static int parse_record(char **v, size_t n, struct object *object)
{
    unsigned long long size;
    char *end;
    size_t i;
    const char *filename;
    if ((n != 10 && n != 11) || strcmp(v[0], "package") ||
        (n == 11 && (!v[10][0] || strlen(v[10]) > 128))) return 0;
    filename = v[7];
    i = strlen(filename);
    if (i < 6 || strcmp(filename + i - 5, ".holy") || strchr(filename, '/') ||
        strlen(v[8]) != 64 || !v[1][0] || !v[2][0] || !v[3][0]) return 0;
    for (i = 0; i < 64; ++i)
        if (!((v[8][i] >= '0' && v[8][i] <= '9') ||
              (v[8][i] >= 'a' && v[8][i] <= 'f'))) return 0;
    errno = 0;
    size = strtoull(v[9], &end, 10);
    if (errno || !v[9][0] || *end || v[9][0] == '-' || !size) return 0;
    object->filename = v[7]; v[7] = NULL;
    object->identity.name = v[1]; v[1] = NULL;
    object->identity.version = v[2]; v[2] = NULL;
    object->identity.release = v[3]; v[3] = NULL;
    object->identity.os = v[4]; v[4] = NULL;
    object->identity.arch = v[5]; v[5] = NULL;
    object->identity.libc = v[6]; v[6] = NULL;
    if (n == 11 && strcmp(v[10], "-")) {
        object->identity.version_family = v[10]; v[10] = NULL;
    }
    memcpy(object->identity.digest, v[8], 65);
    object->identity.size = size;
    return 1;
}

static int parse_claim(char **v, size_t n, struct object *object)
{
    size_t i;
    if (n != 8 || strcmp(v[0], "claim") ||
        strcmp(v[1], object->identity.digest) ||
        !holy_provides_claim_valid(v[2], v[3], v[4], v[5], v[6], v[7]))
        return 0;
    for (i = 0; i < object->claim_count; ++i) {
        const struct claim *c = &object->claims[i];
        if (!strcmp(c->kind, v[2]) && !strcmp(c->name, v[3]) &&
            !strcmp(c->arch, v[4]) && !strcmp(c->libc, v[5]) &&
            !strcmp(c->version, v[6])) return 0;
    }
    return add_claim(object, v[2], v[3], v[4], v[5], v[6], v[7]);
}

static int parse_requirement(char **v, size_t n, struct object *object)
{
    size_t i;
    const char *fields[10];
    if (n != 12 || strcmp(v[0], "require") ||
        strcmp(v[1], object->identity.digest) ||
        !holy_deps_record_valid(v[2], v[3], v[4], v[5], v[6], v[7],
                                v[8], v[9], v[10], v[11])) return 0;
    for (i = 0; i < object->requirement_count; ++i)
        if (!strcmp(object->requirements[i].fields[0], v[2])) return 0;
    for (i = 0; i < 10; ++i) fields[i] = v[i + 2];
    return add_requirement(object, fields);
}

static int safe_target_path(const char *path)
{
    size_t length = strlen(path);
    char *archive_path;
    int valid;
    if (!length || length > (size_t)-1 - 6 || path[length - 1] == '/') return 0;
    archive_path = malloc(length + 6);
    if (!archive_path) return 0;
    memcpy(archive_path, "DATA/", 5);
    memcpy(archive_path + 5, path, length + 1);
    valid = holy_safe_archive_path(archive_path);
    free(archive_path);
    return valid;
}

static int parse_file(char **v, size_t n, struct object *object)
{
    if (n != 3 || strcmp(v[0], "file") ||
        strcmp(v[1], object->identity.digest) ||
        !safe_target_path(v[2]) ||
        (object->file_count && strcmp(object->files[object->file_count - 1], v[2]) >= 0))
        return 0;
    return add_file(object, v[2]);
}

static int parse_soname(char **v, size_t n, struct object *object)
{
    struct soname_fact current;
    if (n != 6 || strcmp(v[0], "soname") ||
        strcmp(v[1], object->identity.digest) || !v[2][0] ||
        (strcmp(v[3], "x86") && strcmp(v[3], "x86_64")) ||
        (strcmp(v[4], "glibc") && strcmp(v[4], "musl")) ||
        !safe_target_path(v[5])) return 0;
    current.name = v[2]; current.arch = v[3];
    current.libc = v[4]; current.path = v[5];
    if (object->soname_count &&
        soname_order(&object->sonames[object->soname_count - 1], &current) >= 0)
        return 0;
    return add_soname(object, v[2], v[3], v[4], v[5]);
}

static int parse_version(char **v, size_t n, struct object *object)
{
    struct version_fact current;
    size_t i;
    if (n != 4 || strcmp(v[0], "elf-version") ||
        strcmp(v[1], object->identity.digest) ||
        !safe_target_path(v[2]) || !v[3][0]) return 0;
    for (i = 0; i < object->soname_count; ++i)
        if (!strcmp(object->sonames[i].path, v[2])) break;
    if (i == object->soname_count) return 0;
    current.path = v[2]; current.name = v[3];
    if (object->version_count &&
        version_order(&object->versions[object->version_count - 1], &current) >= 0)
        return 0;
    return add_version(object, v[2], v[3]);
}

static int parse_export(char **v, size_t n, struct object *object)
{
    struct holy_elf_symbol symbol = {0};
    struct export_fact current = {0};
    unsigned *values[] = {&symbol.binding, &symbol.type, &symbol.visibility,
                          &current.hidden};
    size_t i;
    if (n != 9 || strcmp(v[0], "elf-export") ||
        strcmp(v[1], object->identity.digest) ||
        !safe_target_path(v[2]) || !v[3][0]) return 0;
    for (i = 0; i < object->soname_count; ++i)
        if (!strcmp(object->sonames[i].path, v[2])) break;
    if (i == object->soname_count) return 0;
    for (i = 0; i < 4; ++i) {
        char *end;
        unsigned long value;
        errno = 0;
        value = strtoul(v[5 + i], &end, 10);
        if (errno || !v[5 + i][0] || *end || value > 255) return 0;
        *values[i] = (unsigned)value;
    }
    if ((symbol.binding != STB_GLOBAL && symbol.binding != STB_WEAK &&
         symbol.binding != STB_GNU_UNIQUE) ||
        (symbol.visibility != STV_DEFAULT && symbol.visibility != STV_PROTECTED) ||
        current.hidden > 1) return 0;
    symbol.name = v[3]; symbol.version = v[4];
    symbol.version_hidden = (int)current.hidden;
    current.path = v[2]; current.name = v[3]; current.version = v[4];
    current.binding = symbol.binding; current.type = symbol.type;
    current.visibility = symbol.visibility;
    if (object->export_count &&
        export_order(&object->exports[object->export_count - 1], &current) > 0)
        return 0;
    return add_export(object, v[2], &symbol);
}

static int indexed_file(const struct object *object, const char *path)
{
    size_t low = 0, high = object->file_count;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        int cmp = strcmp(object->files[middle], path);
        if (!cmp) return 1;
        if (cmp < 0) low = middle + 1;
        else high = middle;
    }
    return 0;
}

/* the family's own comparator, since a catalog orders its versions with the same rules
   a requirement does */
static int family_compare(const char *family, const char *left, const char *right, int *order)
{
    if (!family) return 0;
    return !strcmp(family, "pacman") ? holy_pacman_version_compare(left, right, order) :
           !strcmp(family, "deb") ? holy_deb_version_compare(left, right, order) :
           !strcmp(family, "holy") ? holy_version_compare(left, right, order) :
           !strcmp(family, "apk") ? holy_apk_version_compare(left, right, order) :
           !strcmp(family, "xbps") ? holy_xbps_version_compare(left, right, order) :
           !strcmp(family, "rpm") ? holy_rpm_version_compare(left, right, order) : 0;
}

/* the newest member of the family a name names, or count when the name is a choice:
   artifacts that differ in os, architecture, libc or version family are different
   slots, and nothing in the catalog says which one the name meant */
static int same_family(const struct holy_package_identity *a,
                       const struct holy_package_identity *b)
{
    return (!a->version_family && !b->version_family) ||
           (a->version_family && b->version_family &&
            !strcmp(a->version_family, b->version_family));
}

static size_t family_root(const struct object *objects, size_t count, const char *name,
                          const char *arch, const char *libc)
{
    size_t i, members = 0, best = count;
    for (i = 0; i < count; ++i) {
        int order = 0;
        if (strcmp(objects[i].identity.name, name)) continue;
        if (arch && strcmp(objects[i].identity.arch, arch)) continue;
        if (libc && strcmp(objects[i].identity.libc, libc)) continue;
        if (!members) {
            best = i;
            ++members;
            continue;
        }
        /* the members have to be one slot under one family: comparing a candidate with
           its own comparator against a member of another family would order two
           different things and call it a family */
        if (!same_slot(&objects[best].identity, &objects[i].identity) ||
            !same_family(&objects[best].identity, &objects[i].identity) ||
            !family_compare(objects[i].identity.version_family,
                            objects[i].identity.version, objects[best].identity.version,
                            &order)) return count;
        if (order > 0) best = i;
        ++members;
    }
    return members > 1 ? best : count;
}

/* the catalog's own choice, stated the way the resolver states it, so a name that
   carried two versions says which artifact it resolved to */
static void report_family_root(const struct object *object, const char *name,
                               size_t members, int json)
{
    const struct holy_package_identity *identity = &object->identity;
    if (json) {
        printf("{\"schema\":\"holy-local-solve-1\",\"type\":\"family-choice\","
               "\"consumer\":null,\"requirement\":null,\"provider\":\"%s\","
               "\"slot\":{\"name\":", identity->digest);
        printf("\"%s\",\"os\":\"%s\",\"arch\":\"%s\",\"libc\":\"%s\"},"
               "\"family\":\"%s\",\"version\":\"%s\",\"members\":%zu,"
               "\"reason\":\"newest-in-family\"}\n",
               identity->name, identity->os, identity->arch, identity->libc,
               identity->version_family ? identity->version_family : "-",
               identity->version, members);
        return;
    }
    printf("family-choice %s provider=%s slot %s %s %s %s family %s version %s members %zu "
           "reason newest-in-family\n", name, identity->digest, identity->name, identity->os,
           identity->arch, identity->libc,
           identity->version_family ? identity->version_family : "-", identity->version,
           members);
}

struct or_match { const struct object *object; int found; };

static int indexed_version_matches(const struct object *object,
                                   const char *candidate, const char *relation,
                                   const char *version, int identity)
{
    const char *family = object->identity.version_family;
    const char *actual = candidate;
    char *joined = NULL;
    int order, compared;
    if (!strcmp(relation, "any")) return 1;
    if (!family || !candidate || !strcmp(candidate, "-")) return 0;
    if (identity && !strcmp(family, "xbps") && object->identity.release) {
        size_t a = strlen(candidate), b = strlen(object->identity.release);
        if (a > SIZE_MAX - b - 2 || !(joined = malloc(a + b + 2))) return 0;
        snprintf(joined, a + b + 2, "%s_%s", candidate, object->identity.release);
        actual = joined;
    }
    compared = !strcmp(family, "pacman") ?
        holy_pacman_version_compare(actual, version, &order) :
        !strcmp(family, "deb") ?
        holy_deb_version_compare(actual, version, &order) :
        !strcmp(family, "holy") ?
        holy_version_compare(actual, version, &order) :
        !strcmp(family, "apk") ?
        holy_apk_version_compare(actual, version, &order) :
        !strcmp(family, "xbps") ?
        holy_xbps_version_compare(actual, version, &order) :
        !strcmp(family, "rpm") ?
        holy_rpm_version_compare(actual, version, &order) : 0;
    free(joined);
    if (!compared) return 0;
    return !strcmp(relation, "eq") ? order == 0 :
           !strcmp(relation, "ge") ? order >= 0 :
           !strcmp(relation, "gt") ? order > 0 :
           !strcmp(relation, "le") ? order <= 0 :
           !strcmp(relation, "lt") && order < 0;
}

static int indexed_or_branch(void *opaque, const char *name,
                             const char *relation, const char *version)
{
    struct or_match *match = opaque;
    size_t i;
    if (!strcmp(match->object->identity.name, name) &&
        indexed_version_matches(match->object, match->object->identity.version,
                                relation, version, 1)) match->found = 1;
    for (i = 0; i < match->object->claim_count; ++i)
        if (!strcmp(match->object->claims[i].kind, "package") &&
            !strcmp(match->object->claims[i].name, name) &&
            indexed_version_matches(match->object, match->object->claims[i].version,
                                    relation, version, 0)) match->found = 1;
    return 1;
}

static int indexed_provider(const struct object *object, const char *kind,
                            const char *name, int file_index, int soname_index)
{
    static const char *const dirs[] = {"usr/bin/", "bin/", "usr/sbin/", "sbin/"};
    size_t i;
    if (!strcmp(kind, "package-or")) {
        struct or_match match = {object, 0};
        return holy_package_or_each(name, indexed_or_branch, &match) && match.found;
    }
    if (!strcmp(kind, "package") && !strcmp(object->identity.name, name)) return 1;
    if (!strcmp(kind, "soname")) {
        if (!soname_index) return 0;
        for (i = 0; i < object->soname_count; ++i)
            if (!strcmp(object->sonames[i].name, name)) return 1;
        return 0;
    }
    if (!strcmp(kind, "file"))
        return file_index && name[0] == '/' && indexed_file(object, name + 1);
    if (!strcmp(kind, "command")) {
        if (!file_index || !*name || strchr(name, '/')) return 0;
        for (i = 0; i < sizeof dirs / sizeof *dirs; ++i) {
            size_t a = strlen(dirs[i]), b = strlen(name);
            char *path;
            int found;
            if (a > SIZE_MAX - b - 1) return 0;
            path = malloc(a + b + 1);
            if (!path) return 0;
            memcpy(path, dirs[i], a);
            memcpy(path + a, name, b + 1);
            found = indexed_file(object, path);
            free(path);
            if (found) return 1;
        }
        return 0;
    }
    for (i = 0; i < object->claim_count; ++i)
        if (!strcmp(object->claims[i].kind, kind) &&
            !strcmp(object->claims[i].name, name)) return 1;
    return 0;
}

static unsigned char ascii_lower(unsigned char c)
{
    return c >= 'A' && c <= 'Z' ? (unsigned char)(c + 'a' - 'A') : c;
}

static int ascii_prefix(const char *text, const char *prefix)
{
    while (*prefix) {
        if (!*text || ascii_lower((unsigned char)*text++) !=
                      ascii_lower((unsigned char)*prefix++)) return 0;
    }
    return 1;
}

static int fuzzy_rank(const char *query, const char *target)
{
    size_t q = strlen(query), t = strlen(target), i, j;
    unsigned int prev[129], next[129], row_min;
    if (!q || !t || q > 256 || t > 256) return -1;
    if (ascii_prefix(target, query)) return q == t ? 0 : 1;
    for (i = 1; i < t; ++i)
        if (ascii_prefix(target + i, query)) return 2;
    if (q > 128 || t > 128 || q > t + 2 || t > q + 2) return -1;
    for (j = 0; j <= t; ++j) prev[j] = (unsigned int)j;
    for (i = 1; i <= q; ++i) {
        next[0] = (unsigned int)i;
        row_min = next[0];
        for (j = 1; j <= t; ++j) {
            unsigned int cost = ascii_lower((unsigned char)query[i - 1]) ==
                                ascii_lower((unsigned char)target[j - 1]) ? 0 : 1;
            unsigned int deletion = prev[j] + 1;
            unsigned int insertion = next[j - 1] + 1;
            unsigned int replacement = prev[j - 1] + cost;
            next[j] = deletion < insertion ? deletion : insertion;
            if (replacement < next[j]) next[j] = replacement;
            if (next[j] < row_min) row_min = next[j];
        }
        if (row_min > 2) return -1;
        memcpy(prev, next, (t + 1) * sizeof *prev);
    }
    return prev[t] == 1 ? 3 : prev[t] == 2 ? 4 : -1;
}

static int file_hint(const struct object *object, const char *query,
                     const char **matched)
{
    const char *basename = strrchr(query, '/');
    size_t i;
    int best = -1;
    basename = basename ? basename + 1 : query;
    *matched = NULL;
    if (!*basename) return -1;
    for (i = 0; i < object->file_count; ++i) {
        const char *path = object->files[i], *name = strrchr(path, '/');
        int score = fuzzy_rank(basename, name ? name + 1 : path);
        if (query[0] == '/' && score >= 0) {
            if (!strcmp(query + 1, path)) score = 0;
            else ++score;
        }
        if (score >= 0 && (best < 0 || score < best ||
            (score == best && strcmp(path, *matched) < 0))) {
            best = score;
            *matched = path;
        }
    }
    return best;
}

struct mirror {
    const char *base, *ca_file, *downloads;
    int status;
};

struct stage_request {
    const char *root;
    struct holy_repo_set *set;
    const struct holy_package_identity *slot;
    const char *digest;
    int index_only;
    int provider;
    struct holy_repo_slot_list *candidates;
    /* the CLI disambiguates a name a repository offers for several architectures with
       these, so both are optional and neither is a guess */
    const char *arch, *libc;
};

static int copy_identity(struct holy_package_identity *to,
                         const struct holy_package_identity *from)
{
    memset(to, 0, sizeof *to);
    to->name = strdup(from->name);
    to->version = strdup(from->version);
    to->release = strdup(from->release);
    to->version_family = from->version_family ? strdup(from->version_family) : NULL;
    to->os = strdup(from->os);
    to->arch = strdup(from->arch);
    to->libc = strdup(from->libc);
    memcpy(to->digest, from->digest, sizeof to->digest);
    to->size = from->size;
    return to->name && to->version && to->release && to->os && to->arch &&
           to->libc && (!from->version_family || to->version_family);
}

struct closure {
    unsigned char *selected;
    size_t *queue;
    size_t count;
    struct provider_key *providers;
    size_t provider_count;
};

struct provider_key {
    const char *kind, *name;
    size_t index;
};

static int provider_key_order(const void *left, const void *right)
{
    const struct provider_key *a = left, *b = right;
    int order = strcmp(a->kind, b->kind);
    if (!order) order = strcmp(a->name, b->name);
    return order ? order : a->index < b->index ? -1 : a->index > b->index;
}

static int closure_index(const struct object *objects, size_t count,
                         struct closure *closure)
{
    static const char *const dirs[] = {"usr/bin/", "bin/", "usr/sbin/", "sbin/"};
    size_t capacity = count, i, j, k, used = 0;
    struct provider_key *keys;
    for (i = 0; i < count; ++i) {
        const struct object *o = &objects[i];
        size_t extra;
        if (o->claim_count > SIZE_MAX - o->soname_count) return 0;
        extra = o->claim_count + o->soname_count;
        if (o->file_count > (SIZE_MAX - extra) / 2) return 0;
        extra += o->file_count * 2;
        if (capacity > SIZE_MAX - extra) return 0;
        capacity += extra;
    }
    if (capacity > SIZE_MAX / sizeof *keys) return 0;
    keys = calloc(capacity ? capacity : 1, sizeof *keys);
    if (!keys) return 0;
    for (i = 0; i < count; ++i) {
        const struct object *o = &objects[i];
        keys[used++] = (struct provider_key){"package", o->identity.name, i};
        for (j = 0; j < o->claim_count; ++j)
            keys[used++] = (struct provider_key){o->claims[j].kind,
                                                  o->claims[j].name, i};
        for (j = 0; j < o->soname_count; ++j)
            keys[used++] = (struct provider_key){"soname", o->sonames[j].name, i};
        for (j = 0; j < o->file_count; ++j) {
            const char *path = o->files[j];
            keys[used++] = (struct provider_key){"file", path, i};
            for (k = 0; k < sizeof dirs / sizeof *dirs; ++k)
                if (!strncmp(path, dirs[k], strlen(dirs[k])) &&
                    path[strlen(dirs[k])]) {
                    keys[used++] = (struct provider_key){"command",
                                   path + strlen(dirs[k]), i};
                    break;
                }
        }
    }
    qsort(keys, used, sizeof *keys, provider_key_order);
    closure->providers = keys;
    closure->provider_count = used;
    return 1;
}

static int closure_add(struct closure *closure, size_t index)
{
    if (!closure->selected[index]) {
        closure->selected[index] = 1;
        closure->queue[closure->count++] = index;
    }
    return 1;
}

static int closure_provider(struct closure *closure, const char *kind,
                            const char *name)
{
    size_t low = 0, high = closure->provider_count, i;
    const char *file = !strcmp(kind, "file") && name[0] == '/' ? name + 1 : name;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        const struct provider_key *key = &closure->providers[middle];
        int order = strcmp(key->kind, kind);
        if (!order) order = strcmp(key->name, file);
        if (order < 0) low = middle + 1;
        else high = middle;
    }
    for (i = low; i < closure->provider_count; ++i) {
        const struct provider_key *key = &closure->providers[i];
        if (strcmp(key->kind, kind) || strcmp(key->name, file)) break;
        if (!closure_add(closure, key->index)) return 0;
    }
    return 1;
}

static int candidate_symbols(int dir, const struct object *object,
                             const struct soname_fact *fact,
                             const struct holy_scanned_file *consumer,
                             const char *needed)
{
    struct holy_scan_result scan = {0};
    char *snapshot = NULL, actual[65];
    size_t i, j;
    int fd, result = 0, required = 0;
    for (i = 0; i < consumer->elf.symbol_count; ++i) {
        const struct holy_elf_symbol *symbol = &consumer->elf.symbols[i];
        if (!symbol->section && symbol->binding != STB_WEAK && symbol->provider &&
            !strcmp(symbol->provider, needed)) { required = 1; break; }
    }
    if (!required) return 1;
    fd = openat(dir, object->filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return -1;
    snapshot = holy_stage_fd(fd, "holy-soname-probe");
    close(fd);
    if (!snapshot || !digest_file(snapshot, actual) ||
        strcmp(actual, object->identity.digest) ||
        !holy_scan_collect(snapshot, &scan)) { result = -1; goto done; }
    for (i = 0; i < scan.count; ++i) {
        const struct holy_scanned_file *file = &scan.files[i];
        if (strcmp(file->path, fact->path) || file->elf.type != ET_DYN ||
            (file->elf.flags1 & DF_1_PIE) || !file->elf.soname ||
            strcmp(file->elf.soname, needed) ||
            strcmp(holy_elf_machine(&file->elf), fact->arch) ||
            strcmp(file->runtime, fact->libc)) continue;
        result = 1;
        for (j = 0; j < consumer->elf.symbol_count; ++j) {
            const struct holy_elf_symbol *symbol = &consumer->elf.symbols[j];
            if (symbol->section || symbol->binding == STB_WEAK ||
                !symbol->provider || strcmp(symbol->provider, needed)) continue;
            if (!holy_elf_exports_symbol(&file->elf, symbol)) { result = 0; break; }
        }
        break;
    }
done:
    holy_scan_free(&scan);
    if (snapshot) { unlink(snapshot); free(snapshot); }
    return result;
}

static int indexed_exports_symbol(const struct object *object, const char *path,
                                  const struct holy_elf_symbol *wanted)
{
    size_t i;
    for (i = 0; i < object->export_count; ++i) {
        const struct export_fact *s = &object->exports[i];
        if (strcmp(s->path, path) || strcmp(s->name, wanted->name) ||
            (wanted->type == STT_TLS) != (s->type == STT_TLS) ||
            (wanted->type == STT_FUNC && s->type != STT_FUNC && s->type != 10) ||
            (wanted->type == STT_OBJECT && s->type != STT_OBJECT) ||
            (wanted->version && strcmp(s->version, wanted->version)) ||
            (!wanted->version && s->hidden)) continue;
        return 1;
    }
    return 0;
}

static int candidate_exports(const struct object *object,
                             const struct soname_fact *fact,
                             const struct holy_scanned_file *consumer,
                             const char *needed)
{
    size_t i;
    for (i = 0; i < consumer->elf.symbol_count; ++i) {
        const struct holy_elf_symbol *want = &consumer->elf.symbols[i];
        if (want->section || want->binding == STB_WEAK ||
            !want->provider || strcmp(want->provider, needed)) continue;
        if (!indexed_exports_symbol(object, fact->path, want)) return 0;
    }
    return 1;
}

static int object_soname_matches(int dir, const struct object *object,
                                 const struct holy_scanned_file *consumer,
                                 const char *needed, int export_index)
{
    size_t j, k;
    for (j = 0; j < object->soname_count; ++j) {
        const struct soname_fact *fact = &object->sonames[j];
        int compatible = 1, symbols;
        if (strcmp(fact->name, needed) ||
            strcmp(fact->arch, holy_elf_machine(&consumer->elf)) ||
            strcmp(fact->libc, consumer->runtime)) continue;
        for (k = 0; k < consumer->elf.version_count; ++k) {
            const struct holy_elf_version *want = &consumer->elf.versions[k];
            size_t n;
            if (want->weak || strcmp(want->provider, needed)) continue;
            for (n = 0; n < object->version_count; ++n)
                if (!strcmp(object->versions[n].path, fact->path) &&
                    !strcmp(object->versions[n].name, want->name)) break;
            if (n == object->version_count) { compatible = 0; break; }
        }
        if (!compatible) continue;
        symbols = export_index ? candidate_exports(object, fact, consumer, needed) :
                                 candidate_symbols(dir, object, fact, consumer, needed);
        if (symbols) return symbols;
    }
    return 0;
}

static int closure_soname(int dir, const struct object *objects, struct closure *closure,
                          const struct holy_scanned_file *consumer,
                          const char *needed, int export_index)
{
    size_t low = 0, high = closure->provider_count, i;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        const struct provider_key *key = &closure->providers[middle];
        int order = strcmp(key->kind, "soname");
        if (!order) order = strcmp(key->name, needed);
        if (order < 0) low = middle + 1;
        else high = middle;
    }
    for (i = low; i < closure->provider_count; ++i) {
        const struct provider_key *key = &closure->providers[i];
        const struct object *object = &objects[key->index];
        if (strcmp(key->kind, "soname") || strcmp(key->name, needed)) break;
        int matches = object_soname_matches(dir, object, consumer, needed,
                                            export_index);
        if (matches < 0) return 0;
        if (matches && !closure_add(closure, key->index)) return 0;
    }
    return 1;
}

static int closure_or_provider(void *opaque, const char *name,
                               const char *relation, const char *version)
{
    (void)relation; (void)version;
    return closure_provider(opaque, "package", name);
}

static int closure_expand(int dir, const struct object *objects,
                          struct closure *closure, size_t index,
                          const char *snapshot, int version_index,
                          int export_index)
{
    const struct object *o = &objects[index];
    struct holy_scan_result scan = {0};
    size_t i, j;
    int ok = 1;
    for (i = 0; i < o->requirement_count && ok; ++i) {
        const char *kind = o->requirements[i].fields[2];
        const char *name = o->requirements[i].fields[3];
        ok = !strcmp(kind, "package-or") ?
             holy_package_or_each(name, closure_or_provider, closure) :
             closure_provider(closure, kind, name);
    }
    if (ok) ok = holy_scan_collect(snapshot, &scan);
    for (i = 0; i < scan.count && ok; ++i) {
        const struct holy_elf_info *elf = &scan.files[i].elf;
        if (elf->interpreter && elf->interpreter[0] == '/')
            ok = closure_provider(closure, "file", elf->interpreter);
        for (j = 0; j < elf->needed_count && ok; ++j)
            ok = version_index && elf->needed[j][0] != '/' ?
                 closure_soname(dir, objects, closure, &scan.files[i],
                                elf->needed[j], export_index) :
                 closure_provider(closure,
                                  elf->needed[j][0] == '/' ? "file" : "soname",
                                  elf->needed[j]);
    }
    for (i = 0; i < scan.script_count && ok; ++i)
        if (scan.scripts[i].kind == 1 && scan.scripts[i].interpreter[0] == '/')
            ok = closure_provider(closure, "file",
                                  scan.scripts[i].interpreter);
    for (i = 0; i < scan.symlink_count && ok; ++i) {
        char *path = scan.symlinks[i].target[0] == '/' ?
            strdup(scan.symlinks[i].target) :
            holy_relative_link_path(scan.symlinks[i].path,
                strlen(scan.symlinks[i].path), scan.symlinks[i].target, "");
        if (!path) { ok = 0; break; }
        ok = closure_provider(closure, "file", path);
        free(path);
    }
    holy_scan_free(&scan);
    return ok;
}

static int mirror_object(struct mirror *mirror, int dir, const struct object *object)
{
    char *url = holy_fetch_child_url(mirror->base, object->filename);
    char name[70];
    int downloads, ok;
    if (!url) { mirror->status = 2; return 0; }
    mirror->status = holy_fetch_https(url, object->identity.digest,
                                      mirror->downloads, mirror->ca_file, 0);
    free(url);
    if (mirror->status) return 0;
    downloads = open(mirror->downloads, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (downloads < 0) { mirror->status = 1; return 0; }
    snprintf(name, sizeof name, "%s.holy", object->identity.digest);
    ok = !linkat(downloads, name, dir, object->filename, 0) && !fsync(dir);
    if (ok) ok = !unlinkat(downloads, name, 0) && !fsync(downloads);
    close(downloads);
    if (!ok) mirror->status = 1;
    return ok;
}

static int list_probe(const char *directory, const char *query,
                 const char *forced_index, int lock, int emit,
                 const char *fetch_digest, const char *output,
                 const char *provider_kind, const char *provider_name,
                 const char *solve_name, const char *solve_choice,
                  int solve_json, int *solve_rc, struct mirror *mirror,
                  int extract_name, const struct stage_request *stage,
                  const char *file_query, const struct holy_scanned_file *probe)
{
    struct object *objects = NULL;
    char **candidate_snapshots = NULL;
    struct closure closure = {0};
    struct stat st;
    FILE *index = NULL;
    char *line = NULL, *error = NULL, *index_snapshot = NULL, *chosen = NULL;
    char expected[65], actual_digest[65], index_name[71];
    size_t capacity = 0, count = 0, i, j, number = 0, cursor;
    ssize_t length;
    int dir = -1, fd = -1, ok = 0, indexed = 0, file_index = 0;
    int dependency_index = 0, soname_index = 0, version_index = 0;
    int export_index = 0, comparator_index = 0;

    dir = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || (lock && flock(dir, LOCK_SH) < 0)) goto done;
    if (forced_index) {
        if (!*forced_index || strlen(forced_index) >= sizeof index_name ||
            strchr(forced_index, '/')) goto done;
        strcpy(index_name, forced_index);
    } else {
        if (read_current(dir, expected) != 1) goto done;
        snprintf(index_name, sizeof index_name, "index.%s", expected);
    }
    fd = openat(dir, index_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size < 0 || st.st_size > 128LL * 1024 * 1024) goto done;
    index_snapshot = holy_stage_fd(fd, "holy-catalog");
    close(fd);
    fd = -1;
    if (!index_snapshot || (!forced_index &&
        (!digest_file(index_snapshot, actual_digest) ||
         strcmp(actual_digest, expected)))) goto done;
    index = fopen(index_snapshot, "r");
    if (!index) goto done;
    while ((length = getline(&line, &capacity, index)) >= 0) {
        char **v = NULL;
        size_t n = 0;
        struct object *next;
        ++number;
        if (length > 1024 * 1024 || memchr(line, '\0', (size_t)length) ||
            !holy_lex(line, (size_t)length, &v, &n, "index", number, &error)) {
            holy_tokens_free(v, n);
            goto done;
        }
        if (number == 1) {
            int valid = n == 2 && !strcmp(v[0], "format") &&
                        (!strcmp(v[1], "holy-index-prototype-1") ||
                         !strcmp(v[1], "holy-index-prototype-2") ||
                         !strcmp(v[1], "holy-index-prototype-3") ||
                         !strcmp(v[1], "holy-index-prototype-4") ||
                         !strcmp(v[1], "holy-index-prototype-5") ||
                         !strcmp(v[1], "holy-index-prototype-6") ||
                         !strcmp(v[1], "holy-index-prototype-7") ||
                         !strcmp(v[1], "holy-index-prototype-8"));
            if (valid) {
                indexed = strcmp(v[1], "holy-index-prototype-1") != 0;
                file_index = !strcmp(v[1], "holy-index-prototype-3") ||
                             !strcmp(v[1], "holy-index-prototype-4") ||
                             !strcmp(v[1], "holy-index-prototype-5") ||
                             !strcmp(v[1], "holy-index-prototype-6") ||
                             !strcmp(v[1], "holy-index-prototype-7") ||
                             !strcmp(v[1], "holy-index-prototype-8");
                dependency_index = !strcmp(v[1], "holy-index-prototype-4") ||
                                   !strcmp(v[1], "holy-index-prototype-5") ||
                                   !strcmp(v[1], "holy-index-prototype-6") ||
                                   !strcmp(v[1], "holy-index-prototype-7") ||
                                   !strcmp(v[1], "holy-index-prototype-8");
                soname_index = !strcmp(v[1], "holy-index-prototype-5") ||
                               !strcmp(v[1], "holy-index-prototype-6") ||
                                   !strcmp(v[1], "holy-index-prototype-7") ||
                                   !strcmp(v[1], "holy-index-prototype-8");
                version_index = !strcmp(v[1], "holy-index-prototype-6") ||
                                !strcmp(v[1], "holy-index-prototype-7") ||
                                !strcmp(v[1], "holy-index-prototype-8");
                export_index = !strcmp(v[1], "holy-index-prototype-7") ||
                               !strcmp(v[1], "holy-index-prototype-8");
                comparator_index = !strcmp(v[1], "holy-index-prototype-8");
            }
            holy_tokens_free(v, n);
            if (!valid) goto done;
            continue;
        }
        if (file_index && number == 2) {
            int valid = n == 3 && !strcmp(v[0], "coverage") &&
                        !strcmp(v[1], "files") && !strcmp(v[2], "complete");
            holy_tokens_free(v, n);
            if (!valid) goto done;
            continue;
        }
        if (dependency_index && number == 3) {
            int valid = n == 3 && !strcmp(v[0], "coverage") &&
                        !strcmp(v[1], "dependencies") && !strcmp(v[2], "complete");
            holy_tokens_free(v, n);
            if (!valid) goto done;
            continue;
        }
        if (soname_index && number == 4) {
            int valid = n == 3 && !strcmp(v[0], "coverage") &&
                        !strcmp(v[1], "elf-sonames") && !strcmp(v[2], "complete");
            holy_tokens_free(v, n);
            if (!valid) goto done;
            continue;
        }
        if (version_index && number == 5) {
            int valid = n == 3 && !strcmp(v[0], "coverage") &&
                        !strcmp(v[1], "elf-versions") && !strcmp(v[2], "complete");
            holy_tokens_free(v, n);
            if (!valid) goto done;
            continue;
        }
        if (export_index && number == 6) {
            int valid = n == 3 && !strcmp(v[0], "coverage") &&
                        !strcmp(v[1], "elf-exports") && !strcmp(v[2], "complete");
            holy_tokens_free(v, n);
            if (!valid) goto done;
            continue;
        }
        if (indexed && n && !strcmp(v[0], "claim")) {
            int valid = count && !objects[count - 1].file_count &&
                        !objects[count - 1].requirement_count &&
                        !objects[count - 1].soname_count &&
                        !objects[count - 1].version_count &&
                        !objects[count - 1].export_count &&
                        parse_claim(v, n, &objects[count - 1]);
            holy_tokens_free(v, n);
            if (!valid) goto done;
            continue;
        }
        if (dependency_index && n && !strcmp(v[0], "require")) {
            int valid = count && !objects[count - 1].file_count &&
                        !objects[count - 1].soname_count &&
                        !objects[count - 1].version_count &&
                        !objects[count - 1].export_count &&
                        parse_requirement(v, n, &objects[count - 1]);
            holy_tokens_free(v, n);
            if (!valid) goto done;
            continue;
        }
        if (soname_index && n && !strcmp(v[0], "soname")) {
            int valid = count && !objects[count - 1].file_count &&
                        !objects[count - 1].version_count &&
                        !objects[count - 1].export_count &&
                        parse_soname(v, n, &objects[count - 1]);
            holy_tokens_free(v, n);
            if (!valid) goto done;
            continue;
        }
        if (version_index && n && !strcmp(v[0], "elf-version")) {
            int valid = count && !objects[count - 1].file_count &&
                        !objects[count - 1].export_count &&
                        parse_version(v, n, &objects[count - 1]);
            holy_tokens_free(v, n);
            if (!valid) goto done;
            continue;
        }
        if (export_index && n && !strcmp(v[0], "elf-export")) {
            int valid = count && !objects[count - 1].file_count &&
                        parse_export(v, n, &objects[count - 1]);
            holy_tokens_free(v, n);
            if (!valid) goto done;
            continue;
        }
        if (file_index && n && !strcmp(v[0], "file")) {
            int valid = count && parse_file(v, n, &objects[count - 1]);
            holy_tokens_free(v, n);
            if (!valid) goto done;
            continue;
        }
        if (count == (size_t)-1 / sizeof *objects) {
            holy_tokens_free(v, n);
            goto done;
        }
        next = realloc(objects, (count + 1) * sizeof *objects);
        if (!next) { holy_tokens_free(v, n); goto done; }
        objects = next;
        memset(&objects[count], 0, sizeof *objects);
        if ((comparator_index && n != 11) ||
            !parse_record(v, n, &objects[count])) {
            holy_tokens_free(v, n);
            goto done;
        }
        holy_tokens_free(v, n);
        ++count;
        for (i = 0; i + 1 < count; ++i)
            if (!strcmp(objects[i].filename, objects[count - 1].filename) ||
                same_identity(&objects[i].identity, &objects[count - 1].identity))
                goto done;
    }
    if (ferror(index) || !number || (file_index && number < 2) ||
        (dependency_index && number < 3) ||
        (soname_index && number < 4) ||
        (version_index && number < 5) ||
        (export_index && number < 6)) goto done;
    if (emit == 8 && (((!strcmp(provider_kind, "file") ||
                        !strcmp(provider_kind, "command")) && !file_index) ||
                      (!strcmp(provider_kind, "soname") && !soname_index) ||
                      (probe && !version_index) ||
                      !strcmp(provider_kind, "symbol-version"))) {
        *solve_rc = 6;
        ok = 1;
        goto done;
    }
    if (mirror) {
        for (i = 0; i < count; ++i)
            if (!mirror_object(mirror, dir, &objects[i])) goto done;
    }
    if (solve_name || (stage && stage->provider)) {
        candidate_snapshots = calloc(count ? count : 1, sizeof *candidate_snapshots);
        if (!candidate_snapshots) goto done;
    }
    if (stage && (solve_name || stage->provider) && !stage->slot && !stage->index_only &&
        dependency_index && file_index && soname_index) {
        size_t root = count, roots = 0;
        if (!stage->provider) {
            size_t named = 0;
            for (i = 0; i < count; ++i) {
                if (strcmp(objects[i].identity.name, solve_name)) continue;
                ++named;
                if (stage->arch && strcmp(objects[i].identity.arch, stage->arch)) continue;
                if (stage->libc && strcmp(objects[i].identity.libc, stage->libc)) continue;
                root = i;
                ++roots;
            }
            if (roots != 1 && roots) {
                size_t newest = family_root(objects, count, solve_name,
                                            stage->arch, stage->libc);
                if (newest < count) {
                    size_t members = 0;
                    for (i = 0; i < count; ++i)
                        if (!strcmp(objects[i].identity.name, solve_name) &&
                            (!stage->arch || !strcmp(objects[i].identity.arch, stage->arch)) &&
                            (!stage->libc || !strcmp(objects[i].identity.libc, stage->libc)))
                            ++members;
                    root = newest;
                    roots = 1;
                    report_family_root(&objects[newest], solve_name, members, solve_json);
                }
            }
            if (roots != 1) {
                *solve_rc = roots ? 3 : 6;
                /* a name the catalog has and a slot it does not is a different answer
                   from a name it does not have, and the caller needs to know which */
                if (roots) fprintf(stderr, "holypkg: repository root %s\n",
                                   "requires package choice");
                else if (named) fprintf(stderr, "holypkg: repository root %s has no %s\n",
                                        solve_name, stage->arch ? "artifact of that arch"
                                                               : "artifact of that arch and libc");
                else fprintf(stderr, "holypkg: repository root %s not found\n", solve_name);
                ok = 1; goto done;
            }
        }
        closure.selected = calloc(count, 1);
        closure.queue = calloc(count, sizeof *closure.queue);
        if (!closure.selected || !closure.queue ||
            !closure_index(objects, count, &closure)) goto done;
        if (stage->provider) {
            for (i = 0; i < count; ++i)
                if (indexed_provider(&objects[i], provider_kind, provider_name,
                                     file_index, soname_index)) closure_add(&closure, i);
            if (!closure.count) { *solve_rc = 4; ok = 1; goto done; }
        } else closure_add(&closure, root);
    }
    if (stage && stage->provider && !closure.selected) {
        *solve_rc = 6;
        ok = 1; goto done;
    }
    for (cursor = 0; cursor < (closure.selected ? closure.count : count); ++cursor) {
        struct holy_package_identity actual;
        char *snapshot;
        int input, matches;
        i = closure.selected ? closure.queue[cursor] : cursor;
        if (stage && (stage->index_only ||
            (stage->slot && !same_slot(&objects[i].identity, stage->slot)) ||
            (stage->digest && strcmp(objects[i].identity.digest, stage->digest))))
            continue;
        if (query && (emit == 1 || emit == 3) &&
            strcmp(query, objects[i].identity.name)) continue;
        if (fetch_digest && strcmp(fetch_digest, objects[i].identity.digest))
            continue;
        if (solve_name && output && !stage &&
            strcmp(solve_name, objects[i].identity.name)) continue;
        if (emit == 5 && query && fuzzy_rank(query, objects[i].identity.name) < 0)
            continue;
        if (file_query) {
            const char *matched;
            if (!file_index || (emit == 6 ?
                file_hint(&objects[i], file_query, &matched) < 0 :
                !indexed_file(&objects[i], file_query))) continue;
        }
        if (indexed && provider_kind && !(stage && stage->provider)) {
            size_t k;
            objects[i].provider_match = emit == 8 ?
                indexed_provider(&objects[i], provider_kind, provider_name,
                                 file_index, soname_index) :
                !strcmp(provider_kind, "package") &&
                !strcmp(provider_name, objects[i].identity.name);
            if (emit == 8 && probe && objects[i].provider_match) {
                int match = object_soname_matches(dir, &objects[i], probe,
                                                   provider_name, export_index);
                if (match < 0) goto done;
                objects[i].provider_match = match;
            }
            if (emit == 8) {
                if (!objects[i].provider_match) continue;
            } else if (soname_index && !strcmp(provider_kind, "soname")) {
                for (k = 0; k < objects[i].soname_count; ++k)
                    if (!strcmp(objects[i].sonames[k].name, provider_name))
                        objects[i].provider_match = 1;
            } else for (k = 0; k < objects[i].claim_count; ++k)
                if (!strcmp(objects[i].claims[k].kind, provider_kind) &&
                    !strcmp(objects[i].claims[k].name, provider_name))
                    objects[i].provider_match = 1;
            if (!objects[i].provider_match) continue;
        }
        if (emit == 7 || (emit == 8 && indexed)) continue;
        input = openat(dir, objects[i].filename,
                            O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        if (input < 0) goto done;
        snapshot = holy_stage_fd(input, "holy-list");
        close(input);
        if (!snapshot) goto done;
        matches = holy_verify_with_output(snapshot, 0) &&
                  holy_scan_local_with_output(snapshot, 0) &&
                  holy_deps_local_with_output(snapshot, 0) &&
                  holy_provides_local(snapshot, 0) &&
                  holy_package_identity(snapshot, &actual);
        if (matches) {
            matches = same_identity(&objects[i].identity, &actual) &&
                      (!comparator_index ||
                       (!objects[i].identity.version_family == !actual.version_family &&
                        (!actual.version_family ||
                         !strcmp(objects[i].identity.version_family, actual.version_family)))) &&
                      !strcmp(objects[i].identity.digest, actual.digest) &&
                      objects[i].identity.size == actual.size;
            holy_package_identity_free(&actual);
        }
        if (!matches) {
            unlink(snapshot);
            free(snapshot);
            goto done;
        }
        if (indexed) {
            struct claim_cursor cursor = {&objects[i], 0};
            if (!holy_provides_visit(snapshot, compare_claim, &cursor) ||
                cursor.index != objects[i].claim_count) {
                unlink(snapshot);
                free(snapshot);
                goto done;
            }
        }
        if (dependency_index) {
            struct requirement_cursor cursor = {&objects[i], 0};
            if (!holy_deps_visit(snapshot, compare_requirement, &cursor) ||
                cursor.index != objects[i].requirement_count) {
                unlink(snapshot);
                free(snapshot);
                goto done;
            }
        }
        if (soname_index && !compare_sonames(snapshot, &objects[i],
                                             version_index, export_index)) {
            unlink(snapshot);
            free(snapshot);
            goto done;
        }
        if (file_index) {
            struct file_cursor cursor = {&objects[i], 0};
            if (!holy_verify_visit(snapshot, compare_file, &cursor) ||
                cursor.index != objects[i].file_count) {
                unlink(snapshot);
                free(snapshot);
                goto done;
            }
        }
        if (closure.selected &&
            !closure_expand(dir, objects, &closure, i, snapshot,
                            version_index, export_index)) {
            unlink(snapshot);
            free(snapshot);
            goto done;
        }
        if (provider_kind && !indexed && !(stage && stage->provider)) {
            int claim = 0;
            if (!holy_provides_match(snapshot, provider_kind,
                                     provider_name, &claim)) {
                unlink(snapshot);
                free(snapshot);
                goto done;
            }
            objects[i].provider_match = claim ||
                (!strcmp(provider_kind, "package") &&
                 !strcmp(provider_name, objects[i].identity.name));
        }
        if (solve_name || (stage && stage->provider)) candidate_snapshots[i] = snapshot;
        else if (fetch_digest && !strcmp(fetch_digest, objects[i].identity.digest))
            chosen = snapshot;
        else {
            unlink(snapshot);
            free(snapshot);
        }
    }
    if (fetch_digest && (!chosen || !holy_fetch_local(chosen, output))) goto done;
    if (solve_name) {
        const char **paths = NULL;
        size_t root = count, roots = 0, next = 1, named = 0;
        for (i = 0; i < count; ++i) {
            if (strcmp(objects[i].identity.name, solve_name)) continue;
            ++named;
            /* the same two fields the caller named, applied where the verified pool is
               re-counted, so the choice is made once and means the same thing twice */
            if (stage && stage->arch && strcmp(objects[i].identity.arch, stage->arch))
                continue;
            if (stage && stage->libc && strcmp(objects[i].identity.libc, stage->libc))
                continue;
            root = i;
            ++roots;
        }
        if (roots != 1 && roots) {
            size_t newest = family_root(objects, count, solve_name,
                                        stage ? stage->arch : NULL,
                                        stage ? stage->libc : NULL);
            if (newest < count) {
                size_t members = 0;
                for (i = 0; i < count; ++i)
                    if (!strcmp(objects[i].identity.name, solve_name) &&
                        (!stage || !stage->arch ||
                         !strcmp(objects[i].identity.arch, stage->arch)) &&
                        (!stage || !stage->libc ||
                         !strcmp(objects[i].identity.libc, stage->libc)))
                        ++members;
                root = newest;
                roots = 1;
                report_family_root(&objects[newest], solve_name, members, solve_json);
            }
        }
        if (roots != 1 && !(stage && stage->slot)) {
            *solve_rc = roots ? 3 : 6;
            /* a name the catalog has and a slot it does not is a different answer from
               a name it does not have */
            if (roots) fprintf(stderr, "holypkg: repository root requires package choice\n");
            else if (named) fprintf(stderr, "holypkg: repository root %s has no artifact of "
                                   "that arch and libc\n", solve_name);
            else fprintf(stderr, "holypkg: repository root %s not found\n", solve_name);
            if (solve_json)
                printf("{\"schema\":\"holy-local-solve-1\",\"type\":\"error\",\"code\":\"%s\"}\n",
                       roots ? "decision-required" : "unavailable-artifact");
        } else if (stage) {
            size_t position = 0;
            *solve_rc = 6;
            if (count > 100000) { ok = 1; goto done; }
            stage->set->digests = calloc(closure.selected ? closure.count : count,
                                         sizeof *stage->set->digests);
            if (!stage->set->digests) { *solve_rc = 1; ok = 1; goto done; }
            for (cursor = 0; cursor < (closure.selected ? closure.count : count); ++cursor) {
                i = closure.selected ? closure.queue[cursor] : cursor;
                if (stage->slot && !same_slot(&objects[i].identity, stage->slot))
                    continue;
                if (stage->digest && strcmp(objects[i].identity.digest, stage->digest))
                    continue;
                size_t selected = closure.selected ? i :
                                  stage->slot ? i : i ? (i <= root ? i - 1 : i) : root;
                char actual[65];
                if (position >= 10000) { *solve_rc = 6; ok = 1; goto done; }
                if (!holy_cache_stage_local_digest(candidate_snapshots[selected],
                                                   stage->root, actual)) {
                    *solve_rc = 1; ok = 1; goto done;
                }
                if (strcmp(actual, objects[selected].identity.digest)) {
                    *solve_rc = 4; ok = 1; goto done;
                }
                stage->set->digests[position] = strdup(actual);
                if (!stage->set->digests[position]) { *solve_rc = 1; ok = 1; goto done; }
                ++position;
                stage->set->count = position;
            }
            memcpy(stage->set->index, expected, 65);
            *solve_rc = position ? 0 : 6;
        } else if (output) {
            *solve_rc = (extract_name ?
                         holy_extract_local(candidate_snapshots[root], output) :
                         holy_fetch_local(candidate_snapshots[root], output)) ? 0 : 1;
        } else {
            paths = calloc(count, sizeof *paths);
            if (!paths) goto done;
            paths[0] = candidate_snapshots[root];
            for (i = 0; i < count; ++i)
                if (i != root) paths[next++] = candidate_snapshots[i];
            *solve_rc = holy_resolve_local(paths, count, solve_json, expected,
                                           solve_choice);
            free(paths);
        }
    }
    if (stage && stage->provider) {
        size_t position = 0;
        stage->set->digests = calloc(closure.count, sizeof *stage->set->digests);
        if (!stage->set->digests) { *solve_rc = 1; ok = 1; goto done; }
        for (cursor = 0; cursor < closure.count; ++cursor) {
            char actual[65];
            i = closure.queue[cursor];
            if (position >= 10000 || !candidate_snapshots[i] ||
                !holy_cache_stage_local_digest(candidate_snapshots[i], stage->root, actual)) {
                *solve_rc = 6; ok = 1; goto done;
            }
            if (strcmp(actual, objects[i].identity.digest)) {
                *solve_rc = 4; ok = 1; goto done;
            }
            stage->set->digests[position] = strdup(actual);
            if (!stage->set->digests[position]) { *solve_rc = 1; ok = 1; goto done; }
            stage->set->count = ++position;
        }
        memcpy(stage->set->index, expected, 65);
        *solve_rc = position ? 0 : 6;
    }
    if (emit == 7) {
        size_t found = count, matches = 0;
        if (!dependency_index) {
            fputs("status unknown: source has no complete dependency index\n", stdout);
            if (solve_rc) *solve_rc = 6;
        } else {
            size_t named = 0;
            for (j = 0; j < count; ++j) {
                if (strcmp(objects[j].identity.name, query)) continue;
                ++named;
                /* a name one repository carries for several architectures is a choice
                   the caller makes with --arch or --libc, and never a guess */
                if (stage && stage->arch && strcmp(objects[j].identity.arch, stage->arch))
                    continue;
                if (stage && stage->libc && strcmp(objects[j].identity.libc, stage->libc))
                    continue;
                found = j;
                ++matches;
            }
            if (matches > 1) {
                /* several versions of one slot are one thing at two versions, so the
                   newest member answers the name. several slots are the architecture or
                   ABI choice the caller makes with --arch or --libc */
                size_t newest = family_root(objects, count, query,
                                            stage ? stage->arch : NULL,
                                            stage ? stage->libc : NULL);
                if (newest < count) {
                    size_t members = 0;
                    for (j = 0; j < count; ++j)
                        if (!strcmp(objects[j].identity.name, query) &&
                            (!stage || !stage->arch ||
                             !strcmp(objects[j].identity.arch, stage->arch)) &&
                            (!stage || !stage->libc ||
                             !strcmp(objects[j].identity.libc, stage->libc)))
                            ++members;
                    found = newest;
                    matches = 1;
                    /* repo requirements has no JSON form, so this is always the line */
                    report_family_root(&objects[newest], query, members, 0);
                }
            }
            if (matches == 1) {
                if (!record(stdout, &objects[found])) goto done;
                for (j = 0; j < objects[found].requirement_count; ++j)
                    if (!requirement_record(stdout, &objects[found],
                                            &objects[found].requirements[j])) goto done;
                printf("requirements %zu\n", objects[found].requirement_count);
                if (solve_rc) *solve_rc = 0;
            } else {
                if (matches) fprintf(stderr, "holypkg: repository package requires an "
                                   "architecture/ABI choice\n");
                else if (named)
                    fprintf(stderr, "holypkg: repository package %s has no artifact of "
                            "that arch and libc\n", query);
                else fprintf(stderr, "holypkg: repository package %s not found\n", query);
                if (solve_rc) *solve_rc = matches ? 3 : 6;
            }
        }
    } else if (emit == 5 || emit == 6) {
        size_t matches = 0, shown = 0;
        int rank;
        for (rank = 0; rank <= 5; ++rank) for (j = 0; j < count; ++j) {
            const char *matched = NULL;
            int score = emit == 5 ? fuzzy_rank(query, objects[j].identity.name) :
                        file_index ? file_hint(&objects[j], file_query, &matched) : -1;
            if (score != rank) continue;
            ++matches;
            if (shown == 20) continue;
            printf("suggestion score %d %s ", score, emit == 5 ? "name" : "path");
            if (!quote(stdout, emit == 5 ? objects[j].identity.name : matched) ||
                fputc('\n', stdout) == EOF || !record(stdout, &objects[j])) goto done;
            ++shown;
        }
        if (emit == 6) {
            printf("coverage files %s index %s time %lld\n",
                   file_index ? "complete" : "unavailable", expected,
                   (long long)st.st_mtime);
            if (!file_index) {
                fputs("status unknown: source has no complete file index\n", stdout);
                if (solve_rc) *solve_rc = 6;
            } else if (solve_rc) *solve_rc = 0;
        }
        printf("suggested %zu of %zu %s\n", shown, matches,
               emit == 5 ? "packages" : "file candidates");
    } else {
        size_t matches = 0, named = 0, only = count;
        for (j = 0; j < count; ++j) {
            if (query && strcmp(objects[j].identity.name, query)) continue;
            if (query) ++named;
            /* a name one repository carries for several architectures is a choice the
               caller makes with --arch or --libc, and never a guess */
            if (stage && stage->arch && strcmp(objects[j].identity.arch, stage->arch))
                continue;
            if (stage && stage->libc && strcmp(objects[j].identity.libc, stage->libc))
                continue;
            if (provider_kind && !objects[j].provider_match) continue;
            if (file_query && (!file_index || !indexed_file(&objects[j], file_query)))
                continue;
            if (emit == 1 && !record(stdout, &objects[j])) goto done;
            if (emit == 2) candidate_json(&objects[j]);
            if (emit == 3) only = j;
            if (emit == 4 && !record(stdout, &objects[j])) goto done;
            ++matches;
        }
        if (emit == 1) printf("listed %zu %s\n", matches,
                              provider_kind ? "candidates" : "packages");
        if (emit == 2) printf("{\"schema\":\"holy-repo-candidates-1\",\"type\":\"summary\",\"count\":%zu}\n", matches);
        if (emit == 3) {
            if (matches > 1) {
                /* the same version family the solve and requirements paths read: a name
                   the catalog carries at two versions of one slot is one thing, and its
                   newest member is the package the caller asked about */
                size_t newest = family_root(objects, count, query,
                                            stage ? stage->arch : NULL,
                                            stage ? stage->libc : NULL);
                if (newest < count) {
                    size_t members = 0;
                    for (j = 0; j < count; ++j)
                        if (!strcmp(objects[j].identity.name, query) &&
                            (!stage || !stage->arch ||
                             !strcmp(objects[j].identity.arch, stage->arch)) &&
                            (!stage || !stage->libc ||
                             !strcmp(objects[j].identity.libc, stage->libc)))
                            ++members;
                    only = newest;
                    matches = 1;
                    /* info has no JSON form, so this is always the line */
                    report_family_root(&objects[newest], query, members, 0);
                }
            }
            *solve_rc = matches > 1 ? 3 : matches ? 0 : 6;
            if (matches == 1 && !record(stdout, &objects[only])) goto done;
            if (matches != 1) {
                if (matches) fprintf(stderr, "holypkg: repository package requires an "
                                   "architecture/ABI choice\n");
                else if (named) fprintf(stderr, "holypkg: repository package %s has no "
                                       "artifact of that arch and libc\n", query);
                else fprintf(stderr, "holypkg: repository package %s not found\n", query);
            }
        }
        if (emit == 8 && solve_rc) *solve_rc = matches ? 0 : 4;
        if (emit == 4) {
            printf("coverage files %s index %s time %lld\n",
                   file_index ? "complete" : "unavailable", expected,
                   (long long)st.st_mtime);
            printf("listed %zu file candidates\n", matches);
            if (!file_index) {
                fputs("status unknown: source has no complete file index\n", stdout);
                if (solve_rc) *solve_rc = 6;
            } else if (solve_rc) *solve_rc = 0;
        }
    }
    if (stage && stage->index_only) {
        memcpy(stage->set->index, expected, 65);
        if (stage->candidates) {
            struct holy_repo_slot_list *list = stage->candidates;
            size_t matches = 0;
            for (i = 0; i < count; ++i)
                if (same_slot(&objects[i].identity, stage->slot)) ++matches;
            list->items = calloc(matches ? matches : 1, sizeof *list->items);
            if (!list->items) goto done;
            for (i = 0; i < count; ++i) if (same_slot(&objects[i].identity, stage->slot)) {
                if (!copy_identity(&list->items[list->count], &objects[i].identity)) {
                    ++list->count;
                    goto done;
                }
                ++list->count;
            }
            memcpy(list->index, expected, 65);
            *solve_rc = matches ? 0 : 6;
        }
        if (stage->digest) {
            *solve_rc = 3;
            for (i = 0; i < count; ++i)
                if (!strcmp(objects[i].identity.digest, stage->digest) &&
                    same_slot(&objects[i].identity, stage->slot)) {
                    *solve_rc = 0;
                    break;
                }
        }
    }
    ok = 1;
done:
    if (!ok) {
        fprintf(stderr, "holypkg: invalid or stale repository index%s%s\n",
                error ? ": " : "", error ? error : "");
        if (emit == 2) puts("{\"schema\":\"holy-repo-candidates-1\",\"type\":\"error\",\"code\":\"invalid-catalog\"}");
    }
    free(error);
    free(line);
    if (index) fclose(index);
    if (index_snapshot) { unlink(index_snapshot); free(index_snapshot); }
    if (chosen) { unlink(chosen); free(chosen); }
    if (candidate_snapshots) {
        for (i = 0; i < count; ++i)
            if (candidate_snapshots[i]) {
                unlink(candidate_snapshots[i]);
                free(candidate_snapshots[i]);
            }
        free(candidate_snapshots);
    }
    if (fd >= 0) close(fd);
    for (i = 0; i < count; ++i) {
        free(objects[i].filename);
        holy_package_identity_free(&objects[i].identity);
        free_claims(&objects[i]);
        free_requirements(&objects[i]);
        free_sonames(&objects[i]);
        free_versions(&objects[i]);
        free_exports(&objects[i]);
        free_files(&objects[i]);
    }
    free(objects);
    free(closure.selected);
    free(closure.queue);
    free(closure.providers);
    if (dir >= 0) close(dir);
    return ok;
}

static int list(const char *directory, const char *query,
                const char *forced_index, int lock, int emit,
                const char *fetch_digest, const char *output,
                const char *provider_kind, const char *provider_name,
                const char *solve_name, const char *solve_choice,
                int solve_json, int *solve_rc, struct mirror *mirror,
                int extract_name, const struct stage_request *stage,
                const char *file_query)
{
    return list_probe(directory, query, forced_index, lock, emit,
                      fetch_digest, output, provider_kind, provider_name,
                      solve_name, solve_choice, solve_json, solve_rc, mirror,
                      extract_name, stage, file_query, NULL);
}

int holy_repo_list(const char *directory)
{
    return list(directory, NULL, NULL, 1, 1, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, 0, NULL, NULL);
}

int holy_repo_search(const char *directory, const char *query)
{
    if (!query || !*query) {
        fprintf(stderr, "holypkg: package name required\n");
        return 0;
    }
    return list(directory, query, NULL, 1, 1, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, 0, NULL, NULL);
}

int holy_repo_search_fuzzy(const char *directory, const char *query)
{
    if (!query || !*query) return 2;
    return list(directory, query, NULL, 1, 5, NULL, NULL, NULL, NULL,
                NULL, NULL, 0, NULL, NULL, 0, NULL, NULL) ? 0 : 6;
}

int holy_repo_search_file(const char *directory, const char *query)
{
    int result = 6;
    if (!query || query[0] != '/' || !query[1] ||
        !safe_target_path(query + 1)) {
        fprintf(stderr, "holypkg: absolute file path required\n");
        return 2;
    }
    if (!list(directory, NULL, NULL, 1, 4, NULL, NULL, NULL, NULL,
              NULL, NULL, 0, &result, NULL, 0, NULL, query + 1)) return 6;
    return result;
}

int holy_repo_search_file_fuzzy(const char *directory, const char *query)
{
    int result = 6;
    if (!query || !*query || query[strlen(query) - 1] == '/' ||
        (query[0] != '/' && strchr(query, '/'))) return 2;
    if (query[0] == '/' && !safe_target_path(query + 1)) return 2;
    if (!list(directory, NULL, NULL, 1, 6, NULL, NULL, NULL, NULL,
              NULL, NULL, 0, &result, NULL, 0, NULL, query)) return 6;
    return result;
}

int holy_repo_info_name(const char *directory, const char *name,
                        const char *arch, const char *libc)
{
    /* the filters travel in the stage so one query loop serves both, and the set is a
       real one because the loop writes the index digest into it */
    struct holy_repo_set set;
    struct stage_request stage = {NULL, &set, NULL, NULL, 0, 0, NULL, arch, libc};
    int result = 6;
    if (!name || !*name) return 2;
    memset(&set, 0, sizeof set);
    if (!list(directory, name, NULL, 1, 3, NULL, NULL, NULL, NULL,
              NULL, NULL, 0, &result, NULL, 0, &stage, NULL)) return 6;
    holy_repo_set_free(&set);
    return result;
}

int holy_repo_requirements(const char *directory, const char *name,
                           const char *arch, const char *libc)
{
    /* the filters travel in the stage so one query loop serves both, and the set is a
       real one because the loop writes the index digest into it */
    struct holy_repo_set set;
    struct stage_request stage = {NULL, &set, NULL, NULL, 0, 0, NULL, arch, libc};
    int result = 6;
    if (!name || !*name) return 2;
    memset(&set, 0, sizeof set);
    if (!list(directory, name, NULL, 1, 7, NULL, NULL, NULL, NULL,
              NULL, NULL, 0, &result, NULL, 0, &stage, NULL)) return 6;
    holy_repo_set_free(&set);
    return result;
}

int holy_repo_providers(const char *directory, const char *kind,
                        const char *name, int json)
{
    if (!holy_provides_kind(kind) || !name || !*name) {
        fprintf(stderr, "holypkg: provider kind and exact name required\n");
        if (json) puts("{\"schema\":\"holy-repo-candidates-1\",\"type\":\"error\",\"code\":\"invalid-query\"}");
        return 0;
    }
    return list(directory, NULL, NULL, 1, json ? 2 : 1,
                NULL, NULL, kind, name, NULL, NULL, 0, NULL, NULL, 0, NULL, NULL);
}

int holy_repo_has_provider(const char *directory, const char *kind,
                           const char *name)
{
    int result = 6;
    if ((!holy_provides_kind(kind) && strcmp(kind, "package-or")) ||
        !name || !*name ||
        (!strcmp(kind, "package-or") && !holy_package_or_each(name, NULL, NULL))) return 2;
    if (!list(directory, NULL, NULL, 1, 8, NULL, NULL, kind, name,
              NULL, NULL, 0, &result, NULL, 0, NULL, NULL)) return 6;
    return result;
}

int holy_repo_has_compatible_soname(const char *directory, const char *name,
                                    const char *root, const char *consumer_digest,
                                    const char *consumer_path)
{
    struct holy_scan_result scan = {0};
    const struct holy_scanned_file *consumer = NULL;
    char *snapshot;
    size_t i, j;
    int result = 6;
    if (!directory || !name || !*name || strchr(name, '/') || !root ||
        !consumer_digest || strlen(consumer_digest) != 64 || !consumer_path)
        return 2;
    snapshot = holy_cache_snapshot(consumer_digest, root);
    if (!snapshot) return 6;
    if (!holy_scan_collect(snapshot, &scan)) goto done;
    for (i = 0; i < scan.count; ++i) {
        const struct holy_scanned_file *file = &scan.files[i];
        if (strcmp(file->path, consumer_path)) continue;
        for (j = 0; j < file->elf.needed_count; ++j)
            if (!strcmp(file->elf.needed[j], name)) break;
        if (j == file->elf.needed_count || consumer) goto done;
        consumer = file;
    }
    if (!consumer) goto done;
    if (!list_probe(directory, NULL, NULL, 1, 8, NULL, NULL, "soname", name,
                    NULL, NULL, 0, &result, NULL, 0, NULL, NULL, consumer)) result = 6;
done:
    holy_scan_free(&scan);
    unlink(snapshot);
    free(snapshot);
    return result;
}

int holy_repo_solve(const char *directory, const char *name,
                    const char *choice, int json)
{
    int result = 6;
    if (!name || !*name) {
        fprintf(stderr, "holypkg: repository package name required\n");
        if (json) puts("{\"schema\":\"holy-local-solve-1\",\"type\":\"error\",\"code\":\"invalid-query\"}");
        return 2;
    }
    if (!list(directory, NULL, NULL, 1, 0, NULL, NULL,
              NULL, NULL, name, choice, json, &result, NULL, 0, NULL, NULL)) {
        if (json) puts("{\"schema\":\"holy-local-solve-1\",\"type\":\"error\",\"code\":\"invalid-catalog\"}");
        return 6;
    }
    return result;
}

int holy_repo_fetch(const char *directory, const char *digest, const char *output)
{
    size_t i;
    if (!digest || strlen(digest) != 64) goto invalid;
    for (i = 0; i < 64; ++i)
        if (!((digest[i] >= '0' && digest[i] <= '9') ||
              (digest[i] >= 'a' && digest[i] <= 'f'))) goto invalid;
    return list(directory, NULL, NULL, 1, 0, digest, output, NULL, NULL, NULL, NULL, 0, NULL, NULL, 0, NULL, NULL);
invalid:
    fprintf(stderr, "holypkg: expected a lowercase SHA-256 digest\n");
    return 0;
}

int holy_repo_fetch_name(const char *directory, const char *name,
                         const char *output, int extract)
{
    int result = 6;
    if (!name || !*name || !output || !*output) return 2;
    if (!list(directory, NULL, NULL, 1, 0, NULL, output, NULL, NULL,
              name, NULL, 0, &result, NULL, extract, NULL, NULL)) return 6;
    return result;
}

void holy_repo_set_free(struct holy_repo_set *set)
{
    size_t i;
    for (i = 0; i < set->count; ++i) free(set->digests[i]);
    free(set->digests);
    memset(set, 0, sizeof *set);
}

int holy_repo_stage_set(const char *directory, const char *name,
                        const char *root, struct holy_repo_set *set,
                        const char *arch, const char *libc)
{
    struct stage_request stage = {root, set, NULL, NULL, 0, 0, NULL, NULL, NULL};
    int result = 6;
    memset(set, 0, sizeof *set);
    if (!name || !*name || !root || !*root) return 2;
    stage.arch = arch;
    stage.libc = libc;
    if (!list(directory, NULL, NULL, 1, 0, NULL, NULL, NULL, NULL,
              name, NULL, 0, &result, NULL, 0, &stage, NULL)) {
        holy_repo_set_free(set);
        return 6;
    }
    if (result) holy_repo_set_free(set);
    return result;
}

int holy_repo_stage_provider(const char *directory, const char *kind,
                             const char *name, const char *root,
                             struct holy_repo_set *set)
{
    struct stage_request stage = {root, set, NULL, NULL, 0, 1, NULL, NULL, NULL};
    int result = 6;
    memset(set, 0, sizeof *set);
    if (!kind || (strcmp(kind, "package") && strcmp(kind, "package-or") && strcmp(kind, "file") &&
                  strcmp(kind, "command") && strcmp(kind, "soname")) ||
        !name || !*name || !root || !*root ||
        (!strcmp(kind, "package-or") && !holy_package_or_each(name, NULL, NULL))) return 2;
    if (!list(directory, NULL, NULL, 1, 0, NULL, NULL, kind, name,
              NULL, NULL, 0, &result, NULL, 0, &stage, NULL)) {
        holy_repo_set_free(set);
        return 6;
    }
    if (result) holy_repo_set_free(set);
    return result;
}

int holy_repo_stage_slot(const char *directory, const char *root,
                         const struct holy_package_identity *slot,
                         struct holy_repo_set *set)
{
    struct stage_request stage = {root, set, slot, NULL, 0, 0, NULL, NULL, NULL};
    int result = 6;
    memset(set, 0, sizeof *set);
    if (!root || !*root || !slot || !slot->name || !slot->os ||
        !slot->arch || !slot->libc) return 2;
    if (!list(directory, NULL, NULL, 1, 0, NULL, NULL, NULL, NULL,
              slot->name, NULL, 0, &result, NULL, 0, &stage, NULL)) {
        holy_repo_set_free(set);
        return 6;
    }
    if (result) holy_repo_set_free(set);
    return result;
}

void holy_repo_slot_list_free(struct holy_repo_slot_list *list)
{
    size_t i;
    if (!list) return;
    for (i = 0; i < list->count; ++i) holy_package_identity_free(&list->items[i]);
    free(list->items);
    memset(list, 0, sizeof *list);
}

int holy_repo_slot_candidates(const char *directory,
                              const struct holy_package_identity *slot,
                              struct holy_repo_slot_list *out)
{
    struct holy_repo_set index = {0};
    struct stage_request stage = {NULL, &index, slot, NULL, 1, 0, out, NULL, NULL};
    int result = 6;
    if (!directory || !slot || !slot->name || !slot->os || !slot->arch ||
        !slot->libc || !out) return 2;
    memset(out, 0, sizeof *out);
    if (!list(directory, NULL, NULL, 1, 0, NULL, NULL, NULL, NULL,
              NULL, NULL, 0, &result, NULL, 0, &stage, NULL)) result = 6;
    if (result) holy_repo_slot_list_free(out);
    return result;
}

int holy_repo_stage_slot_digest(const char *directory, const char *root,
                                const struct holy_package_identity *slot,
                                const char *digest, struct holy_repo_set *set)
{
    struct stage_request stage = {root, set, slot, digest, 0, 0, NULL, NULL, NULL};
    int result = 6;
    if (!directory || !root || !slot || !slot->name || !slot->os ||
        !slot->arch || !slot->libc || !digest || strlen(digest) != 64 ||
        strspn(digest, "0123456789abcdef") != 64 || !set) return 2;
    memset(set, 0, sizeof *set);
    if (!list(directory, NULL, NULL, 1, 0, NULL, NULL, NULL, NULL,
              slot->name, NULL, 0, &result, NULL, 0, &stage, NULL)) result = 6;
    if (result) holy_repo_set_free(set);
    return result;
}

int holy_repo_source_catalog(const char *directory, const char *source_id,
                             const char *url, const char *public_key)
{
    struct stat st;
    char digest[65], key_hash[65], *record = NULL, *expected = NULL;
    size_t used = 0, expected_size = 0;
    int dir = -1, fd = -1, ok = 0;
    FILE *stream = NULL;
    if (!source_id || strlen(source_id) != 64 ||
        strspn(source_id, "0123456789abcdef") != 64 || !url) return 0;
    dir = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || flock(dir, LOCK_SH) || read_current(dir, digest) != 1) goto done;
    if (public_key && !holy_verify_index_keyhash(dir, digest, public_key, key_hash)) goto done;
    fd = openat(dir, "mirror-origin", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        (st.st_mode & 0022) || (st.st_uid != geteuid() && st.st_uid != 0) ||
        st.st_size <= 0 || st.st_size > 65536) goto done;
    record = malloc((size_t)st.st_size + 1);
    if (!record) goto done;
    while (used < (size_t)st.st_size) {
        ssize_t n = pread(fd, record + used, (size_t)st.st_size - used, (off_t)used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto done;
        used += (size_t)n;
    }
    record[used] = 0;
    stream = open_memstream(&expected, &expected_size);
    if (!stream) goto done;
    {
        int wrote = fputs("format holy-mirror-1\nurl ", stream) != EOF &&
            quote(stream, url) &&
            fprintf(stream, "\nindex-sha256 %s\nverification %s\n", digest,
                    public_key ? "ed25519-pinned-key" : "digest-pinned-unsigned") >= 0 &&
            (!public_key || fprintf(stream, "public-key-sha256 %s\n", key_hash) >= 0) &&
            fprintf(stream, "source-id %s\n", source_id) >= 0 && !ferror(stream);
        if (fclose(stream)) wrote = 0;
        stream = NULL;
        if (!wrote) goto done;
    }
    ok = (used == expected_size && !memcmp(record, expected, used)) ||
         (!public_key && used == expected_size + sizeof "selection current-accepted-unsigned\n" - 1 &&
          !memcmp(record, expected, expected_size) &&
          !memcmp(record + expected_size, "selection current-accepted-unsigned\n",
                  sizeof "selection current-accepted-unsigned\n" - 1));
done:
    if (stream) fclose(stream);
    free(record); free(expected);
    if (fd >= 0) close(fd);
    if (dir >= 0) close(dir);
    return ok;
}

int holy_repo_catalog_index(const char *directory, char digest[65])
{
    int dir = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int ok = 0;
    digest[0] = 0;
    if (dir >= 0 && !flock(dir, LOCK_SH) && read_current(dir, digest) == 1 &&
        list(directory, NULL, NULL, 1, 0, NULL, NULL, NULL, NULL, NULL,
             NULL, 0, NULL, NULL, 0, NULL, NULL)) ok = 1;
    if (dir >= 0) close(dir);
    if (!ok) digest[0] = 0;
    return ok;
}

int holy_repo_catalog_index_fast(const char *directory, char digest[65])
{
    struct holy_repo_set index = {0};
    struct stage_request stage = {NULL, &index, NULL, NULL, 1, 0, NULL, NULL, NULL};
    int ok = list(directory, NULL, NULL, 1, 0, NULL, NULL, NULL, NULL,
                  NULL, NULL, 0, NULL, NULL, 0, &stage, NULL);
    if (ok) memcpy(digest, index.index, 65);
    else digest[0] = 0;
    return ok;
}

int holy_repo_catalog_slot_digest(const char *directory,
                                  const struct holy_package_identity *slot,
                                  const char *artifact, char index_digest[65])
{
    struct holy_repo_set index = {0};
    struct stage_request stage = {NULL, &index, slot, artifact, 1, 0, NULL, NULL, NULL};
    int result = 6;
    if (!slot || !artifact || strlen(artifact) != 64 ||
        strspn(artifact, "0123456789abcdef") != 64) return 2;
    if (!list(directory, NULL, NULL, 1, 0, NULL, NULL, NULL, NULL,
              NULL, NULL, 0, &result, NULL, 0, &stage, NULL)) return 6;
    memcpy(index_digest, index.index, 65);
    return result;
}

static int seal(const char *directory, const char *expected, const char *private_key)
{
    char temporary[43] = {0}, pointer_temp[43] = {0};
    char index_name[71], digest[65], previous[65], line[73];
    char buffer[65536];
    char *snapshot = NULL;
    struct stat st;
    int dir = -1, input = -1, output = -1, pointer = -1, ok = 0;
    ssize_t got;
    size_t written;
    dir = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || flock(dir, LOCK_EX) < 0) goto done;
    if (read_current(dir, previous) < 0) goto done;
    input = openat(dir, "index", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (input < 0 || fstat(input, &st) || !S_ISREG(st.st_mode) ||
        st.st_size < 0 || st.st_size > 128LL * 1024 * 1024) goto done;
    output = holy_temporary_at(dir, temporary);
    if (output < 0) goto done;
    while (lseek(output, 0, SEEK_CUR) < st.st_size) {
        off_t position = lseek(output, 0, SEEK_CUR);
        size_t amount;
        if (position < 0) goto done;
        amount = st.st_size - position < (off_t)sizeof buffer ?
                 (size_t)(st.st_size - position) : sizeof buffer;
        got = pread(input, buffer, amount, position);
        size_t offset = 0;
        if (got < 0) { if (errno == EINTR) continue; goto done; }
        if (!got) goto done;
        while (offset < (size_t)got) {
            ssize_t sent = write(output, buffer + offset, (size_t)got - offset);
            if (sent < 0 && errno == EINTR) continue;
            if (sent <= 0) goto done;
            offset += (size_t)sent;
        }
    }
    if (fstat(input, &st) || st.st_size < 0 ||
        lseek(output, 0, SEEK_CUR) != st.st_size) goto done;
    if (fchmod(output, 0644) || fsync(output)) goto done;
    close(output);
    output = -1;
    close(input);
    input = -1;
    if (!list(directory, NULL, temporary, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, 0, NULL, NULL)) goto done;
    input = openat(dir, temporary, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (input < 0) goto done;
    snapshot = holy_stage_fd(input, "holy-seal");
    if (!snapshot || !digest_file(snapshot, digest) ||
        (expected && strcmp(digest, expected))) goto done;
    snprintf(index_name, sizeof index_name, "index.%s", digest);
    if (linkat(dir, temporary, dir, index_name, 0)) {
        if (errno != EEXIST) goto done;
        close(input);
        input = openat(dir, index_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (input < 0) goto done;
        unlink(snapshot);
        free(snapshot);
        snapshot = holy_stage_fd(input, "holy-seal");
        if (!snapshot || !digest_file(snapshot, previous) ||
            strcmp(previous, digest)) goto done;
    }
    if (fsync(dir)) goto done;
    if (private_key && !holy_sign_index(dir, digest, private_key)) goto done;
    if (fstatat(dir, "current", &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!S_ISREG(st.st_mode)) goto done;
    } else if (errno != ENOENT) goto done;
    pointer = holy_temporary_at(dir, pointer_temp);
    if (pointer < 0) goto done;
    snprintf(line, sizeof line, "sha256 %s\n", digest);
    written = 0;
    while (written < 72) {
        ssize_t sent = write(pointer, line + written, 72 - written);
        if (sent < 0 && errno == EINTR) continue;
        if (sent <= 0) goto done;
        written += (size_t)sent;
    }
    if (fchmod(pointer, 0644) || fsync(pointer)) goto done;
    close(pointer);
    pointer = -1;
    if (renameat(dir, pointer_temp, dir, "current") || fsync(dir)) goto done;
    pointer_temp[0] = '\0';
    printf("sealed %s\n", digest);
    ok = 1;
done:
    if (!ok) fprintf(stderr, "holypkg: repository seal incomplete\n");
    if (snapshot) { unlink(snapshot); free(snapshot); }
    if (pointer >= 0) close(pointer);
    if (output >= 0) close(output);
    if (input >= 0) close(input);
    if (dir >= 0) {
        if (temporary[0]) unlinkat(dir, temporary, 0);
        if (pointer_temp[0]) unlinkat(dir, pointer_temp, 0);
        close(dir);
    }
    return ok;
}

int holy_repo_seal(const char *directory)
{
    return seal(directory, NULL, NULL);
}

int holy_repo_seal_signed(const char *directory, const char *private_key)
{
    return private_key && *private_key && seal(directory, NULL, private_key);
}

int holy_repo_verify_signature(const char *directory, const char *public_key)
{
    char digest[65];
    int dir, ok;
    if (!public_key || !*public_key) return 2;
    dir = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) return 1;
    ok = !flock(dir, LOCK_SH) && holy_repo_catalog_index(directory, digest) &&
         holy_verify_index(dir, digest, public_key);
    close(dir);
    if (ok) printf("verified %s\n", digest);
    else fputs("holypkg: repository signature invalid or unavailable\n", stderr);
    return ok ? 0 : 4;
}

static int mirror_source(const char *base, const char *digest, const char *output,
                         const char *ca_file, const char *source_id,
                         int current_accepted, const char *public_key)
{
    struct mirror mirror = { base, ca_file, NULL, 0 };
    char index_name[71], signature_name[75], key_hash[65] = {0};
    char *url = NULL, *downloads = NULL;
    unsigned char signature[64];
    size_t i, length = strlen(output);
    int dir = -1, provenance = -1, sidecar = -1, result = 1;
    FILE *record = NULL;
    if (strlen(digest) != 64) return 2;
    for (i = 0; i < 64; ++i)
        if (!((digest[i] >= '0' && digest[i] <= '9') ||
              (digest[i] >= 'a' && digest[i] <= 'f'))) return 2;
    if (current_accepted && !source_id) return 2;
    if (source_id) {
        if (strlen(source_id) != 64) return 2;
        for (i = 0; i < 64; ++i)
            if (!((source_id[i] >= '0' && source_id[i] <= '9') ||
                  (source_id[i] >= 'a' && source_id[i] <= 'f'))) return 2;
    }
    snprintf(index_name, sizeof index_name, "index.%s", digest);
    url = holy_fetch_child_url(base, index_name);
    if (!url) return 2;
    if (length > (size_t)-1 - 12 || !(downloads = malloc(length + 12))) goto done;
    snprintf(downloads, length + 12, "%s/.downloads", output);
    mirror.downloads = downloads;
    if (mkdir(output, 0700)) goto done;
    dir = open(output, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || flock(dir, LOCK_EX) || mkdirat(dir, ".downloads", 0700)) goto done;
    result = holy_fetch_https_data(url, digest, output, ca_file);
    if (result) goto done;
    if (public_key) {
        result = holy_fetch_https_signature(base, digest, ca_file, signature);
        if (result) goto done;
        result = 4;
        if (linkat(dir, digest, dir, index_name, 0) ||
            !holy_verify_index_bytes(dir, digest, public_key, signature, key_hash)) goto done;
        snprintf(signature_name, sizeof signature_name, "signature.%s", digest);
        sidecar = openat(dir, signature_name,
                         O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
        if (sidecar < 0) { result = 1; goto done; }
        for (i = 0; i < sizeof signature;) {
            ssize_t sent = write(sidecar, signature + i, sizeof signature - i);
            if (sent < 0 && errno == EINTR) continue;
            if (sent <= 0) { result = 1; goto done; }
            i += (size_t)sent;
        }
        if (fsync(sidecar)) { result = 1; goto done; }
        if (close(sidecar)) { sidecar = -1; result = 1; goto done; }
        sidecar = -1;
        if (fsync(dir)) { result = 1; goto done; }
    }
    if (!list(output, NULL, digest, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, &mirror, 0, NULL, NULL)) {
        result = mirror.status ? mirror.status : 4;
        goto done;
    }
    result = 1;
    if (linkat(dir, digest, dir, "index", 0)) goto done;
    provenance = openat(dir, "mirror-origin", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (provenance < 0 || !(record = fdopen(provenance, "w"))) goto done;
    fputs("format holy-mirror-1\nurl ", record);
    if (!quote(record, base) || fprintf(record, "\nindex-sha256 %s\nverification %s\n", digest,
                                      public_key ? "ed25519-pinned-key" : "digest-pinned-unsigned") < 0 ||
        (public_key && fprintf(record, "public-key-sha256 %s\n", key_hash) < 0) ||
        (source_id && fprintf(record, "source-id %s\n", source_id) < 0) ||
        (current_accepted && fputs("selection current-accepted-unsigned\n", record) == EOF) ||
        fflush(record) || fsync(provenance)) goto done;
    if (fclose(record)) { record = NULL; provenance = -1; goto done; }
    record = NULL; provenance = -1;
    if (unlinkat(dir, digest, 0) || unlinkat(dir, ".downloads", AT_REMOVEDIR) || fsync(dir)) goto done;
    /* seal takes its own exclusive lock after the private download phase. */
    close(dir); dir = -1;
    result = seal(output, digest, NULL) ? 0 : 4;
done:
    if (result) fprintf(stderr, "holypkg: HTTPS catalog mirror incomplete (status %d)\n", result);
    if (record) fclose(record);
    else if (provenance >= 0) close(provenance);
    if (sidecar >= 0) close(sidecar);
    if (dir >= 0) close(dir);
    free(downloads);
    free(url);
    return result;
}

int holy_repo_mirror_source(const char *base, const char *digest, const char *output,
                            const char *ca_file, const char *source_id,
                            int current_accepted)
{
    return mirror_source(base, digest, output, ca_file, source_id,
                         current_accepted, NULL);
}

int holy_repo_mirror_source_signed(const char *base, const char *digest,
                                   const char *output, const char *ca_file,
                                   const char *source_id, const char *public_key)
{
    if (!public_key || !*public_key) return 2;
    return mirror_source(base, digest, output, ca_file, source_id, 0, public_key);
}

int holy_repo_mirror(const char *base, const char *digest, const char *output,
                     const char *ca_file)
{
    return mirror_source(base, digest, output, ca_file, NULL, 0, NULL);
}

int holy_repo_mirror_signed(const char *base, const char *digest, const char *output,
                            const char *ca_file, const char *public_key)
{
    if (!public_key || !*public_key) return 2;
    return mirror_source(base, digest, output, ca_file, NULL, 0, public_key);
}
