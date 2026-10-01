#define _XOPEN_SOURCE 700
#include "up.h"
#include "cache.h"
#include "config.h"
#include "package.h"
#include "repo.h"
#include "source.h"
#include "stage.h"
#include "state.h"
#include "../backends/pacman.h"
#include "../backends/deb-version.h"
#include "../backends/apk-version.h"
#include "../backends/xbps-version.h"
#include "version.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

static int digest_valid(const char *value)
{
    return value && strlen(value) == 64 &&
           strspn(value, "0123456789abcdef") == 64;
}

static int digest_bytes(const void *data, size_t size, char output[65])
{
    unsigned char bytes[32];
    unsigned int count;
    size_t i;
    if (EVP_Digest(data, size, bytes, &count, EVP_sha256(), NULL) != 1 || count != 32)
        return 0;
    for (i = 0; i < 32; ++i) snprintf(output + 2 * i, 3, "%02x", bytes[i]);
    output[64] = 0;
    return 1;
}

static void quoted(FILE *out, const char *value)
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

static int same_slot(const struct holy_package_identity *old,
                     const struct holy_package_identity *candidate)
{
    return !strcmp(old->name, candidate->name) &&
           !strcmp(old->os, candidate->os) &&
           !strcmp(old->arch, candidate->arch) &&
           !strcmp(old->libc, candidate->libc);
}

static int version_order(const struct holy_package_identity *a,
                         const struct holy_package_identity *b, int *order)
{
    char *left = NULL, *right = NULL;
    size_t a_length, b_length;
    int ok = 0;
    if (!a->version_family || !b->version_family ||
        strcmp(a->version_family, b->version_family)) return 0;
    if (!strcmp(a->version_family, "deb")) {
        if (!holy_deb_version_compare(a->version, b->version, order)) return 0;
        return *order || holy_deb_version_compare(a->release, b->release, order);
    }
    if (!strcmp(a->version_family, "holy")) {
        if (!holy_version_compare(a->version, b->version, order)) return 0;
        return *order || holy_version_compare(a->release, b->release, order);
    }
    if (!strcmp(a->version_family, "apk")) {
        if (!holy_apk_version_compare(a->version, b->version, order)) return 0;
        return *order || holy_version_compare(a->release, b->release, order);
    }
    if (!strcmp(a->version_family, "xbps")) {
        a_length = strlen(a->version) + strlen(a->release);
        b_length = strlen(b->version) + strlen(b->release);
        if (a_length > (size_t)-1 - 2 || b_length > (size_t)-1 - 2) return 0;
        left = malloc(a_length + 2);
        right = malloc(b_length + 2);
        if (left && right) {
            snprintf(left, a_length + 2, "%s_%s", a->version, a->release);
            snprintf(right, b_length + 2, "%s_%s", b->version, b->release);
            ok = holy_xbps_version_compare(left, right, order);
        }
        free(left); free(right);
        return ok;
    }
    if (strcmp(a->version_family, "pacman")) return 0;
    a_length = strlen(a->version) + strlen(a->release);
    b_length = strlen(b->version) + strlen(b->release);
    if (a_length > (size_t)-1 - 2 || b_length > (size_t)-1 - 2) return 0;
    left = malloc(a_length + 2);
    right = malloc(b_length + 2);
    if (left && right) {
        snprintf(left, a_length + 2, "%s-%s", a->version, a->release);
        snprintf(right, b_length + 2, "%s-%s", b->version, b->release);
        ok = holy_pacman_version_compare(left, right, order);
    }
    free(left); free(right);
    return ok;
}

static int write_plan(const char *path, const char *data, size_t size)
{
    char *parent = strdup(path), *slash;
    size_t used = 0;
    int fd = -1, dir = -1, ok = 0;
    if (!parent) return 0;
    slash = strrchr(parent, '/');
    if (slash) {
        if (slash == parent) slash[1] = 0;
        else *slash = 0;
    } else { free(parent); parent = strdup("."); if (!parent) return 0; }
    dir = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) goto done;
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) goto done;
    while (used < size) {
        ssize_t n = write(fd, data + used, size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto done;
        used += (size_t)n;
    }
    if (fsync(fd) || fsync(dir)) goto done;
    ok = 1;
done:
    if (fd >= 0) { close(fd); if (!ok) unlink(path); }
    if (dir >= 0) close(dir);
    free(parent);
    return ok;
}

int holy_up_command(int argc, char **argv)
{
    const char *separator, *root = "/", *catalog = NULL, *output = NULL;
    const char *choice = NULL, *arch = NULL, *libc = NULL;
    const char *accepted_arch = NULL, *accepted_privileged = NULL;
    const char **services = NULL;
    size_t service_count = 0, s;
    char *alias = NULL, *bound = NULL, *canonical = NULL, *old_snapshot = NULL;
    char *inner = NULL, *plan = NULL, *temporary_dir = NULL, *temporary_plan = NULL;
    struct holy_package_identity old = {0}, *selected = NULL;
    struct holy_repo_slot_list candidates = {0};
    struct holy_repo_set staged = {0};
    char source_id[65], actual_id[65], old_hash[65], inner_hash[65], plan_hash[65], answer[16];
    size_t i, size = 0, compatible = 0, ambiguous = 0;
    int dir = -1, result = 2, prepared = 0, yes = 0, noninteractive = 0;
    int root_seen = 0, old_present = 0, plan_written = 0;
    FILE *stream = NULL;
    if (argc < 3 || !(separator = strchr(argv[2], ':')) ||
        separator == argv[2] || !separator[1] || strchr(separator + 1, ':')) goto done;
    services = calloc((size_t)argc, sizeof *services);
    if (!services) { result = 1; goto done; }
    alias = malloc((size_t)(separator - argv[2]) + 1);
    if (!alias) { result = 1; goto done; }
    memcpy(alias, argv[2], (size_t)(separator - argv[2]));
    alias[separator - argv[2]] = 0;
    if (!strcmp(alias, "local")) goto done;
    for (i = 3; i < (size_t)argc; ++i) {
        if (!strcmp(argv[i], "--prepare") && !prepared) prepared = 1;
        else if (!strcmp(argv[i], "--output") && !output && i + 1 < (size_t)argc)
            output = argv[++i];
        else if (!strcmp(argv[i], "--catalog") && !catalog && i + 1 < (size_t)argc)
            catalog = argv[++i];
        else if (!strcmp(argv[i], "--choose") && !choice && i + 1 < (size_t)argc)
            choice = argv[++i];
        else if (!strcmp(argv[i], "--arch") && !arch && i + 1 < (size_t)argc)
            arch = argv[++i];
        else if (!strcmp(argv[i], "--libc") && !libc && i + 1 < (size_t)argc)
            libc = argv[++i];
        else if (!strcmp(argv[i], "--accept-arch") && !accepted_arch && i + 1 < (size_t)argc)
            accepted_arch = argv[++i];
        else if (!strcmp(argv[i], "--accept-privileged") && !accepted_privileged && i + 1 < (size_t)argc)
            accepted_privileged = argv[++i];
        else if (!strcmp(argv[i], "--accept-service") && i + 1 < (size_t)argc)
            services[service_count++] = argv[++i];
        else if (!strcmp(argv[i], "--yes") && !yes) yes = 1;
        else if (!strcmp(argv[i], "--noninteractive") && !noninteractive) noninteractive = 1;
        else if (!strcmp(argv[i], "--root") && !root_seen && i + 1 < (size_t)argc) {
            root = argv[++i]; root_seen = 1;
        } else goto done;
    }
    if ((prepared && yes) ||
        (output && !*output) || !*root ||
        (catalog && !*catalog) || (arch && !*arch) || (libc && !*libc) ||
        (choice && !digest_valid(choice)) ||
        (accepted_arch && !digest_valid(accepted_arch)) ||
        (accepted_privileged && !digest_valid(accepted_privileged))) goto done;
    result = holy_source_active_id(root, alias, source_id);
    if (result) goto done;
    result = holy_state_find_slot(root, source_id, separator + 1, arch, libc, old_hash);
    if (result) goto done;
    old_snapshot = holy_cache_snapshot(old_hash, root);
    if (!old_snapshot || !holy_package_identity(old_snapshot, &old)) {
        fprintf(stderr, "holypkg: previous artifact unavailable for downgrade %s\n", old_hash);
        result = 6; goto done;
    }
    if (!catalog) {
        result = holy_source_catalog_path_fast(root, alias, &bound);
        if (result) goto done;
        catalog = bound;
    }
    canonical = realpath(catalog, NULL);
    dir = canonical ? open(canonical, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
    if (dir < 0 || flock(dir, LOCK_SH)) { result = 6; goto done; }
    result = holy_source_catalog(root, alias, canonical, actual_id);
    if (result || strcmp(source_id, actual_id)) { result = 3; goto done; }
    result = holy_repo_slot_candidates(canonical, &old, &candidates);
    if (result) {
        if (result == 6)
            fprintf(stderr, "holypkg: source package slot changed or disappeared\n");
        goto done;
    }
    for (i = 0; i < candidates.count; ++i) {
        struct holy_package_identity *candidate = &candidates.items[i];
        int order = 0;
        if (!same_slot(&old, candidate)) { result = 1; goto done; }
        ++compatible;
        if (!strcmp(candidate->digest, old_hash)) {
            old_present = 1;
            continue;
        }
        printf("update-candidate %s version %s release %s comparator %s\n",
               candidate->digest, candidate->version, candidate->release,
               candidate->version_family ? candidate->version_family : "unknown");
        if (choice) {
            if (!strcmp(choice, candidate->digest)) {
                selected = candidate;
            }
            continue;
        }
        if (!version_order(candidate, &old, &order)) {
            ambiguous = 1;
            continue;
        }
        if (order <= 0) continue;
        if (!selected) { selected = candidate; continue; }
        if (!version_order(candidate, selected, &order) || !order) ambiguous = 1;
        if (order > 0) selected = candidate;
    }
    if (!compatible) {
        fprintf(stderr, "holypkg: source package slot changed or disappeared\n");
        result = 6; goto done;
    }
    if (choice && !selected) { result = 6; goto done; }
    if (!choice && ambiguous) {
        fprintf(stderr, "holypkg: decision-required update candidate; use --choose SHA256\n");
        result = 3; goto done;
    }
    if (!selected) {
        if (!old_present) {
            fprintf(stderr, "holypkg: installed artifact absent from source and no newer candidate\n");
            result = 6; goto done;
        }
        printf("up-to-date %s %s\n", source_id, old_hash);
        result = 0; goto done;
    }
    if ((accepted_arch && strcmp(accepted_arch, selected->digest)) ||
        (accepted_privileged && strcmp(accepted_privileged, selected->digest))) {
        result = 2; goto done;
    }
    result = holy_repo_stage_slot_digest(canonical, root, &old,
                                         selected->digest, &staged);
    if (result) goto done;
    if (strcmp(staged.index, candidates.index) || staged.count != 1 ||
        strcmp(staged.digests[0], selected->digest)) { result = 3; goto done; }
    {
        const char *olds[1] = {old_hash}, *news[1] = {selected->digest};
        struct holy_update_request request = {
            olds, news, 1,
            accepted_arch ? &accepted_arch : NULL, accepted_arch ? 1 : 0,
            accepted_privileged ? &accepted_privileged : NULL,
            accepted_privileged ? 1 : 0,
            services, service_count
        };
        result = holy_state_update_prepare(&request, root, inner_hash, &inner);
    }
    if (result) goto done;
    if (!output) {
        temporary_dir = strdup("/tmp/holypkg-up-XXXXXX");
        if (!temporary_dir || !mkdtemp(temporary_dir)) { result = 1; goto done; }
        temporary_plan = malloc(strlen(temporary_dir) + 6);
        if (!temporary_plan) { result = 1; goto done; }
        sprintf(temporary_plan, "%s/plan", temporary_dir);
        output = temporary_plan;
    }
    stream = open_memstream(&plan, &size);
    if (!stream) { result = 1; goto done; }
    fprintf(stream, "format holy-up-plan-1\nsource-id %s\nalias ", source_id);
    quoted(stream, alias);
    fputs("\ncatalog ", stream);
    quoted(stream, canonical);
    fprintf(stream, "\nindex %s\nold %s\nnew %s\nstate-plan %s\naccept-arch %s\naccept-privileged %s\n",
            staged.index, old_hash, selected->digest, inner_hash,
            accepted_arch ? accepted_arch : "-",
            accepted_privileged ? accepted_privileged : "-");
    for (s = 0; s < service_count; ++s) fprintf(stream, "service %s\n", services[s]);
    fputs(inner, stream);
    {
        int failed = ferror(stream);
        if (fclose(stream)) failed = 1;
        stream = NULL;
        if (failed || !digest_bytes(plan, size, plan_hash) ||
            !write_plan(output, plan, size)) { result = 1; goto done; }
        plan_written = 1;
    }
    printf("prepared %s %s old %s new %s index %s\n",
           plan_hash, output, old_hash, selected->digest, staged.index);
    if (!prepared) {
        char *apply_argv[] = {"holypkg", "apply", (char *)output, "--sha256",
                              plan_hash, "--root", (char *)root, NULL};
        if (fwrite(plan, 1, size, stdout) != size || fflush(stdout)) {
            result = 1; goto done;
        }
        if (!yes) {
            if (noninteractive || !isatty(STDIN_FILENO)) {
                fprintf(stderr, "holypkg: decision-required plan=%s file=%s; apply the reviewed file with its SHA-256\n",
                        plan_hash, output);
                result = 3; goto done;
            }
            if (fprintf(stderr, "Apply plan %s to %s? [y/N] ", plan_hash, root) < 0 ||
                fflush(stderr) || !fgets(answer, sizeof answer, stdin) ||
                (strcmp(answer, "y\n") && strcmp(answer, "Y\n") &&
                 strcmp(answer, "yes\n") && strcmp(answer, "YES\n"))) {
                result = 3; goto done;
            }
        }
        if (dir >= 0) { close(dir); dir = -1; }
        result = holy_apply_command(7, apply_argv);
        if (!result && temporary_plan) {
            unlink(temporary_plan);
            rmdir(temporary_dir);
        }
        if (result) goto done;
    }
    result = 0;
done:
    if (result == 2)
        fputs("usage: holypkg up SOURCE:PACKAGE [--prepare] [--output NEW_FILE] [--catalog MIRROR] [--choose SHA256] [--arch ARCH] [--libc LIBC] [--accept-arch SHA256] [--accept-privileged SHA256] [--accept-service UNIT ...] [--root DIRECTORY] [--yes] [--noninteractive]\n", stderr);
    if (stream) fclose(stream);
    if (dir >= 0) close(dir);
    if (old_snapshot) { unlink(old_snapshot); free(old_snapshot); }
    holy_package_identity_free(&old);
    holy_repo_slot_list_free(&candidates);
    holy_repo_set_free(&staged);
    if (temporary_dir && !plan_written) rmdir(temporary_dir);
    free(alias); free(bound); free(canonical); free(inner); free(plan);
    free(temporary_plan); free(temporary_dir); free(services);
    return result;
}

static char *read_plan(int fd, size_t *size)
{
    struct stat st;
    char *data = NULL;
    size_t used = 0;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 32 ||
        st.st_size > 64 * 1024 * 1024) return NULL;
    *size = (size_t)st.st_size;
    data = malloc(*size + 1);
    if (!data) return NULL;
    while (used < *size) {
        ssize_t n = read(fd, data + used, *size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { free(data); return NULL; }
        used += (size_t)n;
    }
    if (memchr(data, 0, *size) || data[*size - 1] != '\n') {
        free(data); return NULL;
    }
    data[*size] = 0;
    return data;
}

/* one line of the saved plan, since the unit consents are a list rather than a field */
static char *next_line(char *cursor)
{
    char *end = strchr(cursor, '\n');
    if (!end || end - cursor > 4096) return NULL;
    *end = 0;
    return end + 1;
}

static int take_field(char **cursor, const char *key, char **value)
{
    char *end = strchr(*cursor, '\n'), **tokens = NULL, *error = NULL;
    size_t count = 0;
    int ok = 0;
    *value = NULL;
    if (!end || end - *cursor > 1024 * 1024 ||
        !holy_lex(*cursor, (size_t)(end - *cursor), &tokens, &count,
                  "up plan", 0, &error)) goto done;
    if (count != 2 || strcmp(tokens[0], key)) goto done;
    *value = strdup(tokens[1]);
    if (!*value) goto done;
    *cursor = end + 1;
    ok = 1;
done:
    free(error);
    holy_tokens_free(tokens, count);
    return ok;
}

int holy_up_plan_read(const char *path, const char *approved, struct holy_up_plan *plan)
{
    struct stat st;
    char actual[65], recorded[65], *data = NULL, *cursor, *snapshot = NULL, *body = NULL;
    char *source = NULL, *alias = NULL, *catalog = NULL, *index = NULL;
    char *old = NULL, *next = NULL, *inner = NULL, *arch = NULL, *privileged = NULL;
    char **services = NULL;
    size_t size = 0, service_count = 0, i;
    int input = -1, staged = -1, result = 6;
    memset(plan, 0, sizeof *plan);
    if (!path || !*path || (approved && !digest_valid(approved))) return 2;
    input = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (input < 0) return 6;
    /* a hostile rename after the open cannot change the bytes that are parsed */
    if (fstat(input, &st) || !S_ISREG(st.st_mode) || st.st_size < 32 ||
        st.st_size > 64 * 1024 * 1024) { result = 2; goto done; }
    snapshot = holy_stage_fd(input, "holy-up-plan");
    staged = snapshot ? open(snapshot, O_RDONLY | O_NOFOLLOW | O_CLOEXEC) : -1;
        if (staged < 0 || !(data = read_plan(staged, &size))) { result = 2; goto done; }
    if (!digest_bytes(data, size, actual)) { result = 1; goto done; }
    memcpy(recorded, actual, 65);
    if (approved && strcmp(actual, approved)) { result = 3; goto done; }
    if (strncmp(data, "format holy-up-plan-1\n", 22)) { result = 2; goto done; }
    cursor = data + 22;
    if (!take_field(&cursor, "source-id", &source) ||
        !take_field(&cursor, "alias", &alias) ||
        !take_field(&cursor, "catalog", &catalog) ||
        !take_field(&cursor, "index", &index) ||
        !take_field(&cursor, "old", &old) ||
        !take_field(&cursor, "new", &next) ||
        !take_field(&cursor, "state-plan", &inner) ||
        !take_field(&cursor, "accept-arch", &arch) ||
        !take_field(&cursor, "accept-privileged", &privileged)) { result = 2; goto done; }
    /* a unit name ends at the newline, and the rest of the document is not part of it */
    while (!strncmp(cursor, "service ", 8)) {
        char unit[256], **grown, *name = cursor + 8;
        size_t k, length = 0;
        while (name[length] && name[length] != '\n' && length < sizeof unit) ++length;
        if (!length || length >= sizeof unit) { result = 2; goto done; }
        memcpy(unit, name, length);
        unit[length] = 0;
        if (!holy_unit_name_valid(unit)) { result = 2; goto done; }
        for (k = 0; k < service_count; ++k) {
            if (!strcmp(unit, services[k])) { result = 2; goto done; }
        }
        if (service_count >= 65536) { result = 2; goto done; }
        grown = realloc(services, (service_count + 1) * sizeof *grown);
        if (!grown) { result = 1; goto done; }
        services = grown;
        services[service_count] = strdup(unit);
        if (!services[service_count]) { result = 1; goto done; }
        ++service_count;
        if (!(cursor = next_line(cursor))) { result = 2; goto done; }
    }
    if (strncmp(cursor, "[update]\n", 9)) { result = 2; goto done; }
    body = cursor;
    if (!digest_valid(source) || !*alias || catalog[0] != '/' ||
        !digest_valid(index) || !digest_valid(old) || !digest_valid(next) ||
        !digest_valid(inner) ||
        (strcmp(arch, "-") && strcmp(arch, next)) ||
        (strcmp(privileged, "-") && strcmp(privileged, next)) ||
        !digest_bytes(body, strlen(body), actual) || strcmp(actual, inner)) {
        result = 2; goto done;
    }
    plan->body = strdup(body);
    if (!plan->body) { result = 1; goto done; }
    plan->body_length = strlen(body);
    plan->source_id = source; source = NULL;
    plan->alias = alias; alias = NULL;
    plan->catalog = catalog; catalog = NULL;
    plan->index = index; index = NULL;
    plan->old_digest = old; old = NULL;
    plan->new_digest = next; next = NULL;
    plan->state_plan = inner; inner = NULL;
    plan->accept_arch = arch; arch = NULL;
    plan->accept_privileged = privileged; privileged = NULL;
    plan->services = services;
    plan->service_count = service_count;
    services = NULL;
    service_count = 0;
    /* the plan digest is the document digest, which the body digest check reuses */
    memcpy(plan->hash, recorded, 65);
    result = 0;
done:
    if (result) {
        for (i = 0; i < service_count; ++i) free(services[i]);
        free(services);
    }
    if (staged >= 0) close(staged);
    if (input >= 0) close(input);
    if (snapshot) { unlink(snapshot); free(snapshot); }
    free(data); free(source); free(alias); free(catalog); free(index);
    free(old); free(next); free(inner); free(arch); free(privileged);
    if (result) holy_up_plan_free(plan);
    return result;
}

void holy_up_plan_free(struct holy_up_plan *plan)
{
    size_t i;
    if (!plan) return;
    free(plan->source_id); free(plan->alias); free(plan->catalog);
    free(plan->index); free(plan->old_digest); free(plan->new_digest);
    free(plan->state_plan); free(plan->accept_arch); free(plan->accept_privileged);
    for (i = 0; i < plan->service_count; ++i) free(plan->services[i]);
    free(plan->services);
    free(plan->body);
    memset(plan, 0, sizeof *plan);
}

int holy_apply_command(int argc, char **argv)
{
    const char *root = "/", *approved = NULL;
    struct holy_up_plan plan = {0};
    struct holy_package_identity old_identity = {0};
    char source_id[65], current[65];
    int dir = -1, result = 2;
    char *old_snapshot = NULL;
    if (argc == 5 && !strcmp(argv[3], "--sha256")) approved = argv[4];
    else if (argc == 7 && !strcmp(argv[3], "--sha256") &&
             !strcmp(argv[5], "--root")) { approved = argv[4]; root = argv[6]; }
    if (!approved || !digest_valid(approved) || !*root) goto done;
    result = holy_up_plan_read(argv[2], approved, &plan);
    if (result) goto done;
    dir = open(plan.catalog, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || flock(dir, LOCK_SH)) { result = 6; goto done; }
    result = holy_source_active_id(root, plan.alias, source_id);
    if (result) goto done;
    if (strcmp(plan.source_id, source_id)) { result = 3; goto done; }
    result = holy_source_catalog(root, plan.alias, plan.catalog, source_id);
    if (result) goto done;
    old_snapshot = holy_cache_snapshot(plan.old_digest, root);
    if (!old_snapshot || !holy_package_identity(old_snapshot, &old_identity) ||
        strcmp(old_identity.digest, plan.old_digest)) { result = 6; goto done; }
    result = holy_repo_catalog_slot_digest(plan.catalog, &old_identity,
                                           plan.new_digest, current);
    if (result != 0 && result != 3) goto done;
    if (strcmp(current, plan.index)) {
        fprintf(stderr, "holypkg: prepared catalog generation changed\n");
        result = 3; goto done;
    }
    if (result) {
        fprintf(stderr, "holypkg: prepared artifact absent from source slot\n");
        goto done;
    }
    {
        const char *olds[1] = {plan.old_digest}, *news[1] = {plan.new_digest};
        const char *arch = strcmp(plan.accept_arch, "-") ? plan.accept_arch : NULL;
        const char *privileged = strcmp(plan.accept_privileged, "-") ? plan.accept_privileged : NULL;
        struct holy_update_request request = {
            olds, news, 1,
            arch ? &arch : NULL, arch ? 1 : 0,
            privileged ? &privileged : NULL, privileged ? 1 : 0,
            (const char *const *)plan.services, plan.service_count
        };
        result = holy_state_apply_update(plan.state_plan, &request, root);
    }
done:
    if (result == 2)
        fputs("usage: holypkg apply PLAN --sha256 PLAN_SHA256 [--root DIRECTORY]\n", stderr);
    if (dir >= 0) close(dir);
    if (old_snapshot) { unlink(old_snapshot); free(old_snapshot); }
    holy_package_identity_free(&old_identity);
    holy_up_plan_free(&plan);
    return result;
}
