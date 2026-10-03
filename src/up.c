#define _XOPEN_SOURCE 700
#include "up.h"
#include "cache.h"
#include "config.h"
#include "package.h"
#include "repo.h"
#include "source.h"
#include "stage.h"
#include "state.h"
#include "trial.h"
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
    if (dir < 0) { perror("holypkg: plan directory"); goto done; }
    /* a plan a review already holds is never overwritten, so the refusal has to name
       itself: status 1 alone leaves a caller with no way to tell a path that is taken
       from a directory it cannot write, and those want different next steps */
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) { perror("holypkg: plan"); goto done; }
    while (used < size) {
        ssize_t n = write(fd, data + used, size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { perror("holypkg: plan"); goto done; }
        used += (size_t)n;
    }
    if (fsync(fd) || fsync(dir)) { perror("holypkg: plan"); goto done; }
    ok = 1;
done:
    if (fd >= 0) { close(fd); if (!ok) unlink(path); }
    if (dir >= 0) close(dir);
    free(parent);
    return ok;
}

/* one reference being prepared: the slot it updates and the index generation that
   decided its new artifact */
struct up_slot {
    char *alias;
    char source_id[65];
    char old_digest[65];
    char new_digest[65];
    char index[65];
    char signature[16];   /* signed, or unsigned for a source without a key */
    char *catalog;        /* the canonical catalog path the index came from */
    int dir;
};

/* what one reference resolved to, held until the group is prepared */
struct up_selection {
    char *old_snapshot;
    struct holy_package_identity old;
    struct holy_repo_slot_list candidates;
    struct holy_repo_set staged;
    struct holy_package_identity *selected;
};

static void up_slots_free(struct up_slot *slots, size_t count)
{
    size_t i;
    if (!slots) return;
    for (i = 0; i < count; ++i) {
        free(slots[i].alias);
        free(slots[i].catalog);
        if (slots[i].dir >= 0) close(slots[i].dir);
    }
    free(slots);
}

static void up_selection_free(struct up_selection *work)
{
    if (!work) return;
    if (work->old_snapshot) { unlink(work->old_snapshot); free(work->old_snapshot); }
    holy_package_identity_free(&work->old);
    holy_repo_slot_list_free(&work->candidates);
    holy_repo_set_free(&work->staged);
    memset(work, 0, sizeof *work);
}

/* resolves one reference against its catalog and states what it would install. a slot
   that has nothing newer is reported and left out of the group. */
/* --choose names one candidate: a bare digest covers the only reference of the
   command, and SOURCE:PACKAGE=SHA256 is the choice of that one slot of a group */
static const char *up_slot_choice(const char *choice, const char *name)
{
    const char *equals;
    if (!choice) return NULL;
    equals = strchr(choice, '=');
    if (!equals) return choice;
    if ((size_t)(equals - choice) != strlen(name) || strncmp(choice, name, strlen(name)))
        return NULL;
    return equals + 1;
}

/* every installed slot a source can be asked about, as ALIAS:PACKAGE. a slot delivered
   locally, or one whose source no longer has an alias, names nothing, and a slot the
   caller's --arch or --libc excludes is left for the reference loop to refuse */
struct up_all {
    const char *root;
    const char *arch;
    const char *libc;
    char **reference;
    size_t count, limit;
};

static int up_all_slot(void *context, const struct holy_state_slot_ref *ref)
{
    struct up_all *all = context;
    size_t length;
    char **next;
    /* zero continues, so a slot that names nothing is skipped rather than stopping the
       walk over the rest of the installed set */
    if (!ref->alias[0]) return 0;
    if (all->arch && strcmp(all->arch, ref->arch)) return 0;
    if (all->libc && strcmp(all->libc, ref->libc)) return 0;
    if (all->count >= 65536) return 1;
    length = strlen(ref->alias) + 1 + strlen(ref->name) + 1;
    next = realloc(all->reference, (all->count + 1) * sizeof *next);
    if (!next) return 1;
    all->reference = next;
    all->reference[all->count] = malloc(length);
    if (!all->reference[all->count]) return 1;
    snprintf(all->reference[all->count], length, "%s:%s", ref->alias, ref->name);
    ++all->count;
    return 0;
}

static int up_select_slot(struct up_slot *slot, const char *name, const char *root,
                          const char *catalog_option, const char *choice,
                          const char *arch, const char *libc,
                          struct up_selection *work, int *up_to_date)
{
    const char *separator, *catalog = catalog_option, *wanted;
    char *bound = NULL, *canonical = NULL, source_id[65], actual_id[65];
    size_t i, compatible = 0, ambiguous = 0;
    int result = 2, old_present = 0;
    *up_to_date = 0;
    wanted = up_slot_choice(choice, name);
    if (!(separator = strchr(name, ':')) || separator == name || !separator[1] ||
        strchr(separator + 1, ':')) return 2;
    slot->alias = malloc((size_t)(separator - name) + 1);
    if (!slot->alias) return 1;
    memcpy(slot->alias, name, (size_t)(separator - name));
    slot->alias[separator - name] = 0;
    if (!strcmp(slot->alias, "local")) return 2;
    result = holy_source_active_id(root, slot->alias, source_id);
    if (result) goto done;
    memcpy(slot->source_id, source_id, 65);
    result = holy_state_find_slot(root, source_id, separator + 1, arch, libc,
                                  slot->old_digest);
    if (result) goto done;
    work->old_snapshot = holy_cache_snapshot(slot->old_digest, root);
    if (!work->old_snapshot || !holy_package_identity(work->old_snapshot, &work->old)) {
        fprintf(stderr, "holypkg: previous artifact unavailable for downgrade %s\n",
                slot->old_digest);
        result = 6;
        goto done;
    }
    if (!catalog) {
        result = holy_source_catalog_path_fast(root, slot->alias, &bound);
        if (result) goto done;
        catalog = bound;
    }
    canonical = realpath(catalog, NULL);
    slot->catalog = canonical;
    slot->dir = canonical ? open(canonical, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
    if (slot->dir < 0 || flock(slot->dir, LOCK_SH)) {
        fprintf(stderr, "holypkg: catalog %s unavailable for source %s: %s\n",
                catalog, slot->alias, strerror(errno));
        result = 6;
        goto done;
    }
    result = holy_source_catalog(root, slot->alias, canonical, actual_id);
    if (result || strcmp(source_id, actual_id)) {
        /* both the lookup and the slot read the registry, so a source-id that moved
           between them means the source was re-registered while this run was reading
           it, and the slot it named is not the slot the source now serves */
        if (!result)
            fprintf(stderr, "holypkg: source %s serves id %s, not the %s this slot names\n",
                    slot->alias, actual_id, source_id);
        result = 3;
        goto done;
    }
    result = holy_repo_slot_candidates(canonical, &work->old, &work->candidates);
    if (result) {
        if (result == 6)
            fprintf(stderr, "holypkg: source package slot changed or disappeared\n");
        goto done;
    }
    for (i = 0; i < work->candidates.count; ++i) {
        struct holy_package_identity *candidate = &work->candidates.items[i];
        int order = 0;
        if (!same_slot(&work->old, candidate)) {
            /* the repo layer filters candidates by the whole slot already, so this only
               fires if that filter is ever weakened, and the two sets of coordinates
               are what a disagreement would show */
            fprintf(stderr, "holypkg: catalog offers %s %s/%s/%s outside the slot %s/%s/%s\n",
                    candidate->digest,
                    candidate->os ? candidate->os : "-",
                    candidate->arch ? candidate->arch : "-",
                    candidate->libc ? candidate->libc : "-",
                    work->old.os ? work->old.os : "-",
                    work->old.arch ? work->old.arch : "-",
                    work->old.libc ? work->old.libc : "-");
            result = 1;
            goto done;
        }
        ++compatible;
        if (!strcmp(candidate->digest, slot->old_digest)) {
            old_present = 1;
            continue;
        }
        printf("update-candidate %s version %s release %s comparator %s\n",
               candidate->digest, candidate->version, candidate->release,
               candidate->version_family ? candidate->version_family : "unknown");
        if (wanted) {
            if (!strcmp(wanted, candidate->digest)) work->selected = candidate;
            continue;
        }
        if (!version_order(candidate, &work->old, &order)) {
            ambiguous = 1;
            continue;
        }
        if (order <= 0) continue;
        if (!work->selected) { work->selected = candidate; continue; }
        if (!version_order(candidate, work->selected, &order) || !order) ambiguous = 1;
        if (order > 0) work->selected = candidate;
    }
    if (!compatible) {
        fprintf(stderr, "holypkg: source package slot changed or disappeared\n");
        result = 6;
        goto done;
    }
    if (wanted && !work->selected) { result = 6; goto done; }
    if (!wanted && ambiguous) {
        fprintf(stderr, "holypkg: decision-required update candidate; use --choose SHA256\n");
        result = 3;
        goto done;
    }
    if (!work->selected) {
        if (!old_present) {
            fprintf(stderr, "holypkg: installed artifact absent from source and no newer candidate\n");
            result = 6;
            goto done;
        }
        *up_to_date = 1;
        result = 0;
        goto done;
    }
    memcpy(slot->new_digest, work->selected->digest, 65);
    result = holy_repo_stage_slot_digest(canonical, root, &work->old,
                                         work->selected->digest, &work->staged);
    if (result) goto done;
    if (strcmp(work->staged.index, work->candidates.index) ||
        work->staged.count != 1 ||
        strcmp(work->staged.digests[0], work->selected->digest)) { result = 3; goto done; }
    memcpy(slot->index, work->staged.index, 65);
    /* a source that registered a key must have signed the generation this plan fixes */
    result = holy_source_catalog_signature(root, slot->alias, canonical, slot->index,
                                           slot->signature);
    if (result) goto done;
    result = 0;
done:
    free(bound);
    return result;
}

int holy_up_command(int argc, char **argv)
{
    const char *root = "/", *catalog = NULL, *output = NULL;
    const char *choice = NULL, *arch = NULL, *libc = NULL;
    const char *accepted_arch = NULL, *accepted_privileged = NULL;
    const char **services = NULL, **references = NULL;
    struct up_slot *slots = NULL;
    struct up_selection *work = NULL;
    struct holy_update_request request = {0};
    const char **olds = NULL, **news = NULL;
    size_t service_count = 0, reference_count = 0, chosen_count = 0;
    size_t *chosen = NULL, i, s, size = 0;
    char *inner = NULL, *plan = NULL, *temporary_dir = NULL, *temporary_plan = NULL;
    char inner_hash[65], plan_hash[65], answer[16];
    struct up_all all = {NULL, NULL, NULL, NULL, 0, 0};
    int result = 2, prepared = 0, yes = 0, noninteractive = 0;
    int root_seen = 0, up_to_date = 0, every = 0;
    size_t discovered = 0;
    FILE *stream = NULL;
    if (argc < 3) goto done;
    services = calloc((size_t)argc, sizeof *services);
    references = calloc((size_t)argc, sizeof *references);
    slots = calloc((size_t)argc, sizeof *slots);
    work = calloc((size_t)argc, sizeof *work);
    chosen = calloc((size_t)argc, sizeof *chosen);
    olds = calloc((size_t)argc, sizeof *olds);
    news = calloc((size_t)argc, sizeof *news);
    if (!services || !references || !slots || !work || !chosen || !olds || !news) {
        result = 1;
        goto done;
    }
    for (i = 0; i < (size_t)argc; ++i) slots[i].dir = -1;
    for (i = 2; i < (size_t)argc; ++i) {
        if (!strcmp(argv[i], "--all") && !every) every = 1;
        else if (!strcmp(argv[i], "--prepare") && !prepared) prepared = 1;
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
        else if (!strcmp(argv[i], "--accept-arch") && i + 1 < (size_t)argc)
            accepted_arch = argv[++i];
        else if (!strcmp(argv[i], "--accept-privileged") && i + 1 < (size_t)argc)
            accepted_privileged = argv[++i];
        else if (!strcmp(argv[i], "--accept-service") && i + 1 < (size_t)argc)
            services[service_count++] = argv[++i];
        else if (!strcmp(argv[i], "--yes") && !yes) yes = 1;
        else if (!strcmp(argv[i], "--noninteractive") && !noninteractive) noninteractive = 1;
        else if (!strcmp(argv[i], "--root") && !root_seen && i + 1 < (size_t)argc) {
            root = argv[++i]; root_seen = 1;
        } else if (argv[i][0] == '-' || !strchr(argv[i], ':')) {
            goto done;
        } else {
            references[reference_count++] = argv[i];
        }
    }
    if (every) {
        /* every installed slot is a reference, so naming one as well is two ways to say
           the same thing and the narrower one would be silently dropped */
        if (reference_count) goto done;
        all.root = root;
        all.arch = arch;
        all.libc = libc;
        /* a walk that found no slot is the empty reference list the guard below
           refuses, so its status is not carried into result as success */
        result = holy_state_visit_slots(root, up_all_slot, &all);
        if (result || all.count > (size_t)argc) { result = result ? result : 1; goto done; }
        if (!all.count) { result = 2; goto done; }
        /* the walk owns its strings, so they are copied into the borrowed array the
           reference loop reads and freed with it */
        for (i = 0; i < all.count; ++i) {
            references[i] = strdup(all.reference[i]);
            if (!references[i]) { result = 1; goto done; }
            ++reference_count;
        }
        /* only the entries the walk produced are owned here; a reference the caller
           named points into argv and must not be freed */
        discovered = reference_count;
    }
    if (!reference_count || (reference_count > 1 && choice && !strchr(choice, '=')) ||
        (prepared && yes) ||
        (output && !*output) || !*root ||
        (catalog && !*catalog) || (arch && !*arch) || (libc && !*libc) ||
        (choice && (!digest_valid(strchr(choice, '=') ? strchr(choice, '=') + 1 : choice))) ||
        (accepted_arch && !digest_valid(accepted_arch)) ||
        (accepted_privileged && !digest_valid(accepted_privileged))) goto done;
    for (i = 0; i < reference_count; ++i) {
        result = up_select_slot(&slots[i], references[i], root, catalog, choice,
                                arch, libc, &work[i], &up_to_date);
        if (result) goto done;
        if (up_to_date) {
            printf("up-to-date %s %s\n", slots[i].source_id, slots[i].old_digest);
            continue;
        }
        chosen[chosen_count++] = i;
    }
    if (!chosen_count) { result = 0; goto done; }
    for (i = 0; i < chosen_count; ++i) {
        olds[i] = slots[chosen[i]].old_digest;
        news[i] = slots[chosen[i]].new_digest;
    }
    request.olds = (const char *const *)olds;
    request.news = (const char *const *)news;
    request.pair_count = chosen_count;
    if (accepted_arch) { request.accept_arch = &accepted_arch; request.arch_count = 1; }
    if (accepted_privileged) {
        request.accept_privileged = &accepted_privileged;
        request.privileged_count = 1;
    }
    request.accept_service = (const char *const *)services;
    request.service_count = service_count;
    result = holy_state_update_prepare(&request, root, inner_hash, &inner);
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
    fputs("format holy-up-plan-2\n", stream);
    for (i = 0; i < chosen_count; ++i) {
        const struct up_slot *slot = &slots[chosen[i]];
        fprintf(stream, "slot %zu\n", i);
        fprintf(stream, "source-id %s\n", slot->source_id);
        fputs("alias ", stream);
        quoted(stream, slot->alias);
        fputs("\ncatalog ", stream);
        quoted(stream, slot->catalog);
        fprintf(stream, "\nindex %s\nold %s\nnew %s\naccept-arch %s\naccept-privileged %s\n"
                "signature %s\n",
                slot->index, slot->old_digest, slot->new_digest,
                accepted_arch ? accepted_arch : "-",
                accepted_privileged ? accepted_privileged : "-",
                slot->signature);
        for (s = 0; s < service_count; ++s)
            fprintf(stream, "service %s\n", services[s]);
    }
    fprintf(stream, "state-plan %s\n", inner_hash);
    fputs(inner, stream);
    {
        int failed = ferror(stream);
        if (fclose(stream)) failed = 1;
        stream = NULL;
        if (failed || !digest_bytes(plan, size, plan_hash) ||
            !write_plan(output, plan, size)) { result = 1; goto done; }
    }
    /* the review states what each source proved about the generation it fixed, since a
       plan document is where that decision lives */
    for (i = 0; i < chosen_count; ++i) {
        const struct up_slot *slot = &slots[chosen[i]];
        printf("prepared-slot %zu source-id %s old %s new %s index %s signature %s\n", i,
               slot->source_id, slot->old_digest, slot->new_digest, slot->index,
               slot->signature);
    }
    if (chosen_count > 1)
        printf("prepared %s %s slots %zu\n", plan_hash, output, chosen_count);
    else
        printf("prepared %s %s old %s new %s index %s\n", plan_hash, output,
               slots[chosen[0]].old_digest, slots[chosen[0]].new_digest,
               slots[chosen[0]].index);
    if (!prepared) {
        char *apply_argv[] = {"holypkg", "apply", (char *)output, "--sha256",
                              plan_hash, "--root", (char *)root, NULL};
        if (fwrite(plan, 1, size, stdout) != size || fflush(stdout)) {
            result = 1;
            goto done;
        }
        if (!yes) {
            if (noninteractive || !isatty(STDIN_FILENO)) {
                fprintf(stderr, "holypkg: decision-required plan=%s file=%s; apply the reviewed file with its SHA-256\n",
                        plan_hash, output);
                result = 3;
                goto done;
            }
            if (fprintf(stderr, "Apply plan %s to %s? [y/N] ", plan_hash, root) < 0 ||
                fflush(stderr) || !fgets(answer, sizeof answer, stdin) ||
                (strcmp(answer, "y\n") && strcmp(answer, "Y\n") &&
                 strcmp(answer, "yes\n") && strcmp(answer, "YES\n"))) {
                result = 3;
                goto done;
            }
        }
        result = holy_apply_command(7, apply_argv);
        if (!result && temporary_plan) {
            unlink(temporary_plan);
            rmdir(temporary_dir);
        }
    }
    result = 0;
done:
    if (result == 2)
        fputs("usage: holypkg up SOURCE:PACKAGE [SOURCE:PACKAGE ...] [--all] [--prepare] [--output NEW_FILE] [--catalog MIRROR] [--choose SHA256] [--arch ARCH] [--libc LIBC] [--accept-arch SHA256] [--accept-privileged SHA256] [--accept-service UNIT ...] [--root DIRECTORY] [--yes] [--noninteractive]\n", stderr);
    if (stream) fclose(stream);
    up_slots_free(slots, (size_t)argc);
    for (i = 0; i < (size_t)argc; ++i) up_selection_free(&work[i]);
    free(work);
    free(chosen); free((void *)olds); free((void *)news);
    free(inner); free(plan);
    free(temporary_plan); free(temporary_dir); free(services);
    for (i = 0; i < discovered; ++i) free((void *)references[i]);
    for (i = 0; i < all.count; ++i) free(all.reference[i]);
    free(all.reference);
    free(references);
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

/* one slot a prepared plan updates, and the decisions its review named */
static void up_slot_forget(struct holy_up_slot *slot)
{
    size_t i;
    if (!slot) return;
    free(slot->alias); free(slot->catalog);
    free(slot->accept_arch); free(slot->accept_privileged);
    for (i = 0; i < slot->service_count; ++i) free(slot->services[i]);
    free(slot->services);
    memset(slot, 0, sizeof *slot);
}

void holy_up_plan_free(struct holy_up_plan *plan)
{
    size_t i;
    if (!plan) return;
    for (i = 0; i < plan->slot_count; ++i) up_slot_forget(&plan->slots[i]);
    free(plan->slots);
    free(plan->state_plan);
    free(plan->body);
    memset(plan, 0, sizeof *plan);
}

static int up_slot_add_service(struct holy_up_slot *slot, const char *unit, size_t *limit)
{
    char **grown;
    size_t i;
    if (!holy_unit_name_valid(unit)) return 0;
    for (i = 0; i < slot->service_count; ++i)
        if (!strcmp(slot->services[i], unit)) return 0;
    if (slot->service_count >= *limit) return 0;
    grown = realloc(slot->services, (slot->service_count + 1) * sizeof *grown);
    if (!grown) return 0;
    slot->services = grown;
    grown[slot->service_count] = strdup(unit);
    if (!grown[slot->service_count]) return 0;
    ++slot->service_count;
    return 1;
}

/* the header of a plan names one slot per block, and the unit consents belong to the
   slot above them. a v1 document has one implicit slot and no slot line. */
static int up_plan_take_slots(char **cursor, struct holy_up_plan *plan, int grouped,
                              size_t limit)
{
    struct holy_up_slot *slot = NULL, *grown;
    for (;;) {
        char *value = NULL;
        if (!strncmp(*cursor, "slot ", 5)) {
            struct holy_up_slot *grown;
            size_t declared;
            char *stop;
            if (!grouped || plan->slot_count >= limit) return 0;
            errno = 0;
            declared = strtoul(*cursor + 5, &stop, 10);
            if (errno || *stop != '\n' || declared != plan->slot_count) return 0;
            if (!(*cursor = next_line(*cursor))) return 0;
            grown = realloc(plan->slots, (plan->slot_count + 1) * sizeof *grown);
            if (!grown) return 0;
            plan->slots = grown;
            slot = &grown[plan->slot_count];
            memset(slot, 0, sizeof *slot);
            ++plan->slot_count;
            if (!take_field(cursor, "source-id", &value)) return 0;
            memcpy(slot->source_id, value, strlen(value) + 1);
            free(value); value = NULL;
            if (!digest_valid(slot->source_id)) return 0;
            continue;
        }
        if (!slot) {
            if (!grouped) {
                grown = realloc(plan->slots, sizeof *grown);
                if (!grown) return 0;
                plan->slots = grown;
                slot = &grown[0];
                memset(slot, 0, sizeof *slot);
                ++plan->slot_count;
                if (!take_field(cursor, "source-id", &value)) return 0;
                memcpy(slot->source_id, value, strlen(value) + 1);
                free(value); value = NULL;
                if (!digest_valid(slot->source_id)) return 0;
                continue;
            }
            return 0;
        }
        if (!take_field(cursor, "alias", &value)) return 0;
        free(slot->alias);
        slot->alias = value;
        if (!take_field(cursor, "catalog", &value)) return 0;
        free(slot->catalog);
        slot->catalog = value;
        if (!take_field(cursor, "index", &value)) return 0;
        memcpy(slot->index, value, strlen(value) + 1);
        free(value); value = NULL;
        if (!digest_valid(slot->index) || slot->catalog[0] != '/') return 0;
        if (!take_field(cursor, "old", &value)) return 0;
        memcpy(slot->old_digest, value, strlen(value) + 1);
        free(value); value = NULL;
        if (!take_field(cursor, "new", &value)) return 0;
        memcpy(slot->new_digest, value, strlen(value) + 1);
        free(value); value = NULL;
        if (!digest_valid(slot->old_digest) || !digest_valid(slot->new_digest)) return 0;
        if (!take_field(cursor, "accept-arch", &value)) return 0;
        free(slot->accept_arch);
        slot->accept_arch = value;
        if (!take_field(cursor, "accept-privileged", &value)) return 0;
        free(slot->accept_privileged);
        slot->accept_privileged = value;
        if (!take_field(cursor, "signature", &value)) return 0;
        memcpy(slot->signature, value, strlen(value) + 1);
        free(value); value = NULL;
        if (strcmp(slot->signature, "signed") && strcmp(slot->signature, "unsigned")) return 0;
        if ((strcmp(slot->accept_arch, "-") && strcmp(slot->accept_arch, slot->new_digest)) ||
            (strcmp(slot->accept_privileged, "-") &&
             strcmp(slot->accept_privileged, slot->new_digest)) ||
            !*slot->alias) return 0;
        while (!strncmp(*cursor, "service ", 8)) {
            char unit[256];
            size_t length = 0;
            char *name = *cursor + 8;
            while (name[length] && name[length] != '\n' && length < sizeof unit) ++length;
            if (!length || length >= sizeof unit) return 0;
            memcpy(unit, name, length);
            unit[length] = 0;
            if (!up_slot_add_service(slot, unit, &limit)) return 0;
            if (!(*cursor = next_line(*cursor))) return 0;
        }
        /* another block starts the next slot of the group */
        if (!strncmp(*cursor, "slot ", 5)) continue;
        return 1;
    }
}

int holy_up_plan_read(const char *path, const char *approved, struct holy_up_plan *plan)
{
    struct stat st;
    char actual[65], recorded[65], *data = NULL, *cursor, *snapshot = NULL, *body = NULL;
    char *inner = NULL;
    size_t size = 0, i, limit;
    int input = -1, staged = -1, result = 6, grouped = 0;
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
    if (!strncmp(data, "format holy-up-plan-2\n", 22)) grouped = 1;
    else if (strncmp(data, "format holy-up-plan-1\n", 22)) { result = 2; goto done; }
    cursor = data + 22;
    limit = size / 24 + 1;
    if (!up_plan_take_slots(&cursor, plan, grouped, limit)) { result = 2; goto done; }
    if (!plan->slot_count) { result = 2; goto done; }
    if (!take_field(&cursor, "state-plan", &inner) || !digest_valid(inner)) { result = 2; goto done; }
    if (strncmp(cursor, "[update]\n", 9)) { result = 2; goto done; }
    body = cursor;
    if (!digest_bytes(body, strlen(body), actual) || strcmp(actual, inner)) {
        result = 2;
        goto done;
    }
    for (i = 0; i < plan->slot_count; ++i) {
        struct holy_up_slot *slot = &plan->slots[i];
        size_t j;
        if (!strcmp(slot->old_digest, slot->new_digest)) { result = 2; goto done; }
        for (j = 0; j < i; ++j)
            if (!strcmp(slot->old_digest, plan->slots[j].old_digest) ||
                !strcmp(slot->new_digest, plan->slots[j].new_digest) ||
                !strcmp(slot->new_digest, plan->slots[j].old_digest)) {
                result = 2;
                goto done;
            }
    }
    plan->body = strdup(body);
    if (!plan->body) { result = 1; goto done; }
    plan->body_length = strlen(body);
    plan->state_plan = inner;
    inner = NULL;
    /* the plan digest is the document digest, which the body digest check reuses */
    memcpy(plan->hash, recorded, 65);
    result = 0;
done:
    free(inner);
    if (result) holy_up_plan_free(plan);
    if (staged >= 0) close(staged);
    if (input >= 0) close(input);
    if (snapshot) { unlink(snapshot); free(snapshot); }
    free(data);
    return result;
}
/* the catalogs of a group are locked in path order, so two applies of the same group
   take them the same way round */
static int up_slot_order(const void *left, const void *right)
{
    const struct holy_up_slot *const *a = left, *const *b = right;
    return strcmp((*a)->catalog, (*b)->catalog);
}

int holy_apply_trial(const struct holy_up_plan *plan, const char *root, char hash[65])
{
    const char **olds = NULL, **news = NULL;
    struct holy_update_request request = {0};
    char *record = NULL;
    size_t i;
    int ok = 0;
    hash[0] = 0;
    if (!plan->slot_count) return 1;
    olds = calloc(plan->slot_count, sizeof *olds);
    news = calloc(plan->slot_count, sizeof *news);
    if (!olds || !news) goto done;
    for (i = 0; i < plan->slot_count; ++i) {
        olds[i] = plan->slots[i].old_digest;
        news[i] = plan->slots[i].new_digest;
    }
    request.olds = olds;
    request.news = news;
    request.pair_count = plan->slot_count;
    if (holy_state_update_prepare(&request, root, hash, &record)) goto done;
    ok = !holy_state_apply_update(hash, &request, root);
done:
    free(record);
    free(olds);
    free(news);
    return ok;
}

int holy_apply_command(int argc, char **argv)
{
    const char *root = "/", *approved = NULL, *work = NULL;
    struct holy_up_plan plan = {0};
    const char **olds = NULL, **news = NULL, **services = NULL, **arch = NULL, **privileged = NULL;
    const struct holy_up_slot **order = NULL;
    int *dirs = NULL;
    char **snapshots = NULL;
    char *trial_root = NULL;
    char trial_state[65] = "-";
    struct holy_trial_copy copied = {0, 0, 0, 0};
    size_t i, service_total = 0, arch_count = 0, privileged_count = 0, service_count = 0;
    int result = 2;
    /* the plan path is argv[2], so the options after it are read in order rather than
       by counting arguments, and an option this command does not take is a usage error */
    for (i = 3; i < (size_t)argc; ++i) {
        if (!strcmp(argv[i], "--sha256") && i + 1 < (size_t)argc && !approved) {
            approved = argv[++i];
            continue;
        }
        if (!strcmp(argv[i], "--root") && i + 1 < (size_t)argc) { root = argv[++i]; continue; }
        if (!strcmp(argv[i], "--work") && i + 1 < (size_t)argc && !work) {
            work = argv[++i];
            continue;
        }
        goto done;
    }
    if (!approved || !digest_valid(approved) || !*root) goto done;
    /* a rehearsal applies the plan to a copy of the root, so the work directory has to
       be absolute and outside the tree it copies, or the copy would read its own output */
    if (work && (!*work || work[0] != '/' || holy_trial_work_inside(work, root))) goto done;
    result = holy_up_plan_read(argv[2], approved, &plan);
    if (result) goto done;
    /* the copy stands in for the root from here on, so every check and the transaction
       itself run against it and the running root keeps what it had */
    if (work) {
        trial_root = holy_trial_copy_root(root, work, &copied);
        if (!trial_root) {
            fprintf(stderr, "holypkg: the trial could not copy %s\n", root);
            result = 1;
            goto done;
        }
        root = trial_root;
    }
    if (result) goto done;
    for (i = 0; i < plan.slot_count; ++i) service_total += plan.slots[i].service_count;
    dirs = calloc(plan.slot_count, sizeof *dirs);
    olds = calloc(plan.slot_count, sizeof *olds);
    news = calloc(plan.slot_count, sizeof *news);
    services = calloc(service_total ? service_total : 1, sizeof *services);
    arch = calloc(plan.slot_count, sizeof *arch);
    privileged = calloc(plan.slot_count, sizeof *privileged);
    snapshots = calloc(plan.slot_count, sizeof *snapshots);
    order = calloc(plan.slot_count, sizeof *order);
    if (!dirs || !olds || !news || !services || !arch || !privileged || !snapshots || !order) {
        result = 1;
        goto done;
    }
    for (i = 0; i < plan.slot_count; ++i) order[i] = &plan.slots[i];
    if (plan.slot_count > 1) qsort(order, plan.slot_count, sizeof *order, up_slot_order);
    /* the whole review is one decision, so every catalog it names is locked before any
       slot is checked and stays locked until the transaction finishes */
    for (i = 0; i < plan.slot_count; ++i) {
        dirs[i] = open(order[i]->catalog, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (dirs[i] < 0 || flock(dirs[i], LOCK_SH)) { result = 6; goto done; }
    }
    for (i = 0; i < plan.slot_count; ++i) {
        struct holy_up_slot *slot = &plan.slots[i];
        struct holy_package_identity old_identity = {0};
        char source_id[65], current[65];
        const char *slot_arch = strcmp(slot->accept_arch, "-") ? slot->accept_arch : NULL;
        const char *slot_privileged = strcmp(slot->accept_privileged, "-") ?
                                      slot->accept_privileged : NULL;
        size_t j;
        olds[i] = slot->old_digest;
        news[i] = slot->new_digest;
        if (slot_arch) arch[arch_count++] = slot_arch;
        if (slot_privileged) privileged[privileged_count++] = slot_privileged;
        for (j = 0; j < slot->service_count; ++j) services[service_count++] = slot->services[j];
        result = holy_source_active_id(root, slot->alias, source_id);
        if (result) break;
        if (strcmp(slot->source_id, source_id)) { result = 3; break; }
        result = holy_source_catalog(root, slot->alias, slot->catalog, source_id);
        if (result) break;
        {
            char state[16] = {0};
            result = holy_source_catalog_signature(root, slot->alias, slot->catalog,
                                                   slot->index, state);
            if (result) break;
            /* a document that names a generation signed must still be signed by the key
               its source registered, since the plan is the approval */
            if (strcmp(state, slot->signature)) {
                fprintf(stderr, "holypkg: catalog signature for %s is %s, the plan says %s\n",
                        slot->alias, state, slot->signature);
                result = 3;
                break;
            }
        }
        snapshots[i] = holy_cache_snapshot(slot->old_digest, root);
        if (!snapshots[i] || !holy_package_identity(snapshots[i], &old_identity) ||
            strcmp(old_identity.digest, slot->old_digest)) {
            result = 6;
            break;
        }
        result = holy_repo_catalog_slot_digest(slot->catalog, &old_identity,
                                               slot->new_digest, current);
        if (result != 0 && result != 3) break;
        if (strcmp(current, slot->index)) {
            fprintf(stderr, "holypkg: prepared catalog generation changed for %s\n",
                    slot->alias);
            result = 3;
            break;
        }
        if (result) {
            fprintf(stderr, "holypkg: prepared artifact absent from source slot for %s\n",
                    slot->alias);
            break;
        }
        holy_package_identity_free(&old_identity);
    }
    if (result) goto done;
    if (trial_root) {
        /* the copy derives its own state plan, since that plan binds the device and
           inode of the root it was reviewed for, and the copy is a different directory */
        char derived[65];
        if (!holy_apply_trial(&plan, trial_root, derived)) result = 1;
        else snprintf(trial_state, sizeof trial_state, "%s", derived);
    } else {
        /* the state layer rebuilds the plan under its own writer lock and compares the
           approved digest, so the review and the apply are one decision */
        struct holy_update_request request = {
            (const char *const *)olds, (const char *const *)news, plan.slot_count,
            (const char *const *)arch, arch_count,
            (const char *const *)privileged, privileged_count,
            (const char *const *)services, service_count
        };
        result = holy_state_apply_update(plan.state_plan, &request, root);
    }
done:
    if (result == 2)
        fputs("usage: holypkg apply PLAN --sha256 PLAN_SHA256 [--root DIRECTORY] [--work DIRECTORY]\n", stderr);
    if (trial_root) {
        /* the copy is what the rehearsal reported, so it is named with the plan it
           derived and the counts that say what the copy carried and what it refused */
        if (!result)
            printf("apply-trial-root %s slots %zu state-plan %s directories %zu files %zu "
                   "bytes %zu refused %zu\n", trial_root, plan.slot_count, trial_state,
                   copied.directories, copied.files, copied.bytes, copied.refused);
        free(trial_root);
    }
    if (dirs) {
        for (i = 0; i < plan.slot_count; ++i) if (dirs[i] >= 0) close(dirs[i]);
        free(dirs);
    }
    if (snapshots) {
        for (i = 0; i < plan.slot_count; ++i) {
            if (snapshots[i]) { unlink(snapshots[i]); free(snapshots[i]); }
        }
        free(snapshots);
    }
    free(order);
    free(olds); free(news); free(services); free(arch); free(privileged);
    holy_up_plan_free(&plan);
    return result;
}