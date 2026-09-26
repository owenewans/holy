#define _POSIX_C_SOURCE 200809L
#include "resolve.h"
#include "deps.h"
#include "package.h"
#include "provides.h"
#include "scan.h"
#include "solve.h"
#include "stage.h"
#include "verify.h"

#include <archive.h>
#include <archive_entry.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct local_item {
    struct holy_package_identity identity;
    struct holy_solver_requirement *requirements;
    char **requirement_ids;
    size_t requirement_count;
    char *capability;
};

static char *package_capability(const char *name)
{
    size_t n = strlen(name);
    char *capability;
    if (n > 65536) return NULL;
    capability = malloc(n + 9);
    if (capability) {
        memcpy(capability, "package:", 8);
        memcpy(capability + 8, name, n + 1);
    }
    return capability;
}

static int exact_requirement(void *opaque, const char *id,
    const char *consumer, const char *kind, const char *name,
    const char *arch, const char *libc, const char *relation,
    const char *version, const char *original, const char *evidence)
{
    struct local_item *item = opaque;
    struct holy_solver_requirement *next;
    char **ids;
    char *capability;
    char *identifier;
    (void)original; (void)evidence;
    if (strcmp(consumer, item->identity.name) || strcmp(kind, "package") ||
        strcmp(arch, "any") || strcmp(libc, "any") ||
        strcmp(relation, "any") || strcmp(version, "-") ||
        item->requirement_count >= 65536) return 0;
    capability = package_capability(name);
    if (!capability) return 0;
    identifier = strdup(id);
    if (!identifier) { free(capability); return 0; }
    next = realloc(item->requirements,
                   (item->requirement_count + 1) * sizeof *next);
    if (!next) { free(identifier); free(capability); return 0; }
    item->requirements = next;
    ids = realloc(item->requirement_ids,
                  (item->requirement_count + 1) * sizeof *ids);
    if (!ids) { free(identifier); free(capability); return 0; }
    item->requirement_ids = ids;
    item->requirements[item->requirement_count].first = capability;
    item->requirements[item->requirement_count].alternative = NULL;
    item->requirement_ids[item->requirement_count] = identifier;
    ++item->requirement_count;
    return 1;
}

static int inert_metadata(const char *snapshot)
{
    struct archive *a = archive_read_new();
    struct archive_entry *entry;
    int status, hooks = 0, transform = 0, ok = 0;
    if (!a || archive_read_support_filter_lz4(a) != ARCHIVE_OK ||
        archive_read_support_format_tar(a) != ARCHIVE_OK ||
        archive_read_open_filename(a, snapshot, 8192) != ARCHIVE_OK) goto done;
    while ((status = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        const char *name = archive_entry_pathname(entry);
        if (!strcmp(name, "HOLY/hooks")) {
            hooks = 1;
            if (archive_entry_size(entry)) goto done;
        }
        if (!strcmp(name, "HOLY/transform")) {
            transform = 1;
            if (archive_entry_size(entry)) goto done;
        }
        if (archive_read_data_skip(a) != ARCHIVE_OK) goto done;
    }
    ok = status == ARCHIVE_EOF && hooks && transform;
done:
    if (a) archive_read_free(a);
    return ok;
}

static const char *missing_requirement(const struct local_item *local,
                                        size_t count)
{
    unsigned char *seen = calloc(count, 1);
    size_t *queue = malloc(count * sizeof *queue);
    size_t head = 0, tail = 1, j;
    const char *missing = NULL;
    if (!seen || !queue) goto done;
    seen[0] = 1;
    queue[0] = 0;
    while (head < tail) {
        const struct local_item *consumer = &local[queue[head++]];
        for (j = 0; j < consumer->requirement_count; ++j) {
            size_t i, matches = 0, provider = 0;
            for (i = 0; i < count; ++i)
                if (!strcmp(consumer->requirements[j].first,
                            local[i].capability)) {
                    ++matches;
                    provider = i;
                }
            if (!matches) {
                missing = consumer->requirement_ids[j];
                goto done;
            }
            if (matches == 1 && !seen[provider]) {
                seen[provider] = 1;
                queue[tail++] = provider;
            }
        }
    }
done:
    free(seen);
    free(queue);
    return missing;
}

static char *choice_requirement(const char *choice, const char **digest)
{
    const char *equal = strchr(choice, '=');
    char *id;
    size_t i, length;
    if (!equal || equal == choice || strlen(equal + 1) != 64) return NULL;
    length = (size_t)(equal - choice);
    if (length > 65536) return NULL;
    for (i = 0; i < length; ++i)
        if (!((choice[i] >= 'a' && choice[i] <= 'z') ||
              (choice[i] >= 'A' && choice[i] <= 'Z') ||
              (choice[i] >= '0' && choice[i] <= '9') ||
              choice[i] == '-' || choice[i] == '_' || choice[i] == '.')) return NULL;
    for (i = 0; i < 64; ++i)
        if (!((equal[i + 1] >= '0' && equal[i + 1] <= '9') ||
              (equal[i + 1] >= 'a' && equal[i + 1] <= 'f'))) return NULL;
    id = strndup(choice, length);
    if (id) *digest = equal + 1;
    return id;
}

int holy_resolve_local(const char *const *paths, size_t count, int json,
                       const char *generation, const char *choice)
{
    struct local_item *local = NULL;
    struct holy_solver_item *items = NULL;
    int *selected = NULL, result = 6;
    size_t i, j, prepared = 0;
    int solved;
    const char *unresolved = NULL;
    const char *chosen_digest = NULL;
    char *chosen_id = NULL, *choice_capability = NULL;
    if (choice) {
        chosen_id = choice_requirement(choice, &chosen_digest);
        if (!chosen_id) { result = 2; goto done; }
    }
    if (!paths || !count || count > 10000) goto done;
    local = calloc(count, sizeof *local);
    items = calloc(count, sizeof *items);
    selected = calloc(count, sizeof *selected);
    if (!local || !items || !selected) goto done;
    for (i = 0; i < count; ++i) {
        char *snapshot;
        const char **providers;
        if (!paths[i]) goto done;
        snapshot = holy_stage_local(paths[i], "holy-resolve");
        if (!snapshot) goto done;
        prepared = i + 1;
        if (!holy_verify_with_output(snapshot, 0) ||
            !holy_scan_local_with_output(snapshot, 0) ||
            !holy_provides_local(snapshot, 0) ||
            !holy_package_identity(snapshot, &local[i].identity) ||
            strcmp(local[i].identity.os, "linux") ||
            strcmp(local[i].identity.arch, "noarch") ||
            strcmp(local[i].identity.libc, "nolibc") ||
            !inert_metadata(snapshot)) {
            unlink(snapshot); free(snapshot); goto done;
        }
        local[i].capability = package_capability(local[i].identity.name);
        if (!local[i].capability ||
            !holy_deps_visit(snapshot, exact_requirement, &local[i])) {
            unlink(snapshot); free(snapshot); goto done;
        }
        unlink(snapshot);
        free(snapshot);
        for (j = 0; j < i; ++j)
            if (!strcmp(local[j].identity.digest, local[i].identity.digest))
                goto done;
        providers = malloc(sizeof *providers);
        if (!providers) goto done;
        providers[0] = local[i].capability;
        items[i].id = local[i].identity.digest;
        items[i].provides = providers;
        items[i].provides_count = 1;
        items[i].requires = local[i].requirements;
        items[i].requires_count = local[i].requirement_count;
    }
    if (chosen_id) {
        size_t requirement = local[0].requirement_count, provider = count;
        const char **providers;
        char *replacement;
        for (j = 0; j < local[0].requirement_count; ++j)
            if (!strcmp(local[0].requirement_ids[j], chosen_id)) {
                requirement = j;
                break;
            }
        for (i = 0; i < count; ++i)
            if (!strcmp(local[i].identity.digest, chosen_digest)) {
                provider = i;
                break;
            }
        if (requirement == local[0].requirement_count || provider == count ||
            strcmp(local[0].requirements[requirement].first,
                   local[provider].capability)) {
            result = 3;
            goto done;
        }
        choice_capability = malloc(strlen(chosen_id) + 8);
        if (!choice_capability) goto done;
        sprintf(choice_capability, "choice:%s", chosen_id);
        replacement = strdup(choice_capability);
        if (!replacement) goto done;
        providers = realloc((void *)items[provider].provides, 2 * sizeof *providers);
        if (!providers) { free(replacement); goto done; }
        items[provider].provides = providers;
        providers[1] = choice_capability;
        items[provider].provides_count = 2;
        free((char *)local[0].requirements[requirement].first);
        local[0].requirements[requirement].first = replacement;
    }
    solved = holy_solve_exact_unique(items, count, items[0].id, selected);
    if (solved == 1) {
        size_t selected_count = 0;
        for (i = 0; i < count; ++i) if (selected[i]) {
            if (json)
                printf("{\"schema\":\"holy-local-solve-1\",\"type\":\"selected\",\"sha256\":\"%s\"}\n",
                       local[i].identity.digest);
            else printf("selected %s\n", local[i].identity.digest);
            ++selected_count;
        }
        if (json) {
            printf("{\"schema\":\"holy-local-solve-1\",\"type\":\"summary\",\"count\":%zu", selected_count);
            if (generation) printf(",\"generation\":\"%s\"", generation);
            puts("}");
        } else if (generation) printf("generation %s\n", generation);
        result = 0;
    } else if (solved == 3) result = 3;
    else if (solved == 2) {
        result = 4;
        unresolved = missing_requirement(local, count);
    }
done:
    if (result) fprintf(stderr, "holypkg: local resolution %s\n",
                        result == 2 ? "has an invalid choice" :
                        result == 3 ? "needs provider choice" :
                        result == 4 ? "has a dependency conflict" :
                        "requires unsupported data or failed");
    if (unresolved) fprintf(stderr, "holypkg: unresolved requirement %s\n", unresolved);
    if (result && json) {
        if (unresolved)
            printf("{\"schema\":\"holy-local-solve-1\",\"type\":\"error\",\"code\":\"dependency-conflict\",\"requirement\":\"%s\"}\n", unresolved);
        else
            printf("{\"schema\":\"holy-local-solve-1\",\"type\":\"error\",\"code\":\"%s\"}\n",
                   result == 2 ? "invalid-query" :
                   result == 3 ? "decision-required" :
                   result == 4 ? "dependency-conflict" : "unsupported-input");
    }
    for (i = 0; i < prepared; ++i) {
        for (j = 0; j < local[i].requirement_count; ++j)
            free((char *)local[i].requirements[j].first);
        for (j = 0; j < local[i].requirement_count; ++j)
            free(local[i].requirement_ids[j]);
        free(local[i].requirements);
        free(local[i].requirement_ids);
        free(local[i].capability);
        holy_package_identity_free(&local[i].identity);
    }
    if (items) for (i = 0; i < count; ++i) free((void *)items[i].provides);
    free(items); free(local); free(selected);
    free(chosen_id); free(choice_capability);
    return result;
}
