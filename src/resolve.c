#define _POSIX_C_SOURCE 200809L
#include "resolve.h"
#include "deps.h"
#include "package.h"
#include "provides.h"
#include "scan.h"
#include "solve.h"
#include "stage.h"
#include "verify.h"
#include "../backends/pacman.h"
#include "../backends/deb-version.h"
#include "version.h"
#include "../backends/apk-version.h"

#include <archive.h>
#include <archive_entry.h>
#include <elf.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct elf_edge {
    size_t requirement;
    const char *path, *kind, *target;
    char *owned_target;
    const struct holy_scanned_file *file;
    const struct holy_elf_symbol *symbol;
};

struct package_edge {
    size_t requirement;
    char *kind, *arch, *libc, *relation, *version;
};

struct package_claim { char *capability, *version; };

struct payload_path {
    char *path, *link;
    unsigned int mode;
};

struct version_adapter {
    const char *family;
    int (*compare)(const char *, const char *, int *);
};

static const struct version_adapter version_adapters[] = {
    {"pacman", holy_pacman_version_compare},
    {"deb", holy_deb_version_compare},
    {"holy", holy_version_compare},
    {"apk", holy_apk_version_compare}
};

struct local_item {
    struct holy_package_identity identity;
    char *unsupported_id;
    struct holy_solver_requirement *requirements;
    char **requirement_ids;
    char **original_requirements;
    size_t requirement_count;
    char *capability;
    struct holy_scan_result scan;
    struct elf_edge *edges;
    size_t edge_count;
    struct package_edge *package_edges;
    size_t package_edge_count;
    struct package_claim *claims;
    size_t claim_count;
    struct payload_path *file_paths;
    size_t file_count;
};

static int literal_path(const char *path);

static char *named_capability(const char *kind, const char *name)
{
    size_t prefix = strlen(kind), n = strlen(name);
    char *capability;
    if (prefix > 65536 || n > 65536 - prefix - 2) return NULL;
    capability = malloc(prefix + n + 2);
    if (capability) {
        memcpy(capability, kind, prefix);
        capability[prefix] = ':';
        memcpy(capability + prefix + 1, name, n + 1);
    }
    return capability;
}

static char *package_capability(const char *name)
{
    return named_capability("package", name);
}

static int add_requirement(struct local_item *item, const char *id, const char *cap)
{
    struct holy_solver_requirement *next;
    char **ids;
    char *capability;
    char *identifier;
    char *original;
    size_t i;
    if (item->requirement_count >= 65536) return 0;
    for (i = 0; i < item->requirement_count; ++i)
        if (!strcmp(item->requirement_ids[i], id)) return 0;
    capability = strdup(cap);
    if (!capability) return 0;
    identifier = strdup(id);
    if (!identifier) { free(capability); return 0; }
    original = strdup(cap);
    if (!original) { free(capability); free(identifier); return 0; }
    next = realloc(item->requirements,
                   (item->requirement_count + 1) * sizeof *next);
    if (!next) { free(identifier); free(capability); free(original); return 0; }
    item->requirements = next;
    ids = realloc(item->requirement_ids,
                  (item->requirement_count + 1) * sizeof *ids);
    if (!ids) { free(identifier); free(capability); free(original); return 0; }
    item->requirement_ids = ids;
    ids = realloc(item->original_requirements, (item->requirement_count + 1) * sizeof *ids);
    if (!ids) { free(identifier); free(capability); free(original); return 0; }
    item->original_requirements = ids;
    ids[item->requirement_count] = original;
    item->requirements[item->requirement_count].first = capability;
    item->requirements[item->requirement_count].alternative = NULL;
    item->requirement_ids[item->requirement_count] = identifier;
    ++item->requirement_count;
    return 1;
}

static int exact_requirement(void *opaque, const char *id,
    const char *consumer, const char *kind, const char *name,
    const char *arch, const char *libc, const char *relation,
    const char *version, const char *original, const char *evidence)
{
    struct local_item *item = opaque;
    char *capability;
    int ok;
    (void)original; (void)evidence;
    if (strcmp(consumer, item->identity.name)) return 0;
    if (strcmp(kind, "package") && strcmp(kind, "file") &&
        strcmp(kind, "command") && strcmp(kind, "soname")) {
        if (!item->unsupported_id) item->unsupported_id = strdup(id);
        return item->unsupported_id != NULL;
    }
    if (!strcmp(kind, "soname") &&
        (!name[0] || strchr(name, '/') || strcmp(relation, "any"))) {
        if (!item->unsupported_id) item->unsupported_id = strdup(id);
        return item->unsupported_id != NULL;
    }
    if (
        (!strcmp(kind, "file") && (!literal_path(name) || strcmp(relation, "any"))) ||
        (!strcmp(kind, "command") && (!name[0] || strchr(name, '/') ||
                                     !strcmp(name, ".") || !strcmp(name, "..") ||
                                     strcmp(relation, "any")))) return 0;
    capability = named_capability(kind, name);
    if (!capability) return 0;
    ok = add_requirement(item, id, capability);
    free(capability);
    if (ok && (strcmp(kind, "package") || strcmp(arch, "any") ||
               strcmp(libc, "any") || strcmp(relation, "any"))) {
        struct package_edge *grown = realloc(item->package_edges,
            (item->package_edge_count + 1) * sizeof *grown), *edge;
        if (!grown) return 0;
        item->package_edges = grown;
        edge = &grown[item->package_edge_count++];
        memset(edge, 0, sizeof *edge);
        edge->requirement = item->requirement_count - 1;
        edge->kind = strdup(kind); edge->arch = strdup(arch); edge->libc = strdup(libc);
        edge->relation = strdup(relation); edge->version = strdup(version);
        ok = edge->kind && edge->arch && edge->libc && edge->relation && edge->version;
    }
    return ok;
}

static int package_claim(void *opaque, const char *kind, const char *name,
                          const char *arch, const char *libc, const char *version,
                          const char *evidence)
{
    struct local_item *item = opaque;
    struct package_claim *grown, *claim;
    (void)evidence;
    if (strcmp(kind, "package")) return 1;
    if ((strcmp(arch, "any") && strcmp(arch, item->identity.arch)) ||
        (strcmp(libc, "any") && strcmp(libc, item->identity.libc))) {
        fprintf(stderr, "holypkg: package capability scope disagrees with artifact: %s\n", name);
        return 0;
    }
    if (item->claim_count == 65536) return 0;
    grown = realloc(item->claims, (item->claim_count + 1) * sizeof *grown);
    if (!grown) return 0;
    item->claims = grown;
    claim = &grown[item->claim_count++];
    claim->capability = package_capability(name);
    claim->version = strdup(version);
    return claim->capability && claim->version;
}

static const struct version_adapter *version_adapter(const char *family)
{
    size_t i;
    if (!family) return NULL;
    for (i = 0; i < sizeof version_adapters / sizeof *version_adapters; ++i)
        if (!strcmp(family, version_adapters[i].family)) return &version_adapters[i];
    return NULL;
}

static int version_matches(const char *candidate, const struct package_edge *edge,
                           const struct version_adapter *adapter)
{
    int order;
    if (!strcmp(edge->relation, "any")) return 1;
    if (!strcmp(candidate, "-")) return 0;
    if (!adapter || !adapter->compare(candidate, edge->version, &order)) return -1;
    return !strcmp(edge->relation, "eq") ? order == 0 :
           !strcmp(edge->relation, "ge") ? order >= 0 :
           !strcmp(edge->relation, "gt") ? order > 0 :
           !strcmp(edge->relation, "le") ? order <= 0 : order < 0;
}

static int add_provide(struct holy_solver_item *item, const char *capability)
{
    const char **next;
    char *copy;
    size_t i;
    for (i = 0; i < item->provides_count; ++i)
        if (!strcmp(item->provides[i], capability)) return 1;
    if (item->provides_count >= 65536) return 0;
    copy = strdup(capability);
    if (!copy) return 0;
    next = realloc((void *)item->provides, (item->provides_count + 1) * sizeof *next);
    if (!next) { free(copy); return 0; }
    item->provides = next;
    next[item->provides_count++] = copy;
    return 1;
}

static int file_path_order(const void *left, const void *right)
{
    const struct payload_path *a = left, *b = right;
    return strcmp(a->path, b->path);
}

static int collect_file_path(void *opaque, const struct holy_manifest_entry *entry)
{
    struct local_item *item = opaque;
    struct payload_path *paths, *path;
    if (entry->directory) return 1;
    if (item->file_count == SIZE_MAX / sizeof *paths) return 0;
    paths = realloc(item->file_paths, (item->file_count + 1) * sizeof *paths);
    if (!paths) return 0;
    item->file_paths = paths;
    path = &paths[item->file_count];
    path->path = strdup(entry->path);
    path->link = entry->link ? strdup(entry->link) : NULL;
    path->mode = entry->mode;
    if (!path->path || (entry->link && !path->link)) {
        free(path->path); free(path->link);
        return 0;
    }
    ++item->file_count;
    return 1;
}

static const struct payload_path *find_path(const struct local_item *item, const char *path)
{
    struct payload_path key = {(char *)path, NULL, 0};
    return item->file_count ? bsearch(&key, item->file_paths, item->file_count,
                                      sizeof *item->file_paths, file_path_order) : NULL;
}

static int has_file(const struct local_item *item, const char *absolute)
{
    return find_path(item, absolute + 1) != NULL;
}

static int command_target(const struct local_item *item, const char *path)
{
    char *current = strdup(path);
    size_t hop;
    int result = 0;
    if (!current) return 0;
    for (hop = 0; hop < 16; ++hop) {
        const struct payload_path *entry = find_path(item, current);
        char *next;
        if (!entry) break;
        if (!entry->link) { result = (entry->mode & 0111) != 0; break; }
        next = holy_relative_link_path(current, strlen(current), entry->link, "");
        if (!next) break;
        free(current);
        current = next;
    }
    free(current);
    return result;
}

static int has_command(const struct local_item *item, const char *name)
{
    static const char *const dirs[] = {"usr/bin/", "bin/", "usr/sbin/", "sbin/"};
    size_t i, length = strlen(name);
    for (i = 0; i < sizeof dirs / sizeof *dirs; ++i) {
        size_t prefix = strlen(dirs[i]);
        char *path = malloc(prefix + length + 1);
        int found;
        if (!path) return 0;
        memcpy(path, dirs[i], prefix);
        memcpy(path + prefix, name, length + 1);
        found = command_target(item, path);
        free(path);
        if (found) return 1;
    }
    return 0;
}

static int has_soname(const struct local_item *item, const char *name)
{
    size_t i;
    for (i = 0; i < item->scan.count; ++i) {
        const struct holy_scanned_file *file = &item->scan.files[i];
        if (file->elf.type == ET_DYN && !(file->elf.flags1 & DF_1_PIE) &&
            file->elf.soname && !strcmp(file->elf.soname, name) &&
            !strcmp(file->runtime, item->identity.libc)) return 1;
    }
    return 0;
}

static int package_requirements(struct local_item *local, struct holy_solver_item *items, size_t count)
{
    size_t i, j, k;
    for (i = 0; i < count; ++i) for (j = 0; j < local[i].package_edge_count; ++j) {
        const struct package_edge *edge = &local[i].package_edges[j];
        size_t index = edge->requirement;
        const char *base = local[i].original_requirements[index];
        const char *family = local[i].identity.version_family;
        const char *relation = edge->relation;
        const struct version_adapter *adapter = version_adapter(family);
        int constrained = strcmp(relation, "any") != 0;
        char *capability;
        size_t length = strlen(local[i].requirement_ids[index]) + 80;
        if (constrained && !adapter) {
            fprintf(stderr, "holypkg: unsupported-version-family consumer=%s requirement=%s\n",
                local[i].identity.digest, local[i].requirement_ids[index]);
            return 0;
        }
        capability = malloc(length);
        if (!capability) return 0;
        snprintf(capability, length, "package-edge:%s:%s", local[i].identity.digest,
                 local[i].requirement_ids[index]);
        free((char *)local[i].requirements[index].first);
        local[i].requirements[index].first = capability;
        for (k = 0; k < count; ++k) {
            const struct holy_package_identity *candidate = &local[k].identity;
            int matches = 0;
            size_t claim;
            if ((strcmp(edge->arch, "any") && strcmp(edge->arch, candidate->arch)) ||
                (strcmp(edge->libc, "any") && strcmp(edge->libc, candidate->libc))) continue;
            if (constrained && (!candidate->version_family || strcmp(candidate->version_family, family))) continue;
            if (!strcmp(edge->kind, "file")) matches = has_file(&local[k], base + 5);
            else if (!strcmp(edge->kind, "command")) matches = has_command(&local[k], base + 8);
            else if (!strcmp(edge->kind, "soname")) matches = has_soname(&local[k], base + 7);
            else {
                if (!strcmp(base, local[k].capability)) matches = version_matches(candidate->version, edge, adapter);
                for (claim = 0; !matches && claim < local[k].claim_count; ++claim)
                    if (!strcmp(base, local[k].claims[claim].capability))
                        matches = version_matches(local[k].claims[claim].version, edge, adapter);
            }
            if (matches < 0) return 0;
            if (matches && !add_provide(&items[k], capability)) return 0;
        }
    }
    return 1;
}

static int provides(const struct holy_solver_item *item, const char *capability)
{
    size_t i;
    for (i = 0; i < item->provides_count; ++i)
        if (!strcmp(item->provides[i], capability)) return 1;
    return 0;
}

static int compatible(const struct holy_scanned_file *a, const struct holy_scanned_file *b)
{
    return a->elf.elf_class == b->elf.elf_class && a->elf.machine == b->elf.machine &&
           !strcmp(a->runtime, b->runtime);
}

static int exports_symbol(const struct holy_elf_info *elf, const struct holy_elf_symbol *wanted)
{
    size_t i;
    for (i = 0; i < elf->symbol_count; ++i) {
        const struct holy_elf_symbol *s = &elf->symbols[i];
        if (!s->section || (s->binding != STB_GLOBAL && s->binding != STB_WEAK && s->binding != 10) ||
            (s->visibility != STV_DEFAULT && s->visibility != STV_PROTECTED) ||
            strcmp(s->name, wanted->name)) continue;
        if ((wanted->type == STT_TLS) != (s->type == STT_TLS)) continue;
        if (wanted->type == STT_FUNC && s->type != STT_FUNC && s->type != 10) continue;
        if (wanted->type == STT_OBJECT && s->type != STT_OBJECT) continue;
        if (wanted->version) {
            if (!s->version || strcmp(s->version, wanted->version)) continue;
        } else if (s->version_hidden) continue;
        return 1;
    }
    return 0;
}

static int literal_path(const char *path)
{
    const char *part, *end;
    if (path[0] != '/' || !path[1] || strchr(path, '$')) return 0;
    for (part = path + 1; ; part = end + 1) {
        size_t length;
        end = strchr(part, '/');
        length = end ? (size_t)(end - part) : strlen(part);
        if (!length || (length == 1 && part[0] == '.') ||
            (length == 2 && !memcmp(part, "..", 2))) return 0;
        if (!end) return 1;
    }
}

static int needed_matches(const struct holy_scanned_file *consumer,
                           const struct holy_scanned_file *provider, const char *needed)
{
    size_t i, j;
    if (!compatible(consumer, provider) || provider->elf.type != ET_DYN ||
        (provider->elf.flags1 & DF_1_PIE)) return 0;
    if (needed[0] == '/') {
        if (!literal_path(needed) || strcmp(provider->path, needed + 1)) return 0;
    } else if (!provider->elf.soname || strcmp(provider->elf.soname, needed)) return 0;
    for (i = 0; i < consumer->elf.version_count; ++i) {
        const struct holy_elf_version *v = &consumer->elf.versions[i];
        if (v->weak || strcmp(v->provider, needed)) continue;
        for (j = 0; j < provider->elf.defined_version_count; ++j)
            if (!strcmp(v->name, provider->elf.defined_versions[j].name)) break;
        if (j == provider->elf.defined_version_count) return 0;
    }
    for (i = 0; i < consumer->elf.symbol_count; ++i) {
        const struct holy_elf_symbol *s = &consumer->elf.symbols[i];
        if (s->section || s->binding == STB_WEAK || !s->provider || strcmp(s->provider, needed)) continue;
        if (!exports_symbol(&provider->elf, s)) return 0;
    }
    return 1;
}

static int direct_provider(const struct holy_scanned_file *consumer,
                            const struct holy_scanned_file *provider)
{
    size_t i;
    if (consumer == provider) return 1;
    if (consumer->elf.interpreter && consumer->elf.interpreter[0] == '/' &&
        !strcmp(consumer->elf.interpreter + 1, provider->path)) return 1;
    for (i = 0; i < consumer->elf.needed_count; ++i) {
        const char *needed = consumer->elf.needed[i];
        if ((needed[0] == '/' && literal_path(needed) && !strcmp(needed + 1, provider->path)) ||
            (provider->elf.soname && !strcmp(needed, provider->elf.soname))) return 1;
    }
    return 0;
}

static int elf_requirement(struct local_item *local, struct holy_solver_item *items,
                            size_t count, size_t consumer_index,
                            const struct holy_scanned_file *file, const char *kind,
                            const char *target, const struct holy_elf_symbol *symbol)
{
    struct local_item *consumer = &local[consumer_index];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const char *parts[] = {consumer->identity.name, consumer->identity.arch,
                          consumer->identity.libc, file->path, kind, target};
    unsigned char hash[32];
    unsigned int length;
    char id[69] = "elf-", capability[140];
    struct elf_edge *edges;
    size_t i, j;
    int ok = 0;
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto done;
    for (i = 0; i < sizeof parts / sizeof *parts; ++i)
        if (EVP_DigestUpdate(ctx, parts[i], strlen(parts[i]) + 1) != 1) goto done;
    if (EVP_DigestFinal_ex(ctx, hash, &length) != 1 || length != sizeof hash) goto done;
    for (i = 0; i < sizeof hash; ++i) snprintf(id + 4 + i * 2, 3, "%02x", hash[i]);
    snprintf(capability, sizeof capability, "elf:%s:%s", consumer->identity.digest, id);
    edges = realloc(consumer->edges, (consumer->edge_count + 1) * sizeof *edges);
    if (!edges) goto done;
    consumer->edges = edges;
    edges[consumer->edge_count].requirement = consumer->requirement_count;
    edges[consumer->edge_count].path = file->path;
    edges[consumer->edge_count].kind = kind;
    edges[consumer->edge_count].target = target;
    edges[consumer->edge_count].owned_target = NULL;
    edges[consumer->edge_count].file = file;
    edges[consumer->edge_count].symbol = symbol;
    if (!add_requirement(consumer, id, capability)) goto done;
    ++consumer->edge_count;
    for (i = 0; i < count; ++i) {
        for (j = 0; j < local[i].scan.count; ++j) {
            const struct holy_scanned_file *candidate = &local[i].scan.files[j];
            int matches;
            if (!strcmp(kind, "soname") || !strcmp(kind, "needed-path"))
                matches = needed_matches(file, candidate, target);
            else if (!strcmp(kind, "interpreter"))
                matches = target[0] == '/' && !strcmp(target + 1, candidate->path) &&
                          (candidate->mode & 0111) && compatible(file, candidate);
            else matches = compatible(file, candidate) && direct_provider(file, candidate) &&
                           exports_symbol(&candidate->elf, symbol);
            if (matches && !add_provide(&items[i], capability)) goto done;
        }
    }
    ok = 1;
done:
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int script_path_edge(struct local_item *local, struct holy_solver_item *items,
                            size_t count, size_t consumer_index,
                            const struct holy_scanned_script *script,
                            const char *kind, const char *path,
                            const char *link_target)
{
    struct local_item *consumer = &local[consumer_index];
    const char *parts[] = {consumer->identity.name, consumer->identity.arch,
                          consumer->identity.libc, script->path, kind, path};
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    struct elf_edge *edges;
    unsigned char hash[32];
    unsigned int length;
    char id[72] = "script-", capability[160];
    size_t i, j;
    int ok = 0;
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto done;
    for (i = 0; i < sizeof parts / sizeof *parts; ++i)
        if (EVP_DigestUpdate(ctx, parts[i], strlen(parts[i]) + 1) != 1) goto done;
    if (EVP_DigestFinal_ex(ctx, hash, &length) != 1 || length != sizeof hash) goto done;
    for (i = 0; i < sizeof hash; ++i) snprintf(id + 7 + i * 2, 3, "%02x", hash[i]);
    snprintf(capability, sizeof capability, "script:%s:%s", consumer->identity.digest, id);
    edges = realloc(consumer->edges, (consumer->edge_count + 1) * sizeof *edges);
    if (!edges) goto done;
    consumer->edges = edges;
    edges[consumer->edge_count].requirement = consumer->requirement_count;
    edges[consumer->edge_count].path = script->path;
    edges[consumer->edge_count].kind = kind;
    edges[consumer->edge_count].owned_target = malloc(strlen(path) + 2);
    if (!edges[consumer->edge_count].owned_target) goto done;
    sprintf(edges[consumer->edge_count].owned_target, "/%s", path);
    edges[consumer->edge_count].target = edges[consumer->edge_count].owned_target;
    edges[consumer->edge_count].file = NULL;
    edges[consumer->edge_count].symbol = NULL;
    if (!add_requirement(consumer, id, capability)) {
        free(edges[consumer->edge_count].owned_target);
        goto done;
    }
    ++consumer->edge_count;
    for (i = 0; i < count; ++i) {
        if (link_target) {
            for (j = 0; j < local[i].scan.symlink_count; ++j) {
                const struct holy_scanned_symlink *candidate = &local[i].scan.symlinks[j];
                if (!strcmp(candidate->path, path) && !strcmp(candidate->target, link_target) &&
                    !add_provide(&items[i], capability)) goto done;
            }
        } else for (j = 0; j < local[i].scan.count; ++j) {
            const struct holy_scanned_file *candidate = &local[i].scan.files[j];
            if (!strcmp(candidate->path, path) && (candidate->mode & 0111) &&
                (candidate->elf.type == ET_EXEC ||
                 (candidate->elf.type == ET_DYN &&
                  ((candidate->elf.flags1 & DF_1_PIE) || candidate->elf.interpreter))) &&
                !add_provide(&items[i], capability)) goto done;
        }
    }
    ok = 1;
done:
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int script_requirement(struct local_item *local, struct holy_solver_item *items,
                              size_t count, size_t consumer_index,
                              const struct holy_scanned_script *script)
{
    char *path = strdup(script->interpreter + 1);
    char *visited[16] = {0};
    size_t hop, i, j;
    int result = 0;
    if (!path) return 0;
    for (hop = 0; hop < 16; ++hop) {
        const char *target = NULL;
        size_t prefix = 0;
        char *next;
        for (i = 0; i < hop; ++i) if (!strcmp(path, visited[i])) {
            result = 3; goto done;
        }
        visited[hop] = strdup(path);
        if (!visited[hop]) goto done;
        for (i = 0; i < count; ++i) for (j = 0; j < local[i].scan.symlink_count; ++j) {
            const struct holy_scanned_symlink *candidate = &local[i].scan.symlinks[j];
            size_t n = strlen(candidate->path);
            if (n <= prefix || strncmp(path, candidate->path, n) ||
                (path[n] && path[n] != '/')) continue;
            prefix = n;
            target = candidate->target;
        }
        if (!target) {
            result = script_path_edge(local, items, count, consumer_index, script,
                                      "shebang", path, NULL);
            break;
        }
        for (i = 0; i < count; ++i) for (j = 0; j < local[i].scan.symlink_count; ++j) {
            const struct holy_scanned_symlink *candidate = &local[i].scan.symlinks[j];
            if (strlen(candidate->path) == prefix && !strncmp(path, candidate->path, prefix) &&
                strcmp(candidate->target, target)) {
                fprintf(stderr, "holypkg: ambiguous script alias %.*s\n", (int)prefix, path);
                result = 3; goto done;
            }
        }
        next = holy_relative_link_path(path, prefix, target, path + prefix);
        if (!next) { result = 3; goto done; }
        path[prefix] = 0;
        if (!script_path_edge(local, items, count, consumer_index, script,
                              "path-alias", path, target)) { free(next); goto done; }
        free(path);
        path = next;
    }
    if (hop == 16) result = 3;
done:
    for (i = 0; i < 16; ++i) free(visited[i]);
    free(path);
    return result;
}

static int elf_requirements(struct local_item *local, struct holy_solver_item *items, size_t count)
{
    size_t i, j, k;
    for (i = 0; i < count; ++i)
        for (j = 0; j < local[i].scan.script_count; ++j)
            {
                int status = script_requirement(local, items, count, i, &local[i].scan.scripts[j]);
                if (status != 1) return status;
            }
    for (i = 0; i < count; ++i) for (j = 0; j < local[i].scan.count; ++j) {
        const struct holy_scanned_file *f = &local[i].scan.files[j];
        if (f->elf.interpreter && !elf_requirement(local, items, count, i, f, "interpreter", f->elf.interpreter, NULL)) return 0;
        for (k = 0; k < f->elf.needed_count; ++k) {
            if (strchr(f->elf.needed[k], '/') && !literal_path(f->elf.needed[k])) {
                fputs("holypkg: DT_NEEDED paths require a launch context\n", stderr);
                return 0;
            }
            if (!elf_requirement(local, items, count, i, f,
                                 f->elf.needed[k][0] == '/' ? "needed-path" : "soname",
                                 f->elf.needed[k], NULL)) return 0;
        }
        for (k = 0; k < f->elf.symbol_count; ++k) {
            const struct holy_elf_symbol *s = &f->elf.symbols[k];
            if (s->section || !s->name[0] || s->binding == STB_WEAK || s->binding == STB_LOCAL) continue;
            if (s->provider) {
                size_t n;
                for (n = 0; n < f->elf.needed_count; ++n)
                    if (!strcmp(f->elf.needed[n], s->provider)) break;
                if (n == f->elf.needed_count) return 0;
            } else if (!elf_requirement(local, items, count, i, f, "symbol", s->name, s)) return 0;
        }
    }
    return 1;
}

static void json_string(const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    putchar('"');
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p < 32 || *p >= 127) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}

static int symbol_context(const struct local_item *consumer, const struct elf_edge *edge,
                            const struct local_item *provider, const struct holy_solver_item *item)
{
    size_t i, j;
    for (i = 0; i < provider->scan.count; ++i) {
        const struct holy_scanned_file *f = &provider->scan.files[i];
        if (!compatible(edge->file, f) || !exports_symbol(&f->elf, edge->symbol)) continue;
        if (f == edge->file) return 1;
        for (j = 0; j < consumer->edge_count; ++j) {
            const struct elf_edge *dependency = &consumer->edges[j];
            if (dependency->file != edge->file) continue;
            if ((!strcmp(dependency->kind, "soname") && f->elf.soname &&
                 !strcmp(dependency->target, f->elf.soname)) ||
                ((!strcmp(dependency->kind, "interpreter") || !strcmp(dependency->kind, "needed-path")) &&
                 dependency->target[0] == '/' && !strcmp(dependency->target + 1, f->path)))
                if (provides(item, consumer->requirements[dependency->requirement].first)) return 1;
        }
    }
    return 0;
}

static void report_edges(const struct local_item *local, const struct holy_solver_item *items,
                          size_t count, const int *selected, int json)
{
    size_t i, j, k;
    for (i = 0; i < count; ++i) {
        if (selected ? !selected[i] : i != 0) continue;
        for (j = 0; j < local[i].edge_count; ++j) {
            const struct elf_edge *edge = &local[i].edges[j];
            const char *id = local[i].requirement_ids[edge->requirement];
            const char *cap = local[i].requirements[edge->requirement].first;
            int first = 1;
            if (json) {
                printf("{\"schema\":\"holy-local-solve-1\",\"type\":\"%s\",\"id\":\"%s\",\"consumer\":\"%s\",\"path\":",
                       !strcmp(edge->kind, "shebang") ? "script-edge" : "elf-edge",
                       id, local[i].identity.digest);
                json_string(edge->path);
                printf(",\"kind\":\"%s\",\"target\":", edge->kind);
                json_string(edge->target);
                fputs(",\"providers\":[", stdout);
            } else {
                printf("%s %s consumer=%s path=",
                       !strcmp(edge->kind, "shebang") ? "script-edge" : "elf-edge",
                       id, local[i].identity.digest);
                json_string(edge->path);
                printf(" kind=%s target=", edge->kind);
                json_string(edge->target);
                fputs(" providers=", stdout);
            }
            for (k = 0; k < count; ++k) {
                if ((selected && !selected[k]) || !provides(&items[k], cap)) continue;
                if (!first) putchar(',');
                if (json) json_string(local[k].identity.digest);
                else fputs(local[k].identity.digest, stdout);
                first = 0;
            }
            puts(json ? "]}" : "");
        }
    }
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
                                        const struct holy_solver_item *items, size_t count,
                                        const char *const *skip_ids, size_t skip_count,
                                        size_t *consumer_index, size_t *requirement_index)
{
    unsigned char *seen = calloc(count, 1);
    size_t *queue = malloc(count * sizeof *queue);
    size_t head = 0, tail = 1, j;
    const char *missing = NULL;
    if (!seen || !queue) goto done;
    seen[0] = 1;
    queue[0] = 0;
    while (head < tail) {
        size_t current = queue[head++];
        const struct local_item *consumer = &local[current];
        for (j = 0; j < consumer->requirement_count; ++j) {
            size_t i, matches = 0, provider = 0;
            for (i = 0; i < count; ++i)
                if (provides(&items[i], consumer->requirements[j].first)) {
                    ++matches;
                    provider = i;
                }
            if (!matches) {
                size_t skip;
                for (skip = 0; skip < skip_count; ++skip)
                    if (!strncmp(skip_ids[skip], consumer->identity.digest, 64) &&
                        skip_ids[skip][64] == ':' &&
                        !strcmp(skip_ids[skip] + 65, consumer->requirement_ids[j])) break;
                if (skip < skip_count) continue;
                missing = consumer->requirement_ids[j];
                *consumer_index = current;
                *requirement_index = j;
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

static int capture_missing(const struct local_item *consumer, size_t requirement,
                           struct holy_missing_requirement *missing)
{
    size_t k;
    const char *id = consumer->requirement_ids[requirement];
    const char *kind = NULL, *name = NULL, *original;
    for (k = 0; k < consumer->edge_count; ++k) {
        const struct elf_edge *edge = &consumer->edges[k];
        if (edge->requirement != requirement) continue;
        kind = !strcmp(edge->kind, "soname") ? "soname" :
               !strcmp(edge->kind, "symbol") ? NULL : "file";
        name = edge->target;
        break;
    }
    if (!name) {
        original = consumer->original_requirements[requirement];
        if (!strncmp(original, "package:", 8)) { kind = "package"; name = original + 8; }
        else if (!strncmp(original, "file:", 5)) { kind = "file"; name = original + 5; }
        else if (!strncmp(original, "command:", 8)) { kind = "command"; name = original + 8; }
        else if (!strncmp(original, "soname:", 7)) { kind = "soname"; name = original + 7; }
    }
    if (!kind || !name || !*name) return 0;
    missing->consumer = strdup(consumer->identity.digest);
    missing->id = strdup(id);
    missing->kind = strdup(kind);
    missing->name = strdup(name);
    if (missing->consumer && missing->id && missing->kind && missing->name)
        return 1;
    holy_missing_requirement_free(missing);
    return 0;
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

static int artifact_order(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static int edge_order(const void *a, const void *b)
{
    const struct holy_resolved_edge *x = a, *y = b;
    int c = strcmp(x->consumer, y->consumer);
    return c ? c : strcmp(x->id, y->id);
}

static int collect_result(const struct local_item *local, const struct holy_solver_item *items,
                            size_t count, const int *selected, struct holy_resolution *out)
{
    size_t i, j, k;
    memcpy(out->root, local[0].identity.digest, sizeof out->root);
    out->artifacts = calloc(count, sizeof *out->artifacts);
    if (!out->artifacts) return 0;
    for (i = 0; i < count; ++i) if (selected[i]) {
        out->artifacts[out->artifact_count] = strdup(local[i].identity.digest);
        if (!out->artifacts[out->artifact_count]) return 0;
        ++out->artifact_count;
        for (j = 0; j < local[i].requirement_count; ++j) {
            struct holy_resolved_edge *next, *edge;
            const char *path = "-", *kind = "package", *target = NULL;
            for (k = 0; k < local[i].edge_count; ++k) {
                const struct elf_edge *e = &local[i].edges[k];
                if (e->requirement == j) { path = e->path; kind = e->kind; target = e->target; break; }
            }
            if (!target) {
                const char *original = local[i].original_requirements[j];
                if (!strncmp(original, "package:", 8)) target = original + 8;
                else if (!strncmp(original, "file:", 5)) {
                    kind = "file";
                    target = original + 5;
                } else if (!strncmp(original, "command:", 8)) {
                    kind = "command";
                    target = original + 8;
                } else if (!strncmp(original, "soname:", 7)) {
                    kind = "soname";
                    target = original + 7;
                } else return 0;
            }
            if (out->edge_count >= 65536) return 0;
            next = realloc(out->edges, (out->edge_count + 1) * sizeof *next);
            if (!next) return 0;
            out->edges = next;
            edge = &next[out->edge_count++];
            memset(edge, 0, sizeof *edge);
            edge->consumer = strdup(local[i].identity.digest);
            edge->id = strdup(local[i].requirement_ids[j]);
            edge->path = strdup(path);
            edge->kind = strdup(kind);
            edge->target = strdup(target);
            for (k = 0; k < count; ++k)
                if (selected[k] && provides(&items[k], local[i].requirements[j].first)) {
                    edge->provider = strdup(local[k].identity.digest);
                    break;
                }
            if (!edge->consumer || !edge->id || !edge->path || !edge->kind ||
                !edge->target || !edge->provider) return 0;
        }
    }
    qsort(out->artifacts, out->artifact_count, sizeof *out->artifacts, artifact_order);
    if (out->edge_count) qsort(out->edges, out->edge_count, sizeof *out->edges, edge_order);
    return 1;
}

static int resolve(const char *const *paths, size_t count, int json,
                    const char *generation, const char *choice,
                    struct holy_resolution *output, int all,
                    struct holy_missing_requirement *missing_output,
                    const char *const *skip_ids, size_t skip_count)
{
    struct local_item *local = NULL;
    struct holy_solver_item *items = NULL;
    int *selected = NULL, result = 6;
    size_t i, j, prepared = 0;
    int solved;
    const char *unresolved = NULL;
    size_t missing_consumer = 0, missing_index = 0;
    const char *unknown_context = NULL;
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
        if (!paths[i]) goto done;
        snapshot = holy_stage_local(paths[i], "holy-resolve");
        if (!snapshot) goto done;
        prepared = i + 1;
        if (!holy_verify_visit(snapshot, collect_file_path, &local[i]) ||
            !holy_scan_collect(snapshot, &local[i].scan) ||
            !holy_package_identity(snapshot, &local[i].identity) ||
            strcmp(local[i].identity.os, "linux") ||
            !inert_metadata(snapshot)) {
            unlink(snapshot); free(snapshot); goto done;
        }
        if (!holy_provides_visit(snapshot, package_claim, &local[i])) {
            unlink(snapshot); free(snapshot); goto done;
        }
        local[i].capability = package_capability(local[i].identity.name);
        if (!local[i].capability ||
            !holy_deps_visit(snapshot, exact_requirement, &local[i])) {
            unlink(snapshot); free(snapshot); goto done;
        }
        for (j = 0; j < i; ++j)
            if (!strcmp(local[j].identity.digest, local[i].identity.digest)) {
                unlink(snapshot); free(snapshot); goto done;
            }
        items[i].id = local[i].identity.digest;
        if (!add_provide(&items[i], local[i].capability)) {
            unlink(snapshot); free(snapshot); goto done;
        }
        for (j = 0; j < local[i].claim_count; ++j)
            if (!add_provide(&items[i], local[i].claims[j].capability)) {
                unlink(snapshot); free(snapshot); goto done;
            }
        if (local[i].file_count)
            qsort(local[i].file_paths, local[i].file_count,
                  sizeof *local[i].file_paths, file_path_order);
        unlink(snapshot);
        free(snapshot);
    }
    if (!package_requirements(local, items, count)) goto done;
    for (i = 0; i < count; ++i) for (j = 0; j < local[i].scan.script_count; ++j) {
        const struct holy_scanned_script *script = &local[i].scan.scripts[j];
        if (script->kind != 1 || !literal_path(script->interpreter)) {
            fprintf(stderr, "holypkg: script-interpreter-decision consumer=%s interpreter=%s\n",
                    script->path, script->interpreter);
            result = 3;
            goto done;
        }
    }
    {
        int status = elf_requirements(local, items, count);
        if (status != 1) { if (status == 3) result = 3; goto done; }
    }
    for (i = 0; i < count; ++i) {
        items[i].requires = local[i].requirements;
        items[i].requires_count = local[i].requirement_count;
    }
    if (chosen_id) {
        size_t requirement = local[0].requirement_count, provider = count;
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
            !provides(&items[provider], local[0].requirements[requirement].first)) {
            result = 3;
            goto done;
        }
        choice_capability = malloc(strlen(chosen_id) + 8);
        if (!choice_capability) goto done;
        sprintf(choice_capability, "choice:%s", chosen_id);
        replacement = strdup(choice_capability);
        if (!replacement) goto done;
        if (!add_provide(&items[provider], choice_capability)) { free(replacement); goto done; }
        free((char *)local[0].requirements[requirement].first);
        local[0].requirements[requirement].first = replacement;
    }
    solved = all ? holy_solve_exact_set(items, count, selected) :
                   holy_solve_exact_unique(items, count, items[0].id, selected);
    if (solved == 1) for (i = 0; i < count; ++i) if (selected[i]) {
        if (local[i].unsupported_id) {
            unresolved = local[i].unsupported_id;
            unknown_context = "unsupported-requirement";
            result = 3;
            goto done;
        }
        for (j = 0; j < local[i].requirement_count; ++j) {
            size_t k, matches = 0;
            for (k = 0; k < count; ++k)
                if (selected[k] && provides(&items[k], local[i].requirements[j].first)) ++matches;
            if (matches > 1) { result = 3; goto done; }
        }
        for (j = 0; j < local[i].edge_count; ++j) {
            const struct elf_edge *edge = &local[i].edges[j];
            size_t k;
            if (!edge->symbol) continue;
            for (k = 0; k < count; ++k)
                if (selected[k] && provides(&items[k], local[i].requirements[edge->requirement].first) &&
                    !symbol_context(&local[i], edge, &local[k], &items[k])) {
                    result = 3; goto done;
                }
        }
    }
    if (solved == 1) {
        size_t selected_count = 0;
        if (output && !collect_result(local, items, count, selected, output)) { result = 1; goto done; }
        if (json >= 0) report_edges(local, items, count, selected, json);
        for (i = 0; i < count; ++i) if (selected[i]) {
            if (json > 0)
                printf("{\"schema\":\"holy-local-solve-1\",\"type\":\"selected\",\"sha256\":\"%s\"}\n",
                       local[i].identity.digest);
            else if (!json) printf("selected %s\n", local[i].identity.digest);
            ++selected_count;
        }
        if (json > 0) {
            printf("{\"schema\":\"holy-local-solve-1\",\"type\":\"summary\",\"count\":%zu", selected_count);
            if (generation) printf(",\"generation\":\"%s\"", generation);
            puts("}");
        } else if (!json && generation) printf("generation %s\n", generation);
        result = 0;
    } else if (solved == 3) result = 3;
    else if (solved == 2) {
        result = 4;
        unresolved = missing_requirement(local, items, count, skip_ids, skip_count,
                                         &missing_consumer, &missing_index);
        if (missing_output && unresolved &&
            !capture_missing(&local[missing_consumer], missing_index,
                             missing_output)) result = 3;
        if (unresolved) for (j = 0; j < local[missing_consumer].edge_count; ++j) {
                const struct elf_edge *edge = &local[missing_consumer].edges[j];
                if (edge->requirement != missing_index) continue;
                if (edge->symbol) unknown_context = "unknown-symbol-scope";
                else if (!strcmp(edge->kind, "interpreter")) unknown_context = "unknown-interpreter-context";
                if (unknown_context) result = 3;
        }
    }
done:
    if (result && output) holy_resolution_free(output);
    if (json >= 0 && (result == 3 || result == 4) && prepared == count && local && items)
        report_edges(local, items, count, NULL, json);
    if (result && !missing_output) fprintf(stderr, "holypkg: local resolution %s\n",
                        result == 2 ? "has an invalid choice" :
                        result == 3 ? "needs provider choice" :
                        result == 4 ? "has a dependency conflict" :
                        "requires unsupported data or failed");
    if (unresolved && !missing_output)
        fprintf(stderr, "holypkg: unresolved requirement %s\n", unresolved);
    if (result && json > 0) {
        if (unresolved)
            printf("{\"schema\":\"holy-local-solve-1\",\"type\":\"error\",\"code\":\"%s\",\"requirement\":\"%s\"}\n",
                   unknown_context ? unknown_context : "dependency-conflict", unresolved);
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
        for (j = 0; j < local[i].requirement_count; ++j)
            free(local[i].original_requirements[j]);
        free(local[i].requirements);
        free(local[i].requirement_ids);
        free(local[i].original_requirements);
        free(local[i].capability);
        free(local[i].unsupported_id);
        for (j = 0; j < local[i].edge_count; ++j)
            free(local[i].edges[j].owned_target);
        free(local[i].edges);
        for (j = 0; j < local[i].package_edge_count; ++j) {
            free(local[i].package_edges[j].kind);
            free(local[i].package_edges[j].arch); free(local[i].package_edges[j].libc);
            free(local[i].package_edges[j].relation); free(local[i].package_edges[j].version);
        }
        free(local[i].package_edges);
        for (j = 0; j < local[i].claim_count; ++j) {
            free(local[i].claims[j].capability); free(local[i].claims[j].version);
        }
        free(local[i].claims);
        for (j = 0; j < local[i].file_count; ++j) {
            free(local[i].file_paths[j].path);
            free(local[i].file_paths[j].link);
        }
        free(local[i].file_paths);
        holy_scan_free(&local[i].scan);
        holy_package_identity_free(&local[i].identity);
    }
    if (items) for (i = 0; i < count; ++i) {
        for (j = 0; j < items[i].provides_count; ++j) free((void *)items[i].provides[j]);
        free((void *)items[i].provides);
    }
    free(items); free(local); free(selected);
    free(chosen_id); free(choice_capability);
    return result;
}

int holy_resolve_local(const char *const *paths, size_t count, int json,
                       const char *generation, const char *choice)
{
    return resolve(paths, count, json, generation, choice, NULL, 0, NULL, NULL, 0);
}

int holy_resolve_collect(const char *const *paths, size_t count,
                          const char *choice, struct holy_resolution *result)
{
    memset(result, 0, sizeof *result);
    return resolve(paths, count, -1, NULL, choice, result, 0, NULL, NULL, 0);
}

int holy_resolve_collect_set(const char *const *paths, size_t count,
                              struct holy_resolution *result)
{
    memset(result, 0, sizeof *result);
    return resolve(paths, count, -1, NULL, NULL, result, 1, NULL, NULL, 0);
}

void holy_missing_requirement_free(struct holy_missing_requirement *missing)
{
    free(missing->consumer);
    free(missing->id);
    free(missing->kind);
    free(missing->name);
    memset(missing, 0, sizeof *missing);
}

int holy_resolve_missing(const char *const *paths, size_t count,
                         const char *const *skip_ids, size_t skip_count,
                         struct holy_missing_requirement *missing)
{
    memset(missing, 0, sizeof *missing);
    return resolve(paths, count, -1, NULL, NULL, NULL, 0, missing,
                   skip_ids, skip_count);
}

void holy_resolution_free(struct holy_resolution *result)
{
    size_t i;
    for (i = 0; i < result->artifact_count; ++i) free(result->artifacts[i]);
    for (i = 0; i < result->edge_count; ++i) {
        struct holy_resolved_edge *e = &result->edges[i];
        free(e->consumer); free(e->id); free(e->provider);
        free(e->path); free(e->kind); free(e->target);
    }
    free(result->artifacts); free(result->edges);
    memset(result, 0, sizeof *result);
}

static int record_token(FILE *stream, const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    size_t encoded = 2;
    long offset = ftell(stream);
    if (!value || offset < 0 || offset > 16 * 1024 * 1024 - 2) return 0;
    for (; *p; ++p) {
        encoded += (*p < 32 || *p >= 127) ? 4 : (*p == '"' || *p == '\\') ? 2 : 1;
        if (encoded > 16 * 1024 * 1024 - (size_t)offset) return 0;
    }
    if (fputc('"', stream) == EOF) return 0;
    for (p = (const unsigned char *)value; *p; ++p) {
        if (*p == '"' || *p == '\\') {
            if (fputc('\\', stream) == EOF || fputc(*p, stream) == EOF) return 0;
        } else if (*p < 32 || *p >= 127) {
            if (fprintf(stream, "\\x%02x", *p) < 0) return 0;
        } else if (fputc(*p, stream) == EOF) return 0;
    }
    return fputc('"', stream) != EOF;
}

int holy_resolution_record(const struct holy_resolution *result, char **record, size_t *length)
{
    FILE *stream;
    size_t i, j;
    int ok = 0;
    *record = NULL; *length = 0;
    if (!result->artifact_count || strlen(result->root) != 64) return 0;
    stream = open_memstream(record, length);
    if (!stream) return 0;
    if (fprintf(stream, "format holy-resolution-1\nscope artifact-candidates\nroot %s\n", result->root) < 0) goto done;
    for (i = 0; i < result->artifact_count; ++i)
        if (fprintf(stream, "artifact %s\n", result->artifacts[i]) < 0) goto done;
    for (i = 0; i < result->edge_count; ++i) {
        const struct holy_resolved_edge *e = &result->edges[i];
        const char *fields[] = {e->consumer, e->id, e->provider, e->path, e->kind, e->target};
        if (fputs("edge", stream) == EOF) goto done;
        for (j = 0; j < sizeof fields / sizeof *fields; ++j)
            if (fputc(' ', stream) == EOF || !record_token(stream, fields[j])) goto done;
        if (fputc('\n', stream) == EOF) goto done;
    }
    ok = 1;
done:
    if (fclose(stream)) ok = 0;
    if (*length > 16 * 1024 * 1024) ok = 0;
    if (!ok) { free(*record); *record = NULL; *length = 0; }
    return ok;
}
