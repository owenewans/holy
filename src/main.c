#include "config.h"
#include "package.h"
#include "verify.h"
#include "fetch.h"
#include "extract.h"
#include "check.h"
#include "elf.h"
#include "scan.h"
#include "repo.h"
#include "preview.h"
#include "deps.h"
#include "cache.h"
#include "state.h"
#include "provides.h"
#include "resolve.h"
#include "pack.h"
#include "docs.h"
#include "graph.h"
#include "source.h"
#include "import.h"
#include "up.h"
#include "run.h"

#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int add_local(int argc, char **argv)
{
    const char **inputs = NULL, **digests = NULL;
    const char **accepted_arch = NULL, **accepted_privileged = NULL;
    char (*hashes)[65] = NULL;
    const char *root = "/", *choice = NULL, *association = NULL;
    const char *bindings[1];
    char plan[65], answer[16], source_id[65], binding[130];
    size_t count = 0, arch_count = 0, privileged_count = 0, i, j;
    int yes = 0, noninteractive = 0, root_seen = 0, result = 2;
    if (argc < 3 || strncmp(argv[2], "local:", 6) || !argv[2][6]) goto done;
    inputs = calloc((size_t)argc, sizeof *inputs);
    digests = calloc((size_t)argc, sizeof *digests);
    accepted_arch = calloc((size_t)argc, sizeof *accepted_arch);
    accepted_privileged = calloc((size_t)argc, sizeof *accepted_privileged);
    hashes = calloc((size_t)argc, sizeof *hashes);
    if (!inputs || !digests || !accepted_arch || !accepted_privileged || !hashes) {
        result = 1; goto done;
    }
    inputs[count++] = argv[2] + 6;
    for (i = 3; i < (size_t)argc; ++i) {
        if (!strcmp(argv[i], "--candidate") && i + 1 < (size_t)argc &&
            !strncmp(argv[i + 1], "local:", 6) && argv[i + 1][6]) {
            inputs[count++] = argv[++i] + 6;
        } else if (!strcmp(argv[i], "--root") && !root_seen && i + 1 < (size_t)argc &&
                   argv[i + 1][0] && strncmp(argv[i + 1], "--", 2)) {
            root = argv[++i]; root_seen = 1;
        } else if (!strcmp(argv[i], "--choose") && !choice && i + 1 < (size_t)argc &&
                   argv[i + 1][0] && strncmp(argv[i + 1], "--", 2)) {
            choice = argv[++i];
        } else if (!strcmp(argv[i], "--associate-source") && !association &&
                   i + 1 < (size_t)argc && argv[i + 1][0] &&
                   strncmp(argv[i + 1], "--", 2)) {
            association = argv[++i];
        } else if (!strcmp(argv[i], "--accept-arch") && i + 1 < (size_t)argc &&
                   argv[i + 1][0] && strncmp(argv[i + 1], "--", 2)) {
            accepted_arch[arch_count++] = argv[++i];
        } else if (!strcmp(argv[i], "--accept-privileged") && i + 1 < (size_t)argc &&
                   argv[i + 1][0] && strncmp(argv[i + 1], "--", 2)) {
            accepted_privileged[privileged_count++] = argv[++i];
        } else if (!strcmp(argv[i], "--yes") && !yes) yes = 1;
        else if (!strcmp(argv[i], "--noninteractive") && !noninteractive) noninteractive = 1;
        else goto done;
    }
    if (count > 10000) goto done;
    for (i = 0; i < count; ++i) {
        if (!holy_cache_stage_local_digest(inputs[i], root, hashes[i])) {
            result = 1; goto done;
        }
        for (j = 0; j < i; ++j) if (!strcmp(hashes[j], hashes[i])) goto done;
        digests[i] = hashes[i];
    }
    if (association) {
        result = holy_source_active_id(root, association, source_id);
        if (result) goto done;
        snprintf(binding, sizeof binding, "%s=%s", hashes[0], source_id);
        bindings[0] = binding;
    }
    result = holy_state_set(digests, count, choice, NULL, root,
                            association ? bindings : NULL, association ? 1 : 0,
                            accepted_arch, arch_count,
                            accepted_privileged, privileged_count, plan);
    if (result) goto done;
    if (!yes) {
        if (noninteractive || !isatty(STDIN_FILENO)) {
            fprintf(stderr, "holypkg: decision-required plan=%s; rerun with --yes after review\n", plan);
            result = 3; goto done;
        }
        if (fflush(stdout) || fprintf(stderr, "Apply plan %s to %s? [y/N] ", plan, root) < 0 ||
            fflush(stderr)) { result = 1; goto done; }
        if (!fgets(answer, sizeof answer, stdin) ||
             (strcmp(answer, "y\n") && strcmp(answer, "Y\n") &&
             strcmp(answer, "yes\n") && strcmp(answer, "YES\n"))) {
            result = 3; goto done;
        }
    }
    result = holy_state_set(digests, count, choice, plan, root,
                            association ? bindings : NULL, association ? 1 : 0,
                            accepted_arch, arch_count,
                            accepted_privileged, privileged_count, NULL);
done:
    if (result == 2)
        fputs("usage: holypkg add local:FILE [--candidate local:FILE ...] [--choose ID=SHA256] [--associate-source ALIAS] [--accept-arch SHA256 ...] [--accept-privileged SHA256 ...] [--root DIRECTORY] [--yes] [--noninteractive]\n", stderr);
    free(hashes); free(digests); free(inputs);
    free(accepted_arch); free(accepted_privileged);
    return result;
}

static int fetch_source(int argc, char **argv)
{
    const char *separator = strchr(argv[2], ':');
    const char *root = "/", *catalog = NULL, *output = NULL;
    char source_id[65], *alias = NULL, *bound_catalog = NULL;
    int i, extract = 0, root_seen = 0, result = 2;
    if (!separator || separator == argv[2] || !separator[1] ||
        strchr(separator + 1, ':')) goto done;
    alias = malloc((size_t)(separator - argv[2]) + 1);
    if (!alias) { result = 1; goto done; }
    memcpy(alias, argv[2], (size_t)(separator - argv[2]));
    alias[separator - argv[2]] = 0;
    if (!strcmp(alias, "local")) goto done;
    for (i = 3; i < argc; ++i) {
        if (!strcmp(argv[i], "--catalog") && !catalog && i + 1 < argc &&
            argv[i + 1][0] && strncmp(argv[i + 1], "--", 2))
            catalog = argv[++i];
        else if (!strcmp(argv[i], "--output") && !output && i + 1 < argc &&
                 argv[i + 1][0] && strncmp(argv[i + 1], "--", 2))
            output = argv[++i];
        else if (!strcmp(argv[i], "--root") && !root_seen && i + 1 < argc &&
                 argv[i + 1][0] && strncmp(argv[i + 1], "--", 2)) {
            root = argv[++i]; root_seen = 1;
        } else if (!strcmp(argv[i], "--extract") && !extract) extract = 1;
        else goto done;
    }
    if (!output || !*output || !*root) goto done;
    if (!catalog) {
        result = holy_source_catalog_path_fast(root, alias, &bound_catalog);
        if (result) goto done;
        catalog = bound_catalog;
    }
    result = holy_source_catalog(root, alias, catalog, source_id);
    if (!result) result = holy_repo_fetch_name(catalog, separator + 1, output, extract);
done:
    if (result == 2)
        fputs("usage: holypkg fetch SOURCE:PACKAGE [--catalog MIRROR] --output DIRECTORY [--extract] [--root DIRECTORY]\n", stderr);
    free(alias); free(bound_catalog);
    return result;
}

static void print_source_alias(const char *alias)
{
    const unsigned char *p = (const unsigned char *)alias;
    fputc('"', stdout);
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') fprintf(stdout, "\\%c", *p);
        else if (*p < 32 || *p >= 127) fprintf(stdout, "\\x%02x", *p);
        else fputc(*p, stdout);
    }
    fputc('"', stdout);
}

static int search_catalog(const char *catalog, const char *name,
                          int file_search, int fuzzy_search)
{
    if (file_search) return fuzzy_search ?
        holy_repo_search_file_fuzzy(catalog, name) :
        holy_repo_search_file(catalog, name);
    return fuzzy_search ? holy_repo_search_fuzzy(catalog, name) :
                          (holy_repo_search(catalog, name) ? 0 : 6);
}

static int query_source(int argc, char **argv, int search)
{
    const char *root = "/", *catalog = NULL, *alias = NULL, *name = NULL;
    const char *separator = search ? NULL : strchr(argv[2], ':');
    char source_id[65], *owned_alias = NULL, *bound_catalog = NULL;
    char **aliases = NULL;
    size_t alias_count = 0, j, unavailable = 0;
    int i, root_seen = 0, file_search = 0, fuzzy_search = 0, result = 2;
    if (search) name = argv[2];
    else {
        if (!separator || separator == argv[2] || !separator[1] ||
            strchr(separator + 1, ':')) goto done;
        owned_alias = malloc((size_t)(separator - argv[2]) + 1);
        if (!owned_alias) { result = 1; goto done; }
        memcpy(owned_alias, argv[2], (size_t)(separator - argv[2]));
        owned_alias[separator - argv[2]] = 0;
        alias = owned_alias;
        name = separator + 1;
    }
    for (i = 3; i < argc; ++i) {
        if (search && !strcmp(argv[i], "--file") && !file_search)
            file_search = 1;
        else if (search && !strcmp(argv[i], "--fuzzy") && !fuzzy_search)
            fuzzy_search = 1;
        else if (search && !strcmp(argv[i], "--source") && !alias && i + 1 < argc &&
            argv[i + 1][0] && strncmp(argv[i + 1], "--", 2)) alias = argv[++i];
        else if (!strcmp(argv[i], "--catalog") && !catalog && i + 1 < argc &&
                 argv[i + 1][0] && strncmp(argv[i + 1], "--", 2)) catalog = argv[++i];
        else if (!strcmp(argv[i], "--root") && !root_seen && i + 1 < argc &&
                 argv[i + 1][0] && strncmp(argv[i + 1], "--", 2)) {
            root = argv[++i]; root_seen = 1;
        } else goto done;
    }
    if (!name || !*name || (alias && (!*alias || !strcmp(alias, "local"))) ||
        (!alias && (!search || catalog))) goto done;
    if (!alias) {
        result = holy_source_active_aliases(root, &aliases, &alias_count);
        if (result) goto done;
        if (!alias_count) {
            fputs("holypkg: no active sources\n", stderr);
            result = 6; goto done;
        }
        for (j = 0; j < alias_count; ++j) {
            char *path = NULL;
            const char *current = aliases[j];
            int rc = holy_source_catalog_path_fast(root, current, &path);
            if (!rc) rc = holy_source_catalog(root, current, path, source_id);
            printf("source "); print_source_alias(current);
            if (rc) {
                fputs(" coverage unavailable\n", stdout);
                ++unavailable;
            } else {
                printf(" id %s\n", source_id);
                rc = search_catalog(path, name, file_search, fuzzy_search);
                if (rc) ++unavailable;
            }
            free(path);
            if (rc == 2) { result = 2; goto done; }
        }
        printf("searched %zu sources; unavailable %zu\n", alias_count, unavailable);
        result = unavailable ? 6 : ferror(stdout) ? 1 : 0;
        goto done;
    }
    if (!catalog) {
        result = holy_source_catalog_path_fast(root, alias, &bound_catalog);
        if (result) goto done;
        catalog = bound_catalog;
    }
    result = holy_source_catalog(root, alias, catalog, source_id);
    if (!result) {
        if (!search) result = holy_repo_info_name(catalog, name);
        else result = search_catalog(catalog, name, file_search, fuzzy_search);
        if (!result) printf("source-id %s\n", source_id);
    }
done:
    if (result == 2) fprintf(stderr,
        search ? "usage: holypkg search QUERY [--source SOURCE] [--file] [--fuzzy] [--catalog MIRROR] [--root DIRECTORY]\n" :
                 "usage: holypkg info SOURCE:PACKAGE [--catalog MIRROR] [--root DIRECTORY]\n");
    for (j = 0; j < alias_count; ++j) free(aliases[j]);
    free(aliases);
    free(owned_alias); free(bound_catalog);
    return result;
}

static int add_source(int argc, char **argv)
{
    const char *separator = strchr(argv[2], ':');
    const char *root = "/", *catalog = NULL, *choice = NULL;
    const char **accepted_arch = NULL, **accepted_privileged = NULL;
    struct holy_repo_set staged = {0}, next = {0};
    char source_id[65], next_id[65], plan[65], answer[16], *alias = NULL;
    char *bound_catalog = NULL, *next_catalog = NULL;
    size_t arch_count = 0, privileged_count = 0, i;
    int yes = 0, noninteractive = 0, root_seen = 0, result = 2;
    if (!separator || separator == argv[2] || !separator[1] ||
        strchr(separator + 1, ':')) goto done;
    alias = malloc((size_t)(separator - argv[2]) + 1);
    accepted_arch = calloc((size_t)argc, sizeof *accepted_arch);
    accepted_privileged = calloc((size_t)argc, sizeof *accepted_privileged);
    if (!alias || !accepted_arch || !accepted_privileged) { result = 1; goto done; }
    memcpy(alias, argv[2], (size_t)(separator - argv[2]));
    alias[separator - argv[2]] = 0;
    if (!strcmp(alias, "local")) goto done;
    for (i = 3; i < (size_t)argc; ++i) {
        if (!strcmp(argv[i], "--catalog") && !catalog && i + 1 < (size_t)argc &&
            argv[i + 1][0] && strncmp(argv[i + 1], "--", 2)) catalog = argv[++i];
        else if (!strcmp(argv[i], "--root") && !root_seen && i + 1 < (size_t)argc &&
                 argv[i + 1][0] && strncmp(argv[i + 1], "--", 2)) {
            root = argv[++i]; root_seen = 1;
        } else if (!strcmp(argv[i], "--choose") && !choice && i + 1 < (size_t)argc &&
                   argv[i + 1][0] && strncmp(argv[i + 1], "--", 2)) choice = argv[++i];
        else if (!strcmp(argv[i], "--accept-arch") && i + 1 < (size_t)argc &&
                 argv[i + 1][0] && strncmp(argv[i + 1], "--", 2))
            accepted_arch[arch_count++] = argv[++i];
        else if (!strcmp(argv[i], "--accept-privileged") && i + 1 < (size_t)argc &&
                 argv[i + 1][0] && strncmp(argv[i + 1], "--", 2))
            accepted_privileged[privileged_count++] = argv[++i];
        else if (!strcmp(argv[i], "--yes") && !yes) yes = 1;
        else if (!strcmp(argv[i], "--noninteractive") && !noninteractive) noninteractive = 1;
        else goto done;
    }
    if (!catalog) {
        result = holy_source_catalog_path(root, alias, &bound_catalog);
        if (result) goto done;
        catalog = bound_catalog;
    }
    result = holy_source_catalog(root, alias, catalog, source_id);
    if (result) goto done;
    result = holy_repo_stage_set(catalog, separator + 1, root, &staged);
    if (result) goto done;
    result = holy_state_set_source((const char *const *)staged.digests, staged.count,
                                   source_id, staged.index, choice, NULL, root,
                                   accepted_arch, arch_count,
                                   accepted_privileged, privileged_count, plan);
    if (result) goto done;
    if (!yes) {
        if (noninteractive || !isatty(STDIN_FILENO)) {
            fprintf(stderr, "holypkg: decision-required plan=%s; rerun with --yes after review\n", plan);
            result = 3; goto done;
        }
        if (fflush(stdout) || fprintf(stderr, "Apply plan %s to %s? [y/N] ", plan, root) < 0 ||
            fflush(stderr)) { result = 1; goto done; }
        if (!fgets(answer, sizeof answer, stdin) ||
            (strcmp(answer, "y\n") && strcmp(answer, "Y\n") &&
             strcmp(answer, "yes\n") && strcmp(answer, "YES\n"))) {
            result = 3; goto done;
        }
    }
    if (bound_catalog) {
        result = holy_source_catalog_path(root, alias, &next_catalog);
        if (result || strcmp(bound_catalog, next_catalog)) { result = 3; goto done; }
    }
    result = holy_source_catalog(root, alias, catalog, next_id);
    if (result) { result = 3; goto done; }
    result = holy_repo_stage_set(catalog, separator + 1, root, &next);
    if (result) { result = 3; goto done; }
    if (strcmp(source_id, next_id) || strcmp(staged.index, next.index) ||
        staged.count != next.count) { result = 3; goto done; }
    for (i = 0; i < staged.count; ++i)
        if (strcmp(staged.digests[i], next.digests[i])) { result = 3; goto done; }
    result = holy_state_set_source((const char *const *)staged.digests, staged.count,
                                   source_id, staged.index, choice, plan, root,
                                   accepted_arch, arch_count,
                                   accepted_privileged, privileged_count, NULL);
done:
    if (result == 2)
        fputs("usage: holypkg add SOURCE:PACKAGE [--catalog MIRROR] [--choose ID=SHA256] [--accept-arch SHA256 ...] [--accept-privileged SHA256 ...] [--root DIRECTORY] [--yes] [--noninteractive]\n", stderr);
    holy_repo_set_free(&staged); holy_repo_set_free(&next);
    free(alias); free(bound_catalog); free(next_catalog);
    free(accepted_arch); free(accepted_privileged);
    return result;
}

static int installed_ref(int argc, char **argv, int operation)
{
    const char *reference = argc > 2 ? argv[2] : NULL;
    const char *separator = reference ? strchr(reference, ':') : NULL;
    const char *root = "/", *arch = NULL, *libc = NULL;
    char source_id[65], digest[65], answer[16], *alias = NULL;
    int root_seen = 0, json = 0, yes = 0, accept_broken = 0;
    int remove_package = operation == 1, list_files = operation == 2;
    int result = 2, i;
    if (!remove_package && !list_files && (argc == 2 ||
        (argc > 2 && !strncmp(argv[2], "--", 2)))) {
        for (i = 2; i < argc; ++i) {
            if (!strcmp(argv[i], "--root") && !root_seen && i + 1 < argc)
                root = argv[++i], root_seen = 1;
            else if (!strcmp(argv[i], "--json") && !json) json = 1;
            else goto done;
        }
        return holy_state_check("--all", root, json);
    }
    if (!separator || separator == reference || !separator[1] ||
        strchr(separator + 1, ':') || !strncmp(reference, "local:", 6)) goto done;
    alias = malloc((size_t)(separator - reference) + 1);
    if (!alias) { result = 1; goto done; }
    memcpy(alias, reference, (size_t)(separator - reference));
    alias[separator - reference] = 0;
    for (i = 3; i < argc; ++i) {
        if (!strcmp(argv[i], "--root") && !root_seen && i + 1 < argc)
            root = argv[++i], root_seen = 1;
        else if (!strcmp(argv[i], "--arch") && !arch && i + 1 < argc)
            arch = argv[++i];
        else if (!strcmp(argv[i], "--libc") && !libc && i + 1 < argc)
            libc = argv[++i];
        else if (!remove_package && !list_files && !strcmp(argv[i], "--json") && !json) json = 1;
        else if (remove_package && !strcmp(argv[i], "--yes") && !yes) yes = 1;
        else if (remove_package && !strcmp(argv[i], "--accept-broken") && !accept_broken)
            accept_broken = 1;
        else goto done;
    }
    if (!*root || (arch && !*arch) || (libc && !*libc)) goto done;
    result = holy_source_known_id(root, alias, source_id);
    if (result) goto done;
    result = holy_state_find_slot(root, source_id, separator + 1, arch, libc, digest);
    if (result) goto done;
    if (list_files) { result = holy_state_files(digest, root); goto done; }
    if (!remove_package) { result = holy_state_check(digest, root, json); goto done; }
    if (!yes) {
        if (!isatty(STDIN_FILENO)) {
            fprintf(stderr, "holypkg: decision-required remove %s:%s artifact %s; use --yes after review\n",
                    alias, separator + 1, digest);
            result = 3; goto done;
        }
        fprintf(stderr, "Remove %s:%s artifact %s from %s? [y/N] ",
                alias, separator + 1, digest, root);
        if (fflush(stderr) || !fgets(answer, sizeof answer, stdin) ||
            (strcmp(answer, "y\n") && strcmp(answer, "Y\n") &&
             strcmp(answer, "yes\n") && strcmp(answer, "YES\n"))) {
            result = 3; goto done;
        }
    }
    result = holy_state_remove(digest, root, accept_broken);
done:
    if (result == 2)
        fprintf(stderr, "usage: holypkg %s %s [--root DIRECTORY] [--arch ARCH] [--libc LIBC] %s\n",
                remove_package ? "rm" : list_files ? "files" : "check",
                remove_package || list_files ? "SOURCE:PACKAGE" : "[SOURCE:PACKAGE]",
                remove_package ? "[--yes] [--accept-broken]" : list_files ? "" : "[--json]");
    free(alias);
    return result;
}

int main(int argc, char **argv)
{
    struct holy_config config = {0};
    char *error = NULL;
    const char *path;
    int ok;

    setlocale(LC_CTYPE, "");

    if (argc > 1 && !strcmp(argv[1], "add")) {
        if (argc > 2 && strncmp(argv[2], "local:", 6))
            return add_source(argc, argv);
        return add_local(argc, argv);
    }
    if (argc > 1 && !strcmp(argv[1], "up")) return holy_up_command(argc, argv);
    if (argc > 1 && !strcmp(argv[1], "run")) return holy_run(argc, argv);
    if (argc > 1 && !strcmp(argv[1], "apply")) return holy_apply_command(argc, argv);
    if (argc > 1 && !strcmp(argv[1], "search") && argc > 2)
        return query_source(argc, argv, 1);
    if (argc > 2 && !strcmp(argv[1], "info") &&
        strncmp(argv[2], "local:", 6))
        return query_source(argc, argv, 0);

    if (argc > 1 && !strcmp(argv[1], "import")) {
        if (argc == 9 && !strcmp(argv[3], "--source") && !strcmp(argv[5], "--format") &&
            !strcmp(argv[7], "--output")) {
            if (!strcmp(argv[6], "pacman")) return holy_import_pacman(argv[2], argv[4], argv[8]);
            if (!strcmp(argv[6], "deb")) return holy_import_deb(argv[2], argv[4], argv[8]);
        }
        fputs("usage: holypkg import INPUT --source NAME --format pacman|deb --output DIRECTORY\n", stderr);
        return 2;
    }

    if (argc > 1 && !strcmp(argv[1], "source")) {
        if (argc == 6 && !strcmp(argv[2], "catalog") &&
            !strcmp(argv[3], "bind"))
            return holy_source_bind_catalog("/", argv[4], argv[5]);
        if (argc == 8 && !strcmp(argv[2], "catalog") &&
            !strcmp(argv[3], "bind") && !strcmp(argv[6], "--root"))
            return holy_source_bind_catalog(argv[7], argv[4], argv[5]);
        if (argc == 7 && !strcmp(argv[2], "plan") && !strcmp(argv[3], "--config") && !strcmp(argv[5], "--root"))
            return holy_source_plan(argv[4], argv[6]);
        if (argc == 8 && !strcmp(argv[2], "apply") && !strcmp(argv[4], "--sha256") && !strcmp(argv[6], "--root"))
            return holy_source_apply(argv[3], argv[5], argv[7]);
        if (argc == 5 && !strcmp(argv[2], "list") && !strcmp(argv[3], "--root"))
            return holy_source_list(argv[4]);
        fputs("usage: holypkg source plan --config FILE --root DIRECTORY | source apply PLAN --sha256 HASH --root DIRECTORY | source list --root DIRECTORY | source catalog bind ALIAS MIRROR [--root DIRECTORY]\n", stderr);
        return 2;
    }

    if (argc > 1 && !strcmp(argv[1], "sync")) {
        const char *root = "/", *digest = NULL, *accepted = NULL;
        const char *output = NULL, *ca_file = NULL, *commit = NULL;
        int i, root_seen = 0, valid = argc >= 3;
        for (i = 3; valid && i < argc; i += 2) {
            if (i + 1 >= argc) { valid = 0; break; }
            if (!strcmp(argv[i], "--root") && !root_seen) {
                root = argv[i + 1]; root_seen = 1;
            }
            else if (!strcmp(argv[i], "--sha256") && !digest) digest = argv[i + 1];
            else if (!strcmp(argv[i], "--accept-unsigned") && !accepted) accepted = argv[i + 1];
            else if (!strcmp(argv[i], "--output") && !output) output = argv[i + 1];
            else if (!strcmp(argv[i], "--ca-file") && !ca_file) ca_file = argv[i + 1];
            else if (!strcmp(argv[i], "--commit") && !commit) commit = argv[i + 1];
            else valid = 0;
        }
        if (valid && !(digest && accepted))
            return holy_source_sync(argv[2], root, digest, accepted, output, ca_file, commit);
        fputs("usage: holypkg sync SOURCE [--root DIRECTORY] [--output NEW_DIRECTORY] [--sha256 INDEX_SHA256 | --accept-unsigned INDEX_SHA256] [--commit GIT_COMMIT] [--ca-file FILE]\n", stderr);
        return 2;
    }

    if (argc > 1 && !strcmp(argv[1], "orphan")) {
        const char *root = "/";
        int i, json = 0, root_seen = 0;
        for (i = 2; i < argc; ++i) {
            if (!strcmp(argv[i], "--json") && !json) json = 1;
            else if (!strcmp(argv[i], "--root") && !root_seen && i + 1 < argc) {
                root = argv[++i]; root_seen = 1;
            } else { fputs("usage: holypkg orphan [--root DIRECTORY] [--json]\n", stderr); return 2; }
        }
        return holy_orphan(root, json);
    }

    if (argc > 1 && !strcmp(argv[1], "docs")) {
        if (argc == 6 && !strcmp(argv[2], "--root") && !strcmp(argv[4], "--output"))
            return holy_docs(argv[3], argv[5]);
        fputs("usage: holypkg docs --root DIRECTORY --output FILE\n", stderr);
        return 2;
    }

    if (argc == 3 && !strcmp(argv[1], "elf")) {
        struct holy_elf_info info;
        int rc = holy_elf_read(argv[2], &info);
        if (!rc)
            printf("class ELF%d\ne_machine %u\ne_type %u\nmachine %s\nisa %s\nruntime %s\ninterpreter %s\n",
                   info.elf_class == 1 ? 32 : 64,
                   (unsigned int)info.machine, (unsigned int)info.type,
                   holy_elf_machine(&info), holy_elf_isa(&info),
                   holy_elf_runtime(&info),
                   info.interpreter ? info.interpreter : "unknown");
        if (!rc) {
            size_t i;
            for (i = 0; i < info.needed_count; ++i) printf("needed %s\n", info.needed[i]);
            if (info.soname) printf("soname %s\n", info.soname);
            if (info.rpath) printf("rpath %s\n", info.rpath);
            if (info.runpath) printf("runpath %s\n", info.runpath);
            for (i = 0; i < info.version_count; ++i)
                printf("version %s %s%s\n", info.versions[i].provider,
                       info.versions[i].name, info.versions[i].weak ? " weak" : "");
            for (i = 0; i < info.defined_version_count; ++i)
                printf("version-def %s\n", info.defined_versions[i].name);
            if (info.has_dynamic) printf("flags1 0x%llx\n", (unsigned long long)info.flags1);
            for (i = 0; i < info.symbol_count; ++i) {
                const struct holy_elf_symbol *s = &info.symbols[i];
                if (!s->name[0]) continue;
                printf("symbol %s binding=%u type=%u visibility=%u section=%u version-index=%u hidden=%d version=%s provider=%s\n",
                    s->name, s->binding, s->type, s->visibility,
                    (unsigned)s->section, (unsigned)s->version_index,
                    s->version_hidden, s->version ? s->version : "none",
                    s->provider ? s->provider : "none");
            }
        }
        else fprintf(stderr, "holypkg: %s ELF input\n", rc == 1 ? "not an" : "invalid");
        holy_elf_free(&info);
        return rc ? 2 : 0;
    }
    if (argc == 3 && !strcmp(argv[1], "scan") &&
        !strncmp(argv[2], "local:", 6) && argv[2][6])
        return holy_scan_local(argv[2] + 6) ? 0 : 2;
    if (argc == 5 && !strcmp(argv[1], "pack") &&
        !strcmp(argv[3], "--output"))
        return holy_pack(argv[2], argv[4]) ? 0 : 1;
    if (argc == 6 && !strcmp(argv[1], "manifest") &&
        !strcmp(argv[2], "generate") && !strcmp(argv[4], "--output"))
        return holy_generate_files(argv[3], argv[5]) ? 0 : 1;
    if (argc == 3 && !strcmp(argv[1], "manifest") &&
        !strncmp(argv[2], "local:", 6) && argv[2][6])
        return holy_manifest_local(argv[2] + 6) ? 0 : 2;
    if (argc == 3 && !strcmp(argv[1], "requirements") &&
        !strncmp(argv[2], "local:", 6) && argv[2][6])
        return holy_deps_local(argv[2] + 6) ? 0 : 2;
    if (argc == 3 && !strcmp(argv[1], "provides") &&
        !strncmp(argv[2], "local:", 6) && argv[2][6])
        return holy_provides_local(argv[2] + 6, 1) ? 0 : 2;
    if (argc == 4 && !strcmp(argv[1], "provides") &&
        !strncmp(argv[2], "local:", 6) && argv[2][6] &&
        !strcmp(argv[3], "--json"))
        return holy_provides_local(argv[2] + 6, 2) ? 0 : 2;
    if (argc == 4 && !strcmp(argv[1], "requirements") &&
        !strncmp(argv[2], "local:", 6) && argv[2][6] &&
        !strcmp(argv[3], "--json"))
        return holy_deps_local_with_output(argv[2] + 6, 2) ? 0 : 2;
    if (argc >= 3 && !strcmp(argv[1], "solve")) {
        int json = !strcmp(argv[argc - 1], "--json");
        int last = argc - json;
        const char *choice = NULL;
        const char **paths;
        int i, result;
        if (last >= 5 && !strcmp(argv[last - 2], "--choose")) {
            choice = argv[last - 1];
            last -= 2;
        }
        if (last < 3) {
            fprintf(stderr, "holypkg: solve requires local:FILE inputs\n");
            if (json) puts("{\"schema\":\"holy-local-solve-1\",\"type\":\"error\",\"code\":\"invalid-query\"}");
            return 2;
        }
        paths = calloc((size_t)last - 2, sizeof *paths);
        if (!paths) {
            if (json) puts("{\"schema\":\"holy-local-solve-1\",\"type\":\"error\",\"code\":\"operational-error\"}");
            return 1;
        }
        for (i = 2; i < last; ++i) {
            if (strncmp(argv[i], "local:", 6) || !argv[i][6]) {
                free(paths);
                fprintf(stderr, "holypkg: solve requires local:FILE inputs\n");
                if (json) puts("{\"schema\":\"holy-local-solve-1\",\"type\":\"error\",\"code\":\"invalid-query\"}");
                return 2;
            }
            paths[i - 2] = argv[i] + 6;
        }
        result = holy_resolve_local(paths, (size_t)last - 2, json, NULL, choice);
        free(paths);
        return result;
    }
    if (argc > 2 && !strcmp(argv[1], "repo") && !strcmp(argv[2], "mirror")) {
        if ((argc == 10 || argc == 12) && !strcmp(argv[4], "--sha256") &&
            !strcmp(argv[6], "--output") && !strcmp(argv[8], "--public-key") &&
            (argc == 10 || !strcmp(argv[10], "--ca-file")))
            return holy_repo_mirror_signed(argv[3], argv[5], argv[7],
                                           argc == 12 ? argv[11] : NULL, argv[9]);
        if ((argc == 8 || argc == 10) && !strcmp(argv[4], "--sha256") &&
            !strcmp(argv[6], "--output") && (argc == 8 || !strcmp(argv[8], "--ca-file")))
            return holy_repo_mirror(argv[3], argv[5], argv[7], argc == 10 ? argv[9] : NULL);
        fputs("usage: holypkg repo mirror HTTPS_BASE/ --sha256 INDEX_SHA256 --output NEW_DIRECTORY [--public-key PEM] [--ca-file FILE]\n", stderr);
        return 2;
    }
    if (argc == 4 && !strcmp(argv[1], "repo") &&
        !strcmp(argv[2], "index"))
        return holy_repo_index(argv[3]) ? 0 : 1;
    if (argc == 4 && !strcmp(argv[1], "repo") &&
        !strcmp(argv[2], "list"))
        return holy_repo_list(argv[3]) ? 0 : 1;
    if (argc == 5 && !strcmp(argv[1], "repo") &&
        !strcmp(argv[2], "requirements"))
        return holy_repo_requirements(argv[3], argv[4]);
    if (argc == 5 && !strcmp(argv[1], "repo") &&
        !strcmp(argv[2], "search"))
        return holy_repo_search(argv[3], argv[4]) ? 0 : 1;
    if (argc == 5 && !strcmp(argv[1], "repo") &&
        !strcmp(argv[2], "search-file"))
        return holy_repo_search_file(argv[3], argv[4]);
    if (argc == 6 && !strcmp(argv[1], "repo") &&
        !strcmp(argv[2], "search") && !strcmp(argv[5], "--fuzzy"))
        return holy_repo_search_fuzzy(argv[3], argv[4]);
    if (argc == 6 && !strcmp(argv[1], "repo") &&
        !strcmp(argv[2], "search-file") && !strcmp(argv[5], "--fuzzy"))
        return holy_repo_search_file_fuzzy(argv[3], argv[4]);
    if (argc == 5 && !strcmp(argv[1], "repo") &&
        !strcmp(argv[2], "solve"))
        return holy_repo_solve(argv[3], argv[4], NULL, 0);
    if (argc == 6 && !strcmp(argv[1], "repo") &&
        !strcmp(argv[2], "solve") && !strcmp(argv[5], "--json"))
        return holy_repo_solve(argv[3], argv[4], NULL, 1);
    if (argc == 7 && !strcmp(argv[1], "repo") &&
        !strcmp(argv[2], "solve") && !strcmp(argv[5], "--choose"))
        return holy_repo_solve(argv[3], argv[4], argv[6], 0);
    if (argc == 8 && !strcmp(argv[1], "repo") &&
        !strcmp(argv[2], "solve") && !strcmp(argv[5], "--choose") &&
        !strcmp(argv[7], "--json"))
        return holy_repo_solve(argv[3], argv[4], argv[6], 1);
    if (argc == 6 && !strcmp(argv[1], "repo") &&
        !strcmp(argv[2], "providers"))
        return holy_repo_providers(argv[3], argv[4], argv[5], 0) ? 0 : 1;
    if (argc == 7 && !strcmp(argv[1], "repo") &&
        !strcmp(argv[2], "providers") && !strcmp(argv[6], "--json"))
        return holy_repo_providers(argv[3], argv[4], argv[5], 1) ? 0 : 1;
    if (argc == 4 && !strcmp(argv[1], "repo") &&
        !strcmp(argv[2], "seal"))
        return holy_repo_seal(argv[3]) ? 0 : 1;
    if (argc == 6 && !strcmp(argv[1], "repo") &&
        !strcmp(argv[2], "seal") && !strcmp(argv[4], "--key"))
        return holy_repo_seal_signed(argv[3], argv[5]) ? 0 : 1;
    if (argc == 6 && !strcmp(argv[1], "repo") &&
        !strcmp(argv[2], "verify") && !strcmp(argv[4], "--key"))
        return holy_repo_verify_signature(argv[3], argv[5]);
    if (argc == 7 && !strcmp(argv[1], "repo") &&
        !strcmp(argv[2], "fetch") && !strcmp(argv[5], "--output"))
        return holy_repo_fetch(argv[3], argv[4], argv[6]) ? 0 : 1;
    if (argc == 6 && !strcmp(argv[1], "cache") &&
        !strcmp(argv[2], "stage") &&
        !strncmp(argv[3], "local:", 6) && argv[3][6] &&
        !strcmp(argv[4], "--root"))
        return holy_cache_stage_local(argv[3] + 6, argv[5]) ? 0 : 1;
    if (argc == 6 && !strcmp(argv[1], "cache") &&
        !strcmp(argv[2], "verify") && !strcmp(argv[4], "--root"))
        return holy_cache_verify(argv[3], argv[5]) ? 0 : 1;
    if (argc == 7 && !strcmp(argv[1], "db") && !strcmp(argv[2], "plan-update") &&
        !strcmp(argv[5], "--root")) return holy_state_update_plan(argv[3], argv[4], NULL, NULL, argv[6]);
    if (argc == 9 && !strcmp(argv[1], "db") && !strcmp(argv[2], "plan-update") &&
        !strcmp(argv[5], "--accept-privileged") && !strcmp(argv[7], "--root"))
        return holy_state_update_plan(argv[3], argv[4], NULL, argv[6], argv[8]);
    if (argc == 9 && !strcmp(argv[1], "db") && !strcmp(argv[2], "plan-update") &&
        !strcmp(argv[5], "--accept-arch") && !strcmp(argv[7], "--root"))
        return holy_state_update_plan(argv[3], argv[4], argv[6], NULL, argv[8]);
    if (argc == 11 && !strcmp(argv[1], "db") && !strcmp(argv[2], "plan-update") &&
        !strcmp(argv[5], "--accept-arch") && !strcmp(argv[7], "--accept-privileged") &&
        !strcmp(argv[9], "--root"))
        return holy_state_update_plan(argv[3], argv[4], argv[6], argv[8], argv[10]);
    if (argc == 11 && !strcmp(argv[1], "db") && !strcmp(argv[2], "plan-update") &&
        !strcmp(argv[5], "--accept-privileged") && !strcmp(argv[7], "--accept-arch") &&
        !strcmp(argv[9], "--root"))
        return holy_state_update_plan(argv[3], argv[4], argv[8], argv[6], argv[10]);
    if (argc == 8 && !strcmp(argv[1], "db") && !strcmp(argv[2], "apply-update") &&
        !strcmp(argv[6], "--root")) return holy_state_apply_update(argv[3], argv[4], argv[5], NULL, NULL, argv[7]);
    if (argc == 10 && !strcmp(argv[1], "db") && !strcmp(argv[2], "apply-update") &&
        !strcmp(argv[6], "--accept-privileged") && !strcmp(argv[8], "--root"))
        return holy_state_apply_update(argv[3], argv[4], argv[5], NULL, argv[7], argv[9]);
    if (argc == 10 && !strcmp(argv[1], "db") && !strcmp(argv[2], "apply-update") &&
        !strcmp(argv[6], "--accept-arch") && !strcmp(argv[8], "--root"))
        return holy_state_apply_update(argv[3], argv[4], argv[5], argv[7], NULL, argv[9]);
    if (argc == 12 && !strcmp(argv[1], "db") && !strcmp(argv[2], "apply-update") &&
        !strcmp(argv[6], "--accept-arch") && !strcmp(argv[8], "--accept-privileged") &&
        !strcmp(argv[10], "--root"))
        return holy_state_apply_update(argv[3], argv[4], argv[5], argv[7], argv[9], argv[11]);
    if (argc == 12 && !strcmp(argv[1], "db") && !strcmp(argv[2], "apply-update") &&
        !strcmp(argv[6], "--accept-privileged") && !strcmp(argv[8], "--accept-arch") &&
        !strcmp(argv[10], "--root"))
        return holy_state_apply_update(argv[3], argv[4], argv[5], argv[9], argv[7], argv[11]);
    if (argc == 6 && !strcmp(argv[1], "db") && !strcmp(argv[2], "recover") &&
        !strcmp(argv[3], "--update") && !strcmp(argv[4], "--root")) return holy_state_recover_update(argv[5]);
    if (argc == 6 && !strcmp(argv[1], "db") && !strcmp(argv[2], "repair-plan") &&
        !strcmp(argv[4], "--root")) return holy_state_repair(argv[3], NULL, argv[5]);
    if (argc == 8 && !strcmp(argv[1], "db") && !strcmp(argv[2], "repair") &&
        !strcmp(argv[4], "--plan") && !strcmp(argv[6], "--root"))
        return holy_state_repair(argv[3], argv[5], argv[7]);
    if (argc == 6 && !strcmp(argv[1], "db") && !strcmp(argv[2], "recover") &&
        !strcmp(argv[3], "--repair") && !strcmp(argv[4], "--root"))
        return holy_state_repair(NULL, NULL, argv[5]);
    if (argc >= 6 && !strcmp(argv[1], "db") &&
        (!strcmp(argv[2], "plan-set") || !strcmp(argv[2], "apply-set"))) {
        int start = !strcmp(argv[2], "apply-set") ? 4 : 3;
        int end = argc - 2;
        const char *choice = NULL;
        const char **digests, **bindings, **accepted_arch, **accepted_privileged;
        size_t count = 0, binding_count = 0, accepted_count = 0, privileged_count = 0;
        int i, result = 2;
        if (strcmp(argv[argc - 2], "--root")) return 2;
        digests = calloc((size_t)argc, sizeof *digests);
        bindings = calloc((size_t)argc, sizeof *bindings);
        accepted_arch = calloc((size_t)argc, sizeof *accepted_arch);
        accepted_privileged = calloc((size_t)argc, sizeof *accepted_privileged);
        if (!digests || !bindings || !accepted_arch || !accepted_privileged) {
            free(digests); free(bindings); free(accepted_arch); free(accepted_privileged); return 1;
        }
        for (i = start; i < end; ++i) {
            if (!strcmp(argv[i], "--choose")) {
                if (choice || ++i >= end) goto set_done;
                choice = argv[i];
            } else if (!strcmp(argv[i], "--source")) {
                if (++i >= end) goto set_done;
                bindings[binding_count++] = argv[i];
            } else if (!strcmp(argv[i], "--accept-arch")) {
                if (++i >= end) goto set_done;
                accepted_arch[accepted_count++] = argv[i];
            } else if (!strcmp(argv[i], "--accept-privileged")) {
                if (++i >= end) goto set_done;
                accepted_privileged[privileged_count++] = argv[i];
            } else if (argv[i][0] == '-') goto set_done;
            else digests[count++] = argv[i];
        }
        if (count) result = holy_state_set(digests, count, choice,
                                          start == 4 ? argv[3] : NULL, argv[argc - 1],
                                          bindings, binding_count, accepted_arch, accepted_count,
                                          accepted_privileged, privileged_count, NULL);
set_done:
        free(digests); free(bindings); free(accepted_arch); free(accepted_privileged);
        return result;
    }
    if (argc == 6 && !strcmp(argv[1], "db") &&
        !strcmp(argv[2], "recover") && !strcmp(argv[3], "--finish-set") &&
        !strcmp(argv[4], "--root")) return holy_state_finish_set(argv[5]);
    if (argc == 6 && !strcmp(argv[1], "db") &&
        !strcmp(argv[2], "recover") && !strcmp(argv[3], "--continue-set") &&
        !strcmp(argv[4], "--root")) return holy_state_continue_set(argv[5]);
    if (argc == 5 && !strcmp(argv[1], "db") && !strcmp(argv[3], "--root")) {
        if (!strcmp(argv[2], "init")) return holy_state_init(argv[4]) ? 0 : 1;
        if (!strcmp(argv[2], "status")) return holy_state_status(argv[4], 0);
        if (!strcmp(argv[2], "cancel")) return holy_state_cancel(argv[4]);
        if (!strcmp(argv[2], "recover")) return holy_state_recover(argv[4]);
        if (!strcmp(argv[2], "preflight")) return holy_state_preflight(argv[4], 0);
        if (!strcmp(argv[2], "plan")) return holy_state_plan(argv[4]);
        if (!strcmp(argv[2], "recheck")) return holy_state_recheck(argv[4]);
        if (!strcmp(argv[2], "apply")) return holy_state_apply(argv[4]);
    }
    if (argc == 6 && !strcmp(argv[1], "db") &&
        !strcmp(argv[2], "recover") && !strcmp(argv[3], "--abort-empty") &&
        !strcmp(argv[4], "--root"))
        return holy_state_abort_empty(argv[5]);
    if (argc == 6 && !strcmp(argv[1], "db") &&
        !strcmp(argv[2], "recover") && !strcmp(argv[3], "--continue") &&
        !strcmp(argv[4], "--root"))
        return holy_state_continue_remove(argv[5]);
    if (argc == 6 && !strcmp(argv[1], "db") &&
        !strcmp(argv[2], "recover") && !strcmp(argv[3], "--finish-apply") &&
        !strcmp(argv[4], "--root"))
        return holy_state_finish_apply(argv[5]);
    if (argc == 6 && !strcmp(argv[1], "db") &&
        !strcmp(argv[2], "status") && !strcmp(argv[3], "--root") &&
        !strcmp(argv[5], "--json"))
        return holy_state_status(argv[4], 1);
    if (argc == 6 && !strcmp(argv[1], "db") &&
        !strcmp(argv[2], "preflight") && !strcmp(argv[3], "--root") &&
        !strcmp(argv[5], "--json"))
        return holy_state_preflight(argv[4], 1);
    if (argc == 6 && !strcmp(argv[1], "db") &&
        !strcmp(argv[2], "reserve") && !strcmp(argv[4], "--root"))
        return holy_state_reserve(argv[3], argv[5]);
    if (argc == 6 && !strcmp(argv[1], "db") &&
        !strcmp(argv[2], "approve") && !strcmp(argv[4], "--root"))
        return holy_state_approve(argv[3], argv[5]);
    if (argc == 6 && !strcmp(argv[1], "db") &&
        !strcmp(argv[2], "check") && !strcmp(argv[4], "--root"))
        return holy_state_check(argv[3], argv[5], 0);
    if (argc == 7 && !strcmp(argv[1], "db") &&
        !strcmp(argv[2], "check") && !strcmp(argv[4], "--root") &&
        !strcmp(argv[6], "--json"))
        return holy_state_check(argv[3], argv[5], 1);
    if (argc == 6 && !strcmp(argv[1], "db") &&
        !strcmp(argv[2], "rm") && !strcmp(argv[4], "--root"))
        return holy_state_remove(argv[3], argv[5], 0);
    if (argc == 7 && !strcmp(argv[1], "db") &&
        !strcmp(argv[2], "rm") && !strcmp(argv[4], "--accept-broken") &&
        !strcmp(argv[5], "--root"))
        return holy_state_remove(argv[3], argv[6], 1);
    if (argc == 6 && !strcmp(argv[1], "db") &&
        !strcmp(argv[2], "owner") && !strcmp(argv[4], "--root"))
        return holy_state_owner(argv[3], argv[5]);

    if (argc > 1 && !strcmp(argv[1], "rm"))
        return installed_ref(argc, argv, 1);
    if (argc > 1 && !strcmp(argv[1], "files"))
        return installed_ref(argc, argv, 2);
    if (argc > 1 && !strcmp(argv[1], "check") &&
        (argc == 2 || (argc > 2 && strncmp(argv[2], "local:", 6))))
        return installed_ref(argc, argv, 0);

    if (argc == 3 && !strcmp(argv[1], "info") &&
        !strncmp(argv[2], "local:", 6) && argv[2][6])
        return holy_package_info(argv[2] + 6) ? 0 : 2;
    if (argc == 3 && !strcmp(argv[1], "verify") &&
        !strncmp(argv[2], "local:", 6) && argv[2][6])
        return holy_verify(argv[2] + 6) ? 0 : 2;
    if (argc >= 3 && !strcmp(argv[1], "fetch") &&
        strncmp(argv[2], "local:", 6) && strchr(argv[2], ':') &&
        !strstr(argv[2], "://")) return fetch_source(argc, argv);
    if ((argc == 7 || argc == 9) && !strcmp(argv[1], "fetch") &&
        !strcmp(argv[3], "--sha256") && !strcmp(argv[5], "--output") &&
        (argc == 7 || !strcmp(argv[7], "--ca-file")))
        return holy_fetch_https(argv[2], argv[4], argv[6],
                                argc == 9 ? argv[8] : NULL, 1);
    if (argc == 5 && !strcmp(argv[1], "fetch") &&
        !strncmp(argv[2], "local:", 6) && argv[2][6] &&
        !strcmp(argv[3], "--output"))
        return holy_fetch_local(argv[2] + 6, argv[4]) ? 0 : 1;
    if (argc == 6 && !strcmp(argv[1], "fetch") &&
        !strncmp(argv[2], "local:", 6) && argv[2][6] &&
        !strcmp(argv[3], "--extract") && !strcmp(argv[4], "--output"))
        return holy_extract_local(argv[2] + 6, argv[5]) ? 0 : 1;
    if (argc == 5 && !strcmp(argv[1], "check") &&
        !strncmp(argv[2], "local:", 6) && argv[2][6] &&
        !strcmp(argv[3], "--root"))
        return holy_check_local(argv[2] + 6, argv[4], 0);
    if (argc == 5 && !strcmp(argv[1], "preview") &&
        !strncmp(argv[2], "local:", 6) && argv[2][6] &&
        !strcmp(argv[3], "--root"))
        return holy_preview_local(argv[2] + 6, argv[4]);
    if (argc == 6 && !strcmp(argv[1], "preview") &&
        !strncmp(argv[2], "local:", 6) && argv[2][6] &&
        !strcmp(argv[3], "--root") && !strcmp(argv[5], "--json"))
        return holy_preview_local_format(argv[2] + 6, argv[4], 1);
    if (argc == 6 && !strcmp(argv[1], "check") &&
        !strncmp(argv[2], "local:", 6) && argv[2][6] &&
        !strcmp(argv[3], "--root") && !strcmp(argv[5], "--json"))
        return holy_check_local(argv[2] + 6, argv[4], 1);
    if (argc > 1 && !strcmp(argv[1], "fetch")) {
        fputs("usage: holypkg fetch SOURCE:PACKAGE --catalog MIRROR --output DIRECTORY [--extract] [--root DIRECTORY] | holypkg fetch local:FILE [--extract] --output DIRECTORY | holypkg fetch https://URL --sha256 SHA256 --output DIRECTORY [--ca-file FILE]\n", stderr);
        return 2;
    }
    if (argc != 4 || strcmp(argv[1], "config") || strcmp(argv[2], "check")) {
        fprintf(stderr, "usage: holypkg check [SOURCE:PACKAGE] [--root DIRECTORY] [--json] | holypkg files SOURCE:PACKAGE [--root DIRECTORY] | holypkg rm SOURCE:PACKAGE [--root DIRECTORY] [--yes] [--accept-broken] | holypkg run SOURCE:PACKAGE [--root DIRECTORY] [--arch ARCH] [--libc LIBC] -- COMMAND [ARGS...] | holypkg add local:FILE [--candidate local:FILE...] [--choose ID=SHA256] [--root DIRECTORY] [--yes] [--noninteractive] | holypkg config check FILE | holypkg info|verify|manifest|scan local:FILE | holypkg manifest generate DIRECTORY --output FILE | holypkg requirements|provides local:FILE [--json] | holypkg solve local:ROOT [local:CANDIDATE...] [--choose REQUIREMENT_ID=SHA256] [--json] | holypkg fetch local:FILE [--extract] --output DIRECTORY | holypkg fetch https://URL --sha256 SHA256 --output DIRECTORY [--ca-file FILE] | holypkg pack DIRECTORY --output FILE.holy | holypkg check|preview local:FILE --root DIRECTORY [--json] | holypkg cache stage local:FILE --root DIRECTORY | holypkg cache verify SHA256 --root DIRECTORY | holypkg db init|status|cancel|recover|preflight|plan|recheck|apply --root DIRECTORY | holypkg db recover --abort-empty|--continue|--finish-apply --root DIRECTORY | holypkg db check SHA256|--all --root DIRECTORY [--json] | holypkg db rm SHA256 [--accept-broken] --root DIRECTORY | holypkg db owner PATH --root DIRECTORY | holypkg db status|preflight --root DIRECTORY --json | holypkg db reserve SHA256 --root DIRECTORY | holypkg db plan-set ROOT_SHA256 [CANDIDATE_SHA256...] [--choose ID=SHA256] [--source ARTIFACT=SOURCE_ID...] [--accept-arch SHA256...] [--accept-privileged SHA256...] --root DIRECTORY | holypkg db apply-set PLAN_SHA256 ROOT_SHA256 [CANDIDATE_SHA256...] [--choose ID=SHA256] [--source ARTIFACT=SOURCE_ID...] [--accept-arch SHA256...] [--accept-privileged SHA256...] --root DIRECTORY | holypkg db recover --finish-set|--continue-set|--repair --root DIRECTORY | holypkg db plan-update OLD_SHA256 NEW_SHA256 [--accept-arch NEW_SHA256] [--accept-privileged NEW_SHA256] --root DIRECTORY | holypkg db apply-update PLAN_SHA256 OLD_SHA256 NEW_SHA256 [--accept-arch NEW_SHA256] [--accept-privileged NEW_SHA256] --root DIRECTORY | holypkg db recover --update --root DIRECTORY | holypkg db repair-plan SHA256 --root DIRECTORY | holypkg db repair SHA256 --plan PLAN_SHA256 --root DIRECTORY | holypkg db approve PLAN_SHA256 --root DIRECTORY | holypkg elf FILE | holypkg repo index|list|seal DIRECTORY | holypkg repo requirements DIRECTORY NAME | holypkg repo search DIRECTORY NAME [--fuzzy] | holypkg repo search-file DIRECTORY NAME_OR_PATH [--fuzzy] | holypkg repo solve DIRECTORY NAME [--choose REQUIREMENT_ID=SHA256] [--json] | holypkg repo providers DIRECTORY KIND NAME [--json] | holypkg repo fetch DIRECTORY SHA256 --output DIRECTORY\n");
        return 2;
    }
    path = argv[3];
    ok = holy_config_load(path, &config, &error);
    if (!ok) {
        fprintf(stderr, "holypkg: %s\n", error ? error : "out of memory");
        free(error);
        holy_config_free(&config);
        return 2;
    }
    printf("%s: %zu entries\n", path, config.count);
    holy_config_free(&config);
    return 0;
}
