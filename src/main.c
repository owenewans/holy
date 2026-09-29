#define _XOPEN_SOURCE 700
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
#include "stage.h"
#include "import.h"
#include "appimage.h"
#include "up.h"
#include "run.h"
#include "../backends/apk.h"
#include "../backends/xbps.h"
#include "../backends/apt.h"
#include "../backends/apt-release.h"
#include "../backends/rpm-md.h"
#include "../backends/aports.h"
#include "../backends/pkgbuild.h"
#include "../backends/rpmspec.h"
#include "../backends/slackbuild.h"
#include "../backends/voidsrc.h"
#include "recipe.h"

#include <stdio.h>
#include <limits.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int add_local(int argc, char **argv)
{
    const char **inputs = NULL, **digests = NULL;
    const char **accepted_arch = NULL, **accepted_privileged = NULL, **skipped_hooks = NULL;
    const char **associations = NULL, **bindings = NULL;
    char (*hashes)[65] = NULL;
    const char *root = "/", *choice = NULL, *association = NULL;
    char (*binding_storage)[130] = NULL;
    char plan[65], answer[16], source_id[65];
    size_t count = 0, arch_count = 0, privileged_count = 0, skipped_count = 0;
    size_t association_count = 0, binding_count = 0, i, j;
    int yes = 0, noninteractive = 0, root_seen = 0, result = 2;
    if (argc < 3 || strncmp(argv[2], "local:", 6) || !argv[2][6]) goto done;
    inputs = calloc((size_t)argc, sizeof *inputs);
    digests = calloc((size_t)argc, sizeof *digests);
    accepted_arch = calloc((size_t)argc, sizeof *accepted_arch);
    accepted_privileged = calloc((size_t)argc, sizeof *accepted_privileged);
    skipped_hooks = calloc((size_t)argc, sizeof *skipped_hooks);
    associations = calloc((size_t)argc, sizeof *associations);
    bindings = calloc((size_t)argc, sizeof *bindings);
    binding_storage = calloc((size_t)argc, sizeof *binding_storage);
    hashes = calloc((size_t)argc, sizeof *hashes);
    if (!inputs || !digests || !accepted_arch || !accepted_privileged || !skipped_hooks ||
        !associations || !bindings || !binding_storage || !hashes) {
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
        } else if (!strcmp(argv[i], "--associate") && i + 1 < (size_t)argc &&
                   argv[i + 1][0] && strncmp(argv[i + 1], "--", 2)) {
            associations[association_count++] = argv[++i];
        } else if (!strcmp(argv[i], "--accept-arch") && i + 1 < (size_t)argc &&
                   argv[i + 1][0] && strncmp(argv[i + 1], "--", 2)) {
            accepted_arch[arch_count++] = argv[++i];
        } else if (!strcmp(argv[i], "--accept-privileged") && i + 1 < (size_t)argc &&
                   argv[i + 1][0] && strncmp(argv[i + 1], "--", 2)) {
            accepted_privileged[privileged_count++] = argv[++i];
        } else if (!strcmp(argv[i], "--skip-hooks") && i + 1 < (size_t)argc &&
                   argv[i + 1][0] && strncmp(argv[i + 1], "--", 2)) {
            skipped_hooks[skipped_count++] = argv[++i];
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
        snprintf(binding_storage[binding_count], 130, "%s=%s", hashes[0], source_id);
        bindings[binding_count] = binding_storage[binding_count];
        ++binding_count;
    }
    for (i = 0; i < association_count; ++i) {
        const char *spec = associations[i], *equal = strchr(spec, '=');
        result = 2;
        if (!equal || equal - spec != 64 ||
            strspn(spec, "0123456789abcdef") != 64 || !equal[1]) goto done;
        for (j = 0; j < count; ++j) if (!strncmp(spec, hashes[j], 64)) break;
        if (j == count) goto done;
        for (j = 0; j < binding_count; ++j)
            if (!strncmp(spec, bindings[j], 64)) goto done;
        result = holy_source_active_id(root, equal + 1, source_id);
        if (result) goto done;
        snprintf(binding_storage[binding_count], 130, "%.64s=%s", spec, source_id);
        bindings[binding_count] = binding_storage[binding_count];
        ++binding_count;
    }
    result = holy_state_set(digests, count, choice, NULL, root,
                            bindings, binding_count,
                            accepted_arch, arch_count,
                            accepted_privileged, privileged_count,
                            skipped_hooks, skipped_count, plan);
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
                            bindings, binding_count,
                            accepted_arch, arch_count,
                            accepted_privileged, privileged_count,
                            skipped_hooks, skipped_count, NULL);
done:
    if (result == 2)
        fputs("usage: holypkg add local:FILE [--candidate local:FILE ...] [--choose ID=SHA256] [--associate-source ALIAS] [--associate SHA256=ALIAS ...] [--accept-arch SHA256 ...] [--accept-privileged SHA256 ...] [--skip-hooks SHA256 ...] [--root DIRECTORY] [--yes] [--noninteractive]\n", stderr);
    free(hashes); free(digests); free(inputs);
    free(skipped_hooks);
    free(accepted_arch); free(accepted_privileged);
    free(associations); free(bindings); free(binding_storage);
    return result;
}

static int xbps_registered_catalog(const char *root, const char *alias,
                                   const char *catalog, const char *public_key,
                                   int fetch)
{
    char id[65], key[65], supplied[65];
    char *base = NULL, *trust = NULL;
    int result = holy_source_xbps(root, alias, id, &base, &trust, key);
    if (result) return result;
    result = holy_xbps_source_catalog(catalog, id, base, key);
    if (!result && fetch && key[0] &&
        (!public_key || !holy_xbps_key_fingerprint(public_key, supplied) ||
         strcmp(supplied, key))) result = 6;
    if (!result && !key[0] && public_key) result = 2;
    free(base); free(trust);
    return result;
}

static int xbps_bound_catalog(const char *root, const char *alias,
                              const char *arch, const char *candidate,
                              char **bound)
{
    char *selected = NULL, *registered = NULL;
    int result = holy_xbps_catalog_path(root, alias, arch, bound);
    if (result || !candidate) return result;
    selected = realpath(candidate, NULL);
    registered = realpath(*bound, NULL);
    result = selected && registered && !strcmp(selected, registered) ? 0 : 6;
    free(selected); free(registered);
    return result;
}

static int apt_bound_catalog(const char *root, const char *alias,
                             const char *suite, const char *component,
                             const char *index_arch, const char *candidate,
                             char **bound)
{
    char *selected = NULL, *registered = NULL;
    int result = holy_apt_catalog_path(root, alias, suite, component,
                                       index_arch, bound);
    if (result || !candidate) return result;
    selected = realpath(candidate, NULL);
    registered = realpath(*bound, NULL);
    result = selected && registered && !strcmp(selected, registered) ? 0 : 6;
    free(selected); free(registered);
    return result;
}

static int fetch_source(int argc, char **argv)
{
    const char *separator = strchr(argv[2], ':');
    const char *root = "/", *catalog = NULL, *output = NULL;
    const char *repo = NULL, *version = NULL, *arch = NULL, *sha256 = NULL;
    const char *suite = NULL, *component = NULL, *index_arch = NULL;
    const char *ca_file = NULL, *public_key = NULL;
    const char *required_soname = NULL, *required_file = NULL;
    char source_id[65], *alias = NULL, *bound_catalog = NULL, *family = NULL;
    char **repos = NULL;
    size_t repo_count = 0, j;
    int i, extract = 0, import = 0, root_seen = 0, result = 2;
    if (!separator || separator == argv[2] || !separator[1] ||
        strchr(separator + 1, ':')) goto done;
    alias = malloc((size_t)(separator - argv[2]) + 1);
    if (!alias) { result = 1; goto done; }
    memcpy(alias, argv[2], (size_t)(separator - argv[2]));
    alias[separator - argv[2]] = 0;
    if (!strcmp(alias, "local")) goto done;
    for (i = 3; i < argc; ++i) {
        if ((!strcmp(argv[i], "--repo") || !strcmp(argv[i], "--version") ||
             !strcmp(argv[i], "--arch") || !strcmp(argv[i], "--sha256") ||
             !strcmp(argv[i], "--suite") || !strcmp(argv[i], "--component") ||
             !strcmp(argv[i], "--index-arch") ||
             !strcmp(argv[i], "--ca-file") || !strcmp(argv[i], "--public-key") ||
             !strcmp(argv[i], "--require-soname") || !strcmp(argv[i], "--require-file")) &&
            (i + 1 >= argc || !argv[i + 1][0] || !strncmp(argv[i + 1], "--", 2)))
            goto done;
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
        else if (!strcmp(argv[i], "--import") && !import) import = 1;
        else if (!strcmp(argv[i], "--repo") && !repo && i + 1 < argc) repo = argv[++i];
        else if (!strcmp(argv[i], "--version") && !version && i + 1 < argc) version = argv[++i];
        else if (!strcmp(argv[i], "--arch") && !arch && i + 1 < argc) arch = argv[++i];
        else if (!strcmp(argv[i], "--sha256") && !sha256 && i + 1 < argc) sha256 = argv[++i];
        else if (!strcmp(argv[i], "--suite") && !suite && i + 1 < argc) suite = argv[++i];
        else if (!strcmp(argv[i], "--component") && !component && i + 1 < argc) component = argv[++i];
        else if (!strcmp(argv[i], "--index-arch") && !index_arch && i + 1 < argc) index_arch = argv[++i];
        else if (!strcmp(argv[i], "--ca-file") && !ca_file && i + 1 < argc) ca_file = argv[++i];
        else if (!strcmp(argv[i], "--public-key") && !public_key && i + 1 < argc) public_key = argv[++i];
        else if (!strcmp(argv[i], "--require-soname") && !required_soname && i + 1 < argc)
            required_soname = argv[++i];
        else if (!strcmp(argv[i], "--require-file") && !required_file && i + 1 < argc)
            required_file = argv[++i];
        else goto done;
    }
    if (!output || !*output || !*root) goto done;
    result = holy_source_type(root, alias, &family);
    if (result) goto done;
    if (!strcmp(family, "apk")) {
        if (extract || suite || component || index_arch) { result = 2; goto done; }
        if (!version || !arch) {
            fprintf(stderr, "holypkg: APK fetch needs --version and --arch for %s:%s\n",
                    alias, separator + 1);
            result = 3; goto done;
        }
        if (!repo) {
            result = holy_source_apk_repos(root, alias, &repos, &repo_count);
            if (result) goto done;
            if (repo_count != 1) {
                fprintf(stderr, "holypkg: APK source %s has %zu repositories; select --repo\n",
                        alias, repo_count);
                result = 3; goto done;
            }
            repo = repos[0];
        }
        if (!catalog) {
            result = holy_apk_catalog_path(root, alias, repo, &bound_catalog);
            if (result) goto done;
            catalog = bound_catalog;
        }
        result = holy_apk_fetch(catalog, separator + 1, version, arch, output,
                                sha256, ca_file, root, alias, public_key,
                                import, required_soname, required_file);
        goto done;
    }
    if (!strcmp(family, "xbps")) {
        if (extract || repo || sha256 || required_file || suite || component ||
            index_arch ||
            (required_soname && !import)) { result = 2; goto done; }
        if (!version || !arch) {
            fprintf(stderr, "holypkg: XBPS fetch needs --version and --arch for %s:%s\n",
                    alias, separator + 1);
            result = 3; goto done;
        }
        result = xbps_bound_catalog(root, alias, arch, catalog, &bound_catalog);
        if (result) goto done;
        catalog = bound_catalog;
        result = xbps_registered_catalog(root, alias, catalog, public_key, 1);
        if (!result)
            result = holy_xbps_fetch(catalog, separator + 1, version, arch,
                                     output, ca_file, public_key, 1, import,
                                     required_soname);
        goto done;
    }
    if (!strcmp(family, "rpm-md")) {
        char *path = NULL;
        if (extract || repo || sha256 || public_key || required_soname ||
            required_file || suite || component || index_arch) { result = 2; goto done; }
        if (!version || !arch) {
            fprintf(stderr, "holypkg: RPM-MD fetch needs --version and --arch for %s:%s\n",
                    alias, separator + 1);
            result = 3; goto done;
        }
        result = holy_rpm_md_catalog_path(root, alias, &path);
        if (!result && catalog) {
            char *selected = realpath(catalog, NULL);
            char *registered = realpath(path, NULL);
            result = selected && registered && !strcmp(selected, registered) ? 0 : 6;
            free(selected); free(registered);
        }
        if (!result) {
            char id[65];
            char *base = NULL, *trust = NULL;
            result = holy_source_rpm_md(root, alias, id, &base, &trust);
            if (!result) result = holy_rpm_md_source_catalog(path, id, base);
            free(base); free(trust);
        }
        if (!result)
            result = holy_rpm_md_fetch(path, separator + 1, version, arch,
                                       output, ca_file, import);
        free(path);
        goto done;
    }
    if (!strcmp(family, "apt")) {
        if (extract || repo || sha256 || public_key || required_soname ||
            (required_file && !import)) { result = 2; goto done; }
        if (!version || !arch || !suite || !component || !index_arch) {
            fprintf(stderr, "holypkg: APT fetch needs --version, --arch, --suite, --component and --index-arch for %s:%s\n",
                    alias, separator + 1);
            result = 3; goto done;
        }
        result = apt_bound_catalog(root, alias, suite, component, index_arch,
                                   catalog, &bound_catalog);
        if (result) goto done;
        result = holy_apt_fetch(bound_catalog, separator + 1, version, arch,
                                output, ca_file, import, required_file, root, alias);
        goto done;
    }
    if (repo || version || arch || sha256 || ca_file || public_key || import ||
        required_soname || required_file || suite || component || index_arch) {
        result = 2; goto done;
    }
    if (!catalog) {
        result = holy_source_catalog_path_fast(root, alias, &bound_catalog);
        if (result) goto done;
        catalog = bound_catalog;
    }
    result = holy_source_catalog(root, alias, catalog, source_id);
    if (!result) result = holy_repo_fetch_name(catalog, separator + 1, output, extract);
done:
    if (result == 2)
        fputs("usage: holypkg fetch SOURCE:PACKAGE [--catalog MIRROR] --output DIRECTORY [--extract] [--root DIRECTORY] | holypkg fetch APK_SOURCE:PACKAGE --version VERSION --arch ARCH [--repo REPO] --output NEW_DIRECTORY [--root DIRECTORY] [--ca-file FILE] [--public-key FILE] [--sha256 HASH] [--import] [--require-soname SONAME] [--require-file /PATH] | holypkg fetch XBPS_SOURCE:PACKAGE --version VERSION --arch ARCH --output NEW_DIRECTORY [--catalog DIRECTORY] [--root DIRECTORY] [--ca-file FILE] [--public-key FILE] [--import] [--require-soname SONAME] | holypkg fetch APT_SOURCE:PACKAGE --version VERSION --arch ARCH --suite SUITE --component COMPONENT --index-arch ARCH --output NEW_DIRECTORY [--catalog DIRECTORY] [--root DIRECTORY] [--ca-file FILE] [--import] [--require-file /PATH] | holypkg fetch RPM_MD_SOURCE:PACKAGE --version EVR --arch ARCH --output NEW_DIRECTORY [--catalog DIRECTORY] [--root DIRECTORY] [--ca-file FILE] [--import]\n", stderr);
    for (j = 0; j < repo_count; ++j) free(repos[j]);
    free(repos);
    free(alias); free(bound_catalog); free(family);
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

static int query_apk_source(const char *root, const char *alias,
                            const char *repo, const char *name,
                            int search, int file_search)
{
    char **repos = NULL;
    size_t count = 0, i, offered = 0, found = 0, unavailable = 0;
    int result = holy_source_apk_repos(root, alias, &repos, &count);
    if (result) return result;
    if (file_search) {
        fputs("holypkg: APK file index unavailable; select and inspect payload\n", stderr);
        result = 6; goto done;
    }
    for (i = 0; i < count; ++i) {
        char *path = NULL;
        int rc;
        if (repo && strcmp(repos[i], repo)) continue;
        ++offered;
        rc = holy_apk_catalog_path(root, alias, repos[i], &path);
        if (rc) { ++unavailable; free(path); continue; }
        printf("repo "); print_source_alias(repos[i]); fputc('\n', stdout);
        rc = holy_apk_query(path, name, search ? 0 : 1);
        free(path);
        if (rc == 0 || rc == 3) ++found;
        else if (rc != 4) ++unavailable;
        if (rc == 3) { result = 3; goto done; }
    }
    result = !offered ? 4 : !search && found > 1 ? 3 :
             found ? 0 : unavailable ? 6 : 4;
done:
    for (i = 0; i < count; ++i) free(repos[i]);
    free(repos);
    return result;
}

static int query_source(int argc, char **argv, int search)
{
    const char *root = "/", *catalog = NULL, *alias = NULL, *name = NULL;
    const char *repo = NULL, *arch = NULL;
    const char *suite = NULL, *component = NULL, *index_arch = NULL;
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
        else if (!strcmp(argv[i], "--repo") && !repo && i + 1 < argc &&
                 argv[i + 1][0] && strncmp(argv[i + 1], "--", 2)) repo = argv[++i];
        else if (!strcmp(argv[i], "--arch") && !arch && i + 1 < argc &&
                 argv[i + 1][0] && strncmp(argv[i + 1], "--", 2)) arch = argv[++i];
        else if (!strcmp(argv[i], "--suite") && !suite && i + 1 < argc &&
                 argv[i + 1][0] && strncmp(argv[i + 1], "--", 2)) suite = argv[++i];
        else if (!strcmp(argv[i], "--component") && !component && i + 1 < argc &&
                 argv[i + 1][0] && strncmp(argv[i + 1], "--", 2)) component = argv[++i];
        else if (!strcmp(argv[i], "--index-arch") && !index_arch && i + 1 < argc &&
                 argv[i + 1][0] && strncmp(argv[i + 1], "--", 2)) index_arch = argv[++i];
        else if (!strcmp(argv[i], "--root") && !root_seen && i + 1 < argc &&
                 argv[i + 1][0] && strncmp(argv[i + 1], "--", 2)) {
            root = argv[++i]; root_seen = 1;
        } else goto done;
    }
    if (!name || !*name || (alias && (!*alias || !strcmp(alias, "local"))) ||
        (!alias && (!search || catalog || repo)) ||
        ((!!suite + !!component + !!index_arch) % 3 != 0)) goto done;
    if (!alias) {
        result = holy_source_active_aliases(root, &aliases, &alias_count);
        if (result) goto done;
        if (!alias_count) {
            fputs("holypkg: no active sources\n", stderr);
            result = 6; goto done;
        }
        for (j = 0; j < alias_count; ++j) {
            char *path = NULL;
            char *family = NULL;
            const char *current = aliases[j];
            int rc = holy_source_type(root, current, &family);
            printf("source "); print_source_alias(current);
            if (!rc && !strcmp(family, "apk")) {
                rc = holy_source_active_id(root, current, source_id);
                if (!rc) printf(" id %s\n", source_id);
                if (!rc) rc = query_apk_source(root, current, NULL, name, 1,
                                                file_search);
            } else if (!rc && !strcmp(family, "xbps")) {
                rc = !arch || file_search ? 6 :
                     holy_xbps_catalog_path(root, current, arch, &path);
                if (!rc) rc = holy_source_active_id(root, current, source_id);
                if (!rc) printf(" id %s\n", source_id);
                if (!rc) rc = holy_xbps_query(path, name, 0);
            } else if (!rc && !strcmp(family, "rpm-md")) {
                rc = arch || file_search ? 6 :
                     holy_rpm_md_catalog_path(root, current, &path);
                if (!rc) rc = holy_source_active_id(root, current, source_id);
                if (!rc) printf(" id %s\n", source_id);
                if (!rc) rc = holy_rpm_md_query(path, name, 0);
            } else if (!rc && !strcmp(family, "apt")) {
                rc = !suite ? 6 : holy_apt_catalog_path(root, current, suite,
                                                        component, index_arch, &path);
                if (!rc) rc = holy_source_active_id(root, current, source_id);
                if (!rc) printf(" id %s\n", source_id);
                if (!rc) rc = holy_apt_query(path, name, 0, file_search,
                                             root, current);
            } else if (!rc && (!strcmp(family, "holy-http") ||
                               !strcmp(family, "holy-git"))) {
                rc = holy_source_catalog_path_fast(root, current, &path);
                if (!rc) rc = holy_source_catalog(root, current, path, source_id);
                if (!rc) printf(" id %s\n", source_id);
                if (!rc) rc = search_catalog(path, name, file_search, fuzzy_search);
            } else if (!rc) rc = 6;
            if (rc && rc != 4) {
                fputs(" coverage unavailable\n", stdout);
                ++unavailable;
            }
            free(path); free(family);
            if (rc == 2) { result = 2; goto done; }
        }
        printf("searched %zu sources; unavailable %zu\n", alias_count, unavailable);
        result = unavailable ? 6 : ferror(stdout) ? 1 : 0;
        goto done;
    }
    {
        char *family = NULL;
        result = holy_source_type(root, alias, &family);
        if (result) { free(family); goto done; }
        if (!strcmp(family, "apk")) {
            free(family);
            if (catalog || arch || suite) goto done;
            result = holy_source_active_id(root, alias, source_id);
            if (!result) result = query_apk_source(root, alias, repo, name,
                                                    search, file_search);
            if (!result) printf("source-id %s\n", source_id);
            goto done;
        }
        if (!strcmp(family, "xbps")) {
            free(family);
            if (repo || suite || file_search) { result = file_search ? 6 : 2; goto done; }
            if (!arch) {
                fprintf(stderr, "holypkg: XBPS query needs --arch for %s\n", alias);
                result = 3; goto done;
            }
            result = xbps_bound_catalog(root, alias, arch, catalog, &bound_catalog);
            if (result) goto done;
            catalog = bound_catalog;
            result = xbps_registered_catalog(root, alias, catalog, NULL, 0);
            if (!result) result = holy_source_active_id(root, alias, source_id);
            if (!result) result = holy_xbps_query(catalog, name, !search);
            if (!result) printf("source-id %s\n", source_id);
            goto done;
        }
        if (!strcmp(family, "rpm-md")) {
            char *path = NULL;
            free(family);
            if (repo || arch || suite || file_search) { result = file_search ? 6 : 2; goto done; }
            result = holy_rpm_md_catalog_path(root, alias, &path);
            if (!result && catalog) {
                char *selected = realpath(catalog, NULL);
                char *registered = realpath(path, NULL);
                result = selected && registered && !strcmp(selected, registered) ? 0 : 6;
                free(selected); free(registered);
            }
            if (!result) {
                result = holy_source_active_id(root, alias, source_id);
                if (!result) result = holy_rpm_md_query(path, name, !search);
                if (!result) printf("source-id %s\n", source_id);
            }
            free(path);
            goto done;
        }
        if (!strcmp(family, "apt")) {
            free(family);
            if (repo || arch) goto done;
            if (!suite) {
                fprintf(stderr, "holypkg: APT query needs --suite, --component and --index-arch for %s\n", alias);
                result = 3; goto done;
            }
            result = apt_bound_catalog(root, alias, suite, component, index_arch,
                                       catalog, &bound_catalog);
            if (result) goto done;
            result = holy_apt_query(bound_catalog, name, !search, file_search,
                                    root, alias);
            goto done;
        }
        if (repo || arch || suite ||
            (strcmp(family, "holy-http") && strcmp(family, "holy-git"))) {
            free(family); goto done;
        }
        free(family);
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
        search ? "usage: holypkg search QUERY [--source SOURCE] [--repo REPO] [--arch ARCH] [--suite SUITE --component COMPONENT --index-arch ARCH] [--file] [--fuzzy] [--catalog MIRROR] [--root DIRECTORY]\n" :
                 "usage: holypkg info SOURCE:PACKAGE [--repo REPO] [--arch ARCH] [--suite SUITE --component COMPONENT --index-arch ARCH] [--catalog MIRROR] [--root DIRECTORY]\n");
    for (j = 0; j < alias_count; ++j) free(aliases[j]);
    free(aliases);
    free(owned_alias); free(bound_catalog);
    return result;
}

struct source_candidate {
    char *alias, *kind, *name, *catalog, *next_catalog;
    char source_id[65], next_id[65];
    struct holy_repo_set staged, next;
    int provider;
};

struct source_offer { unsigned char offered, rank; int priority; };

struct source_local_candidate {
    char *alias, *path;
    char source_id[65], digest[65];
};

struct source_answer {
    char *consumer, *requirement, *alias;
};

static char *copy_text(const char *value);

static void free_source_answers(struct source_answer *answers, size_t count)
{
    size_t i;
    if (!answers) return;
    for (i = 0; i < count; ++i) {
        free(answers[i].consumer);
        free(answers[i].requirement);
        free(answers[i].alias);
    }
    free(answers);
}

static int load_source_answers(const char *path, struct source_answer **out,
                               size_t *count)
{
    char *snapshot = holy_stage_local(path, "holy-answers");
    struct source_answer *answers = NULL;
    FILE *stream = NULL;
    char line[4097];
    size_t used = 0, number = 0;
    int format = 0, result = 2;
    *out = NULL;
    *count = 0;
    if (!snapshot) return 6;
    stream = fopen(snapshot, "r");
    if (!stream) { result = 6; goto done; }
    while (fgets(line, sizeof line, stream)) {
        char **fields = NULL, *error = NULL;
        size_t length = strlen(line), fields_count = 0, i;
        ++number;
        if (number > 10000 || !length || length == sizeof line - 1 ||
            (line[length - 1] != '\n' && !feof(stream)) ||
            !holy_lex(line, length, &fields, &fields_count,
                      "source answers", number, &error)) {
            free(error); holy_tokens_free(fields, fields_count); goto done;
        }
        free(error);
        if (!fields_count) { holy_tokens_free(fields, fields_count); continue; }
        if (!format) {
            format = fields_count == 2 && !strcmp(fields[0], "format") &&
                     !strcmp(fields[1], "holy-answers-1");
            holy_tokens_free(fields, fields_count);
            if (!format) goto done;
            continue;
        }
        if (fields_count != 4 || strcmp(fields[0], "source") ||
            strlen(fields[1]) != 64 || strspn(fields[1], "0123456789abcdef") != 64 ||
            !fields[2][0] || !fields[3][0] || !strcmp(fields[3], "local") ||
            used == 10000) { holy_tokens_free(fields, fields_count); goto done; }
        for (i = 0; i < used; ++i)
            if (!strcmp(answers[i].consumer, fields[1]) &&
                !strcmp(answers[i].requirement, fields[2])) break;
        if (i != used) { holy_tokens_free(fields, fields_count); goto done; }
        {
            struct source_answer *next = realloc(answers, (used + 1) * sizeof *next);
            if (!next) { holy_tokens_free(fields, fields_count); result = 1; goto done; }
            answers = next;
        }
        answers[used].consumer = copy_text(fields[1]);
        answers[used].requirement = copy_text(fields[2]);
        answers[used].alias = copy_text(fields[3]);
        if (!answers[used].consumer || !answers[used].requirement ||
            !answers[used].alias) {
            ++used;
            holy_tokens_free(fields, fields_count); result = 1; goto done;
        }
        ++used;
        holy_tokens_free(fields, fields_count);
    }
    if (ferror(stream)) { result = 1; goto done; }
    if (!format) goto done;
    *out = answers;
    *count = used;
    answers = NULL;
    result = 0;
done:
    if (result == 2) fprintf(stderr, "holypkg: malformed source answers at line %zu\n", number);
    if (stream) fclose(stream);
    unlink(snapshot);
    free(snapshot);
    free_source_answers(answers, used);
    return result;
}

static char *copy_text(const char *value)
{
    char *copy = malloc(strlen(value) + 1);
    if (copy) strcpy(copy, value);
    return copy;
}

static int missing_from_cache(const char *const *digests, size_t count,
                              const char *root, const char *const *skip_ids,
                              size_t skip_count,
                              struct holy_missing_requirement *missing)
{
    char **paths = calloc(count, sizeof *paths);
    size_t i;
    int result = 6;
    if (!paths) return 1;
    for (i = 0; i < count; ++i) {
        paths[i] = holy_cache_snapshot(digests[i], root);
        if (!paths[i]) goto done;
    }
    result = holy_resolve_missing((const char *const *)paths, count,
                                  skip_ids, skip_count, missing);
done:
    for (i = 0; i < count; ++i) if (paths[i]) {
        unlink(paths[i]);
        free(paths[i]);
    }
    free(paths);
    return result;
}

static int add_source(int argc, char **argv)
{
    const char *separator = strchr(argv[2], ':');
    const char *root = "/", *catalog = NULL, *choice = NULL, *answers_path = NULL;
    const char **accepted_arch = NULL, **accepted_privileged = NULL;
    const char **digests = NULL, **bindings = NULL, **skipped = NULL;
    struct source_candidate *extras = NULL;
    struct source_local_candidate *locals = NULL;
    struct source_answer *answers = NULL;
    struct holy_repo_set staged = {0}, next = {0};
    char source_id[65], next_id[65], plan[65], answer[16], *alias = NULL;
    char *bound_catalog = NULL, *next_catalog = NULL;
    size_t arch_count = 0, privileged_count = 0, extra_count = 0, local_count = 0;
    size_t answer_count = 0;
    size_t digest_count = 0, binding_count = 0, skip_count = 0, i, j, k;
    int unavailable_seen = 0;
    int yes = 0, prepare = 0, noninteractive = 0, root_seen = 0, result = 2;
    if (!separator || separator == argv[2] || !separator[1] ||
        strchr(separator + 1, ':')) goto done;
    alias = malloc((size_t)(separator - argv[2]) + 1);
    accepted_arch = calloc((size_t)argc, sizeof *accepted_arch);
    accepted_privileged = calloc((size_t)argc, sizeof *accepted_privileged);
    if (argc > 10000) goto done;
    extras = calloc(10000, sizeof *extras);
    locals = calloc((size_t)argc, sizeof *locals);
    digests = calloc(10000, sizeof *digests);
    bindings = calloc(10000, sizeof *bindings);
    skipped = calloc(10000, sizeof *skipped);
    if (!alias || !accepted_arch || !accepted_privileged || !extras || !locals ||
        !digests || !bindings || !skipped) { result = 1; goto done; }
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
        else if (!strcmp(argv[i], "--answers") && !answers_path && i + 1 < (size_t)argc &&
                 argv[i + 1][0] && strncmp(argv[i + 1], "--", 2)) answers_path = argv[++i];
        else if (!strcmp(argv[i], "--candidate") && i + 1 < (size_t)argc) {
            const char *ref = argv[++i], *colon = strchr(ref, ':');
            struct source_candidate *item;
            if (extra_count == 10000) goto done;
            item = &extras[extra_count];
            if (!colon || colon == ref || !colon[1] || strchr(colon + 1, ':')) goto done;
            item->alias = malloc((size_t)(colon - ref) + 1);
            if (item->alias) {
                memcpy(item->alias, ref, (size_t)(colon - ref));
                item->alias[colon - ref] = 0;
            }
            item->name = malloc(strlen(colon + 1) + 1);
            if (item->name) strcpy(item->name, colon + 1);
            if (!item->alias || !item->name) { result = 1; goto done; }
            if (!strcmp(item->alias, "local") || !strcmp(item->alias, alias)) goto done;
            ++extra_count;
        }
        else if (!strcmp(argv[i], "--candidate-provider") && i + 1 < (size_t)argc) {
            const char *ref = argv[++i], *first = strchr(ref, ':'), *second;
            struct source_candidate *item;
            if (extra_count == 10000) goto done;
            item = &extras[extra_count];
            if (!first || first == ref || !(second = strchr(first + 1, ':')) ||
                second == first + 1 || !second[1]) goto done;
            item->alias = malloc((size_t)(first - ref) + 1);
            item->kind = malloc((size_t)(second - first));
            item->name = malloc(strlen(second + 1) + 1);
            if (!item->alias || !item->kind || !item->name) { result = 1; goto done; }
            memcpy(item->alias, ref, (size_t)(first - ref));
            item->alias[first - ref] = 0;
            memcpy(item->kind, first + 1, (size_t)(second - first - 1));
            item->kind[second - first - 1] = 0;
            strcpy(item->name, second + 1);
            if (!strcmp(item->alias, "local") || !strcmp(item->alias, alias) ||
                (strcmp(item->kind, "package") && strcmp(item->kind, "file") &&
                 strcmp(item->kind, "command") && strcmp(item->kind, "soname"))) goto done;
            item->provider = 1;
            ++extra_count;
        }
        else if (!strcmp(argv[i], "--candidate-local") && i + 1 < (size_t)argc) {
            const char *spec = argv[++i], *equal = strchr(spec, '=');
            struct source_local_candidate *item = &locals[local_count];
            if (!equal || equal == spec || !equal[1]) goto done;
            item->alias = malloc((size_t)(equal - spec) + 1);
            if (item->alias) {
                memcpy(item->alias, spec, (size_t)(equal - spec));
                item->alias[equal - spec] = 0;
            }
            item->path = copy_text(equal + 1);
            ++local_count;
            if (!item->alias || !item->path) { result = 1; goto done; }
            if (!strcmp(item->alias, "local")) goto done;
        }
        else if (!strcmp(argv[i], "--accept-arch") && i + 1 < (size_t)argc &&
                 argv[i + 1][0] && strncmp(argv[i + 1], "--", 2))
            accepted_arch[arch_count++] = argv[++i];
        else if (!strcmp(argv[i], "--accept-privileged") && i + 1 < (size_t)argc &&
                 argv[i + 1][0] && strncmp(argv[i + 1], "--", 2))
            accepted_privileged[privileged_count++] = argv[++i];
        else if (!strcmp(argv[i], "--yes") && !yes) yes = 1;
        else if (!strcmp(argv[i], "--prepare") && !prepare) prepare = 1;
        else if (!strcmp(argv[i], "--noninteractive") && !noninteractive) noninteractive = 1;
        else goto done;
    }
    if (yes && prepare) goto done;
    if (answers_path) {
        result = load_source_answers(answers_path, &answers, &answer_count);
        if (result) goto done;
    }
    if (!catalog) {
        result = holy_source_catalog_path_fast(root, alias, &bound_catalog);
        if (result) goto done;
        catalog = bound_catalog;
    }
    result = holy_source_catalog(root, alias, catalog, source_id);
    if (result) goto done;
    result = holy_repo_stage_set(catalog, separator + 1, root, &staged);
    if (result) goto done;
    if (staged.count > 10000) { result = 2; goto done; }
    for (i = 0; i < staged.count; ++i) digests[digest_count++] = staged.digests[i];
    for (i = 0; i < local_count; ++i) {
        struct source_local_candidate *item = &locals[i];
        char *binding;
        if (digest_count == 10000) { result = 2; goto done; }
        result = holy_source_active_id(root, item->alias, item->source_id);
        if (result) goto done;
        if (!holy_cache_stage_local_digest(item->path, root, item->digest)) {
            result = 6; goto done;
        }
        for (j = 0; j < digest_count; ++j)
            if (!strcmp(digests[j], item->digest)) {
                fprintf(stderr, "holypkg: duplicate local candidate artifact %s\n", item->digest);
                result = 3; goto done;
            }
        binding = malloc(130);
        if (!binding) { result = 1; goto done; }
        snprintf(binding, 130, "%s=%s", item->digest, item->source_id);
        bindings[binding_count++] = binding;
        digests[digest_count++] = item->digest;
    }
    for (i = 0; i < extra_count; ++i) {
        struct source_candidate *item = &extras[i];
        result = holy_source_catalog_path_fast(root, item->alias, &item->catalog);
        if (result) goto done;
        result = holy_source_catalog(root, item->alias, item->catalog, item->source_id);
        if (result) goto done;
        result = item->provider ?
            holy_repo_stage_provider(item->catalog, item->kind, item->name,
                                     root, &item->staged) :
            holy_repo_stage_set(item->catalog, item->name, root, &item->staged);
        if (result) goto done;
        for (j = 0; j < item->staged.count; ++j) {
            char *binding;
            if (digest_count == 10000) { result = 2; goto done; }
            for (k = 0; k < digest_count; ++k)
                if (!strcmp(digests[k], item->staged.digests[j])) break;
            if (k != digest_count) {
                fprintf(stderr, "holypkg: artifact belongs to multiple candidate sources: %s\n",
                        item->staged.digests[j]);
                result = 3; goto done;
            }
            binding = malloc(130);
            if (!binding) { result = 1; goto done; }
            snprintf(binding, 130, "%s=%s", item->staged.digests[j], item->source_id);
            bindings[binding_count++] = binding;
            digests[digest_count++] = item->staged.digests[j];
        }
    }
    for (k = 0; k < 10000; ++k) {
        struct holy_missing_requirement missing = {0};
        char **aliases = NULL;
        struct source_offer *offers = NULL;
        size_t alias_count = 0, a, offered = 0;
        const char *winner = NULL, *preferred = NULL;
        const char *consumer_origin = NULL;
        char parent_id[65] = {0}, consumer_family[129] = {0};
        int best_rank = 5, best_priority = INT_MIN, best_count = 0;
        int missing_status;
        int progressed = 0, unavailable = 0, answered = 0;
        result = holy_state_probe_source_bindings(digests, digest_count,
                   source_id, staged.index, bindings, binding_count, choice, root,
                   accepted_arch, arch_count, accepted_privileged, privileged_count);
        if (!result) break;
        if (result != 3 && result != 4) goto done;
        missing_status = missing_from_cache(digests, digest_count, root,
                                            skipped, skip_count, &missing);
        if (missing_status == 0 || !missing.kind) {
            holy_missing_requirement_free(&missing);
            if (unavailable_seen) { result = 6; goto done; }
            break;
        }
        if (missing_status != 4 && missing_status != 3) {
            holy_missing_requirement_free(&missing);
            result = missing_status; goto done;
        }
        for (a = 0; a < staged.count; ++a)
            if (!strcmp(staged.digests[a], missing.consumer)) consumer_origin = source_id;
        for (a = 0; !consumer_origin && a < binding_count; ++a)
            if (!strncmp(bindings[a], missing.consumer, 64) && bindings[a][64] == '=')
                consumer_origin = bindings[a] + 65;
        if (consumer_origin) {
            char *family = NULL;
            int priority;
            result = holy_source_parent_id(root, consumer_origin, parent_id);
            if (!result) result = holy_source_rank_info(root, consumer_origin,
                                                        &family, &priority);
            if (!result && family) snprintf(consumer_family, sizeof consumer_family, "%s", family);
            free(family);
            if (result) { holy_missing_requirement_free(&missing); goto done; }
        }
        result = holy_source_active_aliases(root, &aliases, &alias_count);
        if (result) { holy_missing_requirement_free(&missing); goto done; }
        offers = calloc(alias_count ? alias_count : 1, sizeof *offers);
        if (!offers) {
            for (a = 0; a < alias_count; ++a) free(aliases[a]);
            free(aliases);
            holy_missing_requirement_free(&missing);
            result = 1; goto done;
        }
        for (a = 0; a < alias_count; ++a) {
            char *path = NULL;
            char *family = NULL;
            char *source_family = NULL;
            char candidate_id[65];
            int source_priority = 0, rank = 4;
            int probe;
            probe = holy_source_type(root, aliases[a], &family);
            if (probe) { result = probe; break; }
            if (strcmp(family, "holy-http") && strcmp(family, "holy-git")) {
                free(family);
                continue;
            }
            free(family);
            probe = !strcmp(aliases[a], alias) ?
                ((path = copy_text(catalog)) ? 0 : 1) :
                holy_source_catalog_path_fast(root, aliases[a], &path);
            if (!probe) probe = holy_source_catalog(root, aliases[a], path, candidate_id);
            if (!probe) probe = !strcmp(missing.kind, "soname") && missing.path ?
                holy_repo_has_compatible_soname(path, missing.name, root,
                                                missing.consumer, missing.path) :
                holy_repo_has_provider(path, missing.kind, missing.name);
            free(path);
            if (!probe) {
                probe = holy_source_rank_info(root, candidate_id,
                                              &source_family, &source_priority);
                if (probe) { free(source_family); result = probe; break; }
                if (consumer_origin && !strcmp(candidate_id, consumer_origin)) rank = 1;
                else if (parent_id[0] && !strcmp(candidate_id, parent_id)) rank = 2;
                else if (consumer_family[0] && source_family &&
                         !strcmp(consumer_family, source_family)) rank = 3;
                free(source_family);
                ++offered;
                offers[a].offered = 1;
                offers[a].rank = (unsigned char)rank;
                offers[a].priority = source_priority;
                winner = aliases[a];
                if (rank < best_rank || (rank == best_rank && source_priority > best_priority)) {
                    best_rank = rank; best_priority = source_priority;
                    best_count = 1; preferred = aliases[a];
                } else if (rank == best_rank && source_priority == best_priority) ++best_count;
                fprintf(stderr, "holypkg: provider %s:%s available from %s rank=%s priority=%d\n",
                        missing.kind, missing.name, aliases[a],
                        rank == 1 ? "same-source" : rank == 2 ? "parent" :
                        rank == 3 ? "family" : "other", source_priority);
            } else if (probe == 6) ++unavailable;
            else if (probe != 4) { result = probe; break; }
        }
        if (!result && answers) {
            const char *requested = NULL;
            for (a = 0; a < answer_count; ++a)
                if (!strcmp(answers[a].consumer, missing.consumer) &&
                    !strcmp(answers[a].requirement, missing.id)) {
                    requested = answers[a].alias;
                    break;
                }
            if (requested) {
                answered = 1;
                winner = NULL;
                for (a = 0; a < alias_count; ++a)
                    if (offers[a].offered && !strcmp(aliases[a], requested))
                        winner = aliases[a];
                if (!winner) {
                    fprintf(stderr, "holypkg: answer source %s does not offer %s:%s for %s:%s\n",
                            requested, missing.kind, missing.name,
                            missing.consumer, missing.id);
                    result = 3;
                }
            }
        }
        if (!result && !answered && preferred && best_count == 1 &&
            (best_rank <= 2 || !unavailable)) {
            winner = preferred;
            fprintf(stderr, "holypkg: selected %s for %s:%s by %s preference\n",
                    winner, missing.kind, missing.name,
                    best_rank == 1 ? "same-source" : best_rank == 2 ? "parent" :
                    best_rank == 3 ? "family" : "priority");
        } else if (!result && (offered > 1 || (offered && unavailable)) && !answered) {
            winner = NULL;
            if (!noninteractive && isatty(STDIN_FILENO)) {
                char response[4097];
                size_t length = 0;
                fprintf(stderr, "Select source for %s:%s requirement %s (consumer %s), or blank to cancel: ",
                        missing.kind, missing.name, missing.id, missing.consumer);
                if (fflush(stderr)) result = 1;
                if (!result && fgets(response, sizeof response, stdin))
                    length = strlen(response);
                if (length && response[length - 1] == '\n') {
                    response[length - 1] = 0;
                    for (a = 0; a < alias_count; ++a)
                        if (offers[a].offered && !strcmp(response, aliases[a])) winner = aliases[a];
                }
            }
            if (!winner && !result) {
                fprintf(stderr, "holypkg: decision-required for %s:%s (%zu sources offered, %d unavailable); pass --candidate-provider SOURCE:%s:%s\n",
                        missing.kind, missing.name, offered, unavailable,
                        missing.kind, missing.name);
                result = 3;
            }
        }
        if (result) {
            for (a = 0; a < alias_count; ++a) free(aliases[a]);
            free(aliases);
            free(offers);
            holy_missing_requirement_free(&missing);
            goto done;
        }
        for (a = 0; a < alias_count; ++a) {
            struct source_candidate *item;
            if (aliases[a] != winner) continue;
            if (extra_count == 10000) { result = 2; break; }
            item = &extras[extra_count];
            item->alias = copy_text(aliases[a]);
            item->kind = copy_text(missing.kind);
            item->name = copy_text(missing.name);
            item->provider = 1;
            if (!item->alias || !item->kind || !item->name) { result = 1; break; }
            result = !strcmp(item->alias, alias) ?
                ((item->catalog = copy_text(catalog)) ? 0 : 1) :
                holy_source_catalog_path_fast(root, item->alias, &item->catalog);
            if (result) { ++unavailable; result = 0; goto next_alias; }
            result = holy_source_catalog(root, item->alias, item->catalog, item->source_id);
            if (result) { ++unavailable; result = 0; goto next_alias; }
            result = holy_repo_stage_provider(item->catalog, item->kind,
                                              item->name, root, &item->staged);
            if (result == 4) { result = 0; goto next_alias; }
            if (result == 6) { ++unavailable; result = 0; goto next_alias; }
            if (result) break;
            for (j = 0; j < item->staged.count; ++j) {
                size_t existing;
                char *binding;
                for (existing = 0; existing < digest_count; ++existing)
                    if (!strcmp(digests[existing], item->staged.digests[j])) break;
                if (existing < digest_count) {
                    const char *owner = existing < staged.count ? source_id : NULL;
                    size_t q;
                    for (q = 0; !owner && q < binding_count; ++q)
                        if (!strncmp(bindings[q], digests[existing], 64))
                            owner = bindings[q] + 65;
                    if (!owner || strcmp(owner, item->source_id)) {
                        fprintf(stderr, "holypkg: artifact offered by multiple sources: %s\n",
                                item->staged.digests[j]);
                        result = 3; break;
                    }
                    continue;
                }
                if (digest_count == 10000) { result = 2; break; }
                binding = malloc(130);
                if (!binding) { result = 1; break; }
                snprintf(binding, 130, "%s=%s", item->staged.digests[j], item->source_id);
                bindings[binding_count++] = binding;
                digests[digest_count++] = item->staged.digests[j];
                progressed = 1;
            }
            if (result) break;
            ++extra_count;
            continue;
next_alias:
            free(item->alias); free(item->kind); free(item->name);
            free(item->catalog); holy_repo_set_free(&item->staged);
            memset(item, 0, sizeof *item);
        }
        for (a = 0; a < alias_count; ++a) free(aliases[a]);
        free(aliases);
        free(offers);
        if (result) { holy_missing_requirement_free(&missing); goto done; }
        if (progressed) {
            for (i = 0; i < skip_count; ++i) free((void *)skipped[i]);
            skip_count = 0;
            unavailable_seen = 0;
        } else {
            char *key;
            size_t id_length = strlen(missing.id);
            unavailable_seen |= unavailable;
            if (skip_count == 10000) {
                holy_missing_requirement_free(&missing);
                result = 4; goto done;
            }
            if (id_length > (size_t)-1 - 66) {
                holy_missing_requirement_free(&missing);
                result = 2; goto done;
            }
            key = malloc(id_length + 66);
            if (!key) {
                holy_missing_requirement_free(&missing);
                result = 1; goto done;
            }
            snprintf(key, id_length + 66, "%s:%s", missing.consumer, missing.id);
            skipped[skip_count++] = key;
        }
        holy_missing_requirement_free(&missing);
    }
    result = holy_state_set_source_bindings(digests, digest_count,
                                            source_id, staged.index, bindings,
                                            binding_count, choice, NULL, root,
                                            accepted_arch, arch_count,
                                            accepted_privileged, privileged_count, plan);
    if (result) goto done;
    if (prepare) goto done;
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
        result = holy_source_catalog_path_fast(root, alias, &next_catalog);
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
    for (i = 0; i < extra_count; ++i) {
        struct source_candidate *item = &extras[i];
        result = holy_source_catalog_path_fast(root, item->alias, &item->next_catalog);
        if (result || strcmp(item->catalog, item->next_catalog)) { result = 3; goto done; }
        result = holy_source_catalog(root, item->alias, item->catalog, item->next_id);
        if (result || strcmp(item->source_id, item->next_id)) { result = 3; goto done; }
        result = item->provider ?
            holy_repo_stage_provider(item->catalog, item->kind, item->name,
                                     root, &item->next) :
            holy_repo_stage_set(item->catalog, item->name, root, &item->next);
        if (result || strcmp(item->staged.index, item->next.index) ||
            item->staged.count != item->next.count) { result = 3; goto done; }
        for (j = 0; j < item->staged.count; ++j)
            if (strcmp(item->staged.digests[j], item->next.digests[j])) {
                result = 3; goto done;
            }
    }
    for (i = 0; i < local_count; ++i) {
        char refreshed_id[65], refreshed_hash[65];
        result = holy_source_active_id(root, locals[i].alias, refreshed_id);
        if (result || strcmp(refreshed_id, locals[i].source_id) ||
            !holy_cache_stage_local_digest(locals[i].path, root, refreshed_hash) ||
            strcmp(refreshed_hash, locals[i].digest)) {
            result = 3; goto done;
        }
    }
    result = holy_state_set_source_bindings(digests, digest_count,
                                            source_id, staged.index, bindings,
                                            binding_count, choice, plan, root,
                                            accepted_arch, arch_count,
                                            accepted_privileged, privileged_count, NULL);
done:
    if (result == 2)
        fputs("usage: holypkg add SOURCE:PACKAGE [--catalog MIRROR] [--candidate SOURCE:PACKAGE ...] [--candidate-provider SOURCE:KIND:NAME ...] [--candidate-local SOURCE=FILE.holy ...] [--choose ID=SHA256] [--answers FILE] [--accept-arch SHA256 ...] [--accept-privileged SHA256 ...] [--root DIRECTORY] [--prepare | --yes] [--noninteractive]\n", stderr);
    for (i = 0; i < binding_count; ++i) free((void *)bindings[i]);
    for (i = 0; i < skip_count; ++i) free((void *)skipped[i]);
    for (i = 0; extras && i <= extra_count && i < 10000; ++i) {
        free(extras[i].alias); free(extras[i].kind); free(extras[i].name);
        free(extras[i].catalog); free(extras[i].next_catalog);
        holy_repo_set_free(&extras[i].staged);
        holy_repo_set_free(&extras[i].next);
    }
    for (i = 0; i < local_count; ++i) {
        free(locals[i].alias); free(locals[i].path);
    }
    free(locals);
    free(extras); free(digests); free(bindings); free(skipped);
    holy_repo_set_free(&staged); holy_repo_set_free(&next);
    free(alias); free(bound_catalog); free(next_catalog);
    free(accepted_arch); free(accepted_privileged);
    free_source_answers(answers, answer_count);
    return result;
}

static int installed_ref(int argc, char **argv, int operation)
{
    const char *reference = argc > 2 ? argv[2] : NULL;
    const char *separator = reference ? strchr(reference, ':') : NULL;
    const char *root = "/", *arch = NULL, *libc = NULL, *plan = NULL;
    char source_id[65], digest[65], answer[16], *alias = NULL;
    int root_seen = 0, json = 0, yes = 0, accept_broken = 0;
    int remove_package = operation == 1, list_files = operation == 2;
    int explain = operation == 3, repair = operation == 4;
    int result = 2, i;
    if (!remove_package && !list_files && !explain && !repair && (argc == 2 ||
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
        else if (!remove_package && !list_files && !repair && !strcmp(argv[i], "--json") && !json) json = 1;
        else if (repair && !strcmp(argv[i], "--plan") && !plan && i + 1 < argc)
            plan = argv[++i];
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
    if (explain) { result = holy_why(digest, root, json); goto done; }
    if (repair) { result = holy_state_repair(digest, plan, root); goto done; }
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
                remove_package ? "rm" : list_files ? "files" : explain ? "why" : repair ? "repair" : "check",
                remove_package || list_files || explain || repair ? "SOURCE:PACKAGE" : "[SOURCE:PACKAGE]",
                remove_package ? "[--yes] [--accept-broken]" : repair ? "[--plan PLAN_SHA256]" : list_files ? "" : "[--json]");
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
    if (argc > 2 && !strcmp(argv[1], "build")) {
        const char *environment = NULL, *work = NULL, *output = NULL;
        int i, yes = 0, noninteractive = 0, keep = 0;
        unsigned jobs = 1;
        for (i = 3; i < argc; ++i) {
            if (!strcmp(argv[i], "--yes") && !yes) yes = 1;
            else if (!strcmp(argv[i], "--noninteractive") && !noninteractive) noninteractive = 1;
            else if (!strcmp(argv[i], "--keep") && !keep) keep = 1;
            else if (!strcmp(argv[i], "--environment") && !environment && i + 1 < argc)
                environment = argv[++i];
            else if (!strcmp(argv[i], "--work") && !work && i + 1 < argc) work = argv[++i];
            else if (!strcmp(argv[i], "--output") && !output && i + 1 < argc) output = argv[++i];
            else if (!strcmp(argv[i], "--jobs") && i + 1 < argc) {
                char *end = NULL;
                long value = strtol(argv[++i], &end, 10);
                if (!end || *end || value < 1 || value > 4096) {
                    fputs("usage: holypkg build RECIPE --output NEW_DIRECTORY "
                          "[--environment host|clean|vm] [--work NEW_DIRECTORY] "
                          "[--jobs N] [--yes] [--noninteractive] [--keep]\n", stderr);
                    return 2;
                }
                jobs = (unsigned)value;
            } else {
                fputs("usage: holypkg build RECIPE --output NEW_DIRECTORY "
                      "[--environment host|clean|vm] [--work NEW_DIRECTORY] "
                      "[--jobs N] [--yes] [--noninteractive] [--keep]\n", stderr);
                return 2;
            }
        }
        return holy_recipe_build(argv[2], environment ? environment : "host", work, output,
                                 jobs, yes, noninteractive, keep);
    }
    if (argc > 1 && !strcmp(argv[1], "up")) return holy_up_command(argc, argv);
    if (argc > 1 && !strcmp(argv[1], "run")) return holy_run(argc, argv);
    if (argc > 2 && !strcmp(argv[1], "rpm")) {
        if (argc == 13 && !strcmp(argv[2], "index") &&
            !strcmp(argv[5], "--sha256") && !strcmp(argv[7], "--source") &&
            !strcmp(argv[9], "--base") && !strcmp(argv[11], "--output"))
            return holy_rpm_md_index(argv[3], argv[4], argv[6], argv[8], argv[10], argv[12], NULL);
        if ((argc == 10 || argc == 12) && !strcmp(argv[2], "sync") &&
            !strcmp(argv[4], "--sha256") && !strcmp(argv[6], "--source") &&
            !strcmp(argv[8], "--output") &&
            (argc == 10 || !strcmp(argv[10], "--ca-file")))
            return holy_rpm_md_sync(argv[3], argv[5], argv[7], argv[9],
                                    argc == 12 ? argv[11] : NULL, NULL);
        if (argc == 6 && (!strcmp(argv[2], "search") || !strcmp(argv[2], "info")) &&
            !strcmp(argv[4], "--catalog"))
            return holy_rpm_md_query(argv[5], argv[3], !strcmp(argv[2], "info"));
        if (argc == 6 && !strcmp(argv[2], "providers") && !strcmp(argv[4], "--catalog"))
            return holy_rpm_md_providers(argv[5], argv[3]);
        if (argc == 8 && !strcmp(argv[2], "providers") &&
            !strcmp(argv[4], "--source") && !strcmp(argv[6], "--root")) {
            char *catalog = NULL;
            int result = holy_rpm_md_catalog_path(argv[7], argv[5], &catalog);
            if (!result) result = holy_rpm_md_providers(catalog, argv[3]);
            free(catalog);
            return result;
        }
        if (argc >= 10 && argc <= 13 && !strcmp(argv[2], "fetch") &&
            !strcmp(argv[6], "--catalog") && !strcmp(argv[8], "--output")) {
            const char *ca_file = NULL;
            int imported = 0, i;
            for (i = 10; i < argc;) {
                if (!strcmp(argv[i], "--import") && !imported) { imported = 1; ++i; }
                else if (i + 1 < argc && !strcmp(argv[i], "--ca-file") && !ca_file) {
                    ca_file = argv[i + 1]; i += 2;
                } else break;
            }
            if (i == argc) return holy_rpm_md_fetch(argv[7], argv[3], argv[4], argv[5],
                                                      argv[9], ca_file, imported);
        }
        fputs("usage: holypkg rpm index REPOMD PRIMARY --sha256 HASH --source NAME --base HTTPS_BASE/ --output NEW_DIRECTORY | rpm sync HTTPS_BASE/ --sha256 HASH --source NAME --output NEW_DIRECTORY [--ca-file FILE] | rpm search|info QUERY --catalog DIRECTORY | rpm providers CAPABILITY --catalog DIRECTORY | rpm providers CAPABILITY --source ALIAS --root DIRECTORY | rpm fetch NAME EVR ARCH --catalog DIRECTORY --output NEW_DIRECTORY [--ca-file FILE] [--import]\n", stderr);
        return 2;
    }
    if (argc > 2 && !strcmp(argv[1], "apt")) {
        if (argc >= 13 && argc <= 17 && !strcmp(argv[2], "sync-source") &&
            !strcmp(argv[7], "--root") && !strcmp(argv[9], "--keyring") &&
            !strcmp(argv[11], "--output")) {
            const char *ca_file = NULL;
            int inrelease = 0, files = 0, i;
            for (i = 13; i < argc; ++i) {
                if (!strcmp(argv[i], "--inrelease") && !inrelease) inrelease = 1;
                else if (!strcmp(argv[i], "--files") && !files) files = 1;
                else if (!strcmp(argv[i], "--ca-file") && !ca_file && i + 1 < argc)
                    ca_file = argv[++i];
                else return 2;
            }
            int result = holy_apt_release_sync_source(argv[8], argv[3], argv[4], argv[5],
                                                      argv[6], argv[10], argv[12],
                                                      ca_file, inrelease, files);
            if (!result) result = holy_apt_bind(argv[8], argv[3], argv[4], argv[5],
                                                argv[6], argv[12]);
            return result;
        }
        if (argc == 10 && !strcmp(argv[2], "bind") && !strcmp(argv[8], "--root"))
            return holy_apt_bind(argv[9], argv[3], argv[4], argv[5], argv[6], argv[7]);
        if (argc >= 13 && argc <= 17 && !strcmp(argv[2], "sync-signed") &&
            !strcmp(argv[7], "--source") && !strcmp(argv[9], "--keyring") &&
            !strcmp(argv[11], "--output")) {
            const char *ca_file = NULL;
            int inrelease = 0, files = 0, i;
            for (i = 13; i < argc; ++i) {
                if (!strcmp(argv[i], "--inrelease") && !inrelease) inrelease = 1;
                else if (!strcmp(argv[i], "--files") && !files) files = 1;
                else if (!strcmp(argv[i], "--ca-file") && !ca_file && i + 1 < argc)
                    ca_file = argv[++i];
                else return 2;
            }
            return holy_apt_release_sync(argv[3], argv[4], argv[5], argv[6],
                                         argv[8], argv[10], argv[12],
                                         ca_file, inrelease, files);
        }
        if ((argc == 12 || argc == 14) && !strcmp(argv[2], "sync") &&
            !strcmp(argv[4], "--sha256") && !strcmp(argv[6], "--source") &&
            !strcmp(argv[8], "--base") && !strcmp(argv[10], "--output") &&
            (argc == 12 || !strcmp(argv[12], "--ca-file")))
            return holy_apt_sync(argv[3], argv[5], argv[7], argv[9], argv[11],
                                 argc == 14 ? argv[13] : NULL);
        if (argc == 12 && !strcmp(argv[2], "index") &&
            !strcmp(argv[4], "--sha256") && !strcmp(argv[6], "--source") &&
            !strcmp(argv[8], "--base") && !strcmp(argv[10], "--output"))
            return holy_apt_index(argv[3], argv[5], argv[7], argv[9], argv[11]);
        if (argc >= 4 && (!strcmp(argv[2], "search") || !strcmp(argv[2], "info"))) {
            const char *catalog = NULL, *source = NULL, *root = NULL;
            const char *suite = NULL, *component = NULL, *index_arch = NULL;
            char *bound = NULL;
            int i, result, file_search = 0;
            for (i = 4; i < argc;) {
                if (!strcmp(argv[i], "--file") && !file_search &&
                    !strcmp(argv[2], "search")) { file_search = 1; ++i; continue; }
                if (i + 1 >= argc) break;
                if (!strcmp(argv[i], "--catalog") && !catalog) catalog = argv[i + 1];
                else if (!strcmp(argv[i], "--source") && !source) source = argv[i + 1];
                else if (!strcmp(argv[i], "--root") && !root) root = argv[i + 1];
                else if (!strcmp(argv[i], "--suite") && !suite) suite = argv[i + 1];
                else if (!strcmp(argv[i], "--component") && !component) component = argv[i + 1];
                else if (!strcmp(argv[i], "--index-arch") && !index_arch) index_arch = argv[i + 1];
                else break;
                i += 2;
            }
            if (i == argc && (!!source == !!root) &&
                ((catalog && !suite && !component && !index_arch) ||
                 (!catalog && source && suite && component && index_arch))) {
                if (!catalog) {
                    result = holy_apt_catalog_path(root, source, suite, component,
                                                   index_arch, &bound);
                    if (result) return result;
                    catalog = bound;
                }
                result = holy_apt_query(catalog, argv[3], !strcmp(argv[2], "info"),
                                        file_search, root, source);
                free(bound);
                return result;
            }
        }
        if (argc >= 8 && !strcmp(argv[2], "fetch")) {
            const char *catalog = NULL, *output = NULL, *ca_file = NULL;
            const char *required_file = NULL;
            const char *source = NULL, *root = NULL;
            const char *suite = NULL, *component = NULL, *index_arch = NULL;
            char *bound = NULL;
            int imported = 0, i, result;
            for (i = 6; i < argc; ++i) {
                if (!strcmp(argv[i], "--catalog") && !catalog && i + 1 < argc) catalog = argv[++i];
                else if (!strcmp(argv[i], "--output") && !output && i + 1 < argc) output = argv[++i];
                else if (!strcmp(argv[i], "--ca-file") && !ca_file && i + 1 < argc) ca_file = argv[++i];
                else if (!strcmp(argv[i], "--require-file") && !required_file && i + 1 < argc)
                    required_file = argv[++i];
                else if (!strcmp(argv[i], "--source") && !source && i + 1 < argc) source = argv[++i];
                else if (!strcmp(argv[i], "--root") && !root && i + 1 < argc) root = argv[++i];
                else if (!strcmp(argv[i], "--suite") && !suite && i + 1 < argc) suite = argv[++i];
                else if (!strcmp(argv[i], "--component") && !component && i + 1 < argc) component = argv[++i];
                else if (!strcmp(argv[i], "--index-arch") && !index_arch && i + 1 < argc) index_arch = argv[++i];
                else if (!strcmp(argv[i], "--import") && !imported) imported = 1;
                else break;
            }
            if (i == argc && output && (!!source == !!root) &&
                ((catalog && !suite && !component && !index_arch) ||
                 (!catalog && source && suite && component && index_arch))) {
                if (!catalog) {
                    result = holy_apt_catalog_path(root, source, suite, component,
                                                   index_arch, &bound);
                    if (result) return result;
                    catalog = bound;
                }
                result = holy_apt_fetch(catalog, argv[3], argv[4], argv[5], output,
                                        ca_file, imported, required_file, root, source);
                free(bound);
                return result;
            }
        }
        fputs("usage: holypkg apt index FILE --sha256 HASH --source NAME --base HTTPS_BASE/ --output NEW_DIRECTORY | apt sync URL --sha256 HASH --source NAME --base HTTPS_BASE/ --output NEW_DIRECTORY [--ca-file FILE] | apt sync-signed HTTPS_BASE/ SUITE COMPONENT ARCH --source NAME --keyring FILE --output NEW_DIRECTORY [--inrelease] [--files] [--ca-file FILE] | apt sync-source ALIAS SUITE COMPONENT ARCH --root DIRECTORY --keyring FILE --output NEW_DIRECTORY [--inrelease] [--files] [--ca-file FILE] | apt bind ALIAS SUITE COMPONENT INDEX_ARCH CATALOG --root ROOT | apt search|info NAME [--file] --catalog DIRECTORY [--source ALIAS --root ROOT] | apt search|info NAME [--file] --source ALIAS --suite SUITE --component COMPONENT --index-arch ARCH --root ROOT | apt fetch NAME VERSION ARCH [--catalog DIRECTORY | --source ALIAS --suite SUITE --component COMPONENT --index-arch ARCH --root ROOT] --output NEW_DIRECTORY [--ca-file FILE] [--import] [--require-file /PATH]\n", stderr);
        return 2;
    }
    if (argc > 1 && !strcmp(argv[1], "apply")) return holy_apply_command(argc, argv);
    if (argc > 2 && !strcmp(argv[1], "xbps")) {
        if ((argc == 12 || argc == 14) && !strcmp(argv[2], "index") &&
            !strcmp(argv[4], "--sha256") && !strcmp(argv[6], "--source") &&
            !strcmp(argv[8], "--base") && !strcmp(argv[10], "--output") &&
            (argc == 12 || !strcmp(argv[12], "--public-key")))
            return holy_xbps_index(argv[3], argv[7], argv[9], argv[11], argv[5],
                                   argc == 14 ? argv[13] : NULL, NULL);
        if (argc >= 11 && argc <= 15 && (argc & 1) && !strcmp(argv[2], "sync") &&
            !strcmp(argv[5], "--sha256") && !strcmp(argv[7], "--source") &&
            !strcmp(argv[9], "--output")) {
            const char *ca_file = NULL, *public_key = NULL;
            int i;
            for (i = 11; i < argc; i += 2) {
                if (!strcmp(argv[i], "--ca-file") && !ca_file) ca_file = argv[i + 1];
                else if (!strcmp(argv[i], "--public-key") && !public_key) public_key = argv[i + 1];
                else break;
            }
            if (i == argc) return holy_xbps_sync(argv[3], argv[4], argv[8], argv[10], argv[6],
                                                  ca_file, public_key, NULL);
        }
        if (argc >= 11 && argc <= 15 && (argc & 1) &&
            !strcmp(argv[2], "sync-source") && !strcmp(argv[5], "--root") &&
            !strcmp(argv[7], "--sha256") && !strcmp(argv[9], "--output")) {
            const char *ca_file = NULL, *public_key = NULL;
            char id[65], registered_key[65], supplied[65];
            char *base = NULL, *trust = NULL;
            int i, result;
            for (i = 11; i < argc; i += 2) {
                if (!strcmp(argv[i], "--ca-file") && !ca_file) ca_file = argv[i + 1];
                else if (!strcmp(argv[i], "--public-key") && !public_key) public_key = argv[i + 1];
                else break;
            }
            if (i != argc) return 2;
            result = holy_source_xbps(argv[6], argv[3], id, &base, &trust, registered_key);
            if (result) return result;
            if ((registered_key[0] &&
                 (!public_key || !holy_xbps_key_fingerprint(public_key, supplied) ||
                  strcmp(supplied, registered_key))) ||
                (!registered_key[0] && public_key)) result = 6;
            else {
                result = holy_xbps_sync(base, argv[4], argv[3], argv[10], argv[8],
                                        ca_file, public_key, id);
                if (!result) result = holy_xbps_bind(argv[6], argv[3], argv[4], argv[10]);
            }
            free(base); free(trust);
            return result;
        }
        if (argc == 6 && (!strcmp(argv[2], "search") || !strcmp(argv[2], "info")) &&
            !strcmp(argv[4], "--catalog"))
            return holy_xbps_query(argv[5], argv[3], !strcmp(argv[2], "info"));
        if (argc == 6 && !strcmp(argv[2], "providers") && !strcmp(argv[4], "--catalog"))
            return holy_xbps_providers(argv[5], argv[3]);
        if (argc == 10 && (!strcmp(argv[2], "search") || !strcmp(argv[2], "info")) &&
            !strcmp(argv[4], "--catalog") && !strcmp(argv[6], "--source") &&
            !strcmp(argv[8], "--root")) {
            int result = xbps_registered_catalog(argv[9], argv[7], argv[5], NULL, 0);
            return result ? result : holy_xbps_query(argv[5], argv[3], !strcmp(argv[2], "info"));
        }
        if (argc == 10 && (!strcmp(argv[2], "search") || !strcmp(argv[2], "info")) &&
            !strcmp(argv[4], "--source") && !strcmp(argv[6], "--index-arch") &&
            !strcmp(argv[8], "--root")) {
            char *catalog = NULL;
            int result = holy_xbps_catalog_path(argv[9], argv[5], argv[7], &catalog);
            if (!result) result = holy_xbps_query(catalog, argv[3], !strcmp(argv[2], "info"));
            free(catalog);
            return result;
        }
        if (argc == 10 && !strcmp(argv[2], "providers") &&
            !strcmp(argv[4], "--source") && !strcmp(argv[6], "--index-arch") &&
            !strcmp(argv[8], "--root")) {
            char *catalog = NULL;
            int result = holy_xbps_catalog_path(argv[9], argv[5], argv[7], &catalog);
            if (!result) result = holy_xbps_providers(catalog, argv[3]);
            free(catalog);
            return result;
        }
        if (argc >= 14 && argc <= 21 && !strcmp(argv[2], "fetch") &&
            !strcmp(argv[6], "--source") && !strcmp(argv[8], "--index-arch") &&
            !strcmp(argv[10], "--root") && !strcmp(argv[12], "--output")) {
            const char *ca_file = NULL, *public_key = NULL, *required_soname = NULL;
            int import = 0;
            char *catalog = NULL;
            int i, result;
            for (i = 14; i < argc;) {
                if (!strcmp(argv[i], "--import") && !import) { import = 1; ++i; continue; }
                if (i + 1 >= argc) break;
                if (!strcmp(argv[i], "--ca-file") && !ca_file) ca_file = argv[i + 1];
                else if (!strcmp(argv[i], "--public-key") && !public_key) public_key = argv[i + 1];
                else if (!strcmp(argv[i], "--require-soname") && !required_soname) required_soname = argv[i + 1];
                else break;
                i += 2;
            }
            if (i != argc || (required_soname && !import)) return 2;
            result = holy_xbps_catalog_path(argv[11], argv[7], argv[9], &catalog);
            if (!result) result = xbps_registered_catalog(argv[11], argv[7], catalog, public_key, 1);
            if (!result) result = holy_xbps_fetch(catalog, argv[3], argv[4], argv[5],
                                                  argv[13], ca_file, public_key, 1, import,
                                                  required_soname);
            free(catalog);
            return result;
        }
        if (argc >= 10 && argc <= 21 && !strcmp(argv[2], "fetch") &&
            !strcmp(argv[6], "--catalog") && !strcmp(argv[8], "--output")) {
            const char *ca_file = NULL, *public_key = NULL, *source = NULL, *root = NULL;
            const char *required_soname = NULL;
            int i, import = 0;
            for (i = 10; i < argc;) {
                if (!strcmp(argv[i], "--import") && !import) { import = 1; ++i; continue; }
                if (i + 1 >= argc) break;
                if (!strcmp(argv[i], "--ca-file") && !ca_file) ca_file = argv[i + 1];
                else if (!strcmp(argv[i], "--public-key") && !public_key) public_key = argv[i + 1];
                else if (!strcmp(argv[i], "--source") && !source) source = argv[i + 1];
                else if (!strcmp(argv[i], "--root") && !root) root = argv[i + 1];
                else if (!strcmp(argv[i], "--require-soname") && !required_soname) required_soname = argv[i + 1];
                else break;
                i += 2;
            }
            if (i == argc && !!source == !!root && (!required_soname || import)) {
                int result = source ? xbps_registered_catalog(root, source, argv[7], public_key, 1) : 0;
                if (result) return result;
                return holy_xbps_fetch(argv[7], argv[3], argv[4], argv[5], argv[9],
                                       ca_file, public_key, !!source, import, required_soname);
            }
        }
        fputs("usage: holypkg xbps index FILE --sha256 HASH --source NAME --base HTTPS_BASE/ --output NEW_DIRECTORY [--public-key FILE] | xbps sync HTTPS_BASE/ ARCH --sha256 HASH --source NAME --output NEW_DIRECTORY [--ca-file FILE] [--public-key FILE] | xbps sync-source ALIAS ARCH --root ROOT --sha256 HASH --output NEW_DIRECTORY [--ca-file FILE] [--public-key FILE] | xbps search|info QUERY --catalog DIRECTORY [--source ALIAS --root ROOT] | xbps search|info QUERY --source ALIAS --index-arch ARCH --root ROOT | xbps providers SONAME --catalog DIRECTORY | xbps providers SONAME --source ALIAS --index-arch ARCH --root ROOT | xbps fetch NAME VERSION ARCH --catalog DIRECTORY --output NEW_DIRECTORY [--ca-file FILE] [--public-key FILE] [--source ALIAS --root ROOT] [--import] [--require-soname SONAME] | xbps fetch NAME VERSION ARCH --source ALIAS --index-arch ARCH --root ROOT --output NEW_DIRECTORY [--ca-file FILE] [--public-key FILE] [--import] [--require-soname SONAME]\n", stderr);
        return 2;
    }
    if (argc > 2 && !strcmp(argv[1], "apk")) {
        if (argc == 6 && !strcmp(argv[2], "verify-index") &&
            !strcmp(argv[4], "--public-key"))
            return holy_apk_verify_index(argv[3], argv[5]);
        if (argc >= 9 && (argc & 1) && !strcmp(argv[2], "sync")) {
            const char *root = NULL, *output = NULL, *sha256 = NULL;
            const char *accepted = NULL, *ca_file = NULL, *public_key = NULL;
            int i;
            for (i = 5; i < argc; i += 2) {
                if (!strcmp(argv[i], "--root") && !root) root = argv[i + 1];
                else if (!strcmp(argv[i], "--output") && !output) output = argv[i + 1];
                else if (!strcmp(argv[i], "--sha256") && !sha256) sha256 = argv[i + 1];
                else if (!strcmp(argv[i], "--accept-unsigned") && !accepted) accepted = argv[i + 1];
                else if (!strcmp(argv[i], "--ca-file") && !ca_file) ca_file = argv[i + 1];
                else if (!strcmp(argv[i], "--public-key") && !public_key) public_key = argv[i + 1];
                else break;
            }
            if (i == argc && root && output && !(sha256 && accepted))
                return holy_apk_sync(root, argv[3], argv[4], output, sha256,
                                     accepted, ca_file, public_key);
        }
        if (argc == 10 && !strcmp(argv[2], "index") && !strcmp(argv[4], "--source") &&
            !strcmp(argv[6], "--base") && !strcmp(argv[8], "--output"))
            return holy_apk_index(argv[3], argv[5], argv[7], argv[9]);
        if ((argc == 8 || argc == 10 || argc == 12) &&
            !strcmp(argv[2], "bind") && !strcmp(argv[6], "--root")) {
            const char *accepted = NULL, *public_key = NULL;
            int i;
            for (i = 8; i < argc; i += 2) {
                if (!strcmp(argv[i], "--accept-unsigned") && !accepted) accepted = argv[i + 1];
                else if (!strcmp(argv[i], "--public-key") && !public_key) public_key = argv[i + 1];
                else break;
            }
            if (i == argc) return holy_apk_bind(argv[7], argv[3], argv[4], argv[5],
                                                  accepted, public_key);
        }
        if (argc >= 6 && !(argc & 1) &&
            (!strcmp(argv[2], "search") || !strcmp(argv[2], "info") ||
             !strcmp(argv[2], "providers"))) {
            const char *catalog = NULL, *source_alias = NULL, *repo = NULL, *root = NULL;
            char *bound = NULL;
            int i, result;
            for (i = 4; i < argc; i += 2) {
                if (!strcmp(argv[i], "--catalog") && !catalog) catalog = argv[i + 1];
                else if (!strcmp(argv[i], "--source") && !source_alias) source_alias = argv[i + 1];
                else if (!strcmp(argv[i], "--repo") && !repo) repo = argv[i + 1];
                else if (!strcmp(argv[i], "--root") && !root) root = argv[i + 1];
                else break;
            }
            if (i == argc && ((catalog && !source_alias && !repo && !root) ||
                              (!catalog && source_alias && repo && root))) {
                if (!catalog) {
                    result = holy_apk_catalog_path(root, source_alias, repo, &bound);
                    if (result) return result;
                    catalog = bound;
                }
                const char *query = argv[3];
                int mode = !strcmp(argv[2], "info") ? 1 :
                           !strcmp(argv[2], "providers") ? 2 : 0;
                if (mode == 2) {
                    if (strncmp(query, "soname:", 7)) { free(bound); return 2; }
                    query += 7;
                }
                result = holy_apk_query(catalog, query, mode);
                free(bound);
                return result;
            }
        }
        if (argc >= 9 && (!strcmp(argv[2], "fetch") ||
                          !strcmp(argv[2], "fetch-provider"))) {
            const char *catalog = NULL, *output = NULL, *sha256 = NULL;
            const char *ca_file = NULL, *root = NULL, *source_alias = NULL, *repo = NULL;
            const char *public_key = NULL, *required_soname = NULL;
            const char *required_file = NULL;
            char *bound = NULL;
            int provider = !strcmp(argv[2], "fetch-provider");
            int i, result, import = provider;
            if (provider && strncmp(argv[3], "soname:", 7)) return 2;
            for (i = provider ? 5 : 6; i < argc;) {
                if (!provider && !strcmp(argv[i], "--import") && !import) {
                    import = 1; ++i; continue;
                }
                if (i + 1 >= argc) break;
                if (!strcmp(argv[i], "--catalog") && !catalog) catalog = argv[i + 1];
                else if (!strcmp(argv[i], "--output") && !output) output = argv[i + 1];
                else if (!strcmp(argv[i], "--repo") && !repo) repo = argv[i + 1];
                else if (!strcmp(argv[i], "--sha256") && !sha256) sha256 = argv[i + 1];
                else if (!strcmp(argv[i], "--ca-file") && !ca_file) ca_file = argv[i + 1];
                else if (!strcmp(argv[i], "--public-key") && !public_key) public_key = argv[i + 1];
                else if (!strcmp(argv[i], "--root") && !root) root = argv[i + 1];
                else if (!strcmp(argv[i], "--source") && !source_alias) source_alias = argv[i + 1];
                else if (!strcmp(argv[i], "--require-soname") && !required_soname) required_soname = argv[i + 1];
                else if (!strcmp(argv[i], "--require-file") && !required_file) required_file = argv[i + 1];
                else break;
                i += 2;
            }
            if (i == argc && output && (!required_soname || import) &&
                (!required_file || import) &&
                (!provider || (!required_soname && !required_file)) &&
                ((catalog && !repo && (!source_alias || root)) ||
                 (!catalog && source_alias && repo && root))) {
                if (!catalog) {
                    result = holy_apk_catalog_path(root, source_alias, repo, &bound);
                    if (result) return result;
                    catalog = bound;
                }
                result = provider ?
                    holy_apk_fetch_provider(catalog, argv[3] + 7, argv[4], output,
                                            sha256, ca_file, root, source_alias,
                                            public_key) :
                    holy_apk_fetch(catalog, argv[3], argv[4], argv[5], output,
                                   sha256, ca_file, root, source_alias, public_key,
                                   import, required_soname, required_file);
                free(bound);
                return result;
            }
        }
        fputs("usage: holypkg apk verify-index FILE --public-key FILE | apk sync SOURCE REPO --root DIRECTORY --output NEW_DIRECTORY [--sha256 HASH | --accept-unsigned HASH] [--ca-file FILE] [--public-key FILE] | apk bind SOURCE REPO CATALOG --root DIRECTORY [--accept-unsigned HASH] [--public-key FILE] | apk index FILE --source NAME --base URL --output NEW_DIRECTORY | apk search|info NAME [--catalog DIRECTORY | --source SOURCE --repo REPO --root DIRECTORY] | apk providers soname:NAME [--catalog DIRECTORY | --source SOURCE --repo REPO --root DIRECTORY] | apk fetch-provider soname:NAME ARCH --output NEW_DIRECTORY [--catalog DIRECTORY | --source SOURCE --repo REPO --root DIRECTORY] [--sha256 HASH] [--ca-file FILE] [--public-key FILE] | apk fetch NAME VERSION ARCH --output NEW_DIRECTORY [--catalog DIRECTORY | --source SOURCE --repo REPO --root DIRECTORY] [--sha256 HASH] [--ca-file FILE] [--public-key FILE] [--import] [--require-soname SONAME] [--require-file /PATH]\n", stderr);
        return 2;
    }
    if (argc > 1 && !strcmp(argv[1], "search") && argc > 2)
        return query_source(argc, argv, 1);
    if (argc > 2 && !strcmp(argv[1], "info") &&
        strncmp(argv[2], "local:", 6))
        return query_source(argc, argv, 0);

    if (argc > 1 && !strcmp(argv[1], "import")) {
        if (argc == 9 && !strcmp(argv[3], "--source") && !strcmp(argv[5], "--format") &&
            !strcmp(argv[7], "--output")) {
            if (!strcmp(argv[6], "pacman")) return holy_import_pacman(argv[2], argv[4], argv[8]);
            if (!strcmp(argv[6], "rpm")) return holy_import_rpm(argv[2], argv[4], argv[8]);
            if (!strcmp(argv[6], "deb")) return holy_import_deb(argv[2], argv[4], argv[8]);
            if (!strcmp(argv[6], "slackware")) return holy_import_slackware(argv[2], argv[4], argv[8]);
            if (!strcmp(argv[6], "apk")) return holy_import_apk(argv[2], argv[4], argv[8], NULL);
            if (!strcmp(argv[6], "xbps")) return holy_import_xbps(argv[2], argv[4], argv[8]);
            if (!strcmp(argv[6], "appimage")) return holy_import_appimage(argv[2], argv[4], argv[8]);
            if (!strcmp(argv[6], "pkgbuild")) return holy_convert_pkgbuild(argv[2], argv[4], argv[8]);
            if (!strcmp(argv[6], "void")) return holy_convert_voidsrc(argv[2], argv[4], argv[8]);
            if (!strcmp(argv[6], "aports")) return holy_convert_aports(argv[2], argv[4], argv[8]);
            if (!strcmp(argv[6], "slackbuild")) {
                return holy_convert_slackbuild(argv[2], argv[4], argv[8]);
            }
            if (!strcmp(argv[6], "rpmspec")) {
                return holy_convert_rpmspec(argv[2], argv[4], argv[8]);
            }
        }
        if (argc == 11 && !strcmp(argv[3], "--source") && !strcmp(argv[5], "--format") &&
            !strcmp(argv[6], "apk") && !strcmp(argv[7], "--output") &&
            !strcmp(argv[9], "--public-key"))
            return holy_import_apk(argv[2], argv[4], argv[8], argv[10]);
        fputs("usage: holypkg import INPUT --source NAME --format pacman|rpm|deb|slackware|apk|xbps|appimage|pkgbuild|void|aports|slackbuild|rpmspec --output DIRECTORY [--public-key FILE (apk only)]\n", stderr);
        return 2;
    }

    if (argc > 1 && !strcmp(argv[1], "convert")) {
        if (argc == 7 && !strcmp(argv[3], "--source") && !strcmp(argv[5], "--output")) {
            /* the family follows the upstream file name each builder uses */
            const char *base = strrchr(argv[2], '/');
            base = base ? base + 1 : argv[2];
            if (!strcmp(base, "template")) return holy_convert_voidsrc(argv[2], argv[4], argv[6]);
            if (!strcmp(base, "APKBUILD")) return holy_convert_aports(argv[2], argv[4], argv[6]);
            {
                size_t at = strlen(base);
                if (at > 11 && !strcmp(base + at - 11, ".SlackBuild")) {
                    return holy_convert_slackbuild(argv[2], argv[4], argv[6]);
                }
                if (at > 5 && !strcmp(base + at - 5, ".spec")) {
                    return holy_convert_rpmspec(argv[2], argv[4], argv[6]);
                }
            }
            return holy_convert_pkgbuild(argv[2], argv[4], argv[6]);
        }
        fputs("usage: holypkg convert PKGBUILD|APKBUILD|NAME.SlackBuild|NAME.spec|TEMPLATE --source NAME --output NEW_DIRECTORY\n",
              stderr);
        return 2;
    }

    if (argc > 1 && !strcmp(argv[1], "appimage")) {
        if (argc == 4 && !strcmp(argv[2], "inspect")) return holy_appimage_inspect(argv[3]);
        if (argc == 6 && !strcmp(argv[2], "extract") && !strcmp(argv[4], "--output"))
            return holy_appimage_extract(argv[3], argv[5]);
        fputs("usage: holypkg appimage inspect INPUT | appimage extract INPUT --output NEW_DIRECTORY\n", stderr);
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
        if (argc == 6 && !strcmp(argv[2], "show") && !strcmp(argv[4], "--root"))
            return holy_source_show(argv[5], argv[3]);
        fputs("usage: holypkg source plan --config FILE --root DIRECTORY | source apply PLAN --sha256 HASH --root DIRECTORY | source list --root DIRECTORY | source show ALIAS --root DIRECTORY | source catalog bind ALIAS MIRROR [--root DIRECTORY]\n", stderr);
        return 2;
    }

    if (argc > 1 && !strcmp(argv[1], "sync")) {
        const char *root = "/", *digest = NULL, *accepted = NULL;
        const char *output = NULL, *ca_file = NULL, *commit = NULL;
        const char *repo = NULL, *public_key = NULL, *arch = NULL;
        const char *suite = NULL, *component = NULL, *index_arch = NULL;
        const char *keyring = NULL;
        char *family = NULL;
        char **repos = NULL;
        size_t repo_count = 0, j;
        int result;
        int i, root_seen = 0, inrelease = 0, files = 0, valid = argc >= 3;
        for (i = 3; valid && i < argc;) {
            if (!strcmp(argv[i], "--inrelease") && !inrelease) {
                inrelease = 1; ++i; continue;
            }
            if (!strcmp(argv[i], "--files") && !files) {
                files = 1; ++i; continue;
            }
            if (i + 1 >= argc || !argv[i + 1][0] ||
                !strncmp(argv[i + 1], "--", 2)) { valid = 0; break; }
            if (!strcmp(argv[i], "--root") && !root_seen) {
                root = argv[i + 1]; root_seen = 1;
            }
            else if (!strcmp(argv[i], "--sha256") && !digest) digest = argv[i + 1];
            else if (!strcmp(argv[i], "--accept-unsigned") && !accepted) accepted = argv[i + 1];
            else if (!strcmp(argv[i], "--output") && !output) output = argv[i + 1];
            else if (!strcmp(argv[i], "--ca-file") && !ca_file) ca_file = argv[i + 1];
            else if (!strcmp(argv[i], "--commit") && !commit) commit = argv[i + 1];
            else if (!strcmp(argv[i], "--repo") && !repo) repo = argv[i + 1];
            else if (!strcmp(argv[i], "--public-key") && !public_key) public_key = argv[i + 1];
            else if (!strcmp(argv[i], "--arch") && !arch) arch = argv[i + 1];
            else if (!strcmp(argv[i], "--suite") && !suite) suite = argv[i + 1];
            else if (!strcmp(argv[i], "--component") && !component) component = argv[i + 1];
            else if (!strcmp(argv[i], "--index-arch") && !index_arch) index_arch = argv[i + 1];
            else if (!strcmp(argv[i], "--keyring") && !keyring) keyring = argv[i + 1];
            else valid = 0;
            i += 2;
        }
        if (valid && !(digest && accepted)) {
            if ((!!suite + !!component + !!index_arch) % 3 != 0) goto sync_usage;
            result = holy_source_type(root, argv[2], &family);
            if (result) return result;
            if (!strcmp(family, "apk")) {
                free(family);
                if (commit || arch || suite || keyring || inrelease || files ||
                    !output) goto sync_usage;
                if (!repo) {
                    result = holy_source_apk_repos(root, argv[2], &repos, &repo_count);
                    if (result) return result;
                    if (repo_count != 1) {
                        fprintf(stderr, "holypkg: APK source %s has %zu repositories; select --repo\n",
                                argv[2], repo_count);
                        result = 3; goto sync_done;
                    }
                    repo = repos[0];
                }
                result = holy_apk_sync(root, argv[2], repo, output, digest,
                                       accepted, ca_file, public_key);
sync_done:
                for (j = 0; j < repo_count; ++j) free(repos[j]);
                free(repos);
                return result;
            }
            if (!strcmp(family, "xbps")) {
                char id[65], registered_key[65], supplied[65];
                char *base = NULL, *trust = NULL;
                free(family);
                if (!arch || !digest || !output || repo || accepted || commit ||
                    suite || keyring || inrelease || files)
                    goto sync_usage;
                result = holy_source_xbps(root, argv[2], id, &base, &trust,
                                          registered_key);
                if (result) return result;
                if ((registered_key[0] &&
                     (!public_key || !holy_xbps_key_fingerprint(public_key, supplied) ||
                      strcmp(supplied, registered_key))) ||
                    (!registered_key[0] && public_key)) result = 6;
                else {
                    result = holy_xbps_sync(base, arch, argv[2], output,
                                            digest, ca_file, public_key, id);
                    if (!result) result = holy_xbps_bind(root, argv[2], arch, output);
                }
                free(base); free(trust);
                return result;
            }
            if (!strcmp(family, "rpm-md")) {
                char id[65];
                char *base = NULL, *trust = NULL;
                free(family);
                if (!digest || !output || repo || arch || accepted || commit ||
                    public_key || suite || keyring || inrelease || files)
                    goto sync_usage;
                result = holy_source_rpm_md(root, argv[2], id, &base, &trust);
                if (result) { free(base); free(trust); return result; }
                result = holy_rpm_md_sync(base, digest, argv[2], output, ca_file, id);
                if (!result) result = holy_rpm_md_bind(root, argv[2], output);
                free(base); free(trust);
                return result;
            }
            if (!strcmp(family, "apt")) {
                free(family);
                if (!suite || !keyring || !output || repo || arch || digest ||
                    accepted || commit || public_key) goto sync_usage;
                result = holy_apt_release_sync_source(root, argv[2], suite,
                            component, index_arch, keyring, output, ca_file,
                            inrelease, files);
                if (!result) result = holy_apt_bind(root, argv[2], suite,
                                             component, index_arch, output);
                return result;
            }
            free(family);
            if (!repo && !public_key && !arch && !suite && !keyring &&
                !inrelease && !files)
                return holy_source_sync(argv[2], root, digest, accepted, output,
                                        ca_file, commit);
        }
sync_usage:
        fputs("usage: holypkg sync SOURCE [--root DIRECTORY] [--output NEW_DIRECTORY] [--sha256 INDEX_SHA256 | --accept-unsigned INDEX_SHA256] [--commit GIT_COMMIT] [--ca-file FILE] | holypkg sync APK_SOURCE [--repo REPO] --output NEW_DIRECTORY [--root DIRECTORY] [--sha256 HASH | --accept-unsigned HASH] [--ca-file FILE] [--public-key FILE] | holypkg sync XBPS_SOURCE --arch ARCH --sha256 HASH --output NEW_DIRECTORY [--root DIRECTORY] [--ca-file FILE] [--public-key FILE] | holypkg sync APT_SOURCE --suite SUITE --component COMPONENT --index-arch ARCH --keyring FILE --output NEW_DIRECTORY [--root DIRECTORY] [--inrelease] [--files] [--ca-file FILE] | holypkg sync RPM_MD_SOURCE --sha256 REPOMD_SHA256 --output NEW_DIRECTORY [--root DIRECTORY] [--ca-file FILE]\n", stderr);
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

    if (argc > 1 && !strcmp(argv[1], "rollback")) {
        const char *root = "/", *approved = NULL, *arch = NULL, *privileged = NULL;
        int i, root_seen = 0;
        if (argc < 3) goto rollback_usage;
        for (i = 3; i < argc; ++i) {
            if (!strcmp(argv[i], "--root") && !root_seen && i + 1 < argc) {
                root = argv[++i]; root_seen = 1;
            } else if (!strcmp(argv[i], "--apply") && !approved && i + 1 < argc)
                approved = argv[++i];
            else if (!strcmp(argv[i], "--accept-arch") && !arch && i + 1 < argc)
                arch = argv[++i];
            else if (!strcmp(argv[i], "--accept-privileged") && !privileged && i + 1 < argc)
                privileged = argv[++i];
            else goto rollback_usage;
        }
        return holy_state_rollback(argv[2], approved, arch, privileged, root);
rollback_usage:
        fputs("usage: holypkg rollback TRANSACTION [--root DIRECTORY] [--apply PLAN_SHA256] [--accept-arch ARTIFACT_SHA256] [--accept-privileged ARTIFACT_SHA256]\n", stderr);
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
    if (argc == 5 && !strcmp(argv[1], "cache") &&
        !strcmp(argv[2], "list") && !strcmp(argv[3], "--root"))
        return holy_cache_list(argv[4]);
    if (argc == 6 && !strcmp(argv[1], "cache") &&
        !strcmp(argv[2], "clean") && !strcmp(argv[4], "--root"))
        return holy_cache_clean(argv[3], argv[5], 0, 0);
    if (argc == 7 && !strcmp(argv[1], "cache") &&
        !strcmp(argv[2], "clean") && !strcmp(argv[4], "--root") &&
        !strcmp(argv[6], "--yes"))
        return holy_cache_clean(argv[3], argv[5], 1, 0);
    if (argc == 8 && !strcmp(argv[1], "cache") &&
        !strcmp(argv[2], "clean") && !strcmp(argv[4], "--root") &&
        !strcmp(argv[6], "--yes") && !strcmp(argv[7], "--accept-unavailable"))
        return holy_cache_clean(argv[3], argv[5], 1, 1);
    if (argc > 1 && !strcmp(argv[1], "cache")) {
        fputs("usage: holypkg cache stage local:FILE --root DIRECTORY | cache verify SHA256 --root DIRECTORY | cache list --root DIRECTORY | cache clean SHA256 --root DIRECTORY [--yes [--accept-unavailable]]\n", stderr);
        return 2;
    }
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
    if (argc == 6 && !strcmp(argv[1], "db") && !strcmp(argv[2], "configure-plan") &&
        !strcmp(argv[4], "--root")) return holy_state_configure(argv[3], NULL, argv[5], 0);
    if (argc == 7 && !strcmp(argv[1], "db") && !strcmp(argv[2], "configure-apply") &&
        !strcmp(argv[5], "--root")) return holy_state_configure(argv[4], argv[3], argv[6], 0);
    if (argc == 7 && !strcmp(argv[1], "db") && !strcmp(argv[2], "configure-recover") &&
        !strcmp(argv[4], "--retry") && !strcmp(argv[5], "--root"))
        return holy_state_configure(argv[3], NULL, argv[6], 1);
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
        const char **digests, **bindings, **accepted_arch, **accepted_privileged, **skipped_hooks;
        size_t count = 0, binding_count = 0, accepted_count = 0, privileged_count = 0, skipped_count = 0;
        int i, result = 2;
        if (strcmp(argv[argc - 2], "--root")) return 2;
        digests = calloc((size_t)argc, sizeof *digests);
        bindings = calloc((size_t)argc, sizeof *bindings);
        accepted_arch = calloc((size_t)argc, sizeof *accepted_arch);
        accepted_privileged = calloc((size_t)argc, sizeof *accepted_privileged);
        skipped_hooks = calloc((size_t)argc, sizeof *skipped_hooks);
        if (!digests || !bindings || !accepted_arch || !accepted_privileged || !skipped_hooks) {
            free(digests); free(bindings); free(accepted_arch); free(accepted_privileged); free(skipped_hooks); return 1;
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
            } else if (!strcmp(argv[i], "--skip-hooks")) {
                if (++i >= end) goto set_done;
                skipped_hooks[skipped_count++] = argv[i];
            } else if (argv[i][0] == '-') goto set_done;
            else digests[count++] = argv[i];
        }
        if (count) result = holy_state_set(digests, count, choice,
                                          start == 4 ? argv[3] : NULL, argv[argc - 1],
                                          bindings, binding_count, accepted_arch, accepted_count,
                                          accepted_privileged, privileged_count,
                                          skipped_hooks, skipped_count, NULL);
set_done:
        free(digests); free(bindings); free(accepted_arch); free(accepted_privileged); free(skipped_hooks);
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

    if (argc > 1 && !strcmp(argv[1], "owner")) {
        if (argc == 3) return holy_state_owner(argv[2], "/");
        if (argc == 5 && !strcmp(argv[3], "--root"))
            return holy_state_owner(argv[2], argv[4]);
        fputs("usage: holypkg owner PATH [--root DIRECTORY]\n", stderr);
        return 2;
    }

    if (argc > 1 && !strcmp(argv[1], "rm"))
        return installed_ref(argc, argv, 1);
    if (argc > 1 && !strcmp(argv[1], "repair"))
        return installed_ref(argc, argv, 4);
    if (argc > 1 && !strcmp(argv[1], "files"))
        return installed_ref(argc, argv, 2);
    if (argc > 1 && !strcmp(argv[1], "why"))
        return installed_ref(argc, argv, 3);
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
        fprintf(stderr, "usage: holypkg check [SOURCE:PACKAGE] [--root DIRECTORY] [--json] | holypkg files SOURCE:PACKAGE [--root DIRECTORY] | holypkg rm SOURCE:PACKAGE [--root DIRECTORY] [--yes] [--accept-broken] | holypkg run SOURCE:PACKAGE [--root DIRECTORY] [--arch ARCH] [--libc LIBC] -- COMMAND [ARGS...] | holypkg add local:FILE [--candidate local:FILE...] [--choose ID=SHA256] [--skip-hooks SHA256...] [--root DIRECTORY] [--yes] [--noninteractive] | holypkg config check FILE | holypkg info|verify|manifest|scan local:FILE | holypkg manifest generate DIRECTORY --output FILE | holypkg requirements|provides local:FILE [--json] | holypkg solve local:ROOT [local:CANDIDATE...] [--choose REQUIREMENT_ID=SHA256] [--json] | holypkg fetch local:FILE [--extract] --output DIRECTORY | holypkg fetch https://URL --sha256 SHA256 --output DIRECTORY [--ca-file FILE] | holypkg pack DIRECTORY --output FILE.holy | holypkg check|preview local:FILE --root DIRECTORY [--json] | holypkg cache stage local:FILE --root DIRECTORY | holypkg cache verify SHA256 --root DIRECTORY | holypkg db init|status|cancel|recover|preflight|plan|recheck|apply --root DIRECTORY | holypkg db recover --abort-empty|--continue|--finish-apply --root DIRECTORY | holypkg db check SHA256|--all --root DIRECTORY [--json] | holypkg db rm SHA256 [--accept-broken] --root DIRECTORY | holypkg db owner PATH --root DIRECTORY | holypkg db status|preflight --root DIRECTORY --json | holypkg db reserve SHA256 --root DIRECTORY | holypkg db plan-set ROOT_SHA256 [CANDIDATE_SHA256...] [--choose ID=SHA256] [--source ARTIFACT=SOURCE_ID...] [--accept-arch SHA256...] [--accept-privileged SHA256...] [--skip-hooks SHA256...] --root DIRECTORY | holypkg db apply-set PLAN_SHA256 ROOT_SHA256 [CANDIDATE_SHA256...] [--choose ID=SHA256] [--source ARTIFACT=SOURCE_ID...] [--accept-arch SHA256...] [--accept-privileged SHA256...] [--skip-hooks SHA256...] --root DIRECTORY | holypkg db recover --finish-set|--continue-set|--repair --root DIRECTORY | holypkg db configure-plan SHA256 --root DIRECTORY | holypkg db configure-apply PLAN_SHA256 SHA256 --root DIRECTORY | holypkg db configure-recover SHA256 --retry --root DIRECTORY | holypkg db plan-update OLD_SHA256 NEW_SHA256 [--accept-arch NEW_SHA256] [--accept-privileged NEW_SHA256] --root DIRECTORY | holypkg db apply-update PLAN_SHA256 OLD_SHA256 NEW_SHA256 [--accept-arch NEW_SHA256] [--accept-privileged NEW_SHA256] --root DIRECTORY | holypkg db recover --update --root DIRECTORY | holypkg db repair-plan SHA256 --root DIRECTORY | holypkg db repair SHA256 --plan PLAN_SHA256 --root DIRECTORY | holypkg db approve PLAN_SHA256 --root DIRECTORY | holypkg elf FILE | holypkg repo index|list|seal DIRECTORY | holypkg repo requirements DIRECTORY NAME | holypkg repo search DIRECTORY NAME [--fuzzy] | holypkg repo search-file DIRECTORY NAME_OR_PATH [--fuzzy] | holypkg repo solve DIRECTORY NAME [--choose REQUIREMENT_ID=SHA256] [--json] | holypkg repo providers DIRECTORY KIND NAME [--json] | holypkg repo fetch DIRECTORY SHA256 --output DIRECTORY\n");
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
