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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    struct holy_config config = {0};
    char *error = NULL;
    const char *path;
    int ok;

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
                printf("version-def %s\n", info.defined_versions[i]);
        }
        else fprintf(stderr, "holypkg: %s ELF input\n", rc == 1 ? "not an" : "invalid");
        holy_elf_free(&info);
        return rc ? 2 : 0;
    }
    if (argc == 3 && !strcmp(argv[1], "scan") &&
        !strncmp(argv[2], "local:", 6) && argv[2][6])
        return holy_scan_local(argv[2] + 6) ? 0 : 2;
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
        const char **paths;
        int i, result;
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
        result = holy_resolve_local(paths, (size_t)last - 2, json, NULL);
        free(paths);
        return result;
    }
    if (argc == 4 && !strcmp(argv[1], "repo") &&
        !strcmp(argv[2], "index"))
        return holy_repo_index(argv[3]) ? 0 : 1;
    if (argc == 4 && !strcmp(argv[1], "repo") &&
        !strcmp(argv[2], "list"))
        return holy_repo_list(argv[3]) ? 0 : 1;
    if (argc == 5 && !strcmp(argv[1], "repo") &&
        !strcmp(argv[2], "search"))
        return holy_repo_search(argv[3], argv[4]) ? 0 : 1;
    if (argc == 5 && !strcmp(argv[1], "repo") &&
        !strcmp(argv[2], "solve"))
        return holy_repo_solve(argv[3], argv[4], 0);
    if (argc == 6 && !strcmp(argv[1], "repo") &&
        !strcmp(argv[2], "solve") && !strcmp(argv[5], "--json"))
        return holy_repo_solve(argv[3], argv[4], 1);
    if (argc == 6 && !strcmp(argv[1], "repo") &&
        !strcmp(argv[2], "providers"))
        return holy_repo_providers(argv[3], argv[4], argv[5], 0) ? 0 : 1;
    if (argc == 7 && !strcmp(argv[1], "repo") &&
        !strcmp(argv[2], "providers") && !strcmp(argv[6], "--json"))
        return holy_repo_providers(argv[3], argv[4], argv[5], 1) ? 0 : 1;
    if (argc == 4 && !strcmp(argv[1], "repo") &&
        !strcmp(argv[2], "seal"))
        return holy_repo_seal(argv[3]) ? 0 : 1;
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
    if (argc == 5 && !strcmp(argv[1], "db") && !strcmp(argv[3], "--root")) {
        if (!strcmp(argv[2], "init")) return holy_state_init(argv[4]) ? 0 : 1;
        if (!strcmp(argv[2], "status")) return holy_state_status(argv[4]) ? 0 : 1;
    }

    if (argc == 3 && !strcmp(argv[1], "info") &&
        !strncmp(argv[2], "local:", 6) && argv[2][6])
        return holy_package_info(argv[2] + 6) ? 0 : 2;
    if (argc == 3 && !strcmp(argv[1], "verify") &&
        !strncmp(argv[2], "local:", 6) && argv[2][6])
        return holy_verify(argv[2] + 6) ? 0 : 2;
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
        return holy_check_local(argv[2] + 6, argv[4], 0) ? 0 : 1;
    if (argc == 5 && !strcmp(argv[1], "preview") &&
        !strncmp(argv[2], "local:", 6) && argv[2][6] &&
        !strcmp(argv[3], "--root"))
        return holy_preview_local(argv[2] + 6, argv[4]);
    if (argc == 6 && !strcmp(argv[1], "check") &&
        !strncmp(argv[2], "local:", 6) && argv[2][6] &&
        !strcmp(argv[3], "--root") && !strcmp(argv[5], "--json"))
        return holy_check_local(argv[2] + 6, argv[4], 1) ? 0 : 1;
    if (argc != 4 || strcmp(argv[1], "config") || strcmp(argv[2], "check")) {
        fprintf(stderr, "usage: holypkg config check FILE | holypkg info local:FILE | holypkg verify local:FILE | holypkg requirements local:FILE [--json] | holypkg provides local:FILE [--json] | holypkg solve local:ROOT [local:CANDIDATE...] [--json] | holypkg fetch local:FILE [--extract] --output DIRECTORY | holypkg check local:FILE --root DIRECTORY [--json] | holypkg preview local:FILE --root DIRECTORY | holypkg cache stage local:FILE --root DIRECTORY | holypkg cache verify SHA256 --root DIRECTORY | holypkg db init|status --root DIRECTORY | holypkg elf FILE | holypkg scan local:FILE | holypkg repo index DIRECTORY | holypkg repo list DIRECTORY | holypkg repo search DIRECTORY NAME | holypkg repo solve DIRECTORY NAME [--json] | holypkg repo providers DIRECTORY KIND NAME [--json] | holypkg repo seal DIRECTORY | holypkg repo fetch DIRECTORY SHA256 --output DIRECTORY\n");
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
