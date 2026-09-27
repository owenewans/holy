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

#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    struct holy_config config = {0};
    char *error = NULL;
    const char *path;
    int ok;

    setlocale(LC_CTYPE, "");

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
    if (argc >= 6 && !strcmp(argv[1], "db") &&
        (!strcmp(argv[2], "plan-set") || !strcmp(argv[2], "apply-set"))) {
        int start = !strcmp(argv[2], "apply-set") ? 4 : 3;
        int end = argc - 2;
        const char *choice = NULL;
        if (strcmp(argv[argc - 2], "--root")) return 2;
        if (end >= start + 2 && !strcmp(argv[end - 2], "--choose")) {
            choice = argv[end - 1];
            end -= 2;
        }
        if (end <= start) return 2;
        return holy_state_set((const char *const *)(argv + start), (size_t)(end - start),
                              choice, start == 4 ? argv[3] : NULL, argv[argc - 1]);
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
        return holy_state_remove(argv[3], argv[5]);
    if (argc == 6 && !strcmp(argv[1], "db") &&
        !strcmp(argv[2], "owner") && !strcmp(argv[4], "--root"))
        return holy_state_owner(argv[3], argv[5]);

    if (argc == 3 && !strcmp(argv[1], "info") &&
        !strncmp(argv[2], "local:", 6) && argv[2][6])
        return holy_package_info(argv[2] + 6) ? 0 : 2;
    if (argc == 3 && !strcmp(argv[1], "verify") &&
        !strncmp(argv[2], "local:", 6) && argv[2][6])
        return holy_verify(argv[2] + 6) ? 0 : 2;
    if ((argc == 7 || argc == 9) && !strcmp(argv[1], "fetch") &&
        !strcmp(argv[3], "--sha256") && !strcmp(argv[5], "--output") &&
        (argc == 7 || !strcmp(argv[7], "--ca-file")))
        return holy_fetch_https(argv[2], argv[4], argv[6],
                                argc == 9 ? argv[8] : NULL);
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
    if (argc != 4 || strcmp(argv[1], "config") || strcmp(argv[2], "check")) {
        fprintf(stderr, "usage: holypkg config check FILE | holypkg info|verify|manifest|scan local:FILE | holypkg manifest generate DIRECTORY --output FILE | holypkg requirements|provides local:FILE [--json] | holypkg solve local:ROOT [local:CANDIDATE...] [--choose REQUIREMENT_ID=SHA256] [--json] | holypkg fetch local:FILE [--extract] --output DIRECTORY | holypkg fetch https://URL --sha256 SHA256 --output DIRECTORY [--ca-file FILE] | holypkg pack DIRECTORY --output FILE.holy | holypkg check|preview local:FILE --root DIRECTORY [--json] | holypkg cache stage local:FILE --root DIRECTORY | holypkg cache verify SHA256 --root DIRECTORY | holypkg db init|status|cancel|recover|preflight|plan|recheck|apply --root DIRECTORY | holypkg db recover --abort-empty|--continue|--finish-apply --root DIRECTORY | holypkg db check SHA256|--all --root DIRECTORY [--json] | holypkg db rm SHA256 --root DIRECTORY | holypkg db owner PATH --root DIRECTORY | holypkg db status|preflight --root DIRECTORY --json | holypkg db reserve SHA256 --root DIRECTORY | holypkg db plan-set ROOT_SHA256 [CANDIDATE_SHA256...] [--choose ID=SHA256] --root DIRECTORY | holypkg db apply-set PLAN_SHA256 ROOT_SHA256 [CANDIDATE_SHA256...] [--choose ID=SHA256] --root DIRECTORY | holypkg db recover --finish-set|--continue-set --root DIRECTORY | holypkg db approve PLAN_SHA256 --root DIRECTORY | holypkg elf FILE | holypkg repo index|list|seal DIRECTORY | holypkg repo search DIRECTORY NAME | holypkg repo solve DIRECTORY NAME [--choose REQUIREMENT_ID=SHA256] [--json] | holypkg repo providers DIRECTORY KIND NAME [--json] | holypkg repo fetch DIRECTORY SHA256 --output DIRECTORY\n");
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
