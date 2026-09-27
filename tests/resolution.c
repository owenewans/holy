#include "../src/resolve.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int record_limits(void)
{
    struct holy_resolution result = {0};
    struct holy_resolved_edge edge;
    char *artifacts[] = {result.root};
    char *record = NULL, *large;
    size_t length = 0;
    memset(result.root, 'a', 64);
    result.artifacts = artifacts;
    result.artifact_count = 1;
    result.edges = &edge;
    result.edge_count = 1;
    edge.consumer = result.root;
    edge.provider = result.root;
    edge.id = "edge-1";
    edge.path = "usr/lib/test";
    edge.kind = "symbol";
    edge.target = "quote\" slash\\ tab\t";
    if (!holy_resolution_record(&result, &record, &length) ||
        !strstr(record, "quote\\\" slash\\\\ tab\\x09")) abort();
    free(record);
    large = malloc(4 * 1024 * 1024 + 1);
    if (!large) abort();
    memset(large, 1, 4 * 1024 * 1024);
    large[4 * 1024 * 1024] = 0;
    edge.target = large;
    if (holy_resolution_record(&result, &record, &length) || record || length) abort();
    free(large);
    return 0;
}

int main(int argc, char **argv)
{
    struct holy_resolution result;
    char *record = NULL;
    size_t length = 0;
    int status;
    if (argc == 1) return record_limits();
    if (argc < 3) return 2;
    status = !strcmp(argv[1], "--set") ?
             holy_resolve_collect_set((const char *const *)(argv + 2),
                                      (size_t)argc - 2, &result) :
             holy_resolve_collect((const char *const *)(argv + 2),
                                  (size_t)argc - 2,
                                  strcmp(argv[1], "-") ? argv[1] : NULL, &result);
    if (status) {
        if (result.root[0] || result.artifacts || result.edges ||
            result.artifact_count || result.edge_count) abort();
    } else {
        if (!holy_resolution_record(&result, &record, &length)) abort();
        if (fwrite(record, 1, length, stdout) != length) abort();
    }
    free(record);
    holy_resolution_free(&result);
    holy_resolution_free(&result);
    return status;
}
