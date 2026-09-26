#include "config.h"
#include "package.h"
#include "verify.h"
#include "fetch.h"
#include "extract.h"
#include "check.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    struct holy_config config = {0};
    char *error = NULL;
    const char *path;
    int ok;

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
    if (argc == 6 && !strcmp(argv[1], "check") &&
        !strncmp(argv[2], "local:", 6) && argv[2][6] &&
        !strcmp(argv[3], "--root") && !strcmp(argv[5], "--json"))
        return holy_check_local(argv[2] + 6, argv[4], 1) ? 0 : 1;
    if (argc != 4 || strcmp(argv[1], "config") || strcmp(argv[2], "check")) {
        fprintf(stderr, "usage: holypkg config check FILE | holypkg info local:FILE | holypkg verify local:FILE | holypkg fetch local:FILE [--extract] --output DIRECTORY | holypkg check local:FILE --root DIRECTORY [--json]\n");
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
