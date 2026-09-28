#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    FILE *modules;
    char *line = NULL;
    size_t capacity = 0, name_length;
    int module, found = 0;
    if (argc != 3 || !argv[2][0] || strchr(argv[2], ' ')) {
        fputs("usage: holy-module-probe FILE NAME\n", stderr);
        return 2;
    }
    module = open(argv[1], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (module < 0) { perror("open module"); return 1; }
    if (syscall(SYS_finit_module, module, "", 0) < 0 && errno != EEXIST) {
        perror("finit_module");
        close(module);
        return 1;
    }
    close(module);
    modules = fopen("/proc/modules", "r");
    if (!modules) { perror("/proc/modules"); return 1; }
    name_length = strlen(argv[2]);
    while (getline(&line, &capacity, modules) >= 0)
        if (!strncmp(line, argv[2], name_length) && line[name_length] == ' ') {
            found = 1;
            break;
        }
    free(line);
    fclose(modules);
    if (!found) { fprintf(stderr, "module %s not loaded\n", argv[2]); return 1; }
    return 0;
}
