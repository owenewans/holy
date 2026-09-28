#include "../backends/apk-version.h"

#include <stdio.h>

int main(int argc, char **argv)
{
    int order;
    if (argc != 3) return 2;
    if (!holy_apk_version_compare(argv[1], argv[2], &order)) return 3;
    puts(order < 0 ? "<" : order > 0 ? ">" : "=");
    return 0;
}
