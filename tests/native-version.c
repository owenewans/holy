#include "../src/version.h"

#include <stdio.h>

struct case_item { const char *left, *right; int order; };

int main(void)
{
    static const struct case_item cases[] = {
        {"1.9", "1.10", -1}, {"2.0", "1.99", 1},
        {"1.0", "1", 0}, {"1.0.0", "1", 0},
        {"7.3-rc4", "7.3-rc10", -1},
        {"7.3~rc4", "7.3", -1}, {"1.0-a.2", "1.0-a.10", -1},
        {"1.0-1", "1.0-a", -1},
        {"999999999999999999999999", "999999999999999999999998", 1},
        {"1.0-rc", "1.0-rc.1", -1},
        {"01.002", "1.2", 0}
    };
    static const char *const invalid[] = {
        "", "v1", "1.", ".1", "1..2", "1.0-", "1.0--rc", "1+build",
        "1:2", "1/2", "1 2", "1\n2", "1.0-RC", "1.0-rc~1"
    };
    size_t i;
    for (i = 0; i < sizeof cases / sizeof *cases; ++i) {
        int order;
        if (!holy_version_compare(cases[i].left, cases[i].right, &order) ||
            order != cases[i].order ||
            !holy_version_compare(cases[i].right, cases[i].left, &order) ||
            order != -cases[i].order) {
            fprintf(stderr, "Holy version order failed: %s %s\n",
                    cases[i].left, cases[i].right);
            return 1;
        }
    }
    for (i = 0; i < sizeof invalid / sizeof *invalid; ++i) {
        int order;
        if (holy_version_compare(invalid[i], "1", &order)) {
            fprintf(stderr, "accepted malformed Holy version: %s\n", invalid[i]);
            return 1;
        }
    }
    puts("Holy native version fixtures passed");
    return 0;
}
