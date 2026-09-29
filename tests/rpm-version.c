#include "../backends/rpm-version.h"

#include <stdio.h>

int main(void)
{
    static const struct { const char *left, *right; int order; } cases[] = {
        {"1.0~rc1", "1.0", -1},
        {"1.0^202609", "1.0", 1},
        {"1.0^202609", "1.0.1", -1},
        {"1.10", "1.9", 1},
        {"1.0-2", "1.0-1", 1},
        {"1.0-2", "1.0", 0},
        {"2:1.0-1", "1:99.0-9", 1},
        {"1:0.1-1", "1.2", 1},
        {"1.0+1", "1.0.1", 0}
    };
    static const char *const invalid[] = {"", "1:", "x:foo", "1.0:2", "1.0-", "1.0 bad"};
    size_t i;
    for (i = 0; i < sizeof cases / sizeof *cases; ++i) {
        int order;
        if (!holy_rpm_version_compare(cases[i].left, cases[i].right, &order) ||
            order != cases[i].order) {
            fprintf(stderr, "rpm version mismatch: %s vs %s\n", cases[i].left, cases[i].right);
            return 1;
        }
    }
    for (i = 0; i < sizeof invalid / sizeof *invalid; ++i)
        if (holy_rpm_version_valid(invalid[i])) {
            fprintf(stderr, "accepted invalid RPM version: %s\n", invalid[i]);
            return 1;
        }
    return 0;
}
