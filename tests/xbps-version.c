#include "../backends/xbps-version.h"

#include <stdio.h>

struct comparison { const char *left, *right; int order; };

int main(void)
{
    static const struct comparison cases[] = {
        {"1.0", "1.0", 0}, {"1.0", "1.0_1", -1},
        {"1.0_2", "1.0_1", 1}, {"2.0rc2", "2.0rc3", -1},
        {"2.0alpha", "2.0beta", -1}, {"2.0beta", "2.0rc", -1},
        {"1.0.1", "1.0_1", 1}, {"21", "2.1", 1},
        {"1.0pl1", "1.0", 1}, {"1.0_0", "1.0", 0}
    };
    size_t i;
    int order;
    for (i = 0; i < sizeof cases / sizeof *cases; ++i)
        if (!holy_xbps_version_compare(cases[i].left, cases[i].right, &order) ||
            order != cases[i].order ||
            !holy_xbps_version_compare(cases[i].right, cases[i].left, &order) ||
            order != -cases[i].order) {
            fprintf(stderr, "XBPS comparison failed: %s %s\n", cases[i].left, cases[i].right);
            return 1;
        }
    if (holy_xbps_version_compare("1.0_", "1.0", &order) ||
        holy_xbps_version_compare("1.0<2", "1.0", &order) ||
        holy_xbps_version_compare("999999999999999999999999", "1.0", &order)) return 1;
    puts("XBPS version comparisons passed");
    return 0;
}
