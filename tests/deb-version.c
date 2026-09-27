#include "../backends/deb-version.h"

#include <stdio.h>

struct case_item { const char *left, *right; int order; };

int main(void)
{
    static const struct case_item cases[] = {
        {"1.0~~", "1.0~", -1}, {"1.0~rc1", "1.0", -1},
        {"1.0a", "1.0+", -1}, {"1.0+", "1.0.", -1},
        {"1:1.0", "2.0", 1}, {"0:1.0", "1.0", 0},
        {"1.01", "1.1", 0}, {"1.0", "1.0-0", 0},
        {"1.0-1", "1.0-2", -1}, {"1.0-1+b1", "1.0-1", 1},
        {"1.0-1~deb1", "1.0-1", -1}, {"1.0.10", "1.0.9", 1},
        {"01:1.0", "1:1.0", 0}, {"1.0-01", "1.0-1", 0}
    };
    static const char *const invalid[] = {"", "foo", "1:", "1-", "x:1", "1/2", "1 2", "1\n2"};
    size_t i;
    for (i = 0; i < sizeof cases / sizeof *cases; ++i) {
        int order;
        if (!holy_deb_version_compare(cases[i].left, cases[i].right, &order) ||
            order != cases[i].order ||
            !holy_deb_version_compare(cases[i].right, cases[i].left, &order) ||
            order != -cases[i].order) {
            fprintf(stderr, "Debian version order failed: %s %s\n", cases[i].left, cases[i].right);
            return 1;
        }
    }
    for (i = 0; i < sizeof invalid / sizeof *invalid; ++i) {
        int order;
        if (holy_deb_version_compare(invalid[i], "1", &order)) {
            fprintf(stderr, "accepted malformed Debian version: %s\n", invalid[i]);
            return 1;
        }
    }
    puts("Debian version comparator fixtures passed");
    return 0;
}
