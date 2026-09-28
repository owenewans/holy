#include "apk-version.h"

#include <stddef.h>
#include <string.h>

struct apk_number { unsigned long long value; size_t zero_prefix; };
struct apk_suffix { int rank, numbered; unsigned long long number; };
struct apk_version {
    struct apk_number core[64];
    unsigned long long revision;
    struct apk_suffix suffix[32];
    size_t core_count, suffix_count;
    int letter, revised;
};

static int digit(char c) { return c >= '0' && c <= '9'; }

static int number(const char **cursor, unsigned long long *value, size_t *zeros)
{
    const char *p = *cursor;
    unsigned long long n = 0;
    size_t length = 0;
    if (!digit(*p)) return 0;
    while (digit(*p)) {
        if (++length > 17 || n > (18446744073709551615ULL - (unsigned)(*p - '0')) / 10) return 0;
        n = n * 10 + (unsigned)(*p++ - '0');
    }
    if (zeros) {
        const char *q = *cursor;
        while (*q == '0' && q < p) { ++*zeros; ++q; }
    }
    *cursor = p; *value = n;
    return 1;
}

static int parse(const char *text, struct apk_version *out)
{
    static const struct { const char *name; int rank; } suffixes[] = {
        {"alpha", -4}, {"beta", -3}, {"pre", -2}, {"rc", -1},
        {"cvs", 1}, {"svn", 2}, {"git", 3}, {"hg", 4}, {"p", 5}
    };
    const char *p = text;
    size_t i;
    memset(out, 0, sizeof *out);
    if (!p || !*p || strlen(p) > 65536) return 0;
    do {
        if (out->core_count == 64 ||
            !number(&p, &out->core[out->core_count].value,
                    &out->core[out->core_count].zero_prefix)) return 0;
        ++out->core_count;
        if (*p != '.') break;
        ++p;
    } while (1);
    if (*p >= 'a' && *p <= 'z') out->letter = *p++ - 'a' + 1;
    while (*p == '_') {
        struct apk_suffix *suffix;
        if (out->suffix_count == 32) return 0;
        ++p;
        for (i = 0; i < sizeof suffixes / sizeof *suffixes; ++i) {
            size_t length = strlen(suffixes[i].name);
            if (!strncmp(p, suffixes[i].name, length) &&
                (!p[length] || p[length] == '_' || p[length] == '-' || digit(p[length]))) break;
        }
        if (i == sizeof suffixes / sizeof *suffixes) return 0;
        suffix = &out->suffix[out->suffix_count++];
        suffix->rank = suffixes[i].rank;
        p += strlen(suffixes[i].name);
        if (digit(*p)) {
            suffix->numbered = 1;
            if (!number(&p, &suffix->number, NULL)) return 0;
        }
    }
    if (p[0] == '-' && p[1] == 'r') {
        p += 2;
        out->revised = 1;
        if (!number(&p, &out->revision, NULL)) return 0;
    }
    return *p == 0;
}

static int compare_number(unsigned long long left, unsigned long long right)
{
    return left < right ? -1 : left > right ? 1 : 0;
}

int holy_apk_version_compare(const char *left, const char *right, int *order)
{
    struct apk_version a, b;
    size_t i, count;
    if (!order || !parse(left, &a) || !parse(right, &b)) return 0;
    count = a.core_count > b.core_count ? a.core_count : b.core_count;
    for (i = 0; i < count && i < a.core_count && i < b.core_count; ++i) {
        if (i) {
            long long av = a.core[i].zero_prefix ? 1 - (long long)a.core[i].zero_prefix :
                           (long long)a.core[i].value;
            long long bv = b.core[i].zero_prefix ? 1 - (long long)b.core[i].zero_prefix :
                           (long long)b.core[i].value;
            *order = av < bv ? -1 : av > bv ? 1 : 0;
            if (*order) return 1;
        }
        *order = compare_number(a.core[i].value, b.core[i].value);
        if (*order) return 1;
    }
    if (a.core_count != b.core_count) {
        *order = a.core_count < b.core_count ? -1 : 1;
        return 1;
    }
    *order = compare_number((unsigned)a.letter, (unsigned)b.letter);
    if (*order) return 1;
    count = a.suffix_count > b.suffix_count ? a.suffix_count : b.suffix_count;
    for (i = 0; i < count; ++i) {
        int ar = i < a.suffix_count ? a.suffix[i].rank : 0;
        int br = i < b.suffix_count ? b.suffix[i].rank : 0;
        *order = ar < br ? -1 : ar > br ? 1 : 0;
        if (*order) return 1;
        if (i < a.suffix_count && i < b.suffix_count &&
            a.suffix[i].numbered != b.suffix[i].numbered) {
            *order = a.suffix[i].numbered ? 1 : -1;
            return 1;
        }
        *order = compare_number(i < a.suffix_count ? a.suffix[i].number : 0,
                                i < b.suffix_count ? b.suffix[i].number : 0);
        if (*order) return 1;
    }
    if (a.revised != b.revised) {
        *order = a.revised ? 1 : -1;
        return 1;
    }
    *order = compare_number(a.revision, b.revision);
    return 1;
}
