#include "xbps-version.h"

#include <ctype.h>
#include <limits.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>

struct version {
    long long components[256];
    size_t count;
    unsigned long long revision;
};

static int append(struct version *version, long long component)
{
    if (version->count == sizeof version->components / sizeof *version->components) return 0;
    version->components[version->count++] = component;
    return 1;
}

static int number(const char **text, unsigned long long *value)
{
    const unsigned char *p = (const unsigned char *)*text;
    unsigned long long result = 0;
    if (!isdigit(*p)) return 0;
    do {
        unsigned digit = *p - '0';
        if (result > (ULLONG_MAX - digit) / 10) return 0;
        result = result * 10 + digit;
    } while (isdigit(*++p));
    *text = (const char *)p;
    *value = result;
    return 1;
}

static int parse(const char *text, struct version *version)
{
    static const struct { const char *name; int component; } modifiers[] = {
        {"alpha", -3}, {"beta", -2}, {"pre", -1}, {"rc", -1}, {"pl", 0}
    };
    const char *p = text;
    size_t i;
    memset(version, 0, sizeof *version);
    if (!p || !*p || strlen(p) > 1024) return 0;
    while (*p) {
        unsigned long long value;
        if (isdigit((unsigned char)*p)) {
            if (!number(&p, &value) || value > LLONG_MAX || !append(version, (long long)value)) return 0;
        } else if (*p == '.') {
            if (!append(version, 0)) return 0;
            ++p;
        } else if (*p == '_') {
            ++p;
            if (!number(&p, &version->revision) || *p) return 0;
        } else if (isalpha((unsigned char)*p)) {
            for (i = 0; i < sizeof modifiers / sizeof *modifiers; ++i) {
                size_t length = strlen(modifiers[i].name);
                if (!strncasecmp(p, modifiers[i].name, length)) {
                    if (!append(version, modifiers[i].component)) return 0;
                    p += length;
                    break;
                }
            }
            if (i == sizeof modifiers / sizeof *modifiers) {
                int letter = tolower((unsigned char)*p) - 'a' + 1;
                if (!append(version, 0) || !append(version, letter)) return 0;
                ++p;
            }
        } else return 0;
    }
    return 1;
}

int holy_xbps_version_compare(const char *left, const char *right, int *order)
{
    struct version a, b;
    size_t count, i;
    if (!order || !parse(left, &a) || !parse(right, &b)) return 0;
    count = a.count > b.count ? a.count : b.count;
    for (i = 0; i < count; ++i) {
        long long av = i < a.count ? a.components[i] : 0;
        long long bv = i < b.count ? b.components[i] : 0;
        if (av != bv) { *order = av < bv ? -1 : 1; return 1; }
    }
    *order = a.revision < b.revision ? -1 : a.revision > b.revision ? 1 : 0;
    return 1;
}
