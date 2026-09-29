#include "rpm-version.h"

#include <solv/pool.h>
#include <solv/evr.h>

#include <stddef.h>

static int alnum_ascii(unsigned char c)
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z');
}

int holy_rpm_version_valid(const char *evr)
{
    const unsigned char *p = (const unsigned char *)evr;
    size_t length = 0;
    int epoch = 0, release = 0, component = 0;
    if (!p || !*p) return 0;
    while (*p) {
        unsigned char c = *p++;
        if (++length > 65536) return 0;
        if (alnum_ascii(c)) { component = 1; continue; }
        if (c == ':' && !epoch && !release) {
            const unsigned char *q = (const unsigned char *)evr;
            if (!component) return 0;
            while (q < p - 1) {
                if (*q < '0' || *q > '9') return 0;
                ++q;
            }
            epoch = 1; component = 0;
            continue;
        }
        if (c == '-' && !release && component) {
            release = 1; component = 0;
            continue;
        }
        if (c != '.' && c != '_' && c != '+' && c != '~' && c != '^') return 0;
    }
    return component;
}

int holy_rpm_version_compare(const char *left, const char *right, int *order)
{
    Pool *pool;
    const char *p;
    int compared, mode;
    if (!order || !holy_rpm_version_valid(left) || !holy_rpm_version_valid(right)) return 0;
    pool = pool_create();
    if (!pool) return 0;
    pool_setdisttype(pool, DISTTYPE_RPM);
    mode = EVRCMP_COMPARE_EVONLY;
    for (p = right; *p; ++p) if (*p == '-') { mode = EVRCMP_COMPARE; break; }
    compared = pool_evrcmp_str(pool, left, right, mode);
    *order = compared < 0 ? -1 : compared > 0 ? 1 : 0;
    pool_free(pool);
    return 1;
}
