#include "version.h"

#include <stddef.h>
#include <string.h>

struct part { const char *start, *end; };
struct version { struct part core, pre; int prerelease; };

static int digit(unsigned char c) { return c >= '0' && c <= '9'; }
static int letter(unsigned char c) { return c >= 'a' && c <= 'z'; }

static int parse(const char *text, struct version *out)
{
    const char *p, *start, *end;
    if (!text || !*text) return 0;
    for (end = text; *end; ++end) if (end - text >= 65536) return 0;
    p = text;
    do {
        start = p;
        while (digit((unsigned char)*p)) ++p;
        if (p == start) return 0;
        if (*p != '.') break;
        ++p;
    } while (1);
    out->core = (struct part){text, p};
    out->prerelease = *p == '-' || *p == '~';
    out->pre = (struct part){end, end};
    if (out->prerelease) {
        ++p;
        out->pre.start = p;
        do {
            start = p;
            while (digit((unsigned char)*p) || letter((unsigned char)*p)) ++p;
            if (p == start) return 0;
            if (*p != '.' && *p != '-') break;
            ++p;
        } while (1);
        out->pre.end = p;
    }
    return !*p;
}

static int number(struct part a, struct part b)
{
    size_t x, y;
    while (a.start < a.end && *a.start == '0') ++a.start;
    while (b.start < b.end && *b.start == '0') ++b.start;
    x = (size_t)(a.end - a.start);
    y = (size_t)(b.end - b.start);
    if (x != y) return x < y ? -1 : 1;
    if (x) {
        int compared = memcmp(a.start, b.start, x);
        if (compared) return compared < 0 ? -1 : 1;
    }
    return 0;
}

static int core(struct part a, struct part b)
{
    const char *x = a.start, *y = b.start;
    while (x < a.end || y < b.end) {
        static const char zero[] = "0";
        struct part left = {zero, zero + 1}, right = {zero, zero + 1};
        int order;
        if (x < a.end) {
            left.start = x;
            while (x < a.end && *x != '.') ++x;
            left.end = x;
            if (x < a.end) ++x;
        }
        if (y < b.end) {
            right.start = y;
            while (y < b.end && *y != '.') ++y;
            right.end = y;
            if (y < b.end) ++y;
        }
        order = number(left, right);
        if (order) return order;
    }
    return 0;
}

static int identifier(struct part a, struct part b)
{
    const char *x = a.start, *y = b.start;
    while (x < a.end && y < b.end) {
        struct part left, right;
        int numeric = digit((unsigned char)*x), order;
        if (numeric != digit((unsigned char)*y)) return numeric ? -1 : 1;
        left.start = x; right.start = y;
        while (x < a.end && (numeric ? digit((unsigned char)*x) : letter((unsigned char)*x))) ++x;
        while (y < b.end && (numeric ? digit((unsigned char)*y) : letter((unsigned char)*y))) ++y;
        left.end = x; right.end = y;
        if (numeric) order = number(left, right);
        else {
            size_t lx = (size_t)(x - left.start), ly = (size_t)(y - right.start);
            int compared = memcmp(left.start, right.start, lx < ly ? lx : ly);
            order = compared < 0 ? -1 : compared > 0 ? 1 :
                    lx < ly ? -1 : lx > ly ? 1 : 0;
        }
        if (order) return order;
    }
    return x == a.end && y == b.end ? 0 : x == a.end ? -1 : 1;
}

static int prerelease(struct part a, struct part b)
{
    const char *x = a.start, *y = b.start;
    while (x < a.end && y < b.end) {
        struct part left, right;
        int order;
        left.start = x; right.start = y;
        while (x < a.end && *x != '.' && *x != '-') ++x;
        while (y < b.end && *y != '.' && *y != '-') ++y;
        left.end = x; right.end = y;
        order = identifier(left, right);
        if (order) return order;
        if (x < a.end) ++x;
        if (y < b.end) ++y;
    }
    return x == a.end && y == b.end ? 0 : x == a.end ? -1 : 1;
}

int holy_version_compare(const char *left, const char *right, int *order)
{
    struct version a, b;
    if (!order || !parse(left, &a) || !parse(right, &b)) return 0;
    *order = core(a.core, b.core);
    if (!*order && a.prerelease != b.prerelease)
        *order = a.prerelease ? -1 : 1;
    if (!*order && a.prerelease)
        *order = prerelease(a.pre, b.pre);
    return 1;
}
