#include "deb-version.h"

#include <stddef.h>
#include <string.h>

struct part { const char *start, *end; };
struct version { struct part epoch, upstream, revision; };

static int digit(unsigned char c) { return c >= '0' && c <= '9'; }
static int letter(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static int split(const char *text, struct version *out)
{
    const char *p, *end, *colon = NULL, *dash = NULL;
    static const char zero[] = "0";
    if (!text || !*text) return 0;
    for (end = text; *end; ++end) {
        if (end - text >= 65536 || (!letter((unsigned char)*end) &&
            !digit((unsigned char)*end) && !strchr(".+:~-", *end))) return 0;
        if (*end == ':' && !colon) colon = end;
        if (*end == '-') dash = end;
    }
    out->epoch = (struct part){zero, zero + 1};
    if (colon) {
        if (colon == text) return 0;
        for (p = text; p < colon; ++p) if (!digit((unsigned char)*p)) return 0;
        out->epoch = (struct part){text, colon};
        text = colon + 1;
    }
    if (!digit((unsigned char)*text)) return 0;
    if (dash && dash < text) return 0;
    out->upstream = (struct part){text, dash ? dash : end};
    if (out->upstream.start == out->upstream.end) return 0;
    for (p = text; p < out->upstream.end; ++p)
        if (*p == ':' && !colon) return 0;
    if (dash) {
        if (dash + 1 == end) return 0;
        for (p = dash + 1; p < end; ++p)
            if (!letter((unsigned char)*p) && !digit((unsigned char)*p) &&
                !strchr("+.~", *p)) return 0;
        out->revision = (struct part){dash + 1, end};
    } else {
        out->revision = (struct part){end, end};
    }
    return 1;
}

static int numeric(struct part a, struct part b)
{
    size_t x, y;
    while (a.start < a.end && *a.start == '0') ++a.start;
    while (b.start < b.end && *b.start == '0') ++b.start;
    x = (size_t)(a.end - a.start); y = (size_t)(b.end - b.start);
    if (x != y) return x < y ? -1 : 1;
    if (x) {
        int compared = memcmp(a.start, b.start, x);
        if (compared) return compared < 0 ? -1 : 1;
    }
    return 0;
}

static int rank(unsigned char c)
{
    if (c == '~') return -1;
    if (!c || digit(c)) return 0;
    if (letter(c)) return c;
    return c + 256;
}

static int component(struct part a, struct part b)
{
    const char *x = a.start, *y = b.start;
    while (x < a.end || y < b.end) {
        int first = 0;
        while ((x < a.end && !digit((unsigned char)*x)) ||
               (y < b.end && !digit((unsigned char)*y))) {
            int left = rank(x < a.end ? (unsigned char)*x : 0);
            int right = rank(y < b.end ? (unsigned char)*y : 0);
            if (left != right) return left < right ? -1 : 1;
            if (x < a.end) ++x;
            if (y < b.end) ++y;
        }
        while (x < a.end && *x == '0') ++x;
        while (y < b.end && *y == '0') ++y;
        while (x < a.end && y < b.end && digit((unsigned char)*x) && digit((unsigned char)*y)) {
            if (!first) first = *x - *y;
            ++x; ++y;
        }
        if (x < a.end && digit((unsigned char)*x)) return 1;
        if (y < b.end && digit((unsigned char)*y)) return -1;
        if (first) return first < 0 ? -1 : 1;
    }
    return 0;
}

int holy_deb_version_compare(const char *a, const char *b, int *order)
{
    struct version left, right;
    if (!order || !split(a, &left) || !split(b, &right)) return 0;
    *order = numeric(left.epoch, right.epoch);
    if (!*order) *order = component(left.upstream, right.upstream);
    if (!*order) *order = component(left.revision, right.revision);
    return 1;
}
