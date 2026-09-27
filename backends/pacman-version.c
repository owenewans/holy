#include "pacman.h"
#include <string.h>

struct part { const char *start, *end; };

static int digit(unsigned char c) { return c >= '0' && c <= '9'; }
static int letter(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static int component(struct part a, struct part b)
{
    const char *p = a.start, *q = b.start;
    while (p < a.end && q < b.end) {
        const char *x = p, *y = q, *px, *qy;
        size_t n, m;
        int numeric, compared;
        while (p < a.end && !digit((unsigned char)*p) && !letter((unsigned char)*p)) ++p;
        while (q < b.end && !digit((unsigned char)*q) && !letter((unsigned char)*q)) ++q;
        if (p == a.end || q == b.end) break;
        if (p - x != q - y) return p - x < q - y ? -1 : 1;
        numeric = digit((unsigned char)*p);
        px = p; qy = q;
        while (p < a.end && (numeric ? digit((unsigned char)*p) : letter((unsigned char)*p))) ++p;
        while (q < b.end && (numeric ? digit((unsigned char)*q) : letter((unsigned char)*q))) ++q;
        if (q == qy) return numeric ? 1 : -1;
        if (numeric) {
            while (px < p && *px == '0') ++px;
            while (qy < q && *qy == '0') ++qy;
        }
        n = (size_t)(p - px); m = (size_t)(q - qy);
        if (numeric && n != m) return n < m ? -1 : 1;
        compared = memcmp(px, qy, n < m ? n : m);
        if (compared) return compared < 0 ? -1 : 1;
        if (n != m) return n < m ? -1 : 1;
    }
    if (p == a.end && q == b.end) return 0;
    return ((p == a.end && !letter((unsigned char)*q)) ||
            (p < a.end && letter((unsigned char)*p))) ? -1 : 1;
}

static int split(const char *text, struct part parts[3])
{
    const char *p, *end, *dash = NULL;
    static const char zero[] = "0";
    if (!text || !*text) return 0;
    for (end = text; *end; ++end)
        if ((unsigned char)*end <= 32 || (unsigned char)*end >= 127 || end - text >= 65536) return 0;
    for (p = text; digit((unsigned char)*p); ++p) {}
    parts[0] = (struct part){zero, zero + 1};
    if (*p == ':') {
        if (p != text) parts[0] = (struct part){text, p};
        text = p + 1;
    }
    for (p = text; p < end; ++p) if (*p == '-') dash = p;
    parts[1] = (struct part){text, dash ? dash : end};
    parts[2] = (struct part){dash ? dash + 1 : NULL, end};
    return 1;
}

int holy_pacman_version_compare(const char *a, const char *b, int *order)
{
    struct part left[3], right[3];
    int i;
    if (!order || !split(a, left) || !split(b, right)) return 0;
    *order = 0;
    for (i = 0; i < 3; ++i) {
        /* pacman ignores pkgrel unless both versions supply it. */
        if (i == 2 && (!left[i].start || !right[i].start)) break;
        *order = component(left[i], right[i]);
        if (*order) break;
    }
    return 1;
}
