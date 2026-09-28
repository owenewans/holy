#define _POSIX_C_SOURCE 200809L
#include "graph.h"
#include "config.h"
#include "state.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct vertex {
    char digest[65];
    char *name;
    char **providers;
    size_t *links, count;
    int explicit, reached;
};

struct graph {
    struct vertex *vertices;
    size_t count, edges;
    unsigned long long generation;
};

static int digest_valid(const char *text)
{
    return strlen(text) == 64 && strspn(text, "0123456789abcdef") == 64;
}

static int utf8_valid(const char *text)
{
    const unsigned char *p = (const unsigned char *)text;
    while (*p) {
        size_t width, i;
        if (*p < 128) { ++p; continue; }
        width = *p >= 0xc2 && *p <= 0xdf ? 2 : *p >= 0xe0 && *p <= 0xef ? 3 :
                *p >= 0xf0 && *p <= 0xf4 ? 4 : 0;
        if (!width) return 0;
        for (i = 1; i < width; ++i) if ((p[i] & 0xc0) != 0x80) return 0;
        if ((*p == 0xe0 && p[1] < 0xa0) || (*p == 0xed && p[1] >= 0xa0) ||
            (*p == 0xf0 && p[1] < 0x90) || (*p == 0xf4 && p[1] >= 0x90)) return 0;
        p += width;
    }
    return 1;
}

static char *read_record(int dir, const char *name)
{
    struct stat st;
    size_t used = 0;
    char *data = NULL;
    errno = 0;
    int fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return NULL;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 1 ||
        st.st_size > 16 * 1024 * 1024) goto done;
    data = malloc((size_t)st.st_size + 1);
    if (!data) goto done;
    while (used < (size_t)st.st_size) {
        ssize_t got = read(fd, data + used, (size_t)st.st_size - used);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { free(data); data = NULL; goto done; }
        used += (size_t)got;
    }
    if (memchr(data, 0, used) || data[used - 1] != '\n') { free(data); data = NULL; }
    else data[used] = 0;
done:
    close(fd);
    return data;
}

static int collect(void *context, int root, int item, const char *digest)
{
    struct graph *graph = context;
    struct vertex *vertex, *grown;
    static const char *const records[] = {"meta", "state", "graph"};
    size_t r;
    int reason_seen = 0, graph_member = 0, graph_root = 0;
    char root_digest[65] = {0}, previous[65] = {0};
    (void)root;
    if (graph->count == 100000) return 1;
    grown = realloc(graph->vertices, (graph->count + 1) * sizeof *grown);
    if (!grown) return 1;
    graph->vertices = grown;
    vertex = &grown[graph->count++];
    memset(vertex, 0, sizeof *vertex);
    memcpy(vertex->digest, digest, 65);
    for (r = 0; r < 3; ++r) {
        char *data = read_record(item, records[r]), *line;
        size_t number = 0;
        int ok = 1;
        if (!data) return r == 2 && errno == ENOENT ? 6 : 1;
        for (line = data; *line; ) {
            char *end = strchr(line, '\n'), **v = NULL, *error = NULL;
            size_t count = 0;
            ++number;
            if (!end || !holy_lex(line, (size_t)(end - line), &v, &count,
                                  records[r], number, &error)) ok = 0;
            if (ok && r == 0 && count && !strcmp(v[0], "name")) {
                if (count != 2 || vertex->name || !v[1][0] || !utf8_valid(v[1]) ||
                    !(vertex->name = strdup(v[1]))) ok = 0;
            } else if (ok && r == 1 && count && !strcmp(v[0], "reason")) {
                if (count != 2 || reason_seen++ ||
                    (strcmp(v[1], "explicit") && strcmp(v[1], "dependency"))) ok = 0;
                else vertex->explicit = !strcmp(v[1], "explicit");
            } else if (ok && r == 1 && count && !strcmp(v[0], "generation")) {
                char *last;
                unsigned long long recorded;
                errno = 0;
                recorded = count == 2 ? strtoull(v[1], &last, 10) : 0;
                if (count != 2 || errno || *last || recorded > graph->generation) ok = 0;
            } else if (ok && r == 2) {
                if (number == 1) ok = count == 2 && !strcmp(v[0], "format") && !strcmp(v[1], "holy-resolution-1");
                else if (number == 2) ok = count == 2 && !strcmp(v[0], "scope") && !strcmp(v[1], "artifact-candidates");
                else if (number == 3) {
                    ok = count == 2 && !strcmp(v[0], "root") && digest_valid(v[1]);
                    if (ok) memcpy(root_digest, v[1], 65);
                } else if (count == 2 && !strcmp(v[0], "artifact")) {
                    ok = digest_valid(v[1]) && (!previous[0] || strcmp(previous, v[1]) < 0);
                    if (ok) {
                        memcpy(previous, v[1], 65);
                        if (!strcmp(v[1], digest)) graph_member = 1;
                        if (!strcmp(v[1], root_digest)) graph_root = 1;
                    }
                } else if (count == 7 && !strcmp(v[0], "edge") &&
                           digest_valid(v[1]) && digest_valid(v[3]) && v[2][0] &&
                           v[4][0] && v[6][0] &&
                           (!strcmp(v[5], "package") || !strcmp(v[5], "file") ||
                            !strcmp(v[5], "command") ||
                            !strcmp(v[5], "interpreter") ||
                            !strcmp(v[5], "needed-path") || !strcmp(v[5], "soname") ||
                            !strcmp(v[5], "symbol"))) {
                    if (!strcmp(v[1], digest)) {
                        char **providers;
                        if (graph->edges == 1000000 ||
                            !(providers = realloc(vertex->providers, (vertex->count + 1) * sizeof *providers))) ok = 0;
                        else {
                            vertex->providers = providers;
                            providers[vertex->count] = strdup(v[3]);
                            if (!providers[vertex->count]) ok = 0;
                            else { ++vertex->count; ++graph->edges; }
                        }
                    }
                } else ok = 0;
            }
            free(error);
            holy_tokens_free(v, count);
            if (!ok) break;
            line = end + 1;
        }
        free(data);
        if (!ok) return 1;
    }
    return vertex->name && reason_seen && graph_member && graph_root ? 0 : 1;
}

static size_t lookup(const struct graph *graph, const char *digest)
{
    size_t low = 0, high = graph->count;
    while (low < high) {
        size_t mid = low + (high - low) / 2;
        int order = strcmp(graph->vertices[mid].digest, digest);
        if (order < 0) low = mid + 1;
        else if (order > 0) high = mid;
        else return mid;
    }
    return graph->count;
}

static void quoted(const char *text, int json)
{
    const unsigned char *p = (const unsigned char *)text;
    putchar('"');
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') printf("\\%c", *p);
        else if (*p < 32 || *p == 127 || (!json && *p >= 128)) printf(json ? "\\u%04x" : "\\x%02x", *p);
        else putchar(*p);
    }
    putchar('"');
}

int holy_orphan(const char *root, int json)
{
    struct graph graph = {0};
    size_t *queue = NULL, head = 0, tail = 0, roots = 0, orphans = 0, i, j;
    int result = holy_state_visit(root, collect, &graph, &graph.generation);
    if (result) goto done;
    queue = calloc(graph.count ? graph.count : 1, sizeof *queue);
    if (!queue) { result = 1; goto done; }
    for (i = 0; i < graph.count; ++i) {
        struct vertex *v = &graph.vertices[i];
        v->links = calloc(v->count ? v->count : 1, sizeof *v->links);
        if (!v->links) { result = 1; goto done; }
        for (j = 0; j < v->count; ++j) {
            v->links[j] = lookup(&graph, v->providers[j]);
            if (v->links[j] == graph.count) {
                fprintf(stderr, "holypkg: missing graph provider consumer=%s provider=%s\n", v->digest, v->providers[j]);
                result = 4; goto done;
            }
        }
        if (v->explicit) { v->reached = 1; queue[tail++] = i; ++roots; }
    }
    while (head < tail) {
        struct vertex *v = &graph.vertices[queue[head++]];
        for (j = 0; j < v->count; ++j) {
            struct vertex *provider = &graph.vertices[v->links[j]];
            if (!provider->reached) { provider->reached = 1; queue[tail++] = v->links[j]; }
        }
    }
    for (i = 0; i < graph.count; ++i) if (!graph.vertices[i].reached) {
        struct vertex *v = &graph.vertices[i];
        ++orphans;
        if (json) {
            printf("{\"schema\":\"holy-orphan-1\",\"type\":\"candidate\",\"artifact\":\"%s\",\"name\":", v->digest);
            quoted(v->name, 1);
            printf(",\"reason\":\"unreachable-from-explicit\",\"generation\":%llu}\n", graph.generation);
        } else {
            printf("orphan %s ", v->digest); quoted(v->name, 0);
            puts(" reason=dependency unreachable-from-explicit");
        }
    }
    if (json) printf("{\"schema\":\"holy-orphan-1\",\"type\":\"summary\",\"generation\":%llu,\"installed\":%zu,\"explicit\":%zu,\"reachable\":%zu,\"orphans\":%zu}\n",
                     graph.generation, graph.count, roots, tail, orphans);
    else printf("generation %llu installed %zu explicit %zu reachable %zu orphans %zu read-only\n",
                graph.generation, graph.count, roots, tail, orphans);
    if (ferror(stdout)) result = 1;
done:
    if (result) {
        const char *code = result == 5 ? "incomplete-transaction" : result == 6 ? "unknown-installed-graph" :
                           result == 4 ? "missing-provider" : "invalid-state";
        fprintf(stderr, "holypkg: orphan analysis unavailable: %s\n", code);
        if (json) printf("{\"schema\":\"holy-orphan-1\",\"type\":\"error\",\"code\":\"%s\",\"status\":%d}\n", code, result);
    }
    for (i = 0; i < graph.count; ++i) {
        struct vertex *v = &graph.vertices[i];
        for (j = 0; j < v->count; ++j) free(v->providers[j]);
        free(v->providers); free(v->links); free(v->name);
    }
    free(queue); free(graph.vertices);
    return result;
}
