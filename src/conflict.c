/* a read-only conflict report over the installed set. a set is resolved one
   requirement at a time, so two installed artifacts can end up offering one
   capability: two providers of one SONAME, two providers of one package name,
   two declared owners of one file path, or two private programs of one name,
   where the run PATH derived from the private trees picks one by sort order. the
   report names every provider and the reason, and changes nothing. it is the
   answer to a question the set transaction does not ask, since a set that installs
   cleanly can still leave an ambiguous name behind. */

#define _POSIX_C_SOURCE 200809L
#include "conflict.h"
#include "config.h"
#include "provides.h"
#include "state.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CONFLICT_CLAIMS 1000000
#define CONFLICT_LENGTH (16 * 1024 * 1024)

struct claim {
    char *kind;      /* package, soname, file or private-command */
    char *name;
    char *arch;
    char *libc;
    char digest[65];
};

struct report {
    struct claim *claims;
    size_t count, limit;
    size_t instances;
};

static void free_claims(struct report *report)
{
    size_t i;
    for (i = 0; i < report->count; ++i) {
        free(report->claims[i].kind);
        free(report->claims[i].name);
        free(report->claims[i].arch);
        free(report->claims[i].libc);
    }
    free(report->claims);
    memset(report, 0, sizeof *report);
}

static int add_claim(struct report *report, const char *kind, const char *name,
                     const char *arch, const char *libc, const char *digest)
{
    struct claim *grown;
    if (report->count == report->limit) {
        size_t next = report->limit ? report->limit * 2 : 256;
        if (next > CONFLICT_CLAIMS) return 0;
        grown = realloc(report->claims, next * sizeof *grown);
        if (!grown) return 0;
        report->claims = grown;
        report->limit = next;
    }
    report->claims[report->count].kind = strdup(kind);
    report->claims[report->count].name = strdup(name);
    report->claims[report->count].arch = strdup(arch ? arch : "-");
    report->claims[report->count].libc = strdup(libc ? libc : "-");
    if (!report->claims[report->count].kind || !report->claims[report->count].name ||
        !report->claims[report->count].arch || !report->claims[report->count].libc) return 0;
    memcpy(report->claims[report->count].digest, digest, 65);
    ++report->count;
    return 1;
}

/* the record read is bound to the digest the visitor supplies, so the provider
   identity comes from the instance rather than from the record itself */
struct provider_context {
    struct report *report;
    char digest[65];
};

static int collect_capability(void *opaque, const char *kind, const char *name,
                              const char *arch, const char *libc, const char *version,
                              const char *evidence)
{
    struct provider_context *context = opaque;
    (void)version; (void)evidence;
    if (strcmp(kind, "package") && strcmp(kind, "soname") && strcmp(kind, "file")) return 1;
    return add_claim(context->report, kind, name, arch, libc, context->digest);
}

/* a private program is the last component of a private bin directory, which is
   the name a run PATH lookup would resolve */
static int private_program(const char *path, char *program, size_t size)
{
    static const char *const dirs[] = {"usr/bin/", "bin/", "usr/sbin/", "sbin/"};
    static const char prefix[] = "usr/lib/holy/private/";
    const char *artifact, *slash, *at;
    size_t i;
    if (strncmp(path, prefix, sizeof prefix - 1)) return 0;
    artifact = path + sizeof prefix - 1;
    slash = strchr(artifact, '/');
    if (!slash || slash == artifact) return 0;
    ++slash;
    for (i = 0; i < sizeof dirs / sizeof *dirs; ++i) {
        size_t length = strlen(dirs[i]);
        if (strncmp(slash, dirs[i], length)) continue;
        at = slash + length;
        if (!*at || strlen(at) >= size) return 0;
        for (; *at; ++at)
            if (*at == '/') return 0;
        snprintf(program, size, "%s", slash + length);
        return 1;
    }
    return 0;
}

static int collect_files(int files, struct report *report, const char *digest)
{
    struct stat st;
    FILE *stream = NULL;
    char *line = NULL;
    size_t capacity = 0, number = 0;
    ssize_t length;
    int copy, ok = 0;
    if (fstat(files, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        st.st_size > CONFLICT_LENGTH || lseek(files, 0, SEEK_SET)) return 0;
    copy = dup(files);
    if (copy < 0) return 0;
    stream = fdopen(copy, "r");
    if (!stream) { close(copy); return 0; }
    while ((length = getline(&line, &capacity, stream)) >= 0) {
        char **fields = NULL, *error = NULL;
        size_t count = 0;
        char program[256];
        ++number;
        if (memchr(line, 0, (size_t)length) ||
            !holy_lex(line, (size_t)length, &fields, &count,
                      "installed/files", number, &error)) {
            free(error); holy_tokens_free(fields, count); goto done;
        }
        free(error);
        if (count && !strcmp(fields[0], "file") && count == 12 &&
            private_program(fields[1], program, sizeof program) &&
            !add_claim(report, "private-command", program, NULL, NULL, digest)) {
            holy_tokens_free(fields, count); goto done;
        }
        holy_tokens_free(fields, count);
    }
    ok = !ferror(stream) && st.st_size == (off_t)ftello(stream);
done:
    free(line);
    fclose(stream);
    return ok;
}

static int collect(void *context, int root, int item, const char *digest)
{
    struct provider_context provider = {context, {0}};
    struct report *report = context;
    int files;
    (void)root;
    if (report->count >= CONFLICT_CLAIMS) return 1;
    memcpy(provider.digest, digest, 65);
    files = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (files < 0) return 1;
    if (!collect_files(files, report, digest)) { close(files); return 1; }
    close(files);
    files = openat(item, "provides", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (files < 0) return 1;
    if (!holy_provides_visit_fd(files, collect_capability, &provider)) {
        close(files); return 1;
    }
    close(files);
    ++report->instances;
    return 0;
}

static int compare_claims(const void *left, const void *right)
{
    const struct claim *a = left, *b = right;
    int order = strcmp(a->kind, b->kind);
    if (order) return order;
    order = strcmp(a->name, b->name);
    if (order) return order;
    return strcmp(a->digest, b->digest);
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

static const char *reason_for(const struct claim *claims, size_t from, size_t to,
                              int *mixed_abi)
{
    size_t i;
    *mixed_abi = 0;
    for (i = from + 1; i < to; ++i)
        if (strcmp(claims[i].arch, claims[from].arch) || strcmp(claims[i].libc, claims[from].libc)) {
            *mixed_abi = 1;
            break;
        }
    if (*mixed_abi) return "abi-mismatch";
    return !strcmp(claims[from].kind, "package") ? "mixed-providers" :
           !strcmp(claims[from].kind, "private-command") ? "shadowed-path" :
           "duplicate-provider";
}

static void emit(const struct claim *claims, size_t from, size_t to, int json)
{
    size_t i;
    int mixed_abi = 0;
    const char *reason = reason_for(claims, from, to, &mixed_abi);
    if (json) {
        printf("{\"schema\":\"holy-conflict-1\",\"type\":\"finding\",\"kind\":");
        quoted(claims[from].kind, 1);
        printf(",\"name\":");
        quoted(claims[from].name, 1);
        printf(",\"reason\":\"%s\",\"providers\":[", reason);
        for (i = from; i < to; ++i) {
            printf("%s{\"artifact\":\"%s\",\"arch\":", i > from ? "," : "", claims[i].digest);
            quoted(claims[i].arch, 1);
            printf(",\"libc\":");
            quoted(claims[i].libc, 1);
            printf(",\"package\":");
            quoted(claims[i].name, 1);
            printf("}");
        }
        printf("]}\n");
    } else {
        printf("conflict %s ", claims[from].kind);
        quoted(claims[from].name, 0);
        printf(" providers %zu reason %s", to - from, reason);
        for (i = from; i < to; ++i) {
            printf(" provider %s arch ", claims[i].digest);
            quoted(claims[i].arch, 0);
            printf(" libc ");
            quoted(claims[i].libc, 0);
        }
        putchar('\n');
    }
}

int holy_conflict_report(const char *root, int json)
{
    struct report report = {0};
    struct claim *sorted;
    size_t i, findings = 0;
    unsigned long long generation = 0;
    int result;
    if (!root || !*root) return 2;
    result = holy_state_visit(root, collect, &report, &generation);
    if (result) {
        const char *code = result == 5 ? "incomplete-transaction" :
                           result == 6 ? "unavailable-instance-or-graph" : "invalid-state";
        fprintf(stderr, "holypkg: conflict report unavailable: %s\n", code);
        if (json)
            printf("{\"schema\":\"holy-conflict-1\",\"type\":\"error\",\"code\":\"%s\",\"status\":%d}\n",
                   code, result);
        free_claims(&report);
        return result;
    }
    sorted = report.claims;
    qsort(sorted, report.count, sizeof *sorted, compare_claims);
    for (i = 0; i < report.count; ) {
        size_t end = i + 1;
        while (end < report.count && !strcmp(sorted[end].kind, sorted[i].kind) &&
               !strcmp(sorted[end].name, sorted[i].name)) ++end;
        /* one artifact may state a capability twice; only distinct owners collide */
        if (end - i > 1 && strcmp(sorted[i].digest, sorted[i + 1].digest)) {
            emit(sorted, i, end, json);
            ++findings;
        }
        i = end;
    }
    if (json)
        printf("{\"schema\":\"holy-conflict-1\",\"type\":\"summary\",\"generation\":%llu,"
               "\"installed\":%zu,\"capabilities\":%zu,\"findings\":%zu}\n",
               generation, report.instances, report.count, findings);
    else
        printf("generation %llu installed %zu capabilities %zu conflicts %zu read-only\n",
               generation, report.instances, report.count, findings);
    if (ferror(stdout)) result = 1;
    else result = findings ? 1 : 0;
    free_claims(&report);
    return result;
}
