/* a read-only conflict report over the installed set, and the same claim collection
   over the package archives of a planned set. a set is resolved one requirement at a
   time, so two artifacts can end up offering one capability: two providers of one
   SONAME, two providers of one package name, two declared owners of one file path,
   or two private programs of one name, where the run PATH derived from the private
   trees picks one by sort order. the report names every provider and the reason, and
   changes nothing. the set transaction states the same facts about its own selection
   before it stages a file, since a set that installs cleanly can still leave an
   ambiguous name behind. */

#define _POSIX_C_SOURCE 200809L
#include "conflict.h"
#include "config.h"
#include "provides.h"
#include "state.h"
#include "verify.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CONFLICT_CLAIMS 1000000
#define CONFLICT_LENGTH (16 * 1024 * 1024)

void holy_conflict_claims_free(struct holy_conflict_claims *claims)
{
    size_t i;
    for (i = 0; i < claims->count; ++i) {
        free(claims->claim[i].kind);
        free(claims->claim[i].name);
        free(claims->claim[i].arch);
        free(claims->claim[i].libc);
    }
    free(claims->claim);
    memset(claims, 0, sizeof *claims);
}

int holy_conflict_claims_push(struct holy_conflict_claims *claims, const char *kind,
                              const char *name, const char *arch, const char *libc,
                              const char *digest)
{
    struct holy_conflict_claim *grown;
    if (claims->count == claims->limit) {
        size_t next = claims->limit ? claims->limit * 2 : 256;
        if (next > CONFLICT_CLAIMS) return 0;
        grown = realloc(claims->claim, next * sizeof *grown);
        if (!grown) return 0;
        claims->claim = grown;
        claims->limit = next;
    }
    claims->claim[claims->count].kind = strdup(kind);
    claims->claim[claims->count].name = strdup(name);
    claims->claim[claims->count].arch = strdup(arch ? arch : "-");
    claims->claim[claims->count].libc = strdup(libc ? libc : "-");
    if (!claims->claim[claims->count].kind || !claims->claim[claims->count].name ||
        !claims->claim[claims->count].arch || !claims->claim[claims->count].libc) return 0;
    memcpy(claims->claim[claims->count].digest, digest, 65);
    ++claims->count;
    return 1;
}

/* the record read is bound to the digest the visitor supplies, so the provider
   identity comes from the instance rather than from the record itself */
struct provider_context {
    struct holy_conflict_claims *claims;
    char digest[65];
};

static int collect_capability(void *opaque, const char *kind, const char *name,
                              const char *arch, const char *libc, const char *version,
                              const char *evidence)
{
    struct provider_context *context = opaque;
    (void)version; (void)evidence;
    if (strcmp(kind, "package") && strcmp(kind, "soname") && strcmp(kind, "file")) return 1;
    return holy_conflict_claims_push(context->claims, kind, name, arch, libc, context->digest);
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

struct private_context {
    struct holy_conflict_claims *claims;
    const char *digest;
};

static int collect_private(void *opaque, const struct holy_manifest_entry *entry)
{
    struct private_context *context = opaque;
    char program[256];
    if (entry->directory || !private_program(entry->path, program, sizeof program)) return 1;
    return holy_conflict_claims_push(context->claims, "private-command", program,
                                     NULL, NULL, context->digest);
}

static int collect_files(int files, struct holy_conflict_claims *claims, const char *digest)
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
            !holy_conflict_claims_push(claims, "private-command", program, NULL, NULL, digest)) {
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

int holy_conflict_claims_package(struct holy_conflict_claims *claims,
                                 const char *package, const char *digest)
{
    struct private_context private = {claims, digest};
    struct provider_context provider = {claims, {0}};
    if (claims->count >= CONFLICT_CLAIMS) return 1;
    memcpy(provider.digest, digest, 65);
    if (!holy_provides_visit(package, collect_capability, &provider)) return 0;
    if (!holy_verify_visit(package, collect_private, &private)) return 0;
    ++claims->instances;
    return 1;
}

static int collect(void *context, int root, int item, const char *digest)
{
    struct provider_context provider = {context, {0}};
    struct holy_conflict_claims *claims = context;
    int files;
    (void)root;
    if (claims->count >= CONFLICT_CLAIMS) return 1;
    memcpy(provider.digest, digest, 65);
    files = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (files < 0) return 1;
    if (!collect_files(files, claims, digest)) { close(files); return 1; }
    close(files);
    files = openat(item, "provides", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (files < 0) return 1;
    if (!holy_provides_visit_fd(files, collect_capability, &provider)) {
        close(files); return 1;
    }
    close(files);
    ++claims->instances;
    return 0;
}

static int compare_claims(const void *left, const void *right)
{
    const struct holy_conflict_claim *a = left, *b = right;
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

static const char *reason_for(const struct holy_conflict_claim *claims, size_t from, size_t to,
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

static void emit(const struct holy_conflict_claim *claims, size_t from, size_t to, int json)
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

/* the range of one capability, from a sorted claim list. returns the end offset and
   sets found when two distinct artifacts offer it. */
static size_t finding_end(const struct holy_conflict_claims *claims, size_t from, int *found)
{
    size_t end = from + 1;
    while (end < claims->count && !strcmp(claims->claim[end].kind, claims->claim[from].kind) &&
           !strcmp(claims->claim[end].name, claims->claim[from].name)) ++end;
    /* one artifact may state a capability twice; only distinct owners collide */
    *found = end - from > 1 && strcmp(claims->claim[from].digest, claims->claim[from + 1].digest);
    return end;
}

size_t holy_conflict_claims_findings(struct holy_conflict_claims *claims)
{
    size_t i, findings = 0;
    if (claims->count) qsort(claims->claim, claims->count, sizeof *claims->claim, compare_claims);
    for (i = 0; i < claims->count; ) {
        int found = 0;
        i = finding_end(claims, i, &found);
        if (found) ++findings;
    }
    return findings;
}

void holy_conflict_claims_print(const struct holy_conflict_claims *claims, int json)
{
    size_t i;
    for (i = 0; i < claims->count; ) {
        int found = 0;
        size_t end = finding_end(claims, i, &found);
        if (found) emit(claims->claim, i, end, json);
        i = end;
    }
}

int holy_conflict_report(const char *root, int json)
{
    struct holy_conflict_claims claims = {0};
    size_t findings;
    unsigned long long generation = 0;
    int result;
    if (!root || !*root) return 2;
    result = holy_state_visit(root, collect, &claims, &generation);
    if (result) {
        const char *code = result == 5 ? "incomplete-transaction" :
                           result == 6 ? "unavailable-instance-or-graph" : "invalid-state";
        fprintf(stderr, "holypkg: conflict report unavailable: %s\n", code);
        if (json)
            printf("{\"schema\":\"holy-conflict-1\",\"type\":\"error\",\"code\":\"%s\",\"status\":%d}\n",
                   code, result);
        holy_conflict_claims_free(&claims);
        return result;
    }
    findings = holy_conflict_claims_findings(&claims);
    holy_conflict_claims_print(&claims, json);
    if (json)
        printf("{\"schema\":\"holy-conflict-1\",\"type\":\"summary\",\"generation\":%llu,"
               "\"installed\":%zu,\"capabilities\":%zu,\"findings\":%zu}\n",
               generation, claims.instances, claims.count, findings);
    else
        printf("generation %llu installed %zu capabilities %zu conflicts %zu read-only\n",
               generation, claims.instances, claims.count, findings);
    if (ferror(stdout)) result = 1;
    else result = findings ? 1 : 0;
    holy_conflict_claims_free(&claims);
    return result;
}
