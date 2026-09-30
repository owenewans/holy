/* a read-only file index over the installed set. a set resolves a requirement from
   the manifests of its candidates, so a reader outside the planner has no way to ask
   which installed artifact owns a path or provides a name without reading every
   manifest. this index answers that question from the installed records themselves,
   and when a name has several providers it names all of them rather than choosing,
   since a silent choice is exactly the failure a fuzzy candidate causes. */

#define _POSIX_C_SOURCE 200809L
#include "index.h"
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

#define INDEX_LIMIT (16 * 1024 * 1024)
#define INDEX_CLAIMS 1000000

struct owner {
    char digest[65];
    char *path;
};

struct capability {
    char digest[65];
    char *kind;
    char *name;
    char *arch;
    char *libc;
};

struct artifact {
    char digest[65];
    char *name, *arch, *libc;
    struct owner *paths;
    size_t path_count, path_limit;
    struct capability *claims;
    size_t claim_count, claim_limit;
};

struct index {
    struct artifact *artifacts;
    size_t count, limit;
    size_t paths, claims;
    int failed;
};

static void index_free(struct index *index)
{
    size_t i, j;
    for (i = 0; i < index->count; ++i) {
        struct artifact *artifact = &index->artifacts[i];
        for (j = 0; j < artifact->path_count; ++j) free(artifact->paths[j].path);
        free(artifact->paths);
        for (j = 0; j < artifact->claim_count; ++j) {
            free(artifact->claims[j].kind);
            free(artifact->claims[j].name);
            free(artifact->claims[j].arch);
            free(artifact->claims[j].libc);
        }
        free(artifact->claims);
        free(artifact->name);
        free(artifact->arch);
        free(artifact->libc);
    }
    free(index->artifacts);
    memset(index, 0, sizeof *index);
}

static struct artifact *artifact_for(struct index *index, const char *digest)
{
    struct artifact *artifact, *grown;
    if (index->count == index->limit) {
        size_t next = index->limit ? index->limit * 2 : 32;
        if (next > INDEX_CLAIMS) return NULL;
        grown = realloc(index->artifacts, next * sizeof *grown);
        if (!grown) return NULL;
        index->artifacts = grown;
        index->limit = next;
    }
    artifact = &index->artifacts[index->count++];
    memset(artifact, 0, sizeof *artifact);
    memcpy(artifact->digest, digest, 65);
    return artifact;
}

static int add_path(struct artifact *artifact, const char *path)
{
    struct owner *grown;
    if (artifact->path_count == artifact->path_limit) {
        size_t next = artifact->path_limit ? artifact->path_limit * 2 : 64;
        grown = realloc(artifact->paths, next * sizeof *grown);
        if (!grown) return 0;
        artifact->paths = grown;
        artifact->path_limit = next;
    }
    artifact->paths[artifact->path_count].path = strdup(path);
    if (!artifact->paths[artifact->path_count].path) return 0;
    memcpy(artifact->paths[artifact->path_count].digest, artifact->digest, 65);
    ++artifact->path_count;
    return 1;
}

struct claim_context {
    struct index *index;
    char digest[65];
};

static int collect_claim(void *opaque, const char *kind, const char *name, const char *arch,
                         const char *libc, const char *version, const char *evidence)
{
    struct claim_context *context = opaque;
    size_t i;
    struct capability *claim, *grown;
    (void)version; (void)evidence;
    for (i = 0; i < context->index->count; ++i)
        if (!strcmp(context->index->artifacts[i].digest, context->digest)) break;
    if (i == context->index->count) return 1;
    if (strcmp(kind, "package") && strcmp(kind, "file") && strcmp(kind, "soname") &&
        strcmp(kind, "command") && strcmp(kind, "symbol-version")) return 1;
    {
        struct artifact *artifact = &context->index->artifacts[i];
        if (artifact->claim_count == artifact->claim_limit) {
            size_t next = artifact->claim_limit ? artifact->claim_limit * 2 : 16;
            grown = realloc(artifact->claims, next * sizeof *grown);
            if (!grown) return 0;
            artifact->claims = grown;
            artifact->claim_limit = next;
        }
        claim = &artifact->claims[artifact->claim_count];
        claim->kind = strdup(kind);
        claim->name = strdup(name);
        claim->arch = strdup(arch);
        claim->libc = strdup(libc);
        memcpy(claim->digest, artifact->digest, 65);
        if (!claim->kind || !claim->name || !claim->arch || !claim->libc) return 0;
        ++artifact->claim_count;
        ++context->index->claims;
    }
    return 1;
}

static int read_meta(int item, struct artifact *artifact)
{
    struct stat st;
    FILE *stream = NULL;
    char *line = NULL;
    size_t capacity = 0, number = 0;
    ssize_t length;
    int copy, ok = 0;
    if (fstatat(item, "meta", &st, AT_SYMLINK_NOFOLLOW) || !S_ISREG(st.st_mode) ||
        st.st_size < 1 || st.st_size > INDEX_LIMIT) return 0;
    copy = openat(item, "meta", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (copy < 0) return 0;
    stream = fdopen(copy, "r");
    if (!stream) { close(copy); return 0; }
    while ((length = getline(&line, &capacity, stream)) >= 0) {
        char **fields = NULL, *error = NULL;
        size_t count = 0;
        char **target = NULL;
        ++number;
        if (memchr(line, 0, (size_t)length) ||
            !holy_lex(line, (size_t)length, &fields, &count, "installed/meta", number, &error)) {
            free(error);
            holy_tokens_free(fields, count);
            goto done;
        }
        free(error);
        if (count == 2 && !strcmp(fields[0], "name")) target = &artifact->name;
        else if (count == 2 && !strcmp(fields[0], "arch")) target = &artifact->arch;
        else if (count == 2 && !strcmp(fields[0], "libc")) target = &artifact->libc;
        if (target) {
            free(*target);
            *target = strdup(fields[1]);
            if (!*target) { holy_tokens_free(fields, count); goto done; }
        }
        holy_tokens_free(fields, count);
    }
    ok = !ferror(stream) && st.st_size == (off_t)ftello(stream) && artifact->name;
done:
    free(line);
    fclose(stream);
    return ok;
}

static int read_files(int item, struct artifact *artifact)
{
    struct stat st;
    FILE *stream = NULL;
    char *line = NULL;
    size_t capacity = 0, number = 0;
    ssize_t length;
    int copy, ok = 0;
    if (fstatat(item, "files", &st, AT_SYMLINK_NOFOLLOW) || !S_ISREG(st.st_mode) ||
        st.st_size < 0 || st.st_size > INDEX_LIMIT) return 0;
    copy = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (copy < 0) return 0;
    stream = fdopen(copy, "r");
    if (!stream) { close(copy); return 0; }
    while ((length = getline(&line, &capacity, stream)) >= 0) {
        char **fields = NULL, *error = NULL;
        size_t count = 0;
        ++number;
        if (memchr(line, 0, (size_t)length) ||
            !holy_lex(line, (size_t)length, &fields, &count, "installed/files", number, &error)) {
            free(error);
            holy_tokens_free(fields, count);
            goto done;
        }
        free(error);
        /* a directory is shared, so it owns nothing and is not an index entry */
        if (count && strcmp(fields[0], "dir") && count >= 2 && fields[1][0] &&
            !add_path(artifact, fields[1])) {
            holy_tokens_free(fields, count);
            goto done;
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
    struct index *index = context;
    struct artifact *artifact;
    struct claim_context claims;
    (void)root;
    if (index->count >= INDEX_CLAIMS) return 1;
    artifact = artifact_for(index, digest);
    if (!artifact) return 1;
    if (!read_meta(item, artifact)) { index->failed = 1; return 1; }
    if (!read_files(item, artifact)) { index->failed = 1; return 1; }
    index->paths += artifact->path_count;
    claims.index = index;
    memcpy(claims.digest, digest, 65);
    {
        int provides = openat(item, "provides", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        int ok = provides >= 0 && holy_provides_visit_fd(provides, collect_claim, &claims);
        if (provides >= 0) close(provides);
        if (!ok) { index->failed = 1; return 1; }
    }
    return 0;
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

static int compare_artifacts(const void *left, const void *right)
{
    return strcmp(((const struct artifact *)left)->digest, ((const struct artifact *)right)->digest);
}

static int compare_paths(const void *left, const void *right)
{
    return strcmp(((const struct owner *)left)->path, ((const struct owner *)right)->path);
}

static int compare_claims(const void *left, const void *right)
{
    const struct capability *a = left, *b = right;
    int order = strcmp(a->kind, b->kind);
    if (order) return order;
    order = strcmp(a->name, b->name);
    if (order) return order;
    return strcmp(a->digest, b->digest);
}

/* the installed manifests record a relative path, so a query accepts either form and
   is normalized to the relative one; an escaping component is refused */
static int normalize_path(const char *path, char *out, size_t size)
{
    size_t used = 0;
    if (!path) return 0;
    while (*path == '/') ++path;
    if (!*path) return 0;
    while (*path) {
        size_t part = strcspn(path, "/");
        if (!part || (part == 1 && path[0] == '.') || (part == 2 && !memcmp(path, "..", 2)))
            return 0;
        if (used + part + 2 >= size) return 0;
        if (used) out[used++] = '/';
        memcpy(out + used, path, part);
        used += part;
        path += part;
        while (*path == '/') ++path;
    }
    out[used] = 0;
    return 1;
}

static int emit_artifact(const struct artifact *artifact, int json)
{
    size_t i;
    if (json) {
        printf("{\"schema\":\"holy-file-index-1\",\"type\":\"artifact\",\"artifact\":\"%s\",\"name\":",
               artifact->digest);
        quoted(artifact->name, 1);
        printf(",\"arch\":");
        quoted(artifact->arch ? artifact->arch : "-", 1);
        printf(",\"libc\":");
        quoted(artifact->libc ? artifact->libc : "-", 1);
        puts("}");
    } else {
        printf("artifact %s ", artifact->digest);
        quoted(artifact->name, 0);
        printf(" arch ");
        quoted(artifact->arch ? artifact->arch : "-", 0);
        printf(" libc ");
        quoted(artifact->libc ? artifact->libc : "-", 0);
        putchar('\n');
    }
    for (i = 0; i < artifact->path_count; ++i) {
        if (json) {
            printf("{\"schema\":\"holy-file-index-1\",\"type\":\"path\",\"artifact\":\"%s\",\"path\":",
                   artifact->digest);
            quoted(artifact->paths[i].path, 1);
            puts("}");
        } else {
            printf("path %s ", artifact->digest);
            quoted(artifact->paths[i].path, 0);
            putchar('\n');
        }
    }
    for (i = 0; i < artifact->claim_count; ++i) {
        const struct capability *claim = &artifact->claims[i];
        if (json) {
            printf("{\"schema\":\"holy-file-index-1\",\"type\":\"capability\",\"artifact\":\"%s\",\"kind\":",
                   artifact->digest);
            quoted(claim->kind, 1);
            printf(",\"name\":");
            quoted(claim->name, 1);
            printf(",\"arch\":");
            quoted(claim->arch, 1);
            printf(",\"libc\":");
            quoted(claim->libc, 1);
            puts("}");
        } else {
            printf("capability %s %s ", artifact->digest, claim->kind);
            quoted(claim->name, 0);
            printf(" arch ");
            quoted(claim->arch, 0);
            printf(" libc ");
            quoted(claim->libc, 0);
            putchar('\n');
        }
    }
    return !ferror(stdout);
}

int holy_index_report(const char *root, const char *path, const char *kind, const char *name,
                      int json)
{
    struct index index = {0};
    struct owner *owners = NULL;
    size_t owner_count = 0, i, j, matches = 0;
    char wanted[4096];
    unsigned long long generation = 0;
    int result, failed = 0;
    if (!root || !*root) return 2;
    /* a path and a capability are two separate questions, so naming one without the
       other, or both at once, is a usage error rather than a guess */
    if (path && (kind || name)) return 2;
    if (!path && (kind || name) != (kind != NULL && name != NULL)) return 2;
    if (path && !normalize_path(path, wanted, sizeof wanted)) return 2;
    result = holy_state_visit(root, collect, &index, &generation);
    if (result) {
        const char *code = result == 5 ? "incomplete-transaction" :
                           result == 6 ? "unavailable-instance" : "invalid-state";
        fprintf(stderr, "holypkg: file index unavailable: %s\n", code);
        if (json)
            printf("{\"schema\":\"holy-file-index-1\",\"type\":\"error\",\"code\":\"%s\","
                   "\"status\":%d}\n", code, result);
        index_free(&index);
        return result;
    }
    if (index.failed) {
        fprintf(stderr, "holypkg: file index unavailable: invalid installed record\n");
        if (json)
            puts("{\"schema\":\"holy-file-index-1\",\"type\":\"error\",\"code\":\"invalid-state\","
                 "\"status\":1}");
        index_free(&index);
        return 1;
    }
    qsort(index.artifacts, index.count, sizeof *index.artifacts, compare_artifacts);
    for (i = 0; i < index.count; ++i) {
        qsort(index.artifacts[i].paths, index.artifacts[i].path_count,
              sizeof *index.artifacts[i].paths, compare_paths);
        qsort(index.artifacts[i].claims, index.artifacts[i].claim_count,
              sizeof *index.artifacts[i].claims, compare_claims);
    }
    if (path) {
        for (i = 0; i < index.count; ++i) {
            struct artifact *artifact = &index.artifacts[i];
            for (j = 0; j < artifact->path_count; ++j)
                if (!strcmp(artifact->paths[j].path, wanted)) {
                    struct owner *grown = realloc(owners, (owner_count + 1) * sizeof *grown);
                    if (!grown) { free(owners); index_free(&index); return 1; }
                    owners = grown;
                    owners[owner_count].path = artifact->paths[j].path;
                    memcpy(owners[owner_count].digest, artifact->digest, 65);
                    ++owner_count;
                }
        }
        qsort(owners, owner_count, sizeof *owners, compare_paths);
        matches = owner_count;
        for (i = 0; i < owner_count; ++i) {
            if (!json) printf("owner %s ", owners[i].digest);
            if (json) {
                printf("{\"schema\":\"holy-file-index-1\",\"type\":\"path\",\"artifact\":\"%s\","
                       "\"path\":", owners[i].digest);
                quoted(owners[i].path, 1);
                puts("}");
            } else {
                quoted(owners[i].path, 0);
                putchar('\n');
            }
        }
        if (json) printf("{\"schema\":\"holy-file-index-1\",\"type\":\"summary\",\"kind\":\"path\","
                         "\"subject\":");
        if (!json) printf("summary kind path subject ");
        quoted(wanted, json);
        if (json) printf(",\"candidates\":%zu}\n", owner_count);
        else printf(" candidates %zu generation %llu read-only\n", owner_count, generation);
    } else if (kind && name) {
        for (i = 0; i < index.count; ++i) {
            struct artifact *artifact = &index.artifacts[i];
            for (j = 0; j < artifact->claim_count; ++j) {
                if (strcmp(artifact->claims[j].kind, kind) ||
                    strcmp(artifact->claims[j].name, name)) continue;
                ++matches;
                if (json) {
                    printf("{\"schema\":\"holy-file-index-1\",\"type\":\"candidate\",\"kind\":");
                    quoted(kind, 1);
                    printf(",\"name\":");
                    quoted(name, 1);
                    printf(",\"artifact\":\"%s\",\"arch\":", artifact->digest);
                    quoted(artifact->claims[j].arch, 1);
                    printf(",\"libc\":");
                    quoted(artifact->claims[j].libc, 1);
                    puts("}");
                } else {
                    printf("candidate %s %s ", artifact->digest, kind);
                    quoted(name, 0);
                    printf(" arch ");
                    quoted(artifact->claims[j].arch, 0);
                    printf(" libc ");
                    quoted(artifact->claims[j].libc, 0);
                    putchar('\n');
                }
            }
        }
        if (json) printf("{\"schema\":\"holy-file-index-1\",\"type\":\"summary\",\"kind\":");
        if (!json) printf("summary kind capability subject ");
        quoted(kind, json);
        if (json) printf(",\"name\":");
        if (!json) printf(" ");
        quoted(name, json);
        if (json) printf(",\"candidates\":%zu}\n", matches);
        else printf(" candidates %zu generation %llu read-only\n", matches, generation);
    } else {
        for (i = 0; i < index.count; ++i)
            if (!emit_artifact(&index.artifacts[i], json)) { failed = 1; break; }
        if (json)
            printf("{\"schema\":\"holy-file-index-1\",\"type\":\"summary\",\"generation\":%llu,"
                   "\"artifacts\":%zu,\"paths\":%zu,\"capabilities\":%zu}\n",
                   generation, index.count, index.paths, index.claims);
        else
            printf("summary generation %llu artifacts %zu paths %zu capabilities %zu read-only\n",
                   generation, index.count, index.paths, index.claims);
    }
    free(owners);
    index_free(&index);
    if (failed || ferror(stdout)) return 1;
    /* a name with more than one provider is a candidate list, and choosing one of
       them is a decision this report does not make */
    if ((path || (kind && name)) && matches > 1) return 1;
    if (path && !matches) return 6;
    if (kind && name && !matches) return 6;
    return 0;
}
