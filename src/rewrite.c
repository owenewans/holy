#define _POSIX_C_SOURCE 200809L
#include "rewrite.h"
#include "elf.h"

#include <openssl/evp.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define REWRITE_LIMIT 4096

/* patchelf names the operation differently for each field, and DT_RPATH is the one it
   keeps apart from DT_RUNPATH, so the argv carries the flag that says which one the
   caller asked for rather than letting the tool choose */
static const char *flag_for(enum holy_rewrite_kind kind)
{
    switch (kind) {
    case HOLY_REWRITE_INTERPRETER: return "--set-interpreter";
    case HOLY_REWRITE_RPATH: return "--set-rpath";
    case HOLY_REWRITE_RUNPATH: return "--set-rpath";
    case HOLY_REWRITE_SONAME: return "--set-soname";
    case HOLY_REWRITE_NEEDED: return "--replace-needed";
    }
    return NULL;
}

static const char *name_for(enum holy_rewrite_kind kind)
{
    switch (kind) {
    case HOLY_REWRITE_INTERPRETER: return "interpreter";
    case HOLY_REWRITE_RPATH: return "rpath";
    case HOLY_REWRITE_RUNPATH: return "runpath";
    case HOLY_REWRITE_SONAME: return "soname";
    case HOLY_REWRITE_NEEDED: return "needed";
    }
    return NULL;
}

/* the value the file states for one field, borrowed from the ELF facts, or NULL when
   the file states none. a DT_NEEDED entry is the name the dynamic table carries. */
static const char *current_for(const struct holy_elf_info *elf,
                               const struct holy_rewrite_change *change)
{
    switch (change->kind) {
    case HOLY_REWRITE_INTERPRETER: return elf->interpreter;
    case HOLY_REWRITE_RPATH: return elf->rpath;
    case HOLY_REWRITE_RUNPATH: return elf->runpath;
    case HOLY_REWRITE_SONAME: return elf->soname;
    case HOLY_REWRITE_NEEDED: return change->from;
    }
    return NULL;
}

static int needed_states(const struct holy_elf_info *elf, const char *name)
{
    size_t i;
    for (i = 0; i < elf->needed_count; ++i)
        if (!strcmp(elf->needed[i], name)) return 1;
    return 0;
}

static int digest_of(const char *file, char hex[65])
{
    unsigned char buffer[65536], digest[32];
    unsigned int length = 32;
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    struct stat st;
    ssize_t got;
    int fd, ok = 0, i;
    if (!hash || (fd = open(file, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)) < 0) goto done;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        st.st_size > 64 * 1024 * 1024) { close(fd); goto done; }
    if (EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1) { close(fd); goto done; }
    while ((got = read(fd, buffer, sizeof buffer)) != 0) {
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0 || EVP_DigestUpdate(hash, buffer, (size_t)got) != 1) {
            close(fd); goto done;
        }
    }
    close(fd);
    if (EVP_DigestFinal_ex(hash, digest, &length) != 1 || length != 32) goto done;
    for (i = 0; i < 32; ++i) snprintf(hex + i * 2, 3, "%02x", digest[i]);
    ok = 1;
done:
    EVP_MD_CTX_free(hash);
    return ok;
}

/* the tool is named the way a command line names it, so a bare name is resolved
   through PATH the way execv would. the plan records the resolved path, since a plan
   that fixed a name would read a different file after PATH changed. */
static char *resolve(const char *tool)
{
    const char *path, *cursor;
    char *copy;
    struct stat st;
    if (strchr(tool, '/')) return strdup(tool);
    path = getenv("PATH");
    if (!path || !*path) path = "/usr/local/bin:/usr/bin:/bin";
    for (cursor = path; ; ) {
        const char *end = strchr(cursor, ':');
        size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
        if (length) {
            copy = malloc(length + strlen(tool) + 2);
            if (!copy) return NULL;
            snprintf(copy, length + strlen(tool) + 2, "%.*s/%s", (int)length, cursor, tool);
            if (!stat(copy, &st) && S_ISREG(st.st_mode) && (st.st_mode & 0111)) return copy;
            free(copy);
        }
        if (!end) break;
        cursor = end + 1;
    }
    return NULL;
}

int holy_rewrite_tool(const char *tool)
{
    struct stat st;
    char *path, *probe[3];
    pid_t pid;
    int status;
    if (!tool || !*tool || !(path = resolve(tool))) return 0;
    if (stat(path, &st) || !S_ISREG(st.st_mode) || !(st.st_mode & 0111)) {
        free(path);
        return 0;
    }
    probe[0] = path;
    probe[1] = (char *)"--version";
    probe[2] = NULL;
    if ((pid = fork()) < 0) { free(path); return 0; }
    if (!pid) {
        int null = open("/dev/null", O_WRONLY);
        if (null >= 0) { dup2(null, 1); dup2(null, 2); close(null); }
        execv(path, probe);
        _exit(127);
    }
    while (waitpid(pid, &status, 0) < 0) if (errno != EINTR) { free(path); return 0; }
    free(path);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

void holy_rewrite_free(struct holy_rewrite *plan)
{
    size_t i;
    for (i = 0; i < plan->count; ++i) {
        free(plan->change[i].from);
        free(plan->change[i].to);
    }
    free(plan->change);
    for (i = 0; i < plan->argc; ++i) free(plan->argv[i]);
    free(plan->argv);
    free(plan->tool);
    free(plan->file);
    memset(plan, 0, sizeof *plan);
}

/* one argv entry per token, so a value with a space or a quote stays one argument
   instead of being split by anything. the vector keeps its NULL sentinel, since
   execv reads argv until it finds one. */
static int push(char ***list, size_t *count, const char *value)
{
    char **grown = realloc(*list, (*count + 2) * sizeof *grown);
    char *copy;
    if (!grown) return 0;
    *list = grown;
    copy = strdup(value);
    if (!copy) return 0;
    grown[(*count)++] = copy;
    grown[*count] = NULL;
    return 1;
}

static int safe_value(const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    if (!value || !*value) return 0;
    for (; *p; ++p)
        if (*p < 32 || *p == 127) return 0;
    /* an absolute path or a bare soname is the shape either field carries, and a
       relative value would resolve against the running process rather than the file */
    if (value[0] == '-' || (value[0] != '/' && strchr(value, '/'))) return 0;
    return 1;
}

int holy_rewrite_prepare(const char *tool, const char *file,
                         const struct holy_rewrite_change *changes, size_t count,
                         struct holy_rewrite *plan)
{
    struct holy_elf_info elf = {0};
    size_t i, argc = 0;
    int result = -1, parsed;
    memset(plan, 0, sizeof *plan);
    if (!file || !*file || !count || count > REWRITE_LIMIT) return 2;
    for (i = 0; i < count; ++i)
        if (!flag_for(changes[i].kind) || !changes[i].to ||
            !safe_value(changes[i].to) ||
            (changes[i].kind == HOLY_REWRITE_NEEDED &&
             (!changes[i].from || !safe_value(changes[i].from)))) return 2;
    if (!tool || !*tool) tool = "patchelf";
    if (!(plan->tool = resolve(tool)) || !holy_rewrite_tool(plan->tool)) {
        result = 6;
        goto done;
    }
    parsed = holy_elf_read(file, &elf);
    if (parsed) { result = parsed == 1 ? 2 : -1; goto done; }
    if (!elf.has_dynamic) {
        fprintf(stderr, "holypkg: rewrite needs a dynamic ELF; the file has no PT_DYNAMIC\n");
        goto done;
    }
    if (!digest_of(file, plan->hash)) goto done;
    plan->file = strdup(file);
    plan->change = calloc(count, sizeof *plan->change);
    if (!plan->file || !plan->change) goto done;
    if (!push(&plan->argv, &argc, plan->tool) || !push(&plan->argv, &argc, "--no-sort")) goto done;
    for (i = 0; i < count; ++i) {
        const char *current = current_for(&elf, &changes[i]);
        if (changes[i].kind == HOLY_REWRITE_NEEDED) {
            if (!needed_states(&elf, changes[i].from)) {
                fprintf(stderr, "holypkg: the file does not state %s in DT_NEEDED\n",
                        changes[i].from);
                goto done;
            }
            /* a replacement that keeps the same name is a rename of nothing, and the
               spec requires the substitution to be an explicit change of path or name */
            if (!strcmp(changes[i].from, changes[i].to)) {
                fprintf(stderr, "holypkg: a replacement has to change %s\n",
                        changes[i].from);
                goto done;
            }
        }
        if (current && !strcmp(current, changes[i].to)) {
            fprintf(stderr, "holypkg: the file already states %s %s\n",
                    name_for(changes[i].kind), changes[i].to);
            goto done;
        }
        plan->change[i].kind = changes[i].kind;
        plan->change[i].to = strdup(changes[i].to);
        if (!plan->change[i].to) goto done;
        if (current && !(plan->change[i].from = strdup(current))) goto done;
        /* DT_RPATH and DT_RUNPATH are one field to the tool, so the requested one is
           named by the flag rather than inferred from what the file happens to have */
        if (changes[i].kind == HOLY_REWRITE_RPATH &&
            !push(&plan->argv, &argc, "--force-rpath")) goto done;
        if (!push(&plan->argv, &argc, flag_for(changes[i].kind)) ||
            (changes[i].kind == HOLY_REWRITE_NEEDED &&
             !push(&plan->argv, &argc, changes[i].from)) ||
            !push(&plan->argv, &argc, changes[i].to)) goto done;
        ++plan->count;
    }
    if (!plan->count) { result = 0; goto done; }
    if (!push(&plan->argv, &argc, plan->file)) goto done;
    plan->argc = argc;
    result = 1;
done:
    holy_elf_free(&elf);
    if (result != 1) holy_rewrite_free(plan);
    return result;
}

static int run(const char *tool, char *const argv[])
{
    pid_t pid;
    int status;
    if ((pid = fork()) < 0) return 0;
    if (!pid) { execv(tool, argv); _exit(127); }
    while (waitpid(pid, &status, 0) < 0) if (errno != EINTR) return 0;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int holy_rewrite_apply(const struct holy_rewrite *plan)
{
    char actual[65];
    if (!plan || !plan->argc || !plan->hash[0]) return 2;
    /* the plan fixed a digest for this file, so a file that changed under the review
       changes nothing rather than being rewritten with stale decisions */
    if (!digest_of(plan->file, actual) || strcmp(actual, plan->hash)) {
        fprintf(stderr, "holypkg: the file changed since the plan; re-run the plan\n");
        return 4;
    }
    if (!holy_rewrite_tool(plan->tool)) return 6;
    return run(plan->tool, plan->argv) ? 0 : 1;
}

int holy_rewrite_record(const struct holy_rewrite *plan, char **record, size_t *size)
{
    FILE *out;
    size_t i;
    int ok;
    *record = NULL;
    *size = 0;
    if (!plan || !plan->count) return 0;
    out = open_memstream(record, size);
    if (!out) return 0;
    fprintf(out, "format holy-rewrite-1\nfile %s\nsha256 %s\ntool %s\n",
            plan->file, plan->hash, plan->tool);
    for (i = 0; i < plan->count; ++i)
        fprintf(out, "%s %s -> %s\n", name_for(plan->change[i].kind),
                plan->change[i].from ? plan->change[i].from : "-", plan->change[i].to);
    fputs("argv", out);
    for (i = 0; i < plan->argc; ++i) fprintf(out, " %s", plan->argv[i]);
    fputc('\n', out);
    ok = !ferror(out);
    if (fclose(out)) ok = 0;
    if (!ok) { free(*record); *record = NULL; *size = 0; }
    return ok;
}

void holy_rewrite_print(const struct holy_rewrite *plan)
{
    size_t i;
    for (i = 0; i < plan->count; ++i)
        printf("rewrite %s %s %s %s -> %s scope file\n", plan->file, plan->hash,
               name_for(plan->change[i].kind),
               plan->change[i].from ? plan->change[i].from : "-", plan->change[i].to);
    printf("rewrite-argv");
    for (i = 0; i < plan->argc; ++i) printf(" %s", plan->argv[i]);
    putchar('\n');
}