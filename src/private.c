#define _POSIX_C_SOURCE 200809L
#include "private.h"
#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PRIVATE_PLACES 65536
#define PRIVATE_PATH 4096

/* the private root is a lexical prefix, so a path that names it already sits in
   somebody's private tree and a placement may not nest a second one */
int holy_private_path(const char *path)
{
    return path && !strncmp(path, HOLY_PRIVATE_ROOT, sizeof HOLY_PRIVATE_ROOT - 1);
}

static int digest(const char *value)
{
    size_t i;
    if (strlen(value) != 64) return 0;
    for (i = 0; i < 64; ++i) {
        char c = value[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return 1;
}

/* a manifest path is relative, has no empty, dot or dot-dot component, and carries
   no control byte or separator that would let it leave the private tree */
static int safe_path(const char *path)
{
    const char *part;
    if (!path || !*path || strlen(path) > PRIVATE_PATH - 80 || holy_private_path(path)) return 0;
    for (part = path; *part; ) {
        const char *end = strchr(part, '/');
        size_t length = end ? (size_t)(end - part) : strlen(part), i;
        if (!length || (length == 1 && part[0] == '.') ||
            (length == 2 && part[0] == '.' && part[1] == '.')) return 0;
        for (i = 0; i < length; ++i)
            if ((unsigned char)part[i] < 32 || (unsigned char)part[i] == 127) return 0;
        if (!end) break;
        part = end + 1;
    }
    return 1;
}

int holy_private_target(const char *artifact, const char *path, char *target, size_t size)
{
    int written;
    if (!digest(artifact) || !safe_path(path)) return 0;
    written = snprintf(target, size, "%s%s/%s", HOLY_PRIVATE_ROOT, artifact, path);
    return written > 0 && (size_t)written < size;
}

void holy_private_places_free(struct holy_private_places *places)
{
    size_t i;
    for (i = 0; i < places->count; ++i) {
        free(places->place[i].path);
        free(places->place[i].target);
    }
    free(places->place);
    memset(places, 0, sizeof *places);
}

int holy_private_place_add(struct holy_private_places *places, const char *artifact,
                           const char *path)
{
    struct holy_private_place *grown;
    char target[PRIVATE_PATH];
    size_t i;
    if (!digest(artifact) || !safe_path(path) ||
        !holy_private_target(artifact, path, target, sizeof target)) return 0;
    for (i = 0; i < places->count; ++i)
        if (!strcmp(places->place[i].artifact, artifact) &&
            !strcmp(places->place[i].path, path)) return 0;
    /* two artifacts may claim one path privately, but one artifact may not send one
       of its own paths to a target it already uses for another */
    for (i = 0; i < places->count; ++i)
        if (!strcmp(places->place[i].artifact, artifact) &&
            !strcmp(places->place[i].target, target)) return 0;
    if (places->count >= PRIVATE_PLACES) return 0;
    grown = realloc(places->place, (places->count + 1) * sizeof *grown);
    if (!grown) return 0;
    places->place = grown;
    memcpy(places->place[places->count].artifact, artifact, 65);
    places->place[places->count].path = strdup(path);
    places->place[places->count].target = strdup(target);
    if (!places->place[places->count].path || !places->place[places->count].target) {
        free(places->place[places->count].path);
        free(places->place[places->count].target);
        return 0;
    }
    ++places->count;
    return 1;
}

const char *holy_private_lookup(const struct holy_private_places *places,
                                const char *artifact, const char *path)
{
    size_t i;
    for (i = 0; i < places->count; ++i)
        if (!strcmp(places->place[i].artifact, artifact) &&
            !strcmp(places->place[i].path, path)) return places->place[i].target;
    return NULL;
}

size_t holy_private_places_artifact(const struct holy_private_places *places,
                                   const char *artifact)
{
    size_t i, count = 0;
    for (i = 0; i < places->count; ++i)
        if (!strcmp(places->place[i].artifact, artifact)) ++count;
    return count;
}

void holy_private_places_print(const struct holy_private_places *places, size_t count)
{
    size_t i;
    for (i = 0; i < count && i < places->count; ++i)
        printf("private %s %s -> %s scope artifact-path\n",
               places->place[i].artifact, places->place[i].path, places->place[i].target);
}

static int number(const char *text, int base, long long *out)
{
    char *end;
    long long value;
    errno = 0;
    value = strtoll(text, &end, base);
    if (text[0] == '\0' || text[0] == '-' || errno || *end) return 0;
    *out = value;
    return 1;
}

static void quote(FILE *out, const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    fputc('"', out);
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') fprintf(out, "\\%c", *p);
        else if (*p < 32 || *p >= 127) fprintf(out, "\\x%02x", *p);
        else fputc(*p, out);
    }
    fputc('"', out);
}

/* a field the lexer read is written back the way every other manifest row writes it:
   bare when no quoting is needed, escaped when the name needs it. this keeps a
   rewritten row byte-identical to the package that shipped it in every field but
   the path. */
static void field(FILE *out, const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    int bare = *p != '\0';
    for (; bare && *p; ++p)
        if (*p <= ' ' || *p == '"' || *p == '\\' || *p >= 127) bare = 0;
    if (bare) { fputs(value, out); return; }
    quote(out, value);
}

/* the record keeps every field the source manifest carried, so a placed file stays the
   same file with the same mode, owner, size, hash and flags at a different path */
static int emit(FILE *out, char **v, size_t count, const char *target)
{
    size_t i;
    fputs("file ", out);
    quote(out, target);
    for (i = 2; i < count; ++i) {
        fputc(' ', out);
        field(out, v[i]);
    }
    fputc('\n', out);
    return !ferror(out);
}

/* a placed file lives under a tree the package never declared, and the installer
   refuses a missing parent it was not told about, so the record gains the directories
   between the private root and that file. they carry the ownership the placed file
   itself has, since the private tree belongs to the package that shipped it. */
struct parent_list {
    char **path;
    long long uid, gid;
    size_t count;
    char **declared;         /* the directories the source record already states */
    size_t declared_count;
};

static int parent_order(const void *left, const void *right)
{
    return strcmp(*(char *const *)left, *(char *const *)right);
}

/* a directory the source record already states is not written twice: the manifest
   reader rejects a duplicate path, and the existing row already describes it */
static int parent_declared(const struct parent_list *list, const char *path)
{
    size_t i;
    for (i = 0; i < list->declared_count; ++i)
        if (!strcmp(list->declared[i], path)) return 1;
    return 0;
}

static int parent_declare(struct parent_list *list, const char *path)
{
    char **grown;
    if (list->declared_count >= PRIVATE_PLACES) return 0;
    grown = realloc(list->declared, (list->declared_count + 1) * sizeof *grown);
    if (!grown) return 0;
    list->declared = grown;
    list->declared[list->declared_count] = strdup(path);
    if (!list->declared[list->declared_count]) return 0;
    ++list->declared_count;
    return 1;
}

static int parent_add(struct parent_list *list, const char *target)
{
    char *copy = strdup(target), *slash;
    size_t i;
    int ok = 0;
    if (!copy) return 0;
    /* every strict ancestor of the target, from the shallowest down. an ancestor the
       source already states ends the walk, since the ones above it are stated too */
    while ((slash = strrchr(copy, '/'))) {
        char **grown;
        *slash = '\0';
        if (!*copy) break;
        if (parent_declared(list, copy)) break;
        for (i = 0; i < list->count; ++i)
            if (!strcmp(list->path[i], copy)) break;
        if (i < list->count) break;
        if (list->count >= PRIVATE_PLACES) goto done;
        grown = realloc(list->path, (list->count + 1) * sizeof *grown);
        if (!grown) goto done;
        list->path = grown;
        list->path[list->count] = strdup(copy);
        if (!list->path[list->count]) goto done;
        ++list->count;
    }
    ok = 1;
done:
    free(copy);
    return ok;
}

static void parents_free(struct parent_list *list)
{
    size_t i;
    for (i = 0; i < list->count; ++i) free(list->path[i]);
    for (i = 0; i < list->declared_count; ++i) free(list->declared[i]);
    free(list->path);
    free(list->declared);
}

/* strcmp orders a parent before its children because the separator sorts below every
   byte a name component may hold, so one ascending pass is a valid creation order */
static void parents_write(FILE *out, struct parent_list *list)
{
    size_t i;
    if (list->count) qsort(list->path, list->count, sizeof *list->path, parent_order);
    for (i = 0; i < list->count; ++i) {
        fputs("dir ", out);
        quote(out, list->path[i]);
        fprintf(out, " 755 - - %lld %lld 0 - none - -\n", list->uid, list->gid);
    }
}

/* a rewritten row still has to be a row the manifest reader accepts, so the placed
   path is substituted in a copy rather than spliced into the original bytes */
struct rewrite {
    const struct holy_private_places *places;
    const char *artifact;
    struct parent_list parents;
    long long uid, gid;
    size_t mapped;
    int owned;
};

static const char *rewrite_target(struct rewrite *state, char **v, size_t count, int *usable)
{
    size_t i;
    *usable = 0;
    if (count < 2 || strcmp(v[0], "file")) return NULL;
    for (i = 0; i < state->places->count; ++i)
        if (!strcmp(state->places->place[i].artifact, state->artifact) &&
            !strcmp(state->places->place[i].path, v[1])) break;
    if (i == state->places->count) return NULL;
    /* a directory would move a whole subtree, which is the consumer's decision rather
       than one file's, and a hardlink group would break when only one member moved */
    if (count != 12 || strcmp(v[11], "-") ||
        !number(v[5], 10, &state->uid) || !number(v[6], 10, &state->gid)) return NULL;
    *usable = 1;
    return state->places->place[i].target;
}

int holy_private_manifest(const struct holy_private_places *places, const char *artifact,
                          const char *source, size_t length, char **record, size_t *size)
{
    struct rewrite state = {places, artifact, {0}, 0, 0, 0, 0};
    FILE *out;
    size_t start = 0, line = 0;
    int ok = 0;
    *record = NULL;
    *size = 0;
    out = open_memstream(record, size);
    if (!out) return 0;
    while (start < length) {
        const char *end = memchr(source + start, '\n', length - start);
        size_t bytes = end ? (size_t)(end - source - start) : length - start;
        char **v = NULL, *error = NULL;
        size_t count = 0;
        const char *target;
        int usable = 0;
        ++line;
        if (!holy_lex(source + start, bytes, &v, &count, "HOLY/files", line, &error)) {
            free(error);
            goto done;
        }
        free(error);
        if (count >= 2 && !strcmp(v[0], "dir") && !parent_declare(&state.parents, v[1])) {
            holy_tokens_free(v, count);
            goto done;
        }
        target = rewrite_target(&state, v, count, &usable);
        if (usable && target) {
            char *body = NULL;
            size_t body_size = 0;
            FILE *row = open_memstream(&body, &body_size);
            if (!row || !emit(row, v, count, target) || fclose(row) ||
                !parent_add(&state.parents, target) ||
                fwrite(body, 1, body_size, out) != body_size) {
                free(body);
                holy_tokens_free(v, count);
                goto done;
            }
            free(body);
            ++state.mapped;
        } else if (fwrite(source + start, 1, bytes + !!end, out) != bytes + !!end) {
            holy_tokens_free(v, count);
            goto done;
        }
        holy_tokens_free(v, count);
        start += bytes + !!end;
    }
    /* a placement the record does not carry is a decision about a file the package
       does not ship, so the rewrite is refused rather than half applied */
    if (state.mapped != holy_private_places_artifact(places, artifact)) goto done;
    /* the private tree's directories are appended: the manifest reader sorts rows and
       the installer resolves parents against a sorted list, so their place in the
       record does not decide the order they are created in */
    parents_write(out, &state.parents);
    ok = !ferror(out);
done:
    parents_free(&state.parents);
    if (fclose(out)) ok = 0;
    if (!ok) {
        free(*record);
        *record = NULL;
        *size = 0;
    }
    return ok;
}

int holy_private_place_parse(const char *text, char artifact[65], char **path)
{
    const char *equals;
    size_t length;
    *path = NULL;
    if (!text) return 0;
    equals = strchr(text, '=');
    if (!equals || equals - text != 64) return 0;
    memcpy(artifact, text, 64);
    artifact[64] = '\0';
    length = strlen(equals + 1);
    if (!length || !safe_path(equals + 1)) return 0;
    *path = strndup(equals + 1, length);
    return *path != NULL;
}