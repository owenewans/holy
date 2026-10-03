#ifndef HOLY_PRIVATE_H
#define HOLY_PRIVATE_H

#include <stddef.h>

/* the private root one artifact's displaced files live under. the relative structure
   the artifact shipped is kept, so a relocated program still finds its neighbors, and
   the private file stays owned by the package that shipped it rather than by whoever
   won the public path. */
#define HOLY_PRIVATE_ROOT "usr/lib/holy/private/"

/* the longest relative path a private target is built from, which bounds the buffer a
   caller needs for the target itself */
#define PRIVATE_PATH_LIMIT 4096

/* fills target with HOLY_PRIVATE_ROOT + artifact + "/" + the relative path.
   returns 0 unless artifact is a lowercase sha256 and path is a safe relative path
   that is not itself inside the private root. */
int holy_private_target(const char *artifact, const char *path, char *target, size_t size);

/* whether one manifest path already names a private tree, which a placement may
   never nest a second time. */
int holy_private_path(const char *path);

/* one confirmed placement: an artifact whose file at a public path installs under
   its private root instead. the public path keeps its other provider. */
struct holy_private_place {
    char artifact[65];
    char *path;
    char *target;
};

struct holy_private_places {
    struct holy_private_place *place;
    size_t count;
};

void holy_private_places_free(struct holy_private_places *places);
/* rejects a duplicate pair, an unknown digest, an unsafe path, a nested private
   path and a target the same artifact already uses. */
int holy_private_place_add(struct holy_private_places *places, const char *artifact,
                           const char *path);
/* one line per placement in the order it was recorded. */
void holy_private_places_print(const struct holy_private_places *places, size_t count);
/* the private target for one artifact path, or NULL when nothing was placed there */
const char *holy_private_lookup(const struct holy_private_places *places,
                                const char *artifact, const char *path);
/* how many placements one artifact carries */
size_t holy_private_places_artifact(const struct holy_private_places *places,
                                   const char *artifact);

/* rewrites one verified HOLY/files record so each placed path of that artifact names
   its private target. the caller keeps the original as package-files and stores the
   result as files, so the digest of the source artifact and the digest of what was
   installed stay separate. returns 0 when a placed path is absent from the record,
   is a directory, or the record does not parse. */
int holy_private_manifest(const struct holy_private_places *places, const char *artifact,
                          const char *source, size_t length, char **record, size_t *size);

/* reads one ARTIFACT=PATH placement from a plan or a journal line. */
int holy_private_place_parse(const char *text, char artifact[65], char **path);

/* the SONAME one payload of a verified package carries, or NULL when that payload is
   not an ELF or states none. a placed shared library is what a consumer names, so the
   SONAME is the fact a private set has to be matched on. */
int holy_private_soname(const char *snapshot, const char *path, char **soname);

/* one confirmed search decision: the consumer whose search path is set to the private
   directory that holds the library it needs. the directory is absolute, since a search
   path carrying a slash that is not absolute resolves against the process that loads the
   file rather than against the installed root. */
struct holy_private_search {
    char consumer[65];
    char *directory;
};

struct holy_private_searches {
    struct holy_private_search *search;
    size_t count;
};

void holy_private_searches_free(struct holy_private_searches *searches);
/* rejects a duplicate consumer, an unknown digest, and a directory that is not an
   absolute path under the private root with no empty, relative or dotted component. */
int holy_private_search_add(struct holy_private_searches *searches, const char *consumer,
                            const char *directory);
/* reads one CONSUMER=DIR decision from a plan or a journal line. */
int holy_private_search_parse(const char *text, char consumer[65], char **directory);
/* whether one directory is the shape a search path may name */
int holy_private_search_directory(const char *directory);
/* the directory one consumer was decided with, or NULL when it was not decided */
const char *holy_private_search_lookup(const struct holy_private_searches *searches,
                                       const char *consumer);
/* one line per decision in the order it was recorded */
void holy_private_searches_print(const struct holy_private_searches *searches, size_t count);
/* the directory part of an absolute path, which is what a search path names. the caller
   owns the returned string, and NULL when the path has no directory. */
char *holy_private_directory(const char *path);

/* every ELF payload of one package that names SONAME in DT_NEEDED. a zero return from
   the visitor stops the walk. borrowed names stay valid during the callback only. */
typedef int (*holy_private_consumer)(void *context, const char *path, const char *needed);
int holy_private_consumers(const char *snapshot, const char *soname,
                           holy_private_consumer visit, void *context);

#endif