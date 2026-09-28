#ifndef HOLY_REPO_H
#define HOLY_REPO_H

/* materialize a pinned HTTPS catalog in a new directory; CLI status result. */
int holy_repo_mirror(const char *base, const char *digest, const char *output,
                     const char *ca_file);
/* identical validation, with a registered source ID in sealed provenance. */
int holy_repo_mirror_source(const char *base, const char *digest, const char *output,
                            const char *ca_file, const char *source_id,
                            int current_accepted);

/* writes an unsigned local prototype index after validating native objects. */
int holy_repo_index(const char *directory);
int holy_repo_list(const char *directory);
int holy_repo_search(const char *directory, const char *query);
int holy_repo_seal(const char *directory);
int holy_repo_providers(const char *directory, const char *kind,
                        const char *name, int json);
/* returns shell-style status; validates a sealed local catalog before solve. */
int holy_repo_solve(const char *directory, const char *name,
                    const char *choice, int json);
int holy_repo_fetch(const char *directory, const char *digest, const char *output);
/* fetches one unambiguous package name from a sealed local catalog. */
int holy_repo_fetch_name(const char *directory, const char *name,
                         const char *output, int extract);
/* verifies the sealed mirror's recorded source and exact registered URL. */
int holy_repo_source_catalog(const char *directory, const char *source_id,
                             const char *url);

#endif
