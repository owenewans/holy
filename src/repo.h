#ifndef HOLY_REPO_H
#define HOLY_REPO_H

#include <stddef.h>

struct holy_package_identity;

struct holy_repo_set {
    char **digests;
    size_t count;
    char index[65];
};

struct holy_repo_slot_list {
    struct holy_package_identity *items;
    size_t count;
    char index[65];
};

/* materialize a pinned HTTPS catalog in a new directory; CLI status result. */
int holy_repo_mirror(const char *base, const char *digest, const char *output,
                     const char *ca_file);
int holy_repo_mirror_signed(const char *base, const char *digest, const char *output,
                            const char *ca_file, const char *public_key);
/* identical validation, with a registered source ID in sealed provenance. */
int holy_repo_mirror_source(const char *base, const char *digest, const char *output,
                            const char *ca_file, const char *source_id,
                            int current_accepted);
int holy_repo_mirror_source_signed(const char *base, const char *digest,
                                   const char *output, const char *ca_file,
                                   const char *source_id, const char *public_key);

/* writes an unsigned local prototype index after validating native objects. */
int holy_repo_index(const char *directory);
int holy_repo_list(const char *directory);
int holy_repo_search(const char *directory, const char *query);
/* ranked hints only; candidates still need exact requirement validation. */
int holy_repo_search_fuzzy(const char *directory, const char *query);
/* exact absolute path; returns 6 when the catalog has no complete file index. */
int holy_repo_search_file(const char *directory, const char *query);
int holy_repo_search_file_fuzzy(const char *directory, const char *query);
/* verifies the catalog and returns one exact package record or a choice status. */
int holy_repo_info_name(const char *directory, const char *name);
/* reads validated dependency records from one pinned catalog generation. */
int holy_repo_requirements(const char *directory, const char *name);
int holy_repo_seal(const char *directory);
int holy_repo_seal_signed(const char *directory, const char *private_key);
int holy_repo_verify_signature(const char *directory, const char *public_key);
int holy_repo_providers(const char *directory, const char *kind,
                        const char *name, int json);
/* checks exact indexed provider coverage without staging package artifacts. */
int holy_repo_has_provider(const char *directory, const char *kind,
                           const char *name);
/* probes the missing consumer's recorded ELF edge before offering a source. */
int holy_repo_has_compatible_soname(const char *directory, const char *name,
                                    const char *root, const char *consumer_digest,
                                    const char *consumer_path);
/* returns shell-style status; validates a sealed local catalog before solve. */
int holy_repo_solve(const char *directory, const char *name,
                    const char *choice, int json);
int holy_repo_fetch(const char *directory, const char *digest, const char *output);
/* fetches one unambiguous package name from a sealed local catalog. */
int holy_repo_fetch_name(const char *directory, const char *name,
                         const char *output, int extract);
/* verifies the sealed mirror's recorded source and exact registered URL. */
int holy_repo_source_catalog(const char *directory, const char *source_id,
                             const char *url, const char *public_key);
/* verifies the complete sealed catalog and reads its selected index digest. */
int holy_repo_catalog_index(const char *directory, char digest[65]);
/* checks the pinned index and records without opening unrelated payloads. */
int holy_repo_catalog_index_fast(const char *directory, char digest[65]);
/* confirm one artifact belongs to the pinned catalog and installed slot. */
int holy_repo_catalog_slot_digest(const char *directory,
                                  const struct holy_package_identity *slot,
                                  const char *artifact, char index_digest[65]);
/* stages the indexed requirement closure for v5 catalogs; older indexes use the full pool. */
int holy_repo_stage_set(const char *directory, const char *name,
                        const char *root, struct holy_repo_set *set);
/* stage exact indexed providers and their in-source dependency closure. */
int holy_repo_stage_provider(const char *directory, const char *kind,
                             const char *name, const char *root,
                             struct holy_repo_set *set);
/* stages only indexed versions in one installed source slot. */
int holy_repo_stage_slot(const char *directory, const char *root,
                         const struct holy_package_identity *slot,
                         struct holy_repo_set *set);
/* reads one installed slot from the pinned index without opening payloads. */
int holy_repo_slot_candidates(const char *directory,
                              const struct holy_package_identity *slot,
                              struct holy_repo_slot_list *out);
void holy_repo_slot_list_free(struct holy_repo_slot_list *list);
/* stages and verifies one indexed artifact in that slot. */
int holy_repo_stage_slot_digest(const char *directory, const char *root,
                                const struct holy_package_identity *slot,
                                const char *digest, struct holy_repo_set *set);
void holy_repo_set_free(struct holy_repo_set *set);

#endif
