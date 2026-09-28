#ifndef HOLY_SOURCE_H
#define HOLY_SOURCE_H

#include <stddef.h>

/* plan writes a frozen registry proposal to stdout; apply never rereads config. */
int holy_source_plan(const char *config, const char *root);
int holy_source_apply(const char *plan, const char *digest, const char *root);
int holy_source_list(const char *root);
int holy_source_show(const char *root, const char *alias);
/* returns owned active aliases sorted by name; caller frees each and the array. */
int holy_source_active_aliases(const char *root, char ***aliases, size_t *count);
/* resolves one active alias under a shared database lock; shell-style status. */
int holy_source_active_id(const char *root, const char *alias, char output[65]);
/* returns the owned configured backend family for an active alias. */
int holy_source_type(const char *root, const char *alias, char **type);
/* resolves a saved parent source-id for one source-id; empty means no parent. */
int holy_source_parent_id(const char *root, const char *id, char output[65]);
/* returns an owned family (or NULL) and priority for one registered source-id. */
int holy_source_rank_info(const char *root, const char *id,
                          char **family, int *priority);
/* returns owned repository names for one active APK source. */
int holy_source_apk_repos(const char *root, const char *alias,
                          char ***repos, size_t *count);
/* resolves an alias retained in the registry, including inactive origins. */
int holy_source_known_id(const char *root, const char *alias, char output[65]);
/* reads an active APK repository; caller owns the returned URL. */
int holy_source_apk_repo(const char *root, const char *alias, const char *repo,
                         char id[65], char **url, char **trust, char key[65]);
/* reads an active APT source with a single HTTPS repository base. */
int holy_source_apt(const char *root, const char *alias,
                    char id[65], char **url, char **trust, char key[65]);
int holy_source_xbps(const char *root, const char *alias,
                     char id[65], char **url, char **trust, char key[65]);
/* checks one explicit sealed mirror against the active source definition. */
int holy_source_catalog(const char *root, const char *alias,
                        const char *catalog, char source_id[65]);
/* records a verified local mirror for later source queries. */
int holy_source_bind_catalog(const char *root, const char *alias,
                             const char *catalog);
/* returns an owned path for the bound mirror after source/index validation. */
int holy_source_catalog_path(const char *root, const char *alias, char **path);
/* validates the bound index without opening unrelated package payloads. */
int holy_source_catalog_path_fast(const char *root, const char *alias, char **path);
/* mirrors one registered native source with a pinned index digest. */
int holy_source_sync(const char *alias, const char *root, const char *digest,
                     const char *accepted_unsigned, const char *output,
                     const char *ca_file, const char *commit);

/* caller holds database lock; returns an owned alias record and registry hash. */
int holy_source_record(int database, const char *id, char **record, char registry[65]);
/* validates the saved alias record without consulting active configuration. */
int holy_source_instance(int instance, char id[65], char digest[65]);

#endif
