#ifndef HOLY_SOURCE_H
#define HOLY_SOURCE_H

/* plan writes a frozen registry proposal to stdout; apply never rereads config. */
int holy_source_plan(const char *config, const char *root);
int holy_source_apply(const char *plan, const char *digest, const char *root);
int holy_source_list(const char *root);
/* resolves one active alias under a shared database lock; shell-style status. */
int holy_source_active_id(const char *root, const char *alias, char output[65]);
/* checks one explicit sealed mirror against the active source definition. */
int holy_source_catalog(const char *root, const char *alias,
                        const char *catalog, char source_id[65]);
/* mirrors one registered holy-http source with a pinned index digest. */
int holy_source_sync(const char *alias, const char *root, const char *digest,
                     const char *accepted_unsigned, const char *output,
                     const char *ca_file);

/* caller holds database lock; returns an owned alias record and registry hash. */
int holy_source_record(int database, const char *id, char **record, char registry[65]);
/* validates the saved alias record without consulting active configuration. */
int holy_source_instance(int instance, char id[65], char digest[65]);

#endif
