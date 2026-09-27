#ifndef HOLY_SOURCE_H
#define HOLY_SOURCE_H

/* plan writes a frozen registry proposal to stdout; apply never rereads config. */
int holy_source_plan(const char *config, const char *root);
int holy_source_apply(const char *plan, const char *digest, const char *root);
int holy_source_list(const char *root);

/* caller holds database lock; returns an owned alias record and registry hash. */
int holy_source_record(int database, const char *id, char **record, char registry[65]);
/* validates the saved alias record without consulting active configuration. */
int holy_source_instance(int instance, char id[65], char digest[65]);

#endif
