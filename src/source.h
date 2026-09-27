#ifndef HOLY_SOURCE_H
#define HOLY_SOURCE_H

/* plan writes a frozen registry proposal to stdout; apply never rereads config. */
int holy_source_plan(const char *config, const char *root);
int holy_source_apply(const char *plan, const char *digest, const char *root);
int holy_source_list(const char *root);

#endif
