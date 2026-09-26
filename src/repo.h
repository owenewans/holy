#ifndef HOLY_REPO_H
#define HOLY_REPO_H

/* writes an unsigned local prototype index after validating native objects. */
int holy_repo_index(const char *directory);
int holy_repo_list(const char *directory);
int holy_repo_search(const char *directory, const char *query);
int holy_repo_seal(const char *directory);
int holy_repo_providers(const char *directory, const char *kind, const char *name);
int holy_repo_fetch(const char *directory, const char *digest, const char *output);

#endif
