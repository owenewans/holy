#ifndef HOLY_FETCH_H
#define HOLY_FETCH_H

/* copies a local object into an existing directory; no extraction or hooks. */
int holy_fetch_local(const char *source, const char *output);
/* borrows dir; checks expected SHA-256 when non-NULL; writes a 70-byte name. */
int holy_fetch_at(const char *source, int dir, const char *expected,
                   char name[70]);
/* pinned native HTTPS fetch; zero success, otherwise CLI status code. */
int holy_fetch_https(const char *url, const char *expected,
                     const char *output, const char *ca_file);

#endif
