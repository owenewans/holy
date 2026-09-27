#ifndef HOLY_FETCH_H
#define HOLY_FETCH_H

/* copies a local object into an existing directory; no extraction or hooks. */
int holy_fetch_local(const char *source, const char *output);
/* borrows dir; checks expected SHA-256 when non-NULL; writes a 70-byte name. */
int holy_fetch_at(const char *source, int dir, const char *expected,
                   char name[70]);
/* pinned native HTTPS fetch; zero success, optional published-path output. */
int holy_fetch_https(const char *url, const char *expected,
                      const char *output, const char *ca_file, int emit);
/* pinned metadata bytes, at most 16 MiB, published as output/SHA256; no UI. */
int holy_fetch_https_data(const char *url, const char *expected,
                         const char *output, const char *ca_file);
/* owned HTTPS child URL; base is a credential/query-free directory URL. */
char *holy_fetch_child_url(const char *base, const char *filename);

#endif
