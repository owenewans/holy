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
/* HTTPS foreign object into an existing private directory, named by actual SHA-256. */
int holy_fetch_https_foreign(const char *url, const char *output,
                             const char *ca_file, char digest[65]);
int holy_fetch_https_foreign_limited(const char *url, const char *output,
                                     const char *ca_file, char digest[65],
                                     unsigned long long max_bytes);
/* owned HTTPS child URL; base is a credential/query-free directory URL. */
char *holy_fetch_child_url(const char *base, const char *filename);
/* reads the exact 72-byte unsigned HTTPS current pointer; zero succeeds. */
int holy_fetch_https_current(const char *base, const char *ca_file, char digest[65]);
/* 64-byte Ed25519 sidecar; caller verifies it against a trusted key. */
int holy_fetch_https_signature(const char *base, const char *digest,
                               const char *ca_file, unsigned char signature[64]);

#endif
