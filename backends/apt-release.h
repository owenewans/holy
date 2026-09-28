#ifndef HOLY_APT_RELEASE_H
#define HOLY_APT_RELEASE_H

int holy_apt_release_sync(const char *base, const char *suite,
                          const char *component, const char *arch,
                          const char *source, const char *keyring,
                          const char *output, const char *ca_file);
int holy_apt_key_fingerprint(const char *keyring, char hash[65]);
int holy_apt_release_sync_source(const char *root, const char *alias,
                                 const char *suite, const char *component,
                                 const char *arch, const char *keyring,
                                 const char *output, const char *ca_file);
/* 1 valid, 0 absent, -1 invalid, -2 missing verifier. */
int holy_apt_verify_release(const char *catalog, const char *index_hash);

#endif
