#ifndef HOLY_APT_RELEASE_H
#define HOLY_APT_RELEASE_H

int holy_apt_release_sync(const char *base, const char *suite,
                          const char *component, const char *arch,
                          const char *source, const char *keyring,
                          const char *output, const char *ca_file, int inrelease,
                          int files);
int holy_apt_key_fingerprint(const char *keyring, char hash[65]);
int holy_apt_release_sync_source(const char *root, const char *alias,
                                 const char *suite, const char *component,
                                 const char *arch, const char *keyring,
                                 const char *output, const char *ca_file,
                                 int inrelease, int files);
/* 1 detached, 2 InRelease, 0 absent, -1 invalid, -2 missing verifier. */
int holy_apt_verify_release(const char *catalog, const char *index_hash);
/* call after release verification; 1 matching file index, 0 absent, -1 invalid. */
int holy_apt_verify_files(const char *catalog);

#endif
