#ifndef HOLY_IMPORT_H
#define HOLY_IMPORT_H

/* local foreign input; output is a new private conversion directory.
   source is provenance text, never a trusted installed source-id. */
int holy_import_pacman(const char *input, const char *source, const char *output);
int holy_import_deb(const char *input, const char *source, const char *output);
int holy_import_deb_verified(const char *input, const char *source, const char *output,
                             const char *expected_hash, const char *verification,
                             const char *key_hash, const char *signature_hash,
                             const char *index_hash, const char *source_url);
int holy_import_slackware(const char *input, const char *source, const char *output);
int holy_import_apk(const char *input, const char *source, const char *output,
                    const char *public_key);
int holy_import_xbps(const char *input, const char *source, const char *output);
/* called only after the fetcher checks the pinned archive and optional signature. */
int holy_import_xbps_verified(const char *input, const char *source, const char *output,
                              const char *expected_hash, const char *verification,
                              const char *key_hash, const char *signature_hash,
                              const char *index_hash, const char *source_url);

#endif
