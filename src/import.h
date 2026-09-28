#ifndef HOLY_IMPORT_H
#define HOLY_IMPORT_H

/* local foreign input; output is a new private conversion directory.
   source is provenance text, never a trusted installed source-id. */
int holy_import_pacman(const char *input, const char *source, const char *output);
int holy_import_deb(const char *input, const char *source, const char *output);
int holy_import_slackware(const char *input, const char *source, const char *output);
int holy_import_apk(const char *input, const char *source, const char *output,
                    const char *public_key);

#endif
