#ifndef HOLY_IMPORT_H
#define HOLY_IMPORT_H

/* local foreign input; output is a new private conversion directory.
   source is provenance text, never a trusted installed source-id. */
int holy_import_pacman(const char *input, const char *source, const char *output);

#endif
