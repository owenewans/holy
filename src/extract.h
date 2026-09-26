#ifndef HOLY_EXTRACT_H
#define HOLY_EXTRACT_H

/* extracts a verified regular-file package into a new directory. */
int holy_extract_local(const char *source, const char *output);
int holy_extract_preflight(const char *source);

#endif
