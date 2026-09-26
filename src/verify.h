#ifndef HOLY_VERIFY_H
#define HOLY_VERIFY_H

/* checks the regular-file subset of HOLY/files without extracting files. */
int holy_verify(const char *path);
int holy_verify_with_output(const char *path, int emit);

#endif
