#ifndef HOLY_DEB_VERSION_H
#define HOLY_DEB_VERSION_H

/* returns 1 and -1/0/1 in order, or 0 for malformed versions. */
int holy_deb_version_compare(const char *a, const char *b, int *order);

#endif
