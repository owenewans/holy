#ifndef HOLY_XBPS_VERSION_H
#define HOLY_XBPS_VERSION_H

/* returns zero for versions outside the supported Dewey grammar. */
int holy_xbps_version_compare(const char *left, const char *right, int *order);

#endif
