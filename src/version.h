#ifndef HOLY_VERSION_H
#define HOLY_VERSION_H

/* compares explicit Holy native versions; returns 0 for invalid input. */
int holy_version_compare(const char *left, const char *right, int *order);

#endif
