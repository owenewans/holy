#ifndef HOLY_CHECK_H
#define HOLY_CHECK_H

/* compares local package payload with a supplied root without changing it. */
int holy_check_local(const char *package, const char *root);

#endif
