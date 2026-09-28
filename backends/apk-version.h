#ifndef HOLY_APK_VERSION_H
#define HOLY_APK_VERSION_H

/* returns zero when a version uses grammar that this adapter cannot compare. */
int holy_apk_version_compare(const char *left, const char *right, int *order);

#endif
