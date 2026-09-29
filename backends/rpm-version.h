#ifndef HOLY_RPM_VERSION_H
#define HOLY_RPM_VERSION_H

int holy_rpm_version_valid(const char *evr);
int holy_rpm_version_compare(const char *left, const char *right, int *order);

#endif
