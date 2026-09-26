#ifndef HOLY_SCAN_H
#define HOLY_SCAN_H

/* reports ELF facts for regular payload files without executing them. */
int holy_scan_local(const char *path);
int holy_scan_local_with_output(const char *path, int emit);

#endif
