#ifndef HOLY_SCAN_H
#define HOLY_SCAN_H

#include <stddef.h>

/* reports ELF facts for regular payload files without executing them. */
int holy_scan_local(const char *path);
int holy_scan_local_with_output(const char *path, int emit);
/* counts file-scoped DT_NEEDED edges after full payload validation. */
int holy_scan_local_facts(const char *path, int emit, size_t *needed);

#endif
