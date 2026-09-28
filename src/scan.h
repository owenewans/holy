#ifndef HOLY_SCAN_H
#define HOLY_SCAN_H

#include <stddef.h>
#include "elf.h"

struct holy_scanned_file {
    char *path;
    const char *runtime;
    unsigned int mode;
    struct holy_elf_info elf;
};
struct holy_scanned_script {
    char *path;
    char *interpreter;
    int kind;
};
struct holy_scanned_symlink {
    char *path;
    char *target;
};
struct holy_scan_result {
    struct holy_scanned_file *files;
    size_t count;
    struct holy_scanned_script *scripts;
    size_t script_count;
    struct holy_scanned_symlink *symlinks;
    size_t symlink_count;
};

/* collects owned facts from a verified snapshot; free after any result. */
int holy_scan_collect(const char *path, struct holy_scan_result *result);
void holy_scan_free(struct holy_scan_result *result);

/* reports ELF facts for regular payload files without executing them. */
int holy_scan_local(const char *path);
int holy_scan_local_with_output(const char *path, int emit);
/* counts file-scoped DT_NEEDED edges after full payload validation. */
int holy_scan_local_facts(const char *path, int emit, size_t *needed);

#endif
