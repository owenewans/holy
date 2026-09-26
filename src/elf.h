#ifndef HOLY_ELF_H
#define HOLY_ELF_H

#include <stdint.h>
#include <stddef.h>

struct holy_elf_version {
    char *provider;
    char *name;
    int weak;
};

struct holy_elf_info {
    int elf_class;
    uint16_t machine;
    uint16_t type;
    char *interpreter;
    char **needed;
    size_t needed_count;
    char *soname;
    char *rpath;
    char *runpath;
    struct holy_elf_version *versions;
    size_t version_count;
};

/* returns 0 on parsed ELF, 1 on non-ELF, 2 on malformed/unsupported ELF.
   the caller frees interpreter, including after a failed read. */
int holy_elf_read(const char *path, struct holy_elf_info *info);
void holy_elf_free(struct holy_elf_info *info);
const char *holy_elf_machine(const struct holy_elf_info *info);
const char *holy_elf_runtime(const struct holy_elf_info *info);

#endif
