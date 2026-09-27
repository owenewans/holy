#ifndef HOLY_ELF_H
#define HOLY_ELF_H

#include <stdint.h>
#include <stddef.h>

struct holy_elf_version {
    char *provider;
    char *name;
    int weak;
    uint16_t index;
};

struct holy_elf_definition {
    char *name;
    uint16_t index;
};

struct holy_elf_symbol {
    char *name;
    /* raw ELF values; section zero denotes an undefined reference. */
    unsigned binding, type, visibility;
    uint16_t section, version_index;
    int version_hidden;
    const char *version, *provider; /* borrowed from version records */
};

struct holy_elf_info {
    int elf_class;
    uint16_t machine;
    uint16_t type;
    int has_dynamic;
    uint64_t flags1;
    char *interpreter;
    char **needed;
    size_t needed_count;
    char *soname;
    char *rpath;
    char *runpath;
    struct holy_elf_version *versions;
    size_t version_count;
    struct holy_elf_definition *defined_versions;
    size_t defined_version_count;
    struct holy_elf_symbol *symbols;
    size_t symbol_count;
    uint32_t isa_needed;
    int isa_present;
};

/* returns 0 on parsed ELF, 1 on non-ELF, 2 on malformed/unsupported ELF.
   read_fd borrows a regular-file descriptor and does not change its offset.
   the caller frees the info after any result. */
int holy_elf_read_fd(int fd, struct holy_elf_info *info);
int holy_elf_read(const char *path, struct holy_elf_info *info);
void holy_elf_free(struct holy_elf_info *info);
const char *holy_elf_machine(const struct holy_elf_info *info);
const char *holy_elf_runtime(const struct holy_elf_info *info);
const char *holy_elf_isa(const struct holy_elf_info *info);

#endif
