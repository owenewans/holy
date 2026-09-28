#define _POSIX_C_SOURCE 200809L
#include "elf.h"

#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* older libc headers omit these x86 psabi note constants. */
#ifndef GNU_PROPERTY_X86_ISA_1_NEEDED
#define GNU_PROPERTY_X86_ISA_1_NEEDED 0xc0008002
#endif
#ifndef GNU_PROPERTY_X86_ISA_1_BASELINE
#define GNU_PROPERTY_X86_ISA_1_BASELINE (1U << 0)
#endif
#ifndef GNU_PROPERTY_X86_ISA_1_V2
#define GNU_PROPERTY_X86_ISA_1_V2 (1U << 1)
#endif
#ifndef GNU_PROPERTY_X86_ISA_1_V3
#define GNU_PROPERTY_X86_ISA_1_V3 (1U << 2)
#endif
#ifndef GNU_PROPERTY_X86_ISA_1_V4
#define GNU_PROPERTY_X86_ISA_1_V4 (1U << 3)
#endif

static int read_exact(int fd, char *out, size_t length, off_t offset)
{
    size_t done = 0;
    while (done < length) {
        ssize_t got = pread(fd, out + done, length - done, offset + (off_t)done);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return 0;
        done += (size_t)got;
    }
    return 1;
}

static uint32_t word32(const unsigned char *p, int little_endian)
{
    if (little_endian)
        return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
               ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static int read_property_note(const unsigned char *desc, size_t size,
                              int elf_class, int little_endian,
                              struct holy_elf_info *info)
{
    size_t cursor = 0, align = elf_class == ELFCLASS64 ? 8 : 4;
    while (cursor < size) {
        uint32_t type, length;
        size_t consumed, padded;
        if (size - cursor < 8) return 0;
        type = word32(desc + cursor, little_endian);
        length = word32(desc + cursor + 4, little_endian);
        if ((size_t)length > size - cursor - 8) return 0;
        if (type == GNU_PROPERTY_X86_ISA_1_NEEDED) {
            if (length != 4 || info->isa_present) return 0;
            info->isa_needed = word32(desc + cursor + 8, little_endian);
            info->isa_present = 1;
        }
        consumed = 8 + (size_t)length;
        if (consumed > (size_t)-1 - (align - 1)) return 0;
        padded = (consumed + align - 1) & ~(align - 1);
        if (padded > size - cursor) return 0;
        cursor += padded;
    }
    return 1;
}

static int read_notes(Elf *elf, const GElf_Phdr *phdr, uint64_t file_size,
                      int elf_class, int little_endian,
                      struct holy_elf_info *info)
{
    Elf_Data *data;
    size_t cursor = 0;
    if (phdr->p_offset > file_size || phdr->p_filesz > file_size - phdr->p_offset ||
        phdr->p_filesz > 16 * 1024 * 1024) return 0;
    if (!phdr->p_filesz) return 1;
    data = elf_getdata_rawchunk(elf, (off_t)phdr->p_offset,
                                 (size_t)phdr->p_filesz,
                                 elf_class == ELFCLASS64 && phdr->p_align >= 8 ?
                                 ELF_T_NHDR8 : ELF_T_NHDR);
    if (!data) return 0;
    while (cursor < data->d_size) {
        GElf_Nhdr note;
        size_t name_offset, desc_offset;
        size_t next = gelf_getnote(data, cursor, &note, &name_offset, &desc_offset);
        const unsigned char *bytes = data->d_buf;
        if (!next || next <= cursor || next > data->d_size ||
            name_offset > data->d_size || note.n_namesz > data->d_size - name_offset ||
            desc_offset > data->d_size || note.n_descsz > data->d_size - desc_offset)
            return 0;
        if (note.n_type == NT_GNU_PROPERTY_TYPE_0 && note.n_namesz == 4 &&
            !memcmp(bytes + name_offset, "GNU\0", 4) &&
            !read_property_note(bytes + desc_offset, note.n_descsz,
                                elf_class, little_endian, info)) return 0;
        cursor = next;
    }
    return 1;
}

static char *dynamic_string(const char *table, size_t length, uint64_t offset,
                            int allow_empty)
{
    const char *end;
    char *copy;
    size_t n, i;
    if (offset >= length) return NULL;
    end = memchr(table + offset, '\0', length - (size_t)offset);
    if (!end) return NULL;
    n = (size_t)(end - (table + offset));
    if (!n && !allow_empty) return NULL;
    for (i = 0; i < n; ++i)
        if ((unsigned char)table[offset + i] < 32 || table[offset + i] == 127)
            return NULL;
    copy = malloc(n + 1);
    if (copy) memcpy(copy, table + offset, n + 1);
    return copy;
}

static int map_virtual(Elf *elf, size_t count, uint64_t address,
                       uint64_t minimum, uint64_t file_size,
                       uint64_t *offset, uint64_t *available)
{
    size_t i;
    for (i = 0; i < count; ++i) {
        GElf_Phdr load;
        uint64_t delta, start, length;
        if (!gelf_getphdr(elf, (int)i, &load)) return 0;
        if (load.p_type != PT_LOAD || address < load.p_vaddr) continue;
        delta = address - load.p_vaddr;
        if (delta > load.p_filesz || minimum > load.p_filesz - delta ||
            load.p_offset > file_size || delta > file_size - load.p_offset)
            continue;
        start = load.p_offset + delta;
        length = load.p_filesz - delta;
        if (length > file_size - start) length = file_size - start;
        if (minimum > length) continue;
        *offset = start;
        *available = length;
        return 1;
    }
    return 0;
}

static int version_needs(Elf *elf, uint64_t offset, uint64_t available,
                         uint64_t count, const char *strings,
                         size_t string_length, struct holy_elf_info *info)
{
    Elf_Data *data;
    size_t min_need = gelf_fsize(elf, ELF_T_VNEED, 1, EV_CURRENT);
    size_t min_aux = gelf_fsize(elf, ELF_T_VNAUX, 1, EV_CURRENT);
    uint64_t cursor = 0, i;
    if (available > 16 * 1024 * 1024) available = 16 * 1024 * 1024;
    if (!min_need || !min_aux || !count || available < min_aux ||
        count > available / min_need) return 0;
    data = elf_getdata_rawchunk(elf, (off_t)offset, (size_t)available, ELF_T_VNEED);
    if (!data) return 0;
    for (i = 0; i < count; ++i) {
        GElf_Verneed need;
        uint64_t aux_cursor, j;
        char *provider;
        if (cursor > available - min_need || cursor > INT_MAX ||
            !gelf_getverneed(data, (int)cursor, &need) || need.vn_version != 1 ||
            !need.vn_cnt || need.vn_cnt > available / min_aux ||
            !need.vn_aux || need.vn_aux > available - cursor) return 0;
        provider = dynamic_string(strings, string_length, need.vn_file, 0);
        if (!provider) return 0;
        aux_cursor = cursor + need.vn_aux;
        for (j = 0; j < need.vn_cnt; ++j) {
            GElf_Vernaux aux;
            struct holy_elf_version *next;
            char *name, *source;
            if (aux_cursor > available - min_aux || aux_cursor > INT_MAX ||
                !gelf_getvernaux(data, (int)aux_cursor, &aux)) {
                free(provider);
                return 0;
            }
            name = dynamic_string(strings, string_length, aux.vna_name, 0);
            source = strdup(provider);
            if (!name || !source ||
                info->version_count == (size_t)-1 / sizeof *info->versions) {
                free(name);
                free(source);
                free(provider);
                return 0;
            }
            next = realloc(info->versions,
                           (info->version_count + 1) * sizeof *info->versions);
            if (!next) { free(name); free(source); free(provider); return 0; }
            info->versions = next;
            info->versions[info->version_count].provider = source;
            info->versions[info->version_count].name = name;
            info->versions[info->version_count].weak = !!(aux.vna_flags & VER_FLG_WEAK);
            info->versions[info->version_count].index = aux.vna_other & 0x7fff;
            ++info->version_count;
            if (j + 1 < need.vn_cnt) {
                if (!aux.vna_next || aux.vna_next > available - aux_cursor) {
                    free(provider);
                    return 0;
                }
                aux_cursor += aux.vna_next;
            }
        }
        free(provider);
        if (i + 1 < count) {
            if (!need.vn_next || need.vn_next > available - cursor) return 0;
            cursor += need.vn_next;
        }
    }
    return 1;
}

static int version_definitions(Elf *elf, uint64_t offset, uint64_t available,
                               uint64_t count, const char *strings,
                               size_t string_length, struct holy_elf_info *info)
{
    Elf_Data *data;
    size_t min_def = gelf_fsize(elf, ELF_T_VDEF, 1, EV_CURRENT);
    size_t min_aux = gelf_fsize(elf, ELF_T_VDAUX, 1, EV_CURRENT);
    uint64_t cursor = 0, i;
    if (available > 16 * 1024 * 1024) available = 16 * 1024 * 1024;
    if (!min_def || !min_aux || !count || available < min_aux ||
        count > available / min_def) return 0;
    data = elf_getdata_rawchunk(elf, (off_t)offset, (size_t)available, ELF_T_VDEF);
    if (!data) return 0;
    for (i = 0; i < count; ++i) {
        GElf_Verdef def;
        uint64_t aux_cursor, j;
        if (cursor > available - min_def || cursor > INT_MAX ||
            !gelf_getverdef(data, (int)cursor, &def) || def.vd_version != 1 ||
            !def.vd_cnt || def.vd_cnt > available / min_aux ||
            !def.vd_aux || def.vd_aux > available - cursor) return 0;
        aux_cursor = cursor + def.vd_aux;
        for (j = 0; j < def.vd_cnt; ++j) {
            GElf_Verdaux aux;
            char *name;
            struct holy_elf_definition *next;
            if (aux_cursor > available - min_aux || aux_cursor > INT_MAX ||
                !gelf_getverdaux(data, (int)aux_cursor, &aux)) return 0;
            name = dynamic_string(strings, string_length, aux.vda_name, 0);
            if (!name || info->defined_version_count ==
                         (size_t)-1 / sizeof *info->defined_versions) {
                free(name);
                return 0;
            }
            if (j) free(name);
            else {
                next = realloc(info->defined_versions,
                               (info->defined_version_count + 1) *
                               sizeof *info->defined_versions);
                if (!next) { free(name); return 0; }
                info->defined_versions = next;
                info->defined_versions[info->defined_version_count].name = name;
                info->defined_versions[info->defined_version_count++].index = def.vd_ndx & 0x7fff;
            }
            if (j + 1 < def.vd_cnt) {
                if (!aux.vda_next || aux.vda_next > available - aux_cursor) return 0;
                aux_cursor += aux.vda_next;
            }
        }
        if (i + 1 < count) {
            if (!def.vd_next || def.vd_next > available - cursor) return 0;
            cursor += def.vd_next;
        }
    }
    return 1;
}

static int hash_symbol_count(Elf *elf, uint64_t file_size, size_t phdr_count,
                             uint64_t address, int gnu, size_t *count)
{
    uint64_t offset, available, skip;
    uint32_t *words, buckets, first, bloom, last = 0;
    Elf_Data *data;
    size_t i, chain;
    if (!map_virtual(elf, phdr_count, address, gnu ? 16 : 8,
                     file_size, &offset, &available)) return 0;
    data = elf_getdata_rawchunk(elf, (off_t)offset, gnu ? 16 : 8, ELF_T_WORD);
    if (!data) return 0;
    words = data->d_buf;
    buckets = words[0];
    first = words[1];
    if (!gnu) {
        if (!buckets || !first || (uint64_t)buckets + first > (available - 8) / 4)
            return 0;
        *count = first;
        return 1;
    }
    bloom = words[2];
    if (!buckets || !bloom || (bloom & (bloom - 1))) return 0;
    skip = 16 + (uint64_t)bloom * (gelf_getclass(elf) == ELFCLASS64 ? 8 : 4);
    if (skip > available || buckets > (available - skip) / 4 ||
        buckets > 4 * 1024 * 1024) return 0;
    data = elf_getdata_rawchunk(elf, (off_t)(offset + skip), (size_t)buckets * 4, ELF_T_WORD);
    if (!data) return 0;
    words = data->d_buf;
    for (i = 0; i < buckets; ++i) {
        if (words[i] && words[i] < first) return 0;
        if (words[i] > last) last = words[i];
    }
    /* an empty gnu hash does not bound the unexported import symbols. */
    if (!last) { *count = 0; return first != 0; }
    skip += (uint64_t)buckets * 4;
    chain = (size_t)last - first;
    if (chain >= (available - skip) / 4) return 0;
    available = (available - skip) / 4;
    if (available > 4 * 1024 * 1024) available = 4 * 1024 * 1024;
    data = elf_getdata_rawchunk(elf, (off_t)(offset + skip), (size_t)available * 4, ELF_T_WORD);
    if (!data) return 0;
    words = data->d_buf;
    for (; chain < available; ++chain) {
        if (words[chain] & 1) {
            if ((uint64_t)first + chain + 1 > SIZE_MAX) return 0;
            *count = (size_t)first + chain + 1;
            return 1;
        }
    }
    return 0;
}

static int dynamic_symbols(Elf *elf, uint64_t file_size, size_t phdr_count,
                           uint64_t address, uint64_t syment,
                           uint64_t hash, int has_hash, uint64_t gnu_hash,
                           int has_gnu_hash, uint64_t versym, int has_versym,
                           const char *strings, size_t string_length,
                           struct holy_elf_info *info)
{
    struct version_ref { const char *name, *provider; } *versions = NULL;
    Elf_Data *symbols, *indices = NULL;
    uint64_t offset, available;
    size_t count = 0, gnu_count = 0, names_size = 0, i;
    size_t entry = gelf_fsize(elf, ELF_T_SYM, 1, EV_CURRENT);
    int ok = 0;
    if (!entry || syment != entry || (!has_hash && !has_gnu_hash)) return 0;
    if (has_hash && !hash_symbol_count(elf, file_size, phdr_count, hash, 0, &count)) return 0;
    if (has_gnu_hash && !hash_symbol_count(elf, file_size, phdr_count, gnu_hash, 1, &gnu_count)) return 0;
    if (has_hash && has_gnu_hash && gnu_count && count != gnu_count) return 0;
    if (!has_hash) count = gnu_count;
    if (!count) {
        Elf_Scn *section = NULL;
        while ((section = elf_nextscn(elf, section)) != NULL) {
            GElf_Shdr header;
            if (!gelf_getshdr(section, &header)) return 0;
            if (header.sh_type == SHT_DYNSYM && header.sh_addr == address) {
                if (header.sh_entsize != entry || header.sh_size % entry ||
                    header.sh_size > 16 * 1024 * 1024) return 0;
                count = (size_t)(header.sh_size / entry);
                break;
            }
        }
    }
    if (!count || count > 16 * 1024 * 1024 / entry || count > INT_MAX ||
        count > SIZE_MAX / sizeof *info->symbols ||
        !map_virtual(elf, phdr_count, address, count * entry, file_size, &offset, &available)) return 0;
    symbols = elf_getdata_rawchunk(elf, (off_t)offset, count * entry, ELF_T_SYM);
    if (!symbols) return 0;
    if (has_versym) {
        if (!map_virtual(elf, phdr_count, versym, count * 2, file_size, &offset, &available)) return 0;
        indices = elf_getdata_rawchunk(elf, (off_t)offset, count * 2, ELF_T_HALF);
        if (!indices) return 0;
    }
    versions = calloc(32768, sizeof *versions);
    if (!versions) return 0;
    for (i = 0; i < info->version_count; ++i) {
        struct holy_elf_version *v = &info->versions[i];
        if (v->index < 2 || versions[v->index].name) goto done;
        versions[v->index].name = v->name;
        versions[v->index].provider = v->provider;
    }
    for (i = 0; i < info->defined_version_count; ++i) {
        struct holy_elf_definition *v = &info->defined_versions[i];
        if (!v->index || versions[v->index].name) goto done;
        versions[v->index].name = v->name;
    }
    info->symbols = calloc(count, sizeof *info->symbols);
    if (!info->symbols) goto done;
    info->symbol_count = count;
    for (i = 0; i < count; ++i) {
        GElf_Sym symbol;
        GElf_Versym index = 1;
        struct holy_elf_symbol *out = &info->symbols[i];
        if (!gelf_getsym(symbols, (int)i, &symbol) || symbol.st_shndx == SHN_XINDEX ||
            (indices && !gelf_getversym(indices, (int)i, &index))) goto done;
        if (!i && (symbol.st_name || symbol.st_info || symbol.st_other ||
                   symbol.st_shndx || symbol.st_value || symbol.st_size)) goto done;
        out->name = dynamic_string(strings, string_length, symbol.st_name, 1);
        if (!out->name) goto done;
        if (strlen(out->name) + 1 > 64 * 1024 * 1024 - names_size) goto done;
        names_size += strlen(out->name) + 1;
        out->binding = GELF_ST_BIND(symbol.st_info);
        out->type = GELF_ST_TYPE(symbol.st_info);
        out->visibility = symbol.st_other & 7;
        out->section = symbol.st_shndx;
        out->version_index = index & 0x7fff;
        out->version_hidden = !!(index & 0x8000);
        if (out->version_index > 1) {
            struct version_ref *v = &versions[out->version_index];
            if (!v->name) goto done;
            out->version = v->name;
            out->provider = v->provider;
        }
    }
    ok = 1;
done:
    free(versions);
    return ok;
}

static int dynamic_table(Elf *elf, int fd, uint64_t file_size,
                         size_t phdr_count, const GElf_Phdr *dynamic,
                         struct holy_elf_info *info)
{
    Elf_Data *data;
    uint64_t table_addr = 0, table_size = 0, soname = 0, rpath = 0, runpath = 0;
    uint64_t verneed_addr = 0, verneed_num = 0;
    uint64_t verdef_addr = 0, verdef_num = 0;
    uint64_t symtab = 0, syment = 0, hash = 0, gnu_hash = 0, versym = 0;
    uint64_t *needed = NULL;
    size_t needed_count = 0, entry_size, entries, i, j;
    int has_addr = 0, has_size = 0, has_soname = 0, has_rpath = 0, has_runpath = 0;
    int has_verneed = 0, has_verneednum = 0;
    int has_verdef = 0, has_verdefnum = 0;
    int has_symtab = 0, has_syment = 0, has_hash = 0, has_gnu_hash = 0, has_versym = 0;
    int has_flags1 = 0;
    int ended = 0, ok = 0;
    char *strings = NULL;
    if (!dynamic->p_filesz || dynamic->p_filesz > 16 * 1024 * 1024 ||
        dynamic->p_offset > file_size || dynamic->p_filesz > file_size - dynamic->p_offset)
        return 0;
    entry_size = gelf_fsize(elf, ELF_T_DYN, 1, EV_CURRENT);
    if (!entry_size || dynamic->p_filesz % entry_size) return 0;
    entries = (size_t)dynamic->p_filesz / entry_size;
    data = elf_getdata_rawchunk(elf, (off_t)dynamic->p_offset,
                                 (size_t)dynamic->p_filesz, ELF_T_DYN);
    if (!data) return 0;
    for (i = 0; i < entries; ++i) {
        GElf_Dyn item;
        uint64_t *next;
        if (!gelf_getdyn(data, (int)i, &item)) goto done;
        if (item.d_tag == DT_NULL) { ended = 1; break; }
        if (item.d_tag == DT_FLAGS_1) {
            if (has_flags1++) goto done;
            info->flags1 = item.d_un.d_val;
        } else if (item.d_tag == DT_SYMTAB) {
            if (has_symtab++) goto done;
            symtab = item.d_un.d_ptr;
        } else if (item.d_tag == DT_SYMENT) {
            if (has_syment++) goto done;
            syment = item.d_un.d_val;
        } else if (item.d_tag == DT_HASH) {
            if (has_hash++) goto done;
            hash = item.d_un.d_ptr;
        } else if (item.d_tag == DT_GNU_HASH) {
            if (has_gnu_hash++) goto done;
            gnu_hash = item.d_un.d_ptr;
        } else if (item.d_tag == DT_VERSYM) {
            if (has_versym++) goto done;
            versym = item.d_un.d_ptr;
        } else if (item.d_tag == DT_STRTAB) {
            if (has_addr++) goto done;
            table_addr = item.d_un.d_ptr;
        } else if (item.d_tag == DT_STRSZ) {
            if (has_size++) goto done;
            table_size = item.d_un.d_val;
        } else if (item.d_tag == DT_NEEDED) {
            if (needed_count == (size_t)-1 / sizeof *needed) goto done;
            next = realloc(needed, (needed_count + 1) * sizeof *needed);
            if (!next) goto done;
            needed = next;
            needed[needed_count++] = item.d_un.d_val;
        } else if (item.d_tag == DT_SONAME) {
            if (has_soname++) goto done;
            soname = item.d_un.d_val;
        } else if (item.d_tag == DT_RPATH) {
            if (has_rpath++) goto done;
            rpath = item.d_un.d_val;
        } else if (item.d_tag == DT_RUNPATH) {
            if (has_runpath++) goto done;
            runpath = item.d_un.d_val;
        } else if (item.d_tag == DT_VERNEED) {
            if (has_verneed++) goto done;
            verneed_addr = item.d_un.d_ptr;
        } else if (item.d_tag == DT_VERNEEDNUM) {
            if (has_verneednum++) goto done;
            verneed_num = item.d_un.d_val;
        } else if (item.d_tag == DT_VERDEF) {
            if (has_verdef++) goto done;
            verdef_addr = item.d_un.d_ptr;
        } else if (item.d_tag == DT_VERDEFNUM) {
            if (has_verdefnum++) goto done;
            verdef_num = item.d_un.d_val;
        }
    }
    if (!ended || has_symtab != has_syment ||
        (!has_symtab && (has_hash || has_gnu_hash || has_versym))) goto done;
    if (has_verneed != has_verneednum || has_verdef != has_verdefnum) goto done;
    if (needed_count || has_soname || has_rpath || has_runpath || has_verneed ||
        has_verdef || has_symtab) {
        uint64_t string_offset = 0, available = 0;
        if (!has_addr || !has_size || !table_size || table_size > 16 * 1024 * 1024)
            goto done;
        if (!map_virtual(elf, phdr_count, table_addr, table_size, file_size,
                         &string_offset, &available)) goto done;
        strings = malloc((size_t)table_size);
        if (!strings || !read_exact(fd, strings, (size_t)table_size, (off_t)string_offset))
            goto done;
        for (j = 0; j < needed_count; ++j) {
            char **next_names;
            char *name = dynamic_string(strings, (size_t)table_size, needed[j], 0);
            if (!name || info->needed_count == (size_t)-1 / sizeof *info->needed) {
                free(name);
                goto done;
            }
            next_names = realloc(info->needed,
                                 (info->needed_count + 1) * sizeof *info->needed);
            if (!next_names) { free(name); goto done; }
            info->needed = next_names;
            info->needed[info->needed_count++] = name;
        }
        if (has_soname && !(info->soname = dynamic_string(strings, (size_t)table_size, soname, 0)))
            goto done;
        if (has_rpath && !(info->rpath = dynamic_string(strings, (size_t)table_size, rpath, 1)))
            goto done;
        if (has_runpath && !(info->runpath = dynamic_string(strings, (size_t)table_size, runpath, 1)))
            goto done;
        if (has_verneed) {
            uint64_t need_offset, need_available;
            size_t minimum = gelf_fsize(elf, ELF_T_VNEED, 1, EV_CURRENT);
            if (!minimum || !map_virtual(elf, phdr_count, verneed_addr,
                                         minimum, file_size, &need_offset, &need_available) ||
                !version_needs(elf, need_offset, need_available, verneed_num,
                               strings, (size_t)table_size, info)) goto done;
        }
        if (has_verdef) {
            uint64_t def_offset, def_available;
            size_t minimum = gelf_fsize(elf, ELF_T_VDEF, 1, EV_CURRENT);
            if (!minimum || !map_virtual(elf, phdr_count, verdef_addr,
                                         minimum, file_size, &def_offset, &def_available) ||
                !version_definitions(elf, def_offset, def_available, verdef_num,
                                     strings, (size_t)table_size, info)) goto done;
        }
    }
    if (has_symtab && (!strings || !dynamic_symbols(elf, file_size, phdr_count,
        symtab, syment, hash, has_hash, gnu_hash, has_gnu_hash, versym,
        has_versym, strings, (size_t)table_size, info))) goto done;
    ok = 1;
done:
    free(strings);
    free(needed);
    return ok;
}

int holy_elf_read_fd(int fd, struct holy_elf_info *info)
{
    int result = 2, seen = 0, seen_dynamic = 0;
    Elf *elf = NULL;
    GElf_Ehdr ehdr;
    struct stat st;
    off_t original_offset;
    size_t count, i;
    GElf_Phdr dynamic = {0};
    memset(info, 0, sizeof *info);
    original_offset = lseek(fd, 0, SEEK_CUR);
    if (original_offset < 0) return 2;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode)) goto done;
    if (elf_version(EV_CURRENT) == EV_NONE) goto done;
    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) goto done;
    if (elf_kind(elf) != ELF_K_ELF) { result = 1; goto done; }
    if (!gelf_getehdr(elf, &ehdr) || elf_getphdrnum(elf, &count) || count > INT_MAX)
        goto done;
    info->elf_class = gelf_getclass(elf);
    info->machine = ehdr.e_machine;
    info->type = ehdr.e_type;
    if (info->elf_class != ELFCLASS32 && info->elf_class != ELFCLASS64) goto done;
    for (i = 0; i < count; ++i) {
        GElf_Phdr phdr;
        char *end;
        if (!gelf_getphdr(elf, i, &phdr)) goto done;
        if (phdr.p_type == PT_DYNAMIC) {
            if (seen_dynamic++) goto done;
            dynamic = phdr;
            info->has_dynamic = 1;
        }
        if (phdr.p_type == PT_NOTE &&
            !read_notes(elf, &phdr, (uint64_t)st.st_size,
                        info->elf_class, ehdr.e_ident[EI_DATA] == ELFDATA2LSB,
                        info)) goto done;
        if (phdr.p_type != PT_INTERP) continue;
        if (seen++ || !phdr.p_filesz || phdr.p_filesz > 1024 * 1024 ||
            phdr.p_offset > (uint64_t)st.st_size ||
            phdr.p_filesz > (uint64_t)st.st_size - phdr.p_offset) goto done;
        info->interpreter = malloc((size_t)phdr.p_filesz + 1);
        if (!info->interpreter ||
            !read_exact(fd, info->interpreter, (size_t)phdr.p_filesz, (off_t)phdr.p_offset))
            goto done;
        info->interpreter[phdr.p_filesz] = '\0';
        end = memchr(info->interpreter, '\0', (size_t)phdr.p_filesz);
        if (!end || end == info->interpreter) goto done;
        {
            char *p;
            for (p = info->interpreter; p < end; ++p)
                if ((unsigned char)*p < 32 || *p == 127) goto done;
            for (p = end + 1; p < info->interpreter + phdr.p_filesz; ++p)
                if (*p) goto done;
        }
    }
    if (seen_dynamic && !dynamic_table(elf, fd, (uint64_t)st.st_size,
                                        count, &dynamic, info)) goto done;
    result = 0;
done:
    if (elf) elf_end(elf);
    if (lseek(fd, original_offset, SEEK_SET) < 0) result = 2;
    return result;
}

int holy_elf_read(const char *path, struct holy_elf_info *info)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    int result;
    if (fd < 0) {
        perror(path);
        memset(info, 0, sizeof *info);
        return 2;
    }
    result = holy_elf_read_fd(fd, info);
    close(fd);
    return result;
}

void holy_elf_free(struct holy_elf_info *info)
{
    free(info->interpreter);
    info->interpreter = NULL;
    {
        size_t i;
        for (i = 0; i < info->needed_count; ++i) free(info->needed[i]);
    }
    free(info->needed);
    info->needed = NULL;
    info->needed_count = 0;
    free(info->soname);
    free(info->rpath);
    free(info->runpath);
    info->soname = info->rpath = info->runpath = NULL;
    {
        size_t i;
        for (i = 0; i < info->version_count; ++i) {
            free(info->versions[i].provider);
            free(info->versions[i].name);
        }
    }
    free(info->versions);
    info->versions = NULL;
    info->version_count = 0;
    {
        size_t i;
        for (i = 0; i < info->defined_version_count; ++i)
            free(info->defined_versions[i].name);
    }
    free(info->defined_versions);
    info->defined_versions = NULL;
    info->defined_version_count = 0;
    {
        size_t i;
        for (i = 0; i < info->symbol_count; ++i) free(info->symbols[i].name);
    }
    free(info->symbols);
    info->symbols = NULL;
    info->symbol_count = 0;
}

const char *holy_elf_machine(const struct holy_elf_info *info)
{
    if (info->machine == EM_386 && info->elf_class == ELFCLASS32) return "x86";
    if (info->machine == EM_X86_64 && info->elf_class == ELFCLASS64) return "x86_64";
    if (info->machine == EM_X86_64 && info->elf_class == ELFCLASS32) return "x32";
    return "other";
}

const char *holy_elf_runtime(const struct holy_elf_info *info)
{
    const char *base;
    if (!info->interpreter) {
        size_t i;
        int glibc = 0, musl = 0;
        if (info->type == ET_DYN && info->soname &&
            ((!strcmp(info->soname, "libc.musl-x86_64.so.1") &&
              info->machine == EM_X86_64 && info->elf_class == ELFCLASS64) ||
             (!strcmp(info->soname, "libc.musl-i386.so.1") &&
              info->machine == EM_386 && info->elf_class == ELFCLASS32))) return "musl";
        if (info->type == ET_DYN && info->soname &&
            (!strcmp(info->soname, "libc.so.6") ||
             (!strcmp(info->soname, "ld-linux-x86-64.so.2") &&
              info->machine == EM_X86_64 && info->elf_class == ELFCLASS64) ||
             (!strcmp(info->soname, "ld-linux.so.2") &&
              info->machine == EM_386 && info->elf_class == ELFCLASS32))) return "glibc";
        if (info->type == ET_DYN && info->has_dynamic) {
            for (i = 0; i < info->needed_count; ++i) {
                if (!strcmp(info->needed[i], "libc.so.6")) glibc = 1;
                if ((!strcmp(info->needed[i], "libc.musl-x86_64.so.1") &&
                     info->machine == EM_X86_64 && info->elf_class == ELFCLASS64) ||
                    (!strcmp(info->needed[i], "libc.musl-i386.so.1") &&
                     info->machine == EM_386 && info->elf_class == ELFCLASS32)) musl = 1;
            }
            for (i = 0; i < info->version_count; ++i)
                if (info->versions[i].provider && info->versions[i].name &&
                    !strcmp(info->versions[i].provider, "libc.so.6") &&
                    !strncmp(info->versions[i].name, "GLIBC_", 6)) glibc = 1;
            if (glibc != musl) return glibc ? "glibc" : "musl";
        }
        if (info->type == ET_EXEC && !info->has_dynamic && !info->needed_count)
            return "nolibc";
        return "unknown";
    }
    base = strrchr(info->interpreter, '/');
    base = base ? base + 1 : info->interpreter;
    if (!strcmp(base, "ld-linux-x86-64.so.2") || !strcmp(base, "ld-linux.so.2"))
        return "glibc";
    if (!strcmp(base, "ld-musl-x86_64.so.1") || !strcmp(base, "ld-musl-i386.so.1"))
        return "musl";
    return "unknown";
}

const char *holy_elf_isa(const struct holy_elf_info *info)
{
    uint32_t mask = info->isa_needed;
    if (!info->isa_present || info->machine != EM_X86_64 ||
        info->elf_class != ELFCLASS64 ||
        (mask & ~(GNU_PROPERTY_X86_ISA_1_BASELINE | GNU_PROPERTY_X86_ISA_1_V2 |
                  GNU_PROPERTY_X86_ISA_1_V3 | GNU_PROPERTY_X86_ISA_1_V4)))
        return "unknown";
    if (mask & GNU_PROPERTY_X86_ISA_1_V4) return "x86-64-v4";
    if (mask & GNU_PROPERTY_X86_ISA_1_V3) return "x86-64-v3";
    if (mask & GNU_PROPERTY_X86_ISA_1_V2) return "x86-64-v2";
    if (mask & GNU_PROPERTY_X86_ISA_1_BASELINE) return "x86-64-baseline";
    return "unknown";
}

int holy_elf_exports_symbol(const struct holy_elf_info *provider,
                            const struct holy_elf_symbol *wanted)
{
    size_t i;
    for (i = 0; i < provider->symbol_count; ++i) {
        const struct holy_elf_symbol *s = &provider->symbols[i];
        if (!s->section ||
            (s->binding != STB_GLOBAL && s->binding != STB_WEAK && s->binding != 10) ||
            (s->visibility != STV_DEFAULT && s->visibility != STV_PROTECTED) ||
            strcmp(s->name, wanted->name)) continue;
        if ((wanted->type == STT_TLS) != (s->type == STT_TLS)) continue;
        if (wanted->type == STT_FUNC && s->type != STT_FUNC && s->type != 10) continue;
        if (wanted->type == STT_OBJECT && s->type != STT_OBJECT) continue;
        if (wanted->version) {
            if (!s->version || strcmp(s->version, wanted->version)) continue;
        } else if (s->version_hidden) continue;
        return 1;
    }
    return 0;
}
