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

static int dynamic_table(Elf *elf, int fd, uint64_t file_size,
                         size_t phdr_count, const GElf_Phdr *dynamic,
                         struct holy_elf_info *info)
{
    Elf_Data *data;
    uint64_t table_addr = 0, table_size = 0, soname = 0, rpath = 0, runpath = 0;
    uint64_t verneed_addr = 0, verneed_num = 0;
    uint64_t *needed = NULL;
    size_t needed_count = 0, entry_size, entries, i, j;
    int has_addr = 0, has_size = 0, has_soname = 0, has_rpath = 0, has_runpath = 0;
    int has_verneed = 0, has_verneednum = 0;
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
        if (item.d_tag == DT_STRTAB) {
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
        }
    }
    if (!ended) goto done;
    if (has_verneed != has_verneednum) goto done;
    if (needed_count || has_soname || has_rpath || has_runpath || has_verneed) {
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
    }
    ok = 1;
done:
    free(strings);
    free(needed);
    return ok;
}

int holy_elf_read(const char *path, struct holy_elf_info *info)
{
    int fd, result = 2, seen = 0, seen_dynamic = 0;
    Elf *elf = NULL;
    GElf_Ehdr ehdr;
    struct stat st;
    size_t count, i;
    GElf_Phdr dynamic = {0};
    memset(info, 0, sizeof *info);
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) { perror(path); return 2; }
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
        }
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
    if (!info->interpreter) return "unknown";
    base = strrchr(info->interpreter, '/');
    base = base ? base + 1 : info->interpreter;
    if (!strcmp(base, "ld-linux-x86-64.so.2") || !strcmp(base, "ld-linux.so.2"))
        return "glibc";
    if (!strcmp(base, "ld-musl-x86_64.so.1") || !strcmp(base, "ld-musl-i386.so.1"))
        return "musl";
    return "unknown";
}
