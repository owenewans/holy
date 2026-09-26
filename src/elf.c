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

static int dynamic_table(Elf *elf, int fd, uint64_t file_size,
                         size_t phdr_count, const GElf_Phdr *dynamic,
                         struct holy_elf_info *info)
{
    Elf_Data *data;
    uint64_t table_addr = 0, table_size = 0, soname = 0, rpath = 0, runpath = 0;
    uint64_t *needed = NULL;
    size_t needed_count = 0, entry_size, entries, i, j;
    int has_addr = 0, has_size = 0, has_soname = 0, has_rpath = 0, has_runpath = 0;
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
        }
    }
    if (!ended) goto done;
    if (needed_count || has_soname || has_rpath || has_runpath) {
        uint64_t string_offset = 0;
        int found = 0;
        if (!has_addr || !has_size || !table_size || table_size > 16 * 1024 * 1024)
            goto done;
        for (j = 0; j < phdr_count; ++j) {
            GElf_Phdr load;
            uint64_t delta;
            if (!gelf_getphdr(elf, j, &load)) goto done;
            if (load.p_type != PT_LOAD || table_addr < load.p_vaddr) continue;
            delta = table_addr - load.p_vaddr;
            if (delta > load.p_filesz || table_size > load.p_filesz - delta ||
                load.p_offset > file_size || delta > file_size - load.p_offset ||
                table_size > file_size - load.p_offset - delta) continue;
            string_offset = load.p_offset + delta;
            found = 1;
            break;
        }
        if (!found) goto done;
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
