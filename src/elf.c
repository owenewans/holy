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

int holy_elf_read(const char *path, struct holy_elf_info *info)
{
    int fd, result = 2, seen = 0;
    Elf *elf = NULL;
    GElf_Ehdr ehdr;
    struct stat st;
    size_t count, i;
    memset(info, 0, sizeof *info);
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) { perror(path); return 2; }
    if (fstat(fd, &st) || !S_ISREG(st.st_mode)) goto done;
    if (elf_version(EV_CURRENT) == EV_NONE) goto done;
    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) goto done;
    if (elf_kind(elf) != ELF_K_ELF) { result = 1; goto done; }
    if (!gelf_getehdr(elf, &ehdr) || elf_getphdrnum(elf, &count)) goto done;
    info->elf_class = gelf_getclass(elf);
    info->machine = ehdr.e_machine;
    info->type = ehdr.e_type;
    if (info->elf_class != ELFCLASS32 && info->elf_class != ELFCLASS64) goto done;
    for (i = 0; i < count; ++i) {
        GElf_Phdr phdr;
        char *end;
        if (!gelf_getphdr(elf, i, &phdr)) goto done;
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
        }
    }
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
