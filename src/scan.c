#define _POSIX_C_SOURCE 200809L
#include "scan.h"
#include "elf.h"
#include "package.h"
#include "verify.h"
#include "stage.h"

#include <archive.h>
#include <archive_entry.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void print_path(const char *path)
{
    const unsigned char *p = (const unsigned char *)path;
    for (; *p; ++p) {
        if (*p == '\\' || *p <= 32 || *p >= 127)
            printf("\\x%02x", (unsigned int)*p);
        else putchar(*p);
    }
}

int holy_scan_local_with_output(const char *path, int emit)
{
    struct archive *a = NULL;
    struct archive_entry *entry;
    char *snapshot = holy_stage_local(path, "holy-scan");
    char *arch = NULL, *libc = NULL;
    char buffer[65536];
    size_t scanned = 0;
    int status, ok = 0;
    if (!snapshot) {
        fprintf(stderr, "holypkg: could not stage regular local input\n");
        return 0;
    }
    if (!holy_verify_with_output(snapshot, 0) ||
        !holy_package_tags(snapshot, &arch, &libc)) goto done;
    a = archive_read_new();
    if (!a || archive_read_support_filter_lz4(a) != ARCHIVE_OK ||
        archive_read_support_format_tar(a) != ARCHIVE_OK ||
        archive_read_open_filename(a, snapshot, 8192) != ARCHIVE_OK) goto done;
    while ((status = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        const char *name = archive_entry_pathname(entry);
        size_t prefix = 0;
        la_ssize_t got;
        FILE *temp;
        struct holy_elf_info info;
        int result;
        if (!name || strncmp(name, "DATA/", 5) || !name[5] ||
            archive_entry_filetype(entry) != AE_IFREG ||
            archive_entry_hardlink(entry) || archive_entry_size(entry) < 4) {
            if (archive_read_data_skip(a) != ARCHIVE_OK) goto done;
            continue;
        }
        while (prefix < 4) {
            got = archive_read_data(a, buffer + prefix, 4 - prefix);
            if (got <= 0) goto done;
            prefix += (size_t)got;
        }
        if (memcmp(buffer, "\177ELF", 4)) {
            if (archive_read_data_skip(a) != ARCHIVE_OK) goto done;
            continue;
        }
        temp = tmpfile();
        if (!temp) goto done;
        if (fwrite(buffer, 1, prefix, temp) != prefix) {
            fclose(temp);
            goto done;
        }
        while ((got = archive_read_data(a, buffer, sizeof buffer)) > 0)
            if (fwrite(buffer, 1, (size_t)got, temp) != (size_t)got) {
                fclose(temp);
                goto done;
            }
        if (got < 0 || fflush(temp)) { fclose(temp); goto done; }
        result = holy_elf_read_fd(fileno(temp), &info);
        fclose(temp);
        if (result) {
            holy_elf_free(&info);
            fprintf(stderr, "holypkg: malformed ELF in payload: %s\n", name);
            goto done;
        }
        if (strcmp(arch, holy_elf_machine(&info)) ||
            (strcmp(holy_elf_runtime(&info), "unknown") &&
             strcmp(libc, holy_elf_runtime(&info)))) {
            fprintf(stderr, "holypkg: ELF arch/libc mismatch in payload: %s\n", name);
            holy_elf_free(&info);
            goto done;
        }
        if (emit) {
            fputs("elf ", stdout);
            print_path(name + 5);
            printf(" class=ELF%d machine=%s e_machine=%u runtime=%s isa=%s\n",
                   info.elf_class == 1 ? 32 : 64, holy_elf_machine(&info),
                   (unsigned int)info.machine, holy_elf_runtime(&info),
                   holy_elf_isa(&info));
        }
        holy_elf_free(&info);
        ++scanned;
    }
    if (status != ARCHIVE_EOF) goto done;
    if (emit) printf("scanned %zu ELF files\n", scanned);
    ok = 1;
done:
    if (!ok) fprintf(stderr, "holypkg: payload ELF scan incomplete\n");
    if (a) archive_read_free(a);
    unlink(snapshot);
    free(snapshot);
    free(arch);
    free(libc);
    return ok;
}

int holy_scan_local(const char *path)
{
    return holy_scan_local_with_output(path, 1);
}
