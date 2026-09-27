#define _POSIX_C_SOURCE 200809L
#include "scan.h"
#include "elf.h"
#include "package.h"
#include "verify.h"
#include "stage.h"

#include <archive.h>
#include <archive_entry.h>
#include <gelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void print_token(const char *path)
{
    const unsigned char *p = (const unsigned char *)path;
    for (; *p; ++p) {
        if (*p == '\\' || *p <= 32 || *p >= 127)
            printf("\\x%02x", (unsigned int)*p);
        else putchar(*p);
    }
}

static const char *named_runtime(const struct holy_elf_info *info, const char *path)
{
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    if (!strcmp(base, "libc.so.6")) return "glibc";
    if ((!strcmp(holy_elf_machine(info), "x86_64") &&
         (!strcmp(base, "libc.musl-x86_64.so.1") || !strcmp(base, "ld-musl-x86_64.so.1"))) ||
        (!strcmp(holy_elf_machine(info), "x86") &&
         (!strcmp(base, "libc.musl-i386.so.1") || !strcmp(base, "ld-musl-i386.so.1")))) return "musl";
    return NULL;
}

static int scan(const char *path, int emit, size_t *needed,
                struct holy_scan_result *collected)
{
    struct archive *a = NULL;
    struct archive_entry *entry;
    char *snapshot = holy_stage_local(path, "holy-scan");
    char *arch = NULL, *libc = NULL;
    char buffer[65536];
    size_t scanned = 0, edges = 0;
    int status, ok = 0;
    if (needed) *needed = 0;
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
        const char *runtime;
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
        {
            size_t i;
            for (i = 0; i < info.needed_count; ++i) {
                const char *required = named_runtime(&info, info.needed[i]);
                if (required && strcmp(libc, required)) {
                    fprintf(stderr, "holypkg: ELF runtime requirement conflicts with package libc: %s\n", name);
                    holy_elf_free(&info);
                    goto done;
                }
            }
        }
        runtime = holy_elf_runtime(&info);
        if (!strcmp(runtime, "unknown") && info.type == ET_DYN) {
            size_t i;
            for (i = 0; i < info.needed_count; ++i) {
                const char *required = named_runtime(&info, info.needed[i]);
                if (required) runtime = required;
            }
            if (info.soname &&
                ((!strcmp(info.soname, "ld-linux-x86-64.so.2") &&
                  !strcmp(holy_elf_machine(&info), "x86_64")) ||
                 (!strcmp(info.soname, "ld-linux.so.2") &&
                  !strcmp(holy_elf_machine(&info), "x86"))))
                for (i = 0; i < info.defined_version_count; ++i)
                    if (!strcmp(info.defined_versions[i].name, "GLIBC_PRIVATE"))
                        runtime = "glibc";
        }
        if (!strcmp(runtime, "unknown")) {
            fprintf(stderr, "holypkg: ELF runtime unknown; package tag cannot prove ABI: %s\n",
                    name);
            holy_elf_free(&info);
            goto done;
        }
        if (strcmp(arch, holy_elf_machine(&info)) || strcmp(libc, runtime)) {
            fprintf(stderr, "holypkg: ELF arch/libc mismatch in payload: %s\n", name);
            holy_elf_free(&info);
            goto done;
        }
        if (emit) {
            size_t i;
            fputs("elf ", stdout);
            print_token(name + 5);
            printf(" class=ELF%d machine=%s e_machine=%u runtime=%s isa=%s\n",
                   info.elf_class == 1 ? 32 : 64, holy_elf_machine(&info),
                    (unsigned int)info.machine, runtime,
                   holy_elf_isa(&info));
            if (info.soname) {
                fputs("soname ", stdout);
                print_token(name + 5);
                putchar(' ');
                print_token(info.soname);
                putchar('\n');
            }
            for (i = 0; i < info.needed_count; ++i) {
                fputs("needed ", stdout);
                print_token(name + 5);
                putchar(' ');
                print_token(info.needed[i]);
                putchar('\n');
            }
            for (i = 0; i < info.version_count; ++i) {
                fputs("version ", stdout);
                print_token(name + 5);
                putchar(' ');
                print_token(info.versions[i].provider);
                putchar(' ');
                print_token(info.versions[i].name);
                printf(" %s\n", info.versions[i].weak ? "weak" : "required");
            }
            for (i = 0; i < info.defined_version_count; ++i) {
                fputs("version-def ", stdout);
                print_token(name + 5);
                putchar(' ');
                print_token(info.defined_versions[i].name);
                putchar('\n');
            }
            for (i = 0; i < info.symbol_count; ++i) {
                const struct holy_elf_symbol *s = &info.symbols[i];
                if (!s->name[0]) continue;
                fputs("symbol ", stdout);
                print_token(name + 5);
                putchar(' ');
                print_token(s->name);
                printf(" binding=%u type=%u visibility=%u section=%u version-index=%u hidden=%d version=",
                       s->binding, s->type, s->visibility, (unsigned)s->section,
                       (unsigned)s->version_index, s->version_hidden);
                print_token(s->version ? s->version : "none");
                fputs(" provider=", stdout);
                print_token(s->provider ? s->provider : "none");
                putchar('\n');
            }
        }
        if (info.needed_count > (size_t)-1 - edges) {
            holy_elf_free(&info);
            goto done;
        }
        edges += info.needed_count;
        if (collected) {
            struct holy_scanned_file *next;
            char *copy = strdup(name + 5);
            if (!copy || collected->count >= 65536) {
                free(copy); holy_elf_free(&info); goto done;
            }
            next = realloc(collected->files, (collected->count + 1) * sizeof *next);
            if (!next) { free(copy); holy_elf_free(&info); goto done; }
            collected->files = next;
            next[collected->count].path = copy;
            next[collected->count].runtime = runtime;
            next[collected->count].mode = (unsigned int)archive_entry_perm(entry);
            next[collected->count++].elf = info;
            memset(&info, 0, sizeof info);
        }
        holy_elf_free(&info);
        ++scanned;
    }
    if (status != ARCHIVE_EOF) goto done;
    if (emit) printf("scanned %zu ELF files\n", scanned);
    if (needed) *needed = edges;
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

int holy_scan_local_with_output(const char *path, int emit)
{
    return holy_scan_local_facts(path, emit, NULL);
}

int holy_scan_local_facts(const char *path, int emit, size_t *needed)
{
    return scan(path, emit, needed, NULL);
}

int holy_scan_collect(const char *path, struct holy_scan_result *result)
{
    memset(result, 0, sizeof *result);
    return scan(path, 0, NULL, result);
}

void holy_scan_free(struct holy_scan_result *result)
{
    size_t i;
    for (i = 0; i < result->count; ++i) {
        free(result->files[i].path);
        holy_elf_free(&result->files[i].elf);
    }
    free(result->files);
    memset(result, 0, sizeof *result);
}

int holy_scan_local(const char *path)
{
    return holy_scan_local_with_output(path, 1);
}
