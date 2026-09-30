#define _POSIX_C_SOURCE 200809L
#include "scan.h"
#include "elf.h"
#include "package.h"
#include "verify.h"
#include "install.h"
#include "stage.h"
#include "script.h"

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

struct scan_link { char *path, *target; unsigned int mode; };
struct scan_links { struct scan_link *items; size_t count; struct holy_scan_result *collected; };

static int collect_link(void *opaque, const struct holy_manifest_entry *entry)
{
    struct scan_links *links = opaque;
    struct scan_link *next;
    if (entry->link && links->collected) {
        struct holy_scanned_symlink *alias;
        if (links->collected->symlink_count >= 65536) return 0;
        alias = realloc(links->collected->symlinks,
            (links->collected->symlink_count + 1) * sizeof *alias);
        if (!alias) return 0;
        links->collected->symlinks = alias;
        alias = &alias[links->collected->symlink_count];
        alias->path = strdup(entry->path);
        alias->target = strdup(entry->link);
        if (!alias->path || !alias->target) {
            free(alias->path); free(alias->target);
            return 0;
        }
        ++links->collected->symlink_count;
    }
    if (!entry->hardlink) return 1;
    if (links->count >= 65536) return 0;
    next = realloc(links->items, (links->count + 1) * sizeof *next);
    if (!next) return 0;
    links->items = next;
    next = &next[links->count++];
    next->path = malloc(strlen(entry->path) + 6);
    next->target = strdup(entry->hardlink);
    next->mode = entry->mode;
    if (next->path) sprintf(next->path, "DATA/%s", entry->path);
    return next->path && next->target;
}

static int link_order(const void *left, const void *right)
{
    const struct scan_link *a = left, *b = right;
    int result = strcmp(a->target, b->target);
    return result ? result : strcmp(a->path, b->path);
}

static const char *module_release(const char *name, size_t *length)
{
    const char *prefix = "DATA/usr/lib/modules/";
    const char *release, *end;
    size_t size = strlen(name);
    if (strncmp(name, prefix, strlen(prefix)) || size < 3 ||
        strcmp(name + size - 3, ".ko")) return NULL;
    release = name + strlen(prefix);
    end = strchr(release, '/');
    if (!end || end == release || strncmp(end, "/kernel/", 8) || !end[8])
        return NULL;
    *length = (size_t)(end - release);
    return release;
}

static int inspect_elf(int fd, const char *name, unsigned int mode,
                        const char *arch, const char *libc, int emit, size_t *edges,
                        struct holy_scan_result *collected)
{
    struct holy_elf_info info;
    const char *runtime;
    int result;
    result = holy_elf_read_fd(fd, &info);
    if (result) {
        holy_elf_free(&info);
        fprintf(stderr, "holypkg: malformed ELF in payload: %s\n", name);
        return 0;
    }
    if (info.type == ET_REL) {
        size_t release_length = 0;
        const char *release = module_release(name, &release_length);
        if (!release || strcmp(libc, "nolibc") ||
            strcmp(arch, holy_elf_machine(&info)) ||
            !holy_elf_kernel_module_fd(fd, &info, release, release_length)) {
            fprintf(stderr, "holypkg: invalid kernel module or unsupported ELF object: %s\n", name);
            holy_elf_free(&info);
            return 0;
        }
        if (emit) {
            fputs("kernel-module ", stdout);
            print_token(name + 5);
            printf(" machine=%s release=", holy_elf_machine(&info));
            fwrite(release, 1, release_length, stdout);
            putchar('\n');
        }
        holy_elf_free(&info);
        return 1;
    }
    {
        size_t i;
        for (i = 0; i < info.needed_count; ++i) {
            const char *required = named_runtime(&info, info.needed[i]);
            if (required && strcmp(libc, required)) {
                fprintf(stderr, "holypkg: ELF runtime requirement conflicts with package libc: %s\n", name);
                holy_elf_free(&info);
                return 0;
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
        return 0;
    }
    if (strcmp(arch, holy_elf_machine(&info)) || strcmp(libc, runtime)) {
        fprintf(stderr, "holypkg: ELF arch/libc mismatch in payload: %s\n", name);
        holy_elf_free(&info);
        return 0;
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
    if (info.needed_count > (size_t)-1 - *edges) {
        holy_elf_free(&info);
        return 0;
    }
    *edges += info.needed_count;
    if (collected) {
        struct holy_scanned_file *next;
        char *copy = strdup(name + 5);
        if (!copy || collected->count >= 65536) {
            free(copy); holy_elf_free(&info); return 0;
        }
        next = realloc(collected->files, (collected->count + 1) * sizeof *next);
        if (!next) { free(copy); holy_elf_free(&info); return 0; }
        collected->files = next;
        next[collected->count].path = copy;
        next[collected->count].runtime = runtime;
        next[collected->count].mode = mode;
        next[collected->count++].elf = info;
        memset(&info, 0, sizeof info);
    }
    holy_elf_free(&info);
    return 1;
}

static int inspect_script(int fd, const char *name, unsigned int mode,
                          la_int64_t size, int emit, struct holy_scan_result *collected)
{
    char *interpreter = NULL;
    int kind = holy_script_read_fd(fd, (off_t)size, (mode_t)mode, &interpreter);
    if (kind < 0) return 0;
    if (!kind) return 1;
    if (emit) {
        fputs("script ", stdout);
        print_token(name + 5);
        putchar(' ');
        print_token(interpreter);
        printf(" kind=%s\n", kind == 1 ? "direct" : kind == 2 ? "env" : "unknown");
    }
    if (collected) {
        struct holy_scanned_script *next;
        if (collected->script_count >= 65536) { free(interpreter); return 0; }
        next = realloc(collected->scripts, (collected->script_count + 1) * sizeof *next);
        if (!next) { free(interpreter); return 0; }
        collected->scripts = next;
        next = &next[collected->script_count];
        next->path = strdup(name + 5);
        if (!next->path) { free(interpreter); return 0; }
        next->interpreter = interpreter;
        next->kind = kind;
        ++collected->script_count;
    } else free(interpreter);
    return 1;
}

static int scan(const char *path, int emit, size_t *needed,
                struct holy_scan_result *collected)
{
    struct archive *a = NULL;
    struct archive_entry *entry;
    char *snapshot = holy_stage_local(path, "holy-scan");
    char *arch = NULL, *libc = NULL;
    char buffer[65536];
    size_t scanned = 0, edges = 0, i;
    struct scan_links links = {0};
    int status, ok = 0;
    if (needed) *needed = 0;
    if (!snapshot) {
        fprintf(stderr, "holypkg: could not stage regular local input\n");
        return 0;
    }
    links.collected = collected;
    if (!holy_verify_visit(snapshot, collect_link, &links) ||
        !holy_package_tags(snapshot, &arch, &libc)) goto done;
    if (links.count) qsort(links.items, links.count, sizeof *links.items, link_order);
    a = archive_read_new();
    if (!a || archive_read_support_filter_lz4(a) != ARCHIVE_OK ||
        archive_read_support_format_tar(a) != ARCHIVE_OK ||
        archive_read_open_filename(a, snapshot, 8192) != ARCHIVE_OK) goto done;
    while ((status = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        const char *name = archive_entry_pathname(entry);
        size_t prefix = 0, prefix_limit;
        la_ssize_t got;
        FILE *temp;
        int elf, script;
        if (!name || strncmp(name, "DATA/", 5) || !name[5] ||
            archive_entry_filetype(entry) != AE_IFREG ||
            archive_entry_hardlink(entry) || archive_entry_size(entry) < 2) {
            if (archive_read_data_skip(a) != ARCHIVE_OK) goto done;
            continue;
        }
        prefix_limit = archive_entry_size(entry) < 4 ?
                       (size_t)archive_entry_size(entry) : 4;
        while (prefix < prefix_limit) {
            got = archive_read_data(a, buffer + prefix, prefix_limit - prefix);
            if (got <= 0) goto done;
            prefix += (size_t)got;
        }
        elf = prefix == 4 && !memcmp(buffer, "\177ELF", 4);
        script = (archive_entry_perm(entry) & 0111) && prefix >= 2 &&
                 buffer[0] == '#' && buffer[1] == '!';
        if (!elf && !script) {
            if (archive_read_data_skip(a) != ARCHIVE_OK) goto done;
            continue;
        }
        temp = tmpfile();
        if (!temp) goto done;
        if (fwrite(buffer, 1, prefix, temp) != prefix) {
            fclose(temp);
            goto done;
        }
        while ((got = archive_read_data(a, buffer,
                        elf ? sizeof buffer :
                        prefix < 256 ? 256 - prefix : 0)) > 0) {
            if (fwrite(buffer, 1, (size_t)got, temp) != (size_t)got) {
                fclose(temp);
                goto done;
            }
            if (!elf) {
                prefix += (size_t)got;
                if (prefix == 256) break;
            }
        }
        if (got < 0 || fflush(temp)) { fclose(temp); goto done; }
        if (!elf) {
            size_t low = 0, high = links.count, j;
            if (!inspect_script(fileno(temp), name, (unsigned int)archive_entry_perm(entry),
                                archive_entry_size(entry), emit, collected)) { fclose(temp); goto done; }
            while (low < high) {
                size_t middle = low + (high - low) / 2;
                if (strcmp(links.items[middle].target, name + 5) < 0) low = middle + 1;
                else high = middle;
            }
            for (j = low; j < links.count && !strcmp(links.items[j].target, name + 5); ++j)
                if (!inspect_script(fileno(temp), links.items[j].path, links.items[j].mode,
                                    archive_entry_size(entry), emit, collected)) { fclose(temp); goto done; }
            if (archive_read_data_skip(a) != ARCHIVE_OK) { fclose(temp); goto done; }
            fclose(temp);
            continue;
        }
        if (!inspect_elf(fileno(temp), name, (unsigned int)archive_entry_perm(entry),
                         arch, libc, emit, &edges, collected)) { fclose(temp); goto done; }
        {
            size_t low = 0, high = links.count, i;
            while (low < high) {
                size_t middle = low + (high - low) / 2;
                if (strcmp(links.items[middle].target, name + 5) < 0) low = middle + 1;
                else high = middle;
            }
            for (i = low; i < links.count && !strcmp(links.items[i].target, name + 5); ++i) {
                if (!inspect_elf(fileno(temp), links.items[i].path, links.items[i].mode,
                                 arch, libc, emit, &edges, collected)) { fclose(temp); goto done; }
                ++scanned;
            }
        }
        fclose(temp);
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
    for (i = 0; i < links.count; ++i) { free(links.items[i].path); free(links.items[i].target); }
    free(links.items);
    return ok;
}

/* the installed payload gives the same ELF and script facts as the archive it was
   installed from, read through the target root, so an installed artifact whose cached
   object is gone is still describable. a hardlink alias is a second name for bytes
   the manifest already owns, and a symlink alias names a file the loader resolves
   through, so neither adds a fact here. */
struct payload_scan {
    const char *arch, *libc;
    struct holy_scan_result *collected;
    size_t edges;
};

static int payload_file(void *opaque, const char *path, int fd)
{
    struct payload_scan *state = opaque;
    struct stat st;
    unsigned char buffer[4];
    char name[4096];
    ssize_t got;
    int elf, script;
    if (fstat(fd, &st) || st.st_size < 0) return 0;
    got = pread(fd, buffer, sizeof buffer, 0);
    if (got < 0) return 0;
    if (strlen(path) + 6 > sizeof name) return 0;
    strcpy(name, "DATA/");
    strcpy(name + 5, path);
    elf = got == 4 && !memcmp(buffer, "\177ELF", 4);
    script = (st.st_mode & 0111) && got >= 2 && buffer[0] == '#' && buffer[1] == '!';
    if (!elf && !script) return 1;
    if (elf) return inspect_elf(fd, name, (unsigned int)st.st_mode, state->arch,
                                state->libc, 0, &state->edges, state->collected);
    return inspect_script(fd, name, (unsigned int)st.st_mode, st.st_size, 0,
                          state->collected);
}

int holy_scan_installed(int files_fd, int root, const char *arch, const char *libc,
                        struct holy_scan_result *result)
{
    struct payload_scan state;
    if (!arch || !libc || !arch[0] || !libc[0] || !files_fd || !root) return 0;
    memset(&state, 0, sizeof state);
    state.arch = arch;
    state.libc = libc;
    state.collected = result;
    memset(result, 0, sizeof *result);
    return holy_install_visit_regular(files_fd, root, NULL, payload_file, &state) == 1;
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
    for (i = 0; i < result->script_count; ++i) {
        free(result->scripts[i].path);
        free(result->scripts[i].interpreter);
    }
    free(result->scripts);
    for (i = 0; i < result->symlink_count; ++i) {
        free(result->symlinks[i].path);
        free(result->symlinks[i].target);
    }
    free(result->symlinks);
    free(result->files);
    memset(result, 0, sizeof *result);
}

int holy_scan_local(const char *path)
{
    return holy_scan_local_with_output(path, 1);
}
