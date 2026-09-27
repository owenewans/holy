#define _POSIX_C_SOURCE 200809L
#include "preview.h"
#include "extract.h"
#include "package.h"
#include "scan.h"
#include "stage.h"
#include "verify.h"
#include "deps.h"
#include "provides.h"

#include <archive.h>
#include <archive_entry.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct action {
    char *path;
    char *interpreter;
    char *helper;
    int state;
};

static void print_path(const char *path)
{
    const unsigned char *p = (const unsigned char *)path;
    for (; *p; ++p)
        if (*p == '\\' || *p <= 32 || *p >= 127)
            printf("\\x%02x", (unsigned int)*p);
        else putchar(*p);
}

static void json_string(const char *text)
{
    const unsigned char *p = (const unsigned char *)text;
    putchar('"');
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p >= 32 && *p < 127) putchar(*p);
        else printf("\\u%04x", (unsigned int)*p);
    }
    putchar('"');
}

static char *env_helper(const char *text, size_t used, size_t position)
{
    size_t start, end;
    while (position < used && (text[position] == ' ' || text[position] == '\t'))
        ++position;
    if (position + 2 < used && text[position] == '-' &&
        text[position + 1] == 'S' &&
        (text[position + 2] == ' ' || text[position + 2] == '\t')) {
        position += 2;
        while (position < used && (text[position] == ' ' || text[position] == '\t'))
            ++position;
    }
    start = position;
    while (position < used && text[position] != ' ' && text[position] != '\t' &&
           text[position] != '\r' && text[position] != '\n' && text[position])
        ++position;
    end = position;
    if (end > start && (end < used || used < 256) && text[start] != '-') {
        for (position = start; position < end; ++position)
            if (text[position] == '"' || text[position] == '\'' ||
                text[position] == '\\') break;
        if (position == end) return strndup(text + start, end - start);
    }
    return strdup("unknown");
}

/* 0: new, 1: existing directory, 2: conflict, -1: I/O failure. */
static int inspect_path(int root, const char *name, int wants_directory)
{
    char *copy = strdup(name), *cursor, *slash;
    struct stat st;
    size_t length;
    int current = root, next, state = -1;
    if (!copy) return -1;
    length = strlen(copy);
    if (length && copy[length - 1] == '/') copy[length - 1] = '\0';
    cursor = copy;
    while ((slash = strchr(cursor, '/')) != NULL) {
        *slash = '\0';
        next = openat(current, cursor, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) {
            state = errno == ENOENT ? 0 :
                    (errno == ENOTDIR || errno == ELOOP) ? 2 : -1;
            goto done;
        }
        if (current != root) close(current);
        current = next;
        cursor = slash + 1;
    }
    if (!*cursor) { state = -1; goto done; }
    if (fstatat(current, cursor, &st, AT_SYMLINK_NOFOLLOW) < 0)
        state = errno == ENOENT ? 0 : -1;
    else state = wants_directory && S_ISDIR(st.st_mode) ? 1 : 2;
done:
    if (current != root) close(current);
    free(copy);
    return state;
}

static int preview(const char *package, const char *root_path,
                   int json, int resolved, int completed, int accepted_privileged)
{
    struct archive *archive = NULL;
    struct archive_entry *entry;
    struct holy_package_identity identity = {0};
    struct action *actions = NULL;
    char *snapshot = holy_stage_local(package, "holy-preview");
    size_t count = 0, i, conflicts = 0, requirements = 0, elf_needed = 0;
    size_t script_interpreters = 0, helper_commands = 0;
    int root = -1, status, rc = 2;
    if (!snapshot || !holy_verify_with_output(snapshot, 0) ||
        !holy_extract_preflight(snapshot) ||
        !holy_scan_local_facts(snapshot, 0, &elf_needed) ||
        !holy_deps_count(snapshot, &requirements) ||
        !holy_provides_local(snapshot, 0) ||
        !holy_package_identity(snapshot, &identity)) goto done;
    root = open(root_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) { perror("holypkg: target root"); rc = 1; goto done; }
    archive = archive_read_new();
    if (!archive || archive_read_support_filter_lz4(archive) != ARCHIVE_OK ||
        archive_read_support_format_tar(archive) != ARCHIVE_OK ||
        archive_read_open_filename(archive, snapshot, 8192) != ARCHIVE_OK) goto done;
    while ((status = archive_read_next_header(archive, &entry)) == ARCHIVE_OK) {
        const char *path = archive_entry_pathname(entry);
        struct action *next;
        int state;
        if (!strcmp(path, "HOLY/hooks")) {
            if (archive_entry_size(entry) != 0) {
                fprintf(stderr, "holypkg: preview requires empty hooks\n");
                rc = 6;
                goto done;
            }
        }
        if (strncmp(path, "DATA/", 5) || !path[5]) {
            if (archive_read_data_skip(archive) != ARCHIVE_OK) goto done;
            continue;
        }
        if ((archive_entry_perm(entry) & 07000) &&
            (!accepted_privileged || archive_entry_filetype(entry) != AE_IFREG ||
             archive_entry_hardlink(entry) || (archive_entry_perm(entry) & 03000))) {
            fprintf(stderr, "holypkg: privileged payload mode requires review\n");
            rc = 6;
            goto done;
        }
        if (count == (size_t)-1 / sizeof *actions) goto done;
        state = inspect_path(root, path + 5,
                             archive_entry_filetype(entry) == AE_IFDIR);
        if (state < 0) { rc = 1; goto done; }
        next = realloc(actions, (count + 1) * sizeof *actions);
        if (!next) { rc = 1; goto done; }
        actions = next;
        actions[count].path = strdup(path + 5);
        if (!actions[count].path) { rc = 1; goto done; }
        actions[count].interpreter = NULL;
        actions[count].helper = NULL;
        actions[count].state = state;
        ++count;
        if (state == 2) ++conflicts;
        if (archive_entry_filetype(entry) == AE_IFREG &&
            !archive_entry_hardlink(entry) &&
            (archive_entry_perm(entry) & 0111)) {
            char prefix[257];
            size_t used = 0, limit = archive_entry_size(entry) < 256 ?
                          (size_t)archive_entry_size(entry) : 256;
            while (used < limit) {
                la_ssize_t got = archive_read_data(archive, prefix + used,
                                                  limit - used);
                if (got <= 0) goto done;
                used += (size_t)got;
            }
            if (used >= 2 && !memcmp(prefix, "#!", 2)) {
                size_t start = 2, end;
                if (script_interpreters == (size_t)-1) goto done;
                ++script_interpreters;
                while (start < used && (prefix[start] == ' ' || prefix[start] == '\t'))
                    ++start;
                end = start;
                while (end < used && prefix[end] != ' ' && prefix[end] != '\t' &&
                       prefix[end] != '\r' && prefix[end] != '\n' && prefix[end])
                    ++end;
                if (end > start && prefix[start] == '/' &&
                    (end < used || used < 256)) {
                    char separator = end < used ? prefix[end] : '\0';
                    prefix[end] = '\0';
                    actions[count - 1].interpreter = strdup(prefix + start);
                    prefix[end] = separator;
                } else actions[count - 1].interpreter = strdup("unknown");
                if (!actions[count - 1].interpreter) { rc = 1; goto done; }
                if (!strcmp(actions[count - 1].interpreter, "/usr/bin/env") ||
                    !strcmp(actions[count - 1].interpreter, "/bin/env")) {
                    if (helper_commands == (size_t)-1) goto done;
                    actions[count - 1].helper = env_helper(prefix, used, end);
                    if (!actions[count - 1].helper) { rc = 1; goto done; }
                    ++helper_commands;
                }
            } else if (used < 4 || memcmp(prefix, "\177ELF", 4)) {
                fprintf(stderr, "holypkg: executable format unknown; interpreter decision required\n");
                rc = 6;
                goto done;
            }
        }
        if (archive_read_data_skip(archive) != ARCHIVE_OK) goto done;
    }
    if (status != ARCHIVE_EOF) goto done;
    if (json > 0) {
        for (i = 0; i < count; ++i) {
            fputs("{\"schema\":\"holy-preview-1\",\"type\":\"path\",\"path\":", stdout);
            json_string(actions[i].path);
            printf(",\"state\":\"%s\",\"interpreter\":",
                   actions[i].state == 0 ? "new" :
                   actions[i].state == 1 ? "existing-dir" : "conflict");
            if (actions[i].interpreter) json_string(actions[i].interpreter);
            else fputs("null", stdout);
            fputs(",\"helper\":", stdout);
            if (actions[i].helper) json_string(actions[i].helper);
            else fputs("null", stdout);
            puts("}");
        }
        printf("{\"schema\":\"holy-preview-1\",\"type\":\"summary\",\"artifact\":\"%s\",\"paths\":%zu,\"conflicts\":%zu,\"requirements\":%zu,\"elf_needed\":%zu,\"script_interpreters\":%zu,\"helper_commands\":%zu}\n",
               identity.digest, count, conflicts, requirements, elf_needed,
               script_interpreters, helper_commands);
    } else if (json == 0) {
        printf("preview artifact=%s paths=%zu conflicts=%zu requirements=%zu elf-needed=%zu script-interpreters=%zu helper-commands=%zu\n",
               identity.digest, count, conflicts, requirements, elf_needed,
               script_interpreters, helper_commands);
        for (i = 0; i < count; ++i) {
            printf("%s ", actions[i].state == 0 ? "new" :
                            actions[i].state == 1 ? "existing-dir" : "conflict");
            print_path(actions[i].path);
            putchar('\n');
            if (actions[i].interpreter) {
                fputs("interpreter ", stdout);
                print_path(actions[i].path);
                putchar(' ');
                print_path(actions[i].interpreter);
                putchar('\n');
            }
            if (actions[i].helper) {
                fputs("helper-command ", stdout);
                print_path(actions[i].path);
                putchar(' ');
                print_path(actions[i].helper);
                putchar('\n');
            }
        }
    }
    rc = (conflicts && !completed) ? 4 :
         ((!resolved && (requirements || elf_needed)) || script_interpreters) ? 3 : 0;
done:
    if (rc == 2) fprintf(stderr, "holypkg: cannot preview package\n");
    if (json > 0 && rc != 0 && rc != 3 && rc != 4)
        printf("{\"schema\":\"holy-preview-1\",\"type\":\"error\",\"code\":\"%s\"}\n",
               rc == 6 ? "unsupported-input" :
               rc == 1 ? "operational-error" : "invalid-preview");
    if (archive) archive_read_free(archive);
    if (root >= 0) close(root);
    if (snapshot) { unlink(snapshot); free(snapshot); }
    for (i = 0; i < count; ++i) {
        free(actions[i].path);
        free(actions[i].interpreter);
        free(actions[i].helper);
    }
    free(actions);
    holy_package_identity_free(&identity);
    return rc;
}

int holy_preview_local(const char *package, const char *root_path)
{
    return holy_preview_local_format(package, root_path, 0);
}

int holy_preview_local_format(const char *package, const char *root_path, int json)
{
    return preview(package, root_path, json, 0, 0, 0);
}

int holy_preview_resolved(const char *package, const char *root_path, int completed,
                          int accepted_privileged)
{
    return preview(package, root_path, -1, 1, completed, accepted_privileged);
}
