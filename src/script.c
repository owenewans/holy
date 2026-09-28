#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "script.h"
#include "elf.h"
#include "package.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

int holy_script_read_fd(int fd, off_t file_size, mode_t mode, char **interpreter)
{
    unsigned char header[256];
    size_t size;
    const unsigned char *end, *start, *cursor;
    int kind = 0;
    *interpreter = NULL;
    if (!(mode & 0111) || file_size < 2) return 0;
    size = file_size < (off_t)sizeof header ? (size_t)file_size : sizeof header;
    if (pread(fd, header, size, 0) != (ssize_t)size) return -1;
    if (header[0] != '#' || header[1] != '!') return 0;
    kind = 3;
    end = memchr(header + 2, '\n', size - 2);
    if (!end && file_size > (off_t)size) goto unknown;
    if (!end) end = header + size;
    if (memchr(header, 0, (size_t)(end - header)) ||
        memchr(header, '\r', (size_t)(end - header))) goto unknown;
    start = header + 2;
    while (start < end && (*start == ' ' || *start == '\t')) ++start;
    cursor = start;
    while (cursor < end && *cursor != ' ' && *cursor != '\t') ++cursor;
    if (cursor == start || *start != '/' ||
        (cursor == end && !memchr(header + 2, '\n', size - 2) &&
         size == sizeof header)) goto unknown;
    *interpreter = strndup((const char *)start, (size_t)(cursor - start));
    if (!*interpreter) return -1;
    kind = !strcmp(strrchr(*interpreter, '/') + 1, "env") ? 2 : 1;
    return kind;
unknown:
    *interpreter = strdup("<unresolved-shebang>");
    return *interpreter ? kind : -1;
}

int holy_script_target_status(int root, const char *interpreter)
{
    struct open_how how = {0};
    struct stat st;
    struct holy_elf_info info;
    char *path;
    int fd, result = -1;
    size_t length = strlen(interpreter);
    if (interpreter[0] != '/' || !interpreter[1] || length > (size_t)-1 - 6) return -1;
    path = malloc(length + 6);
    if (!path) return -1;
    snprintf(path, length + 6, "DATA%s", interpreter);
    if (!holy_safe_archive_path(path)) { free(path); return -1; }
    free(path);
    how.flags = O_RDONLY | O_CLOEXEC | O_NONBLOCK;
    how.resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS;
    fd = (int)syscall(SYS_openat2, root, interpreter, &how, sizeof how);
    if (fd < 0) {
        if (errno == ENOENT) return 0;
        return errno == ENOSYS ? -2 : -1;
    }
    if (!fstat(fd, &st) && S_ISREG(st.st_mode) && (st.st_mode & 0111)) {
        int parsed = holy_elf_read_fd(fd, &info);
        if (!parsed && (info.type == ET_EXEC ||
            (info.type == ET_DYN &&
             ((info.flags1 & DF_1_PIE) || info.interpreter)))) result = 1;
        holy_elf_free(&info);
    }
    close(fd);
    return result;
}
