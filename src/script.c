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

/* the tools that control a service in a dinit, systemd, OpenRC, SysV, upstart or runit
   profile. a body that names one of them is visible before the review approves it, and
   the body stays the authority on what it does with it. */
static const char *const service_tools[] = {
    "dinitctl", "systemctl", "service", "rc-service", "rc-update", "initctl",
    "chkconfig", "update-rc.d", "insserv", "sv", "runsv", NULL
};

/* the bytes a token cannot hold: shell metacharacters, both quotes and whitespace */
static int token_break(unsigned char byte)
{
    return byte <= ' ' || byte == ';' || byte == '|' || byte == '&' || byte == '(' ||
           byte == ')' || byte == '<' || byte == '>' || byte == '`' || byte == '"' ||
           byte == '$' || byte == '\\' || byte == '\'';
}

void holy_script_service_commands(const char *body, size_t length,
                                  struct holy_script_command *out, size_t limit,
                                  size_t *total)
{
    size_t i = 0, line = 1;
    int line_start = 1;
    *total = 0;
    while (i < length) {
        size_t start, end, base, name;
        while (i < length && (body[i] == ' ' || body[i] == '\t' || body[i] == '\r')) ++i;
        if (i >= length) break;
        /* a comment names nothing a shell would run, and a hook body is mostly comments */
        if (line_start && body[i] == '#') {
            while (i < length && body[i] != '\n') ++i;
            continue;
        }
        line_start = 0;
        start = i;
        while (i < length && !token_break((unsigned char)body[i])) ++i;
        end = i;
        base = start;
        for (name = start; name < end; ++name)
            if (body[name] == '/') base = name + 1;
        while (i < length && token_break((unsigned char)body[i])) {
            if (body[i] == '\n') { ++line; line_start = 1; }
            if (body[i] == ';') line_start = 1;
            ++i;
        }
        if (base == end) continue;
        for (size_t tool = 0; service_tools[tool]; ++tool)
            if (strlen(service_tools[tool]) == name - base &&
                !memcmp(body + base, service_tools[tool], name - base)) {
                ++*total;
                if (out && *total <= limit && name - base < sizeof out[0].tool) {
                    out[*total - 1].line = line;
                    memcpy(out[*total - 1].tool, body + base, name - base);
                    out[*total - 1].tool[name - base] = 0;
                }
                break;
            }
    }
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
