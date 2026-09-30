#ifndef HOLY_SCRIPT_H
#define HOLY_SCRIPT_H

#include <stddef.h>
#include <sys/types.h>

/* a service tool a script body names; the review reports what it saw and leaves the
   decision to the reader, since an allowed hook keeps the powers of a root shell. */
struct holy_script_command {
    size_t line;      /* 1-based */
    char tool[64];    /* the tool as the body names it */
};

/* 0 no shebang, 1 direct, 2 env, 3 unresolved, -1 read error.
   interpreter is owned by the caller for positive results. */
int holy_script_read_fd(int fd, off_t size, mode_t mode, char **interpreter);
/* every token whose basename names a service tool, in body order, outside comments.
   fills out with at most limit entries and reports the whole number in total. */
void holy_script_service_commands(const char *body, size_t length,
                                  struct holy_script_command *out, size_t limit,
                                  size_t *total);
/* 1 executable ELF found in root, 0 absent, -1 unknown, -2 openat2 absent. */
int holy_script_target_status(int root, const char *interpreter);

#endif
