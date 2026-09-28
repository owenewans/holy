#ifndef HOLY_SCRIPT_H
#define HOLY_SCRIPT_H

#include <sys/types.h>

/* 0 no shebang, 1 direct, 2 env, 3 unresolved, -1 read error.
   interpreter is owned by the caller for positive results. */
int holy_script_read_fd(int fd, off_t size, mode_t mode, char **interpreter);
/* 1 executable ELF found in root, 0 absent, -1 unknown, -2 openat2 absent. */
int holy_script_target_status(int root, const char *interpreter);

#endif
