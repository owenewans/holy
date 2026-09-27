#ifndef HOLY_CHECK_H
#define HOLY_CHECK_H

/* compares without mutation; returns CLI status (0 pass, 1 findings/error,
   2 invalid input, 6 required path-resolution syscall unavailable). */
int holy_check_local(const char *package, const char *root, int json);

#endif
