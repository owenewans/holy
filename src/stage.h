#ifndef HOLY_STAGE_H
#define HOLY_STAGE_H

/* returns a private copied path; caller unlinks and frees it. */
char *holy_stage_local(const char *source, const char *prefix);
/* borrows a regular-file fd and copies from offset zero. */
char *holy_stage_fd(int input, const char *prefix);
/* creates an exclusive mode 0600 temp file beneath an opened directory. */
int holy_temporary_at(int dir, char name[43]);
/* the same, opened for reading as well, for a payload the packer reads back. */
int holy_spool_at(int dir, char name[43]);

#endif
