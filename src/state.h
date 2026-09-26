#ifndef HOLY_STATE_H
#define HOLY_STATE_H

/* initializes an empty database under an explicit target root. */
int holy_state_init(const char *root_path);
/* checks database layout and prints its monotonic generation. */
int holy_state_status(const char *root_path);

#endif
