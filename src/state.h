#ifndef HOLY_STATE_H
#define HOLY_STATE_H

/* initializes an empty database under an explicit target root. */
int holy_state_init(const char *root_path);
/* 0 empty, 5 recognized prepared reservation, 1 invalid database. */
int holy_state_status(const char *root_path, int json);
/* reserve one cached object at the current generation; no payload mutation. */
int holy_state_reserve(const char *digest, const char *root_path);
/* discard only the recognized prepared reservation. */
int holy_state_cancel(const char *root_path);
/* clean one validated temporary reservation after interrupted publication. */
int holy_state_recover(const char *root_path);
/* read-only preview of the one prepared cache object against target root. */
int holy_state_preflight(const char *root_path, int json);

#endif
