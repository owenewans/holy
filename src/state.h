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
/* validates a reserved cache object and emits a read-only, generation-bound plan. */
int holy_state_plan(const char *root_path);
/* persist approval only when the current writer-locked plan matches. */
int holy_state_approve(const char *hash, const char *root_path);
/* revalidate an approved plan; no rootfs or database mutation. */
int holy_state_recheck(const char *root_path);
/* narrow, journaled installation of one approved data-only artifact. */
int holy_state_apply(const char *root_path);
/* clear a journal only when no payload or installed instance was written. */
int holy_state_abort_empty(const char *root_path);
/* compare one installed data manifest to the target root without repair. */
int holy_state_check(const char *digest, const char *root_path);
/* remove one intact data-only installed instance; shared directories remain. */
int holy_state_remove(const char *digest, const char *root_path);
/* finish a removing journal if remaining listed files are unchanged. */
int holy_state_continue_remove(const char *root_path);
/* clear a completed applying journal after verifying the installed instance. */
int holy_state_finish_apply(const char *root_path);
/* lookup installed data-file ownership without inspecting the live payload. */
int holy_state_owner(const char *path, const char *root_path);

#endif
