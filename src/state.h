#ifndef HOLY_STATE_H
#define HOLY_STATE_H

#include <stddef.h>

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
/* compare one or --all installed data manifests; no repair. */
int holy_state_check(const char *digest, const char *root_path, int json);
/* remove one intact installed instance; accepted broken edges remain visible. */
int holy_state_remove(const char *digest, const char *root_path, int accept_broken);
/* finish a removing journal if remaining listed files are unchanged. */
int holy_state_continue_remove(const char *root_path);
/* clear a completed applying journal after verifying the installed instance. */
int holy_state_finish_apply(const char *root_path);
/* lookup installed data-file ownership without inspecting the live payload. */
int holy_state_owner(const char *path, const char *root_path);

/* borrowed arrays: source bindings and exact hashes accepting non-native placement.
   architecture decisions apply only to newly installed artifacts in this set. */
int holy_state_set(const char *const *digests, size_t count, const char *choice,
                   const char *approved, const char *root_path,
                   const char *const *bindings, size_t binding_count,
                   const char *const *accepted_arch, size_t accepted_count);
int holy_state_finish_set(const char *root_path);
int holy_state_continue_set(const char *root_path);

/* missing-only repair; NULL digest resumes a recorded repair. */
int holy_state_repair(const char *digest, const char *approved, const char *root_path);
/* read-only replacement preview, preserving the installed source and slot. */
int holy_state_update_plan(const char *old_digest, const char *new_digest,
                           const char *root_path);
int holy_state_apply_update(const char *plan, const char *old_digest,
                            const char *new_digest, const char *root_path);
int holy_state_recover_update(const char *root_path);

/* borrows root/instance fds under a shared lock, in artifact order; 0 succeeds. */
typedef int (*holy_instance_visit)(void *, int, int, const char *);
int holy_state_visit(const char *root_path, holy_instance_visit visit, void *context,
                     unsigned long long *generation);

/* returns a locked database fd, caller closes it; status uses CLI codes. */
int holy_state_lock(const char *root_path, int exclusive,
                     unsigned long long *generation, int *status);

#endif
