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
/* list paths from the installed manifest, independent of current payload drift. */
int holy_state_files(const char *digest, const char *root_path);
/* remove one intact installed instance; accepted broken edges remain visible. */
/* one artifact, kept for the single form of db rm. */
int holy_state_remove(const char *digest, const char *root_path, int accept_broken);
/* several artifacts in one command: every one is checked before the first is removed,
   each removal is its own journalled transaction. */
int holy_state_remove_group(const char *const *digests, size_t count,
                            const char *root_path, int accept_broken);
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
                   const char *const *accepted_arch, size_t accepted_count,
                   const char *const *accepted_privileged, size_t privileged_count,
                   const char *const *skipped_hooks, size_t skipped_count,
                   const char *const *accepted_service, size_t service_count,
                   char plan_hash[65]);
/* binds newly selected catalog artifacts to one active registered source. */
int holy_state_set_source(const char *const *digests, size_t count,
                          const char *source_id, const char *catalog_index,
                          const char *choice,
                          const char *approved, const char *root_path,
                          const char *const *accepted_arch, size_t accepted_count,
                          const char *const *accepted_privileged, size_t privileged_count,
                          const char *const *accepted_service, size_t service_count,
                          char plan_hash[65]);
int holy_state_set_source_bindings(const char *const *digests, size_t count,
                                  const char *source_id, const char *catalog_index,
                                  const char *const *bindings, size_t binding_count,
                                  const char *choice, const char *approved,
                                  const char *root_path,
                                  const char *const *accepted_arch, size_t accepted_count,
                                  const char *const *accepted_privileged, size_t privileged_count,
                                  const char *const *accepted_service, size_t service_count,
                                  char plan_hash[65]);
/* read-only probe for installed-provider reuse before source discovery. */
int holy_state_probe_source_bindings(const char *const *digests, size_t count,
                                    const char *source_id, const char *catalog_index,
                                    const char *const *bindings, size_t binding_count,
                                    const char *choice, const char *root_path,
                                    const char *const *accepted_arch, size_t accepted_count,
                                    const char *const *accepted_privileged,
                                    size_t privileged_count,
                                    const char *const *accepted_service,
                                    size_t service_count);
int holy_state_finish_set(const char *root_path);
int holy_state_continue_set(const char *root_path);
/* reviewed postinstall hook configuration; a running journal needs explicit retry. */
int holy_state_configure(const char *digest, const char *approved,
                         const char *root_path, int retry);

/* missing-only repair; NULL digest resumes a recorded repair. */
int holy_state_repair(const char *digest, const char *approved, const char *root_path);
/* read-only replacement preview, preserving the installed source and slot. */
int holy_state_update_plan(const char *old_digest, const char *new_digest,
                           const char *accepted_arch, const char *accepted_privileged,
                           const char *const *accepted_service, size_t service_count,
                           const char *root_path);
/* returns owned canonical plan text and its digest without printing it. */
int holy_state_update_prepare(const char *old_digest, const char *new_digest,
                              const char *accepted_arch, const char *accepted_privileged,
                              const char *const *accepted_service, size_t service_count,
                              const char *root_path, char hash[65], char **record);
int holy_state_apply_update(const char *plan, const char *old_digest,
                            const char *new_digest, const char *accepted_arch,
                            const char *accepted_privileged,
                            const char *const *accepted_service, size_t service_count,
                            const char *root_path);
int holy_state_recover_update(const char *root_path);
/* review or apply a cached reverse update from a committed transaction. a set
   transaction reports the operations its reverse needs instead. */
int holy_state_rollback(const char *transaction, const char *approved,
                        const char *accepted_arch, const char *accepted_privileged,
                        const char *const *accepted_service, size_t service_count,
                        const char *root_path);
/* finds one installed slot by immutable source ID and package identity. */
/* every committed transaction the root keeps, with the decisions it was reviewed with.
   0 reported, 5 an unfinished transaction, 6 the root has no usable database. */
int holy_state_transactions(const char *root_path, int json);

int holy_state_find_slot(const char *root_path, const char *source_id,
                         const char *name, const char *arch, const char *libc,
                         char digest[65]);

/* borrows root/instance fds under a shared lock, in artifact order; 0 succeeds. */
typedef int (*holy_instance_visit)(void *, int, int, const char *);
int holy_state_visit(const char *root_path, holy_instance_visit visit, void *context,
                     unsigned long long *generation);

/* one field of an installed instance meta record, which is the package meta the
   instance was installed from; 0 when the record is absent, unreadable or lacks it. */
int holy_state_instance_field(int instance, const char *key, char *out, size_t size);
/* a consented service unit is named, not a path: letters, digits, dot, dash,
   underscore and at. */
int holy_unit_name_valid(const char *name);
/* the source an installed instance came from, or 0 when it states none. */
int holy_state_instance_source(int instance, char source[65]);
/* returns a locked database fd, caller closes it; status uses CLI codes. */
int holy_state_lock(const char *root_path, int exclusive,
                     unsigned long long *generation, int *status);

#endif
