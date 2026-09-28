#ifndef HOLY_INSTALL_H
#define HOLY_INSTALL_H

#include <stddef.h>
#include <sys/stat.h>

struct holy_manifest_entry;

/* requires an already verified snapshot; root is an open target-root directory. */
int holy_install_preflight(const char *snapshot, int root, int accepted_privileged);
/* exact existing payload or absent paths; caller owns an interrupted journal. */
int holy_install_preflight_resume(const char *snapshot, int root, int accepted_privileged);
/* validates declared parents and directories; create requires a published journal.
   existing directories are never chmodded, removed or replaced. */
int holy_install_directory_plan(int root, const struct holy_manifest_entry *entries,
                                 size_t count, int create, int recovering);
/* writes files, relative symlinks and direct hardlinks; partial payload remains journaled. */
int holy_install_payload(const char *snapshot, int root, int accepted_privileged);
/* 1 intact, 0 changed/missing, -1 invalid installed manifest. */
int holy_install_check_manifest(int files_fd, int root);
/* update preflight permits content drift only for config regular files;
   the caller must then bind each observed file in its plan. */
int holy_install_check_manifest_except_configs(int files_fd, int root);
/* borrowed path/code/target; target is NULL for payload drift. */
typedef int (*holy_install_finding)(void *context, const char *path,
                                    const char *code, const char *target);
int holy_install_check_report(int files_fd, int root,
                              holy_install_finding finding, void *context);
/* visits intact regular payload through root-confined fds; fd is borrowed. */
typedef int (*holy_install_regular_visit)(void *context, const char *path, int fd);
int holy_install_visit_regular(int files_fd, int root, const char *filter,
                               holy_install_regular_visit visit, void *context);
/* caller must journal first; directories and unlisted paths are retained. */
int holy_install_remove_manifest(int files_fd, int root);
/* resume a removing journal: absent listed files are accepted, changed files block. */
int holy_install_finish_remove_manifest(int files_fd, int root);
/* 0 absent, 1 file or symlink, 2 directory, -1 malformed or I/O error. */
int holy_install_manifest_owns(int files_fd, const char *path);
/* 1 executable, 0 absent/nonexecutable, -1 invalid installed manifest. */
int holy_install_manifest_executable(int files_fd, const char *path);
/* 1 conflicting claims, 0 disjoint/shared directories, -1 invalid input. */
int holy_install_manifests_conflict(int left_fd, int right_fd);

/* missing-only repair; caller verifies manifest, ownership and journals first. */
int holy_install_payload_missing(const char *snapshot, int root);
/* restore a transformed instance using its local manifest for config paths. */
int holy_install_payload_missing_mapped(const char *snapshot, int root, int files_fd);
int holy_install_check_or_missing(int files_fd, int root);
/* modified public configs cannot be recreated from an archived payload. */
int holy_install_check_repair_transformed(int files_fd, int root);
int holy_install_check_path(int files_fd, int root, const char *path);
/* read-only normalized entry check: 1 matches, 2 absent, 0 drift, -1 unsupported. */
int holy_install_check_entry(int root, const struct holy_manifest_entry *entry);
/* hash a stable regular file beneath root without following the final path;
   observed borrows entry->path and hash points to the caller's 32-byte buffer. */
int holy_install_observe_regular(int root, const struct holy_manifest_entry *entry,
                                 struct holy_manifest_entry *observed,
                                 unsigned char hash[32]);

/* raw content/attributes for mixed update states; temporary NULL selects public path.
   returns 1 exact, 2 absent, 0 drift, -1 invalid; observed is optional. */
int holy_install_entry_state(int root, const struct holy_manifest_entry *entry,
                              const char *temporary, struct stat *observed);
/* link a reserved sibling to a verified public or reserved source without replacement. */
int holy_install_prepare_link(int root, const struct holy_manifest_entry *next,
    const char *temporary, const struct holy_manifest_entry *source,
    const char *source_temporary, int recovering);
/* removes only an intact reserved sibling; absence is accepted during recovery. */
int holy_install_remove_temporary(int root, const struct holy_manifest_entry *entry,
                                   const char *temporary);

/* caller owns the journal reservation for a temporary basename beside next.
   prepare verifies content before publishing it; fd is borrowed, read at offset 0. */
int holy_install_prepare_file(int root, const struct holy_manifest_entry *next,
                              int content_fd, const char *temporary);
/* checks the reserved sibling: 1 exact staged object, 2 absent, 0 drift. */
int holy_install_temporary_state(int root, const struct holy_manifest_entry *next,
                                 const char *temporary);
/* read-only: require before, or allow the completed after state during recovery. */
int holy_install_transition_check(int root, const struct holy_manifest_entry *before,
                                  const struct holy_manifest_entry *after, int recovering);
/* caller validates ownership, checks initial state and journals before mutation.
   NULL before adds, NULL after removes. No directories. temporary names a
   prepared file/symlink; completed transitions are repeatable during recovery. */
int holy_install_transition(int root, const struct holy_manifest_entry *before,
                            const struct holy_manifest_entry *after, const char *temporary);

#endif
