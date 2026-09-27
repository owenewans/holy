#ifndef HOLY_INSTALL_H
#define HOLY_INSTALL_H

struct holy_manifest_entry;

/* requires an already verified snapshot; root is an open target-root directory. */
int holy_install_preflight(const char *snapshot, int root);
/* writes new files/relative symlinks; partial payload remains for journal recovery. */
int holy_install_payload(const char *snapshot, int root);
/* 1 intact, 0 changed/missing, -1 invalid installed manifest. */
int holy_install_check_manifest(int files_fd, int root);
/* borrowed path/code; callback returns zero on output/allocation failure. */
typedef int (*holy_install_finding)(void *context, const char *path, const char *code);
int holy_install_check_report(int files_fd, int root,
                              holy_install_finding finding, void *context);
/* caller must journal first; directories and unlisted paths are retained. */
int holy_install_remove_manifest(int files_fd, int root);
/* resume a removing journal: absent listed files are accepted, changed files block. */
int holy_install_finish_remove_manifest(int files_fd, int root);
/* 0 absent, 1 file or symlink, 2 directory, -1 malformed or I/O error. */
int holy_install_manifest_owns(int files_fd, const char *path);
/* 1 conflicting claims, 0 disjoint/shared directories, -1 invalid input. */
int holy_install_manifests_conflict(int left_fd, int right_fd);

/* missing-only repair; caller verifies manifest, ownership and journals first. */
int holy_install_payload_missing(const char *snapshot, int root);
int holy_install_check_or_missing(int files_fd, int root);
int holy_install_check_path(int files_fd, int root, const char *path);

/* caller owns the journal reservation for a temporary basename beside next.
   prepare verifies content before publishing it; fd is borrowed, read at offset 0. */
int holy_install_prepare_file(int root, const struct holy_manifest_entry *next,
                              int content_fd, const char *temporary);
/* read-only: require before, or allow the completed after state during recovery. */
int holy_install_transition_check(int root, const struct holy_manifest_entry *before,
                                  const struct holy_manifest_entry *after, int recovering);
/* caller validates ownership, checks initial state and journals before mutation.
   NULL before adds, NULL after removes. No directories. temporary names a
   prepared file/symlink; completed transitions are repeatable during recovery. */
int holy_install_transition(int root, const struct holy_manifest_entry *before,
                            const struct holy_manifest_entry *after, const char *temporary);

#endif
