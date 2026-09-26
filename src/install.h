#ifndef HOLY_INSTALL_H
#define HOLY_INSTALL_H

/* requires an already verified snapshot; root is an open target-root directory. */
int holy_install_preflight(const char *snapshot, int root);
/* writes only new regular DATA files; partial files remain for journal recovery. */
int holy_install_payload(const char *snapshot, int root);
/* 1 intact, 0 changed/missing, -1 invalid installed manifest. */
int holy_install_check_manifest(int files_fd, int root);

#endif
