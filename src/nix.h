#ifndef HOLY_NIX_H
#define HOLY_NIX_H

/* a captured Nix closure to one native package per store path. the capture names the
   store paths of a closure and the references between them, each store path travels
   whole under a private path, and nothing runs: no store, no daemon, no profile and
   no sandbox this manager can promise. */
int holy_import_nix(const char *input, const char *source, const char *output);

#endif
