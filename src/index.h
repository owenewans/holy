#ifndef HOLY_INDEX_H
#define HOLY_INDEX_H

/* a read-only file index over the installed set: which artifact owns a path and
   which artifacts provide a capability. with no selector the whole index is printed;
   with one the candidates are named, and more than one candidate is status 1, since
   picking one of them would be a guess. 0 one candidate or the whole index, 1 more
   than one candidate, 2 invalid input, 4 an incomplete transaction, 6 an instance
   record is unavailable. */
int holy_index_report(const char *root, const char *path, const char *kind,
                      const char *name, int json);

#endif
