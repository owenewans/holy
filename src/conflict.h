#ifndef HOLY_CONFLICT_H
#define HOLY_CONFLICT_H

/* read-only conflict report over the installed set: shared public paths, repeated
   package names, repeated SONAMEs and private programs of one name. 0 no conflict,
   1 a conflict was found, 2 invalid input, 4 an incomplete transaction,
   6 an instance or graph record is unavailable. */
int holy_conflict_report(const char *root, int json);

#endif
