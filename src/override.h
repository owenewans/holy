#ifndef HOLY_OVERRIDE_H
#define HOLY_OVERRIDE_H

/* user overrides in the target root, under etc/holy/overrides. a record names the
   packaged file it applies to, the conditions under which it applies and the digest
   the patched file must have, so a package version that no longer matches is reported
   for review instead of applied quietly. 0 the listing completed, 2 one record is not
   a valid override, 3 one record needs review, 5 an incomplete transaction,
   6 the root has no usable database. */
int holy_override_list(const char *root_path, int json);

#endif
