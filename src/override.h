#ifndef HOLY_OVERRIDE_H
#define HOLY_OVERRIDE_H

#include <stddef.h>

/* user overrides in the target root, under etc/holy/overrides. a record names the
   packaged file it applies to, the conditions under which it applies and the digest
   the patched file must have, so a package version that no longer matches is reported
   for review instead of applied quietly. 0 the listing completed, 2 one record is not
   a valid override, 3 one record needs review, 5 an incomplete transaction,
   6 the root has no usable database. */
int holy_override_list(const char *root_path, int json);

/* the reviewed plan for one whole-file record: what applying it would write, and the
   hash that says so. 0 prepared, 2 the name or record is not usable, 3 the record is
   not one this manager applies or no longer applies to the file in place,
   5 an unfinished transaction, 6 the record or the target root is unavailable. */
int holy_override_plan(const char *name, const char *root_path, int json);
/* applies the reviewed plan of one whole-file record, writing the body over the file it
   names under the database writer lock. 0 written or already in place, 2 the approval
   or the record is not usable, 3 the plan or the installed set changed, 5 an
   unfinished transaction, 6 the record or the target root is unavailable. */
int holy_override_apply(const char *name, const char *approved, const char *root_path,
                        int json);

/* one valid record with what the file it names holds in the target root. the caller
   owns the vector. */
struct holy_override_record_info {
    char *name;
    char *path;
    char *file;        /* applied, pending, absent or review */
    char *patch;
};

/* every valid record of the store, in name order, with no database lock taken, so a
   caller that already holds the writer lock can read the same facts the plan bound.
   0 read, 1 the store could not be read. */
int holy_override_records(const char *root_path, struct holy_override_record_info **records,
                          size_t *record_count);
void holy_override_records_free(struct holy_override_record_info *records, size_t count);

#endif
