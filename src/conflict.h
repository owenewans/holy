#ifndef HOLY_CONFLICT_H
#define HOLY_CONFLICT_H

#include <stddef.h>

/* read-only conflict report over the installed set: shared public paths, repeated
   package names, repeated SONAMEs and private programs of one name. 0 no conflict,
   1 a conflict was found, 2 invalid input, 4 an incomplete transaction,
   6 an instance or graph record is unavailable. */
int holy_conflict_report(const char *root, int json);

/* the claims behind that report, collected from installed instance records or from
   the package archives of a planned set. a claim names the capability, the artifact
   that offers it and the arch/libc the offer is scoped to, so a duplicate of one
   name with a different ABI is reported as a mismatch rather than a duplicate. */
struct holy_conflict_claim {
    char *kind;      /* package, soname, file or private-command */
    char *name;
    char *arch;
    char *libc;
    char digest[65];
};

struct holy_conflict_claims {
    struct holy_conflict_claim *claim;
    size_t count, limit;
    size_t instances;
};

void holy_conflict_claims_free(struct holy_conflict_claims *claims);
int holy_conflict_claims_push(struct holy_conflict_claims *claims, const char *kind,
                              const char *name, const char *arch, const char *libc,
                              const char *digest);
/* reads the provides records and the payload manifest of one package archive. */
int holy_conflict_claims_package(struct holy_conflict_claims *claims,
                                 const char *package, const char *digest);
/* sorts the claims and counts the capabilities two artifacts both offer. */
size_t holy_conflict_claims_findings(struct holy_conflict_claims *claims);
/* one line per finding, in the order the claims sort into. */
void holy_conflict_claims_print(const struct holy_conflict_claims *claims, int json);

#endif
