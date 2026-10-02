#ifndef HOLY_REWRITE_H
#define HOLY_REWRITE_H

#include <stddef.h>

/* the ELF rewriting the spec assigns to patchelf. this module never rewrites a byte
   itself: it reads the facts the current file states, prepares the argv patchelf would
   run, records that argv for a review, and runs it through execv. a second rewriter in
   this repository would be the thing the spec forbids. */

enum holy_rewrite_kind {
    HOLY_REWRITE_INTERPRETER,   /* --set-interpreter PATH */
    HOLY_REWRITE_RPATH,         /* --force-rpath --set-rpath PATH */
    HOLY_REWRITE_RUNPATH,       /* --set-rpath PATH, which clears DT_RPATH */
    HOLY_REWRITE_SONAME,        /* --set-soname NAME */
    HOLY_REWRITE_NEEDED         /* --replace-needed OLD NEW */
};

struct holy_rewrite_change {
    enum holy_rewrite_kind kind;
    char *from;                 /* the value the file states now, NULL when absent */
    char *to;
};

struct holy_rewrite {
    char *tool;                 /* the patchelf this plan names */
    char *file;
    char hash[65];              /* sha256 of the file the plan was made for */
    struct holy_rewrite_change *change;
    size_t count;
    char **argv;                /* the prepared command, tool included */
    size_t argc;
};

/* reads the file and states the argv patchelf would run for these changes. a change
   the file already satisfies is refused rather than run as a no-op, since a plan that
   claims a rewrite that does not happen misleads the review. returns 1 with a plan,
   0 when no change was stated, 2 for an invalid argument, 6 when the tool is
   unavailable and -1 on an allocation or read failure. */
int holy_rewrite_prepare(const char *tool, const char *file,
                         const struct holy_rewrite_change *changes, size_t count,
                         struct holy_rewrite *plan);

/* re-hashes the file and requires the digest the plan fixed, then runs the prepared
   argv. a file that changed since the review changes nothing. */
int holy_rewrite_apply(const struct holy_rewrite *plan);

/* the plan as reviewable text, one line per change plus the argv and the digest.
   the caller frees the record. */
int holy_rewrite_record(const struct holy_rewrite *plan, char **record, size_t *size);
void holy_rewrite_free(struct holy_rewrite *plan);

/* whether patchelf is present and reports a version. the spec makes it a package, so a
   host without one is a requirement failure rather than a silent fallback. */
int holy_rewrite_tool(const char *tool);

/* one line per change, the way the plan states them. */
void holy_rewrite_print(const struct holy_rewrite *plan);

#endif