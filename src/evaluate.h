#ifndef HOLY_EVALUATE_H
#define HOLY_EVALUATE_H

#include <stddef.h>
#include <stdio.h>

/* an upstream evaluator a converter may run for an exact foreign expansion, held in
   the working environment rather than installed. it is a build and import tool
   dependency, never a second manager of the installed system. */
struct holy_evaluator {
    const char *path;       /* the program to run, an absolute path */
    const char *const *argv;/* the arguments after argv[0], NULL terminated */
    const char *cwd;        /* the directory it runs in, or NULL for the caller's */
};

/* what one run produced, so a converter can compare it with its own reading. */
struct holy_evaluator_result {
    char *text;             /* the evaluator's standard output, or NULL */
    size_t length;
    char digest[65];        /* the SHA-256 of the output */
    char program_digest[65];/* the SHA-256 of the evaluator program itself */
    int status;             /* the exit status the evaluator produced */
};

/* the consent gate: y runs it, n refuses without writing, s skips the evaluator and
   converts from the text alone, e exits without converting. returns 1 to run, 0 to
   skip and 3 when the caller refused or the answer was not one of the four. */
int holy_evaluator_consent(const char *program, const char *digest, int approved,
                           int noninteractive);

/* runs the evaluator in its own user, mount and network namespaces with the host
   toolchain read-only, captures its output, and reports the program and output
   digests. returns 0 on a run, 3 when the caller refused or exited, and 6 when this
   host cannot provide the namespaces. *skipped is set when the operator chose to
   convert from the text alone. */
int holy_evaluator_run(const struct holy_evaluator *evaluator,
                       struct holy_evaluator_result *result, int approved,
                       int noninteractive, int *skipped);

/* copies the evaluator output beside the recipe it was compared with and writes the
   differences between the text reading and the evaluator's own fields, so the operator
   sees what the exact expansion changed before any build. returns the difference
   count. */
size_t holy_evaluator_report(const struct holy_evaluator_result *result,
                             const char *recipe_path, const char *program);

void holy_evaluator_free(struct holy_evaluator_result *result);

#endif
