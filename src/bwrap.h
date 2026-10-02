#ifndef HOLY_BWRAP_H
#define HOLY_BWRAP_H

#include <stddef.h>

/* bubblewrap is the isolation backend of a root trial and of a clean build root. it
   is an ordinary package, so the program is a declared input with a path this code
   resolves, never a name it takes from PATH. the isolation a trial promises is
   listed here as flags rather than inherited from the documentation of a tool whose
   version the user did not pin. */

struct holy_bwrap {
    char **argv;
    size_t count, capacity;
};

/* argv[0] is the program, and nothing else is set yet */
void holy_bwrap_init(struct holy_bwrap *bwrap, const char *program);
int holy_bwrap_add(struct holy_bwrap *bwrap, const char *value);
/* a tmpfs whose size bwrap reads before the destination, which is the only order it
   accepts the two in */
int holy_bwrap_tmpfs(struct holy_bwrap *bwrap, const char *destination,
                     unsigned long long bytes);
int holy_bwrap_bind(struct holy_bwrap *bwrap, int writable, const char *source,
                    const char *destination);
int holy_bwrap_dev(struct holy_bwrap *bwrap, const char *node);

/* the set every Holy trial declares: no host pid, ipc, uts or cgroup, a user
   namespace, an empty environment, a session of its own, nothing above the caller,
   and a command that is pid 1 of its own pid namespace. network keeps the host
   stack, and the caller says so in the record either way. */
void holy_bwrap_isolate(struct holy_bwrap *bwrap, int network, int as_pid_1);

void holy_bwrap_free(struct holy_bwrap *bwrap);

/* the host's copy. the backend runs the trial, so it belongs to the machine that runs
   the check rather than to the root the check exposes: a target that does not have
   bubblewrap installed yet is a fact for check to report, not a reason it cannot run */
char *holy_bwrap_program(void);

/* zero when this host runs the program and it gives a process its namespaces, six
   otherwise. the reason is the requirement the caller reports. */
int holy_bwrap_probe(const char *program);

/* appends the target argv behind the separating -- and runs the whole vector. output,
   when it is not -1, receives the target's stdout and stderr; the redirection happens in
   the child, so this process keeps its own streams and its own report still reaches the
   caller. returns the status the target produced, 128 plus the signal for a killed one,
   and 1 for a backend that could not be run, which prints its own reason. */
int holy_bwrap_exec(struct holy_bwrap *bwrap, char *const argv[], int output);

#endif
