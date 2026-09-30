#ifndef HOLY_TRIAL_H
#define HOLY_TRIAL_H

/* runs one command in a private root trial: private mount propagation, own /proc,
   /run and /tmp, PID, IPC and UTS namespaces, a user namespace when available and a
   controlled /dev. argv is passed through unchanged, without a hidden shell, and the
   command runs as PID 1 of its own PID namespace. Returns the command status, 128
   plus the signal for a killed command, 6 when a namespace is unavailable and 1 when
   a trial step fails. */
int holy_trial_command(char *const argv[]);

#endif
