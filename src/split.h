#ifndef HOLY_SPLIT_H
#define HOLY_SPLIT_H

#include <stddef.h>

/* proposes the split outputs of a prepared package tree. every non-directory path
   receives one output, an explicit rule outranks a heuristic, and a path the rules
   cannot settle is reported as a decision rather than guessed. */
int holy_split_propose(const char *tree, const char *output, char *const *rule, size_t rules);

#endif
