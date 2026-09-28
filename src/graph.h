#ifndef HOLY_GRAPH_H
#define HOLY_GRAPH_H

/* read one installed snapshot and report unreachable dependency instances. */
int holy_orphan(const char *root, int json);
/* show one installed dependency path from an explicit root to a package. */
int holy_why(const char *digest, const char *root, int json);

#endif
