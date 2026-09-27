#ifndef HOLY_GRAPH_H
#define HOLY_GRAPH_H

/* read one installed snapshot and report unreachable dependency instances. */
int holy_orphan(const char *root, int json);

#endif
