#ifndef HOLY_FETCH_H
#define HOLY_FETCH_H

/* copies a local object into an existing directory; no extraction or hooks. */
int holy_fetch_local(const char *source, const char *output);

#endif
