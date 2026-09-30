#ifndef HOLY_SNAP_H
#define HOLY_SNAP_H

int holy_snap_inspect(const char *input);
int holy_snap_extract(const char *input, const char *output);
int holy_import_snap(const char *input, const char *source, const char *output);

#endif
