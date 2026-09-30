#ifndef HOLY_SCOOP_H
#define HOLY_SCOOP_H

/* a Scoop manifest to a native package conversion. the manifest is read as JSON
   text and the artifact beside it is verified and carried; nothing is executed,
   and no Wine requirement is invented for a program Holy cannot run. */
int holy_import_scoop(const char *input, const char *source, const char *output);

#endif
