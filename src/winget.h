#ifndef HOLY_WINGET_H
#define HOLY_WINGET_H

/* a WinGet package manifest to a native package conversion. the manifest is read
   as YAML text and the artifact beside it is verified and carried; nothing is
   executed, and no Wine requirement is invented for a program Holy cannot run. */
int holy_import_winget(const char *input, const char *source, const char *output);

#endif
