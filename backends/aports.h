#ifndef HOLY_APORTS_H
#define HOLY_APORTS_H

/* converts one APKBUILD into a holy-recipe(5) manifest plus a conversion report.
   output is a new private directory. the file is read as text and never executed.
   returns 0 native, 3 review-required, 2 malformed input, 6 unreadable input. */
int holy_convert_aports(const char *input, const char *source, const char *output);

#endif
