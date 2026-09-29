#ifndef HOLY_PKGBUILD_H
#define HOLY_PKGBUILD_H

/* converts one PKGBUILD into a holy-recipe(5) manifest plus a conversion report.
   output is a new private directory. the source text is never executed.
   returns 0 native, 3 review-required, 2 malformed input, 6 unreadable input. */
int holy_convert_pkgbuild(const char *input, const char *source, const char *output);

#endif
