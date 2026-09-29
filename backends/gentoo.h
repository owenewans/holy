#ifndef HOLY_GENTOO_H
#define HOLY_GENTOO_H

/* a Gentoo ebuild to holy-recipe(5) conversion. the ebuild is read as text and
   never run. */
int holy_convert_gentoo(const char *input, const char *source, const char *output);

#endif
