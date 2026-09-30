#ifndef HOLY_GUIX_H
#define HOLY_GUIX_H

/* a Guix package definition to a holy-recipe(5) manifest plus a conversion report.
   the definition is Scheme text and is never evaluated: a build system becomes the
   shell that runs the same tools, an origin becomes a pinned source, and an
   argument this reader does not model is named rather than guessed. */
int holy_convert_guix(const char *input, const char *source, const char *output);

#endif
