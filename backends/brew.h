#ifndef HOLY_BREW_H
#define HOLY_BREW_H

/* a Homebrew formula to a holy-recipe(5) manifest plus a conversion report. the
   formula is read as Ruby text and never evaluated: a system call becomes the
   shell that runs the same command, and any other statement of an install body
   is preserved verbatim and named, since only the formula's author knows what it
   does. */
int holy_convert_brew(const char *input, const char *source, const char *output);

#endif
