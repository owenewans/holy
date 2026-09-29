#ifndef HOLY_DEBSRC_H
#define HOLY_DEBSRC_H

/* converts one debian source package into a holy-recipe(5) manifest plus a report.
   output is a new private directory. the files are read as text and never run.
   input is the debian directory. returns 0 native, 3 review-required,
   2 malformed input, 6 unreadable input. */
int holy_convert_debsrc(const char *input, const char *source, const char *output);

#endif
