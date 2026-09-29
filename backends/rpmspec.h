#ifndef HOLY_RPMSPEC_H
#define HOLY_RPMSPEC_H

/* converts one RPM spec file into a holy-recipe(5) manifest plus a report.
   output is a new private directory. the spec is read as text and never run.
   returns 0 native, 3 review-required, 2 malformed input, 6 unreadable input. */
int holy_convert_rpmspec(const char *input, const char *source, const char *output);

#endif
