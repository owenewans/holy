#ifndef HOLY_VOIDSRC_H
#define HOLY_VOIDSRC_H

/* converts one Void template into a holy-recipe(5) manifest, a conversion
   report and the files it names. output is a new private directory.
   the template is read as text and is never executed.
   returns 0 native, 3 review-required, 2 malformed input, 6 unreadable input. */
int holy_convert_voidsrc(const char *input, const char *source, const char *output);

#endif
