#ifndef HOLY_SLACKBUILD_H
#define HOLY_SLACKBUILD_H

/* converts one SlackBuild script into a holy-recipe(5) manifest plus a report.
   output is a new private directory. the script is read as text and never run.
   returns 0 native, 3 review-required, 2 malformed input, 6 unreadable input. */
int holy_convert_slackbuild(const char *input, const char *source, const char *output);

#endif
