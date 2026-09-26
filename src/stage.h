#ifndef HOLY_STAGE_H
#define HOLY_STAGE_H

/* returns a private copied path; caller unlinks and frees it. */
char *holy_stage_local(const char *source, const char *prefix);

#endif
