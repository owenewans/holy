#ifndef HOLY_PROVIDES_H
#define HOLY_PROVIDES_H

/* verifies a supported HOLY/provides subset; emit prints claims. */
int holy_provides_local(const char *package, int emit);
/* exact declared match; returns false if any capability record is invalid. */
int holy_provides_match(const char *package, const char *kind,
                        const char *name, int *matched);
int holy_provides_kind(const char *kind);

#endif
