#ifndef HOLY_RECIPE_H
#define HOLY_RECIPE_H

/* runs one holy-recipe manifest and writes its .holy outputs into a new directory.
   environment is host, clean or vm; work is a new private build root.
   approve_all skips step review, noninteractive refuses unreviewed steps. */
int holy_recipe_build(const char *path, const char *environment, const char *work,
                      const char *output, unsigned jobs, int approve_all,
                      int noninteractive, int keep);

#endif
