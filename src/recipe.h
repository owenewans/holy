#ifndef HOLY_RECIPE_H
#define HOLY_RECIPE_H

#include "sandbox.h"

/* runs one holy-recipe manifest and writes its .holy outputs into a new directory.
   environment is host, clean or vm; work is a new private build root.
   request carries the explicit parameters of the clean environment and is ignored for
   the other two. approve_all skips step review, noninteractive refuses unreviewed
   steps. */
int holy_recipe_build(const char *path, const char *environment, const char *work,
                      const char *output, const struct holy_sandbox_request *request,
                      unsigned jobs, int approve_all, int noninteractive, int keep);

#endif