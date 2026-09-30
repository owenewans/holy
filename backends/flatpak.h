#ifndef HOLY_FLATPAK_H
#define HOLY_FLATPAK_H

/* a Flatpak manifest to holy-recipe(5) conversion. the manifest is read as JSON
   text and never built. */
int holy_convert_flatpak(const char *input, const char *source, const char *output);

#endif
