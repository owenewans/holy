#ifndef HOLY_APPIMAGE_H
#define HOLY_APPIMAGE_H

int holy_appimage_inspect(const char *input);
int holy_appimage_extract(const char *input, const char *output);
int holy_import_appimage(const char *input, const char *source, const char *output);

#endif
