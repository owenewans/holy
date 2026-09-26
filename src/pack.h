#ifndef HOLY_PACK_H
#define HOLY_PACK_H

/* write a verified regular-file/dir .holy from a prepared tree. */
int holy_pack(const char *tree, const char *output);
/* generate a manifest for a prepared DATA tree without changing it. */
int holy_generate_files(const char *tree, const char *output);

#endif
