#ifndef HOLY_DISK_H
#define HOLY_DISK_H

#include <stddef.h>

int holy_disk_main(int argc, char **argv);

/* the layout word at INDEX, or NULL past the end of the list */
const char *holy_disk_layout_word(size_t index);

#endif
