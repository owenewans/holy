#ifndef HOLY_KEYRING_H
#define HOLY_KEYRING_H

#include <stddef.h>

/* named public keys enrolled in the target root, under var/lib/holypkg/keys.
   the store keeps the key bytes and the digest recorded at enrollment, so a key
   changed on disk is refused instead of silently trusted. 0 ok, 2 invalid input,
   3 a decision the caller has to state, 4 the key is unreadable or not a key,
   5 an incomplete transaction, 6 the root has no usable database. */
int holy_keyring_add(const char *root_path, const char *name, const char *file,
                     int replace);
int holy_keyring_list(const char *root_path, int json);
int holy_keyring_show(const char *root_path, const char *name);
int holy_keyring_remove(const char *root_path, const char *name, int confirmed);

/* 1 the name is enrolled and the key path is in out, 0 no such name or no
   database, -1 the name is not a usable key name, -2 the enrolled key changed. */
int holy_keyring_path(const char *root_path, const char *name, char *out, size_t size);

/* 1 the name is a usable enrolled key name. */
int holy_keyring_name(const char *name);

/* the path a public-key value names: the readable file itself, or the key enrolled
   under that name in ROOT. the caller owns the returned path and frees it, and NULL
   is a value that is neither, which the command reports rather than guessing. */
char *holy_keyring_resolve(const char *root_path, const char *value);

/* the file name a reader should call the key at. an apk index names its signature after
   the key file, so a key enrolled under another name is verified under the name it was
   enrolled from rather than the name it is stored under. */
int holy_keyring_keyname(const char *root_path, const char *key_path, char *out, size_t size);

#endif
