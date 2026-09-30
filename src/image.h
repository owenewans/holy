#ifndef HOLY_IMAGE_H
#define HOLY_IMAGE_H

#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include "pack.h"

/* a single-file squashfs image: one AppDir or one snap root that becomes one
   native package. every byte is spooled into a single file, so the packer never
   opens a host path it was handed, and each entry keeps the digest its manifest
   record carries. */

struct holy_text {
    char *data;
    size_t used, capacity;
};

/* an ordered set of names, which the payload needs, provides or cannot carry */
struct holy_names {
    struct holy_text names;
    size_t *offsets;
    size_t count, capacity;
};

struct holy_payload {
    struct holy_stream_entry *entries;
    unsigned char (*digests)[32];
    size_t count, capacity;
    /* the directories the payload declares; an installer places a file only
       under a directory the same manifest records */
    struct holy_names directories;
    int spool;
    off_t written;
    /* a payload is installed as the installing user, so every entry this
       converter writes is attributed to that user */
    long long uid, gid;
    /* what the payload implies */
    struct holy_names needed, provided, absolute;
    size_t files, links, elfs, scripts, unknown, path_views;
    char arch[16], libc[16];
    int mixed;
};

/* opens a directory for reading with its own file description; a duplicated
   descriptor would share the directory offset with the copy */
int holy_image_directory(int parent);
/* a child path under a parent, "" for the parent itself */
char *holy_image_path(const char *parent, const char *name);
/* writes one quoted value the manifest lexer reads back */
void holy_quoted(FILE *out, const char *value);

void holy_text_free(struct holy_text *text);
int holy_text_add(struct holy_text *text, const char *value);
int holy_text_read(int dir, const char *name, struct holy_text *out, size_t limit);

int holy_names_add(struct holy_names *set, const char *name);
int holy_names_has(const struct holy_names *set, const char *name);
const char *holy_names_get(const struct holy_names *set, size_t index);

void holy_payload_free(struct holy_payload *payload);
int holy_payload_add(struct holy_payload *payload, const char *path, const char *link,
                     unsigned mode, long long offset, long long size, int directory);
int holy_payload_add_text(struct holy_payload *payload, struct holy_text *body,
                          const char *path, unsigned mode);
/* copies one host file into the spool, hashing what it wrote */
int holy_payload_spool_file(struct holy_payload *payload, int input, long long *offset,
                            long long *size, unsigned char digest[32]);
/* copies bytes already in memory into the spool, hashing what it wrote */
int holy_payload_spool_bytes(struct holy_payload *payload, const void *data, size_t length,
                             long long *offset, long long *size, unsigned char digest[32]);

/* one file written into the spool in pieces, which is how an archive member
   becomes a payload entry without being held in memory */
struct holy_spool_writer {
    void *context;
    long long offset, size;
};

int holy_spool_open(struct holy_payload *payload, struct holy_spool_writer *writer);
int holy_spool_append(struct holy_payload *payload, struct holy_spool_writer *writer,
                      const void *data, size_t length);
int holy_spool_close(struct holy_payload *payload, struct holy_spool_writer *writer,
                     unsigned char digest[32]);
/* walks one directory of the image into the payload, never following a link */
int holy_payload_walk(struct holy_payload *payload, int parent, const char *prefix,
                      const char *payload_prefix, unsigned depth);
/* the absolute path a link would name, which a payload cannot carry */
char *holy_payload_link_target(const char *path, const char *target);
/* one manifest record per payload entry, in the form the packer writes */
int holy_payload_manifest(FILE *out, const struct holy_payload *payload, size_t first);
/* writes the seven record streams into the spool and adds them as entries */
int holy_payload_records(struct holy_payload *payload, FILE *files[7], char *text[7],
                         size_t sizes[7]);

#define HOLY_PAYLOAD_NOARCH "noarch"
#define HOLY_PAYLOAD_NOLIBC "nolibc"

#endif
