/* a captured Nix closure to one native package per store path; see man/holypkg.8 and
   man/holy-package.5. a capture names the store paths of a closure and the references
   between them, and a store path is a directory a store has already built. this
   converter reads the capture once, keeps every store path whole under a private path,
   turns each declared reference into a package requirement and checks each reference
   against the bytes the referring path carries. nothing runs, so no store, daemon,
   profile or sandbox is reproduced, and a program that opens an absolute /nix/store
   path keeps needing a view this manager does not build. */
#define _POSIX_C_SOURCE 200809L
#include "nix.h"
#include "image.h"
#include "pack.h"
#include "stage.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* the store digest Nix base32 encodes, and the name it carries beside it */
#define NIX_HASH 32
#define NIX_NAME 200
#define NIX_ENTRY 400
#define NIX_NEEDLE (NIX_HASH + NIX_NAME + 2)
#define NIX_PATHS 128
#define NIX_EDGES 512
/* one pass over a store path confirms its references; a tree larger than this is
   counted as unconfirmed rather than read without a bound */
#define NIX_SCAN (16 * 1024 * 1024)

/* the alphabet a Nix store hash is written in; e, o, t and u are absent */
static const char nix_base32[] = "0123456789abcdfghijklmnpqrsvwxyz";

struct nix_path {
    char hash[NIX_HASH + 1], name[NIX_NAME + 1], entry[NIX_ENTRY + 1];
    size_t first, count;
    int root, stated;
};

struct nix_edge {
    size_t from, to;
    char hash[NIX_HASH + 1], name[NIX_NAME + 1], needle[NIX_NEEDLE];
    int inside;
};

struct nix_result {
    size_t entries, files, links, elfs, scripts, unknown, views;
    size_t needed, provided, absolute, outside, unconfirmed;
    char arch[16], libc[16];
    int entry;
    char artifact[320], digest[65];
};

static int digest_fd(int fd, char result[65])
{
    unsigned char buffer[65536], whole[32];
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    unsigned length = 0, index;
    ssize_t got;
    if (!context || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(context);
        return 0;
    }
    for (;;) {
        got = read(fd, buffer, sizeof buffer);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) break;
        if (EVP_DigestUpdate(context, buffer, (size_t)got) != 1) break;
    }
    if (got == 0 && EVP_DigestFinal_ex(context, whole, &length) == 1 && length == sizeof whole &&
        lseek(fd, 0, SEEK_SET) != -1) {
        for (index = 0; index < 32; ++index) snprintf(result + index * 2, 3, "%02x", whole[index]);
        result[64] = 0;
        EVP_MD_CTX_free(context);
        return 1;
    }
    EVP_MD_CTX_free(context);
    return 0;
}

/* a name the package format can record, and the one Nix writes after the hash */
static int label(const char *value)
{
    size_t at;
    if (!value || !*value || !isalnum((unsigned char)value[0])) return 0;
    for (at = 0; value[at]; ++at)
        if (!isalnum((unsigned char)value[at]) &&
            !(value[at] == '.' || value[at] == '_' || value[at] == '+' || value[at] == '-'))
            return 0;
    return 1;
}

/* one store path, with or without the /nix/store prefix a store query prints */
static int store_path(const char *value, char hash[NIX_HASH + 1], char name[NIX_NAME + 1])
{
    static const char prefix[] = "/nix/store/";
    const char *at, *cut;
    size_t used;
    if (!value) return 0;
    if (!strncmp(value, prefix, sizeof prefix - 1)) value += sizeof prefix - 1;
    if (strlen(value) < NIX_HASH + 2 || strchr(value, '/')) return 0;
    for (at = value; at - value < NIX_HASH; ++at)
        if (!*at || !strchr(nix_base32, *at)) return 0;
    if (value[NIX_HASH] != '-') return 0;
    memcpy(hash, value, NIX_HASH);
    hash[NIX_HASH] = 0;
    at = value + NIX_HASH + 1;
    cut = at + strlen(at);
    used = (size_t)(cut - at);
    if (!used || used > NIX_NAME) return 0;
    memcpy(name, at, used);
    name[used] = 0;
    return 1;
}

static size_t find_path(const struct nix_path *paths, size_t count, const char *hash,
                        const char *name)
{
    size_t index;
    for (index = 0; index < count; ++index)
        if (!strcmp(paths[index].hash, hash) && !strcmp(paths[index].name, name)) return index;
    return count;
}

static char *read_capture(const char *input, size_t *length)
{
    struct stat st;
    char *data = NULL;
    size_t used = 0;
    int fd = open(input, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        st.st_size > 4 * 1024 * 1024) {
        close(fd);
        return NULL;
    }
    data = malloc((size_t)st.st_size + 1);
    if (!data) { close(fd); return NULL; }
    while (used < (size_t)st.st_size) {
        ssize_t got = read(fd, data + used, (size_t)st.st_size - used);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { free(data); close(fd); return NULL; }
        used += (size_t)got;
    }
    close(fd);
    data[used] = 0;
    *length = used;
    return data;
}

/* the whitespace separated fields of one capture line, copied out so the capture can
   be read in more than one pass the way holy.conf splits a line */
static size_t fields(const char *line, size_t length, char *scratch, size_t room,
                     char *field[], size_t limit)
{
    size_t count = 0, used = 0;
    while (count < limit) {
        size_t start;
        while (used < length && (line[used] == ' ' || line[used] == '\t')) ++used;
        if (used >= length || line[used] == '\n' || line[used] == '\r') break;
        start = used;
        while (used < length && line[used] != ' ' && line[used] != '\t' &&
               line[used] != '\n' && line[used] != '\r') ++used;
        if (used - start + 1 > room) return limit;
        field[count] = scratch;
        memcpy(scratch, line + start, used - start);
        scratch[used - start] = 0;
        scratch += used - start + 1;
        room -= used - start + 1;
        ++count;
    }
    return count;
}

static int relative_path(const char *value)
{
    const char *at = value;
    if (!*value || *value == '/') return 0;
    while (*at) {
        const char *slash = strchr(at, '/');
        size_t used = slash ? (size_t)(slash - at) : strlen(at);
        if (!used || (used == 1 && at[0] == '.') || (used == 2 && !memcmp(at, "..", 2))) return 0;
        if (!slash) break;
        at = slash + 1;
    }
    return 1;
}

/* one capture line, split into fields, and the offset of the line after it */
static size_t record(const char *data, size_t length, size_t at, size_t *next, char *scratch,
                     size_t room, char *field[], size_t limit)
{
    size_t stop = at;
    while (stop < length && data[stop] != '\n') ++stop;
    *next = stop < length ? stop + 1 : length + 1;
    return fields(data + at, stop - at, scratch, room, field, limit);
}

/* the store paths a capture declares, and the output root it names. the root and the
   entry records may come before or after the path record they name, so the capture is
   read once for the store paths and once for everything that refers to them */
static int read_capture_paths(const char *data, size_t length, struct nix_path *paths,
                              size_t *count, char root_hash[NIX_HASH + 1],
                              char root_name[NIX_NAME + 1], int *seen_root)
{
    size_t at = 0, index;
    while (at <= length) {
        char scratch[8192], *field[64], hash[NIX_HASH + 1], name[NIX_NAME + 1];
        size_t got = record(data, length, at, &at, scratch, sizeof scratch, field,
                            sizeof field / sizeof *field);
        if (got >= sizeof field / sizeof *field) return 2;
        if (!got || field[0][0] == '#') continue;
        if (!strcmp(field[0], "path") && got == 2) {
            if (!store_path(field[1], hash, name)) {
                fputs("holypkg: a path record is not a Nix store path\n", stderr);
                return 2;
            }
            if (!label(name)) {
                fprintf(stderr, "holypkg: the store path name %s is not a package name\n", name);
                return 2;
            }
            if (*count == NIX_PATHS) {
                fputs("holypkg: the capture declares more store paths than one conversion "
                      "carries\n", stderr);
                return 3;
            }
            if (find_path(paths, *count, hash, name) != *count) continue;
            for (index = 0; index < *count; ++index)
                if (!strcmp(paths[index].name, name)) {
                    /* two store paths of one name would need a rewritten package name,
                       and a name is what the operator types */
                    fprintf(stderr, "holypkg: two store paths of the capture carry the name "
                                    "%s\n", name);
                    return 2;
                }
            snprintf(paths[*count].name, sizeof paths[*count].name, "%s", name);
            snprintf(paths[*count].hash, sizeof paths[*count].hash, "%s", hash);
            ++*count;
            continue;
        }
        if (!strcmp(field[0], "root") && got == 2) {
            if (*seen_root || !store_path(field[1], root_hash, root_name)) {
                fputs("holypkg: a capture names one output root\n", stderr);
                return 2;
            }
            *seen_root = 1;
            continue;
        }
    }
    if (!*count || !*seen_root) {
        fputs("holypkg: a capture declares at least one store path and one output root\n",
              stderr);
        return 2;
    }
    return 0;
}

/* the entry points and the references a capture declares, which may only be resolved
   once every store path it names is known */
static int read_capture_edges(const char *data, size_t length, struct nix_path *paths,
                              size_t count, const char root_hash[NIX_HASH + 1],
                              const char root_name[NIX_NAME + 1], struct nix_edge *edges,
                              size_t *edge_count, size_t *root, size_t *unknown)
{
    size_t at = 0, index, i;
    while (at <= length) {
        char scratch[8192], *field[64], hash[NIX_HASH + 1], name[NIX_NAME + 1];
        size_t got = record(data, length, at, &at, scratch, sizeof scratch, field,
                            sizeof field / sizeof *field);
        if (got >= sizeof field / sizeof *field) return 2;
        if (!got || field[0][0] == '#') continue;
        if (!strcmp(field[0], "root") && got == 2) continue;
        if (!strcmp(field[0], "path") && got == 2) continue;
        if (!strcmp(field[0], "entry") && got == 3) {
            if (!store_path(field[1], hash, name) || !relative_path(field[2]) ||
                strlen(field[2]) > NIX_ENTRY) {
                fputs("holypkg: an entry record names a store path and a path inside it\n",
                      stderr);
                return 2;
            }
            index = find_path(paths, count, hash, name);
            if (index == count || paths[index].stated) {
                fputs("holypkg: an entry record names a store path the capture does not "
                      "declare, or one it declares twice\n", stderr);
                return 2;
            }
            snprintf(paths[index].entry, sizeof paths[index].entry, "%s", field[2]);
            paths[index].stated = 1;
            continue;
        }
        if (!strcmp(field[0], "references") && got >= 2) {
            if (!store_path(field[1], hash, name)) {
                fputs("holypkg: a references record names a Nix store path\n", stderr);
                return 2;
            }
            index = find_path(paths, count, hash, name);
            if (index == count) {
                fputs("holypkg: the capture declares references for a store path it does not "
                      "declare\n", stderr);
                return 2;
            }
            for (i = 2; i < got; ++i) {
                struct nix_edge *edge;
                if (!store_path(field[i], hash, name)) {
                    fputs("holypkg: a references record names a Nix store path\n", stderr);
                    return 2;
                }
                if (*edge_count == NIX_EDGES) {
                    fputs("holypkg: the capture declares more references than one conversion "
                          "carries\n", stderr);
                    return 3;
                }
                edge = &edges[(*edge_count)++];
                edge->from = index;
                edge->to = find_path(paths, count, hash, name);
                edge->inside = edge->to != count;
                snprintf(edge->hash, sizeof edge->hash, "%s", hash);
                snprintf(edge->name, sizeof edge->name, "%s", name);
                snprintf(edge->needle, sizeof edge->needle, "%s-%s", hash, name);
                ++paths[index].count;
            }
            continue;
        }
        ++*unknown;
    }
    *root = find_path(paths, count, root_hash, root_name);
    if (*root == count) return 1;
    paths[*root].root = 1;
    /* the edges of one store path are contiguous, so the report can name them in the
       order the capture lists them */
    for (index = 0, at = 0; index < count; ++index) {
        paths[index].first = at;
        at += paths[index].count;
    }
    return 0;
}

static int contains(const unsigned char *data, size_t length, const char *needle)
{
    size_t used = strlen(needle), at;
    if (!used || used > length) return 0;
    for (at = 0; at + used <= length; ++at)
        if (data[at] == (unsigned char)needle[0] && !memcmp(data + at, needle, used)) return 1;
    return 0;
}

/* one pass over a store path, looking for the name of every store path it declares a
   reference to. a Nix store records the references itself, so a reference this pass
   cannot find stays a requirement: a payload cannot prove that a store path has none */
static int scan_references(int parent, const struct nix_edge *edges, size_t count,
                           unsigned char *found, unsigned depth, long long *budget)
{
    DIR *dir;
    struct dirent *entry;
    int copy, ok = 1;
    if (depth > 64) return 0;
    copy = holy_image_directory(parent);
    if (copy < 0) return 0;
    dir = fdopendir(copy);
    if (!dir) { close(copy); return 0; }
    errno = 0;
    while ((entry = readdir(dir))) {
        struct stat st;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (fstatat(parent, entry->d_name, &st, AT_SYMLINK_NOFOLLOW)) { ok = 0; break; }
        if (S_ISDIR(st.st_mode)) {
            int child = openat(parent, entry->d_name,
                               O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (child < 0 ||
                !scan_references(child, edges, count, found, depth + 1, budget)) ok = 0;
            if (child >= 0) close(child);
        } else if (S_ISREG(st.st_mode) && *budget > 0) {
            unsigned char buffer[65536 + NIX_NEEDLE];
            size_t kept = 0, i;
            int fd = openat(parent, entry->d_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            if (fd < 0) { ok = 0; break; }
            for (;;) {
                ssize_t got = read(fd, buffer + kept, 65536);
                size_t length;
                if (got < 0 && errno == EINTR) continue;
                if (got < 0) { ok = 0; break; }
                if (!got) break;
                length = kept + (size_t)got;
                *budget -= got;
                for (i = 0; i < count && !found[i]; ++i)
                    if (contains(buffer, length, edges[i].needle)) found[i] = 1;
                if (length >= NIX_NEEDLE) {
                    memcpy(buffer, buffer + length - NIX_NEEDLE, NIX_NEEDLE);
                    kept = NIX_NEEDLE;
                } else kept = length;
                if (*budget <= 0) break;
            }
            close(fd);
            if (!ok) break;
        }
        if (!ok) break;
        errno = 0;
    }
    if (errno) ok = 0;
    closedir(dir);
    return ok;
}

static int launcher_script(struct holy_text *out, const char *name, const char *source)
{
    return holy_text_add(out, "#!/bin/sh\n"
                               "# a captured store path is not a Nix store. this launcher starts\n"
                               "# the recorded entry point in the run context the package owns; a\n"
                               "# program that opens an absolute /nix/store path still needs a\n"
                               "# store view, which the package report says it does not have.\n"
                               "set -e\n"
                               "if [ \"$(id -u)\" = 0 ]; then\n"
                               "  echo '") &&
           holy_text_add(out, name) &&
           holy_text_add(out, ": the captured payload is not confined; run it as your own user"
                               "' >&2\n  exit 1\nfi\nexec holypkg run ") &&
           holy_text_add(out, source) && holy_text_add(out, ":") && holy_text_add(out, name) &&
           holy_text_add(out, " -- /usr/lib/holy/private/") && holy_text_add(out, name) &&
           holy_text_add(out, "/usr/bin/") && holy_text_add(out, name) &&
           holy_text_add(out, " \"$@\"\n");
}

static int copy_original(const char *data, size_t length, int output)
{
    int out = openat(output, "original", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                     0600);
    size_t at = 0;
    int ok = 0;
    if (out < 0) return 0;
    while (at < length) {
        ssize_t written = write(out, data + at, length - at);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) goto done;
        at += (size_t)written;
    }
    ok = !fsync(out) && !fsync(output);
done:
    close(out);
    return ok;
}

/* the payload of one store path: the tree whole under a private path, and a launcher
   for the entry point the capture names */
static int package_store_path(const char *source, const char *capture, size_t count,
                              const struct nix_path *paths, const struct nix_edge *edges,
                              size_t index, int directory, const char *capture_digest,
                              struct nix_result *result)
{
    const struct nix_path *path = &paths[index];
    const struct nix_edge *mine = edges + path->first;
    struct holy_payload payload = {0};
    struct holy_text launcher = {0};
    char *text[7] = {0};
    size_t sizes[7] = {0}, i, data_first, confirmed = 0;
    FILE *files[7] = {0};
    char private[256], base[768], held[1024], link[768], spool_name[43];
    const char *arch = HOLY_PAYLOAD_NOARCH, *libc = HOLY_PAYLOAD_NOLIBC;
    int tree = -1, spool = -1, status = 1, entry_ok = 0;

    {
        /* the store path sits beside the capture, so nothing runs to build or unpack it */
        const char *slash = strrchr(capture, '/');
        size_t cut = slash ? (size_t)(slash - capture) + 1 : 0;
        size_t used = NIX_HASH + 1 + NIX_NAME;
        char *tree_path = malloc(cut + used + 1);
        if (!tree_path) return 1;
        memcpy(tree_path, capture, cut);
        snprintf(tree_path + cut, used + 1, "%s-%s", path->hash, path->name);
        tree = open(tree_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (tree < 0) {
            fprintf(stderr, "holypkg: the store path %s-%s is not beside the capture\n",
                    path->hash, path->name);
            free(tree_path);
            return 6;
        }
        free(tree_path);
    }
    for (i = 0; i < 7; ++i)
        if (!(files[i] = open_memstream(&text[i], &sizes[i]))) goto done;
    spool = holy_spool_at(directory, spool_name);
    if (spool < 0) goto done;
    payload.spool = spool;
    payload.uid = (long long)geteuid();
    payload.gid = (long long)getegid();
    if (!holy_payload_add(&payload, "HOLY", NULL, 0755, 0, 0, 1) ||
        !holy_payload_add(&payload, "DATA", NULL, 0755, 0, 0, 1)) goto done;
    data_first = payload.count;
    snprintf(private, sizeof private, "usr/lib/holy/private/%s", path->name);
    snprintf(base, sizeof base, "DATA/%s/store/%s-%s", private, path->hash, path->name);
    if (!holy_payload_add(&payload, base, NULL, 0755, 0, 0, 1) ||
        !holy_payload_walk(&payload, tree, "", base, 0)) goto done;
    if (payload.mixed) {
        fputs("holypkg: the store path carries more than one architecture or runtime, and one\n"
              "       .holy records one of each\n", stderr);
        status = 3;
        goto done;
    }
    if (payload.arch[0]) {
        arch = payload.arch;
        libc = payload.libc;
    }
    /* the entry point the capture names has to be an executable file of that store path */
    if (path->stated) {
        int check = openat(tree, path->entry, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        struct stat entry;
        if (check < 0 || fstat(check, &entry) || !S_ISREG(entry.st_mode) ||
            !(entry.st_mode & 0111)) {
            if (check >= 0) close(check);
            fputs("holypkg: the entry point the capture names is not an executable file in its "
                  "own store path\n", stderr);
            status = 3;
            goto done;
        }
        close(check);
        snprintf(link, sizeof link, "DATA/%s/usr/bin", private);
        if (!holy_payload_add(&payload, link, NULL, 0755, 0, 0, 1)) goto done;
        snprintf(link, sizeof link, "DATA/%s/usr/bin/%s", private, path->name);
        snprintf(held, sizeof held, "../../store/%s-%s/%s", path->hash, path->name, path->entry);
        if (!holy_payload_add(&payload, link, held, 0777, 0, 0, 0)) goto done;
        if (!launcher_script(&launcher, path->name, source)) goto done;
        snprintf(held, sizeof held, "DATA/usr/bin/%s", path->name);
        if (!holy_payload_add_text(&payload, &launcher, held, 0755)) goto done;
        entry_ok = 1;
    }
    {
        /* one pass confirms the references the capture declares, so the report can say
           which of them the payload carries and which the store alone states */
        unsigned char found[NIX_EDGES];
        long long budget = NIX_SCAN;
        memset(found, 0, sizeof found);
        if (!path->count || scan_references(tree, mine, path->count, found, 0, &budget))
            for (i = 0; i < path->count; ++i)
                if (found[i]) ++confirmed;
    }
    snprintf(result->arch, sizeof result->arch, "%s", arch);
    snprintf(result->libc, sizeof result->libc, "%s", libc);
    fputs("format holy-package-1\nname ", files[0]); holy_quoted(files[0], path->name);
    /* Nix states no version, so the store hash is the identity of a package */
    fputs("\nversion 0\nrelease 1\nos linux\narch ", files[0]); holy_quoted(files[0], arch);
    fputs("\nlibc ", files[0]); holy_quoted(files[0], libc);
    fputs("\nx-version-family nix\nx-source-family nix\nx-converter holy-nix-1\n"
          "x-nix-store-hash ", files[0]);
    holy_quoted(files[0], path->hash);
    fputs("\nx-nix-store-path ", files[0]);
    fputc('-', files[0]); holy_quoted(files[0], path->hash);
    fputc('-', files[0]); holy_quoted(files[0], path->name);
    fprintf(files[0], "\nx-nix-closure %zu\nx-nix-capture-sha256 %s\n", count, capture_digest);
    if (!holy_payload_manifest(files[1], &payload, data_first)) goto done;
    for (i = 0; i < path->count; ++i) {
        const struct nix_edge *edge = &mine[i];
        char id[128];
        if (edge->inside) {
            snprintf(id, sizeof id, "nix-reference-%zu", i);
            fputs("require ", files[2]); holy_quoted(files[2], id);
            fputc(' ', files[2]); holy_quoted(files[2], path->name);
            fputs(" package ", files[2]); holy_quoted(files[2], edge->name);
            fprintf(files[2], " %s %s any - ", arch, libc);
            holy_quoted(files[2], "nix_store_path");
            fputc(' ', files[2]); holy_quoted(files[2], "nix-closure");
        } else {
            /* a store path the capture does not carry becomes a package requirement:
               the target needs a source that provides it and the hash is its identity.
               the consumer states no machine or runtime for it, because the store path
               that would state one is the one the capture does not carry */
            snprintf(id, sizeof id, "nix-outside-%zu", i);
            fputs("require ", files[2]); holy_quoted(files[2], id);
            fputc(' ', files[2]); holy_quoted(files[2], path->name);
            fputs(" package ", files[2]); holy_quoted(files[2], edge->name);
            fputs(" any any any - ", files[2]);
            holy_quoted(files[2], edge->hash);
            fputc(' ', files[2]); holy_quoted(files[2], "nix-store-outside");
        }
        fputc('\n', files[2]);
    }
    for (i = 0; i < payload.needed.count; ++i) {
        const char *soname = holy_names_get(&payload.needed, i);
        char id[128];
        if (holy_names_has(&payload.provided, soname)) continue;
        snprintf(id, sizeof id, "nix-soname-%zu", i);
        fputs("require ", files[2]); holy_quoted(files[2], id);
        fputc(' ', files[2]); holy_quoted(files[2], path->name);
        fputs(" soname ", files[2]); holy_quoted(files[2], soname);
        fprintf(files[2], " %s %s any - ", arch, libc);
        holy_quoted(files[2], "dt_needed");
        fputc(' ', files[2]); holy_quoted(files[2], "nix-payload");
        fputc('\n', files[2]);
    }
    for (i = 0; i < payload.absolute.count; ++i) {
        char id[128];
        snprintf(id, sizeof id, "nix-link-%zu", i);
        fputs("require ", files[2]); holy_quoted(files[2], id);
        fputc(' ', files[2]); holy_quoted(files[2], path->name);
        fputs(" file ", files[2]); holy_quoted(files[2], holy_names_get(&payload.absolute, i));
        fputs(" any any any - ", files[2]);
        holy_quoted(files[2], "symlink_target");
        fputc(' ', files[2]); holy_quoted(files[2], "nix-payload");
        fputc('\n', files[2]);
    }
    fputs("provide package ", files[3]); holy_quoted(files[3], path->name);
    fprintf(files[3], " %s %s - ", arch, libc);
    holy_quoted(files[3], "nix-closure");
    fputc('\n', files[3]);
    for (i = 0; i < payload.provided.count; ++i) {
        fputs("provide soname ", files[3]);
        holy_quoted(files[3], holy_names_get(&payload.provided, i));
        fprintf(files[3], " %s %s - ", arch, libc);
        holy_quoted(files[3], "nix-payload");
        fputc('\n', files[3]);
    }
    /* no hook runs at install: a captured store path is not executed */
    fputs("format holy-import-origin-1\nfamily nix\nsource-name ", files[5]);
    holy_quoted(files[5], source);
    fputs("\noriginal-sha256 ", files[5]); holy_quoted(files[5], capture_digest);
    fputs("\nverification unverified\nconverter holy-nix-1\noriginal-version 0\nstore-path ",
          files[5]);
    fputc('-', files[5]); holy_quoted(files[5], path->hash);
    fputc('-', files[5]); holy_quoted(files[5], path->name);
    fputs("\nstore-hash ", files[5]); holy_quoted(files[5], path->hash);
    fputs("\nmode closure\n", files[5]);
    fputs("format holy-import-transform-1\nstore the captured store path travels whole under a\n"
          "private path\n", files[6]);
    fprintf(files[6], "private %s\nstore-path %s-%s\n", private, path->hash, path->name);
    if (entry_ok)
        fprintf(files[6], "launcher /usr/bin/%s starts the recorded entry point in the package "
                          "run context\n", path->name);
    fputs("store-view none; an absolute /nix/store path needs a view this manager does not "
          "build\n", files[6]);
    fputs("sandbox dropped; a Nix profile, a store daemon and its namespaces are not "
          "reproduced\n", files[6]);
    fprintf(files[6], "references %zu; a store path the capture does not carry becomes a package "
                      "requirement\n", path->count);
    if (ferror(files[0]) || ferror(files[2]) || ferror(files[3]) || ferror(files[5]) ||
        ferror(files[6])) goto done;
    if (!holy_payload_records(&payload, files, text, sizes)) goto done;
    result->entries = payload.count;
    result->files = payload.files;
    result->links = payload.links;
    result->elfs = payload.elfs;
    result->scripts = payload.scripts;
    result->unknown = payload.unknown;
    result->views = payload.path_views;
    result->needed = payload.needed.count;
    result->provided = payload.provided.count;
    result->absolute = payload.absolute.count;
    result->unconfirmed = path->count - confirmed;
    result->entry = entry_ok;
    snprintf(result->artifact, sizeof result->artifact, "%s--%s--%s.holy", path->name, arch,
             libc);
    if (!holy_pack_stream(spool, payload.entries, payload.count, directory,
                          result->artifact)) goto done;
    {
        int packed = openat(directory, result->artifact, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (packed < 0 || !digest_fd(packed, result->digest)) goto done;
        close(packed);
    }
    printf("imported %s store %s-%s arch %s libc %s mode closure\n", result->artifact,
           path->hash, path->name, arch, libc);
    status = 0;
done:
    for (i = 0; i < 7; ++i) if (files[i]) fclose(files[i]);
    for (i = 0; i < 7; ++i) free(text[i]);
    holy_payload_free(&payload);
    holy_text_free(&launcher);
    if (spool >= 0) {
        if (spool_name[0]) unlinkat(directory, spool_name, 0);
        close(spool);
    }
    if (tree >= 0) close(tree);
    return status;
}

static int write_report(int directory, const char *source, const char *capture_digest,
                        const struct nix_path *paths, size_t count,
                        const struct nix_edge *edges, const struct nix_result *results,
                        size_t unknown)
{
    size_t i, j;
    int fd = openat(directory, "package", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
    FILE *log;
    if (fd < 0) return 0;
    log = fdopen(fd, "w");
    if (!log) { close(fd); return 0; }
    fprintf(log, "format holy-nix-closure-1\nconverter holy-nix-1\nsource-name %s\n", source);
    fputs("status review-required\nmode closure\n", log);
    for (i = 0; i < count; ++i) {
        const struct nix_path *path = &paths[i];
        const struct nix_result *result = &results[i];
        fprintf(log, "package %s store-path %s-%s%s\n", path->name, path->hash, path->name,
                path->root ? " root" : "");
        fprintf(log, "package-artifact %s sha256 %s arch %s libc %s\n", result->artifact,
                result->digest, result->arch, result->libc);
        fprintf(log, "package-payload usr/lib/holy/private/%s/store/%s-%s\n", path->name,
                path->hash, path->name);
        fprintf(log, "package-entries %zu files %zu elf %zu links %zu sonames %zu "
                     "link-requirements %zu unknown %zu\n",
                result->entries, result->files, result->elfs, result->links, result->provided,
                result->absolute, result->unknown);
        if (result->entry) fprintf(log, "package-entry %s\n", path->entry);
        else fputs("package-entry the capture names none, so the package claims no /usr/bin "
                   "path\n", log);
        fprintf(log, "package-references %zu unconfirmed %zu outside %zu\n", path->count,
                result->unconfirmed, result->outside);
        for (j = 0; j < path->count; ++j) {
            const struct nix_edge *edge = &edges[path->first + j];
            fprintf(log, "reference %s -> %s-%s %s\n", path->name, edge->hash, edge->name,
                    edge->inside ? "inside" : "outside");
        }
        if (result->views)
            fprintf(log, "package-path-views %zu links name an absolute or escaping target; "
                         "each path it named is a recorded file requirement\n", result->views);
        if (result->scripts)
            fprintf(log, "package-scripts %zu files carry an interpreter; nothing runs them at "
                         "install\n", result->scripts);
    }
    fputs("version Nix states no version, so every package records zero and the store hash is "
          "the identity\n", log);
    fprintf(log, "capture %s; the capture is copied beside the packages as original\n",
            capture_digest);
    fputs("execution no Nix store, daemon, profile or sandbox is reproduced; a program that\n"
          "opens an absolute /nix/store path needs a view this manager does not build, and the\n"
          "launcher starts the recorded entry point in the package run context\n", log);
    if (unknown)
        fprintf(log, "unknown %zu records of the capture this reader does not model\n", unknown);
    return !ferror(log) && !fflush(log) && !fsync(fileno(log)) && !fclose(log);
}

int holy_import_nix(const char *input, const char *source, const char *output)
{
    struct nix_path *paths = NULL;
    struct nix_edge *edges = NULL;
    struct nix_result *results = NULL;
    char *data = NULL, capture_digest[65], root_hash[NIX_HASH + 1], root_name[NIX_NAME + 1];
    size_t length = 0, count = 0, edge_count = 0, root = 0, unknown = 0, i;
    int seen_root = 0, directory = -1, copied = -1, result = 1;

    if (!source || !*source || !strcmp(source, "local")) return 2;
    for (i = 0; source[i]; ++i)
        if ((unsigned char)source[i] <= 32 || source[i] == ':' || source[i] == '/' ||
            source[i] == '@') return 2;
    if (!input || !output || !*output) {
        fputs("usage: holypkg import CAPTURE --source NAME --format nix "
              "--output NEW_DIRECTORY\n", stderr);
        return 2;
    }
    data = read_capture(input, &length);
    if (!data) {
        fprintf(stderr, "holypkg: closure capture unavailable: %s\n", input);
        return 6;
    }
    paths = calloc(NIX_PATHS, sizeof *paths);
    edges = calloc(NIX_EDGES, sizeof *edges);
    if (!paths || !edges) goto done;
    result = read_capture_paths(data, length, paths, &count, root_hash, root_name, &seen_root);
    if (result) goto done;
    result = read_capture_edges(data, length, paths, count, root_hash, root_name, edges,
                                &edge_count, &root, &unknown);
    if (result) goto done;
    if (mkdir(output, 0700) && errno != EEXIST) {
        fprintf(stderr, "holypkg: conversion directory unavailable: %s\n", output);
        result = 1;
        goto done;
    }
    directory = open(output, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) {
        fprintf(stderr, "holypkg: conversion directory unavailable: %s\n", output);
        result = 1;
        goto done;
    }
    if (!copy_original(data, length, directory)) goto done;
    copied = openat(directory, "original", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (copied < 0 || !digest_fd(copied, capture_digest)) goto done;
    close(copied);
    copied = -1;
    results = calloc(count, sizeof *results);
    if (!results) goto done;
    for (i = 0; i < count; ++i) {
        size_t j;
        int status = package_store_path(source, input, count, paths, edges, i, directory,
                                        capture_digest, &results[i]);
        if (status) { result = status; goto done; }
        for (j = 0; j < edge_count; ++j)
            if (edges[j].from == i && !edges[j].inside) ++results[i].outside;
    }
    if (!write_report(directory, source, capture_digest, paths, count, edges, results,
                      unknown)) goto done;
    result = 0;
done:
    if (directory >= 0) close(directory);
    free(data);
    free(paths);
    free(edges);
    free(results);
    if (result) {
        fputs("holypkg: the closure conversion is incomplete; no installed state changed\n",
              stderr);
        return result;
    }
    fputs("holypkg: the packages run without a Nix store, without the store paths the capture\n"
          "       does not carry and without a store view; read the closure report before\n"
          "       installing them\n", stderr);
    return 3;
}
