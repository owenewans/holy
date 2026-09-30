/* a Solus eopkg to a native package; see man/holypkg.8 and man/holy-package.5.
   an eopkg is a ZIP carrying metadata.xml, files.xml and an install tar. this
   converter reads the metadata as XML text, walks the install tar with libarchive as
   the bytes it holds, turns each runtime dependency into a package requirement and
   records what a Solus installation would also do and this one does not: an install
   script, a COMAR object, a delta and a signature are named and dropped rather than
   executed or trusted. the payload travels whole under a private path, since a
   Solus package owns a system layout this manager records rather than claims. */
#define _POSIX_C_SOURCE 200809L
#include "eopkg.h"
#include "image.h"
#include "pack.h"
#include "stage.h"

#include <archive.h>
#include <archive_entry.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define EOPKG_METADATA (4 * 1024 * 1024)
#define EOPKG_DEPENDS 256
#define EOPKG_DEPTH 16
#define EOPKG_TAG 64

/* what the artifact carried beside the payload */
struct eopkg_parts {
    int metadata, files, install, install_xz, setup, delta, signature;
    size_t unknown, members;
    char install_digest[65];
};

struct eopkg_dep {
    char *name, *distribution;
    size_t line;
};

struct eopkg_meta {
    char *name, *version, *release, *arch, *summary, *license, *url, *component, *format;
    struct eopkg_dep depends[EOPKG_DEPENDS];
    size_t depends_count;
    size_t unknown, packager, description, history, conflicts, replaces, provides, files;
};

/* the tags on the way to the element being read, so a name lands in its own context:
   a Name under Source is not the package name */
struct eopkg_walk {
    char path[EOPKG_DEPTH][EOPKG_TAG];
    size_t depth;
    struct holy_text body;
    char *attribute_name, *attribute_distribution;
    size_t line;
    struct eopkg_meta *meta;
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

static int digest_bytes(const void *data, size_t length, char result[65])
{
    unsigned char whole[32];
    unsigned size = 0;
    size_t index;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (!context) return 0;
    if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(context, data, length) != 1 ||
        EVP_DigestFinal_ex(context, whole, &size) != 1 || size != sizeof whole) {
        EVP_MD_CTX_free(context);
        return 0;
    }
    EVP_MD_CTX_free(context);
    for (index = 0; index < 32; ++index) snprintf(result + index * 2, 3, "%02x", whole[index]);
    result[64] = 0;
    return 1;
}

static char *trimmed(char *value)
{
    char *at = value;
    size_t length;
    while (*at == ' ' || *at == '\t' || *at == '\n' || *at == '\r') ++at;
    if (at != value) memmove(value, at, strlen(at) + 1);
    length = strlen(value);
    while (length && (value[length - 1] == ' ' || value[length - 1] == '\t' ||
                      value[length - 1] == '\n' || value[length - 1] == '\r'))
        value[--length] = 0;
    return value;
}

/* the value of one attribute of an opening tag, or NULL when it states none */
static char *attribute(const char *tag, size_t length, const char *name)
{
    size_t name_length = strlen(name), at;
    for (at = 0; at + name_length + 1 < length; ++at) {
        char quote;
        size_t end;
        if (memcmp(tag + at, name, name_length) || tag[at + name_length] != '=') continue;
        quote = tag[at + name_length + 1];
        if (quote != '"' && quote != '\'') continue;
        end = at + name_length + 2;
        while (end < length && tag[end] != quote) ++end;
        if (end >= length) return NULL;
        {
            char *value = malloc(end - (at + name_length + 2) + 1);
            if (!value) return NULL;
            memcpy(value, tag + at + name_length + 2, end - (at + name_length + 2));
            value[end - (at + name_length + 2)] = 0;
            return value;
        }
    }
    return NULL;
}

static int name_character(int value)
{
    return isalnum((unsigned char)value) || value == '_' || value == '-' || value == ':' ||
           value == '.';
}

static void meta_free(struct eopkg_meta *meta)
{
    size_t i;
    free(meta->name); free(meta->version); free(meta->release); free(meta->arch);
    free(meta->summary); free(meta->license); free(meta->url); free(meta->component);
    free(meta->format);
    for (i = 0; i < meta->depends_count; ++i) {
        free(meta->depends[i].name);
        free(meta->depends[i].distribution);
    }
    memset(meta, 0, sizeof *meta);
}

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

/* the elements this reader models, and where each value lands */
static int scalar_target(struct eopkg_meta *meta, const char *path, char ***target)
{
    *target = NULL;
    if (!strcmp(path, "PISI/Package/Name")) *target = &meta->name;
    else if (!strcmp(path, "PISI/Package/Version")) *target = &meta->version;
    else if (!strcmp(path, "PISI/Package/Architecture")) *target = &meta->arch;
    else if (!strcmp(path, "PISI/Package/Summary")) *target = &meta->summary;
    else if (!strcmp(path, "PISI/Package/License")) *target = &meta->license;
    else if (!strcmp(path, "PISI/Package/Url")) *target = &meta->url;
    else if (!strcmp(path, "PISI/Package/PartOf")) *target = &meta->component;
    else if (!strcmp(path, "PISI/Format")) *target = &meta->format;
    return *target != NULL;
}

/* the elements whose children this reader counts instead of modelling */
static int container(const char *path)
{
    static const char *const known[] = {
        "PISI", "PISI/Source", "PISI/Source/Packager", "PISI/Package",
        "PISI/Package/History", "PISI/Package/History/Update",
        "PISI/Package/RuntimeDependencies", "PISI/Package/BuildDependencies",
        "PISI/Package/SourceDependencies", "PISI/Package/Conflicts",
        "PISI/Package/Replaces", "PISI/Package/Provides", "PISI/Package/UpdateScript",
        "PISI/Files", "PISI/Files/File", NULL
    };
    size_t i;
    for (i = 0; known[i]; ++i) if (!strcmp(path, known[i])) return 1;
    return 0;
}

static void current_path(const struct eopkg_walk *walk, char *out, size_t size)
{
    size_t i, used = 0;
    out[0] = 0;
    for (i = 0; i < walk->depth; ++i) {
        int written = snprintf(out + used, size - used, "%s%s", i ? "/" : "", walk->path[i]);
        if (written < 0 || (size_t)written >= size - used) { out[0] = 0; return; }
        used += (size_t)written;
    }
}

static void walk_free(struct eopkg_walk *walk)
{
    holy_text_free(&walk->body);
    free(walk->attribute_name);
    free(walk->attribute_distribution);
    memset(walk, 0, sizeof *walk);
}

/* one element finished, which is where a value is stored or a count is taken */
static int close_element(struct eopkg_walk *walk)
{
    char path[EOPKG_DEPTH * EOPKG_TAG], *value;
    char **target = NULL;
    current_path(walk, path, sizeof path);
    value = malloc(walk->body.used + 1);
    if (!value) return 0;
    memcpy(value, walk->body.data ? walk->body.data : "", walk->body.used);
    value[walk->body.used] = 0;
    trimmed(value);
    if (scalar_target(walk->meta, path, &target)) {
        if (*value) {
            free(*target);
            *target = value;
            return 1;
        }
    } else if (!strcmp(path, "PISI/Package/RuntimeDependencies/Dependency")) {
        if (label(value)) {
            if (walk->meta->depends_count == EOPKG_DEPENDS) { free(value); return 0; }
            walk->meta->depends[walk->meta->depends_count].name = value;
            walk->meta->depends[walk->meta->depends_count].distribution =
                walk->attribute_distribution;
            walk->meta->depends[walk->meta->depends_count].line = walk->line;
            walk->attribute_distribution = NULL;
            ++walk->meta->depends_count;
            return 1;
        }
    } else if (!strcmp(path, "PISI/Package/Conflicts")) ++walk->meta->conflicts;
    else if (!strcmp(path, "PISI/Package/Replaces")) ++walk->meta->replaces;
    else if (!strcmp(path, "PISI/Package/Provides")) ++walk->meta->provides;
    else if (!strcmp(path, "PISI/Source/Packager/Name") ||
             !strcmp(path, "PISI/Source/Packager/Email")) ++walk->meta->packager;
    else if (!strcmp(path, "PISI/Package/Description")) ++walk->meta->description;
    else if (!strcmp(path, "PISI/Package/History/Update")) ++walk->meta->history;
    else if (!strcmp(path, "PISI/Files/File")) ++walk->meta->files;
    else if (!container(path)) ++walk->meta->unknown;
    free(value);
    return 1;
}

static int element_text(struct eopkg_walk *walk, const char *data, size_t length)
{
    size_t piece = length, at;
    if (!piece) return 1;
    for (at = 0; at < piece; ++at)
        if (data[at] == '<' || data[at] == '>') {
            /* markup inside a text value is markup this reader does not expand */
            piece = at;
            break;
        }
    if (!piece) return 1;
    {
        char *text = malloc(piece + 1);
        if (!text) return 0;
        memcpy(text, data, piece);
        text[piece] = 0;
        if (!holy_text_add(&walk->body, trimmed(text))) { free(text); return 0; }
        free(text);
    }
    return 1;
}

/* the metadata of one eopkg, read as XML text. a declaration, a comment and a
   processing instruction are skipped, and no entity is expanded because a package
   name, a version and a dependency name never carry one */
static int read_metadata(const char *data, size_t length, struct eopkg_meta *meta)
{
    struct eopkg_walk walk;
    size_t at = 0, line = 1;
    memset(&walk, 0, sizeof walk);
    walk.meta = meta;
    while (at < length) {
        const char *start = memchr(data + at, '<', length - at);
        const char *tag, *end;
        size_t name_length, i;
        if (!start) {
            if (!element_text(&walk, data + at, length - at)) goto fail;
            break;
        }
        if (!element_text(&walk, data + at, (size_t)(start - (data + at)))) goto fail;
        for (i = at; i < (size_t)(start - data); ++i) if (data[i] == '\n') ++line;
        tag = start + 1;
        end = tag + 1;
        while (end < data + length && *end != '>') ++end;
        if (end >= data + length) goto fail;
        if (tag[0] == '?' || tag[0] == '!') {
            at = (size_t)(end - data) + 1;
            continue;
        }
        if (tag[0] == '/') {
            if (!walk.depth || !close_element(&walk)) goto fail;
            --walk.depth;
            at = (size_t)(end - data) + 1;
            continue;
        }
        name_length = 0;
        while (tag + name_length < end && name_character((unsigned char)tag[name_length]))
            ++name_length;
        if (!name_length) goto fail;
        if (walk.depth == EOPKG_DEPTH) goto fail;
        if (name_length >= EOPKG_TAG) goto fail;
        memcpy(walk.path[walk.depth], tag, name_length);
        walk.path[walk.depth][name_length] = 0;
        if (end > tag && end[-1] == '/') {
            /* a self-closing element carries no text, so it opens and closes at once */
            ++walk.depth;
            if (!close_element(&walk)) goto fail;
            --walk.depth;
            at = (size_t)(end - data) + 1;
            continue;
        }
        ++walk.depth;
        holy_text_free(&walk.body);
        walk.body.used = 0;
        free(walk.attribute_name);
        free(walk.attribute_distribution);
        walk.attribute_name = attribute(tag, (size_t)(end - tag), "name");
        walk.attribute_distribution = attribute(tag, (size_t)(end - tag), "releaseFrom");
        walk.line = line;
        at = (size_t)(end - data) + 1;
    }
    /* a document that ends inside an element is not a metadata this reader accepts */
    if (walk.depth) goto fail;
    walk_free(&walk);
    /* Solus states no release of its own, so the native revision starts at one */
    if (!meta->release) meta->release = strdup("1");
    if (!meta->format) meta->format = strdup("1.2");
    return 1;
fail:
    walk_free(&walk);
    return 0;
}

/* the artifact is a ZIP carrying the metadata, the file list and an install tar. the
   metadata is kept as text, the install tar as bytes, and every other member is named
   so the report can say what the conversion dropped rather than losing it silently */
static int read_artifact(const char *snapshot, char *metadata, size_t metadata_size,
                         struct eopkg_parts *parts, char **payload, size_t *payload_length)
{
    struct archive *a = archive_read_new();
    struct archive_entry *entry;
    char buffer[65536];
    FILE *install = NULL;
    size_t install_length = 0;
    int status, result = 1, copied = 0;
    la_ssize_t got;
    *payload = NULL;
    *payload_length = 0;
    if (!a) return 1;
    if (archive_read_support_filter_all(a) != ARCHIVE_OK ||
        archive_read_support_format_all(a) != ARCHIVE_OK ||
        archive_read_open_filename(a, snapshot, 8192) != ARCHIVE_OK) {
        fputs("holypkg: an eopkg is a ZIP carrying metadata.xml and an install tar\n", stderr);
        goto done;
    }
    metadata[0] = 0;
    while ((status = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        const char *name = archive_entry_pathname(entry);
        long long size = archive_entry_size(entry);
        if (++parts->members > 4096) {
            fputs("holypkg: the eopkg carries more members than one conversion reads\n",
                  stderr);
            goto done;
        }
        if (!name || archive_entry_filetype(entry) != AE_IFREG || size < 0 ||
            size > 1024LL * 1024 * 1024) {
            fputs("holypkg: an eopkg carries regular files only\n", stderr);
            goto done;
        }
        if (!strcmp(name, "metadata.xml")) {
            if (parts->metadata || (size_t)size >= metadata_size) {
                fputs("holypkg: the eopkg metadata is missing, repeated or too large\n",
                      stderr);
                goto done;
            }
            parts->metadata = 1;
            copied = 0;
            while ((got = archive_read_data(a, buffer, sizeof buffer)) > 0) {
                size_t used = strlen(metadata);
                if (used + (size_t)got >= metadata_size) {
                    fputs("holypkg: the eopkg metadata is larger than this reader accepts\n",
                          stderr);
                    goto done;
                }
                memcpy(metadata + used, buffer, (size_t)got);
                metadata[used + (size_t)got] = 0;
                copied = 1;
            }
            if (got < 0 || !copied) goto done;
            continue;
        }
        if (!strcmp(name, "files.xml")) { parts->files = 1; continue; }
        if (!strcmp(name, "EOPKG-SETUP") || !strcmp(name, "autopilot") ||
            !strcmp(name, "comar")) { parts->setup = 1; continue; }
        if (!strncmp(name, "delta", 5)) { parts->delta = 1; continue; }
        if (!strncmp(name, "EOPKG-SIGNATURE", 14) || !strncmp(name, "signature", 9) ||
            !strcmp(name, "SHA1SUM")) { parts->signature = 1; continue; }
        if (!strcmp(name, "install.tar") || !strcmp(name, "install.tar.xz") ||
            !strcmp(name, "install.tar.gz") || !strcmp(name, "install")) {
            if (*payload) {
                fputs("holypkg: the eopkg carries more than one install tar\n", stderr);
                goto done;
            }
            parts->install = 1;
            parts->install_xz = strstr(name, ".xz") != NULL;
            install = tmpfile();
            if (!install) goto done;
            while ((got = archive_read_data(a, buffer, sizeof buffer)) > 0) {
                if (fwrite(buffer, 1, (size_t)got, install) != (size_t)got) goto done;
                install_length += (size_t)got;
            }
            if (got < 0) goto done;
            continue;
        }
        /* a member this reader does not model is counted, since a ZIP may also carry a
           source recipe or a delta this manager does not build */
        ++parts->unknown;
    }
    if (status != ARCHIVE_EOF) {
        fputs("holypkg: the eopkg cannot be read as an archive\n", stderr);
        goto done;
    }
    if (!parts->metadata) {
        fputs("holypkg: the eopkg states no metadata.xml\n", stderr);
        goto done;
    }
    if (!install) {
        fputs("holypkg: the eopkg states no install tar\n", stderr);
        goto done;
    }
    /* the length is the one counted while reading, since a stream has no size of its own */
    if (fflush(install) || fseek(install, 0, SEEK_SET)) goto done;
    {
        *payload = malloc(install_length + 1);
        if (!*payload) goto done;
        if (install_length &&
            fread(*payload, 1, install_length, install) != install_length) goto done;
        (*payload)[install_length] = 0;
        *payload_length = install_length;
    }
    fclose(install);
    install = NULL;
    result = 0;
done:
    if (install) fclose(install);
    if (a) archive_read_free(a);
    if (result && *payload) { free(*payload); *payload = NULL; }
    return result;
}

/* the install tar, written beside the capture so libarchive reads the exact bytes */
static char *stage_payload(const char *data, size_t length, const char *capture)
{
    const char *slash = strrchr(capture, '/');
    size_t cut = slash ? (size_t)(slash - capture) + 1 : 0;
    char *path;
    int fd;
    size_t at = 0;
    if (cut > 4096 || length > 1024u * 1024u * 1024u) return NULL;
    path = malloc(cut + 64);
    if (!path) return NULL;
    memcpy(path, capture, cut);
    snprintf(path + cut, 64, ".holy-eopkg-payload-XXXXXX");
    fd = mkstemp(path);
    if (fd < 0) { free(path); return NULL; }
    while (at < length) {
        ssize_t written = write(fd, data + at, length - at);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) { close(fd); unlink(path); free(path); return NULL; }
        at += (size_t)written;
    }
    if (close(fd)) { unlink(path); free(path); return NULL; }
    return path;
}

static int payload_path(const char *private_root, const char *name, char *out, size_t size)
{
    const char *at = name;
    if (!name || !*name) return 0;
    /* a Solus install tar spells its members with a leading ./ , which names the
       same path, so the prefix is dropped rather than kept as a component */
    while (*at == '/' || ((at[0] == '.' || at[0] == '\\') && at[1] == '/')) ++at;
    if (!*at || !strcmp(at, ".") || !strcmp(at, "..")) return 0;
    if ((size_t)snprintf(out, size, "%s/%s", private_root, at) >= size) return 0;
    /* a payload path may not leave the private tree it travels in */
    for (at = out; *at; ++at)
        if (at[0] == '.' && at[1] == '.' && (!at[2] || at[2] == '/')) return 0;
    return 1;
}

/* one install tar member, placed whole under the private path */
static int install_member(struct holy_payload *payload, struct archive *reader,
                          struct archive_entry *entry, const char *private_root,
                          size_t *files, size_t *links, size_t *directories)
{
    unsigned char buffer[65536];
    const char *raw = archive_entry_pathname(entry);
    const char *link = archive_entry_symlink(entry);
    mode_t type = archive_entry_filetype(entry);
    char path[2048];
    unsigned mode = (unsigned)archive_entry_perm(entry);
    la_ssize_t got;
    if (!raw) return 0;
    if (type == AE_IFDIR) {
        if (!payload_path(private_root, raw, path, sizeof path)) return 0;
        *directories += 1;
        return holy_payload_add(payload, path, NULL, mode | 0111, 0, 0, 1);
    }
    if (type == AE_IFLNK) {
        char *absolute;
        if (!link || !*link || !payload_path(private_root, raw, path, sizeof path)) return 0;
        *links += 1;
        absolute = holy_payload_link_target(path + 5, link);
        if (absolute) {
            free(absolute);
            return holy_payload_add(payload, path, link, 0777, 0, 0, 0);
        }
        /* a payload carries no absolute or escaping link, so the path it named becomes
           a recorded requirement instead of a member this manager cannot place */
        ++payload->path_views;
        return 1;
    }
    if (type != AE_IFREG) return 1;
    if (!payload_path(private_root, raw, path, sizeof path)) return 0;
    {
        struct holy_spool_writer writer;
        unsigned char digest[32];
        if (!holy_spool_open(payload, &writer)) return 0;
        for (;;) {
            got = archive_read_data(reader, buffer, sizeof buffer);
            if (got < 0) { holy_spool_close(payload, &writer, digest); return 0; }
            if (!got) break;
            if (!holy_spool_append(payload, &writer, buffer, (size_t)got)) {
                holy_spool_close(payload, &writer, digest);
                return 0;
            }
        }
        if (!holy_spool_close(payload, &writer, digest)) return 0;
        if (!holy_payload_add(payload, path, NULL, mode ? mode : 0644, writer.offset,
                              writer.size, 0)) return 0;
        memcpy(payload->digests[payload->count - 1], digest, sizeof digest);
    }
    *files += 1;
    return 1;
}

/* the whole install tar, read with libarchive and placed under a private path */
static int walk_payload(const char *staged, struct holy_payload *payload,
                        const char *private_root, size_t *files, size_t *links,
                        size_t *directories)
{
    struct archive *a = archive_read_new();
    struct archive_entry *entry;
    int status, result = 1;
    if (!a) return 0;
    if (archive_read_support_filter_all(a) != ARCHIVE_OK ||
        archive_read_support_format_all(a) != ARCHIVE_OK ||
        archive_read_open_filename(a, staged, 8192) != ARCHIVE_OK) {
        archive_read_free(a);
        fputs("holypkg: the install tar cannot be read as an archive\n", stderr);
        return 0;
    }
    while ((status = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        if (archive_entry_size(entry) < 0) goto done;
        if (!install_member(payload, a, entry, private_root, files, links, directories))
            goto done;
    }
    if (status != ARCHIVE_EOF) goto done;
    result = 0;
done:
    archive_read_free(a);
    if (result)
        fputs("holypkg: the install tar holds a path this manager cannot place\n", stderr);
    return !result;
}

static int copy_original(const char *source, int output)
{
    int in = open(source, O_RDONLY | O_CLOEXEC), out = -1, ok = 0;
    unsigned char buffer[65536];
    ssize_t got;
    if (in < 0) return 0;
    out = openat(output, "original", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                 0600);
    if (out < 0) goto done;
    while ((got = read(in, buffer, sizeof buffer)) > 0) {
        size_t at = 0;
        while (at < (size_t)got) {
            ssize_t written = write(out, buffer + at, (size_t)got - at);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) goto done;
            at += (size_t)written;
        }
    }
    ok = got == 0 && !fsync(out) && !fsync(output);
done:
    if (in >= 0) close(in);
    if (out >= 0) close(out);
    return ok;
}

/* the payload of one eopkg: the install tar under a private path, the metadata
   beside it and a report that names everything this conversion dropped */
static int package_eopkg(const char *input, const char *source, const char *output)
{
    struct eopkg_meta meta = {0};
    struct eopkg_parts parts;
    struct holy_payload payload = {0};
    char *metadata = NULL, *staged = NULL, *text[7] = {0}, original[65];
    char *body = NULL, *snapshot = NULL;
    size_t body_length = 0, sizes[7] = {0}, i, data_first;
    size_t files = 0, links = 0, directories = 0;
    FILE *files_out[7] = {0}, *log = NULL;
    char private[600], spool_name[43], artifact[700];
    const char *arch = HOLY_PAYLOAD_NOARCH, *libc = HOLY_PAYLOAD_NOLIBC;
    int fd = -1, output_fd = -1, spool = -1, log_fd = -1, result = 1, published = 0;
    struct stat st;

    memset(&parts, 0, sizeof parts);
    fd = open(input, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        st.st_size > 1024LL * 1024 * 1024) {
        fputs("holypkg: an eopkg is a regular file this manager can read\n", stderr);
        result = 6;
        goto done;
    }
    snapshot = holy_stage_fd(fd, "holy-eopkg");
    if (!snapshot) goto done;
    {
        int copy = open(snapshot, O_RDONLY | O_CLOEXEC);
        int ok = copy >= 0 && digest_fd(copy, original);
        if (copy >= 0) close(copy);
        if (!ok) goto done;
    }
    metadata = malloc(EOPKG_METADATA + 1);
    if (!metadata) goto done;
    if (read_artifact(snapshot, metadata, EOPKG_METADATA, &parts, &body, &body_length)) {
        result = 2;
        goto done;
    }
    if (!digest_bytes(body, body_length, parts.install_digest)) {
        fputs("holypkg: the install tar cannot be digested\n", stderr);
        goto done;
    }
    if (!read_metadata(metadata, strlen(metadata), &meta)) {
        fputs("holypkg: the eopkg metadata is not a document this reader accepts\n", stderr);
        result = 2;
        goto done;
    }
    if (!meta.name || !label(meta.name) || !meta.version || !*meta.version) {
        fputs("holypkg: the eopkg states no package name or version this format can "
              "record\n", stderr);
        result = 2;
        goto done;
    }
    if (!meta.arch) {
        fputs("holypkg: the eopkg states no architecture\n", stderr);
        result = 2;
        goto done;
    }
    if (strcmp(meta.arch, "noarch") && strcmp(meta.arch, "x86_64") && strcmp(meta.arch, "i686") &&
        strcmp(meta.arch, "aarch64") && strcmp(meta.arch, "armv7hl")) {
        fprintf(stderr, "holypkg: the eopkg architecture %s requires classification\n",
                meta.arch);
        result = 3;
        goto done;
    }
    if (mkdir(output, 0700) && errno != EEXIST) {
        fprintf(stderr, "holypkg: conversion directory unavailable: %s\n", output);
        goto done;
    }
    output_fd = open(output, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (output_fd < 0 || !copy_original(snapshot, output_fd)) goto done;
    for (i = 0; i < 7; ++i)
        if (!(files_out[i] = open_memstream(&text[i], &sizes[i]))) goto done;
    spool = holy_spool_at(output_fd, spool_name);
    if (spool < 0) goto done;
    payload.spool = spool;
    payload.uid = (long long)geteuid();
    payload.gid = (long long)getegid();
    if (!holy_payload_add(&payload, "HOLY", NULL, 0755, 0, 0, 1) ||
        !holy_payload_add(&payload, "DATA", NULL, 0755, 0, 0, 1)) goto done;
    data_first = payload.count;
    snprintf(private, sizeof private, "usr/lib/holy/private/%s/eopkg", meta.name);
    staged = stage_payload(body, body_length, input);
    if (!staged) goto done;
    {
        char root[1200];
        snprintf(root, sizeof root, "DATA/%s", private);
        if (!holy_payload_add(&payload, root, NULL, 0755, 0, 0, 1) ||
            !walk_payload(staged, &payload, root, &files, &links, &directories)) goto done;
    }
    payload.unknown = files;
    fputs("format holy-package-1\nname ", files_out[0]); holy_quoted(files_out[0], meta.name);
    fputs("\nversion ", files_out[0]); holy_quoted(files_out[0], meta.version);
    fputs("\nrelease ", files_out[0]); holy_quoted(files_out[0], meta.release);
    fputs("\nos linux\narch ", files_out[0]); holy_quoted(files_out[0], arch);
    fputs("\nlibc ", files_out[0]); holy_quoted(files_out[0], libc);
    fputs("\nx-version-family eopkg\nx-source-family eopkg\nx-converter holy-eopkg-1\n"
          "x-source-arch ", files_out[0]);
    holy_quoted(files_out[0], meta.arch);
    fputs("\nx-eopkg-format ", files_out[0]); holy_quoted(files_out[0], meta.format);
    if (meta.component) {
        fputs("\nx-eopkg-component ", files_out[0]); holy_quoted(files_out[0], meta.component);
    }
    fputc('\n', files_out[0]);
    if (!holy_payload_manifest(files_out[1], &payload, data_first)) goto done;
    for (i = 0; i < meta.depends_count; ++i) {
        char id[96];
        snprintf(id, sizeof id, "eopkg-depend-%zu", i);
        fputs("require ", files_out[2]); holy_quoted(files_out[2], id);
        fputc(' ', files_out[2]); holy_quoted(files_out[2], meta.name);
        fputs(" package ", files_out[2]); holy_quoted(files_out[2], meta.depends[i].name);
        /* a Solus dependency names a distribution release, which is a property of the
           repository rather than of the dependency, so the requirement is exact */
        fputs(" any any any - ", files_out[2]);
        holy_quoted(files_out[2], meta.depends[i].distribution ?
                    meta.depends[i].distribution : "-");
        fputc(' ', files_out[2]); holy_quoted(files_out[2], "eopkg-metadata.xml");
        fputc('\n', files_out[2]);
    }
    for (i = 0; i < payload.needed.count; ++i) {
        const char *soname = holy_names_get(&payload.needed, i);
        char id[96];
        if (holy_names_has(&payload.provided, soname)) continue;
        snprintf(id, sizeof id, "eopkg-soname-%zu", i);
        fputs("require ", files_out[2]); holy_quoted(files_out[2], id);
        fputc(' ', files_out[2]); holy_quoted(files_out[2], meta.name);
        fputs(" soname ", files_out[2]); holy_quoted(files_out[2], soname);
        fprintf(files_out[2], " %s %s any - ", arch, libc);
        holy_quoted(files_out[2], "dt_needed");
        fputc(' ', files_out[2]); holy_quoted(files_out[2], "eopkg-payload");
        fputc('\n', files_out[2]);
    }
    for (i = 0; i < payload.absolute.count; ++i) {
        char id[96];
        snprintf(id, sizeof id, "eopkg-link-%zu", i);
        fputs("require ", files_out[2]); holy_quoted(files_out[2], id);
        fputc(' ', files_out[2]); holy_quoted(files_out[2], meta.name);
        fputs(" file ", files_out[2]); holy_quoted(files_out[2],
                                                    holy_names_get(&payload.absolute, i));
        fputs(" any any any - ", files_out[2]);
        holy_quoted(files_out[2], "symlink_target");
        fputc(' ', files_out[2]); holy_quoted(files_out[2], "eopkg-payload");
        fputc('\n', files_out[2]);
    }
    fputs("provide package ", files_out[3]); holy_quoted(files_out[3], meta.name);
    fprintf(files_out[3], " %s %s - ", arch, libc);
    holy_quoted(files_out[3], "eopkg-package");
    fputc('\n', files_out[3]);
    for (i = 0; i < payload.provided.count; ++i) {
        fputs("provide soname ", files_out[3]);
        holy_quoted(files_out[3], holy_names_get(&payload.provided, i));
        fprintf(files_out[3], " %s %s - ", arch, libc);
        holy_quoted(files_out[3], "eopkg-payload");
        fputc('\n', files_out[3]);
    }
    fputs("format holy-import-origin-1\nfamily eopkg\nsource-name ", files_out[5]);
    holy_quoted(files_out[5], source);
    fputs("\noriginal-sha256 ", files_out[5]); holy_quoted(files_out[5], original);
    fputs("\nverification unverified\nconverter holy-eopkg-1\noriginal-version ", files_out[5]);
    holy_quoted(files_out[5], meta.version);
    fputs("\noriginal-arch ", files_out[5]); holy_quoted(files_out[5], meta.arch);
    fprintf(files_out[5], "\neopkg-format %s\ninstall-sha256 %s\nmode artifact\n",
            meta.format, parts.install_digest);
    if (parts.files) fputs("eopkg-files recorded as a declared file list\n", files_out[5]);
    fputs("format holy-import-transform-1\neopkg the install tar travels whole under a "
          "private path\n", files_out[6]);
    fprintf(files_out[6], "private %s\n", private);
    fprintf(files_out[6], "install-sha256 %s\n", parts.install_digest);
    fputs("system-layout the tar places paths this manager records rather than claims, so "
          "the package owns a private copy\n", files_out[6]);
    fputs("install-script dropped; nothing runs at install and a COMAR object is a lifecycle "
          "ABI this manager does not provide\n", files_out[6]);
    if (parts.delta)
        fputs("delta dropped; a Solus delta is a different payload, not a patch this manager "
              "applies\n", files_out[6]);
    if (parts.signature)
        fputs("signature recorded and not trusted; the artifact is verified by its own "
              "digest only\n", files_out[6]);
    if (ferror(files_out[0]) || ferror(files_out[2]) || ferror(files_out[3]) ||
        ferror(files_out[5]) || ferror(files_out[6])) goto done;
    if (!holy_payload_records(&payload, files_out, text, sizes)) goto done;
    log_fd = openat(output_fd, "package", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
    if (log_fd < 0) goto done;
    log = fdopen(log_fd, "w");
    if (!log) { log_fd = -1; goto done; }
    log_fd = -1;
    fputs("format holy-eopkg-package-1\nconverter holy-eopkg-1\n", log);
    fputs("status review-required\nmode artifact\n", log);
    fprintf(log, "name %s version %s release %s arch %s libc %s\n", meta.name, meta.version,
            meta.release, arch, libc);
    fprintf(log, "original %s sha256 %s format %s\n", input, original, meta.format);
    fprintf(log, "payload %zu files %zu links %zu directories %zu under %s\n", files, files,
            links, directories, private);
    fprintf(log, "install-tar sha256 %s\n", parts.install_digest);
    if (meta.summary) fputs("summary the metadata states one\n", log);
    if (meta.license) fprintf(log, "license %s\n", meta.license);
    if (meta.url) fprintf(log, "url %s\n", meta.url);
    if (meta.component) fprintf(log, "component %s\n", meta.component);
    if (meta.packager) fprintf(log, "packager %zu source identity records; the author of a "
                                    "Solus package grants no trust here\n", meta.packager);
    fprintf(log, "depends %zu; each becomes an exact package requirement the target has to "
                 "satisfy from a source that has it\n", meta.depends_count);
    for (i = 0; i < meta.depends_count; ++i)
        fprintf(log, "dependency %s line %zu%s%s\n", meta.depends[i].name,
                meta.depends[i].line,
                meta.depends[i].distribution ? " releaseFrom " : "",
                meta.depends[i].distribution ? meta.depends[i].distribution : "");
    if (meta.conflicts)
        fprintf(log, "conflicts %zu counted; a Solus conflict is a resolver decision this "
                     "manager does not import\n", meta.conflicts);
    if (meta.replaces)
        fprintf(log, "replaces %zu counted; a Solus replacement is a resolver decision this "
                     "manager does not import\n", meta.replaces);
    if (meta.provides)
        fprintf(log, "provides %zu counted; the SONAMEs the payload itself carries are the "
                     "capabilities recorded\n", meta.provides);
    if (meta.description)
        fputs("description the metadata states one and this manifest has no field for it\n",
              log);
    if (meta.history)
        fprintf(log, "history %zu update records; the build history of a Solus package is not "
                     "a runtime requirement\n", meta.history);
    if (parts.files)
        fputs("file-list the artifact declares one; a declared list is a claim and the "
              "payload manifest is the authority for what the package owns\n", log);
    if (parts.setup)
        fputs("install-script the artifact states one; it is dropped, nothing runs at "
              "install, and a COMAR object is a lifecycle ABI this manager does not "
              "provide\n", log);
    if (parts.delta)
        fputs("delta the artifact states one; it is dropped, since a Solus delta is a "
              "different payload rather than a patch\n", log);
    if (parts.signature)
        fputs("signature the artifact states one; it is recorded and not trusted, and the "
              "artifact is verified by its own digest only\n", log);
    if (parts.unknown)
        fprintf(log, "unknown %zu archive members this reader does not model\n",
                parts.unknown);
    if (parts.members)
        fprintf(log, "artifact %zu members; every one is read, kept or named here\n",
                parts.members);
    if (payload.path_views)
        fprintf(log, "path-views %zu links name an absolute or escaping target; each path it "
                     "named is a recorded file requirement\n", payload.path_views);
    if (ferror(log) || fflush(log) || fsync(fileno(log)) || fclose(log)) { log = NULL; goto done; }
    log = NULL;
    snprintf(artifact, sizeof artifact, "%s--%s--%s.holy", meta.name, arch, libc);
    if (!holy_pack_stream(spool, payload.entries, payload.count, output_fd, artifact))
        goto done;
    published = 1;
    {
        int packed = openat(output_fd, artifact, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        char digest[65];
        if (packed < 0 || !digest_fd(packed, digest)) goto done;
        close(packed);
        printf("imported %s artifact %s arch %s libc %s mode artifact\n", artifact, digest,
               arch, libc);
    }
    result = 0;
done:
    if (log) fclose(log);
    if (log_fd >= 0) close(log_fd);
    for (i = 0; i < 7; ++i) if (files_out[i]) fclose(files_out[i]);
    for (i = 0; i < 7; ++i) free(text[i]);
    holy_payload_free(&payload);
    meta_free(&meta);
    if (staged) { unlink(staged); free(staged); }
    if (spool >= 0) {
        if (!published && spool_name[0]) unlinkat(output_fd, spool_name, 0);
        close(spool);
    }
    if (snapshot) { unlink(snapshot); free(snapshot); }
    if (output_fd >= 0) close(output_fd);
    if (fd >= 0) close(fd);
    free(metadata);
    free(body);
    if (result)
        fputs("holypkg: the eopkg conversion is incomplete; no installed state changed\n",
              stderr);
    return result;
}

int holy_import_eopkg(const char *input, const char *source, const char *output)
{
    size_t i;
    int result;
    if (!source || !*source || !strcmp(source, "local")) return 2;
    for (i = 0; source[i]; ++i)
        if ((unsigned char)source[i] <= 32 || source[i] == ':' || source[i] == '/' ||
            source[i] == '@') return 2;
    if (!input || !output || !*output) {
        fputs("usage: holypkg import PACKAGE.eopkg --source NAME --format eopkg "
              "--output NEW_DIRECTORY\n", stderr);
        return 2;
    }
    result = package_eopkg(input, source, output);
    if (result) return result;
    fputs("holypkg: the package carries a private copy of a Solus layout, runs no install "
          "script and trusts no signature; read the package report before installing it\n",
          stderr);
    return 3;
}
