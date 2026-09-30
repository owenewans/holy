/* one verified foreign artifact becomes a native package; see man/holypkg.8 and
   man/holy-package.5. the artifact is carried whole under a private path because a
   package may hold a file this manager cannot classify, and nothing executes it:
   a PowerShell installer, a Windows shortcut and a Wine runtime all belong to a
   system this one is not, so each of them is dropped with a report line instead of
   being promised. the caller has already read the manifest and decided what it
   means; this code verifies the bytes against the digest the manifest pins and
   writes the package. */
#define _POSIX_C_SOURCE 200809L
#include "artifact.h"
#include "image.h"
#include "pack.h"
#include "stage.h"
#include "../backends/shrecipe.h"

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

/* what the payload carries: the artifact with no program of its own placed */
struct artifact_members {
    size_t files, directories, refused;
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
        for (index = 0; index < 32; ++index)
            snprintf(result + index * 2, 3, "%02x", whole[index]);
        result[64] = 0;
        EVP_MD_CTX_free(context);
        return 1;
    }
    EVP_MD_CTX_free(context);
    return 0;
}

static int is_literal(const char *value)
{
    return value && *value && !strpbrk(value, "$`\\\"'");
}

char *holy_artifact_digest(const char *value)
{
    char *lower;
    size_t i;
    if (!value || strlen(value) != 64) return NULL;
    for (i = 0; i < 64; ++i)
        if (!isxdigit((unsigned char)value[i])) return NULL;
    lower = malloc(65);
    if (!lower) return NULL;
    for (i = 0; i < 64; ++i)
        lower[i] = (char)tolower((unsigned char)value[i]);
    lower[64] = 0;
    return lower;
}

char *holy_artifact_beside(const char *input, const char *url)
{
    const char *at, *stop, *slash;
    size_t length, cut;
    char *name, *beside;
    if (!url || !is_literal(url)) return NULL;
    stop = url + strlen(url);
    while (stop > url && stop[-1] == '/') --stop;
    for (at = stop; at > url && at[-1] != '/' && at[-1] != '\\'; --at) continue;
    length = (size_t)(stop - at);
    if (!length || length > 200) return NULL;
    /* the artifact sits beside the manifest, so the directory part is kept and the
       file name replaces the manifest name */
    slash = strrchr(input, '/');
    cut = slash ? (size_t)(slash - input) + 1 : 0;
    if (cut + length + 1 > 4096) return NULL;
    name = malloc(length + 1);
    beside = malloc(cut + length + 2);
    if (!name || !beside) { free(name); free(beside); return NULL; }
    memcpy(name, at, length);
    name[length] = 0;
    if (strchr(name, '*') || !strcmp(name, ".") || !strcmp(name, "..")) {
        free(name);
        free(beside);
        return NULL;
    }
    memcpy(beside, input, cut);
    memcpy(beside + cut, name, length + 1);
    free(name);
    return beside;
}

static int copy_original(const char *source, int output)
{
    unsigned char buffer[65536];
    int in = open(source, O_RDONLY | O_CLOEXEC), out = -1, ok = 0;
    ssize_t got;
    if (in < 0) goto done;
    out = openat(output, "original", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (out < 0) goto done;
    while ((got = read(in, buffer, sizeof buffer)) > 0) {
        size_t at = 0;
        while (at < (size_t)got) {
            ssize_t n = write(out, buffer + at, (size_t)got - at);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) goto done;
            at += (size_t)n;
        }
    }
    ok = got == 0 && !fsync(out) && !fsync(output);
done:
    if (in >= 0) close(in);
    if (out >= 0) close(out);
    return ok;
}

/* one payload path, refused when it would leave the private tree */
static char *payload_path(const char *private_path, const char *name)
{
    char *path;
    const char *at;
    if (!name || !*name || name[0] == '/') return NULL;
    for (at = name; *at; ++at)
        if (at[0] == '.' && at[1] == '.' && (!at[2] || at[2] == '/')) return NULL;
    if (strchr(name, '\\') || strlen(name) > 900) return NULL;
    path = malloc(strlen(private_path) + strlen(name) + 2);
    if (!path) return NULL;
    sprintf(path, "%s/%s", private_path, name);
    return path;
}

/* one archive member, streamed into the spool under the directory the manifest
   states as the root of every entry */
static int spool_member(struct holy_payload *payload, struct archive *reader,
                        struct archive_entry *entry, const char *private_path,
                        const char *directory, struct artifact_members *members)
{
    unsigned char buffer[65536], digest[32];
    struct holy_spool_writer writer;
    const char *raw = archive_entry_pathname(entry);
    const char *rest = raw;
    char *composed = NULL, *path;
    unsigned mode = (unsigned)archive_entry_perm(entry);
    int ok = 0;
    if (directory) {
        /* the manifest places every entry under one directory, so the first
           component of the archive path is replaced by it */
        const char *slash = strchr(raw, '/');
        if (!slash) {
            ++members->refused;
            return 1;
        }
        while (*++slash == '/') continue;
        if (!*slash) {
            ++members->refused;
            return 1;
        }
        composed = malloc(strlen(directory) + strlen(slash) + 2);
        if (!composed) return 0;
        if ((size_t)snprintf(composed, strlen(directory) + strlen(slash) + 2, "%s/%s",
                             directory, slash) >= strlen(directory) + strlen(slash) + 2) {
            free(composed);
            composed = NULL;
            ++members->refused;
            return 1;
        }
        rest = composed;
    }
    if (!mode) mode = 0644;
    path = payload_path(private_path, rest);
    if (!path) return 0;
    if (archive_entry_filetype(entry) == AE_IFDIR) {
        if (!holy_payload_add(payload, path, NULL, mode | 0111, 0, 0, 1)) goto done;
        ++members->directories;
        ok = 1;
        goto done;
    }
    if (archive_entry_filetype(entry) != AE_IFREG) {
        ++members->refused;
        ok = 1;
        goto done;
    }
    if (!holy_spool_open(payload, &writer)) goto done;
    for (;;) {
        ssize_t got = archive_read_data(reader, buffer, sizeof buffer);
        if (got < 0) goto close_writer;
        if (!got) break;
        if (!holy_spool_append(payload, &writer, buffer, (size_t)got)) goto close_writer;
    }
    if (!holy_spool_close(payload, &writer, digest)) goto done;
    if (!holy_payload_add(payload, path, NULL, mode, writer.offset, writer.size, 0)) goto done;
    memcpy(payload->digests[payload->count - 1], digest, sizeof digest);
    ++members->files;
    ok = 1;
    goto done;
close_writer:
    holy_spool_close(payload, &writer, digest);
done:
    free(composed);
    free(path);
    return ok;
}

/* every dependency name of a manifest list, with the version each pins dropped */
static size_t dependencies(const char *list, char names[][256], size_t limit)
{
    size_t count = 0, at = 0;
    while (list[at] && count < limit) {
        size_t used = 0, cut, length = 0;
        char name[256];
        while (list[at] == ' ' || list[at] == '\t' || list[at] == ',' || list[at] == '\n') ++at;
        while (list[at + used] && list[at + used] != ' ' && list[at + used] != '\t' &&
               list[at + used] != ',' && list[at + used] != '\n') ++used;
        /* a bucket writes name/version or name@version, and a version is not a
           package name */
        cut = used;
        while (cut && list[at + cut - 1] != '/' && list[at + cut - 1] != '@') --cut;
        while (length < cut && length + 1 < sizeof name) {
            char c = list[at + length];
            if (!isalnum((unsigned char)c) && c != '.' && c != '_' && c != '-' && c != '+')
                break;
            name[length] = c;
            ++length;
        }
        name[length] = 0;
        if (length) {
            memcpy(names[count], name, length + 1);
            ++count;
        }
        at += used;
    }
    return count;
}

int holy_artifact_package(const char *input, const char *source, const char *output,
                          const struct holy_artifact *fields)
{
    struct holy_payload payload = {0};
    struct artifact_members members = {0};
    struct archive *reader = NULL;
    char *text[7] = {0}, *beside = NULL, *hash = NULL;
    size_t sizes[7] = {0}, i, data_first, count = 0;
    char depends[64][256];
    FILE *files[7] = {0}, *log = NULL;
    char artifact[700], private[600], payload_root[700], program[900];
    char declared[65], spool_name[43];
    const char *arch = HOLY_PAYLOAD_NOARCH, *libc = HOLY_PAYLOAD_NOLIBC;
    int dir = -1, spool = -1, log_fd = -1, result = 1, published = 0, program_found = 0;

    beside = holy_artifact_beside(input, fields->url);
    if (!beside) {
        fputs("holypkg: the artifact URL names no file\n", stderr);
        result = 2;
        goto done;
    }
    hash = holy_artifact_digest(fields->hash);
    if (!hash) {
        fputs("holypkg: a manifest needs a sha256 digest for its artifact\n", stderr);
        result = 2;
        goto done;
    }
    if (mkdir(output, 0700) && errno != EEXIST) {
        fprintf(stderr, "holypkg: conversion directory unavailable: %s\n", output);
        goto done;
    }
    dir = open(output, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) {
        fprintf(stderr, "holypkg: conversion directory unavailable: %s\n", output);
        goto done;
    }
    /* the artifact has to be here: nothing may run to fetch and unpack it */
    {
        int artifact_fd = open(beside, O_RDONLY | O_CLOEXEC);
        if (artifact_fd < 0) {
            const char *slash = strrchr(beside, '/');
            fprintf(stderr, "holypkg: the artifact %s is not beside the manifest\n",
                    slash ? slash + 1 : beside);
            result = 6;
            goto done;
        }
        if (!digest_fd(artifact_fd, declared)) { close(artifact_fd); goto done; }
        close(artifact_fd);
        if (strcmp(declared, hash)) {
            const char *slash = strrchr(beside, '/');
            fprintf(stderr, "holypkg: the artifact %s has the digest %s and the manifest pins "
                            "%s\n", slash ? slash + 1 : beside, declared, hash);
            result = 6;
            goto done;
        }
    }
    if (!copy_original(input, dir)) goto done;

    for (i = 0; i < 7; ++i)
        if (!(files[i] = open_memstream(&text[i], &sizes[i]))) goto done;
    spool = holy_spool_at(dir, spool_name);
    if (spool < 0) goto done;
    payload.spool = spool;
    payload.uid = (long long)geteuid();
    payload.gid = (long long)getegid();
    if (!holy_payload_add(&payload, "HOLY", NULL, 0755, 0, 0, 1) ||
        !holy_payload_add(&payload, "DATA", NULL, 0755, 0, 0, 1)) goto done;
    data_first = payload.count;
    snprintf(private, sizeof private, "usr/lib/holy/private/%s", fields->name);
    snprintf(payload_root, sizeof payload_root, "DATA/%s", private);
    if (!holy_payload_add(&payload, payload_root, NULL, 0755, 0, 0, 1)) goto done;

    /* an archive libarchive reads has its members placed under the directory the
       manifest states, and any other artifact travels as one file */
    reader = archive_read_new();
    if (reader &&
        archive_read_support_filter_all(reader) == ARCHIVE_OK &&
        archive_read_support_format_all(reader) == ARCHIVE_OK &&
        archive_read_open_filename(reader, beside, 8192) == ARCHIVE_OK) {
        struct archive_entry *entry;
        int status;
        while ((status = archive_read_next_header(reader, &entry)) == ARCHIVE_OK) {
            if (!archive_entry_pathname(entry)) continue;
            if (!spool_member(&payload, reader, entry, payload_root, fields->directory,
                              &members)) {
                fputs("holypkg: the artifact holds a path this manager cannot place\n", stderr);
                result = 3;
                goto done;
            }
        }
        if (status != ARCHIVE_EOF) {
            fputs("holypkg: the artifact cannot be read as an archive\n", stderr);
            result = 6;
            goto done;
        }
        archive_read_free(reader);
        reader = NULL;
        if (!members.files) {
            fputs("holypkg: the artifact holds no file this manager can place\n", stderr);
            result = 3;
            goto done;
        }
    } else {
        const char *base = strrchr(beside, '/');
        unsigned char digest[32];
        long long offset, size;
        char *held;
        int artifact_fd;
        if (reader) {
            archive_read_free(reader);
            reader = NULL;
        }
        held = payload_path(payload_root, base ? base + 1 : beside);
        if (!held) goto done;
        artifact_fd = open(beside, O_RDONLY | O_CLOEXEC);
        if (artifact_fd < 0) { free(held); goto done; }
        if (!holy_payload_spool_file(&payload, artifact_fd, &offset, &size, digest)) {
            close(artifact_fd);
            free(held);
            goto done;
        }
        close(artifact_fd);
        if (!holy_payload_add(&payload, held, NULL, 0600, offset, size, 0)) {
            free(held);
            goto done;
        }
        memcpy(payload.digests[payload.count - 1], digest, sizeof digest);
        ++members.files;
        free(held);
    }
    /* the payload holds files this manager cannot classify, since a program for
       another operating system is neither an ELF nor a script */
    payload.unknown = members.files;

    /* the program the manifest states, and where the payload carries it */
    if (fields->program && is_literal(fields->program) && !strchr(fields->program, '\\')) {
        size_t length = strlen(fields->program);
        for (i = 0; i < payload.count; ++i) {
            const char *held = payload.entries[i].path;
            size_t base = strlen(held);
            if (base <= length || held[base - length - 1] != '/' ||
                strcmp(held + base - length, fields->program)) continue;
            if (snprintf(program, sizeof program, "/%s", held + strlen("DATA")) >=
                (int)sizeof program) {
                fputs("holypkg: the program path is too long to record\n", stderr);
                result = 3;
                goto done;
            }
            program_found = 1;
            break;
        }
    }

    fputs("format holy-package-1\nname ", files[0]); holy_quoted(files[0], fields->name);
    fputs("\nversion ", files[0]); holy_quoted(files[0], fields->version);
    fputs("\nrelease 1\nos linux\narch ", files[0]); holy_quoted(files[0], arch);
    fputs("\nlibc ", files[0]); holy_quoted(files[0], libc);
    fputs("\nx-version-family ", files[0]); holy_quoted(files[0], fields->family);
    fputs("\nx-source-family ", files[0]); holy_quoted(files[0], fields->family);
    fputs("\nx-converter ", files[0]); holy_quoted(files[0], fields->converter);
    fputs("\nx-artifact-url ", files[0]); holy_quoted(files[0], fields->url);
    fputs("\nx-artifact-sha256 ", files[0]); holy_quoted(files[0], hash);
    if (fields->directory) {
        fputs("\nx-extract-dir ", files[0]); holy_quoted(files[0], fields->directory);
    }
    if (fields->program) {
        fputs("\nx-manifest-program ", files[0]); holy_quoted(files[0], fields->program);
    }
    if (program_found) {
        fputs("\nx-program-path ", files[0]); holy_quoted(files[0], program);
    }
    if (!holy_payload_manifest(files[1], &payload, data_first)) goto done;

    if (fields->depends && is_literal(fields->depends))
        count = dependencies(fields->depends, depends, 64);
    for (i = 0; i < count; ++i) {
        char identifier[64];
        snprintf(identifier, sizeof identifier, "%s-depend-%zu", fields->family, i);
        fputs("require ", files[2]); holy_token(files[2], identifier);
        fputc(' ', files[2]); holy_quoted(files[2], fields->name);
        fputs(" package ", files[2]); holy_quoted(files[2], depends[i]);
        fprintf(files[2], " %s %s any - ", arch, libc);
        holy_quoted(files[2], "artifact-dependency");
        fputc(' ', files[2]); holy_quoted(files[2], "artifact-manifest");
        fputc('\n', files[2]);
    }
    fputs("provide package ", files[3]);
    holy_quoted(files[3], fields->name);
    fprintf(files[3], " %s %s - ", arch, libc);
    holy_quoted(files[3], "artifact-manifest");
    fputc('\n', files[3]);
    /* no hook runs at install: a converted artifact is not executed */
    fputs("format holy-import-origin-1\nfamily ", files[5]);
    holy_quoted(files[5], fields->family);
    fputs("\nsource-name ", files[5]); holy_quoted(files[5], source);
    fputs("\noriginal-sha256 ", files[5]); holy_quoted(files[5], declared);
    fputs("\nverification local-artifact\nconverter ", files[5]);
    holy_quoted(files[5], fields->converter);
    fputs("\noriginal-version ", files[5]); holy_quoted(files[5], fields->version);
    fprintf(files[5], "\nartifact-url %s\nartifact-sha256 %s\nmode artifact\n", fields->url, hash);
    fputs("format holy-import-transform-1\nartifact carried whole under a private path\n",
          files[6]);
    fprintf(files[6], "private %s\n", private);
    if (fields->directory) fprintf(files[6], "extract-dir %s\n", fields->directory);
    if (fields->program) fprintf(files[6], "program %s declared by the manifest\n",
                                 fields->program);
    if (program_found) fprintf(files[6], "program-path %s\n", program);
    fputs("installer dropped; nothing is executed and no Wine requirement is invented\n",
          files[6]);
    if (!holy_payload_records(&payload, files, text, sizes)) goto done;

    log_fd = openat(dir, "package", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (log_fd < 0) goto done;
    log = fdopen(log_fd, "w");
    if (!log) { log_fd = -1; goto done; }
    log_fd = -1;
    {
        char header[128];
        snprintf(header, sizeof header, "format holy-%s-package-1\nconverter %s\n",
                 fields->family, fields->converter);
        fputs(header, log);
    }
    fputs("status review-required\nmode artifact\n", log);
    fprintf(log, "name %s version %s arch %s libc %s\n", fields->name, fields->version, arch,
            libc);
    if (fields->summary && is_literal(fields->summary) && *fields->summary)
        fprintf(log, "description carried\n");
    if (fields->homepage && is_literal(fields->homepage) && strstr(fields->homepage, "://"))
        fprintf(log, "homepage %s\n", fields->homepage);
    if (fields->license && is_literal(fields->license) && *fields->license)
        fprintf(log, "license %s\n", fields->license);
    fprintf(log, "artifact %s\n", fields->url);
    fprintf(log, "artifact-sha256 %s verified against the digest the manifest pins\n", hash);
    fprintf(log, "artifact-placed the payload carries %zu files under %s\n", members.files,
            private);
    if (fields->directory)
        fprintf(log, "extract-dir %s is the directory the manifest places the program in\n",
                fields->directory);
    if (fields->program)
        fprintf(log, "program %s %s\n", fields->program, program_found ?
                "is in the payload at the path HOLY/meta records" :
                "is not in the artifact, so no program path is recorded");
    fprintf(log, "execution nothing runs the artifact; a package cannot promise a Wine\n"
                 "runtime, so no such requirement is recorded\n");
    if (count)
        fprintf(log, "depends %zu %s; each becomes a requirement a target\n"
                     "has to satisfy from a source that has it\n", count,
                fields->dependency_note ? fields->dependency_note : "applications");
    if (fields->installers)
        fprintf(log, "installer %zu PowerShell installer keys are dropped; nothing is executed\n"
                     "and nothing runs at install\n", fields->installers);
    if (fields->integrations)
        fprintf(log, "integration %zu Windows integration keys are dropped; a PATH entry, an\n"
                     "environment variable, a persisted directory and a shortcut belong to a\n"
                     "Windows installation\n", fields->integrations);
    if (fields->updates)
        fprintf(log, "update %zu keys that check or rewrite the upstream version belong to a\n"
                     "%s, and a Holy source owns its own index\n", fields->updates,
                fields->catalog ? fields->catalog : "catalog");
    if (fields->unknown_keys)
        fprintf(log, "unknown %zu manifest keys this importer does not model\n",
                fields->unknown_keys);
    if (members.refused)
        fprintf(log, "refused %zu archive members of a kind or a path a payload does not "
                     "carry\n", members.refused);
    fprintf(log, "payload entries %zu directories %zu\n", payload.count, members.directories);
    if (fflush(log) || fsync(fileno(log)) || fclose(log)) { log = NULL; goto done; }
    log = NULL;
    snprintf(artifact, sizeof artifact, "%s--%s--%s.holy", fields->name, arch, libc);
    if (!holy_pack_stream(spool, payload.entries, payload.count, dir, artifact)) goto done;
    published = 1;
    {
        int packed = openat(dir, artifact, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        char packed_digest[65];
        if (packed < 0 || !digest_fd(packed, packed_digest)) {
            if (packed >= 0) close(packed);
            goto done;
        }
        close(packed);
        printf("imported %s artifact ", artifact);
        holy_quoted(stdout, packed_digest);
        printf(" arch %s libc %s mode artifact\n", arch, libc);
    }
    result = 0;
done:
    if (log) fclose(log);
    if (log_fd >= 0) close(log_fd);
    for (i = 0; i < 7; ++i) if (files[i]) fclose(files[i]);
    for (i = 0; i < 7; ++i) free(text[i]);
    holy_payload_free(&payload);
    if (reader) archive_read_free(reader);
    free(beside);
    free(hash);
    if (spool >= 0) {
        if (!published && spool_name[0]) unlinkat(dir, spool_name, 0);
        close(spool);
    }
    if (dir >= 0) close(dir);
    return result;
}
