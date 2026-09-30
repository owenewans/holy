/* a Scoop manifest to a native package conversion; see man/holypkg.8 and
   man/holy-package.5. a manifest names an artifact with a URL and a SHA-256 and
   asks PowerShell to place it, so the artifact beside the manifest is verified
   against the digest the manifest pins and carried whole under a private path,
   the directory and the program the manifest states are recorded, and every
   installer or integration step is dropped with a report line. nothing runs, and
   no Wine requirement is invented, since a package cannot promise a runtime this
   manager does not provide. */
#define _POSIX_C_SOURCE 200809L
#include "scoop.h"
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
struct scoop_members {
    size_t files, directories, refused, unknown_bytes;
};

/* the manifest keys this importer reads */
static const char *const carried[] = {
    "version", "description", "homepage", "license", "url", "hash", "extract_dir", "bin",
    "depends", NULL
};

/* the keys that ask Windows for an install, an environment or a shortcut */
static const char *const installer_keys[] = {
    "installer", "pre_install", "post_install", "uninstaller", NULL
};

static const char *const integration_keys[] = {
    "env_add_path", "env_set", "persist", "shortcuts", "psmodule", "suggest", NULL
};

/* the keys that belong to a bucket, which owns its own index */
static const char *const update_keys[] = {
    "checkver", "autoupdate", NULL
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
        if (got < 0) break;
        if (!got) break;
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

static int is_label(const char *value)
{
    size_t at;
    if (!value || !*value) return 0;
    for (at = 0; value[at]; ++at)
        if (!isalnum((unsigned char)value[at]) &&
            !(value[at] == '.' || value[at] == '_' || value[at] == '+' || value[at] == '-'))
            return 0;
    return 1;
}

/* the manifest states no shell, so a value that asks one is refused */
static int is_literal(const char *value)
{
    return value && *value && !strpbrk(value, "$`\\\"'");
}

static int hex_digest(const char *value)
{
    size_t i;
    if (!value || strlen(value) != 64) return 0;
    for (i = 0; i < 64; ++i)
        if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f')))
            return 0;
    return 1;
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

/* the file the manifest calls its artifact: the last component of its URL */
static char *artifact_name(const char *url)
{
    const char *at, *stop;
    size_t length;
    char *name;
    if (!url) return NULL;
    stop = url + strlen(url);
    while (stop > url && stop[-1] == '/') --stop;
    for (at = stop; at > url && at[-1] != '/' && at[-1] != '\\'; --at) continue;
    length = (size_t)(stop - at);
    if (!length || length > 200) return NULL;
    name = malloc(length + 1);
    if (!name) return NULL;
    memcpy(name, at, length);
    name[length] = 0;
    if (!is_literal(name) || strchr(name, '*') || !strcmp(name, ".") || !strcmp(name, "..")) {
        free(name);
        return NULL;
    }
    return name;
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
                        const char *extract_dir, struct scoop_members *members)
{
    unsigned char buffer[65536], digest[32];
    struct holy_spool_writer writer;
    const char *raw = archive_entry_pathname(entry);
    const char *rest = raw;
    char *composed = NULL, *path;
    unsigned mode = (unsigned)archive_entry_perm(entry);
    int ok = 0;
    if (extract_dir) {
        /* the manifest places every entry under one directory, so the first
           component of the archive path is replaced by it */
        const char *slash = strchr(raw, '/');
        if (!slash) {
            ++members->refused;
            return 1;
        }
        if (!*slash) {
            ++members->refused;
            return 1;
        }
        while (*++slash == '/') continue;
        if (!*slash) {
            ++members->refused;
            return 1;
        }
        composed = malloc(strlen(extract_dir) + strlen(slash) + 2);
        if (!composed) return 0;
        if ((size_t)snprintf(composed, strlen(extract_dir) + strlen(slash) + 2, "%s/%s",
                             extract_dir, slash) >= strlen(extract_dir) + strlen(slash) + 2) {
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
        if (got < 0) { holy_spool_close(payload, &writer, digest); goto done; }
        if (!got) break;
        if (!holy_spool_append(payload, &writer, buffer, (size_t)got)) {
            holy_spool_close(payload, &writer, digest);
            goto done;
        }
    }
    if (!holy_spool_close(payload, &writer, digest)) goto done;
    if (!holy_payload_add(payload, path, NULL, mode, writer.offset, writer.size, 0)) goto done;
    memcpy(payload->digests[payload->count - 1], digest, sizeof digest);
    ++members->files;
    ok = 1;
done:
    free(composed);
    free(path);
    return ok;
}

/* the dependency names of a manifest list, with the version each pins dropped */
static size_t dependencies(const char *list, char names[][256], size_t limit)
{
    size_t count = 0, at = 0;
    while (list[at] && count < limit) {
        size_t used = 0, cut;
        while (list[at] == ' ' || list[at] == '\t' || list[at] == ',' || list[at] == '\n') ++at;
        while (list[at + used] && list[at + used] != ' ' && list[at + used] != '\t' &&
               list[at + used] != ',' && list[at + used] != '\n') ++used;
        /* a bucket writes name/version or name@version, and the version is not a
           package name */
        cut = used;
        while (cut && list[at + cut - 1] != '/' && list[at + cut - 1] != '@') --cut;
        if (cut) {
            char name[256];
            size_t length = 0;
            while (length < cut && length + 1 < sizeof name) {
                char c = list[at + length];
                if (!isalnum((unsigned char)c) && c != '.' && c != '_' && c != '-' && c != '+')
                    break;
                name[length] = c;
                ++length;
            }
            name[length] = 0;
            if (length && is_label(name)) {
                memcpy(names[count], name, length + 1);
                ++count;
            }
        }
        at += used;
    }
    return count;
}

static int scoop_import(const char *input, const char *source, const char *output)
{
    struct holy_json_value *manifest = NULL;
    struct holy_payload payload = {0};
    struct scoop_members members = {0};
    struct archive *reader = NULL;
    char *text[7] = {0};
    size_t sizes[7] = {0}, i, data_first, count = 0;
    char depends[64][256];
    FILE *files[7] = {0}, *log = NULL;
    char name[256], version[256], artifact[700], private[600], payload_root[700];
    char program[900], declared[65], spool_name[43], beside[900];
    const char *url, *hash, *summary, *homepage, *license, *extract_dir, *bin, *depends_text;
    const char *arch = HOLY_PAYLOAD_NOARCH, *libc = HOLY_PAYLOAD_NOLIBC;
    int dir = -1, spool = -1, log_fd = -1, read_status = 0, result = 1, published = 0;
    size_t unknown = 0, installers = 0, integrations = 0, updates = 0;
    int program_found = 0;

    if (!source || !*source || !strcmp(source, "local")) return 2;
    for (i = 0; source[i]; ++i)
        if ((unsigned char)source[i] <= 32 || source[i] == ':' || source[i] == '/' ||
            source[i] == '@') return 2;
    if (!input || !output || !*output) {
        fputs("usage: holypkg import NAME.json --source NAME --format scoop "
              "--output NEW_DIRECTORY\n", stderr);
        return 2;
    }
    manifest = holy_json_read(input, &read_status);
    if (!manifest) {
        if (read_status == 6) fprintf(stderr, "holypkg: manifest unavailable: %s\n", input);
        else
            fputs("holypkg: a Scoop manifest is JSON text, and this importer reads no other "
                  "form\n", stderr);
        return read_status;
    }
    if (manifest->kind != HOLY_JSON_OBJECT) {
        fputs("holypkg: a Scoop manifest is a JSON object\n", stderr);
        result = 2;
        goto done;
    }
    /* a bucket names an app by the file its manifest lives in */
    {
        const char *base = strrchr(input, '/');
        const char *dot;
        size_t length;
        base = base ? base + 1 : input;
        dot = strrchr(base, '.');
        length = dot ? (size_t)(dot - base) : strlen(base);
        if (!length || length >= sizeof name) {
            fputs("holypkg: the manifest file name is not a package name\n", stderr);
            result = 2;
            goto done;
        }
        memcpy(name, base, length);
        name[length] = 0;
    }
    if (!is_label(name)) {
        fputs("holypkg: the manifest file name is not a package name\n", stderr);
        result = 2;
        goto done;
    }
    {
        const char *text_version = holy_json_text(holy_json_get(manifest, "version"));
        if (!text_version || !is_label(text_version)) {
            fputs("holypkg: a Scoop manifest needs a literal version\n", stderr);
            result = 2;
            goto done;
        }
        snprintf(version, sizeof version, "%s", text_version);
    }
    url = holy_json_text(holy_json_get(manifest, "url"));
    hash = holy_json_text(holy_json_get(manifest, "hash"));
    if (!url || !is_literal(url) || !strstr(url, "://")) {
        fputs("holypkg: a Scoop manifest needs an artifact URL\n", stderr);
        result = 2;
        goto done;
    }
    if (!hex_digest(hash)) {
        fputs("holypkg: a Scoop manifest needs a sha256 digest for its artifact\n", stderr);
        result = 2;
        goto done;
    }
    extract_dir = holy_json_text(holy_json_get(manifest, "extract_dir"));
    if (holy_json_get(manifest, "extract_dir") && !extract_dir) {
        fputs("holypkg: a Scoop extract_dir list names several programs, which this importer "
              "cannot place\n", stderr);
        result = 3;
        goto done;
    }
    if (extract_dir && (!is_literal(extract_dir) || strchr(extract_dir, '/'))) {
        fputs("holypkg: a Scoop extract_dir is one directory name\n", stderr);
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
        char *file = artifact_name(url);
        size_t at;
        int artifact_fd;
        if (!file) {
            fputs("holypkg: the artifact URL names no file\n", stderr);
            result = 2;
            goto done;
        }
        at = (size_t)snprintf(beside, sizeof beside, "%s", input);
        if (at >= sizeof beside) { free(file); goto done; }
        while (at > 0 && beside[at - 1] != '/') --at;
        if (snprintf(beside + at, sizeof beside - at, "%s", file) >= (int)(sizeof beside - at)) {
            free(file);
            goto done;
        }
        artifact_fd = open(beside, O_RDONLY | O_CLOEXEC);
        if (artifact_fd < 0) {
            fprintf(stderr, "holypkg: the artifact %s is not beside the manifest\n", file);
            free(file);
            result = 6;
            goto done;
        }
        if (!digest_fd(artifact_fd, declared)) { close(artifact_fd); free(file); goto done; }
        close(artifact_fd);
        if (strcmp(declared, hash)) {
            fprintf(stderr, "holypkg: the artifact %s has the digest %s and the manifest pins "
                            "%s\n", file, declared, hash);
            free(file);
            result = 6;
            goto done;
        }
        free(file);
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
    snprintf(private, sizeof private, "usr/lib/holy/private/%s", name);
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
            if (!spool_member(&payload, reader, entry, payload_root, extract_dir, &members)) {
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
        char *file = artifact_name(url);
        char *held;
        unsigned char digest[32];
        long long offset, size;
        int artifact_fd;
        if (reader) {
            archive_read_free(reader);
            reader = NULL;
        }
        if (!file) goto done;
        held = payload_path(payload_root, file);
        free(file);
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
    bin = holy_json_text(holy_json_get(manifest, "bin"));
    if (bin && is_literal(bin) && !strchr(bin, '\\')) {
        size_t length = strlen(bin);
        for (i = 0; i < payload.count; ++i) {
            const char *held = payload.entries[i].path;
            size_t base = strlen(held);
            if (base <= length || held[base - length - 1] != '/' ||
                strcmp(held + base - length, bin)) continue;
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

    fputs("format holy-package-1\nname ", files[0]); holy_quoted(files[0], name);
    fputs("\nversion ", files[0]); holy_quoted(files[0], version);
    fputs("\nrelease 1\nos linux\narch ", files[0]); holy_quoted(files[0], arch);
    fputs("\nlibc ", files[0]); holy_quoted(files[0], libc);
    fputs("\nx-version-family scoop\nx-source-family scoop\nx-converter holy-scoop-1\n"
          "x-artifact-url ", files[0]);
    holy_quoted(files[0], url);
    fputs("\nx-artifact-sha256 ", files[0]); holy_quoted(files[0], hash);
    if (extract_dir) {
        fputs("\nx-scoop-extract-dir ", files[0]); holy_quoted(files[0], extract_dir);
    }
    if (bin) {
        fputs("\nx-scoop-bin ", files[0]); holy_quoted(files[0], bin);
    }
    if (program_found) {
        fputs("\nx-scoop-program ", files[0]); holy_quoted(files[0], program);
    }
    if (!holy_payload_manifest(files[1], &payload, data_first)) goto done;

    depends_text = holy_json_text(holy_json_get(manifest, "depends"));
    if (depends_text && is_literal(depends_text))
        count = dependencies(depends_text, depends, 64);
    for (i = 0; i < count; ++i) {
        char identifier[64];
        snprintf(identifier, sizeof identifier, "scoop-depend-%zu", i);
        fputs("require ", files[2]); holy_token(files[2], identifier);
        fputc(' ', files[2]); holy_quoted(files[2], name);
        fputs(" package ", files[2]); holy_quoted(files[2], depends[i]);
        fprintf(files[2], " %s %s any - ", arch, libc);
        holy_quoted(files[2], "scoop-depends");
        fputc(' ', files[2]); holy_quoted(files[2], "scoop-manifest");
        fputc('\n', files[2]);
    }
    fputs("provide package ", files[3]);
    holy_quoted(files[3], name);
    fprintf(files[3], " %s %s - ", arch, libc);
    holy_quoted(files[3], "scoop-manifest");
    fputc('\n', files[3]);
    /* no hook runs at install: a converted artifact is not executed */
    fputs("format holy-import-origin-1\nfamily scoop\nsource-name ", files[5]);
    holy_quoted(files[5], source);
    fputs("\noriginal-sha256 ", files[5]); holy_quoted(files[5], declared);
    fputs("\nverification local-artifact\nconverter holy-scoop-1\noriginal-version ",
          files[5]);
    holy_quoted(files[5], version);
    fprintf(files[5], "\nartifact-url %s\nartifact-sha256 %s\nmode artifact\n", url, hash);
    fputs("format holy-import-transform-1\nartifact carried whole under a private path\n",
          files[6]);
    fprintf(files[6], "private %s\n", private);
    if (extract_dir) fprintf(files[6], "extract-dir %s\n", extract_dir);
    if (bin) fprintf(files[6], "program %s declared by the manifest\n", bin);
    if (program_found) fprintf(files[6], "program-path %s\n", program);
    fputs("installer dropped; nothing is executed and no Wine requirement is invented\n",
          files[6]);
    if (!holy_payload_records(&payload, files, text, sizes)) goto done;

    summary = holy_json_text(holy_json_get(manifest, "description"));
    homepage = holy_json_text(holy_json_get(manifest, "homepage"));
    license = holy_json_text(holy_json_get(manifest, "license"));
    for (i = 0; i < manifest->count; ++i) {
        const char *key = manifest->members[i].key;
        size_t index;
        int known = 0;
        if (!key) continue;
        for (index = 0; carried[index]; ++index)
            if (!strcmp(key, carried[index])) known = 1;
        for (index = 0; installer_keys[index]; ++index)
            if (!strcmp(key, installer_keys[index])) { known = 1; ++installers; break; }
        for (index = 0; integration_keys[index]; ++index)
            if (!strcmp(key, integration_keys[index])) { known = 1; ++integrations; break; }
        for (index = 0; update_keys[index]; ++index)
            if (!strcmp(key, update_keys[index])) { known = 1; ++updates; break; }
        if (!known) ++unknown;
    }

    log_fd = openat(dir, "package", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (log_fd < 0) goto done;
    log = fdopen(log_fd, "w");
    if (!log) { log_fd = -1; goto done; }
    log_fd = -1;
    fputs("format holy-scoop-package-1\nconverter holy-scoop-1\n", log);
    fputs("status review-required\nmode artifact\n", log);
    fprintf(log, "name %s version %s arch %s libc %s\n", name, version, arch, libc);
    if (summary && is_literal(summary) && *summary) fprintf(log, "description carried\n");
    if (homepage && is_literal(homepage) && strstr(homepage, "://"))
        fprintf(log, "homepage %s\n", homepage);
    if (license && is_literal(license) && *license) fprintf(log, "license %s\n", license);
    fprintf(log, "artifact %s\n", url);
    fprintf(log, "artifact-sha256 %s verified against the digest the manifest pins\n", hash);
    fprintf(log, "artifact-placed the payload carries %zu files under %s\n", members.files,
            private);
    if (extract_dir)
        fprintf(log, "extract-dir %s is the directory the manifest places the program in\n",
                extract_dir);
    if (bin)
        fprintf(log, "program %s %s\n", bin, program_found ?
                "is in the payload at the path HOLY/meta records" :
                "is not in the artifact, so no program path is recorded");
    fprintf(log, "execution nothing runs the artifact; a package cannot promise a Wine\n"
                 "runtime, so no such requirement is recorded\n");
    if (count)
        fprintf(log, "depends %zu apps of the same bucket; each becomes a requirement a target\n"
                     "has to satisfy from a source that has it\n", count);
    if (installers)
        fprintf(log, "installer %zu PowerShell installer keys are dropped; nothing is executed\n"
                     "and nothing runs at install\n", installers);
    if (integrations)
        fprintf(log, "integration %zu Windows integration keys are dropped; a PATH entry, an\n"
                     "environment variable, a persisted directory and a shortcut belong to a\n"
                     "Windows installation\n", integrations);
    if (updates)
        fprintf(log, "update %zu keys that check or rewrite the upstream version belong to a\n"
                     "Scoop bucket, and a Holy source owns its own index\n", updates);
    if (unknown)
        fprintf(log, "unknown %zu manifest keys this importer does not model\n", unknown);
    if (members.refused)
        fprintf(log, "refused %zu archive members of a kind or a path a payload does not "
                     "carry\n", members.refused);
    fprintf(log, "payload entries %zu directories %zu\n", payload.count, members.directories);
    if (fflush(log) || fsync(fileno(log)) || fclose(log)) { log = NULL; goto done; }
    log = NULL;
    snprintf(artifact, sizeof artifact, "%s--%s--%s.holy", name, arch, libc);
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
    holy_json_free(manifest);
    if (spool >= 0) {
        if (!published && spool_name[0]) unlinkat(dir, spool_name, 0);
        close(spool);
    }
    if (dir >= 0) close(dir);
    return result;
}

int holy_import_scoop(const char *input, const char *source, const char *output)
{
    int result = scoop_import(input, source, output);
    if (result) return result;
    fputs("holypkg: the package carries a program for another operating system; nothing runs it,\n"
          "       no Wine runtime is required, and every installer step is dropped\n", stderr);
    return 3;
}
