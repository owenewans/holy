#define _POSIX_C_SOURCE 200809L
#include "snap.h"
#include "image.h"
#include "pack.h"
#include "stage.h"
#include "verify.h"
#include "version.h"

#include <openssl/evp.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static uint16_t le16(const unsigned char *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t le32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static uint64_t le64(const unsigned char *p)
{
    return (uint64_t)le32(p) | (uint64_t)le32(p + 4) << 32;
}

static int digest_fd(int fd, char result[65])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char buffer[65536], hash[32];
    unsigned length;
    ssize_t got;
    size_t i;
    int ok = 0;
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 || lseek(fd, 0, SEEK_SET) < 0)
        goto done;
    while ((got = read(fd, buffer, sizeof buffer)) > 0)
        if (EVP_DigestUpdate(ctx, buffer, (size_t)got) != 1) goto done;
    if (got < 0 || EVP_DigestFinal_ex(ctx, hash, &length) != 1 || length != sizeof hash) goto done;
    for (i = 0; i < 32; ++i) snprintf(result + i * 2, 3, "%02x", hash[i]);
    ok = 1;
done:
    EVP_MD_CTX_free(ctx);
    return ok;
}

/* a snap starts with a little-endian 32-bit offset to its SquashFS superblock,
   which is the one place a snap reader looks for a filesystem header */
static int snap_info(int fd, off_t *offset, char hash[65], unsigned *compression)
{
    unsigned char head[8], super[96] = {0};
    struct stat st;
    uint32_t size;
    uint64_t used;
    unsigned log;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 8 + 96 ||
        st.st_size > 4LL * 1024 * 1024 * 1024 || pread(fd, head, sizeof head, 0) != sizeof head)
        return 2;
    *offset = (off_t)le32(head);
    if (*offset < 8 || *offset + (off_t)sizeof super > st.st_size) return 2;
    if (pread(fd, super, sizeof super, *offset) != (ssize_t)sizeof super) return 1;
    if (memcmp(super, "hsqs", 4)) return 2;
    size = le32(super + 12); log = le16(super + 22); used = le64(super + 40);
    if (!le32(super + 4) || size < 4096 || size > 1048576 || (size & (size - 1)) ||
        log < 12 || log > 20 || size != (1u << log) ||
        le16(super + 20) < 1 || le16(super + 20) > 6 ||
        le16(super + 28) != 4 || le16(super + 30) != 0 ||
        used < 96 || used > (uint64_t)(st.st_size - *offset)) return 2;
    /* the machine of a snap lives in its payload, not in the superblock, so the
       header carries the compressor instead */
    *compression = le16(super + 20);
    return digest_fd(fd, hash) ? 0 : 1;
}

static int snap_snapshot(const char *input, char **path, off_t *offset, char hash[65],
                        unsigned *compression)
{
    int fd = open(input, O_RDONLY | O_NONBLOCK | O_CLOEXEC), copy, result;
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size < 8 + 96 || st.st_size > 4LL * 1024 * 1024 * 1024) {
        if (fd >= 0) close(fd);
        return 2;
    }
    result = 6;
    *path = holy_stage_fd(fd, "holy-snap");
    if (!*path) { result = 1; goto done; }
    copy = open(*path, O_RDONLY | O_CLOEXEC);
    if (copy < 0) { result = 1; goto done; }
    result = snap_info(copy, offset, hash, compression);
    close(copy);
done:
    if (fd >= 0) close(fd);
    return result;
}

int holy_snap_inspect(const char *input)
{
    char *path = NULL, hash[65];
    unsigned compression = 0;
    off_t offset = 0;
    int result = snap_snapshot(input, &path, &offset, hash, &compression);
    if (!result)
        printf("type snap\nsquashfs-offset %lld\ncompression %u\nsha256 %s\n",
               (long long)offset, compression, hash);
    else fprintf(stderr, "holypkg: snap inspection failed (status %d)\n", result);
    if (path) { unlink(path); free(path); }
    return result;
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

/* what one meta/snap.yaml states. the file is a plain YAML subset: top-level
   keys, two-space nested blocks, bare or quoted scalars and dash lists, which is
   everything the manifest uses, so the reader takes exactly that and counts the
   lines it does not model. */
struct snap_meta {
    struct holy_text name, version, base, summary, confinement, grade, command;
    struct holy_names plugs, hooks, chain, environment;
    size_t unknown_lines;
};

static void meta_free(struct snap_meta *meta)
{
    struct holy_names *sets[] = { &meta->plugs, &meta->hooks, &meta->chain, &meta->environment };
    size_t i;
    holy_text_free(&meta->name);
    holy_text_free(&meta->version);
    holy_text_free(&meta->base);
    holy_text_free(&meta->summary);
    holy_text_free(&meta->confinement);
    holy_text_free(&meta->grade);
    holy_text_free(&meta->command);
    for (i = 0; i < sizeof sets / sizeof *sets; ++i) {
        holy_text_free(&sets[i]->names);
        free(sets[i]->offsets);
        memset(sets[i], 0, sizeof *sets[i]);
    }
}

static struct holy_text *top_field(struct snap_meta *meta, const char *key)
{
    if (!strcmp(key, "name")) return &meta->name;
    if (!strcmp(key, "version")) return &meta->version;
    if (!strcmp(key, "base")) return &meta->base;
    if (!strcmp(key, "summary")) return &meta->summary;
    if (!strcmp(key, "confinement")) return &meta->confinement;
    if (!strcmp(key, "grade")) return &meta->grade;
    if (!strcmp(key, "command")) return &meta->command;
    return NULL;
}

/* one scalar value: a quoted string with its own quotes, or a bare token that
   ends before a comment */
static int scalar(const char *line, size_t length, struct holy_text *out)
{
    char quote = 0;
    size_t at = 0, used, i;
    while (at < length && line[at] == ' ') ++at;
    if (at < length && (line[at] == '"' || line[at] == '\'')) {
        quote = line[at++];
        if (at >= length) return 0;
    }
    used = length - at;
    while (used && (line[at + used - 1] == ' ' || line[at + used - 1] == '\r' ||
                    line[at + used - 1] == '\n')) --used;
    if (quote) {
        if (used < 2 || line[at + used - 1] != quote) return 0;
        --used;
    } else {
        for (i = 0; i + 1 < used; ++i)
            if (line[at + i] == ' ' && line[at + i + 1] == '#') { used = i; break; }
    }
    if (!used) return 0;
    if (used + 1 > out->capacity) {
        char *grown = realloc(out->data, used + 1);
        if (!grown) return 0;
        out->data = grown;
        out->capacity = used + 1;
    }
    memcpy(out->data, line + at, used);
    out->used = used;
    out->data[used] = 0;
    return 1;
}

/* one line of the manifest; parent is the key that opened the block the line
   sits in, or NULL at the top level */
static int yaml_line(const char *line, size_t length, struct snap_meta *meta,
                     const char *parent)
{
    char key[128];
    size_t at = 0, used = 0;
    if (line[0] == '#') return 1;
    if (line[0] == '-' && (length == 1 || line[1] == ' ')) {
        char item[4096];
        size_t size;
        if (!parent || strcmp(parent, "command-chain")) { ++meta->unknown_lines; return 1; }
        size = length > 2 ? length - 2 : 0;
        if (!size || size >= sizeof item) { ++meta->unknown_lines; return 1; }
        memcpy(item, line + 2, size);
        item[size] = 0;
        return holy_names_add(&meta->chain, item);
    }
    while (at < length && line[at] != ':' && used + 1 < sizeof key) key[used++] = line[at++];
    key[used] = 0;
    if (at >= length || line[at] != ':') { ++meta->unknown_lines; return 1; }
    at++;
    if (at < length && line[at] == ' ') ++at;
    if (!parent) {
        struct holy_text *field = top_field(meta, key);
        if (field) return scalar(line + at, length - at, field) ? 1 : 0;
        if (!strcmp(key, "type") || !strcmp(key, "adopt-info") || !strcmp(key, "license") ||
            !strcmp(key, "website") || !strcmp(key, "issues") || !strcmp(key, "icon") ||
            !strcmp(key, "publisher") || !strcmp(key, "license-provenance") ||
            !strcmp(key, "system-usernames")) return 1;
        ++meta->unknown_lines;
        return 1;
    }
    if (!strcmp(parent, "environment")) {
        /* the key is the variable name; its value is not carried */
        return holy_names_add(&meta->environment, key);
    }
    if (at < length) {
        /* a value inside a block the reader only names */
        ++meta->unknown_lines;
        return 1;
    }
    if (!strcmp(parent, "plugs")) return holy_names_add(&meta->plugs, key);
    if (!strcmp(parent, "hooks")) return holy_names_add(&meta->hooks, key);
    if (!strcmp(parent, "environment")) return holy_names_add(&meta->environment, key);
    ++meta->unknown_lines;
    return 1;
}

/* the key a line opens a block with, or NULL when it carries a value or an item */
static const char *yaml_opener(const char *line, size_t length, char *key, size_t size)
{
    size_t at = 0, used = 0;
    if (line[0] == '-') return NULL;
    while (at < length && line[at] != ':' && used + 1 < size) key[used++] = line[at++];
    key[used] = 0;
    if (at >= length || line[at] != ':') return NULL;
    at++;
    if (at < length && line[at] == ' ') ++at;
    return at >= length ? key : NULL;
}

static int read_snap_yaml(int root, struct snap_meta *meta)
{
    char parents[8][128];
    char line[8192], key[128];
    int file = openat(root, "meta/snap.yaml", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    FILE *stream;
    unsigned previous = 0;
    int ok = 0;
    if (file < 0) return 0;
    stream = fdopen(file, "r");
    if (!stream) { close(file); return 0; }
    memset(parents, 0, sizeof parents);
    while (fgets(line, sizeof line, stream)) {
        size_t length = strlen(line), at = 0;
        unsigned depth;
        const char *opener;
        while (length && (line[length - 1] == '\n' || line[length - 1] == '\r')) --length;
        while (at < length && (line[at] == ' ' || line[at] == '\t')) ++at;
        if (at >= length || line[at] == '#') continue;
        depth = (unsigned)(at / 2);
        if (depth > 7 || depth > previous + 1) { ++meta->unknown_lines; break; }
        if (!yaml_line(line + at, length - at, meta, depth ? parents[depth - 1] : NULL)) break;
        opener = yaml_opener(line + at, length - at, key, sizeof key);
        if (opener) snprintf(parents[depth], sizeof parents[depth], "%s", opener);
        previous = depth;
    }
    ok = !ferror(stream);
    fclose(stream);
    return ok;
}

/* the name a converted snap carries; a name the manifest cannot record is
   refused rather than rewritten, since it is what the operator types */
static int snap_name(struct snap_meta *meta, char *name, size_t size)
{
    size_t length, at;
    if (!meta->name.used || strlen(meta->name.data) >= size) return 0;
    memcpy(name, meta->name.data, strlen(meta->name.data) + 1);
    if (!isalnum((unsigned char)name[0])) return 0;
    for (at = 0; name[at]; ++at)
        if (!isalnum((unsigned char)name[at]) && name[at] != '-' && name[at] != '_' &&
            name[at] != '+' && name[at] != '.') return 0;
    length = strlen(name);
    return length > 0 && length < size;
}

static int extract_snap(const char *input, const char *output, const char *source)
{
    char *path = NULL, *original = NULL, *root = NULL, hash[65], copied_hash[65];
    unsigned compression = 0;
    off_t offset = 0;
    struct stat st;
    pid_t child;
    int dir = -1, copied = -1, status;
    int result = snap_snapshot(input, &path, &offset, hash, &compression);
    if (result) goto done;
    if (geteuid() == 0) {
        result = 6;
        fputs("holypkg: snap extraction requires an unprivileged user\n", stderr);
        goto done;
    }
    result = 1;
    if (mkdir(output, 0700)) goto done;
    dir = open(output, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || fstat(dir, &st) || st.st_uid != geteuid() || (st.st_mode & 0777) != 0700 ||
        !copy_original(path, dir)) goto done;
    copied = openat(dir, "original", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (copied < 0 || !digest_fd(copied, copied_hash) || strcmp(hash, copied_hash) ||
        mkdirat(dir, "snap", 0700)) goto done;
    close(copied); copied = -1;
    if (strlen(output) > SIZE_MAX - 16) goto done;
    original = malloc(strlen(output) + 10);
    root = malloc(strlen(output) + 6);
    if (!original || !root) goto done;
    sprintf(original, "%s/original", output);
    sprintf(root, "%s/snap", output);
    {
        char number[32];
        snprintf(number, sizeof number, "%lld", (long long)offset);
        child = fork();
        if (child < 0) goto done;
        if (!child) {
            execlp("unsquashfs", "unsquashfs", "-no-xattrs", "-offset", number,
                   "-d", root, original, (char *)NULL);
            _exit(127);
        }
    }
    while (waitpid(child, &status, 0) < 0) if (errno != EINTR) goto done;
    if (!WIFEXITED(status) || WEXITSTATUS(status)) {
        result = WIFEXITED(status) && WEXITSTATUS(status) == 127 ? 6 : 2;
        goto done;
    }
    {
        int receipt = openat(dir, "conversion", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                             O_CLOEXEC, 0600);
        FILE *file;
        if (receipt < 0) goto done;
        file = fdopen(receipt, "w");
        if (!file) { close(receipt); goto done; }
        fprintf(file, "format holy-snap-extract-1\nconverter holy-snap-1\n"
                      "original-sha256 %s\ncompression %u\nsquashfs-offset %lld\n"
                      "mode extract\nverification unverified\n", hash, compression,
                (long long)offset);
        if (source) { fputs("source-name ", file); holy_quoted(file, source); fputc('\n', file); }
        fputs("state extracted-unclassified\n", file);
        if (fflush(file) || fsync(fileno(file))) { fclose(file); goto done; }
        if (fclose(file) || fsync(dir)) goto done;
    }
    printf("extracted %s compression %u original %s\n", output, compression, hash);
    result = 0;
done:
    if (result)
        fprintf(stderr,
                "holypkg: snap extraction incomplete (status %d); no installed state changed\n",
                result);
    if (copied >= 0) close(copied);
    if (dir >= 0) close(dir);
    free(original); free(root);
    if (path) { unlink(path); free(path); }
    return result;
}

int holy_snap_extract(const char *input, const char *output)
{
    return extract_snap(input, output, NULL);
}

/* the launcher starts the recorded payload in the run context the package owns,
   so the paths a snap hardcodes come from that context rather than the host */
static int launcher_script(struct holy_text *out, const char *name, const char *source,
                           const char *private)
{
    return holy_text_add(out, "#!/bin/sh\n"
                               "# a converted snap carries no confinement and no snapd. this launcher\n"
                               "# starts the recorded payload in the run context the package owns, so\n"
                               "# the absolute paths the snap expects come from that context instead of\n"
                               "# the host.\n"
                               "set -e\n"
                               "if [ \"$(id -u)\" = 0 ]; then\n"
                               "  echo '") &&
           holy_text_add(out, name) &&
           holy_text_add(out, ": the converted payload is not confined; run it as your own user"
                               "' >&2\n  exit 1\nfi\nexec holypkg run ") &&
           holy_text_add(out, source) && holy_text_add(out, ":") && holy_text_add(out, name) &&
           holy_text_add(out, " -- /") && holy_text_add(out, private) &&
           holy_text_add(out, "/usr/bin/") && holy_text_add(out, name) &&
           holy_text_add(out, ".snap \"$@\"\n");
}

/* the native package of one extracted snap: the snap root travels whole under a
   private path, the command becomes a link under a private bin directory and the
   launcher reaches a public path */
static int package_snap(const char *source, const char *output)
{
    struct snap_meta meta = {0};
    struct holy_payload payload = {0};
    struct holy_text launcher = {0};
    char *text[7] = {0};
    size_t sizes[7] = {0}, i, data_first;
    FILE *files[7] = {0}, *log = NULL;
    char name[256], version[64] = "0", private[600], launcher_path[600];
    char digest[65], spool_name[43], artifact[700], path[900], link[900];
    const char *arch = HOLY_PAYLOAD_NOARCH, *libc = HOLY_PAYLOAD_NOLIBC;
    const char *command = NULL;
    int dir = -1, root = -1, spool = -1, log_fd = -1, original = -1;
    int result = 1, order = 0, version_stated = 0, published = 0;

    dir = open(output, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) return 1;
    root = openat(dir, "snap", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) goto done;
    if (!read_snap_yaml(root, &meta)) {
        fputs("holypkg: the snap has no readable meta/snap.yaml\n", stderr);
        result = 3;
        goto done;
    }
    if (!snap_name(&meta, name, sizeof name)) {
        fputs("holypkg: the snap name is not a package name\n", stderr);
        result = 2;
        goto done;
    }
    /* a version the manifest states has to be one the manifest can record */
    if (meta.version.used && holy_version_compare(meta.version.data, meta.version.data, &order)) {
        snprintf(version, sizeof version, "%s", meta.version.data);
        version_stated = 1;
    } else if (meta.version.used) {
        fputs("holypkg: the snap states a version this manifest cannot record\n", stderr);
    }
    /* the command is the entry point; a chain names the first element instead */
    command = meta.command.used ? meta.command.data : NULL;
    if (!command && meta.chain.count) {
        command = holy_names_get(&meta.chain, 0);
        fputs("holypkg: the snap declares a command chain; the launcher starts its first element\n",
              stderr);
    }
    if (!command) {
        fputs("holypkg: the snap names no command, so the package would have no entry point\n",
              stderr);
        result = 3;
        goto done;
    }
    if (command[0] == '/' || strstr(command, "..") || strchr(command, '$') ||
        strchr(command, '`')) {
        fputs("holypkg: the snap command names a path this manager cannot place\n", stderr);
        result = 3;
        goto done;
    }
    {
        int check = openat(root, command, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        struct stat entry;
        if (check < 0 || fstat(check, &entry) || !S_ISREG(entry.st_mode) ||
            !(entry.st_mode & 0111)) {
            if (check >= 0) close(check);
            fputs("holypkg: the snap command is not an executable file in its own tree\n", stderr);
            result = 3;
            goto done;
        }
        close(check);
    }
    original = openat(dir, "original", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (original < 0 || !digest_fd(original, digest)) goto done;
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
    snprintf(path, sizeof path, "DATA/%s/snap", private);
    if (!holy_payload_add(&payload, path, NULL, 0755, 0, 0, 1) ||
        !holy_payload_walk(&payload, root, "", path, 0)) goto done;
    /* the command has to be reachable under a bin directory, because that is the
       only place the run launcher can name a file the package owns */
    snprintf(link, sizeof link, "DATA/%s/usr/bin", private);
    if (!holy_payload_add(&payload, link, NULL, 0755, 0, 0, 1)) goto done;
    snprintf(link, sizeof link, "DATA/%s/usr/bin/%s.snap", private, name);
    snprintf(path, sizeof path, "../../snap/%s", command);
    if (!holy_payload_add(&payload, link, path, 0777, 0, 0, 0)) goto done;
    snprintf(launcher_path, sizeof launcher_path, "/usr/bin/%s", name);
    if (!launcher_script(&launcher, name, source, private)) goto done;
    snprintf(path, sizeof path, "DATA/usr/bin/%s", name);
    if (!holy_payload_add_text(&payload, &launcher, path, 0755)) goto done;
    {
        /* the conversion receipt travels with the package, so an installed copy
           can still be compared with the snap it came from */
        struct holy_text body = {0};
        int kept = holy_text_read(dir, "conversion", &body, 1024 * 1024);
        if (kept && body.used) {
            snprintf(path, sizeof path, "DATA/usr/share/holy/%s/conversion", name);
            kept = holy_payload_add_text(&payload, &body, path, 0644);
        }
        holy_text_free(&body);
        if (!kept) goto done;
    }
    if (payload.mixed) {
        fputs("holypkg: the payload carries more than one architecture or runtime, and one\n"
              "       .holy records one, so the conversion stops here\n", stderr);
        result = 3;
        goto done;
    }
    if (payload.arch[0]) {
        arch = payload.arch;
        libc = payload.libc;
    }
    fputs("format holy-package-1\nname ", files[0]); holy_quoted(files[0], name);
    fputs("\nversion ", files[0]); holy_quoted(files[0], version);
    fputs("\nrelease \"1\"\nos linux\narch ", files[0]); holy_quoted(files[0], arch);
    fputs("\nlibc ", files[0]); holy_quoted(files[0], libc);
    fputs("\nx-version-family snap\nx-source-family snap\nx-converter holy-snap-1\n"
          "x-source-arch ", files[0]);
    holy_quoted(files[0], arch);
    fprintf(files[0], "\nx-snap-base %s\nx-snap-confinement %s\n",
            meta.base.used ? meta.base.data : "-",
            meta.confinement.used ? meta.confinement.data : "strict");
    if (!holy_payload_manifest(files[1], &payload, data_first)) goto done;
    if (meta.base.used) {
        /* the base a snap asks for is a runtime snapd would mount from a snap
           store; on this system it has to come from a registered source, and the
           runtime it brings is not something a squashfs superblock states */
        fputs("require snap-base ", files[2]); holy_quoted(files[2], name);
        fputs(" package ", files[2]); holy_quoted(files[2], meta.base.data);
        fprintf(files[2], " %s any any - ", arch);
        holy_quoted(files[2], "snap-base");
        fputc(' ', files[2]); holy_quoted(files[2], "snap-manifest");
        fputc('\n', files[2]);
    }
    for (i = 0; i < payload.needed.count; ++i) {
        const char *soname = holy_names_get(&payload.needed, i);
        char id[128];
        if (holy_names_has(&payload.provided, soname)) continue;
        snprintf(id, sizeof id, "snap-needed-%zu", i);
        fputs("require ", files[2]); holy_quoted(files[2], id);
        fputc(' ', files[2]); holy_quoted(files[2], name);
        fputs(" soname ", files[2]); holy_quoted(files[2], soname);
        fprintf(files[2], " %s %s any - ", arch, libc);
        holy_quoted(files[2], "dt_needed");
        fputc(' ', files[2]); holy_quoted(files[2], "snap-payload");
        fputc('\n', files[2]);
    }
    for (i = 0; i < payload.absolute.count; ++i) {
        char id[128];
        /* a link whose absolute or escaping target cannot travel in a payload
           stays a requirement, so the installer reports it */
        snprintf(id, sizeof id, "snap-link-%zu", i);
        fputs("require ", files[2]); holy_quoted(files[2], id);
        fputc(' ', files[2]); holy_quoted(files[2], name);
        fputs(" file ", files[2]); holy_quoted(files[2], holy_names_get(&payload.absolute, i));
        fputs(" any any any - ", files[2]);
        holy_quoted(files[2], "symlink_target");
        fputc(' ', files[2]); holy_quoted(files[2], "snap-payload");
        fputc('\n', files[2]);
    }
    fputs("provide package ", files[3]); holy_quoted(files[3], name);
    fprintf(files[3], " %s %s - ", arch, libc);
    holy_quoted(files[3], "snap-payload");
    fputc('\n', files[3]);
    for (i = 0; i < payload.provided.count; ++i) {
        fputs("provide soname ", files[3]);
        holy_quoted(files[3], holy_names_get(&payload.provided, i));
        fprintf(files[3], " %s %s - ", arch, libc);
        holy_quoted(files[3], "snap-payload");
        fputc('\n', files[3]);
    }
    fputs("format holy-import-origin-1\nfamily snap\nsource-name ", files[5]);
    holy_quoted(files[5], source);
    fputs("\noriginal-sha256 ", files[5]); holy_quoted(files[5], digest);
    fputs("\nverification unverified\nconverter holy-snap-1\noriginal-version ", files[5]);
    holy_quoted(files[5], version);
    fprintf(files[5], "\ncommand %s\nmode extract\n", command);
    fputs("snap the snap root travels whole under a private path\n", files[6]);
    fprintf(files[6], "launcher /usr/bin/%s starts the payload in the package run context\n", name);
    fprintf(files[6], "command %s reachable as /usr/lib/holy/private/%s/usr/bin/%s.snap\n",
            command, name, name);
    fprintf(files[6], "confinement dropped; the payload runs with the caller's context\n");
    if (meta.base.used)
        fprintf(files[6], "snap-base %s required as a package; snapd would mount it from a store\n",
                meta.base.data);
    for (i = 0; i < meta.plugs.count; ++i)
        fprintf(files[6], "plug %s dropped; the payload runs without the interface\n",
                holy_names_get(&meta.plugs, i));
    for (i = 0; i < meta.hooks.count; ++i)
        fprintf(files[6], "hook %s recorded; nothing runs it at install\n",
                holy_names_get(&meta.hooks, i));
    for (i = 0; i < meta.environment.count; ++i)
        fprintf(files[6], "environment %s recorded; the launcher does not set it\n",
                holy_names_get(&meta.environment, i));
    for (i = 0; i < meta.chain.count; ++i)
        fprintf(files[6], "command-chain %s recorded; the launcher starts the command only\n",
                holy_names_get(&meta.chain, i));
    if (ferror(files[0]) || ferror(files[2]) || ferror(files[3]) || ferror(files[5]) ||
        ferror(files[6])) goto done;
    if (!holy_payload_records(&payload, files, text, sizes)) goto done;
    log_fd = openat(dir, "package", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (log_fd < 0) goto done;
    log = fdopen(log_fd, "w");
    if (!log) { log_fd = -1; goto done; }
    log_fd = -1;
    fputs("format holy-snap-package-1\nconverter holy-snap-1\n", log);
    fputs("status review-required\nmode extract\n", log);
    fprintf(log, "name %s version %s arch %s libc %s\n", name, version, arch, libc);
    if (version_stated) fprintf(log, "version the manifest states %s\n", version);
    else fputs("version the manifest states none, so the package records zero\n", log);
    if (meta.base.used)
        fprintf(log, "base-required %s is the runtime snapd would mount from a snap store; it is\n"
                     "a package requirement here, so the target needs a source that provides it\n",
                meta.base.data);
    else fputs("base-required the manifest states none, so the payload has no recorded runtime\n", log);
    if (meta.confinement.used)
        fprintf(log, "confinement %s is dropped: the payload runs with the caller's context,\n"
                     "with no namespace, seccomp or AppArmor profile from the snap\n",
                meta.confinement.data);
    if (meta.plugs.count)
        fprintf(log, "plugs %zu interfaces are dropped; each needs a host decision before the\n"
                     "payload may reach what it names\n", meta.plugs.count);
    else fputs("plugs the manifest names none\n", log);
    if (meta.hooks.count)
        fprintf(log, "hooks %zu the manifest declares; they are recorded and not run at install\n",
                meta.hooks.count);
    if (meta.chain.count)
        fprintf(log, "command-chain %zu entries; the launcher starts the command and does not run\n"
                     "the chain\n", meta.chain.count);
    if (meta.environment.count)
        fprintf(log, "environment %zu variables the manifest declares; the launcher does not set\n"
                     "them, so the payload runs with the caller's environment\n",
                meta.environment.count);
    if (meta.unknown_lines)
        fprintf(log, "unknown %zu lines of the manifest this reader does not model\n",
                meta.unknown_lines);
    if (payload.path_views)
        fprintf(log, "path-view-required %zu links name an absolute or escaping target; a payload\n"
                     "carries neither, so each path it named is a recorded file requirement\n",
                payload.path_views);
    if (payload.scripts)
        fprintf(log, "scripts %zu files carry an interpreter; nothing runs them at install\n",
                payload.scripts);
    if (payload.unknown)
        fprintf(log, "unknown %zu files are not an ELF this reader recognizes; they are carried\n"
                     "as payload and no requirement is derived from them\n", payload.unknown);
    fprintf(log, "payload files %zu elf %zu links %zu provided %zu required %zu\n",
            payload.files, payload.elfs, payload.links, payload.provided.count,
            payload.needed.count);
    if (fflush(log) || fsync(fileno(log)) || fclose(log)) { log = NULL; goto done; }
    log = NULL;
    snprintf(artifact, sizeof artifact, "%s--%s--%s.holy", name, arch, libc);
    if (!holy_pack_stream(spool, payload.entries, payload.count, dir, artifact)) goto done;
    published = 1;
    {
        int packed = openat(dir, artifact, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (packed < 0 || !digest_fd(packed, digest)) {
            if (packed >= 0) close(packed);
            goto done;
        }
        close(packed);
    }
    printf("imported %s original ", artifact);
    holy_quoted(stdout, digest);
    printf(" arch %s libc %s mode extract\n", arch, libc);
    result = 0;
done:
    if (log) fclose(log);
    if (log_fd >= 0) close(log_fd);
    for (i = 0; i < 7; ++i) if (files[i]) fclose(files[i]);
    for (i = 0; i < 7; ++i) free(text[i]);
    holy_payload_free(&payload);
    meta_free(&meta);
    holy_text_free(&launcher);
    if (spool >= 0) {
        if (!published && spool_name[0]) unlinkat(dir, spool_name, 0);
        close(spool);
    }
    if (original >= 0) close(original);
    if (root >= 0) close(root);
    if (dir >= 0) close(dir);
    return result;
}

int holy_import_snap(const char *input, const char *source, const char *output)
{
    size_t i;
    int result;
    if (!source || !*source || !strcmp(source, "local")) return 2;
    for (i = 0; source[i]; ++i)
        if ((unsigned char)source[i] <= 32 || source[i] == ':' ||
            source[i] == '/' || source[i] == '@') return 2;
    result = extract_snap(input, output, source);
    if (result) return result;
    result = package_snap(source, output);
    if (result) return result;
    fputs("holypkg: the package runs without snapd, without its base runtime and without its\n"
          "       confinement; read the package report before installing it\n", stderr);
    return 3;
}
