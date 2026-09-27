#define _POSIX_C_SOURCE 200809L
#include "docs.h"
#include "config.h"
#include "state.h"
#include "install.h"

#include <archive.h>
#include <archive_entry.h>
#include <openssl/evp.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SOURCE_LIMIT (16 * 1024 * 1024)
#define TEXT_LIMIT (64 * 1024 * 1024)

struct bundle {
    FILE *out;
    const char *artifact;
    char *name, *version, *source;
    int root, manifest;
    size_t packages, pages, aliases, missing, omitted, package_pages;
};

static void quoted(FILE *out, const char *text)
{
    const unsigned char *p = (const unsigned char *)text;
    fputc('"', out);
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') fprintf(out, "\\%c", *p);
        else if (*p < 32 || *p >= 127) fprintf(out, "\\x%02x", (unsigned)*p);
        else fputc(*p, out);
    }
    fputc('"', out);
}

static unsigned char *read_file(int fd, size_t *size)
{
    struct stat st;
    unsigned char *data;
    size_t used = 0;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        st.st_size > SOURCE_LIMIT) return NULL;
    *size = (size_t)st.st_size;
    data = malloc(*size + 1);
    if (!data) return NULL;
    while (used < *size) {
        ssize_t got = read(fd, data + used, *size - used);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { free(data); return NULL; }
        used += (size_t)got;
    }
    data[*size] = 0;
    return data;
}

static int records(int dir, const char *name,
                   int (*visit)(struct bundle *, char **, size_t), struct bundle *b)
{
    size_t size, start = 0, i, line = 0;
    unsigned char *data;
    int fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK), ok = 1;
    if (fd < 0) return 0;
    data = read_file(fd, &size);
    close(fd);
    if (!data) return 0;
    if (memchr(data, 0, size)) { free(data); return 0; }
    for (i = 0; i <= size; ++i) {
        char **v = NULL, *error = NULL;
        size_t n = 0;
        if (i < size && data[i] != '\n') continue;
        ++line;
        ok = holy_lex((char *)data + start, i - start, &v, &n, name, line, &error);
        if (ok && n) ok = visit(b, v, n);
        free(error);
        holy_tokens_free(v, n);
        if (!ok) break;
        start = i + 1;
    }
    free(data);
    return ok;
}

static int identity(struct bundle *b, char **v, size_t n)
{
    char **field = NULL;
    if (!strcmp(v[0], "name")) field = &b->name;
    else if (!strcmp(v[0], "version")) field = &b->version;
    if (!field) return 1;
    if (n != 2 || !v[1][0] || *field) return 0;
    *field = strdup(v[1]);
    return *field != NULL;
}

static int source(struct bundle *b, char **v, size_t n)
{
    if (strcmp(v[0], "source-id")) return 1;
    if (n != 2 || !v[1][0] || b->source) return 0;
    b->source = strdup(v[1]);
    return b->source != NULL;
}

static void attribution(struct bundle *b)
{
    fprintf(b->out, " artifact %s package ", b->artifact);
    quoted(b->out, b->name);
    fputs(" version ", b->out);
    quoted(b->out, b->version);
    fputs(" source-id ", b->out);
    quoted(b->out, b->source);
}

static int open_page(int root, const char *path)
{
    char *copy = strdup(path), *part, *slash;
    int fd = dup(root);
    if (!copy || fd < 0) { free(copy); if (fd >= 0) close(fd); return -1; }
    part = copy;
    for (;;) {
        int next;
        slash = strchr(part, '/');
        if (slash) *slash = 0;
        if (!*part || !strcmp(part, ".") || !strcmp(part, "..")) { close(fd); fd = -1; break; }
        next = openat(fd, part, O_RDONLY | O_NOFOLLOW | O_CLOEXEC |
                      (slash ? O_DIRECTORY : O_NONBLOCK));
        close(fd);
        fd = next;
        if (fd < 0 || !slash) break;
        part = slash + 1;
    }
    free(copy);
    return fd;
}

static int text_body(FILE *out, const unsigned char *data, size_t size, const char *codec)
{
    struct archive *a;
    struct archive_entry *entry;
    int support = ARCHIVE_FATAL, ok = 0;
    char buffer[8192];
    size_t total = 0;
    la_ssize_t got;
    if (!codec) return size && !memchr(data, 0, size) && fwrite(data, 1, size, out) == size;
    a = archive_read_new();
    if (!a) return 0;
    if (!strcmp(codec, "gz")) support = archive_read_support_filter_gzip(a);
    else if (!strcmp(codec, "bz2")) support = archive_read_support_filter_bzip2(a);
    else if (!strcmp(codec, "xz")) support = archive_read_support_filter_xz(a);
    else if (!strcmp(codec, "zst")) support = archive_read_support_filter_zstd(a);
    if (support != ARCHIVE_OK || archive_read_support_format_raw(a) != ARCHIVE_OK ||
        archive_read_open_memory(a, data, size) != ARCHIVE_OK ||
        archive_read_next_header(a, &entry) != ARCHIVE_OK || archive_filter_code(a, 0) == ARCHIVE_FILTER_NONE)
        goto done;
    while ((got = archive_read_data(a, buffer, sizeof buffer)) > 0) {
        if ((size_t)got > TEXT_LIMIT - total || memchr(buffer, 0, (size_t)got) ||
            fwrite(buffer, 1, (size_t)got, out) != (size_t)got) goto done;
        total += (size_t)got;
    }
    ok = got == 0 && total && archive_read_next_header(a, &entry) == ARCHIVE_EOF;
done:
    archive_read_free(a);
    return ok;
}

static int page(struct bundle *b, char **v, size_t n)
{
    const char *base, *section, *codec = NULL;
    char *name = NULL, *dot;
    unsigned char *data = NULL, digest[32];
    unsigned int length;
    char hash[65];
    size_t size, i;
    int fd = -1, ok = 0;
    if (n < 2) return 0;
    if (strncmp(v[1], "usr/share/man/", 14) || !strcmp(v[0], "dir")) return 1;
    base = strrchr(v[1], '/');
    if (!base || !base[1] || !(name = strdup(base + 1))) return 0;
    dot = strrchr(name, '.');
    if (dot && (!strcmp(dot, ".gz") || !strcmp(dot, ".bz2") ||
                !strcmp(dot, ".xz") || !strcmp(dot, ".zst"))) {
        codec = strrchr(base, '.') + 1;
        *dot = 0;
        dot = strrchr(name, '.');
    }
    if (!dot || dot == name || dot[1] < '1' || dot[1] > '9') {
        fputs("omitted-man path ", b->out); quoted(b->out, v[1]);
        attribution(b); fputs(" reason unsupported-name-or-codec\n", b->out);
        ++b->omitted;
        ok = 1;
        goto done;
    }
    *dot = 0;
    section = dot + 1;
    if (!strcmp(v[0], "symlink") && n == 13) {
        if (holy_install_check_path(b->manifest, b->root, v[1]) != 1) goto done;
        fputs("alias path ", b->out); quoted(b->out, v[1]);
        fputs(" target ", b->out); quoted(b->out, v[12]);
        attribution(b); fputc('\n', b->out);
        ++b->aliases;
        ok = 1;
        goto done;
    }
    if ((strcmp(v[0], "file") || n != 12) &&
        (strcmp(v[0], "hardlink") || n != 13)) goto done;
    if (strlen(v[8]) != 64 || (!strcmp(v[0], "hardlink") &&
        holy_install_check_path(b->manifest, b->root, v[1]) != 1)) goto done;
    fd = open_page(b->root, v[1]);
    if (fd < 0 || !(data = read_file(fd, &size)) ||
        EVP_Digest(data, size, digest, &length, EVP_sha256(), NULL) != 1 || length != 32) goto done;
    for (i = 0; i < 32; ++i) snprintf(hash + i * 2, 3, "%02x", digest[i]);
    if (strcmp(hash, v[8])) goto done;
    fputs("page name ", b->out); quoted(b->out, name);
    fputs(" section ", b->out); quoted(b->out, section);
    fputs(" path ", b->out); quoted(b->out, v[1]);
    attribution(b);
    fprintf(b->out, " sha256 %s encoding roff-source\n", hash);
    if (!text_body(b->out, data, size, codec)) goto done;
    fputs("\nend-page\n", b->out);
    ++b->pages;
    ++b->package_pages;
    ok = !ferror(b->out);
done:
    if (fd >= 0) close(fd);
    free(data);
    free(name);
    return ok;
}

static int instance(void *context, int root, int item, const char *artifact)
{
    struct bundle *b = context;
    int ok;
    b->root = root; b->artifact = artifact; b->package_pages = 0;
    b->manifest = openat(item, "files", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    ok = b->manifest >= 0 && records(item, "meta", identity, b) && b->name && b->version &&
         records(item, "state", source, b) && b->source && records(item, "files", page, b);
    if (b->manifest >= 0) close(b->manifest);
    if (ok && !b->package_pages) {
        fputs("missing-man", b->out); attribution(b); fputc('\n', b->out);
        ++b->missing;
    }
    free(b->name); free(b->version); free(b->source);
    b->name = b->version = b->source = NULL;
    ++b->packages;
    return ok && !ferror(b->out) ? 0 : 4;
}

int holy_docs(const char *root, const char *output)
{
    struct bundle b = {0};
    unsigned long long generation = 0;
    size_t length = strlen(output);
    char *temp;
    int fd = -1, result = 1;
    if (length > SIZE_MAX - 16 || !(temp = malloc(length + 16))) return 1;
    snprintf(temp, length + 16, "%s.tmp.XXXXXX", output);
    fd = mkstemp(temp);
    if (fd < 0) goto done;
    b.out = fdopen(fd, "w");
    if (!b.out) goto done;
    fputs("format holy-docs-1\n", b.out);
    result = holy_state_visit(root, instance, &b, &generation);
    if (result) goto done;
    fprintf(b.out, "summary generation %llu packages %zu pages %zu aliases %zu missing-man %zu omitted %zu\n",
            generation, b.packages, b.pages, b.aliases, b.missing, b.omitted);
    if (fflush(b.out) || fsync(fd) || link(temp, output)) result = 1;
done:
    if (b.out) fclose(b.out);
    else if (fd >= 0) close(fd);
    if (fd >= 0) unlink(temp);
    free(temp);
    if (result) fprintf(stderr, "holypkg: documentation unavailable, changed, or output exists (status %d)\n", result);
    return result;
}
