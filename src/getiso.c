#define _XOPEN_SOURCE 700
#include "config.h"
#include "sign.h"

#include <errno.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

struct option {
    const char *section;
    const char *key;
    char *value;
    int required;
    int path;
};

struct source {
    char *alias;
    char *type;
    char *url;
    char *index;
    char *commit;
    char *ca_file;
    char *mirror;
    char *embed_mirror;
    char *trust;
    char key[65];
};

static struct source *sources;
static size_t source_count;

static struct option options[] = {
    {"image", "arch", NULL, 1, 0},
    {"image", "output", NULL, 1, 1},
    {"image", "kernel-image", NULL, 1, 1},
    {"image", "kernel-version", NULL, 1, 0},
    {"image", "limine-dir", NULL, 1, 1},
    {"image", "static-holypkg", NULL, 1, 1},
    {"image", "static-holyinstall", NULL, 1, 1},
    {"image", "static-cc", NULL, 1, 1},
    {"image", "glibc-cc", NULL, 0, 0},
    {"image", "musl-cc", NULL, 0, 1},
    {"image", "profile", NULL, 1, 0},
    {"image", "root-storage", NULL, 1, 0},
    {"image", "libc-boot-state", NULL, 0, 0},
    {"image", "network-recovery", NULL, 0, 0},
    {"image", "install-test", NULL, 0, 0},
    {"image", "install-firmware", NULL, 0, 0},
    {"image", "boot-test", NULL, 0, 0},
    {"packages", "busybox", NULL, 1, 1},
    {"packages", "dinit", NULL, 1, 1},
    {"packages", "mdevd", NULL, 1, 1},
    {"packages", "glibc", NULL, 0, 1},
    {"packages", "musl", NULL, 0, 1},
    {"packages", "doas", NULL, 0, 1},
    {"packages", "storage-tools", NULL, 0, 1},
    {"resolver", "answers", NULL, 0, 1},
    {"resolver", "answers-sha256", NULL, 0, 0},
    {"docs", "output", NULL, 0, 0}
};

static char **additional;
static size_t additional_count;
static int docs_count;

struct input_frame {
    dev_t device;
    ino_t inode;
    const struct input_frame *parent;
};

static int digest_valid(const char *s)
{
    size_t i;
    if (strlen(s) != 64) return 0;
    for (i = 0; i < 64; ++i)
        if (!((s[i] >= '0' && s[i] <= '9') ||
              (s[i] >= 'a' && s[i] <= 'f'))) return 0;
    return 1;
}

static int file_digest_matches(const char *path, const char *expected)
{
    struct stat st;
    if (stat(path, &st) || !S_ISREG(st.st_mode)) return 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    FILE *input = fopen(path, "rb");
    unsigned char buffer[8192], digest[32];
    char actual[65];
    unsigned length;
    size_t count, i;
    int ok = ctx && input && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    while (ok && (count = fread(buffer, 1, sizeof buffer, input)) > 0)
        ok = EVP_DigestUpdate(ctx, buffer, count) == 1;
    if (ok && ferror(input)) ok = 0;
    if (ok) ok = EVP_DigestFinal_ex(ctx, digest, &length) == 1 && length == sizeof digest;
    if (ok) {
        for (i = 0; i < sizeof digest; ++i)
            snprintf(actual + i * 2, 3, "%02x", digest[i]);
        ok = !strcmp(actual, expected);
    }
    if (input) fclose(input);
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int alias_valid(const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    if (!*p || !strcmp(s, "local")) return 0;
    for (; *p; ++p)
        if (!( (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
               (*p >= '0' && *p <= '9') || *p == '_' || *p == '-')) return 0;
    return 1;
}

static struct source *source_for(const char *alias)
{
    size_t i;
    for (i = 0; i < source_count; ++i)
        if (!strcmp(sources[i].alias, alias)) return &sources[i];
    return NULL;
}

static char *reference_alias(const char *value)
{
    const char *colon = strchr(value, ':');
    size_t n;
    char *alias;
    if (!colon || colon == value || !colon[1] || strchr(value, '/')) return NULL;
    n = (size_t)(colon - value);
    alias = strndup(value, n);
    if (alias && !alias_valid(alias)) { free(alias); return NULL; }
    return alias;
}

static struct option *find(const char *section, const char *key)
{
    size_t i;
    for (i = 0; i < sizeof options / sizeof options[0]; ++i)
        if (!strcmp(section, options[i].section) && !strcmp(key, options[i].key))
            return &options[i];
    return NULL;
}

static const char *get(const char *section, const char *key)
{
    struct option *o = find(section, key);
    return o && o->value ? o->value : NULL;
}

static int die(const char *path, size_t line, const char *message)
{
    fprintf(stderr, "holygetiso: %s:%zu: %s\n", path, line, message);
    return 2;
}

static char *config_path(const char *config, const char *value, int existing)
{
    const char *slash;
    size_t prefix, length;
    char *joined, *resolved;
    if (value[0] == '/') joined = strdup(value);
    else {
        slash = strrchr(config, '/');
        prefix = slash ? (size_t)(slash - config + 1) : 0;
        length = strlen(value);
        if (prefix > (size_t)-1 - length - 1) return NULL;
        joined = malloc(prefix + length + 1);
        if (!joined) return NULL;
        memcpy(joined, config, prefix);
        memcpy(joined + prefix, value, length + 1);
    }
    if (!joined) return NULL;
    if (!existing) return joined;
    resolved = realpath(joined, NULL);
    free(joined);
    return resolved;
}

static char *package_value(const char *config, const char *value)
{
    char *alias = reference_alias(value);
    char *result;
    if (alias) {
        free(alias);
        return strdup(value);
    }
    result = config_path(config, value, 1);
    return result;
}

static int parse_file(const char *path, const struct input_frame *parent, size_t depth)
{
    FILE *file;
    struct stat st;
    struct input_frame frame;
    const struct input_frame *ancestor;
    char *line = NULL;
    size_t capacity = 0, number = 0;
    const char *section = NULL;
    struct source *current = NULL;
    ssize_t length;
    int rc = 0;
    if (depth >= 64) return die(path, 0, "include depth exceeds 64");
    file = fopen(path, "r");
    if (!file || fstat(fileno(file), &st) || !S_ISREG(st.st_mode)) {
        if (file) fclose(file);
        return die(path, 0, "include must be a readable regular file");
    }
    for (ancestor = parent; ancestor; ancestor = ancestor->parent)
        if (ancestor->device == st.st_dev && ancestor->inode == st.st_ino) {
            fclose(file);
            return die(path, 0, "include cycle");
        }
    frame.device = st.st_dev;
    frame.inode = st.st_ino;
    frame.parent = parent;
    while ((length = getline(&line, &capacity, file)) >= 0) {
        char **tokens = NULL, *error = NULL;
        size_t count = 0;
        struct option *o;
        ++number;
        if (memchr(line, 0, (size_t)length)) {
            rc = die(path, number, "NUL byte in config"); break;
        }
        if (!holy_lex(line, (size_t)length, &tokens, &count, path, number, &error)) {
            fprintf(stderr, "holygetiso: %s\n", error ? error : "invalid config");
            free(error); rc = 2; break;
        }
        if (!count) { holy_tokens_free(tokens, count); continue; }
        if (!strcmp(tokens[0], "include") &&
            !(section && !strcmp(section, "docs") && count == 2 &&
              !strcmp(tokens[1], "installed-man-pages"))) {
            char *child = count == 2 && tokens[1][0] ?
                config_path(path, tokens[1], 1) : NULL;
            if (!child) rc = die(path, number, "include requires one existing path");
            else { rc = parse_file(child, &frame, depth + 1); free(child); }
        } else if (tokens[0][0] == '[') {
            current = NULL;
            if (count == 2 && !strcmp(tokens[0], "[source") &&
                tokens[1][0] &&
                tokens[1][strlen(tokens[1]) - 1] == ']') {
                char *alias = strndup(tokens[1], strlen(tokens[1]) - 1);
                struct source *next;
                if (!alias || !alias_valid(alias) || source_for(alias) ||
                    source_count >= 64 ||
                    !(next = realloc(sources, (source_count + 1) * sizeof(*sources)))) {
                    free(alias);
                    rc = die(path, number, "invalid or duplicate source alias");
                } else {
                    sources = next;
                    current = &sources[source_count++];
                    memset(current, 0, sizeof(*current));
                    current->alias = alias;
                    section = "source";
                }
            } else if (count != 1 || !tokens[0][0] ||
                       tokens[0][strlen(tokens[0]) - 1] != ']')
                rc = die(path, number, "invalid section");
            else if (!strcmp(tokens[0], "[image]")) section = "image";
            else if (!strcmp(tokens[0], "[packages]")) section = "packages";
            else if (!strcmp(tokens[0], "[resolver]")) section = "resolver";
            else if (!strcmp(tokens[0], "[docs]")) section = "docs";
            else rc = die(path, number, "unsupported section");
        } else if (!section || count != 2 || !tokens[1][0]) {
            rc = die(path, number, "expected key and one value");
        } else if (!strcmp(section, "source")) {
            char **target = NULL;
            if (!strcmp(tokens[0], "public-key")) {
                char *key_path = config_path(path, tokens[1], 1);
                if (current->key[0]) rc = die(path, number, "duplicate source key");
                else if (!key_path || !holy_public_key_hex(key_path, current->key))
                    rc = die(path, number, "invalid Ed25519 public key");
                free(key_path);
            } else if (!strcmp(tokens[0], "type")) target = &current->type;
            else if (!strcmp(tokens[0], "url")) target = &current->url;
            else if (!strcmp(tokens[0], "index-sha256")) target = &current->index;
            else if (!strcmp(tokens[0], "commit")) target = &current->commit;
            else if (!strcmp(tokens[0], "ca-file")) target = &current->ca_file;
            else if (!strcmp(tokens[0], "mirror")) target = &current->mirror;
            else if (!strcmp(tokens[0], "embed-mirror")) target = &current->embed_mirror;
            else if (!strcmp(tokens[0], "trust")) target = &current->trust;
            if (!target && strcmp(tokens[0], "public-key")) rc = die(path, number, "unsupported source key");
            else if (target && *target) rc = die(path, number, "duplicate source key");
            else if (target) {
                *target = (!strcmp(tokens[0], "ca-file") ||
                           !strcmp(tokens[0], "mirror")) ?
                    config_path(path, tokens[1], 1) : strdup(tokens[1]);
                if (!*target) rc = die(path, number, "missing source path or out of memory");
            }
        } else if (!strcmp(section, "docs") && !strcmp(tokens[0], "include")) {
            if (docs_count++ || strcmp(tokens[1], "installed-man-pages"))
                rc = die(path, number, "expected one installed-man-pages include");
        } else if (!strcmp(section, "packages") && !strcmp(tokens[0], "add")) {
            char *resolved = package_value(path, tokens[1]);
            char **next;
            if (!resolved) rc = die(path, number, "missing package path");
            else if (strchr(resolved, '\n') || strchr(resolved, '\r') ||
                     additional_count > ((size_t)-1 / sizeof(*additional)) - 1) {
                free(resolved);
                rc = die(path, number, "unsupported package path or too many packages");
            } else {
                next = realloc(additional, (additional_count + 1) * sizeof(*additional));
                if (!next) { free(resolved); rc = die(path, number, "out of memory"); }
                else { additional = next; additional[additional_count++] = resolved; }
            }
        } else if (!(o = find(section, tokens[0]))) {
            rc = die(path, number, "unknown key");
        } else if (o->value) {
            rc = die(path, number, "duplicate scalar key");
        } else {
            o->value = !strcmp(section, "packages") ? package_value(path, tokens[1]) :
                       o->path ? config_path(path, tokens[1], strcmp(o->key, "output") != 0) : strdup(tokens[1]);
            if (!o->value) rc = die(path, number, "missing path or out of memory");
        }
        holy_tokens_free(tokens, count);
        if (rc) break;
    }
    if (ferror(file) && !rc) rc = 6;
    free(line);
    fclose(file);
    return rc;
}

static int parse(const char *path)
{
    size_t i;
    int rc = parse_file(path, NULL, 0);
    if (rc) return rc;
    for (i = 0; i < sizeof options / sizeof options[0]; ++i)
        if (options[i].required && !options[i].value) {
            fprintf(stderr, "holygetiso: missing [%s] %s\n", options[i].section, options[i].key);
            return 2;
        }
    if (!docs_count || !get("docs", "output") ||
        strcmp(get("docs", "output"), "/usr/share/holy/llm.txt"))
        return die(path, 0, "[docs] requires installed-man-pages and /usr/share/holy/llm.txt");
    if (!!get("resolver", "answers") != !!get("resolver", "answers-sha256") ||
        (get("resolver", "answers-sha256") &&
         (!digest_valid(get("resolver", "answers-sha256")) ||
          !file_digest_matches(get("resolver", "answers"),
                               get("resolver", "answers-sha256")))))
        return die(path, 0, "resolver answers require a matching SHA-256 pin");
    if (strcmp(get("image", "arch"), "x86_64") && strcmp(get("image", "arch"), "i686"))
        return die(path, 0, "arch must be x86_64 or i686");
    if (strchr(get("image", "output"), '\n') ||
        strchr(get("image", "output"), '\r'))
        return die(path, 0, "output path cannot contain a line break");
    if (strcmp(get("image", "profile"), "static-core") &&
        strcmp(get("image", "profile"), "dual-libc"))
        return die(path, 0, "profile must be static-core or dual-libc");
    if (get("image", "boot-test") && strcmp(get("image", "boot-test"), "required") &&
        strcmp(get("image", "boot-test"), "build-only"))
        return die(path, 0, "boot-test must be required or build-only");
    if (!strcmp(get("image", "profile"), "dual-libc") &&
        (!get("packages", "glibc") || !get("packages", "musl") || !get("image", "musl-cc")))
        return die(path, 0, "dual-libc requires glibc, musl and musl-cc");
    if (!strcmp(get("image", "install-test") ? get("image", "install-test") : "0", "1") &&
        (!get("packages", "doas") || !get("packages", "storage-tools")))
        return die(path, 0, "install-test requires doas and storage-tools");
    for (i = 0; i < source_count; ++i)
        if (!sources[i].type ||
            (strcmp(sources[i].type, "holy-http") && strcmp(sources[i].type, "holy-git")) ||
            !sources[i].url || !sources[i].index ||
            !digest_valid(sources[i].index) ||
            (!strcmp(sources[i].type, "holy-git") && !sources[i].commit) ||
            (strcmp(sources[i].type, "holy-git") && sources[i].commit) ||
            (sources[i].commit &&
             ((strlen(sources[i].commit) != 40 && strlen(sources[i].commit) != 64) ||
              strspn(sources[i].commit, "0123456789abcdef") != strlen(sources[i].commit))) ||
            (sources[i].mirror && sources[i].ca_file) ||
            (sources[i].trust && strcmp(sources[i].trust, "warn") &&
             strcmp(sources[i].trust, "require") && strcmp(sources[i].trust, "ignore")) ||
            (sources[i].trust && !strcmp(sources[i].trust, "require") && !sources[i].key[0]) ||
            (sources[i].embed_mirror && strcmp(sources[i].embed_mirror, "yes") &&
             strcmp(sources[i].embed_mirror, "no")) ||
            (sources[i].ca_file && (strchr(sources[i].ca_file, '\n') ||
                                    strchr(sources[i].ca_file, '\r'))) ||
            (sources[i].mirror && (strchr(sources[i].mirror, '\n') ||
                                   strchr(sources[i].mirror, '\r'))))
            return die(path, 0, "source requires native type, url, index-sha256 and Git commit when applicable");
    for (i = 0; i < sizeof options / sizeof options[0]; ++i) {
        char *alias;
        if (strcmp(options[i].section, "packages") || !options[i].value) continue;
        alias = reference_alias(options[i].value);
        if (alias && (!source_for(alias) ||
                      (!strcmp(options[i].key, "doas") ||
                       !strcmp(options[i].key, "storage-tools")))) {
            free(alias);
            return die(path, 0, "package source reference is unknown or unsupported");
        }
        free(alias);
    }
    for (i = 0; i < additional_count; ++i) {
        char *alias = reference_alias(additional[i]);
        if (alias && !source_for(alias)) {
            free(alias);
            return die(path, 0, "additional package refers to unknown source");
        }
        free(alias);
    }
    return 0;
}

static int env(const char *name, const char *value)
{
    return setenv(name, value ? value : "", 1) == 0;
}

static char *source_path(const char *dir, const char *alias, const char *suffix)
{
    size_t a = strlen(dir), b = strlen(alias), c = strlen(suffix);
    char *path;
    if (c > (size_t)-1 - 2 || b > (size_t)-1 - c - 2 ||
        a > (size_t)-1 - b - c - 2) return NULL;
    path = malloc(a + b + c + 2);
    if (path) snprintf(path, a + b + c + 2, "%s/%s%s", dir, alias, suffix);
    return path;
}

static int quote(FILE *out, const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    if (fputc('"', out) == EOF) return 0;
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') {
            if (fputc('\\', out) == EOF || fputc(*p, out) == EOF) return 0;
        } else if (*p < 32 || *p == 127) {
            if (fprintf(out, "\\x%02x", *p) < 0) return 0;
        } else if (fputc(*p, out) == EOF) return 0;
    }
    return fputc('"', out) != EOF;
}

static void remove_source_inputs(const char *dir)
{
    char *path;
    size_t i;
    if (!dir) return;
    path = source_path(dir, "sources", ".conf");
    if (path) { unlink(path); free(path); }
    path = source_path(dir, "aliases", "");
    if (path) { unlink(path); free(path); }
    path = source_path(dir, "effective", ".conf");
    if (path) { unlink(path); free(path); }
    for (i = 0; i < source_count; ++i) {
        path = source_path(dir, sources[i].alias, ".index");
        if (path) { unlink(path); free(path); }
        path = source_path(dir, sources[i].alias, ".commit");
        if (path) { unlink(path); free(path); }
        path = source_path(dir, sources[i].alias, ".ca");
        if (path) { unlink(path); free(path); }
        path = source_path(dir, sources[i].alias, ".mirror");
        if (path) { unlink(path); free(path); }
        path = source_path(dir, sources[i].alias, ".embed");
        if (path) { unlink(path); free(path); }
    }
    rmdir(dir);
}

static int write_option(FILE *out, const char *key, const char *value)
{
    return fprintf(out, "%s ", key) >= 0 && quote(out, value) &&
           fputc('\n', out) != EOF;
}

static int effective_config(const char *dir, char **result, char hash[65])
{
    static const char digits[] = "0123456789abcdef";
    EVP_MD_CTX *sha = NULL;
    unsigned char digest[32], buffer[8192];
    unsigned digest_length;
    char *path = source_path(dir, "effective", ".conf");
    FILE *out = NULL, *input = NULL;
    size_t i, j, count;
    int ok = 1;
    *result = NULL;
    if (!path || !(out = fopen(path, "wx"))) { free(path); return 0; }
    for (j = 0; j < 3 && ok; ++j) {
        const char *section = j == 0 ? "image" : j == 1 ? "packages" : "resolver";
        if (j == 2 && !get("resolver", "answers")) continue;
        if (fprintf(out, "[%s]\n", section) < 0) { ok = 0; break; }
        for (i = 0; i < sizeof options / sizeof options[0]; ++i)
            if (!strcmp(options[i].section, section) && options[i].value &&
                !write_option(out, options[i].key, options[i].value)) { ok = 0; break; }
        if (j) for (i = 0; i < additional_count; ++i)
            if (!write_option(out, "add", additional[i])) { ok = 0; break; }
    }
    for (i = 0; i < source_count && ok; ++i) {
        const struct source *s = &sources[i];
        if (fprintf(out, "[source %s]\n", s->alias) < 0 ||
            !write_option(out, "type", s->type) ||
            !write_option(out, "url", s->url) ||
            !write_option(out, "index-sha256", s->index) ||
            (s->commit && !write_option(out, "commit", s->commit)) ||
            (s->trust && !write_option(out, "trust", s->trust)) ||
            (s->key[0] && !write_option(out, "public-key-ed25519", s->key)) ||
            (s->ca_file && !write_option(out, "ca-file", s->ca_file)) ||
            (s->mirror && !write_option(out, "mirror", s->mirror)) ||
            (s->embed_mirror && !write_option(out, "embed-mirror", s->embed_mirror))) ok = 0;
    }
    if (ok && (fputs("[docs]\ninclude installed-man-pages\n", out) == EOF ||
               !write_option(out, "output", get("docs", "output")))) ok = 0;
    if (fclose(out)) ok = 0;
    if (!ok || !(input = fopen(path, "rb")) || !(sha = EVP_MD_CTX_new()) ||
        EVP_DigestInit_ex(sha, EVP_sha256(), NULL) != 1) goto failed;
    while ((count = fread(buffer, 1, sizeof buffer, input)) > 0)
        if (EVP_DigestUpdate(sha, buffer, count) != 1) goto failed;
    if (ferror(input) || EVP_DigestFinal_ex(sha, digest, &digest_length) != 1 ||
        digest_length != sizeof digest) goto failed;
    for (i = 0; i < sizeof digest; ++i) {
        hash[i * 2] = digits[digest[i] >> 4];
        hash[i * 2 + 1] = digits[digest[i] & 15];
    }
    hash[64] = 0;
    fclose(input);
    EVP_MD_CTX_free(sha);
    *result = path;
    return 1;
failed:
    if (input) fclose(input);
    EVP_MD_CTX_free(sha);
    unlink(path);
    free(path);
    return 0;
}

static int write_source_inputs(char **result)
{
    char *dir = strdup("/tmp/holygetiso-XXXXXX");
    char *path = NULL;
    FILE *out = NULL, *aliases = NULL;
    size_t i;
    int ok = 1;
    *result = NULL;
    if (!dir || !mkdtemp(dir)) { free(dir); return 0; }
    path = source_path(dir, "sources", ".conf");
    out = path ? fopen(path, "wx") : NULL;
    free(path);
    path = source_path(dir, "aliases", "");
    aliases = path ? fopen(path, "wx") : NULL;
    free(path);
    if (!out || !aliases) ok = 0;
    for (i = 0; i < source_count && ok; ++i) {
        FILE *pin, *ca;
        int written;
        path = source_path(dir, sources[i].alias, ".index");
        pin = path ? fopen(path, "wx") : NULL;
        free(path);
        if (!pin) { ok = 0; break; }
        written = fprintf(pin, "%s\n", sources[i].index) >= 0;
        if (fclose(pin)) written = 0;
        if (!written) { ok = 0; break; }
        if (sources[i].commit) {
            path = source_path(dir, sources[i].alias, ".commit");
            ca = path ? fopen(path, "wx") : NULL;
            free(path);
            if (!ca) { ok = 0; break; }
            written = fprintf(ca, "%s\n", sources[i].commit) >= 0;
            if (fclose(ca)) written = 0;
            if (!written) { ok = 0; break; }
        }
        if (sources[i].ca_file) {
            path = source_path(dir, sources[i].alias, ".ca");
            ca = path ? fopen(path, "wx") : NULL;
            free(path);
            if (!ca) { ok = 0; break; }
            written = fprintf(ca, "%s\n", sources[i].ca_file) >= 0;
            if (fclose(ca)) written = 0;
            if (!written) { ok = 0; break; }
        }
        if (sources[i].mirror) {
            path = source_path(dir, sources[i].alias, ".mirror");
            ca = path ? fopen(path, "wx") : NULL;
            free(path);
            if (!ca) { ok = 0; break; }
            written = fprintf(ca, "%s\n", sources[i].mirror) >= 0;
            if (fclose(ca)) written = 0;
            if (!written) { ok = 0; break; }
        }
        if (sources[i].embed_mirror && !strcmp(sources[i].embed_mirror, "yes")) {
            path = source_path(dir, sources[i].alias, ".embed");
            ca = path ? fopen(path, "wx") : NULL;
            free(path);
            if (!ca) { ok = 0; break; }
            written = fputs("yes\n", ca) >= 0;
            if (fclose(ca)) written = 0;
            if (!written) { ok = 0; break; }
        }
        if (fprintf(aliases, "%s\n", sources[i].alias) < 0 ||
            fprintf(out, "[source %s]\ntype %s\nurl ", sources[i].alias,
                    sources[i].type) < 0 ||
            !quote(out, sources[i].url) || fputc('\n', out) == EOF ||
            (sources[i].trust && !write_option(out, "trust", sources[i].trust)) ||
            (sources[i].key[0] && !write_option(out, "public-key-ed25519", sources[i].key))) ok = 0;
    }
    if (out && fclose(out)) ok = 0;
    if (aliases && fclose(aliases)) ok = 0;
    if (!ok) { remove_source_inputs(dir); free(dir); return 0; }
    *result = dir;
    return 1;
}

static int check_source_inputs(const char *dir)
{
    char *path = source_path(dir, "sources", ".conf");
    char *const args[] = {"./holypkg", "config", "check", path, NULL};
    pid_t child;
    int status, rc;
    if (!path) return 1;
    child = fork();
    if (child < 0) { free(path); return 1; }
    if (!child) {
        execv(args[0], args);
        _exit(127);
    }
    do { rc = waitpid(child, &status, 0); } while (rc < 0 && errno == EINTR);
    free(path);
    if (rc < 0 || !WIFEXITED(status)) return 1;
    return WEXITSTATUS(status);
}

int main(int argc, char **argv)
{
    char hash[65], *config, *source_dir = NULL, *effective = NULL;
    char **command;
    pid_t child;
    size_t i, used;
    int status, rc, check = argc == 3 && !strcmp(argv[1], "--check");
    if (argc == 4 && !strcmp(argv[1], "--export-inputs")) {
        char *const export_command[] = {"sh", "tools/export-image-inputs.sh", argv[2], argv[3], NULL};
        if (access("tools/export-image-inputs.sh", R_OK)) {
            fputs("holygetiso: run from the Holy repository\n", stderr);
            return 6;
        }
        child = fork();
        if (child < 0) { perror("fork"); return 1; }
        if (!child) { execvp("sh", export_command); perror("sh"); _exit(1); }
        do { rc = waitpid(child, &status, 0); } while (rc < 0 && errno == EINTR);
        if (rc < 0) { perror("waitpid"); return 1; }
        return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    }
    if ((!check && argc != 2) || (check && argc != 3)) {
        fprintf(stderr, "usage: holygetiso [--check] CONFIG | holygetiso --export-inputs IMAGE_OUTPUT DIRECTORY\n");
        return 2;
    }
    config = realpath(argv[check ? 2 : 1], NULL);
    if (!config) { perror(argv[check ? 2 : 1]); return 6; }
    rc = parse(config);
    if (rc) { free(config); return rc; }
    if (!write_source_inputs(&source_dir) ||
        !effective_config(source_dir, &effective, hash)) {
        fprintf(stderr, "holygetiso: cannot freeze effective config\n");
        remove_source_inputs(source_dir); free(source_dir); free(config);
        return 6;
    }
    if (source_count) {
        if (access("./holypkg", X_OK)) {
            fprintf(stderr, "holygetiso: holypkg required for source config\n");
            remove_source_inputs(source_dir); free(effective); free(source_dir);
            free(config); return 6;
        }
        rc = check_source_inputs(source_dir);
        if (rc) {
            remove_source_inputs(source_dir); free(effective); free(source_dir); free(config);
            return rc;
        }
    }
    if (check) {
        printf("config-sha256 %s\narch %s\nprofile %s\noutput %s\n",
               hash, get("image", "arch"), get("image", "profile"),
               get("image", "output"));
        for (i = 0; i < additional_count; ++i)
            printf("add %s\n", additional[i]);
        for (i = 0; i < sizeof options / sizeof options[0]; ++i)
            if (!strcmp(options[i].section, "packages") && options[i].value &&
                strchr(options[i].value, ':'))
                printf("core %s %s\n", options[i].key, options[i].value);
        for (i = 0; i < source_count; ++i)
            printf("source %s index %s\n", sources[i].alias, sources[i].index);
        remove_source_inputs(source_dir); free(effective); free(source_dir); free(config);
        return 0;
    }
    if (access("tools/bootstrap-image.sh", R_OK) || access("./holypkg", X_OK)) {
        fprintf(stderr, "holygetiso: run from the Holy repository after make\n");
        remove_source_inputs(source_dir); free(effective); free(source_dir); free(config); return 6;
    }
    if (!env("ARCH", get("image", "arch")) ||
        !env("IMAGE_PROFILE", get("image", "profile")) ||
        !env("ROOT_STORAGE", get("image", "root-storage")) ||
        !env("LIBC_BOOT_STATE", get("image", "libc-boot-state") ? get("image", "libc-boot-state") : "present") ||
        !env("NETWORK_RECOVERY", get("image", "network-recovery") ? get("image", "network-recovery") : "off") ||
        !env("INSTALL_TEST", get("image", "install-test") ? get("image", "install-test") : "0") ||
        !env("IMAGE_BOOT_TEST", get("image", "boot-test") ? get("image", "boot-test") : "required") ||
        !env("INSTALL_FIRMWARE", get("image", "install-firmware") ? get("image", "install-firmware") : "") ||
        !env("STATIC_HOLYINSTALL", get("image", "static-holyinstall")) ||
        !env("GLIBC_PACKAGE", get("packages", "glibc")) ||
        !env("MUSL_PACKAGE", get("packages", "musl")) ||
        !env("DOAS_PACKAGE", get("packages", "doas")) ||
        !env("STORAGE_TOOLS_PACKAGE", get("packages", "storage-tools")) ||
        !env("GLIBC_CC", get("image", "glibc-cc") ? get("image", "glibc-cc") : "gcc") ||
        !env("MUSL_CC", get("image", "musl-cc")) ||
        !env("HOLY_IMAGE_CONFIG_SHA256", hash) ||
        !env("HOLY_IMAGE_CONFIG_FILE", effective) ||
        !env("HOLY_IMAGE_ANSWERS", get("resolver", "answers")) ||
        !env("HOLY_IMAGE_ANSWERS_SHA256", get("resolver", "answers-sha256")) ||
        !env("HOLY_IMAGE_SOURCE_DIR", source_count ? source_dir : NULL)) {
        perror("setenv"); remove_source_inputs(source_dir); free(source_dir);
        free(effective); free(config); return 1;
    }
    if (additional_count > (((size_t)-1 / sizeof(*command)) - 33) / 3) {
        remove_source_inputs(source_dir); free(effective); free(source_dir); free(config); return 2;
    }
    command = calloc(33 + additional_count * 3, sizeof(*command));
    if (!command) {
        remove_source_inputs(source_dir); free(effective); free(source_dir); free(config); return 1;
    }
    command[0] = "sh";
    command[1] = "tools/bootstrap-image.sh";
    command[2] = "./holypkg";
    command[3] = (char *)get("image", "static-holypkg");
    command[4] = (char *)get("image", "static-cc");
    command[5] = (char *)get("packages", "busybox");
    command[6] = (char *)get("packages", "dinit");
    command[7] = (char *)get("packages", "mdevd");
    command[8] = (char *)get("image", "kernel-image");
    command[9] = (char *)get("image", "kernel-version");
    command[10] = (char *)get("image", "limine-dir");
    command[11] = (char *)get("image", "output");
    used = 12;
    for (i = 0; i < sizeof options / sizeof options[0]; ++i) {
        char *alias;
        if (strcmp(options[i].section, "packages") || !options[i].value) continue;
        if (!strcmp(options[i].key, "doas") ||
            !strcmp(options[i].key, "storage-tools")) continue;
        alias = reference_alias(options[i].value);
        if (!alias) continue;
        command[used++] = "--core";
        command[used++] = (char *)options[i].key;
        command[used++] = alias;
        command[used++] = strchr(options[i].value, ':') + 1;
    }
    for (i = 0; i < additional_count; ++i) {
        char *alias = reference_alias(additional[i]);
        if (alias) {
            command[used++] = "--source";
            command[used++] = alias;
            command[used++] = strchr(additional[i], ':') + 1;
        } else {
            command[used++] = "--local";
            command[used++] = additional[i];
        }
    }
    child = fork();
    if (child < 0) {
        perror("fork"); remove_source_inputs(source_dir); free(effective); free(source_dir);
        free(command); free(config); return 1;
    }
    if (!child) {
        execvp("sh", command);
        perror("sh"); _exit(1);
    }
    do { rc = waitpid(child, &status, 0); } while (rc < 0 && errno == EINTR);
    for (i = 12; i < used; ++i) {
        if (!strcmp(command[i], "--source")) free(command[++i]);
        else if (!strcmp(command[i], "--core")) { ++i; free(command[++i]); }
    }
    free(command);
    remove_source_inputs(source_dir);
    free(effective);
    free(source_dir);
    free(config);
    if (rc < 0) { perror("waitpid"); return 1; }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 1;
}
