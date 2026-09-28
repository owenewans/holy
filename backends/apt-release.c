#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "apt-release.h"
#include "apt.h"
#include "../src/fetch.h"
#include "../src/stage.h"
#include "../src/source.h"

#include <curl/curl.h>
#include <openssl/evp.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

static int hex_hash(const char *value)
{
    return value && strlen(value) == 64 && strspn(value, "0123456789abcdef") == 64;
}

static int segment(const char *value)
{
    size_t i, size = value ? strlen(value) : 0;
    if (!size || size > 128 || !strcmp(value, ".") || !strcmp(value, "..")) return 0;
    for (i = 0; i < size; ++i)
        if (!((value[i] >= 'a' && value[i] <= 'z') ||
              (value[i] >= 'A' && value[i] <= 'Z') ||
              (value[i] >= '0' && value[i] <= '9') ||
              value[i] == '.' || value[i] == '_' || value[i] == '-')) return 0;
    return 1;
}

static char *path_name(const char *directory, const char *name)
{
    size_t a = strlen(directory), b = strlen(name);
    char *path;
    if (a > SIZE_MAX - b - 2 || !(path = malloc(a + b + 2))) return NULL;
    memcpy(path, directory, a);
    path[a] = '/';
    memcpy(path + a + 1, name, b + 1);
    return path;
}

static char *child_directory(const char *base, const char *name)
{
    char *path = holy_fetch_child_url(base, name), *next;
    size_t size;
    if (!path) return NULL;
    size = strlen(path);
    next = realloc(path, size + 2);
    if (!next) { free(path); return NULL; }
    next[size] = '/'; next[size + 1] = 0;
    return next;
}

static int hash_file(const char *path, char hash[65], off_t *size, off_t limit)
{
    unsigned char bytes[65536], result[32];
    unsigned int count;
    EVP_MD_CTX *ctx = NULL;
    struct stat st;
    ssize_t got;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    int ok = 0;
    size_t i;
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        st.st_size > limit || !(ctx = EVP_MD_CTX_new()) ||
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto done;
    for (;;) {
        got = read(fd, bytes, sizeof bytes);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) break;
        if (EVP_DigestUpdate(ctx, bytes, (size_t)got) != 1) goto done;
    }
    if (got < 0 || EVP_DigestFinal_ex(ctx, result, &count) != 1 || count != 32) goto done;
    for (i = 0; i < 32; ++i) snprintf(hash + i * 2, 3, "%02x", result[i]);
    if (size) *size = st.st_size;
    ok = 1;
done:
    EVP_MD_CTX_free(ctx);
    if (fd >= 0) close(fd);
    return ok;
}

int holy_apt_key_fingerprint(const char *keyring, char hash[65])
{
    return keyring && hash && hash_file(keyring, hash, NULL, 1024 * 1024);
}

static int copy_file(const char *source, const char *target, off_t limit)
{
    struct stat st;
    char buffer[65536];
    ssize_t got;
    int input = open(source, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    int output = -1, ok = 0;
    if (input < 0 || fstat(input, &st) || !S_ISREG(st.st_mode) ||
        st.st_size < 0 || st.st_size > limit) goto done;
    output = open(target, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (output < 0) goto done;
    for (;;) {
        size_t written = 0;
        got = read(input, buffer, sizeof buffer);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) break;
        while (written < (size_t)got) {
            ssize_t n = write(output, buffer + written, (size_t)got - written);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) goto done;
            written += (size_t)n;
        }
    }
    ok = !got && !fsync(output);
done:
    if (input >= 0) close(input);
    if (output >= 0) close(output);
    if (!ok) unlink(target);
    return ok;
}

static int valid_contents(const char *path)
{
    char bytes[65536];
    unsigned char magic[2];
    size_t total = 0;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    gzFile input;
    int got, status, ok = 0;
    if (fd < 0) return 0;
    if (read(fd, magic, sizeof magic) != (ssize_t)sizeof magic ||
        magic[0] != 0x1f || magic[1] != 0x8b || lseek(fd, 0, SEEK_SET) < 0) {
        close(fd); return 0;
    }
    input = gzdopen(fd, "rb");
    if (!input) { close(fd); return 0; }
    for (;;) {
        got = gzread(input, bytes, sizeof bytes);
        if (got < 0 || total > 512u * 1024u * 1024u - (size_t)got) break;
        if (!got) { ok = total > 0; break; }
        total += (size_t)got;
    }
    gzerror(input, &status);
    if (status != Z_OK && status != Z_STREAM_END) ok = 0;
    if (gzclose(input) != Z_OK) ok = 0;
    return ok;
}

static int verify_signature(const char *key, const char *signature, const char *release)
{
    pid_t child = fork();
    int status;
    if (child < 0) return 1;
    if (!child) {
        execlp("gpgv", "gpgv", "--quiet", "--keyring", key,
               signature, release, (char *)NULL);
        _exit(127);
    }
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return 1;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return 0;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 127) return 6;
    return 4;
}

static int verify_inline(const char *key, const char *inrelease)
{
    pid_t child = fork();
    int status;
    if (child < 0) return 1;
    if (!child) {
        execlp("gpgv", "gpgv", "--quiet", "--keyring", key,
               inrelease, (char *)NULL);
        _exit(127);
    }
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return 1;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return 0;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 127) return 6;
    return 4;
}

static int extract_inline(const char *input, const char *output)
{
    int fd = open(input, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    int out = -1, ok = 0, stage = 0;
    FILE *file = NULL;
    char *line = NULL;
    size_t capacity = 0, total = 0;
    ssize_t length;
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size > 8 * 1024 * 1024) goto done;
    file = fdopen(fd, "r");
    if (!file) goto done;
    fd = -1;
    out = open(output, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (out < 0) goto done;
    while ((length = getline(&line, &capacity, file)) >= 0) {
        size_t n = (size_t)length;
        if (!n || n > 65536 || memchr(line, 0, n) || line[n - 1] != '\n' ||
            (n >= 2 && line[n - 2] == '\r')) goto done;
        if (stage == 0) {
            if (strcmp(line, "-----BEGIN PGP SIGNED MESSAGE-----\n")) goto done;
            stage = 1;
        } else if (stage == 1) {
            if (n == 1) stage = 2;
            else if (strncmp(line, "Hash: ", 6) || n > 128) goto done;
        } else if (stage == 2) {
            const char *body = line;
            size_t written = 0;
            if (!strcmp(line, "-----BEGIN PGP SIGNATURE-----\n")) { stage = 3; continue; }
            if (line[0] == '-' && (n < 2 || line[1] != ' ')) goto done;
            if (n >= 2 && line[0] == '-' && line[1] == ' ') { body += 2; n -= 2; }
            if (n >= 2 && (body[n - 2] == ' ' || body[n - 2] == '\t')) goto done;
            if (total > 4 * 1024 * 1024 - n) goto done;
            while (written < n) {
                ssize_t count = write(out, body + written, n - written);
                if (count < 0 && errno == EINTR) continue;
                if (count <= 0) goto done;
                written += (size_t)count;
            }
            total += n;
        } else if (stage == 3) {
            if (!strcmp(line, "-----END PGP SIGNATURE-----\n")) stage = 4;
            else if (n > 128) goto done;
        } else goto done;
    }
    ok = !ferror(file) && stage == 4 && !fsync(out);
done:
    free(line);
    if (file) fclose(file);
    if (fd >= 0) close(fd);
    if (out >= 0) close(out);
    if (!ok) unlink(output);
    return ok;
}

static int release_entry(const char *release, const char *path, const char *suite,
                         char hash[65], off_t *size)
{
    int fd = open(release, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    FILE *stream = NULL;
    struct stat st;
    char *line = NULL;
    size_t capacity = 0, lines = 0;
    ssize_t length;
    int in_sha256 = 0, seen_section = 0, found = 0, suite_match = 0;
    int valid_until_seen = 0, ok = 0;
    time_t now = time(NULL);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size > 4 * 1024 * 1024 || now == (time_t)-1) goto done;
    stream = fdopen(fd, "r");
    if (!stream) goto done;
    fd = -1;
    while ((length = getline(&line, &capacity, stream)) >= 0) {
        char digest[65], filename[1025], trailing;
        unsigned long long amount;
        if (++lines > 100000 || length > 65536 || memchr(line, 0, (size_t)length)) goto done;
        if (!strncasecmp(line, "Valid-Until:", 12)) {
            time_t deadline = curl_getdate(line + 12, NULL);
            if (valid_until_seen++ || deadline == (time_t)-1 || deadline < now) goto done;
        }
        if ((!strncasecmp(line, "Suite:", 6) && line[6] == ' ') ||
            (!strncasecmp(line, "Codename:", 9) && line[9] == ' ')) {
            const char *value = line + (line[0] == 'S' || line[0] == 's' ? 6 : 9);
            size_t length;
            while (*value == ' ' || *value == '\t') ++value;
            length = strcspn(value, "\r\n");
            if (length == strlen(suite) && !memcmp(value, suite, length))
                suite_match = 1;
        }
        if (!strncasecmp(line, "SHA256:", 7)) {
            if (seen_section++) goto done;
            in_sha256 = 1;
            continue;
        }
        if (line[0] != ' ' && line[0] != '\t') in_sha256 = 0;
        if (!in_sha256) continue;
        if (sscanf(line, " %64s %llu %1024s %c", digest, &amount, filename, &trailing) != 3 ||
            !hex_hash(digest)) goto done;
        if (!strcmp(filename, path)) {
            if (found++ || amount > 64ULL * 1024 * 1024) goto done;
            strcpy(hash, digest);
            *size = (off_t)amount;
        }
    }
    ok = !ferror(stream) && seen_section == 1 && found == 1 && suite_match;
done:
    if (stream) fclose(stream);
    if (fd >= 0) close(fd);
    free(line);
    return ok;
}

int holy_apt_verify_release(const char *catalog, const char *index_hash)
{
    char *proof = path_name(catalog, "release-proof");
    char *release = NULL, *signature = NULL, *key = NULL, *original = NULL;
    char *extracted = NULL;
    char release_hash[65], key_hash[65], path[1025], suite[129], actual[65];
    char stated_release[65], stated_key[65], stated_signature[65], extra[128];
    char scratch[] = "/tmp/holy-apt-verify-XXXXXX";
    struct stat st;
    FILE *stream = NULL;
    off_t expected_size, actual_size;
    int result = -1, fd, inline_signature = 0, scratch_created = 0;
    if (!proof) return -1;
    fd = open(proof, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT) { result = 0; goto done; }
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size > 2048) {
        if (fd >= 0) close(fd);
        goto done;
    }
    stream = fdopen(fd, "r");
    if (!stream) { close(fd); goto done; }
    release = path_name(catalog, "release");
    if (!release || fscanf(stream, "release-sha256 %64s\nkey-sha256 %64s\nsuite %128s\nindex-path %1024s\n",
               stated_release, stated_key, suite, path) != 4 ||
        !hex_hash(stated_release) || !hex_hash(stated_key) ||
        !segment(suite) ||
        !strchr(path, '/') || path[0] == '/' || strstr(path, "..")) goto done;
    if (fgets(extra, sizeof extra, stream)) {
        if (strcmp(extra, "signature-kind inrelease\n") ||
            fscanf(stream, "signature-sha256 %64s\n", stated_signature) != 1 ||
            !hex_hash(stated_signature) || fgetc(stream) != EOF) goto done;
        inline_signature = 1;
    } else if (ferror(stream)) goto done;
    if (!release_entry(release, path, suite, actual, &expected_size) ||
        strcmp(actual, index_hash)) goto done;
    signature = path_name(catalog, inline_signature ? "inrelease" : "release.gpg");
    key = path_name(catalog, "keyring");
    original = path_name(catalog, "original");
    if (!release || !signature || !key || !original ||
        !hash_file(release, release_hash, NULL, 4 * 1024 * 1024) ||
        strcmp(release_hash, stated_release) ||
        !hash_file(signature, actual, NULL,
                   inline_signature ? 8 * 1024 * 1024 : 1024 * 1024) ||
        (inline_signature && strcmp(actual, stated_signature)) ||
        !hash_file(key, key_hash, NULL, 1024 * 1024) ||
        strcmp(key_hash, stated_key) ||
        !hash_file(original, actual, &actual_size, 64 * 1024 * 1024) ||
        strcmp(actual, index_hash) || actual_size != expected_size) goto done;
    if (inline_signature) {
        if (!mkdtemp(scratch)) goto done;
        scratch_created = 1;
        extracted = path_name(scratch, "release");
        if (!extracted) goto done;
        {
            int verified = verify_inline(key, signature);
            if (verified) { if (verified == 6) result = -2; goto done; }
        }
        if (!extract_inline(signature, extracted)) goto done;
        if (!hash_file(extracted, actual, NULL, 4 * 1024 * 1024) ||
            strcmp(actual, stated_release)) goto done;
        result = 2;
    } else {
        int verified = verify_signature(key, signature, release);
        if (verified) { if (verified == 6) result = -2; goto done; }
        result = 1;
    }
done:
    if (stream) fclose(stream);
    if (extracted) unlink(extracted);
    if (scratch_created) rmdir(scratch);
    free(extracted);
    free(proof); free(release); free(signature); free(key); free(original);
    return result;
}

int holy_apt_verify_files(const char *catalog)
{
    char *proof = path_name(catalog, "file-proof"), *release_proof = NULL;
    char *release = NULL, *contents = NULL;
    char suite[129], path[1025], stated_hash[65], expected_hash[65], actual[65];
    char package_path[1025], release_suite[129], component[129], arch[129];
    char release_hash[65], key_hash[65], wanted[512], trailing;
    unsigned long long stated_size, retrieved_at;
    struct stat st;
    FILE *file = NULL, *bound = NULL;
    off_t expected_size, actual_size;
    int fd, bound_fd = -1, result = -1;
    if (!proof) return -1;
    fd = open(proof, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT) { result = 0; goto done; }
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size > 2048) {
        if (fd >= 0) close(fd);
        goto done;
    }
    file = fdopen(fd, "r");
    if (!file) { close(fd); goto done; }
    if (fscanf(file, "suite %128s\nfile-index-path %1024s\nfile-index-sha256 %64s\nfile-index-size %llu\nfile-index-coverage partial\nretrieved-at %llu\n",
               suite, path, stated_hash, &stated_size, &retrieved_at) != 5 ||
        fgetc(file) != EOF || !retrieved_at ||
        !segment(suite) || !hex_hash(stated_hash) || path[0] == '/' ||
        !strchr(path, '/') || strstr(path, "..") || stated_size > 64ULL * 1024 * 1024)
        goto done;
    release_proof = path_name(catalog, "release-proof");
    if (!release_proof ||
        (bound_fd = open(release_proof, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)) < 0 ||
        fstat(bound_fd, &st) || !S_ISREG(st.st_mode) || st.st_size > 2048 ||
        !(bound = fdopen(bound_fd, "r")) ||
        fscanf(bound, "release-sha256 %64s\nkey-sha256 %64s\nsuite %128s\nindex-path %1024s\n",
               release_hash, key_hash, release_suite, package_path) != 4 ||
        strcmp(suite, release_suite) ||
        sscanf(package_path, "%128[^/]/binary-%128[^/]/Packages.gz%c",
               component, arch, &trailing) != 2 ||
        !segment(component) || !segment(arch) ||
        snprintf(wanted, sizeof wanted, "%s/Contents-%s.gz", component, arch) >=
        (int)sizeof wanted || strcmp(path, wanted)) goto done;
    release = path_name(catalog, "release");
    contents = path_name(catalog, "contents.gz");
    if (!release || !contents ||
        !release_entry(release, path, suite, expected_hash, &expected_size) ||
        strcmp(stated_hash, expected_hash) || stated_size != (unsigned long long)expected_size ||
        !hash_file(contents, actual, &actual_size, 64 * 1024 * 1024) ||
        strcmp(actual, expected_hash) || actual_size != expected_size) goto done;
    result = 1;
done:
    if (file) fclose(file);
    if (bound) fclose(bound);
    else if (bound_fd >= 0) close(bound_fd);
    free(proof); free(release_proof); free(release); free(contents);
    return result;
}

static int sync_release(const char *base, const char *suite,
                        const char *component, const char *arch,
                        const char *source, const char *keyring,
                        const char *output, const char *ca_file,
                        const char *root, const char *source_id,
                        const char *source_key, const char *source_trust,
                        int inrelease, int files)
{
    char *staging = NULL, *catalog = NULL, *key_copy = NULL;
    char *dists = NULL, *suite_url = NULL, *component_url = NULL, *arch_url = NULL;
    char *release_url = NULL, *signature_url = NULL, *index_url = NULL, *files_url = NULL;
    char *release = NULL, *signature = NULL, *index = NULL, *contents = NULL, *target = NULL;
    char release_hash[65] = {0}, signature_hash[65] = {0}, index_hash[65] = {0};
    char key_hash[65], expected_hash[65], files_hash[65] = {0};
    char relative[512], files_relative[512], subdir[160], files_name[160];
    struct stat st;
    off_t expected_size, actual_size, files_size = 0;
    FILE *proof = NULL;
    int dir = -1, parent_fd = -1, result = 1, published = 0;
    char *parent = NULL;
    if (!base || !segment(suite) || !segment(component) || !segment(arch) ||
        !segment(source) || !strcmp(source, "local") || !keyring || !output ||
        !*output || (lstat(output, &st) == 0 || errno != ENOENT)) return 2;
    {
        const char *slash = strrchr(output, '/');
        parent = slash ? strndup(output, slash == output ? 1 : (size_t)(slash - output)) : strdup(".");
        if (!parent) return 1;
        parent_fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (parent_fd < 0) { result = 6; goto done; }
    }
    dists = child_directory(base, "dists");
    suite_url = dists ? child_directory(dists, suite) : NULL;
    component_url = suite_url ? child_directory(suite_url, component) : NULL;
    if (snprintf(subdir, sizeof subdir, "binary-%s", arch) >= (int)sizeof subdir ||
        snprintf(relative, sizeof relative, "%s/%s/Packages.gz", component, subdir) >=
        (int)sizeof relative ||
        snprintf(files_name, sizeof files_name, "Contents-%s.gz", arch) >= (int)sizeof files_name ||
        snprintf(files_relative, sizeof files_relative, "%s/%s", component, files_name) >=
        (int)sizeof files_relative) { result = 2; goto done; }
    arch_url = component_url ? child_directory(component_url, subdir) : NULL;
    release_url = !inrelease && suite_url ? holy_fetch_child_url(suite_url, "Release") : NULL;
    signature_url = suite_url ? holy_fetch_child_url(suite_url,
                                   inrelease ? "InRelease" : "Release.gpg") : NULL;
    index_url = arch_url ? holy_fetch_child_url(arch_url, "Packages.gz") : NULL;
    files_url = files && component_url ? holy_fetch_child_url(component_url, files_name) : NULL;
    if (!index_url || (!inrelease && !release_url) || !signature_url ||
        (files && !files_url)) { result = 2; goto done; }
    staging = malloc(strlen(output) + sizeof ".tmp-XXXXXX");
    if (!staging) goto done;
    sprintf(staging, "%s.tmp-XXXXXX", output);
    if (!mkdtemp(staging)) goto done;
    if (!inrelease) {
        result = holy_fetch_https_foreign_limited(release_url, staging, ca_file,
                                                  release_hash, 4 * 1024 * 1024);
        if (result) goto done;
        release = path_name(staging, release_hash);
    }
    result = holy_fetch_https_foreign_limited(signature_url, staging, ca_file,
                                              signature_hash,
                                              inrelease ? 8 * 1024 * 1024 : 1024 * 1024);
    if (result) goto done;
    signature = path_name(staging, signature_hash);
    key_copy = holy_stage_local(keyring, "holy-apt-key");
    if (!key_copy || (!inrelease && !release) || !signature ||
        !hash_file(key_copy, key_hash, NULL, 1024 * 1024)) { result = 6; goto done; }
    if (source_key && strcmp(source_key, key_hash)) { result = 4; goto done; }
    if (inrelease) release = path_name(staging, "release-clear");
    if (!release) { result = 1; goto done; }
    result = inrelease ? verify_inline(key_copy, signature) :
                         verify_signature(key_copy, signature, release);
    if (result) goto done;
    if (inrelease && !extract_inline(signature, release)) { result = 4; goto done; }
    if (inrelease && !hash_file(release, release_hash, NULL, 4 * 1024 * 1024)) {
        result = 4; goto done;
    }
    if (!release_entry(release, relative, suite, expected_hash, &expected_size)) {
        result = 4; goto done;
    }
    if (files && !release_entry(release, files_relative, suite, files_hash, &files_size)) {
        result = 4; goto done;
    }
    result = holy_fetch_https_foreign_limited(index_url, staging, ca_file,
                                              index_hash, 64 * 1024 * 1024);
    if (result) goto done;
    index = path_name(staging, index_hash);
    if (!index || !hash_file(index, index_hash, &actual_size, 64 * 1024 * 1024) ||
        strcmp(index_hash, expected_hash) || actual_size != expected_size) {
        result = 4; goto done;
    }
    if (files) {
        char received[65];
        result = holy_fetch_https_foreign_limited(files_url, staging, ca_file,
                                                  received, 64 * 1024 * 1024);
        if (result) goto done;
        contents = path_name(staging, received);
        if (!contents || strcmp(received, files_hash) ||
            !hash_file(contents, received, &actual_size, 64 * 1024 * 1024) ||
            actual_size != files_size || !valid_contents(contents)) {
            result = 4; goto done;
        }
    }
    catalog = path_name(staging, "catalog");
    if (!catalog) { result = 1; goto done; }
    result = holy_apt_index_quiet(index, expected_hash, source, base, catalog);
    if (result) goto done;
    target = path_name(catalog, "release");
    if (!target || !copy_file(release, target, 4 * 1024 * 1024)) { result = 1; goto done; }
    free(target); target = path_name(catalog, inrelease ? "inrelease" : "release.gpg");
    if (!target || !copy_file(signature, target,
                             inrelease ? 8 * 1024 * 1024 : 1024 * 1024)) { result = 1; goto done; }
    free(target); target = path_name(catalog, "keyring");
    if (!target || !copy_file(key_copy, target, 1024 * 1024)) { result = 1; goto done; }
    free(target); target = path_name(catalog, "release-proof");
    if (!target || !(proof = fopen(target, "wx"))) { result = 1; goto done; }
    fprintf(proof, "release-sha256 %s\nkey-sha256 %s\nsuite %s\nindex-path %s\n",
            release_hash, key_hash, suite, relative);
    if (inrelease)
        fprintf(proof, "signature-kind inrelease\nsignature-sha256 %s\n", signature_hash);
    {
        int failed = fflush(proof) || fsync(fileno(proof));
        if (fclose(proof)) failed = 1;
        proof = NULL;
        if (failed) { result = 1; goto done; }
    }
    {
        int verified = holy_apt_verify_release(catalog, expected_hash);
        if (verified != (inrelease ? 2 : 1)) {
            result = verified == -2 ? 6 : 4; goto done;
        }
    }
    if (files) {
        time_t retrieved_at = time(NULL);
        if (retrieved_at == (time_t)-1) { result = 1; goto done; }
        free(target); target = path_name(catalog, "contents.gz");
        if (!target || !copy_file(contents, target, 64 * 1024 * 1024)) {
            result = 1; goto done;
        }
        free(target); target = path_name(catalog, "file-proof");
        if (!target || !(proof = fopen(target, "wx"))) { result = 1; goto done; }
        fprintf(proof, "suite %s\nfile-index-path %s\nfile-index-sha256 %s\nfile-index-size %lld\nfile-index-coverage partial\nretrieved-at %lld\n",
                suite, files_relative, files_hash, (long long)files_size,
                (long long)retrieved_at);
        {
            int failed = ferror(proof) || fflush(proof) || fsync(fileno(proof));
            if (fclose(proof)) failed = 1;
            proof = NULL;
            if (failed || holy_apt_verify_files(catalog) != 1) {
                result = 4; goto done;
            }
        }
    }
    if (source_id) {
        char current_id[65], current_key[65];
        char *current_base = NULL, *current_trust = NULL;
        result = holy_source_apt(root, source, current_id, &current_base,
                                 &current_trust, current_key);
        if (!result && (strcmp(current_id, source_id) ||
                        strcmp(current_key, source_key) ||
                        strcmp(current_base, base) ||
                        strcmp(current_trust, source_trust))) result = 3;
        free(current_base); free(current_trust);
        if (result) goto done;
    }
    free(target); target = path_name(catalog, "conversion");
    if (!target) { result = 1; goto done; }
    {
        int marker = open(target, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC);
        char line[128];
        int length = source_id ? snprintf(line, sizeof line,
                                          "release-required yes\nsource-id %s\n", source_id) :
                                 snprintf(line, sizeof line, "release-required yes\n");
        if (marker < 0 || length < 0 || length >= (int)sizeof line ||
            write(marker, line, (size_t)length) != length ||
            fsync(marker)) {
            if (marker >= 0) close(marker);
            result = 1; goto done;
        }
        close(marker);
    }
    dir = open(catalog, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir < 0 || fsync(dir)) { result = 1; goto done; }
#ifdef SYS_renameat2
    if (syscall(SYS_renameat2, AT_FDCWD, catalog, AT_FDCWD, output, 1u)) {
        result = errno == EEXIST ? 2 : 6; goto done;
    }
#else
    result = 6; goto done;
#endif
    published = 1;
    if (fsync(parent_fd)) { result = 1; goto done; }
    printf("apt signed catalog %s release %s index %s\n", output, release_hash, index_hash);
    result = 0;
done:
    if (proof) fclose(proof);
    if (dir >= 0) close(dir);
    if (parent_fd >= 0) close(parent_fd);
    if (!published && catalog) {
        const char *files[] = {"original", "conversion", "release", "release.gpg",
                               "inrelease", "keyring", "release-proof", "contents.gz", "file-proof"};
        size_t i;
        for (i = 0; i < sizeof files / sizeof files[0]; ++i) {
            char *name = path_name(catalog, files[i]);
            if (name) { unlink(name); free(name); }
        }
        rmdir(catalog);
    }
    if (release) unlink(release);
    if (signature) unlink(signature);
    if (index) unlink(index);
    if (contents) unlink(contents);
    if (staging) rmdir(staging);
    if (key_copy) { unlink(key_copy); free(key_copy); }
    free(parent); free(staging); free(catalog); free(dists); free(suite_url); free(component_url);
    free(arch_url); free(release_url); free(signature_url); free(index_url); free(files_url);
    free(release); free(signature); free(index); free(contents); free(target);
    if (result) fprintf(stderr, "holypkg: APT signed sync failed (status %d)\n", result);
    return result;
}

int holy_apt_release_sync(const char *base, const char *suite,
                          const char *component, const char *arch,
                          const char *source, const char *keyring,
                          const char *output, const char *ca_file, int inrelease,
                          int files)
{
    return sync_release(base, suite, component, arch, source, keyring,
                        output, ca_file, NULL, NULL, NULL, NULL, inrelease, files);
}

int holy_apt_release_sync_source(const char *root, const char *alias,
                                 const char *suite, const char *component,
                                 const char *arch, const char *keyring,
                                 const char *output, const char *ca_file,
                                 int inrelease, int files)
{
    char id[65], key[65], actual[65];
    char *base = NULL, *trust = NULL, *snapshot = NULL;
    int result = holy_source_apt(root, alias, id, &base, &trust, key);
    if (result) goto done;
    snapshot = keyring ? holy_stage_local(keyring, "holy-apt-source-key") : NULL;
    if (!key[0] || !snapshot || !holy_apt_key_fingerprint(snapshot, actual)) {
        result = 6; goto done;
    }
    if (strcmp(key, actual)) { result = 4; goto done; }
    result = sync_release(base, suite, component, arch, alias, snapshot,
                          output, ca_file, root, id, key, trust, inrelease, files);
done:
    if (snapshot) { unlink(snapshot); free(snapshot); }
    free(base); free(trust);
    return result;
}
