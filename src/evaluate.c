/* an upstream evaluator, run for an exact foreign expansion. it lives in the working
   environment and is a build and import tool dependency, never a second manager of
   the installed system, so running it is shown as running code. */
#define _GNU_SOURCE 1

#include "evaluate.h"
#include "sandbox.h"

#include <openssl/evp.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* removes a tree this module created, since it owns the only copy */
static void remove_tree(const char *path)
{
    DIR *entries = opendir(path);
    struct dirent *entry;
    if (!entries) return;
    while ((entry = readdir(entries)) != NULL) {
        char *child;
        struct stat st;
        size_t length;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        length = strlen(path) + strlen(entry->d_name) + 2;
        child = malloc(length);
        if (!child) break;
        snprintf(child, length, "%s/%s", path, entry->d_name);
        if (!lstat(child, &st) && S_ISDIR(st.st_mode)) remove_tree(child);
        else unlink(child);
        free(child);
    }
    closedir(entries);
    rmdir(path);
}

/* the string.h searches, read as loops: glibc 2.42 wraps them in a C11 _Generic that
   a C99 build rejects */
static char *last_slash(char *text)
{
    char *found = NULL, *cursor;
    for (cursor = text; *cursor; ++cursor)
        if (*cursor == '/') found = cursor;
    return found;
}

static char *first_of(char *text, const char *accepted)
{
    char *cursor;
    for (cursor = text; *cursor; ++cursor) {
        const char *at = accepted;
        for (; *at; ++at)
            if (*at == *cursor) return cursor;
    }
    return NULL;
}

static char *first_newline(const char *text, size_t length)
{
    size_t i;
    for (i = 0; i < length; ++i)
        if (text[i] == '\n') return (char *)text + i;
    return NULL;
}

static void complain(const char *what, const char *detail)
{
    fprintf(stderr, "holypkg: evaluator %s%s%s\n", what, detail ? ": " : "",
            detail ? detail : "");
}

/* the digest of one file, or 0 when it cannot be read */
static int digest_of(const char *path, char digest[65])
{
    unsigned char buffer[65536], bytes[32];
    unsigned int size = 0;
    size_t got, i;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    FILE *in = context ? fopen(path, "rb") : NULL;
    int ok = 0;
    if (!in || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) goto done;
    while ((got = fread(buffer, 1, sizeof buffer, in)) > 0)
        if (EVP_DigestUpdate(context, buffer, got) != 1) goto done;
    if (ferror(in) || EVP_DigestFinal_ex(context, bytes, &size) != 1 || size != 32) goto done;
    for (i = 0; i < 32; ++i) snprintf(digest + i * 2, 3, "%02x", bytes[i]);
    digest[64] = 0;
    ok = 1;
done:
    if (in) fclose(in);
    EVP_MD_CTX_free(context);
    return ok;
}

int holy_evaluator_consent(const char *program, const char *digest, int approved,
                           int noninteractive)
{
    char answer[32];
    if (approved) return 1;
    if (noninteractive || !isatty(STDIN_FILENO)) {
        fprintf(stderr, "holypkg: the evaluator %s sha256 %s runs the code it carries, so it "
                "needs --yes or a terminal answer\n", program, digest ? digest : "-");
        return 3;
    }
    /* the program digest is in the prompt, since the operator decides which program runs */
    printf("evaluator %s sha256 %s runs code: it expands the foreign recipe as the upstream "
           "builder would\n", program, digest ? digest : "-");
    fflush(stdout);
    fprintf(stderr, "Run the evaluator %s? [y/N/s/e] ", program);
    if (fflush(stderr) || !fgets(answer, sizeof answer, stdin)) return 3;
    if (answer[0] == 'y' || answer[0] == 'Y') return 1;
    if (answer[0] == 's' || answer[0] == 'S') return 0;
    /* n refuses and e exits, and both write nothing */
    return 3;
}

int holy_evaluator_run(const struct holy_evaluator *evaluator,
                       struct holy_evaluator_result *result, int approved,
                       int noninteractive, int *skipped)
{
    /* the input's own directory and the program's own directory, each at the same path
       inside the root, so the evaluator is reachable and nothing else is */
    struct holy_sandbox_mount read_only[2];
    size_t read_only_count = 0;
    char *program_directory = NULL;
    struct holy_sandbox sandbox;
    struct stat st;
    char *work = NULL, *captured = NULL;
    char *entries[3];
    char **argv = NULL;
    size_t count = 0, i, used = 0, length;
    int status, consent, ok = 0;
    memset(&sandbox, 0, sizeof sandbox);
    memset(result, 0, sizeof *result);
    if (!evaluator || !evaluator->path || evaluator->path[0] != '/') {
        complain("program path is not absolute", evaluator ? evaluator->path : NULL);
        return 2;
    }
    if (lstat(evaluator->path, &st) || !S_ISREG(st.st_mode) ||
        !(st.st_mode & 0111)) {
        complain("program is not an executable file", evaluator->path);
        return 2;
    }
    if (!digest_of(evaluator->path, result->program_digest)) {
        complain("program could not be hashed", evaluator->path);
        return 6;
    }
    if (skipped) *skipped = 0;
    consent = holy_evaluator_consent(evaluator->path, result->program_digest, approved,
                                     noninteractive);
    /* a skip converts from the text alone, which is what the operator asked for */
    if (consent != 1) {
        if (skipped) *skipped = consent == 0;
        return consent ? 3 : 0;
    }
    if (holy_sandbox_probe()) {
        complain("namespaces are unavailable on this host", NULL);
        return 6;
    }
    /* the work directory holds the build root the evaluator runs in and the file its
       output lands in */
    length = strlen(evaluator->path) + 32;
    work = malloc(length);
    if (!work) return 1;
    snprintf(work, length, "/tmp/holy-evaluate-%ld", (long)getpid());
    if (mkdir(work, 0700) && errno != EEXIST) {
        complain("create the evaluator work directory", strerror(errno));
        free(work);
        return 6;
    }
    sandbox.work = work;
    sandbox.uid = 0;
    sandbox.output[0] = -1;
    sandbox.output[1] = -1;
    /* the evaluator reads the file it expands, so its directory is bound read-only and
       nothing else of the caller's tree is reachable */
    if (evaluator->cwd) {
        read_only[read_only_count].source = evaluator->cwd;
        read_only[read_only_count].destination = evaluator->cwd;
        read_only[read_only_count].writable = 0;
        ++read_only_count;
    }
    {
        /* the program itself has to be reachable inside the root, and only the
           directory holding it is */
        char *slash = last_slash((char *)evaluator->path);
        if (!slash || slash == evaluator->path) {
            complain("the evaluator path must name a directory", evaluator->path);
            free(work);
            return 2;
        }
        program_directory = strndup(evaluator->path, (size_t)(slash - evaluator->path));
        if (!program_directory) {
            free(work);
            return 1;
        }
        read_only[read_only_count].source = program_directory;
        read_only[read_only_count].destination = program_directory;
        read_only[read_only_count].writable = 0;
        ++read_only_count;
    }
    sandbox.mounts = read_only;
    sandbox.mount_count = read_only_count;
    if (holy_sandbox_prepare(&sandbox)) {
        free(work);
        return 6;
    }
    length = strlen(work) + 32;
    captured = malloc(length);
    if (!captured) goto done;
    snprintf(captured, length, "%s/evaluator-output", work);
    {
        int fd = open(captured, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0) {
            complain("create the output file", strerror(errno));
            goto done;
        }
        sandbox.output[0] = fd;
        sandbox.output[1] = fd;
    }
    for (count = 0; evaluator->argv && evaluator->argv[count]; ++count) ;
    argv = calloc(count + 2, sizeof *argv);
    if (!argv) goto done;
    argv[used++] = (char *)evaluator->path;
    for (i = 0; i < count; ++i) argv[used++] = (char *)evaluator->argv[i];
    argv[used] = NULL;
    /* the evaluator sees a declared environment, so a variable the host exports does
       not reach it and its result is the same on every host */
    entries[0] = (char *)"PATH=/usr/bin:/bin";
    entries[1] = NULL;
    sandbox.output[1] = sandbox.output[0];
    status = holy_sandbox_run(&sandbox, argv, evaluator->cwd, entries);
    result->status = status;
    if (status) {
        fprintf(stderr, "holypkg: evaluator %s failed with status %d\n", evaluator->path,
                status);
        goto failed;
    }
    if (!digest_of(captured, result->digest)) {
        complain("hash the evaluator output", NULL);
        goto done;
    }
    {
        FILE *in = fopen(captured, "rb");
        long size;
        if (!in) { complain("read the evaluator output", NULL); goto done; }
        if (fseek(in, 0, SEEK_END) || (size = ftell(in)) < 0) { fclose(in); goto done; }
        rewind(in);
        /* the output is bounded, since a converter reads fields rather than a payload */
        if (size > 1048576L) size = 1048576L;
        result->text = malloc((size_t)size + 1);
        if (!result->text) { fclose(in); goto done; }
        result->length = fread(result->text, 1, (size_t)size, in);
        result->text[result->length] = 0;
        fclose(in);
    }
    printf("evaluator %s sha256 %s status %d output-sha256 %s bytes %zu\n",
           evaluator->path, result->program_digest, result->status, result->digest,
           result->length);
    ok = 1;
done:
    if (ok) printf("evaluator-output %s\n", captured);
    free(argv);
    holy_sandbox_free(&sandbox);
    /* the private work directory goes with the run, since the output has been copied
       into the conversion directory and the root holds nothing the caller needs */
    if (captured) unlink(captured);
    if (work) {
        char root[4200];
        snprintf(root, sizeof root, "%s/env", work);
        remove_tree(root);
        rmdir(work);
    }
    free(captured);
    free(program_directory);
    free(work);
    return ok ? 0 : 1;
failed:
    free(argv);
    free(captured);
    free(program_directory);
    holy_sandbox_free(&sandbox);
    free(work);
    return 1;
}

/* one field of a holy-recipe manifest, or NULL when the record states none */
static char *recipe_field(const char *path, const char *key)
{
    char line[1024], *stop;
    FILE *in = fopen(path, "r");
    size_t key_length = strlen(key);
    char *value = NULL;
    if (!in) return NULL;
    while (fgets(line, sizeof line, in)) {
        if (strncmp(line, key, key_length) || line[key_length] != ' ')
            continue;
        value = strdup(line + key_length + 1);
        break;
    }
    fclose(in);
    if (!value) return NULL;
    stop = first_of(value, "\r\n");
    if (stop) *stop = 0;
    /* a manifest quotes its values, so the quotes belong to the field */
    {
        size_t length = strlen(value);
        char *unquoted;
        if (length < 2 || value[0] != '"' || value[length - 1] != '"') return value;
        unquoted = strdup(value + 1);
        if (!unquoted) return value;
        unquoted[length - 2] = 0;
        free(value);
        return unquoted;
    }
}

/* the fields an evaluator writes as KEY=VALUE lines and this converter's own reading of
   them, compared line by line. returns the number of differences written. */
static size_t evaluator_field(const char *text, size_t length, const char *name,
                              const char *value, const char *label)
{
    size_t at = 0, name_length = strlen(name);
    const char *found = NULL;
    /* a .SRCINFO writes KEY = VALUE and a shell writer writes KEY=VALUE, so the spaces
       around the sign belong to neither */
    while (at < length) {
        char *stop = first_newline(text + at, length - at);
        size_t line = stop ? (size_t)(stop - (text + at)) : length - at;
        if (line > name_length && !strncmp(text + at, name, name_length)) {
            size_t after = at + name_length;
            size_t value_at = after;
            while (value_at < at + line && (text[value_at] == ' ' || text[value_at] == '\t'))
                ++value_at;
            if (value_at < at + line && text[value_at] == '=') {
                ++value_at;
                while (value_at < at + line &&
                       (text[value_at] == ' ' || text[value_at] == '\t'))
                    ++value_at;
                found = text + value_at;
                break;
            }
        }
        if (!stop) break;
        at += line + 1;
    }
    if (!found || !value || !*value) return 0;
    {
        size_t value_length = strcspn(found, "\r\n");
        if (value_length == strlen(value) && !strncmp(found, value, value_length)) return 0;
        printf("%s evaluator=\"", label);
        {
            size_t c;
            for (c = 0; c < value_length; ++c)
                fputc(found[c] == '"' || found[c] == '\\' ? '_' : found[c], stdout);
        }
        printf("\" text=\"%s\"\n", value);
        return 1;
    }
}

size_t holy_evaluator_report(const struct holy_evaluator_result *result,
                             const char *recipe_path, const char *program)
{
    /* the fields a foreign evaluator names in KEY=VALUE form, and the manifest keys they
       correspond to */
    static const char *const names[] = { "pkgbase", "pkgver", "pkgrel" };
    static const char *const keys[] = { "name", "version", "release" };
    static const char *const labels[] = { "evaluator-name", "evaluator-version",
                                          "evaluator-release" };
    char directory[4096];
    char *values[3];
    size_t count = 0, i;
    char *slash;
    if (!result || !result->text || !recipe_path) return 0;
    /* the output travels beside the recipe, so the comparison is repeatable */
    slash = last_slash((char *)recipe_path);
    if (!slash || (size_t)(slash - recipe_path) >= sizeof directory) return 0;
    memcpy(directory, recipe_path, (size_t)(slash - recipe_path));
    directory[slash - recipe_path] = 0;
    {
        char fragment[4200];
        FILE *out;
        snprintf(fragment, sizeof fragment, "%s/evaluator-output", directory);
        out = fopen(fragment, "wb");
        if (out) {
            fwrite(result->text, 1, result->length, out);
            if (fclose(out)) return 0;
            printf("evaluator-output %s sha256 %s\n", fragment, result->digest);
        }
    }
    for (i = 0; i < sizeof names / sizeof *names; ++i)
        values[i] = recipe_field(recipe_path, keys[i]);
    for (i = 0; i < sizeof names / sizeof *names; ++i)
        count += evaluator_field(result->text, result->length, names[i], values[i],
                                 labels[i]);
    for (i = 0; i < sizeof values / sizeof *values; ++i) free(values[i]);
    if (count)
        printf("evaluator %s disagrees with the text reading on %zu field%s; review the "
               "recipe before building\n", program, count, count == 1 ? "" : "s");
    else
        printf("evaluator %s agrees with the text reading\n", program);
    return count;
}

void holy_evaluator_free(struct holy_evaluator_result *result)
{
    if (!result) return;
    free(result->text);
    memset(result, 0, sizeof *result);
}
