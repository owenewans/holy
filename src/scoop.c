/* a Scoop manifest to a native package conversion; see man/holypkg.8 and
   man/holy-package.5. a manifest names an artifact with a URL and a SHA-256 and
   asks PowerShell to place it, so this converter reads the JSON manifest, counts
   every key that belongs to a Windows installation or to the bucket, and hands the
   verified artifact to the shared writer that carries it into a package. */
#define _POSIX_C_SOURCE 200809L
#include "scoop.h"
#include "artifact.h"
#include "../backends/shrecipe.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* the manifest keys this converter reads */
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

static int literal(const char *value)
{
    return value && *value && !strpbrk(value, "$`\\\"'");
}

static int scoop_convert(const char *input, const char *source, const char *output)
{
    struct holy_json_value *manifest = NULL;
    struct holy_artifact fields = {0};
    char name[256], version[256];
    const char *url, *extract_dir, *text_version;
    size_t i, unknown = 0, installers = 0, integrations = 0, updates = 0;
    int read_status = 0, result = 1;

    manifest = holy_json_read(input, &read_status);
    if (!manifest) {
        if (read_status == 6) fprintf(stderr, "holypkg: manifest unavailable: %s\n", input);
        else
            fputs("holypkg: a Scoop manifest is JSON text, and this converter reads no other "
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
    text_version = holy_json_text(holy_json_get(manifest, "version"));
    if (!text_version || !is_label(text_version)) {
        fputs("holypkg: a Scoop manifest needs a literal version\n", stderr);
        result = 2;
        goto done;
    }
    snprintf(version, sizeof version, "%s", text_version);
    url = holy_json_text(holy_json_get(manifest, "url"));
    if (!url || !literal(url) || !strstr(url, "://")) {
        fputs("holypkg: a Scoop manifest needs an artifact URL\n", stderr);
        result = 2;
        goto done;
    }
    if (!holy_artifact_digest(holy_json_text(holy_json_get(manifest, "hash")))) {
        fputs("holypkg: a Scoop manifest needs a sha256 digest for its artifact\n", stderr);
        result = 2;
        goto done;
    }
    extract_dir = holy_json_text(holy_json_get(manifest, "extract_dir"));
    if (holy_json_get(manifest, "extract_dir") && !extract_dir) {
        fputs("holypkg: a Scoop extract_dir list names several programs, which this converter "
              "cannot place\n", stderr);
        result = 3;
        goto done;
    }
    if (extract_dir && (!literal(extract_dir) || strchr(extract_dir, '/'))) {
        fputs("holypkg: a Scoop extract_dir is one directory name\n", stderr);
        result = 2;
        goto done;
    }
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

    fields.family = "scoop";
    fields.converter = "holy-scoop-1";
    fields.name = name;
    fields.version = version;
    fields.url = url;
    fields.hash = holy_json_text(holy_json_get(manifest, "hash"));
    fields.directory = extract_dir;
    fields.program = holy_json_text(holy_json_get(manifest, "bin"));
    fields.depends = holy_json_text(holy_json_get(manifest, "depends"));
    fields.dependency_note = "apps of the same bucket";
    fields.catalog = "Scoop bucket";
    fields.summary = holy_json_text(holy_json_get(manifest, "description"));
    fields.homepage = holy_json_text(holy_json_get(manifest, "homepage"));
    fields.license = holy_json_text(holy_json_get(manifest, "license"));
    fields.installers = installers;
    fields.integrations = integrations;
    fields.updates = updates;
    fields.unknown_keys = unknown;
    result = holy_artifact_package(input, source, output, &fields);
done:
    holy_json_free(manifest);
    return result;
}

int holy_import_scoop(const char *input, const char *source, const char *output)
{
    size_t i;
    int result;
    if (!source || !*source || !strcmp(source, "local")) return 2;
    for (i = 0; source[i]; ++i)
        if ((unsigned char)source[i] <= 32 || source[i] == ':' || source[i] == '/' ||
            source[i] == '@') return 2;
    if (!input || !output || !*output) {
        fputs("usage: holypkg import NAME.json --source NAME --format scoop "
              "--output NEW_DIRECTORY\n", stderr);
        return 2;
    }
    result = scoop_convert(input, source, output);
    if (result) return result;
    fputs("holypkg: the package carries a program for another operating system; nothing runs it,\n"
          "       no Wine runtime is required, and every installer step is dropped\n", stderr);
    return 3;
}
