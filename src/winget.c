/* a WinGet package manifest to a native package conversion; see man/holypkg.8 and
   man/holy-package.5. a winget-pkgs manifest is YAML whose top level states the
   package, the installer type, the artifact address and its SHA-256, while a
   dependency list and the switches of an installer sit in nested blocks this
   converter counts rather than guesses at. the verified artifact travels into a
   package through the shared writer, and nothing runs it. */
#define _POSIX_C_SOURCE 200809L
#include "winget.h"
#include "artifact.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WINGET_KEYS 48

/* the top level keys this converter reads */
static const char *const carried[] = {
    "PackageIdentifier", "PackageVersion", "InstallerUrl", "InstallerSha256", "DisplayName",
    "PublisherUrl", "Homepage", "LicenseUrl", "PackageDependencies", NULL
};

/* the keys that describe how Windows installs the artifact */
static const char *const installer_keys[] = {
    "InstallerType", "InstallerSwitches", "InstallerScope", "ElevationRequirement",
    "NestedInstallerType", "NestedInstallerFiles", "InstallLocationRequired", "Platform",
    "MinimumOSVersion", "ReleaseDate", "ManifestType", "ManifestVersion", NULL
};

/* the keys that configure what the program reads after the install */
static const char *const integration_keys[] = {
    "Commands", "InstallerSuccessCodes", "PackageFamilyNames", "Architecture",
    "Market", "Publisher", "Moniker", "Tags", "PackageDependencies", NULL
};

/* the keys that belong to a catalog, which owns its own index */
static const char *const update_keys[] = {
    "PackageUpdateCallback", "UpdateBehavior", "ReleaseDate", "InstallerSha256", NULL
};

struct win_field {
    char key[64];
    char *value;
};

struct win_manifest {
    struct win_field fields[WINGET_KEYS];
    size_t count;
    /* a dependency list is a nested block of entries, one per architecture */
    char depends[4096];
    size_t unknown;
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

static char *trim(char *text)
{
    char *end;
    while (*text == ' ' || *text == '\t') ++text;
    if ((*text == '\'' || *text == '"') && strlen(text) > 1) {
        size_t length = strlen(text);
        if (text[length - 1] == *text) text[length - 1] = 0;
        ++text;
    }
    end = text + strlen(text);
    while (end > text && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' ||
                          end[-1] == '\n')) --end;
    *end = 0;
    return text;
}

static int field_set(struct win_manifest *manifest, const char *key, size_t length,
                     const char *value)
{
    char *copy;
    size_t i;
    for (i = 0; i < manifest->count; ++i)
        if (!strcmp(manifest->fields[i].key, key)) {
            copy = strdup(value);
            if (!copy) return 0;
            free(manifest->fields[i].value);
            manifest->fields[i].value = copy;
            return 1;
        }
    if (manifest->count >= WINGET_KEYS || length >= sizeof manifest->fields[0].key) return 0;
    memcpy(manifest->fields[manifest->count].key, key, length);
    manifest->fields[manifest->count].key[length] = 0;
    copy = strdup(value);
    if (!copy) return 0;
    manifest->fields[manifest->count].value = copy;
    ++manifest->count;
    return 1;
}

static const char *field_get(const struct win_manifest *manifest, const char *key)
{
    size_t i;
    for (i = 0; i < manifest->count; ++i)
        if (!strcmp(manifest->fields[i].key, key)) return manifest->fields[i].value;
    return NULL;
}

/* one line of a manifest: a top level key with its value, or an entry of the
   dependency block this converter reads */
static int read_line(struct win_manifest *manifest, char *line, int nested)
{
    char *at = line, *colon, *value;
    size_t length;
    while (*at == ' ' || *at == '\t') ++at;
    if (!*at || *at == '#' || *at == '\n' || *at == '\r') return 0;
    if (nested) {
        /* a dependency entry is "- Package: Contoso.Dep", and the name follows */
        if (*at == '-') {
            ++at;
            while (*at == ' ') ++at;
            colon = strchr(at, ':');
            if (!colon) return 0;
            *colon = 0;
            value = trim(colon + 1);
            if (!strcmp(trim(at), "Package") && *value && literal(value)) {
                size_t used = strlen(manifest->depends);
                if (used + strlen(value) + 2 < sizeof manifest->depends) {
                    snprintf(manifest->depends + used, sizeof manifest->depends - used,
                             "%s%s", used ? " " : "", value);
                    return 1;
                }
            }
            return 0;
        }
        return 0;
    }
    if (*at == ' ' || *at == '\t') return 0;
    colon = strchr(at, ':');
    if (!colon) return 0;
    *colon = 0;
    value = trim(colon + 1);
    length = strlen(at);
    if (!length) return 0;
    return field_set(manifest, at, length, value);
}

static int read_manifest(const char *path, struct win_manifest *manifest)
{
    char line[2048];
    FILE *in = fopen(path, "rb");
    int nested = 0;
    if (!in) return 6;
    while (fgets(line, sizeof line, in)) {
        /* an indented line belongs to the block the line above it opened */
        if (line[0] == ' ' || line[0] == '\t') {
            if (nested) read_line(manifest, line, 1);
            continue;
        }
        if (!read_line(manifest, line, 0)) continue;
        /* the dependency block holds the packages this manifest names */
        nested = !strcmp(line, "PackageDependencies");
    }
    if (ferror(in)) { fclose(in); return 6; }
    fclose(in);
    return manifest->count ? 0 : 2;
}

static void manifest_free(struct win_manifest *manifest)
{
    size_t i;
    for (i = 0; i < manifest->count; ++i) free(manifest->fields[i].value);
}

static int key_listed(const char *const *keys, const char *key)
{
    size_t i;
    for (i = 0; keys[i]; ++i)
        if (!strcmp(key, keys[i])) return 1;
    return 0;
}

static int winget_convert(const char *input, const char *source, const char *output)
{
    struct win_manifest manifest;
    struct holy_artifact fields = {0};
    char identifier[256], version[256];
    const char *url, *sha, *read;
    size_t i, unknown = 0, installers = 0, integrations = 0, updates = 0;
    int status, result = 1;

    memset(&manifest, 0, sizeof manifest);
    status = read_manifest(input, &manifest);
    if (status) {
        if (status == 6) fprintf(stderr, "holypkg: manifest unavailable: %s\n", input);
        else
            fputs("holypkg: a WinGet manifest is YAML text with top level keys, and this "
                  "converter reads no other form\n", stderr);
        return status;
    }
    read = field_get(&manifest, "PackageIdentifier");
    if (!read || !literal(read) || !is_label(read)) {
        fputs("holypkg: a WinGet manifest needs a literal PackageIdentifier\n", stderr);
        result = 2;
        goto done;
    }
    snprintf(identifier, sizeof identifier, "%s", read);
    read = field_get(&manifest, "PackageVersion");
    if (!read || !is_label(read)) {
        fputs("holypkg: a WinGet manifest needs a literal PackageVersion\n", stderr);
        result = 2;
        goto done;
    }
    snprintf(version, sizeof version, "%s", read);
    url = field_get(&manifest, "InstallerUrl");
    if (!url || !literal(url) || !strstr(url, "://")) {
        fputs("holypkg: a WinGet manifest needs an InstallerUrl\n", stderr);
        result = 2;
        goto done;
    }
    sha = field_get(&manifest, "InstallerSha256");
    if (!holy_artifact_digest(sha)) {
        fputs("holypkg: a WinGet manifest needs an InstallerSha256 digest\n", stderr);
        result = 2;
        goto done;
    }
    for (i = 0; i < manifest.count; ++i) {
        const char *key = manifest.fields[i].key;
        if (key_listed(carried, key)) continue;
        if (key_listed(installer_keys, key)) { ++installers; continue; }
        if (key_listed(integration_keys, key)) { ++integrations; continue; }
        if (key_listed(update_keys, key)) { ++updates; continue; }
        ++unknown;
    }

    fields.family = "winget";
    fields.converter = "holy-winget-1";
    fields.name = identifier;
    fields.version = version;
    fields.url = url;
    fields.hash = sha;
    fields.directory = NULL;
    fields.program = NULL;
    fields.depends = manifest.depends;
    fields.dependency_note = "packages of the same catalog";
    fields.catalog = "WinGet catalog";
    fields.summary = field_get(&manifest, "DisplayName");
    fields.homepage = field_get(&manifest, "PublisherUrl");
    if (!fields.homepage) fields.homepage = field_get(&manifest, "Homepage");
    fields.license = field_get(&manifest, "LicenseUrl");
    fields.installers = installers;
    fields.integrations = integrations;
    fields.updates = updates;
    fields.unknown_keys = unknown;
    result = holy_artifact_package(input, source, output, &fields);
done:
    manifest_free(&manifest);
    return result;
}

int holy_import_winget(const char *input, const char *source, const char *output)
{
    size_t i;
    int result;
    if (!source || !*source || !strcmp(source, "local")) return 2;
    for (i = 0; source[i]; ++i)
        if ((unsigned char)source[i] <= 32 || source[i] == ':' || source[i] == '/' ||
            source[i] == '@') return 2;
    if (!input || !output || !*output) {
        fputs("usage: holypkg import NAME.yaml --source NAME --format winget "
              "--output NEW_DIRECTORY\n", stderr);
        return 2;
    }
    result = winget_convert(input, source, output);
    if (result) return result;
    fputs("holypkg: the package carries a program for another operating system; nothing runs it,\n"
          "       no Wine runtime is required, and every installer switch is dropped\n", stderr);
    return 3;
}
