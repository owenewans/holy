#define _POSIX_C_SOURCE 200809L
#include "private.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct consumer_report {
    size_t count;
};

static int report_consumer(void *context, const char *path, const char *needed)
{
    struct consumer_report *report = context;
    printf("consumer %s needs %s\n", path, needed);
    ++report->count;
    return 1;
}

/* the private placement of one verified manifest. a plan or a journal names the
   placements as ARTIFACT=PATH, and the result is the record the installed instance
   keeps as files while package-files stays what the package shipped. */

static const char artifact[] =
    "06454e9dbc7db23ef1fcb4e016c3fac740da0658631f6afd9c11bc7fd379f77e";
static const char other[] =
    "d6668133a5daaa103d18e3b5503992c88e296849585126c5abf1fb64c42a34b3";

static const char manifest[] =
    "format holy-files-1\n"
    "dir \"usr\" 755 - - 0 0 0 - none - -\n"
    "dir \"usr/bin\" 755 - - 0 0 0 - none - -\n"
    "file \"usr/bin/prog\" 755 - - 0 0 1101160 "
        "673e1776889eb81e50c00a6bdb19518d52e21736fba923677fd741e04c4255de none - -\n"
    "file \"usr/bin/helper\" 755 - - 0 0 994600 "
        "46b544b61923cff149da63414772d0b61babc605f08766414ebe9976dedfdda7 none - -\n"
    "file \"etc/tool.conf\" 644 - - 0 0 12 "
        "0000000000000000000000000000000000000000000000000000000000000000 config - -\n";

static int expect(const char *name, int condition)
{
    if (!condition) { fprintf(stderr, "private fixture failed: %s\n", name); return 0; }
    return 1;
}

static int contains(const char *text, const char *needle)
{
    return text && strstr(text, needle) != NULL;
}

static size_t count_occurrences(const char *text, const char *needle)
{
    size_t seen = 0;
    size_t length = strlen(needle);
    while ((text = strstr(text, needle)) != NULL) { ++seen; text += length; }
    return seen;
}

/* every directory row has to name a path that sorts after the directory rows written
   before it, since the installer creates them from a sorted list */
static int parents_in_order(const char *record)
{
    const char *cursor = record;
    char previous[4096], current[4096];
    size_t seen = 0;
    previous[0] = '\0';
    while ((cursor = strstr(cursor, "dir \"")) != NULL) {
        const char *start = cursor + 5, *end;
        size_t length;
        cursor = start;
        end = strchr(start, '"');
        if (!end) return 0;
        length = (size_t)(end - start);
        if (length >= sizeof current) return 0;
        memcpy(current, start, length);
        current[length] = '\0';
        if (seen && strcmp(previous, current) >= 0) return 0;
        memcpy(previous, current, length + 1);
        seen = 1;
        cursor = end;
    }
    return seen != 0;
}

static int targets(void)
{
    char target[4096];
    if (!expect("a digest and a relative path build a private target",
            holy_private_target(artifact, "usr/bin/prog", target, sizeof target))) return 0;
    if (!expect("the private target keeps the artifact id and the relative structure",
            !strcmp(target, HOLY_PRIVATE_ROOT "06454e9dbc7db23ef1fcb4e016c3fac740da0658631f6afd9c11bc7fd379f77e/usr/bin/prog")))
        return 0;
    if (!expect("an uppercase digest is not an artifact id",
            !holy_private_target("06454E9DBC7DB23EF1FCB4E016C3FAC740DA0658631F6AFD9C11BC7FD379F77E",
                                 "usr/bin/prog", target, sizeof target))) return 0;
    if (!expect("a short digest is not an artifact id",
            !holy_private_target("06454e9d", "usr/bin/prog", target, sizeof target))) return 0;
    if (!expect("an absolute path is refused",
            !holy_private_target(artifact, "/usr/bin/prog", target, sizeof target))) return 0;
    if (!expect("a dot-dot component is refused",
            !holy_private_target(artifact, "usr/../etc/shadow", target, sizeof target))) return 0;
    if (!expect("an empty component is refused",
            !holy_private_target(artifact, "usr//bin/prog", target, sizeof target))) return 0;
    if (!expect("a path already inside a private tree is not nested again",
            !holy_private_target(artifact, HOLY_PRIVATE_ROOT "aa/usr/bin/prog",
                                 target, sizeof target))) return 0;
    if (!expect("a private path is recognised as private",
            holy_private_path(HOLY_PRIVATE_ROOT "aa/usr/bin/prog") &&
            !holy_private_path("usr/bin/prog"))) return 0;
    return 1;
}

static int table(void)
{
    struct holy_private_places places = {0};
    char parsed[65], *path = NULL;
    if (!expect("a placement is added", holy_private_place_add(&places, artifact, "usr/bin/prog"))) return 0;
    if (!expect("the same pair twice is refused",
            !holy_private_place_add(&places, artifact, "usr/bin/prog"))) return 0;
    if (!expect("a second artifact may claim one path privately",
            holy_private_place_add(&places, other, "usr/bin/prog"))) return 0;
    if (!expect("lookup names the private target of that artifact",
            holy_private_lookup(&places, artifact, "usr/bin/prog") != NULL &&
            !strcmp(holy_private_lookup(&places, artifact, "usr/bin/prog"),
                    HOLY_PRIVATE_ROOT "06454e9dbc7db23ef1fcb4e016c3fac740da0658631f6afd9c11bc7fd379f77e/usr/bin/prog"))) return 0;
    if (!expect("a different artifact has nothing placed at that path",
            holy_private_lookup(&places, other, "usr/bin/helper") == NULL)) return 0;
    if (!expect("an artifact count names only its own placements",
            holy_private_places_artifact(&places, artifact) == 1 &&
            holy_private_places_artifact(&places, other) == 1)) return 0;
    if (!expect("ARTIFACT=PATH parses", holy_private_place_parse(
            "06454e9dbc7db23ef1fcb4e016c3fac740da0658631f6afd9c11bc7fd379f77e=usr/bin/prog",
            parsed, &path) &&
            !strcmp(parsed, artifact) && !strcmp(path, "usr/bin/prog"))) return 0;
    free(path);
    path = NULL;
    if (!expect("a line without a digest is refused",
            !holy_private_place_parse("usr/bin/prog=usr/bin/prog", parsed, &path))) return 0;
    if (!expect("a line without a path is refused",
            !holy_private_place_parse("06454e9dbc7db23ef1fcb4e016c3fac740da0658631f6afd9c11bc7fd379f77e=",
                                      parsed, &path))) return 0;
    holy_private_places_free(&places);
    return 1;
}

static int rewrite(void)
{
    struct holy_private_places places = {0};
    char *record = NULL;
    size_t size = 0;
    if (!expect("a placement is added", holy_private_place_add(&places, artifact, "usr/bin/prog"))) return 0;
    if (!expect("a second artifact claims the same path privately",
            holy_private_place_add(&places, other, "usr/bin/prog"))) return 0;
    if (!expect("the manifest rewrites", holy_private_manifest(&places, artifact,
            manifest, strlen(manifest), &record, &size))) return 0;
    if (!expect("the placed path names the private target", contains(record,
            "file \"" HOLY_PRIVATE_ROOT "06454e9dbc7db23ef1fcb4e016c3fac740da0658631f6afd9c11bc7fd379f77e/usr/bin/prog\" 755 - - 0 0 1101160 "
            "673e1776889eb81e50c00a6bdb19518d52e21736fba923677fd741e04c4255de none - -")))
        return 0;
    if (!expect("the public path is gone", !contains(record, "\"usr/bin/prog\""))) return 0;
    if (!expect("an unplaced file keeps its path", contains(record,
            "file \"usr/bin/helper\" 755 - - 0 0 994600 "
            "46b544b61923cff149da63414772d0b61babc605f08766414ebe9976dedfdda7 none - -"))) return 0;
    if (!expect("a directory keeps its record", contains(record,
            "dir \"usr/bin\" 755 - - 0 0 0 - none - -"))) return 0;
    if (!expect("a config keeps its flags", contains(record,
            "file \"etc/tool.conf\" 644 - - 0 0 12 "
            "0000000000000000000000000000000000000000000000000000000000000000 config - -"))) return 0;
    if (!expect("the format line is preserved", contains(record, "format holy-files-1\n"))) return 0;
    if (!expect("the private tree declares its own directories", contains(record,
            "dir \"usr/lib/holy/private/06454e9dbc7db23ef1fcb4e016c3fac740da0658631f6afd9c11bc7fd379f77e/usr\" 755 - - 0 0 0 - none - -\n") &&
            contains(record, "dir \"usr/lib/holy/private/06454e9dbc7db23ef1fcb4e016c3fac740da0658631f6afd9c11bc7fd379f77e/usr/bin\" 755 - - 0 0 0 - none - -\n")))
        return 0;
    if (!expect("the private directories are declared in creation order", parents_in_order(record))) return 0;
    if (!expect("a directory the source already states is written once",
            count_occurrences(record, "dir \"usr\" 755 - - 0 0 0 - none - -") == 1 &&
            count_occurrences(record, "dir \"usr/bin\" 755 - - 0 0 0 - none - -") == 1)) return 0;
    if (!expect("a shared ancestor of both private targets is declared once",
            count_occurrences(record, "dir \"usr/lib\" 755 - - 0 0 0 - none - -") == 1 &&
            count_occurrences(record, "dir \"usr/lib/holy/private\" 755 - - 0 0 0 - none - -") == 1)) return 0;
    free(record);
    record = NULL;
    if (!expect("a placement the record does not carry is refused", !holy_private_manifest(
            &places, artifact, "format holy-files-1\ndir \"usr\" 755 - - 0 0 0 - none - -\n",
            strlen("format holy-files-1\ndir \"usr\" 755 - - 0 0 0 - none - -\n"),
            &record, &size))) return 0;
    if (!expect("a refused rewrite leaves no record", !record && !size)) return 0;
    if (!expect("an artifact with no placement of its own rewrites nothing",
            holy_private_manifest(&places,
                "1111111111111111111111111111111111111111111111111111111111111111",
                manifest, strlen(manifest), &record, &size) &&
            record && !strcmp(record, manifest))) return 0;
    free(record);
    record = NULL;
    if (!expect("another artifact's placement maps its own row only",
            holy_private_manifest(&places, other, manifest, strlen(manifest), &record, &size) &&
            contains(record, "file \"" HOLY_PRIVATE_ROOT
                "d6668133a5daaa103d18e3b5503992c88e296849585126c5abf1fb64c42a34b3/usr/bin/prog\"") &&
            !contains(record, "file \"usr/bin/prog\""))) return 0;
    free(record);
    record = NULL;
    if (!expect("an unparsable record is refused", !holy_private_manifest(&places, artifact,
            "format holy-files-1\nfile \"unterminated\n", 38, &record, &size))) return 0;
    holy_private_places_free(&places);
    return 1;
}

int main(int argc, char **argv)
{
    /* the SONAME a placed library carries and the programs that name it, which is how
       a private placement decides whether it strands anything */
    if (argc == 4 && !strcmp(argv[1], "--soname")) {
        char *soname = NULL;
        if (!holy_private_soname(argv[2], argv[3], &soname)) {
            fputs("private fixture failed: the archive or the payload is unreadable\n", stderr);
            return 1;
        }
        printf("soname %s\n", soname ? soname : "-");
        free(soname);
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "--consumers")) {
        struct consumer_report report = {0};
        if (!holy_private_consumers(argv[2], argv[3], report_consumer, &report)) {
            fputs("private fixture failed: the archive is unreadable\n", stderr);
            return 1;
        }
        printf("consumers %zu\n", report.count);
        return 0;
    }
    if (!targets() || !table() || !rewrite()) return 1;
    puts("private placement fixture ok");
    return 0;
}