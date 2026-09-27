#define _POSIX_C_SOURCE 200809L
#include "../backends/pacman.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define require(x) do { if (!(x)) { fprintf(stderr, "pacman fixture line %d\n", __LINE__); return 1; } } while (0)
#define BASE "pkgname = fixture\npkgver = 2:1.2.3-4.1\narch = x86_64\n"

static int valid(const char *s)
{
    struct holy_pacman_metadata metadata;
    struct holy_pacman_error error;
    int ok = holy_pacman_parse(s, strlen(s), &metadata, &error);
    holy_pacman_free(&metadata);
    return ok;
}

int main(void)
{
    struct holy_pacman_metadata metadata;
    struct holy_pacman_error error;
    const char sample[] = BASE
        "pkgdesc = literal $HOME $(touch nope) # not a comment\n"
        "xdata = pkgtype=split\n"
        "depend = libfoo>=2:1.0-4\n"
        "depend = lib:libfoo.so.3\n"
        "provides = libfoo.so=3-64\n"
        "optdepend = helper>=3:2-1: Unicode пояснение\n"
        "conflict = older<1.0\n"
        "replaces = renamed\n"
        "backup = etc/a b.conf\n"
        "makedepend = compiler\n"
        "checkdepend = tester\n"
        "license = GPL-3.0-or-later\n"
        "license = MIT\n"
        "future = preserve me\n";
    FILE *file;
    char bytes[4096];
    size_t size;
    require(holy_pacman_parse(sample, sizeof sample - 1, &metadata, &error));
    require(!strcmp(metadata.version, "2:1.2.3-4.1") && !strcmp(metadata.name, "fixture"));
    require(metadata.count == 17 && metadata.unknown_count == 1);
    require(!strcmp(metadata.fields[3].value, "literal $HOME $(touch nope) # not a comment"));
    require(metadata.fields[5].line == 6 && metadata.fields[5].kind == HOLY_PACMAN_DEPEND);
    require(!strcmp(metadata.fields[5].relation.name, "libfoo"));
    require(!strcmp(metadata.fields[5].relation.version, "2:1.0-4"));
    require(!strcmp(metadata.fields[5].relation.comparison, "ge"));
    require(!strcmp(metadata.fields[5].value, "libfoo>=2:1.0-4"));
    require(metadata.fields[6].relation.kind == HOLY_PACMAN_SONAME_V2);
    require(!strcmp(metadata.fields[6].relation.prefix, "lib"));
    require(metadata.fields[7].relation.kind == HOLY_PACMAN_SONAME_V1);
    require(metadata.fields[7].relation.elf_class == 64);
    require(metadata.fields[8].kind == HOLY_PACMAN_OPTIONAL);
    require(!strcmp(metadata.fields[8].relation.version, "3:2-1"));
    require(!strcmp(metadata.fields[8].relation.description, "Unicode пояснение"));
    require(metadata.fields[9].kind == HOLY_PACMAN_CONFLICT);
    require(metadata.fields[10].kind == HOLY_PACMAN_REPLACE);
    require(metadata.fields[11].kind == HOLY_PACMAN_BACKUP);
    holy_pacman_free(&metadata);
    require(valid(" \t# comment\n" BASE "pkgdesc = \nurl = \n"));
    require(valid("pkgname = fixture\npkgver = 1-1\narch = riscv64"));
    require(valid(BASE "xdata = pkgtype=future\n"));
    require(!valid(""));
    require(!valid("pkgname = fixture\npkgver = 1-1\n"));
    require(!valid(BASE "pkgname = duplicate\n"));
    require(!valid(BASE "depend=bad\n"));
    require(!valid(BASE "depend = foo>=\n"));
    require(!valid(BASE "depend = foo=>2\n"));
    require(!valid(BASE "provides = virtual>=1\n"));
    require(!valid(BASE "optdepend = tool: \n"));
    require(!valid(BASE "backup = ../outside\n"));
    require(!valid(BASE "backup = /etc/passwd\n"));
    require(!valid(BASE "backup = a//b\n"));
    require(!valid(BASE "size = 18446744073709551616\n"));
    require(!valid(BASE "size = -1\n"));
    require(!valid(BASE "builddate = yesterday\n"));
    require(!valid(BASE "pkgdesc = bad\r\n"));
    require(!valid(BASE "pkgdesc = \xc0\x80\n"));
    require(!valid(BASE "pkgdesc = \xed\xa0\x80\n"));
    require(!valid(BASE "pkgdesc = \xf4\x90\x80\x80\n"));
    require(!valid(BASE "pkgdesc = \xe2\n"));
    require(!valid(BASE "xdata = extra=value\n"));
    require(!valid(BASE "xdata = pkgtype=pkg\nxdata = pkgtype=split\n"));
    require(!holy_pacman_parse(BASE "\0junk", sizeof BASE + 4, &metadata, &error));
    holy_pacman_free(&metadata);
    require(!holy_pacman_parse("", 1024u * 1024u + 1, &metadata, &error));
    holy_pacman_free(&metadata);
    file = fopen("tests/fixtures/pacman/gzip.PKGINFO", "rb");
    require(file != NULL);
    size = fread(bytes, 1, sizeof bytes, file);
    require(!ferror(file) && feof(file));
    fclose(file);
    require(holy_pacman_parse(bytes, size, &metadata, &error));
    require(!strcmp(metadata.name, "gzip") && !strcmp(metadata.version, "1.15-1"));
    require(!metadata.unknown_count && !strcmp(metadata.package_type, "pkg"));
    holy_pacman_free(&metadata);
    file = fopen("tests/fixtures/pacman/vercmp.tsv", "r");
    require(file);
    size = 0;
    while (fgets(bytes, sizeof bytes, file)) {
        char a[256], b[256];
        int expected, order;
        if (bytes[0] == '#' || bytes[0] == '\n') continue;
        require(sscanf(bytes, "%255s %255s %d", a, b, &expected) == 3);
        require(holy_pacman_version_compare(a, b, &order) && order == expected);
        require(holy_pacman_version_compare(b, a, &order) && order == -expected);
        size += 2;
    }
    require(!ferror(file) && size == 92);
    fclose(file);
    {
        int order;
        require(!holy_pacman_version_compare(NULL, "1", &order));
        require(!holy_pacman_version_compare("", "1", &order));
        require(!holy_pacman_version_compare("1\xff", "1", &order));
        require(holy_pacman_version_compare("01:000000000000000000000002-7", "1:2-6", &order) && order == 1);
    }
    puts("pacman metadata and 92 upstream version fixtures passed");
    return 0;
}
