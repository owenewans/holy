#!/usr/bin/env python3
"""converts SlackBuild scripts into holy recipes and builds the produced manifests."""
import hashlib
import io
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile


binary = str(Path(sys.argv[1]).resolve())


def run(*args, status=0):
    result = subprocess.run([binary, *map(str, args)], text=True, capture_output=True,
                           errors="replace")
    assert result.returncode == status, (args, result.returncode, result.stdout, result.stderr)
    return result.stdout


def read_metadata(artifact):
    contents = subprocess.run(["lz4", "-dc", str(artifact)], check=True,
                              capture_output=True).stdout
    with tarfile.open(fileobj=io.BytesIO(contents)) as archive:
        def read(name):
            return archive.extractfile(name).read().decode()
        names = sorted(member.name for member in archive.getmembers())
        return {name: read(name) for name in
                ("HOLY/meta", "HOLY/files", "HOLY/deps", "HOLY/hooks", "HOLY/origin",
                 "HOLY/transform")}, names


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def source_tree(root, name, version):
    directory = root / f"{name}-{version}"
    (directory / "usr/share").mkdir(parents=True)
    write(directory / "Makefile", """all: bin/%(name)s
bin/%(name)s: hello.c
\tmkdir -p bin
\t$(CC) $(CFLAGS) -o $@ hello.c
install: bin/%(name)s
\tmkdir -p $(DESTDIR)/usr/bin $(DESTDIR)/usr/lib
\tcp bin/%(name)s $(DESTDIR)/usr/bin/
\tcp hello.txt $(DESTDIR)/usr/lib/
""" % {"name": name})
    write(directory / "hello.c", '#include <stdio.h>\nint main(void){puts("hi");return 0;}\n')
    write(directory / "hello.txt", "greeting\n")
    write(directory / "COPYING", "fixture licence text\n")
    return directory


def main():
    if not shutil.which("lz4"):
        print("lz4 required for the slackbuild fixture", file=sys.stderr)
        return 6
    for tool in ("cc", "make", "tar", "patch"):
        if not shutil.which(tool):
            print(f"{tool} required for the slackbuild fixture", file=sys.stderr)
            return 6
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        source = source_tree(root, "sb-demo", "3.2.1")
        archive = root / "sb-demo-3.2.1.tar.gz"
        subprocess.run(["tar", "czf", str(archive), "-C", str(root), "sb-demo-3.2.1"],
                       check=True)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()

        package = root / "sb-demo"
        package.mkdir()
        shutil.copy(archive, package / "sb-demo-3.2.1.tar.gz")
        write(package / "sb-demo.SlackBuild", """#!/bin/bash

# Slackware build script for sb-demo

cd $(dirname $0) ; CWD=$(pwd)

PRGNAM=sb-demo
VERSION=${VERSION:-3.2.1}
BUILD=${BUILD:-1}
TAG=${TAG:-_SBo}
PKGTYPE=${PKGTYPE:-tgz}

if [ -z "$ARCH" ]; then
  case "$( uname -m )" in
    i?86) ARCH=i586 ;;
    arm*) ARCH=arm ;;
       *) ARCH=$( uname -m ) ;;
  esac
fi

if [ ! -z "${PRINT_PACKAGE_NAME}" ]; then
  echo "$PRGNAM-$VERSION-$ARCH-$BUILD$TAG.$PKGTYPE"
  exit 0
fi

TMP=${TMP:-/tmp/SBo}
PKG=$TMP/package-$PRGNAM
OUTPUT=${OUTPUT:-/tmp}

if [ "$ARCH" = "x86_64" ]; then
  SLKCFLAGS="-O2 -fPIC"
  LIBDIRSUFFIX="64"
else
  SLKCFLAGS="-O2"
  LIBDIRSUFFIX=""
fi

set -e

rm -rf $PKG
mkdir -p $TMP $PKG $OUTPUT
cd $TMP

rm -rf $PRGNAM-$VERSION
tar xvf $CWD/$PRGNAM-$VERSION.tar.gz
cd $PRGNAM-$VERSION

patch --verbose -p1 -i $CWD/greeting.patch

make $MAKEFLAGS CFLAGS="$SLKCFLAGS"
make install DESTDIR=$PKG

find $PKG -print0 | xargs -0 file | grep -e "executable" | grep ELF \\
  | cut -f 1 -d : | xargs strip --strip-unneeded 2> /dev/null || true

mkdir -p $PKG/usr/doc/$PRGNAM-$VERSION
cp -a COPYING $PKG/usr/doc/$PRGNAM-$VERSION
cat $CWD/$PRGNAM.SlackBuild > $PKG/usr/doc/$PRGNAM-$VERSION/$PRGNAM.SlackBuild

mkdir -p $PKG/install
cat $CWD/slack-desc > $PKG/install/slack-desc
cat $CWD/doinst.sh > $PKG/install/doinst.sh

cd $PKG
/sbin/makepkg -l y -c n $OUTPUT/$PRGNAM-$VERSION-$ARCH-$BUILD$TAG.$PKGTYPE
""")
        write(package / "greeting.patch",
              "--- a/hello.c\n+++ b/hello.c\n@@ -1 +1 @@\n"
              '-#include <stdio.h>\n+#include <stdio.h> /* patched */\n')
        write(package / "slack-desc", """# HOW TO EDIT THIS FILE:
# Line up the first '|' above the ':' following the base package name.

    |-----handy-ruler------------------------------------------------------|
sb-demo: sb-demo (a SlackBuild fixture)
sb-demo:
sb-demo: The sb-demo program greets the operator once and then stops.
sb-demo: It exists so the converter has a linear script to read.
sb-demo:
sb-demo: homepage: https://example.org/sb-demo
sb-demo: requires: gcc make
sb-demo:
sb-demo:
sb-demo:
""")
        write(package / "info", f"""PRGNAM="sb-demo"
VERSION="3.2.1"
HOMEPAGE="https://example.org/sb-demo"
DOWNLOAD="https://example.org/sb-demo-{digest}.tar.gz"
MD5SUM="00000000000000000000000000000000"
REQUIRES=""
MAINTAINER="Fixture <fixture@example.org>"
EMAIL="fixture@example.org"
""")
        write(package / "doinst.sh", 'if [ -x /usr/bin/sb-demo ]; then\n'
              '  /usr/bin/sb-demo >/dev/null\nfi\n')

        out = run("convert", package / "sb-demo.SlackBuild", "--source", "slackbuilds",
                  "--output", root / "conv", status=3)
        assert "converted sb-demo status review-required" in out
        recipe = (root / "conv" / "sb-demo.recipe").read_text()
        report = (root / "conv" / "conversion").read_text()
        assert (root / "conv" / "sb-demo.SlackBuild").read_text() == \
            (package / "sb-demo.SlackBuild").read_text()
        assert hashlib.sha256((root / "conv" / "sb-demo.SlackBuild").read_bytes()).hexdigest() \
            in report
        assert (root / "conv" / "sb-demo-3.2.1.tar.gz").is_file()
        assert (root / "conv" / "doinst.sh").is_file()

        # identity, provenance and the local source are carried
        assert 'name "sb-demo"' in recipe and 'version "3.2.1"' in recipe
        assert 'release "1"' in recipe and 'arch any' in recipe and 'libc any' in recipe
        assert 'x-source-family slackware' in recipe and 'x-converter slackbuild-1' in recipe
        assert 'x-tag "_SBo"' in recipe and 'x-pkgtype "tgz"' in recipe
        assert "sb-demo (a SlackBuild fixture)" in recipe
        assert "stops." in recipe
        assert 'homepage "https://example.org/sb-demo"' in recipe
        assert 'depend "gcc" "any" "-"' in recipe
        assert 'depend "make" "any" "-"' in recipe
        assert f'source "sb-demo-3.2.1.tar.gz" "sb-demo-3.2.1.tar.gz"' in recipe
        assert f'source-sha256 "sb-demo-3.2.1.tar.gz" "{digest}"' in recipe
        # the slackbuild variables are rebuilt from the exported Holy paths
        assert 'PRGNAM=sb-demo' in recipe and 'VERSION=3.2.1' in recipe and 'BUILD=1' in recipe
        assert 'ARCH="$HOLY_ARCH"' in recipe
        assert 'CWD="$HOLY_SRC"' in recipe and 'TMP="$HOLY_SRC"' in recipe
        assert 'PKG="$HOLY_DEST"' in recipe and 'DESTDIR="$HOLY_DEST"' in recipe
        # the body keeps its own shell, and the packaging call is left out
        assert "make install DESTDIR=$PKG" in recipe
        assert "cd $PKG" not in recipe
        assert "/sbin/makepkg" not in recipe
        assert 'hook-install /bin/sh "usr/share/holy/slackbuild/doinst.sh"' in recipe

        # the report names what was carried, what changed and what stayed unknown
        assert "status review-required" in report
        assert "carried PRGNAM 7" in report
        assert "carried VERSION 8" in report
        assert "preserved PKGTYPE 11" in report
        assert "carried slack-desc summary" in report
        assert "carried source sb-demo-3.2.1.tar.gz" in report
        assert "preserved hook doinst.sh" in report
        assert "unknown the slackbuild strip pass is not reproduced" in report
        assert "unknown the script rewrites ownership" not in report
        assert "preserved info DOWNLOAD" in report
        assert "unknown the md5sum this format pins" in report
        assert "semantic-change the machine the script detects from uname -m becomes $HOLY_ARCH" \
            in report
        assert "semantic-change the engine fetches and unpacks the archive" in report
        assert "semantic-change the cd $PKG and /sbin/makepkg lines are left out" in report
        assert "semantic-change the $PKG/install tree is slackbuild packaging metadata" in report
        assert "carried local source greeting.patch" in report
        assert "carried local source slack-desc" in report

        # the converted recipe builds through the normal engine
        run("build", root / "conv" / "sb-demo.recipe", "--output", root / "built", "--yes")
        # the payload decides the group, so the fixture reads the artifacts it produced
        built = sorted(path.name for path in (root / "built").glob("*.holy"))
        assert built == ["sb-demo--noarch--nolibc.holy", "sb-demo--x86_64--glibc.holy"]
        program, _ = read_metadata(root / "built" / "sb-demo--x86_64--glibc.holy")
        data, _ = read_metadata(root / "built" / "sb-demo--noarch--nolibc.holy")
        assert 'name "sb-demo"' in program["HOLY/meta"]
        assert 'x-source-family "slackware"' in program["HOLY/meta"]
        assert digest in program["HOLY/origin"]
        assert "usr/bin/sb-demo" in program["HOLY/files"]
        assert "usr/bin/sb-demo" not in data["HOLY/files"]
        assert "usr/lib/hello.txt" in data["HOLY/files"]
        assert "usr/doc/sb-demo-3.2.1/COPYING" in data["HOLY/files"]
        assert "usr/share/holy/slackbuild/doinst.sh" in data["HOLY/files"]
        assert 'hook postinstall "/bin/sh" "usr/share/holy/slackbuild/doinst.sh"' \
            in data["HOLY/hooks"]

        # unreviewed steps still need a decision
        run("build", root / "conv" / "sb-demo.recipe", "--output", root / "unreviewed",
            "--noninteractive", status=3)

        # a computed identity, a missing archive and a script with no body
        write(package / "sb-demo.SlackBuild", """PRGNAM=sb-demo
VERSION=$(echo 1.0 | tr -d x)
BUILD=1
set -e
make
/sbin/makepkg x
""")
        run("convert", package / "sb-demo.SlackBuild", "--source", "slackbuilds",
            "--output", root / "computed", status=2)
        write(package / "sb-demo.SlackBuild", """PRGNAM=sb-demo
BUILD=1
set -e
make
/sbin/makepkg x
""")
        run("convert", package / "sb-demo.SlackBuild", "--source", "slackbuilds",
            "--output", root / "noversion", status=2)
        write(package / "sb-demo.SlackBuild", """PRGNAM=sb-demo
VERSION=1.0
BUILD=1
set -e
/sbin/makepkg x
""")
        run("convert", package / "sb-demo.SlackBuild", "--source", "slackbuilds",
            "--output", root / "nobody", status=3)
        report = (root / "nobody" / "conversion").read_text()
        assert "unknown the script has no build body between set -e and makepkg" in report
        assert "unknown source sb-demo-1.0.tar.gz is not beside the script" in report

        # a doinst.sh the script installs but that is not beside it
        write(package / "sb-demo.SlackBuild", """PRGNAM=sb-demo
VERSION=1.0
BUILD=1
set -e
tar xvf $CWD/sb-demo-1.0.tar.gz
cp $CWD/doinst.sh $PKG/install/
cd $PKG
/sbin/makepkg x
""")
        (package / "doinst.sh").unlink()
        run("convert", package / "sb-demo.SlackBuild", "--source", "slackbuilds",
            "--output", root / "nohook", status=3)
        report = (root / "nohook" / "conversion").read_text()
        assert "unknown the script installs doinst.sh but no such file is beside it" in report

        # malformed text and unusable arguments
        run("convert", package / "sb-demo.SlackBuild", "--source", "slackbuilds", status=2)
        run("convert", package / "sb-demo.SlackBuild", "--source", "local",
            "--output", root / "nope", status=2)
        run("convert", package / "sb-demo.SlackBuild", "--source", "slackbuilds:extra",
            "--output", root / "nope", status=2)
        run("convert", root / "missing" / "sb-demo.SlackBuild", "--source", "slackbuilds",
            "--output", root / "nope", status=6)
        # import takes the same conversion path
        write(package / "sb-demo.SlackBuild", """PRGNAM=sb-imported
VERSION=1
BUILD=1
set -e
mkdir -p $PKG/usr/share/sb-imported
printf 'data\\n' > $PKG/usr/share/sb-imported/data
cd $PKG
/sbin/makepkg x
""")
        run("import", package / "sb-demo.SlackBuild", "--source", "slackbuilds",
            "--format", "slackbuild", "--output", root / "imported", status=3)
        assert (root / "imported" / "conversion").is_file()
        assert (root / "imported" / "sb-imported.recipe").is_file()
    return 0


if __name__ == "__main__":
    sys.exit(main())
