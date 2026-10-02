#!/usr/bin/env python3
"""converts Void template fixtures into holy recipes and builds the produced manifests."""
import hashlib
import io
import os
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
                ("HOLY/meta", "HOLY/files", "HOLY/deps", "HOLY/provides", "HOLY/hooks",
                 "HOLY/origin", "HOLY/transform")}, names


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def source_tree(root, name, version):
    directory = root / f"{name}-{version}"
    (directory / "etc").mkdir(parents=True)
    write(directory / "Makefile", """CFLAGS ?= -O2 -pipe
all: bin/%(name)s
bin/%(name)s: main.c
\tmkdir -p bin
\t$(CC) $(CFLAGS) -o $@ main.c
check: bin/%(name)s
\t./bin/%(name)s
install: bin/%(name)s
\tmkdir -p $(DESTDIR)/usr/bin $(DESTDIR)/usr/include $(DESTDIR)/usr/lib/pkgconfig
\tcp bin/%(name)s $(DESTDIR)/usr/bin/
\tcp main.h $(DESTDIR)/usr/include/
\tcp %(name)s.pc $(DESTDIR)/usr/lib/pkgconfig/
\tprintf 'greeting\\n' > $(DESTDIR)/usr/share-greeting
""" % {"name": name})
    write(directory / "main.c", '#include <stdio.h>\nint main(void){printf("hi\\n");return 0;}\n')
    write(directory / "main.h", "/* header */\n")
    write(directory / f"{name}.pc", "Name: %s\n" % name)
    write(directory / "README", f"{name} documentation\n")
    write(directory / "LICENSE", "fixture license text\n")
    return directory


def main():
    if not shutil.which("lz4"):
        print("lz4 required for void fixture", file=sys.stderr)
        return 6
    for tool in ("gcc", "make", "tar", "patch"):
        if not shutil.which(tool):
            print(f"{tool} required for void fixture", file=sys.stderr)
            return 6
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        source = source_tree(root, "void-demo", "1.4.2")
        archive = root / "void-demo-1.4.2.tar.gz"
        subprocess.run(["tar", "czf", str(archive), "-C", str(root), "void-demo-1.4.2"],
                       check=True)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()

        # a template with its own build steps, a patches directory and two subpackages
        package = root / "void-demo"
        package.mkdir()
        write(package / "template", f"""# Template file for 'void-demo'
pkgname=void-demo
version=1.4.2
revision=3
build_style=gnu-makefile
short_desc="Void template conversion fixture"
maintainer="Fixture <fixture@example.org>"
license="MIT"
homepage="https://example.org/void-demo"
changelog="https://example.org/void-demo/CHANGES"
distfiles="void-demo-${{version}}.tar.gz"
checksum={digest}
makedepends="gcc make patch"
hostmakedepends="pkgconf"
checkdepends="tar"
depends="glibc>=2.38"
conf_files="/etc/void-demo.conf"
make_build_args="CC=gcc"

do_build() {{
\tmake ${{makejobs}} PREFIX=/usr
}}

do_check() {{
\tmake check
}}

do_install() {{
\tinstall -d "$DESTDIR/etc"
\tmake PREFIX=/usr DESTDIR="$DESTDIR" install
\tprintf 'enabled = 1\\n' > "$DESTDIR/etc/void-demo.conf"
\tvlicense LICENSE
}}

void-demo-devel_package() {{
\tshort_desc+=" - development files"
\tdepends="${{sourcepkg}}>=${{version}}_${{revision}}"
\tpkg_install() {{
\t\tvmove usr/include
\t\tvmove usr/lib/pkgconfig
\t}}
}}

void-demo-doc_package() {{
\tpkg_install() {{
\t\tvmove usr/share-greeting
\t}}
}}
""")
        write(package / "patches" / "0001-greeting.patch",
              "--- a/main.c\n+++ b/main.c\n@@ -1 +1 @@\n"
              '-#include <stdio.h>\n+#include <stdio.h> /* patched */\n')
        write(package / "patches" / "0001-greeting.patch.args", "-Np1\n")
        shutil.copy(archive, package / "void-demo-1.4.2.tar.gz")

        out = run("convert", package / "template", "--source", "voidpkgs",
                  "--output", root / "conv", status=3)
        assert "converted void-demo status review-required" in out
        recipe = (root / "conv" / "void-demo.recipe").read_text()
        report = (root / "conv" / "conversion").read_text()
        assert (root / "conv" / "template").read_text() == (package / "template").read_text()
        assert hashlib.sha256((root / "conv" / "template").read_bytes()).hexdigest() in report
        assert (root / "conv" / "patches.tar").is_file()

        # identity, dependencies and provenance are carried
        assert 'name "void-demo"' in recipe and 'version "1.4.2"' in recipe
        assert 'release "3"' in recipe and 'arch any' in recipe and 'libc any' in recipe
        assert 'license "MIT"' in recipe
        assert 'x-source-family xbps' in recipe and 'x-converter voidsrc-1' in recipe
        assert 'x-build-style "gnu-makefile"' in recipe
        assert 'x-maintainer "Fixture <fixture@example.org>"' in recipe
        # a local distfile travels with the recipe, so the build needs no network
        assert 'source "void-demo-1.4.2.tar.gz" "void-demo-1.4.2.tar.gz"' in recipe
        assert f'source-sha256 "void-demo-1.4.2.tar.gz" "{digest}"' in recipe
        assert (root / "conv" / "void-demo-1.4.2.tar.gz").is_file()
        assert 'build-depend "gcc" "any" "-"' in recipe
        assert 'build-depend "pkgconf" "any" "-"' in recipe
        assert 'build-depend "patch" "any" "-"' in recipe
        assert 'depend "glibc" "ge" "2.38"' in recipe
        assert 'config "etc/void-demo.conf"' in recipe
        assert 'output "void-demo" runtime' in recipe
        assert 'output "void-demo-devel" runtime' in recipe
        assert 'output "void-demo-doc" runtime' in recipe
        assert 'split-step void-demo-devel split /bin/bash' in recipe
        assert 'split-step void-demo-doc split /bin/bash' in recipe
        # the xbps-src working variables are rebuilt from the exported Holy paths
        assert 'DESTDIR="$HOLY_DEST"' in recipe
        assert 'PKGDESTDIR="$HOLY_DEST"' in recipe
        assert 'PKGDESTDIR="$HOLY_SPLIT_DEST"' in recipe
        assert 'vmove usr/include' in recipe
        assert 'vinstall() {' in recipe
        # the patch directory arrives as one staged archive
        assert 'source "patches" "patches.tar"' in recipe
        assert "patch -s $patch_args" in recipe

        # the report names what was carried, preserved and what stayed unknown
        assert "status review-required" in report
        assert "preserved do_build template:" in report
        assert "preserved do_install template:" in report
        assert "preserved subpackage void-demo-devel template:" in report
        assert "preserved depends depends=" in report
        assert "helper common/build-style/gnu-makefile.sh" in report
        assert "helper v* helpers carried" in report
        # the build style and the shared helper scripts are the environment this
        # converter does not run, and their ordered digest reaches the recipe
        assert "helper-environment gnu-makefile" in report
        assert "helper-environment common/environment/setup/install.sh" in report
        env_digest = report.split("helper-environment-sha256 ")[1].split()[0]
        assert f'x-helper-environment-sha256 "{env_digest}"' in recipe
        assert "semantic-change distfiles are extracted into HOLY_SRC" in report

        # the converted recipe builds through the normal engine
        run("build", root / "conv" / "void-demo.recipe", "--output", root / "built", "--yes")
        library, _ = read_metadata(root / "built" / "void-demo--x86_64--glibc.holy")
        data, _ = read_metadata(root / "built" / "void-demo--noarch--nolibc.holy")
        devel, _ = read_metadata(root / "built" / "void-demo-devel--noarch--nolibc.holy")
        docs, _ = read_metadata(root / "built" / "void-demo-doc--noarch--nolibc.holy")
        assert 'arch "x86_64"' in library["HOLY/meta"]
        assert 'libc "glibc"' in library["HOLY/meta"]
        assert 'x-source-family "xbps"' in library["HOLY/meta"]
        assert 'x-build-style "gnu-makefile"' in library["HOLY/meta"]
        assert "usr/bin/void-demo" in library["HOLY/files"]
        # a file without ELF lands in the noarch output and keeps its config flag
        assert "etc/void-demo.conf" in data["HOLY/files"]
        assert "config" in data["HOLY/files"]
        assert "usr/share/licenses/void-demo/LICENSE" in data["HOLY/files"]
        assert "usr/include/main.h" in devel["HOLY/files"]
        assert "usr/lib/pkgconfig/void-demo.pc" in devel["HOLY/files"]
        assert "usr/share-greeting" in docs["HOLY/files"]
        assert "usr/bin/void-demo" not in devel["HOLY/files"]
        assert "etc/void-demo.conf" not in devel["HOLY/files"]
        assert "usr/include/main.h" not in docs["HOLY/files"]
        assert digest in library["HOLY/origin"]
        assert "gcc" in library["HOLY/transform"]
        assert '"usr/bin/void-demo" "holy-recipe"' in library["HOLY/deps"]

        # unreviewed steps still need a decision
        run("build", root / "conv" / "void-demo.recipe", "--output", root / "unreviewed",
            "--noninteractive", status=3)

        # a build style with no template step of its own reports the missing phase
        write(package / "template", """# Template file for 'void-style'
pkgname=void-style
version=2.0
revision=1
build_style=gnu-configure
short_desc="Build style fixture"
maintainer="Fixture <fixture@example.org>"
license="MIT"
distfiles="https://example.org/void-style-2.0.tar.xz"
checksum="0000000000000000000000000000000000000000000000000000000000000000"
""")
        out = run("convert", package / "template", "--source", "voidpkgs",
                  "--output", root / "style", status=3)
        assert "converted void-style status review-required" in out
        report = (root / "style" / "conversion").read_text()
        assert "helper common/build-style/gnu-configure.sh supplies the configure step" in report
        assert "helper common/build-style/gnu-configure.sh supplies the package step" in report
        assert "helper common/build-style/gnu-configure.sh supplies the build step" in report

        # a template with no build steps at all is native
        write(package / "template", """# Template file for 'void-data'
pkgname=void-data
version=1
revision=1
short_desc="Data only fixture"
maintainer="Fixture <fixture@example.org>"
license="MIT"
distfiles="void-data-1.tar.gz"
checksum=SKIP
metapackage=no

do_install() {
\tvmkdir usr/share/void-data
\tprintf 'data\\n' > "$PKGDESTDIR/usr/share/void-data/data"
}
""")
        write(package / "void-data-1.tar.gz", "not a real archive")
        run("convert", package / "template", "--source", "voidpkgs", "--output", root / "data",
            status=3)
        recipe = (root / "data" / "void-data.recipe").read_text()
        report = (root / "data" / "conversion").read_text()
        assert (root / "data" / "void-data-1.tar.gz").is_file()
        assert 'output "void-data" runtime' in recipe
        assert "unknown source void-data-1.tar.gz has no sha256 checksum" in report
        assert "semantic-change local distfile void-data-1.tar.gz copied" in report

        # build options are fixed to build_options_default and reported
        write(package / "template", """# Template file for 'void-options'
pkgname=void-options
version=3
revision=1
short_desc="Build option fixture"
maintainer="Fixture <fixture@example.org>"
license="MIT"
build_options="zlib docs"
build_options_default="zlib"
configure_args="--with-zlib=$(vopt_with zlib) --with-docs=$(vopt_with docs)"

do_install() {
\tprintf 'option\\n' > "$PKGDESTDIR/option"
}
""")
        out = run("convert", package / "template", "--source", "voidpkgs",
                  "--output", root / "options", status=3)
        assert "converted void-options status review-required" in out
        recipe = (root / "options" / "void-options.recipe").read_text()
        report = (root / "options" / "conversion").read_text()
        assert 'configure_args="--with-zlib=--with-zlib --with-docs=--without-docs"' in recipe
        assert "vopt_with" not in recipe
        assert "semantic-change build options fixed to build_options_default" in report
        assert 'x-build_options "zlib docs"' in recipe

        # a conditional block, an unknown helper and a site constant are reported
        write(package / "template", """# Template file for 'void-review'
pkgname=void-review
version=1
revision=1
short_desc="Review fixture"
maintainer="Fixture <fixture@example.org>"
license="MIT"
distfiles="${PYPI_SITE}/void-review-1.tar.gz"
checksum=0000000000000000000000000000000000000000000000000000000000000000

do_install() {
\tvsed -i Makefile -e 's/a/b/'
\tmsg_warn 'incomplete'
}

if [ "$CHROOT_READY" ]; then
void-review-extra_package() {
\tpkg_install() {
\t\tvmove usr/share/void-review
\t}
}
fi
""")
        out = run("convert", package / "template", "--source", "voidpkgs",
                  "--output", root / "review", status=3)
        assert "converted void-review status review-required" in out
        report = (root / "review" / "conversion").read_text()
        assert "unknown helper vsed is not carried in do_install" in report
        assert "unknown helper msg_warn is not carried in do_install" in report
        assert "unknown conditional block template:17 if [ \"$CHROOT_READY\" ]; then" in report
        assert "unknown distfile ${PYPI_SITE}/void-review-1.tar.gz uses an expansion" in report
        assert "unknown subpackage void-review-extra is defined in a conditional block" in report

        # an INSTALL file becomes one hook and its missing ACTION is reported
        write(package / "template", """# Template file for 'void-hook'
pkgname=void-hook
version=1
revision=1
short_desc="Hook fixture"
maintainer="Fixture <fixture@example.org>"
license="MIT"

do_install() {
\tvmkdir usr/bin
\tcp hook.sh "$PKGDESTDIR/usr/bin/hook.sh"
}
""")
        write(package / "INSTALL", 'case "$ACTION" in\n  post) msg_system "installed";;\nesac\n')
        run("convert", package / "template", "--source", "voidpkgs", "--output", root / "hook",
            status=3)
        recipe = (root / "hook" / "void-hook.recipe").read_text()
        report = (root / "hook" / "conversion").read_text()
        assert (root / "hook" / "INSTALL").is_file()
        assert 'hook-install /bin/bash "usr/share/holy/void-hook/INSTALL"' in recipe
        assert 'source "INSTALL" "INSTALL"' in recipe
        assert "preserved hook INSTALL" in report
        assert "semantic-change INSTALL runs with ACTION unset" in report
        assert 'cp "$HOLY_SRC/$hook_source" "$HOLY_DEST/$hook_source"' in recipe
        assert "usr/share/holy/void-hook" in recipe
        # import takes the same conversion path
        run("import", package / "template", "--source", "voidpkgs", "--format", "void",
            "--output", root / "imported", status=3)
        assert (root / "imported" / "void-hook.recipe").is_file()

        # malformed text, a missing identity and unusable arguments
        write(package / "template", "pkgname=broken\nversion=1\nrevision=1\ndo_build() {\n  true\n")
        run("convert", package / "template", "--source", "voidpkgs",
            "--output", root / "bad", status=2)
        write(package / "template", "pkgname=broken\nversion=$(date +%s)\nrevision=1\n")
        run("convert", package / "template", "--source", "voidpkgs",
            "--output", root / "dynamic", status=2)
        write(package / "template", "pkgname=broken\nrevision=1\n")
        run("convert", package / "template", "--source", "voidpkgs",
            "--output", root / "missing-version", status=2)
        run("convert", package / "template", "--source", "voidpkgs", status=2)
        run("convert", package / "template", "--source", "local",
            "--output", root / "nope", status=2)
        run("convert", package / "template", "--source", "void:extra",
            "--output", root / "nope", status=2)
        run("convert", root / "missing" / "template", "--source", "voidpkgs",
            "--output", root / "nope", status=6)
        run("convert", package / "template", "--source", "voidpkgs",
            "--output", root / "imported", "--format", "void", status=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
