#!/usr/bin/env python3
"""converts APKBUILD fixtures into holy recipes and builds the produced manifests."""
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
    write(directory / "LICENSE", "fixture license text\n")
    return directory


def main():
    if not shutil.which("lz4"):
        print("lz4 required for aports fixture", file=sys.stderr)
        return 6
    for tool in ("gcc", "make", "tar"):
        if not shutil.which(tool):
            print(f"{tool} required for aports fixture", file=sys.stderr)
            return 6
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        source = source_tree(root, "aports-demo", "2.1.0")
        archive = root / "aports-demo-2.1.0.tar.gz"
        subprocess.run(["tar", "czf", str(archive), "-C", str(root), "aports-demo-2.1.0"],
                       check=True)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()

        package = root / "aports-demo"
        package.mkdir()
        shutil.copy(archive, package / "aports-demo-2.1.0.tar.gz")
        write(package / "APKBUILD", f"""# Maintainer: Fixture <fixture@example.org>
maintainer="Fixture <fixture@example.org>"
pkgname=aports-demo
pkgver=2.1.0
pkgrel=2
pkgdesc="APKBUILD conversion fixture"
url="https://example.org/aports-demo"
arch="x86_64"
license="MIT"
depends="glibc>=2.38 !musl"
makedepends="
\tgcc
\tmake
\t"
checkdepends="tar"
if [ "$CARCH" = "x86_64" ]; then
\tdepends="$depends
\tzlib>=1.3
\t"
fi
subpackages="
\t$pkgname-dev
\t$pkgname-doc
\t$pkgname-extras:extras
\t$pkgname-static
\t"
install="$pkgname.post-install"
source="aports-demo-$pkgver.tar.gz
\t0001-greeting.patch
\t"
sha512sums="
{digest}  aports-demo-2.1.0.tar.gz
"

build() {{
\tmake $MAKEFLAGS PREFIX=/usr
}}

check() {{
\tmake check
}}

package() {{
\tmake PREFIX=/usr DESTDIR="$pkgdir" install
\tmkdir -p "$pkgdir/etc" "$pkgdir/usr/share/doc/aports-demo"
\tprintf 'enabled = 1\\n' > "$pkgdir/etc/aports-demo.conf"
\tprintf 'readme\\n' > "$pkgdir/usr/share/doc/aports-demo/README"
}}

dev() {{
\tmkdir -p "$subpkgdir/usr/share"
\tmv "$pkgdir"/usr/include "$pkgdir"/usr/lib "$subpkgdir"/usr/\n\tmv "$pkgdir"/usr/share-greeting "$subpkgdir"/usr/share/dev-greeting
}}

doc() {{
\tdefault_doc
\tmkdir -p "$subpkgdir/usr/share"
\tmv "$pkgdir"/usr/share/doc "$subpkgdir"/usr/share/doc
}}

extras() {{
\tmkdir -p "$subpkgdir/usr/share/aports-demo"
\tprintf 'extra\\n' > "$subpkgdir/usr/share/aports-demo/extra"
}}
""")
        write(package / "0001-greeting.patch",
              "--- a/main.c\n+++ b/main.c\n@@ -1 +1 @@\n"
              '-#include <stdio.h>\n+#include <stdio.h> /* patched */\n')
        write(package / "aports-demo.post-install", 'case "$ACTION" in\n  post) echo ok;;\nesac\n')

        out = run("convert", package / "APKBUILD", "--source", "aports",
                  "--output", root / "conv", status=3)
        assert "converted aports-demo status review-required" in out
        recipe = (root / "conv" / "aports-demo.recipe").read_text()
        report = (root / "conv" / "conversion").read_text()
        assert (root / "conv" / "APKBUILD").read_text() == (package / "APKBUILD").read_text()
        assert hashlib.sha256((root / "conv" / "APKBUILD").read_bytes()).hexdigest() in report
        assert (root / "conv" / "aports-demo-2.1.0.tar.gz").is_file()
        assert (root / "conv" / "aports-demo.post-install").is_file()

        # identity, dependencies and provenance are carried
        assert 'name "aports-demo"' in recipe and 'version "2.1.0"' in recipe
        assert 'release "2"' in recipe and 'arch "x86_64"' in recipe and 'libc any' in recipe
        assert 'license "MIT"' in recipe and 'summary "APKBUILD conversion fixture"' in recipe
        assert 'homepage "https://example.org/aports-demo"' in recipe
        assert 'x-source-family apk' in recipe and 'x-converter aports-1' in recipe
        assert 'x-maintainer "Fixture <fixture@example.org>"' in recipe
        assert f'source "aports-demo-2.1.0.tar.gz" "aports-demo-2.1.0.tar.gz"' in recipe
        assert f'source-sha256 "aports-demo-2.1.0.tar.gz" "{digest}"' in recipe
        assert 'depend "glibc" "ge" "2.38"' in recipe
        assert 'x-conflicts "musl"' in recipe
        assert 'build-depend "gcc" "any" "-"' in recipe
        assert 'build-depend "make" "any" "-"' in recipe
        assert 'build-depend "tar" "any" "-"' in recipe
        # the abuild working variables are rebuilt from the exported Holy paths
        assert 'srcdir="$HOLY_SRC"' in recipe
        assert 'DESTDIR="$HOLY_DEST"' in recipe
        assert 'PKGDESTDIR="$HOLY_DEST"' in recipe
        assert 'PKGDESTDIR="$HOLY_SPLIT_DEST"' in recipe
        assert 'cd "$builddir"' in recipe
        # each split function becomes its own output
        assert 'output "aports-demo" runtime' in recipe
        assert 'output "aports-demo-dev" runtime' in recipe
        assert 'output "aports-demo-doc" runtime' in recipe
        assert 'output "aports-demo-extras" runtime' in recipe
        # a subpackage with no written split function has no output of its own
        assert 'output "aports-demo-static" runtime' not in recipe
        assert 'split-step aports-demo-extras split /bin/sh' in recipe
        assert 'mv "$pkgdir"/usr/share-greeting "$subpkgdir"/usr/share/dev-greeting' in recipe
        # an install action script becomes one hook
        assert 'hook-install /bin/sh "usr/share/holy/aports-demo/aports-demo.post-install"' \
            in recipe

        # the report names what was carried, preserved and what stayed unknown
        assert "status review-required" in report
        assert "preserved build APKBUILD:" in report
        assert "preserved package APKBUILD:" in report
        assert "preserved subpackage aports-demo-extras from extras APKBUILD:" in report
        # a conditional block and the append inside it are named with their lines, and nothing
        # the block adds reaches the dependency list
        assert 'unknown conditional block APKBUILD:16 if [ "$CARCH" = "x86_64" ]; then' in report
        assert "unknown conditional assignment depends APKBUILD:19" in report
        assert 'depend "zlib" "ge" "1.3"' in recipe
        # an append writes the list into itself, and no resolver could satisfy that name
        assert "unknown dependency $depends is the list appending to itself" in report
        assert '"$depends"' not in recipe
        assert "preserved hook aports-demo.post-install" in report
        assert "preserved conflict musl" in report
        assert "unknown helper default_doc is not carried in aports-demo-doc" in report
        assert "unknown subpackage aports-demo-static needs the abuild default_static helper" \
            in report
        assert "preserved subpackage aports-demo-dev from dev APKBUILD:" in report
        assert "unknown sha512sums pins a digest a Holy source cannot use" in report
        assert "helper abuild runs default_prepare" in report
        # abuild is the helper environment, and its digest reaches the built artifact
        assert "helper-environment abuild" in report
        env_digest = report.split("helper-environment-sha256 ")[1].split()[0]
        assert f'x-helper-environment-sha256 "{env_digest}"' in recipe
        assert "semantic-change local source aports-demo-2.1.0.tar.gz copied" in report
        assert "unknown dependency musl uses a resolver-specific prefix" not in report

        # the converted recipe builds through the normal engine
        run("build", root / "conv" / "aports-demo.recipe", "--output", root / "built", "--yes")
        library, _ = read_metadata(root / "built" / "aports-demo--x86_64--glibc.holy")
        devel, _ = read_metadata(root / "built" / "aports-demo-dev--noarch--nolibc.holy")
        document, _ = read_metadata(root / "built" / "aports-demo-doc--noarch--nolibc.holy")
        extras, _ = read_metadata(root / "built" / "aports-demo-extras--noarch--nolibc.holy")
        assert 'arch "x86_64"' in library["HOLY/meta"]
        assert 'libc "glibc"' in library["HOLY/meta"]
        assert 'x-source-family "apk"' in library["HOLY/meta"]
        assert "usr/bin/aports-demo" in library["HOLY/files"]
        assert digest in library["HOLY/origin"]
        assert "gcc" in library["HOLY/transform"]
        assert f'x-helper-environment-sha256 "{env_digest}"' in library["HOLY/meta"]
        assert '"usr/bin/aports-demo" "holy-recipe"' in library["HOLY/deps"]
        assert "usr/share/dev-greeting" in devel["HOLY/files"]
        assert "usr/include/main.h" in devel["HOLY/files"]
        assert "usr/bin/aports-demo" not in devel["HOLY/files"]
        assert "usr/lib/pkgconfig/aports-demo.pc" in devel["HOLY/files"]
        assert "usr/lib/pkgconfig/aports-demo.pc" not in library["HOLY/files"]
        assert "usr/share/doc/aports-demo/README" in document["HOLY/files"]
        assert "usr/share/aports-demo/extra" in extras["HOLY/files"]
        assert "usr/include/main.h" not in extras["HOLY/files"]
        # the hook script travels in the payload of the output that declares it
        data = read_metadata(root / "built" / "aports-demo--noarch--nolibc.holy")[0]
        assert "usr/share/holy/aports-demo/aports-demo.post-install" in data["HOLY/files"]
        assert 'hook postinstall "/bin/sh" "usr/share/holy/aports-demo/aports-demo.post-install"' \
            in data["HOLY/hooks"]

        # unreviewed steps still need a decision
        run("build", root / "conv" / "aports-demo.recipe", "--output", root / "unreviewed",
            "--noninteractive", status=3)

        # a filename:: target, a remote source without a sha256 and an unreadable statement
        write(package / "APKBUILD", """pkgname=aports-remote
pkgver=1.0
pkgrel=0
pkgdesc="Remote source fixture"
url="https://example.org"
arch="noarch"
license="MIT"
source="aports-remote-1.0.tar.gz::https://example.org/download?id=1"
sha256sums="0000000000000000000000000000000000000000000000000000000000000000  aports-remote-1.0.tar.gz"
options="!check"

[ -n "$CARCH" ] && options="!check"

package() {
	mkdir -p "$pkgdir/usr/share/aports-remote"
	printf 'data\\n' > "$pkgdir/usr/share/aports-remote/data"
}
""")
        out = run("convert", package / "APKBUILD", "--source", "aports",
                  "--output", root / "remote", status=3)
        assert "converted aports-remote status review-required" in out
        recipe = (root / "remote" / "aports-remote.recipe").read_text()
        report = (root / "remote" / "conversion").read_text()
        assert 'arch "noarch"' in recipe
        assert 'source "aports-remote-1.0.tar.gz" "https://example.org/download?id=1"' in recipe
        assert "unknown unreadable statement APKBUILD:12" in report
        assert "preserved options" in report
        assert 'x-options "!check"' in recipe

        # an install action with no Holy stage is reported instead of mapped
        write(package / "APKBUILD", """pkgname=aports-action
pkgver=1
pkgrel=0
pkgdesc="Install action fixture"
url="https://example.org"
arch="all"
license="MIT"
install="$pkgname.post-upgrade"

package() {
	mkdir -p "$pkgdir/usr/share/aports-action"
}
""")
        write(package / "aports-action.post-upgrade", "echo upgraded\n")
        run("convert", package / "APKBUILD", "--source", "aports",
            "--output", root / "action", status=3)
        report = (root / "action" / "conversion").read_text()
        assert "unknown install action aports-action.post-upgrade has no Holy hook stage" in report

        # a subpackage that names its own arch and a depends_dev list are reported
        write(package / "APKBUILD", """pkgname=aports-arch
pkgver=1
pkgrel=0
pkgdesc="Arch fixture"
url="https://example.org"
arch="all !s390x"
license="MIT"
depends_dev="linux-headers"
subpackages="$pkgname-data::noarch"

package() {
	mkdir -p "$pkgdir/usr/share/aports-arch"
}

data() {
	mv "$pkgdir"/usr/share/aports-arch "$subpkgdir"/usr/share
}
""")
        run("convert", package / "APKBUILD", "--source", "aports",
            "--output", root / "arch", status=3)
        recipe = (root / "arch" / "aports-arch.recipe").read_text()
        report = (root / "arch" / "conversion").read_text()
        assert 'arch "noarch"' in recipe
        assert "preserved arch all !s390x" in report
        assert "preserved depends_dev APKBUILD:8" in report
        assert "preserved subpackage aports-arch-data declares its own arch noarch" in report
        assert 'split-step aports-arch-data split /bin/sh' in recipe

        # malformed text and unusable arguments
        write(package / "APKBUILD", "pkgname=broken\npkgver=1\npkgrel=0\nbuild() {\n  true\n")
        run("convert", package / "APKBUILD", "--source", "aports",
            "--output", root / "bad", status=2)
        write(package / "APKBUILD", "pkgname=broken\npkgver=$(date +%s)\npkgrel=0\n")
        run("convert", package / "APKBUILD", "--source", "aports",
            "--output", root / "dynamic", status=2)
        write(package / "APKBUILD", "pkgname=broken\npkgrel=0\n")
        run("convert", package / "APKBUILD", "--source", "aports",
            "--output", root / "missing-version", status=2)
        run("convert", package / "APKBUILD", "--source", "aports", status=2)
        run("convert", package / "APKBUILD", "--source", "local",
            "--output", root / "nope", status=2)
        run("convert", package / "APKBUILD", "--source", "aports:extra",
            "--output", root / "nope", status=2)
        run("convert", root / "missing" / "APKBUILD", "--source", "aports",
            "--output", root / "nope", status=6)
        # import takes the same conversion path
        write(package / "APKBUILD", """pkgname=aports-imported
pkgver=1
pkgrel=0
pkgdesc="Import fixture"
url="https://example.org"
arch="noarch"
license="MIT"

package() {
\tmkdir -p "$pkgdir/usr/share/aports-imported"
}
""")
        run("import", package / "APKBUILD", "--source", "aports", "--format", "aports",
            "--output", root / "imported", status=3)
        assert (root / "imported" / "conversion").is_file()
        assert (root / "imported" / "aports-imported.recipe").is_file()
    return 0


if __name__ == "__main__":
    sys.exit(main())
