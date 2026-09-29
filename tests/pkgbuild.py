#!/usr/bin/env python3
"""converts PKGBUILD fixtures into holy recipes and builds the produced manifests."""
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
\tmkdir -p $(DESTDIR)/usr/bin $(DESTDIR)/usr/share/%(name)s
\tcp bin/%(name)s $(DESTDIR)/usr/bin/
\tprintf 'greeting\\n' > $(DESTDIR)/usr/share/%(name)s/greeting
""" % {"name": name})
    write(directory / "main.c", '#include <stdio.h>\nint main(void){printf("hi\\n");return 0;}\n')
    write(directory / "README", f"{name} documentation\n")
    write(directory / "etc" / f"{name}.conf", "enabled = 1\n")
    return directory


def main():
    if not shutil.which("lz4"):
        print("lz4 required for pkgbuild fixture", file=sys.stderr)
        return 6
    for tool in ("gcc", "make", "tar"):
        if not shutil.which(tool):
            print(f"{tool} required for pkgbuild fixture", file=sys.stderr)
            return 6
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        source = source_tree(root, "pkgbuild-demo", "1.2.3")
        archive = root / "pkgbuild-demo-1.2.3.tar.gz"
        subprocess.run(["tar", "czf", str(archive), "-C", str(root), "pkgbuild-demo-1.2.3"],
                       check=True)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        write(root / "PKGBUILD", f"""# Maintainer: Fixture <fixture@example.org>
pkgname=pkgbuild-demo
pkgbase=pkgbuild-demo
pkgver=1.2.3
pkgrel=2
pkgdesc="PKGBUILD conversion fixture"
arch=('x86_64')
url="https://example.org/pkgbuild-demo"
license=('MIT')
epoch=1
depends=('glibc' 'zlib>=1.3')
makedepends=('gcc' 'make')
optdepends=('python: scripting')
backup=('etc/pkgbuild-demo.conf')
install=pkgbuild-demo.install
source=("pkgbuild-demo-$pkgver.tar.gz")
sha256sums=('{digest}')

build() {{
  cd "$srcdir/pkgbuild-demo-$pkgver"
  make -j"$HOLY_JOBS" CFLAGS="$CFLAGS"
}}

check() {{
  cd "$srcdir/pkgbuild-demo-$pkgver"
  make check
}}

package() {{
  cd "$srcdir/pkgbuild-demo-$pkgver"
  make DESTDIR="$pkgdir" PREFIX=/usr install
  install -Dm644 etc/pkgbuild-demo.conf "$pkgdir/etc/pkgbuild-demo.conf"
}}

package_docs() {{
  mkdir -p "$pkgdir/usr/share/doc/$pkgname"
  install -Dm644 "$srcdir/pkgbuild-demo-$pkgver/README" "$pkgdir/usr/share/doc/$pkgname/README"
}}
""")
        write(root / "pkgbuild-demo.install", "post_install() {\n  echo installed\n}\n")

        out = run("convert", root / "PKGBUILD", "--source", "aur",
                  "--output", root / "conv")
        assert "converted pkgbuild-demo status native" in out
        recipe = (root / "conv" / "pkgbuild-demo.recipe").read_text()
        report = (root / "conv" / "conversion").read_text()
        assert (root / "conv" / "PKGBUILD").read_text() == (root / "PKGBUILD").read_text()
        assert (root / "conv" / "pkgbuild-demo-1.2.3.tar.gz").is_file()
        assert (root / "conv" / "pkgbuild-demo.install").is_file()
        assert hashlib.sha256((root / "conv" / "PKGBUILD").read_bytes()).hexdigest() in report

        # identity, dependencies and provenance are carried
        assert 'name "pkgbuild-demo"' in recipe and 'version "1.2.3"' in recipe
        assert 'release "2"' in recipe and 'arch "x86_64"' in recipe
        assert 'license "MIT"' in recipe and 'x-epoch "1"' in recipe
        assert 'build-depend "gcc" "any" "-"' in recipe
        assert 'depend "zlib" "ge" "1.3"' in recipe
        assert 'x-optdepend "python" "scripting"' in recipe
        assert 'config "etc/pkgbuild-demo.conf"' in recipe
        assert 'source "pkgbuild-demo-1.2.3.tar.gz" "pkgbuild-demo-1.2.3.tar.gz"' in recipe
        assert f'source-sha256 "pkgbuild-demo-1.2.3.tar.gz" "{digest}"' in recipe
        assert 'hook-install /bin/bash "usr/share/holy/pkgbuild-demo/pkgbuild-demo.install"' in recipe
        assert 'output "pkgbuild-demo" runtime' in recipe
        assert 'output "pkgbuild-demo-docs" runtime' in recipe
        assert 'split-step pkgbuild-demo-docs split /bin/bash' in recipe
        # the makepkg working variables point at the exported Holy paths
        assert 'cd "$srcdir/pkgbuild-demo-$pkgver"' not in recipe
        assert 'cd "$HOLY_SRC/pkgbuild-demo-$pkgver"' in recipe
        assert 'DESTDIR="$HOLY_DEST"' in recipe
        assert '"$pkgdir/usr/share/doc/$pkgname"' not in recipe
        assert '"$HOLY_SPLIT_DEST/usr/share/doc/$pkgname"' in recipe

        # the report names what was carried, preserved and what stayed unknown
        assert "status native" in report
        assert "preserved build PKGBUILD:" in report
        assert "preserved split pkgbuild-demo-docs PKGBUILD:" in report
        assert "preserved hook pkgbuild-demo.install PKGBUILD:" in report
        assert "helper makepkg.conf" in report
        assert "semantic-change single source lifted" in report
        assert "unknown 0" in report

        # the converted recipe builds through the normal engine
        run("build", root / "conv" / "pkgbuild-demo.recipe", "--output", root / "built",
            "--yes")
        library = root / "built" / "pkgbuild-demo--x86_64--glibc.holy"
        data = root / "built" / "pkgbuild-demo--noarch--nolibc.holy"
        docs = root / "built" / "pkgbuild-demo-docs--noarch--nolibc.holy"
        library_meta, _ = read_metadata(library)
        data_meta, _ = read_metadata(data)
        docs_meta, _ = read_metadata(docs)
        assert 'arch "x86_64"' in library_meta["HOLY/meta"]
        assert 'libc "glibc"' in library_meta["HOLY/meta"]
        assert 'x-source-family "pacman"' in library_meta["HOLY/meta"]
        assert 'x-converter "pkgbuild-1"' in library_meta["HOLY/meta"]
        assert "usr/bin/pkgbuild-demo" in library_meta["HOLY/files"]
        assert "config" in data_meta["HOLY/files"]
        assert "usr/share/holy/pkgbuild-demo/pkgbuild-demo.install" in data_meta["HOLY/files"]
        assert "README" in docs_meta["HOLY/files"]
        assert "pkgbuild-demo" not in docs_meta["HOLY/files"].split("\n")[0]
        # the shared library requirement stays with the output that carries the file
        assert '"usr/bin/pkgbuild-demo" "holy-recipe"' in library_meta["HOLY/deps"]
        assert '"usr/bin/pkgbuild-demo"' not in data_meta["HOLY/deps"]
        assert '"usr/bin/pkgbuild-demo"' not in docs_meta["HOLY/deps"]
        assert 'hook postinstall "/bin/bash" "usr/share/holy/pkgbuild-demo/pkgbuild-demo.install"' \
            in data_meta["HOLY/hooks"]
        assert "postinstall" not in docs_meta["HOLY/hooks"]
        assert digest in data_meta["HOLY/origin"]

        # review gates: unreviewed steps and a missing source
        run("build", root / "conv" / "pkgbuild-demo.recipe", "--output", root / "unreviewed",
            "--noninteractive", status=3)
        write(root / "PKGBUILD-git", """pkgname=pkgbuild-git
pkgver=r42.abcdef
pkgrel=1
pkgdesc="VCS fixture"
arch=('x86_64')
license=('custom')
source=('pkgbuild-git::git+https://example.org/pkgbuild.git')
sha256sums=('SKIP')
pkgver() {
  cd pkgbuild-git
  printf 'r42.abcdef\\n'
}

package() {
  install -Dm644 README "$pkgdir/usr/share/doc/$pkgname/README"
}
""")
        out = run("convert", root / "PKGBUILD-git", "--source", "aur",
                  "--output", root / "git", status=3)
        assert "converted pkgbuild-git status review-required" in out
        report = (root / "git" / "conversion").read_text()
        assert "status review-required" in report
        assert "function pkgver" in report
        assert "unknown source" in report
        assert (root / "git" / "pkgbuild-git.recipe").is_file()

        # a list element keeps its commas, and a brace inside a parameter
        # expansion does not end a function body
        write(root / "PKGBUILD-list", """pkgname=pkgbuild-list
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
depends=(
  'alpha>=1.0'
  'beta: needed for beta'
  'gamma: has a ) paren'
  'delta,' 'epsilon'
)
optdepends=('zeta: needs ) and spaces')

prepare() {
  msg="a } b"
  printf '%s\\n' "${msg#\\}}" > marker
}

package() {
  install -Dm644 marker "$pkgdir/usr/share/pkgbuild-list/marker"
}
""")
        run("convert", root / "PKGBUILD-list", "--source", "aur",
            "--output", root / "list")
        recipe = (root / "list" / "pkgbuild-list.recipe").read_text()
        assert 'depend "alpha" "ge" "1.0"' in recipe
        assert 'depend "beta" "any" "-"' in recipe
        assert 'depend "gamma" "any" "-"' in recipe
        # a comma inside quotes is part of the name, not a separator
        assert 'depend "delta," "any" "-"' in recipe
        assert 'depend "epsilon" "any" "-"' in recipe
        assert 'x-optdepend "zeta" "needs ) and spaces"' in recipe
        assert "preserved prepare PKGBUILD:" in \
            (root / "list" / "conversion").read_text()

        # a metapackage PKGBUILD without a package function
        write(root / "PKGBUILD-meta", """pkgname=pkgbuild-meta
pkgver=1
pkgrel=1
arch=('any')
license=('custom')
""")
        out = run("convert", root / "PKGBUILD-meta", "--source", "aur",
                  "--output", root / "meta")
        assert "converted pkgbuild-meta status native" in out
        assert 'output "pkgbuild-meta" metapackage' in \
            (root / "meta" / "pkgbuild-meta.recipe").read_text()

        # malformed input and unusable arguments
        write(root / "PKGBUILD-bad", "pkgname=broken\npkgver=1\npkgrel=1\nbuild() {\n  true\n")
        run("convert", root / "PKGBUILD-bad", "--source", "aur",
            "--output", root / "bad", status=2)
        # a computed version is refused instead of being guessed
        write(root / "PKGBUILD-dynamic", """pkgname=broken-dynamic
pkgver=$(date +%s)
pkgrel=1
arch=('x86_64')
""")
        run("convert", root / "PKGBUILD-dynamic", "--source", "aur",
            "--output", root / "dynamic", status=2)
        run("convert", root / "PKGBUILD", "--source", "local",
            "--output", root / "nope", status=2)
        run("convert", root / "PKGBUILD", "--source", "arch:extra",
            "--output", root / "nope", status=2)
        run("convert", root / "PKGBUILD", "--source", "aur", status=2)
        run("convert", root / "missing", "--source", "aur",
            "--output", root / "nope", status=6)
        run("import", root / "PKGBUILD", "--source", "aur", "--format", "pkgbuild",
            "--output", root / "imported")
        assert (root / "imported" / "pkgbuild-demo.recipe").is_file()

        # a split step in a hand written recipe owns its whole staging tree
        write(root / "split.recipe", """format holy-recipe-1
name split-demo
version 1
release 1
arch noarch
libc nolibc
output split-demo runtime
output split-demo-extra runtime
step package /bin/sh <<PACKAGE
mkdir -p "$HOLY_DEST/usr/share/split-demo"
printf 'main\\n' > "$HOLY_DEST/usr/share/split-demo/main"
PACKAGE
split-step split-demo-extra split /bin/sh <<SPLIT
mkdir -p "$HOLY_SPLIT_DEST/usr/share/split-demo"
printf 'extra\\n' > "$HOLY_SPLIT_DEST/usr/share/split-demo/extra"
SPLIT
""")
        run("build", root / "split.recipe", "--output", root / "split-out", "--yes")
        main_meta, _ = read_metadata(root / "split-out" / "split-demo--noarch--nolibc.holy")
        extra_meta, _ = read_metadata(root / "split-out" /
                                      "split-demo-extra--noarch--nolibc.holy")
        assert "main" in main_meta["HOLY/files"]
        assert "extra" not in main_meta["HOLY/files"]
        assert "extra" in extra_meta["HOLY/files"]
        assert "main" not in extra_meta["HOLY/files"]

        # a build without --work keeps its private root for the whole run
        run("build", root / "split.recipe", "--output", root / "implicit-out", "--yes")
        implicit, _ = read_metadata(root / "implicit-out" /
                                    "split-demo--noarch--nolibc.holy")
        assert "main" in implicit["HOLY/files"]
        write(root / "keep.recipe", """format holy-recipe-1
name keep-demo
version 1
release 1
arch noarch
libc nolibc
output keep-demo runtime
step package /bin/sh <<PACKAGE
printf 'kept\\n' > "$HOLY_DEST/kept"
PACKAGE
""")
        kept = run("build", root / "keep.recipe", "--output", root / "keep-out",
                   "--yes", "--keep")
        root_path = Path(kept.split("build root kept ")[1].split()[0])
        assert root_path.is_dir() and (root_path / "dest").is_dir()
        # a root named by --work belongs to the caller, so it survives either way
        named = root / "named-work"
        named.mkdir()
        kept = run("build", root / "keep.recipe", "--output", root / "keep-out-2",
                   "--work", named, "--yes", "--keep")
        assert "build root kept (caller)" in kept
        assert named.is_dir()
        write(root / "bad-split.recipe", """format holy-recipe-1
name split-bad
version 1
release 1
arch noarch
libc nolibc
output split-bad runtime
split-step split-missing split /bin/sh <<SPLIT
exit 0
SPLIT
""")
        run("build", root / "bad-split.recipe", "--output", root / "bad-split",
            "--yes", status=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
