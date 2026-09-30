#!/usr/bin/env python3
"""converts Pacstall pacscripts into holy recipes and builds the produced manifests."""
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
    directory.mkdir(parents=True)
    write(directory / "Makefile", """CFLAGS ?= -O2 -pipe
all: bin/%(name)s
bin/%(name)s: main.c
\tmkdir -p bin
\t$(CC) $(CFLAGS) -o $@ main.c
clean:
\trm -rf bin
check: bin/%(name)s
\t./bin/%(name)s
install: bin/%(name)s
\tmkdir -p $(DESTDIR)/usr/bin $(DESTDIR)/usr/share/%(name)s $(DESTDIR)/etc
\tcp bin/%(name)s $(DESTDIR)/usr/bin/
\tprintf 'greeting\\n' > $(DESTDIR)/usr/share/%(name)s/greeting
\tprintf 'enabled = 1\\n' > $(DESTDIR)/etc/%(name)s.conf
""" % {"name": name})
    write(directory / "main.c", '#include <stdio.h>\nint main(void){printf("hi\\n");return 0;}\n')
    write(directory / "README", f"{name} documentation\n")
    return directory


def convert(package, file_name, name=None, status=0, source="pacstall"):
    out = run("convert", package / f"{file_name}.pacscript", "--source", source,
              "--output", package / "conv", status=status)
    name = name or file_name
    return out, (package / "conv" / f"{name}.recipe").read_text(), \
        (package / "conv" / "conversion").read_text()


def beside(directory, archive):
    """a local source travels with the pacscript that names it"""
    directory.mkdir(parents=True, exist_ok=True)
    shutil.copy(archive, directory / archive.name)


def main():
    if not shutil.which("lz4"):
        print("lz4 required for the pacstall fixture", file=sys.stderr)
        return 6
    for tool in ("cc", "make", "tar"):
        if not shutil.which(tool):
            print(f"{tool} required for the pacstall fixture", file=sys.stderr)
            return 6
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        package = root / "pacstall-demo"
        package.mkdir(parents=True)
        source_tree(package, "holy-pacstall-demo", "1.2.3")
        archive = package / "holy-pacstall-demo-1.2.3.tar.gz"
        subprocess.run(["tar", "czf", str(archive), "-C", str(package), "holy-pacstall-demo-1.2.3"],
                       check=True)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        write(package / "holy-pacstall-demo.pacscript", f"""# Maintainer: Fixture <fixture@example.org>
pkgname="holy-pacstall-demo"
pkgver="1.2.3"
pkgrel="2"
pkgdesc="Pacstall conversion fixture"
arch=("amd64")
url="https://example.org/holy-pacstall-demo"
license=("MIT")
maintainer=("Fixture <fixture@example.org>")
depends=("libc6" "zlib1g>=1.2")
makedepends=("gcc" "make")
optdepends=("python3: scripting")
backup=("/etc/holy-pacstall-demo.conf")
source=("holy-pacstall-demo-$pkgver.tar.gz")
sha256sums=("{digest}")

prepare() {{
  make -C "$srcdir/holy-pacstall-demo-$pkgver" clean
}}

build() {{
  make -C "$srcdir/holy-pacstall-demo-$pkgver" -j"$NCPU"
}}

check() {{
  make -C "$srcdir/holy-pacstall-demo-$pkgver" check
}}

package() {{
  make -C "$srcdir/holy-pacstall-demo-$pkgver" DESTDIR="$pkgdir" install
}}
""")

        out, recipe, report = convert(package, "holy-pacstall-demo")
        assert "converted holy-pacstall-demo status native" in out
        assert str(package / "conv" / "holy-pacstall-demo.recipe") in out

        # the identity, the provenance and the metadata a pacscript writes
        assert 'name "holy-pacstall-demo"' in recipe and 'version "1.2.3"' in recipe
        assert 'release "2"' in recipe and 'arch "x86_64"' in recipe
        assert 'libc any' in recipe
        assert 'summary "Pacstall conversion fixture"' in recipe
        assert 'homepage "https://example.org/holy-pacstall-demo"' in recipe
        assert 'x-source-family pacstall' in recipe and 'x-converter pacstall-1' in recipe
        assert 'x-license "MIT"' in recipe
        assert 'x-maintainer "Fixture <fixture@example.org>"' in recipe
        assert 'output "holy-pacstall-demo" runtime' in recipe
        assert 'config "etc/holy-pacstall-demo.conf"' in recipe
        assert 'x-optdepend "python3" "scripting"' in recipe
        assert 'depend "libc6" "any" "-"' in recipe
        assert 'depend "zlib1g" "ge" "1.2"' in recipe
        assert 'build-depend "gcc" "any" "-"' in recipe
        assert "carried depends" in report and "carried makedepends" in report
        assert "status native" in report and "unknown 0" in report
        assert hashlib.sha256((package / "holy-pacstall-demo.pacscript").read_bytes()).hexdigest() \
            in report

        # the local source travels with the recipe and is verified there
        assert 'source "holy-pacstall-demo-1.2.3.tar.gz" "holy-pacstall-demo-1.2.3.tar.gz"' in recipe
        assert f'source-sha256 "holy-pacstall-demo-1.2.3.tar.gz" "{digest}"' in recipe
        assert (package / "conv" / "holy-pacstall-demo-1.2.3.tar.gz").is_file()
        assert "carried the local source holy-pacstall-demo-1.2.3.tar.gz" in report

        # the body of each phase keeps its own shell behind the Pacstall prologue
        for phase, body in (("prepare", "make -C"), ("build", '-j"$NCPU"'),
                            ("check", '$pkgver" check'), ("package", 'DESTDIR="$pkgdir"')):
            assert f"step {phase} /bin/sh <<STEP" in recipe
            assert body in recipe
        assert 'pkgdir="$HOLY_DEST"' in recipe and 'srcdir="$HOLY_SRC"' in recipe
        assert 'NCPU="$HOLY_JOBS"' in recipe and 'startdir="$HOLY_BUILD"' in recipe
        assert 'pkgname="holy-pacstall-demo"' in recipe and 'pkgver="1.2.3"' in recipe
        assert 'pkgrel="2"' in recipe and 'gives="holy-pacstall-demo"' in recipe
        assert 'cd "$HOLY_SRC" || exit 1' in recipe
        assert "step unpack /bin/sh <<UNPACK" in recipe
        assert "takes the place of srcdir" in report

        # the converted recipe builds through the normal engine
        run("build", package / "conv" / "holy-pacstall-demo.recipe", "--output", root / "built",
            "--yes")
        library = root / "built" / "holy-pacstall-demo--x86_64--glibc.holy"
        data = root / "built" / "holy-pacstall-demo--noarch--nolibc.holy"
        library_meta, library_names = read_metadata(library)
        data_meta, _ = read_metadata(data)
        assert 'arch "x86_64"' in library_meta["HOLY/meta"]
        assert 'libc "glibc"' in library_meta["HOLY/meta"]
        assert 'x-source-family "pacstall"' in library_meta["HOLY/meta"]
        assert 'x-converter "pacstall-1"' in library_meta["HOLY/meta"]
        assert "usr/bin/holy-pacstall-demo" in library_meta["HOLY/files"]
        assert "usr/share/holy-pacstall-demo/greeting" in data_meta["HOLY/files"]
        assert "config" in data_meta["HOLY/files"]
        assert '"usr/bin/holy-pacstall-demo" "holy-recipe"' in library_meta["HOLY/deps"]
        assert '"usr/bin/holy-pacstall-demo"' not in data_meta["HOLY/deps"]
        assert digest in data_meta["HOLY/origin"]
        assert "DATA/usr/bin/holy-pacstall-demo" in library_names

        # an unreviewed step still needs a decision
        run("build", package / "conv" / "holy-pacstall-demo.recipe", "--output", root / "unchecked",
            "--noninteractive", status=3)

        # a split pkgbase gives each name its own output and its own staging tree
        split = root / "split"
        beside(split, archive)
        write(split / "holy-pacstall-split.pacscript", f"""pkgname=(
  "holy-pacstall-split"
  "holy-pacstall-split-doc"
)
pkgbase="holy-pacstall-splits"
pkgver="0.4"
pkgdesc="A split pacscript fixture"
arch=("any")
source=("holy-pacstall-demo-1.2.3.tar.gz")
sha256sums=("{digest}")

package_holy-pacstall-split() {{
  make -C "$srcdir/holy-pacstall-demo-1.2.3" DESTDIR="$pkgdir" install
}}

package_holy-pacstall-split-doc() {{
  install -Dm644 "$srcdir/holy-pacstall-demo-1.2.3/README" "$pkgdir/usr/share/doc/holy-pacstall-split/README"
}}
""")
        out, recipe, report = convert(split, "holy-pacstall-split", "holy-pacstall-splits")
        assert 'name "holy-pacstall-splits"' in recipe
        assert 'x-pkgbase "holy-pacstall-splits"' in recipe
        assert 'output "holy-pacstall-split" runtime' in recipe
        assert 'output "holy-pacstall-split-doc" runtime' in recipe
        assert 'split-step "holy-pacstall-split" split /bin/sh <<STEP' in recipe
        assert 'split-step "holy-pacstall-split-doc" split /bin/sh <<STEP' in recipe
        # a split body installs into the staging tree of its own output
        assert 'pkgdir="$HOLY_SPLIT_DEST"' in recipe
        assert 'pkgdir="$HOLY_DEST"' not in recipe
        assert '"$pkgdir/usr/share/doc/holy-pacstall-split/README"' in recipe
        assert 'pkgname="holy-pacstall-split-doc"' in recipe
        assert "the list of names becomes one output each" in report
        assert "preserved the package_holy-pacstall-split body" in report
        run("build", split / "conv" / "holy-pacstall-splits.recipe", "--output", root / "split-out",
            "--yes")
        split_meta, _ = read_metadata(root / "split-out" /
                                      "holy-pacstall-split--x86_64--glibc.holy")
        doc_meta, _ = read_metadata(root / "split-out" /
                                    "holy-pacstall-split-doc--noarch--nolibc.holy")
        assert "usr/bin/holy-pacstall-demo" in split_meta["HOLY/files"]
        assert "README" in doc_meta["HOLY/files"]
        assert "usr/bin/holy-pacstall-demo" not in doc_meta["HOLY/files"]

        # the install time functions become one hook per group, and the payload
        # carries the script
        hooked = root / "hooked"
        beside(hooked, archive)
        write(hooked / "holy-pacstall-hook.pacscript", f"""pkgname="holy-pacstall-hook"
pkgver="2.0"
pkgdesc="A pacscript with install time functions"
arch=("any")
source=("holy-pacstall-demo-1.2.3.tar.gz")
sha256sums=("{digest}")

package() {{
  make -C "$srcdir/holy-pacstall-demo-1.2.3" DESTDIR="$pkgdir" install
}}

post_install() {{
  fancy_message info "installed ${{gives}}"
}}

pre_remove() {{
  rm -f "/usr/share/${{gives}}/greeting"
}}
""")
        out, recipe, report = convert(hooked, "holy-pacstall-hook", status=3)
        assert "status review-required" in out
        assert 'hook-install /bin/bash "usr/share/holy/holy-pacstall-hook/holy-pacstall-hook.install"' \
            in recipe
        assert 'hook-remove /bin/bash "usr/share/holy/holy-pacstall-hook/holy-pacstall-hook.remove"' \
            in recipe
        install_script = (hooked / "conv" / "holy-pacstall-hook.install").read_text()
        assert 'pkgname=holy-pacstall-hook' in install_script
        assert 'fancy_message info "installed ${gives}"' in install_script
        assert (hooked / "conv" / "holy-pacstall-hook.remove").read_text().count("rm -f") == 1
        assert "the post_install body calls the fancy_message helper" in report
        assert "the install functions become one install hook" in report
        assert "the remove functions become one remove hook" in report
        run("build", hooked / "conv" / "holy-pacstall-hook.recipe", "--output", root / "hook-out",
            "--yes")
        library_meta, _ = read_metadata(root / "hook-out" /
                                        "holy-pacstall-hook--x86_64--glibc.holy")
        data_meta, _ = read_metadata(root / "hook-out" / "holy-pacstall-hook--noarch--nolibc.holy")
        assert 'hook postinstall "/bin/bash" ' \
            '"usr/share/holy/holy-pacstall-hook/holy-pacstall-hook.install"' in data_meta["HOLY/hooks"]
        assert "holy-pacstall-hook.install" in data_meta["HOLY/files"]
        # the record names the digest of the script the payload carries
        script = (hooked / "conv" / "holy-pacstall-hook.install").read_bytes()
        assert hashlib.sha256(script).hexdigest() in data_meta["HOLY/hooks"]

        # a source a Holy recipe cannot fetch is reported rather than carried
        report_case = root / "reported"
        write(report_case / "holy-pacstall-reported.pacscript", """_lib="reported"
pkgname="holy-pacstall-${_lib}"
pkgver="1.0"
pkgdesc="A pacscript with what a recipe cannot hold"
arch=("amd64" "arm64")
epoch="2"
source=("git+https://example.org/holy-pacstall-reported.git#tag=v1.0"
        "https://example.org/plain.tar.gz"
        "http://example.org/insecure.tar.gz")
sha256sums=("SKIP" "" "0000000000000000000000000000000000000000000000000000000000000000")
source_amd64=("https://example.org/only-amd64.tar.gz")
sha256sums_amd64=("SKIP")
depends=("libc6" "one|two")
pacdeps=("helper-pac")
if [[ "$TARCH" == "amd64" ]]; then
  pacdeps+=("helper-amd64")
fi

incompatible=("debian:trixie")
external_connection=true
md5sums=("00000000000000000000000000000000")
noextract=("https://example.org/only-amd64.tar.gz")
backup=("r:/etc/holy-pacstall-reported.conf" "/etc/holy-pacstall-reported.state")
optdepends=("python3")
arch_note="a setting a Holy recipe has no place for"
give_this="carried"

prepare() {
  if command -v meson > /dev/null; then
    meson setup "$KVER" "$homedir"
  fi
}

package() {
  printf 'x\n' > "${pkgdir}/usr/bin/holy-pacstall-reported"
}
""")
        out, recipe, report = convert(report_case, "holy-pacstall-reported", status=3)
        assert 'name "holy-pacstall-reported"' in recipe
        assert 'x-epoch "2"' in recipe
        assert "the epoch 2 is preserved and dropped" in report
        assert "arch amd64 is one machine of a list" in report
        assert "arch arm64 names a machine Holy does not carry" in report
        assert 'arch "arm64"' in recipe
        assert 'x-conflicts "nothing"' not in recipe
        # a git address, a missing digest and a plain http address are all reported
        assert "is a git address" in report
        assert "has no sha256sums entry" in report
        assert "is a plain http address" in report
        assert "the sha256sums list holds 3 entries for 3 sources" not in report
        assert "the source_amd64 list names a machine or a distribution" in report
        assert "the sha256sums_amd64 list names a machine or a distribution" in report
        pacscript = str(report_case / "holy-pacstall-reported.pacscript")
        assert f"the group one|two at {pacscript}:13 offers alternatives" in report
        assert 'depend "one" "any" "-"' in recipe
        assert 'depend "two" "any" "-"' not in recipe
        assert 'depend "helper-pac" "any" "-"' in recipe
        assert "names a package of the same pacstall repository" in report
        assert "incompatible steers a Pacstall run" in report
        assert "external_connection steers a Pacstall run" in report
        assert "the md5sums list pins a digest a Holy source cannot use" in report
        assert "noextract steers a Pacstall run" in report
        assert 'config "etc/holy-pacstall-reported.conf" mutable' in recipe
        assert "asks for the old file to be removed on an upgrade" in report
        assert 'config "etc/holy-pacstall-reported.state"' in recipe
        assert 'x-optdepend "python3"' in recipe
        assert "the arch_note key is a Pacstall setting this converter reports" in report
        assert "the give_this key is a Pacstall setting this converter reports" in report
        assert "the prepare body reads KVER, which is the running kernel" in report
        assert "the prepare body reads homedir, which is the home directory" in report
        assert f"conditional block {pacscript}:15 if [[" in report
        assert f"conditional assignment pacdeps {pacscript}:16" in report

        # a machine that Holy does not carry is written as it stands
        foreign = root / "foreign"
        beside(foreign, archive)
        write(foreign / "holy-pacstall-foreign.pacscript", """pkgname="holy-pacstall-foreign"
pkgver="1"
pkgdesc="A pacscript for a machine Holy does not carry"
arch=("riscv64")
source=("holy-pacstall-demo-1.2.3.tar.gz")
sha256sums=("0000000000000000000000000000000000000000000000000000000000000000")
""")
        out, recipe, report = convert(foreign, "holy-pacstall-foreign", status=3)
        assert 'arch "riscv64"' in recipe
        assert "arch riscv64 names a machine Holy does not carry" in report
        assert "the pacscript names no source" not in report

        # a local source that is not beside the pacscript is reported
        missing = root / "missing"
        write(missing / "holy-pacstall-missing.pacscript", """pkgname="holy-pacstall-missing"
pkgver="1"
pkgdesc="A pacscript whose local source is absent"
arch=("any")
source=("absent.tar.gz")
sha256sums=("0000000000000000000000000000000000000000000000000000000000000000")
""")
        out, recipe, report = convert(missing, "holy-pacstall-missing", status=3)
        assert "is not beside the pacscript" in report
        assert 'source "absent.tar.gz"' not in recipe

        # a gives a body installs under becomes the package name when it is computed
        computed = root / "computed"
        beside(computed, archive)
        write(computed / "holy-pacstall-computed.pacscript", """pkgname="holy-pacstall-computed"
pkgver="1"
pkgdesc="A pacscript with a computed gives"
arch=("any")
gives="libicu${pkgver:0:2}"
source=("holy-pacstall-demo-1.2.3.tar.gz")
sha256sums=("0000000000000000000000000000000000000000000000000000000000000000")

package() {
  make -C "$srcdir" DESTDIR="$pkgdir" install
}
""")
        out, recipe, report = convert(computed, "holy-pacstall-computed")
        # the body installs under the package name, since the expansion needs the
        # shell to pick the first characters of a version
        assert 'gives="holy-pacstall-computed"' in recipe

        # a pacscript that cannot state its identity
        write(computed / "no-name.pacscript", """pkgver="1"
pkgdesc="No name here"
""")
        run("convert", computed / "no-name.pacscript", "--source", "pacstall",
            "--output", root / "nope", status=2)
        write(computed / "computed-name.pacscript", """pkgname="holy-${_nowhere}"
pkgver="1"
pkgdesc="A name no assignment holds"
""")
        run("convert", computed / "computed-name.pacscript", "--source", "pacstall",
            "--output", root / "nope", status=2)
        write(computed / "tilde-version.pacscript", """pkgname="holy-tilde"
pkgver="1.0~rc1"
pkgdesc="A version a recipe cannot hold"
arch=("any")
""")
        run("convert", computed / "tilde-version.pacscript", "--source", "pacstall",
            "--output", root / "nope", status=2)
        write(computed / "split-no-base.pacscript", """pkgname=(
  "one"
  "two"
)
pkgver="1"
pkgdesc="A list of names with no pkgbase"
""")
        run("convert", computed / "split-no-base.pacscript", "--source", "pacstall",
            "--output", root / "nope", status=2)
        write(computed / "unterminated.pacscript", """pkgname="holy-unterminated"
pkgver="1"
pkgdesc="A body that never closes"

package() {
  printf 'x\\n' > "$pkgdir/x"
""")
        run("convert", computed / "unterminated.pacscript", "--source", "pacstall",
            "--output", root / "nope", status=2)

        # unusable arguments
        run("convert", package / "holy-pacstall-demo.pacscript", "--source", "pacstall", status=2)
        run("convert", package / "holy-pacstall-demo.pacscript", "--source", "local",
            "--output", root / "nope", status=2)
        run("convert", package / "holy-pacstall-demo.pacscript", "--source", "pacstall:other",
            "--output", root / "nope", status=2)
        run("convert", root / "absent" / "holy-pacstall-demo.pacscript", "--source", "pacstall",
            "--output", root / "nope", status=6)

        # import takes the same conversion path
        imported = root / "imported-source"
        beside(imported, archive)
        write(imported / "holy-pacstall-import.pacscript", f"""pkgname="holy-pacstall-import"
pkgver="1.0"
pkgdesc="An import fixture"
arch=("any")
source=("holy-pacstall-demo-1.2.3.tar.gz")
sha256sums=("{digest}")
depends=("libc6")
""")
        run("import", imported / "holy-pacstall-import.pacscript", "--source", "pacstall",
            "--format", "pacstall", "--output", root / "imported")
        assert (root / "imported" / "holy-pacstall-import.recipe").is_file()
        assert (root / "imported" / "conversion").is_file()
        assert 'depend "libc6"' in (root / "imported" / "holy-pacstall-import.recipe").read_text()
    return 0


if __name__ == "__main__":
    sys.exit(main())
