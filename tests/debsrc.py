#!/usr/bin/env python3
"""converts Debian source packages into holy recipes and builds the manifests."""
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
    result = subprocess.run(["lz4", "-dc", str(artifact)], capture_output=True)
    assert result.returncode == 0, (artifact, result.returncode, result.stderr)
    with tarfile.open(fileobj=io.BytesIO(result.stdout)) as archive:
        def read(name):
            return archive.extractfile(name).read().decode()
        return {name: read(name) for name in
                ("HOLY/meta", "HOLY/files", "HOLY/deps", "HOLY/origin", "HOLY/transform")}, None


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def main():
    if not shutil.which("lz4"):
        print("lz4 required for the debsrc fixture", file=sys.stderr)
        return 6
    for tool in ("cc", "make"):
        if not shutil.which(tool):
            print(f"{tool} required for the debsrc fixture", file=sys.stderr)
            return 6
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        package = root / "deb-demo"
        debian = package / "debian"
        debian.mkdir(parents=True)
        # a source tree the rules file can build from
        source = root / "deb-demo-2.6.0"
        (source / "usr/share").mkdir(parents=True)
        write(source / "Makefile", """all: bin/deb-demo
bin/deb-demo: hello.c
\tmkdir -p bin
\t$(CC) $(CFLAGS) -o $@ hello.c
install: bin/deb-demo
\tmkdir -p $(DESTDIR)/usr/bin $(DESTDIR)/usr/lib $(DESTDIR)/usr/include
\tcp bin/deb-demo $(DESTDIR)/usr/bin/
\tcp hello.txt $(DESTDIR)/usr/lib/
\tcp hello.h $(DESTDIR)/usr/include/
""")
        write(source / "hello.c", '#include <stdio.h>\nint main(void){puts("hi");return 0;}\n')
        write(source / "hello.h", "/* header */\n")
        write(source / "hello.txt", "greeting\n")
        write(source / "README", "the deb-demo fixture\n")
        write(source / "COPYING", "fixture licence text\n")
        digest = hashlib.sha256((source / "hello.c").read_bytes()).hexdigest()

        write(debian / "control", """Source: deb-demo
Section: devel
Priority: optional
Maintainer: Fixture <fixture@example.org>
Uploaders: Someone Else <else@example.org>,
  Third Person <third@example.org>
Build-Depends: debhelper-compat (= 13),
 dpkg-dev (>= 1.15.5), make
Standards-Version: 4.7.0
Homepage: https://example.org/deb-demo
Vcs-Git: https://salsa.debian.org/fixture/deb-demo.git
Rules-Requires-Root: no

Package: deb-demo
Architecture: all
Multi-Arch: foreign
Depends: ${misc:Depends}, libc6 (>= 2.34)
Recommends: hello
Suggests: bye
Conflicts: deb-demo-old (<< 1.0-1)
Replaces: deb-demo-old (<< 1.0-1)
Provides: deb-demo-interface
Description: A Debian source conversion fixture
 The deb-demo program greets the operator once and then stops.
 It exists so the converter has a source package to read.

Package: deb-demo-dev
Architecture: all
Multi-Arch: foreign
Depends: deb-demo (= ${binary:Version}),
 ${misc:Depends}
Description: Development files for deb-demo
 Headers for deb-demo.
""")
        write(debian / "changelog", """deb-demo (2.6.0-1) unstable; urgency=medium

  * The fixture release.
  * Another line.

 -- Fixture <fixture@example.org>  Mon, 01 Jan 2024 00:00:00 +0000

deb-demo (2.5.0-1) unstable; urgency=low

  * An older release.

 -- Fixture <fixture@example.org>  Sun, 01 Jan 2023 00:00:00 +0000
""")
        write(debian / "rules", """#!/usr/bin/make -f

%:
	dh $@

override_dh_auto_build:
	make CFLAGS="-O2"

override_dh_auto_install:
	make install DESTDIR=$(CURDIR)/debian/deb-demo
	mkdir -p $(CURDIR)/debian/deb-demo/usr/share/doc/deb-demo
	cp README $(CURDIR)/debian/deb-demo/usr/share/doc/deb-demo/
""")
        write(debian / "deb-demo-dev.install",
              "usr/include/hello.h usr/include\nusr/share/doc/deb-demo/README\n")
        write(debian / "deb-demo.postinst", "#!/bin/sh\nset -e\ncase \"$1\" in\n  configure) ;;\nesac\n")
        write(debian / "copyright", "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n")
        write(debian / "watch", "version=4\n")
        write(debian / "source" / "format", "3.0 (quilt)\n")
        write(debian / "lintian-overrides", "deb-demo: package-installs-python-bytecode\n")

        out = run("convert", debian, "--source", "debian", "--output", root / "conv", status=3)
        assert "converted deb-demo status review-required" in out
        recipe = (root / "conv" / "deb-demo.recipe").read_text()
        report = (root / "conv" / "conversion").read_text()
        assert (root / "conv" / "control").read_text() == (debian / "control").read_text()
        assert hashlib.sha256((root / "conv" / "control").read_bytes()).hexdigest() in report
        assert (root / "conv" / "changelog").is_file()
        assert (root / "conv" / "rules").is_file()

        # the changelog gives the version, split into upstream and Debian revision
        assert 'name "deb-demo"' in recipe
        assert 'version "2.6.0"' in recipe and 'release "1"' in recipe
        assert 'arch "any"' in recipe and 'libc any' in recipe
        assert 'homepage "https://example.org/deb-demo"' in recipe
        assert 'summary "A Debian source conversion fixture"' in recipe
        assert 'x-source-family deb' in recipe and 'x-converter debsrc-1' in recipe
        # a wrapped dependency list keeps its entries
        assert 'build-depend "debhelper-compat" "eq" "13"' in recipe
        assert 'build-depend "dpkg-dev" "ge" "1.15.5"' in recipe
        assert 'build-depend "make" "any" "-"' in recipe
        assert 'depend "libc6" "ge" "2.34"' in recipe
        assert 'x-conflicts "deb-demo-old"' in recipe
        assert 'x-suggests "hello"' in recipe
        assert 'x-suggests "bye"' in recipe
        assert 'x-provides "deb-demo-interface"' in recipe
        assert 'depend "deb-demo"' not in recipe
        # the dpkg substitution variables are reported, not carried
        assert 'unknown the substitution ${misc:Depends} in Depends is filled in by dpkg' in report
        # the binary that names its own files becomes a split output
        assert 'output "deb-demo" runtime' in recipe
        assert 'output "deb-demo-dev" runtime' in recipe
        assert 'split-step deb-demo-dev split /bin/sh' in recipe
        assert '"usr/include" "usr/share/doc/deb-demo/README"' in recipe
        assert 'cp -a "$HOLY_DEST/$entry" "$HOLY_SPLIT_DEST/$entry"' in recipe
        # the rules keep their own shell and dh is reported rather than run
        assert "step build /bin/sh <<STEP" in recipe
        assert "dh $@" in recipe
        assert "override_dh_auto_build:" in recipe

        # the report names what was carried, preserved and reported
        assert "status review-required" in report
        assert "carried debian/control" in report
        assert "carried Package deb-demo 14" in report
        assert "carried Package deb-demo-dev 27" in report
        assert "carried changelog version 2.6.0" in report
        assert "semantic-change the Debian revision 1 becomes the Holy release" in report
        assert "preserved debian/rules" in report
        assert "preserved subpackage deb-demo-dev from its file list" in report
        assert "preserved maintainer script deb-demo.postinst" in report
        assert "unknown debhelper calls the recipe make" in report
        assert "unknown lintian-overrides is a lint suppression list" in report

        # unreviewed steps still need a decision
        run("build", root / "conv" / "deb-demo.recipe", "--output", root / "unreviewed",
            "--noninteractive", status=3)

        # a native package has no Debian revision, and an epoch is preserved
        write(debian / "changelog", """deb-demo (2.6.0) unstable; urgency=medium

  * A native package.

 -- Fixture <fixture@example.org>  Mon, 01 Jan 2024 00:00:00 +0000
""")
        run("convert", debian, "--source", "debian", "--output", root / "native", status=3)
        recipe = (root / "native" / "deb-demo.recipe").read_text()
        assert 'version "2.6.0"' in recipe and 'release "1"' in recipe
        write(debian / "changelog", """deb-demo (1:2.6.0-1) unstable; urgency=medium

  * A package with an epoch.

 -- Fixture <fixture@example.org>  Mon, 01 Jan 2024 00:00:00 +0000
""")
        run("convert", debian, "--source", "debian", "--output", root / "epoch", status=3)
        recipe = (root / "epoch" / "deb-demo.recipe").read_text()
        assert 'version "2.6.0"' in recipe and 'release "1"' in recipe
        assert "preserved the epoch 1 of the changelog version" in (
            root / "epoch" / "conversion").read_text()

        # a malformed changelog, a missing control and a rich dependency
        write(debian / "changelog", "deb-demo 2.6.0 unstable\n")
        run("convert", debian, "--source", "debian", "--output", root / "badlog", status=2)
        (debian / "changelog").write_text("deb-demo (2.6.0-1) unstable; urgency=medium\n")
        (debian / "control").write_text("Section: devel\nMaintainer: Fixture\n")
        run("convert", debian, "--source", "debian", "--output", root / "nocontrol", status=2)
        write(debian / "control", """Source: deb-demo
Section: devel
Priority: optional
Maintainer: Fixture <fixture@example.org>
Build-Depends: make
Architecture: all
Package: deb-demo
Architecture: all
Depends: deb-demo-old | deb-demo-new, libc6 [amd64 !i386] <!nocheck>
Description: A rich dependency fixture
 It has an alternative and a qualifier.
""")
        run("convert", debian, "--source", "debian", "--output", root / "rich", status=3)
        report = (root / "rich" / "conversion").read_text()
        assert ("unknown Depends offers alternatives for deb-demo-old, only the first is "
                "carried") in report

        # a file list that names no path is reported instead of an empty split step
        write(debian / "control", """Source: deb-demo
Section: devel
Priority: optional
Maintainer: Fixture <fixture@example.org>
Build-Depends: make
Architecture: all

Package: deb-demo
Architecture: all
Depends: ${misc:Depends}
Description: An empty file list fixture
 It has a subpackage whose list is empty.

Package: deb-demo-dev
Architecture: all
Depends: ${misc:Depends}
Description: Development files for deb-demo
 Headers for deb-demo.
""")
        write(debian / "deb-demo-dev.install", "\n# a comment only\n")
        write(debian / "rules", "#!/usr/bin/make -f\n\n%:\n\tdh $@\n")
        run("convert", debian, "--source", "debian", "--output", root / "emptylist", status=3)
        report = (root / "emptylist" / "conversion").read_text()
        assert "unknown the file list deb-demo-dev.install of deb-demo-dev names no path" in report
        assert "split-step deb-demo-dev" not in (root / "emptylist" / "deb-demo.recipe").read_text()

        # unusable arguments
        run("convert", debian, "--source", "debian", status=2)
        run("convert", debian, "--source", "local", "--output", root / "nope", status=2)
        run("convert", debian, "--source", "debian:extra", "--output", root / "nope", status=2)
        run("convert", root / "missing", "--source", "debian", "--output", root / "nope",
            status=6)
        # import takes the same conversion path
        write(debian / "control", """Source: deb-imported
Section: misc
Priority: optional
Maintainer: Fixture <fixture@example.org>
Architecture: all
Package: deb-imported
Architecture: all
Depends: ${misc:Depends}
Description: An import fixture
 It only has to convert.
""")
        write(debian / "changelog", "deb-imported (1-1) unstable; urgency=low\n\n -- F <f@e.org>  Mon, 01 Jan 2024 00:00:00 +0000\n")
        write(debian / "rules", "#!/usr/bin/make -f\n\n%:\n\tdh $@\n")
        run("import", debian, "--source", "debian", "--format", "debian",
            "--output", root / "imported", status=3)
        assert (root / "imported" / "conversion").is_file()
        assert (root / "imported" / "deb-imported.recipe").is_file()
        assert digest
    return 0


if __name__ == "__main__":
    sys.exit(main())
