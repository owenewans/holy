#!/usr/bin/env python3
"""converts RPM spec fixtures into holy recipes and builds the produced manifests."""
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


def source_tree(root, name, version):
    directory = root / f"{name}-{version}"
    (directory / "usr/share").mkdir(parents=True)
    write(directory / "Makefile", """all: bin/%(name)s
bin/%(name)s: hello.c
\tmkdir -p bin
\t$(CC) $(CFLAGS) -o $@ hello.c
install: bin/%(name)s
\tmkdir -p $(DESTDIR)/usr/bin $(DESTDIR)/usr/lib $(DESTDIR)/usr/include
\tcp bin/%(name)s $(DESTDIR)/usr/bin/
\tcp hello.txt $(DESTDIR)/usr/lib/
\tcp hello.h $(DESTDIR)/usr/include/
""" % {"name": name})
    write(directory / "hello.c", '#include <stdio.h>\nint main(void){puts("hi");return 0;}\n')
    write(directory / "hello.h", "/* header */\n")
    write(directory / "hello.txt", "greeting\n")
    return directory


def main():
    if not shutil.which("lz4"):
        print("lz4 required for the rpmspec fixture", file=sys.stderr)
        return 6
    for tool in ("cc", "make", "tar", "patch"):
        if not shutil.which(tool):
            print(f"{tool} required for the rpmspec fixture", file=sys.stderr)
            return 6
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        source = source_tree(root, "rpm-demo", "1.4.0")
        archive = root / "rpm-demo-1.4.0.tar.gz"
        subprocess.run(["tar", "czf", str(archive), "-C", str(root), "rpm-demo-1.4.0"],
                       check=True)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()

        package = root / "rpm-demo"
        package.mkdir()
        shutil.copy(archive, package / "rpm-demo-1.4.0.tar.gz")
        write(package / "greeting.patch", "--- a/hello.c\n+++ b/hello.c\n@@ -1 +1 @@\n"
              "-#include <stdio.h>\n+#include <stdio.h> /* patched */\n")
        write(package / "rpm-demo.spec", """%global build_id 42

Name:           rpm-demo
Version:        1.4.0
Release:        7%{?dist}
Summary:        An RPM spec conversion fixture
License:        MIT
URL:            https://example.org/rpm-demo
Source0:        rpm-demo-1.4.0.tar.gz
Patch0:         greeting.patch
BuildArch:      noarch
BuildRequires:  make
BuildRequires:  gcc >= 11
Requires:       bash >= 5.0
Requires:       /bin/sh
Provides:       rpm-demo-extra = %{version}
Conflicts:      rpm-demo-old
Recommends:     bash-completion

%description
The rpm-demo program greets the operator once and then stops.
It exists so the converter has a spec to read.

%package devel
Summary:        Development files for %{name}
Requires:       %{name} = %{version}-%{release}
%description devel
Headers and the pkg-config fragment for %{name}.

%prep
%setup -q -n %{name}-%{version}
%autopatch -p1

%build
make CFLAGS="-O2"

%install
mkdir -p %{buildroot}/usr/bin %{buildroot}/usr/lib %{buildroot}/usr/include
cp bin/rpm-demo %{buildroot}/usr/bin/
cp hello.txt %{buildroot}/usr/lib/
cp hello.h %{buildroot}/usr/include/

%check
test -x bin/rpm-demo

%files
%license COPYING
/usr/bin/rpm-demo

%files devel
/usr/include/hello.h

%changelog
* Mon Jan 01 2024 Fixture <fixture@example.org> - 1.4.0-7
- The fixture release.
""")

        out = run("convert", package / "rpm-demo.spec", "--source", "fedora",
                  "--output", root / "conv", status=3)
        assert "converted rpm-demo status review-required" in out
        recipe = (root / "conv" / "rpm-demo.recipe").read_text()
        report = (root / "conv" / "conversion").read_text()
        assert (root / "conv" / "rpm-demo.spec").read_text() == \
            (package / "rpm-demo.spec").read_text()
        assert hashlib.sha256((root / "conv" / "rpm-demo.spec").read_bytes()).hexdigest() in report
        assert (root / "conv" / "rpm-demo-1.4.0.tar.gz").is_file()

        # identity, provenance and the recorded sources
        assert 'name "rpm-demo"' in recipe and 'version "1.4.0"' in recipe
        assert 'release "7"' in recipe and 'arch "noarch"' in recipe and 'libc any' in recipe
        assert 'summary "An RPM spec conversion fixture"' in recipe
        assert 'license "MIT"' in recipe
        assert 'homepage "https://example.org/rpm-demo"' in recipe
        assert 'x-source-family rpm' in recipe and 'x-converter rpmspec-1' in recipe
        assert f'source "rpm-demo-1.4.0.tar.gz" "rpm-demo-1.4.0.tar.gz"' in recipe
        assert f'source-sha256 "rpm-demo-1.4.0.tar.gz" "{digest}"' in recipe
        assert 'source "greeting.patch" "greeting.patch"' in recipe
        # the requirement lists keep their comparison
        assert 'build-depend "make" "any" "-"' in recipe
        assert 'build-depend "gcc" "ge" "11"' in recipe
        assert 'depend "bash" "ge" "5.0"' in recipe
        assert 'x-provides "rpm-demo-extra"' in recipe
        assert 'x-suggests "bash-completion"' in recipe
        assert 'depend "bash-completion"' not in recipe
        assert 'x-conflicts "rpm-demo-old"' in recipe
        assert 'depend "rpm-demo" "ge" "5.0"' not in recipe
        # the sections become the Holy phases
        assert "step prepare /bin/sh <<STEP" in recipe
        assert "step build /bin/sh <<STEP" in recipe
        assert "step package /bin/sh <<STEP" in recipe
        assert "step check /bin/sh <<STEP" in recipe
        # the macros a body reads are rebuilt from the exported paths
        assert '_sourcedir="$HOLY_SRC"' in recipe
        assert '_builddir="$HOLY_BUILD"' in recipe
        assert 'buildroot="$HOLY_DEST"' in recipe
        assert "build_id=42" in recipe
        assert "cp bin/rpm-demo $HOLY_DEST/usr/bin/" in recipe
        # a section command that stands for a shell line is carried, not run
        assert 'cd "$HOLY_SRC/rpm-demo-1.4.0"' in recipe
        assert 'patch --batch --forward -p1 -i "$patch"' in recipe
        assert "%autopatch" not in recipe
        # a subpackage is a file list, so its step copies the paths out
        assert 'output "rpm-demo" runtime' in recipe
        assert 'output "devel" runtime' in recipe
        assert 'split-step devel split /bin/sh' in recipe
        assert '"/usr/include/hello.h"' in recipe
        assert 'cp -a "$HOLY_DEST/$entry" "$HOLY_SPLIT_DEST/$entry"' in recipe

        # the report names what was carried, what changed and what stayed unknown
        assert "status review-required" in report
        assert "carried Name 3" in report
        assert "carried Version 4" in report
        assert "carried Release 5" in report
        assert "carried package devel 24" in report
        assert "carried rpm-demo-1.4.0.tar.gz 9" in report
        assert "carried greeting.patch 10" in report
        assert "semantic-change local greeting.patch copied next to the recipe" in report
        assert "preserved the prep section at line 30" in report
        assert "preserved the build section at line 34" in report
        assert "preserved the install section at line 37" in report
        assert "preserved the check section at line 43" in report
        assert "preserved subpackage devel from its %files list at line 24" in report
        assert "unknown requirement /bin/sh names a file" in report
        assert "semantic-change the distribution suffix on Release is left out" in report
        assert "semantic-change the %files list of devel becomes a copy" in report
        assert "preserved the main %files list is not carried" in report

        # the converted recipe builds through the normal engine
        run("build", root / "conv" / "rpm-demo.recipe", "--output", root / "built", "--yes")
        built = sorted(path.name for path in (root / "built").glob("*.holy"))
        assert built == ["devel--noarch--nolibc.holy", "rpm-demo--noarch--nolibc.holy",
                         "rpm-demo--x86_64--glibc.holy"]
        program, _ = read_metadata(root / "built" / "rpm-demo--x86_64--glibc.holy")
        tree, _ = read_metadata(root / "built" / "rpm-demo--noarch--nolibc.holy")
        devel, _ = read_metadata(root / "built" / "devel--noarch--nolibc.holy")
        assert 'name "rpm-demo"' in program["HOLY/meta"]
        assert 'x-source-family "rpm"' in program["HOLY/meta"]
        assert digest in program["HOLY/origin"]
        assert "usr/bin/rpm-demo" in program["HOLY/files"]
        assert "usr/bin/rpm-demo" not in tree["HOLY/files"]
        # the subpackage carries only the paths its own %files list named
        assert "usr/include/hello.h" in devel["HOLY/files"]
        assert "usr/bin/rpm-demo" not in devel["HOLY/files"]
        assert "usr/include/hello.h" not in program["HOLY/files"]

        # unreviewed steps still need a decision
        run("build", root / "conv" / "rpm-demo.recipe", "--output", root / "unreviewed",
            "--noninteractive", status=3)

        # a missing identity, a computed identity and a rich dependency
        write(package / "rpm-demo.spec", """Name: rpm-demo
Version: $(date +%s)
Release: 1
%install
mkdir -p $RPM_BUILD_ROOT/usr/share/rpm-demo
""")
        run("convert", package / "rpm-demo.spec", "--source", "fedora",
            "--output", root / "computed", status=2)
        write(package / "rpm-demo.spec", """Name: rpm-demo
Release: 1
%install
mkdir -p $RPM_BUILD_ROOT/usr/share/rpm-demo
""")
        run("convert", package / "rpm-demo.spec", "--source", "fedora",
            "--output", root / "noversion", status=2)
        write(package / "rpm-demo.spec", """Name: rpm-demo
Version: 1
Release: 1
Requires: (rpm-demo-a or rpm-demo-b)
BuildRequires: rpmlib(CompressedFileNames)
%install
mkdir -p $RPM_BUILD_ROOT/usr/share/rpm-demo
""")
        run("convert", package / "rpm-demo.spec", "--source", "fedora",
            "--output", root / "rich", status=3)
        report = (root / "rich" / "conversion").read_text()
        assert "unknown requirement (rpm-demo-a or rpm-demo-b) uses a resolver-specific form" \
            in report
        assert "unknown requirement rpmlib(CompressedFileNames) uses a resolver-specific form" \
            in report
        # a macro the vendor set would resolve is the helper environment this converter
        # fixes rather than runs, and the ordered digest reaches the recipe
        write(package / "rpm-demo.spec", """Name: rpm-demo
Version: 1
Release: 1
%install
mkdir -p %{_vendorprefix}/usr/share/rpm-demo
""")
        run("convert", package / "rpm-demo.spec", "--source", "fedora",
            "--output", root / "macro", status=3)
        report = (root / "macro" / "conversion").read_text()
        assert "unknown macro %{_vendorprefix} is not carried" in report
        assert "helper-environment rpm-macros" in report
        env_digest = report.split("helper-environment-sha256 ")[1].split()[0]
        assert f'x-helper-environment-sha256 "{env_digest}"' in \
            (root / "macro" / "rpm-demo.recipe").read_text()

        # a subpackage with no files list, and a files list option
        write(package / "rpm-demo.spec", """Name: rpm-demo
Version: 1
Release: 1
%package extra
Summary: Extra files
%install
mkdir -p $RPM_BUILD_ROOT/usr/share/rpm-demo
%files -f rpm-demo.lang
/usr/bin/rpm-demo
""")
        run("convert", package / "rpm-demo.spec", "--source", "fedora",
            "--output", root / "extra", status=3)
        report = (root / "extra" / "conversion").read_text()
        assert "unknown subpackage extra has no %files list" in report
        assert "unknown the %files option -f rpm-demo.lang is not carried" in report

        # malformed text and unusable arguments
        run("convert", package / "rpm-demo.spec", "--source", "fedora", status=2)
        run("convert", package / "rpm-demo.spec", "--source", "local",
            "--output", root / "nope", status=2)
        run("convert", package / "rpm-demo.spec", "--source", "fedora:extra",
            "--output", root / "nope", status=2)
        run("convert", root / "missing" / "rpm-demo.spec", "--source", "fedora",
            "--output", root / "nope", status=6)
        # import takes the same conversion path
        write(package / "rpm-demo.spec", """Name: rpm-imported
Version: 1
Release: 1
%install
mkdir -p $RPM_BUILD_ROOT/usr/share/rpm-imported
printf 'data\\n' > $RPM_BUILD_ROOT/usr/share/rpm-imported/data
""")
        run("import", package / "rpm-demo.spec", "--source", "fedora", "--format", "rpmspec",
            "--output", root / "imported", status=0)
        assert (root / "imported" / "conversion").is_file()
        assert (root / "imported" / "rpm-imported.recipe").is_file()
    return 0


if __name__ == "__main__":
    sys.exit(main())
