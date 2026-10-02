#!/usr/bin/env python3
"""converts Gentoo ebuilds into holy recipes and checks the produced manifests."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


binary = str(Path(sys.argv[1]).resolve())


def run(*args, status=0):
    result = subprocess.run([binary, *map(str, args)], text=True, capture_output=True,
                           errors="replace")
    assert result.returncode == status, (args, result.returncode, result.stdout, result.stderr)
    return result.stdout


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def convert(package, file_name, name=None, status=3):
    out = run("convert", package / f"{file_name}.ebuild", "--source", "gentoo",
              "--output", package / "conv", status=status)
    name = name or file_name.rsplit("-", 1)[0]
    return out, (package / "conv" / f"{name}.recipe").read_text(), \
        (package / "conv" / "conversion").read_text()


def main():
    for tool in ("cc", "make"):
        if not shutil.which(tool):
            print(f"{tool} required for the gentoo fixture", file=sys.stderr)
            return 6
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        package = root / "holy-demo"
        files = package / "files"
        write(files / "holy-demo-1.0-r2-hello.patch", """--- a/holo
+++ b/holo
@@ -1 +1 @@
-old
+new
""")
        write(files / "holy-demo-1.0-r2-meson.patch", "diff --git a/meson.build b/meson.build\n")
        write(package / "holy-demo-1.0-r2.ebuild", """# Copyright 2026 Fixture Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

inherit toolchain-funcs

DESCRIPTION="The holy-demo fixture greets the operator once"
HOMEPAGE="https://example.org/holy-demo/"
SRC_URI="
	https://example.org/holy-demo-${PV}.tar.xz
	verify-sig? ( https://example.org/holy-demo-${PV}.tar.xz.sig )
"
S="${WORKDIR}/${P}"

LICENSE="GPL-2+"
SLOT="0"
KEYWORDS="~amd64 x86"
IUSE="+doc static test"
REQUIRED_USE="static? ( !test )"

BDEPEND="
	app-build/ninja
	doc? ( app-text/asciidoc )
"
RDEPEND="
	>=virtual/libc-1
	!app-misc/old-demo ( < 1.0-r1 )
	doc? ( app-text/asciidoc )
	|| ( app-admin/holo-one app-admin/holo-two )
	^^app-admin/holo-three
"
DEPEND="${RDEPEND}
	~dev-libs/libholo-2.0:0
	sys-devel/holo-config[static-libs(+),!shared]
	app-misc/holo-any:*
"
PDEPEND="app-misc/holo-extras"

PATCHES=(
	"${FILESDIR}"/"${P}-hello.patch"
	"${FILESDIR}"/"${P}-meson.patch"
)

src_prepare() {
	default

	sed -i -e "s:@CC@:$(tc-getCC):g" -e "s:@H@:${EPREFIX}/usr/bin/holo-demo:g" Makefile || die
}

src_compile() {
	ninja ${MAKEFLAGS} || die
	emake check || die
}

src_test() {
	./demo --selftest || die
}

src_install() {
	install -D -m0755 demo "${ED}/usr/bin/holo-demo" || die
	einstalldocs
}

pkg_postinst() {
	elog "run holo-demo to greet"
}
""")

        out, recipe, report = convert(package, "holy-demo-1.0-r2", "holy-demo")
        assert "converted holy-demo status review-required" in out
        assert str(package / "conv" / "holy-demo.recipe") in out

        # the identity comes from the file name, and a revision becomes the release
        assert 'name "holy-demo"' in recipe
        assert 'version "1.0"' in recipe and 'release "2"' in recipe
        assert 'arch "any"' in recipe and 'libc any' in recipe
        assert 'summary "The holy-demo fixture greets the operator once"' in recipe
        assert 'homepage "https://example.org/holy-demo/"' in recipe
        assert 'x-source-family gentoo' in recipe and 'x-converter gentoo-1' in recipe
        assert 'x-eapi "8"' in recipe
        assert 'x-license "GPL-2+"' in recipe and 'x-slot "0"' in recipe
        assert 'output "holy-demo" runtime' in recipe
        assert "semantic-change the revision r2 becomes the Holy release" in report

        # a local patch travels with the recipe and is hashed as SHA-256
        for patch in ("holy-demo-1.0-r2-hello.patch", "holy-demo-1.0-r2-meson.patch"):
            assert f'source "{patch}" "{patch}"' in recipe
            assert f'source-sha256 "{patch}"' in recipe
            assert hashlib.sha256((files / patch).read_bytes()).hexdigest() in recipe
            assert (package / "conv" / patch).read_bytes() == (files / patch).read_bytes()
        assert "carried the local patch holy-demo-1.0-r2-hello.patch" in report

        # a remote archive has no sha256 here, so it is reported
        assert "unknown the source https://example.org/holy-demo-1.0.tar.xz has no sha256" \
            in report
        assert "the USE flag verify-sig gates the sources inside it" in report

        # the dependency lists, with the comparator names the other converters use
        assert 'build-depend "ninja"' in recipe
        assert 'depend "libc" "ge" "1"' in recipe
        assert 'build-depend "libholo"' in recipe
        assert 'x-conflicts "old-demo"' in recipe
        assert 'depend "holo-one"' in recipe and 'depend "holo-three"' in recipe
        assert 'depend "holo-extras"' in recipe
        assert "carried RDEPEND" in report and "carried BDEPEND" in report

        # what a Holy record cannot hold is reported, not guessed
        assert "the USE flag doc in RDEPEND gates its atoms" in report
        assert "the any-of group in RDEPEND is reported as a whole" in report
        assert "the use dependency of sys-devel/holo-config[static-libs(+),!shared]" in report
        assert "the slot of app-misc/holo-any:*" in report
        assert "the ~ atom ~dev-libs/libholo-2.0:0 in DEPEND is a version range" in report
        assert "carried RDEPEND !app-misc/old-demo becomes a conflict" in report
        assert "the virtual >=virtual/libc-1 in RDEPEND names an interface" in report
        assert "IUSE +doc static test is a package manager setting" in report
        assert "REQUIRED_USE static? ( !test ) is a package manager setting" in report

        # each eclass and each helper the bodies call is reported, never faked
        assert "helper the toolchain-funcs eclass" in report
        # the helper environments the converter could not run are named, and their
        # SHA-256 travels in both the report and the recipe
        assert "helper-environment toolchain-funcs" in report
        assert "helper-environment ebuild.sh" in report
        digest = report.split("helper-environment-sha256 ")[1].split()[0]
        assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)
        assert f'x-helper-environment-sha256 "{digest}"' in recipe
        assert 'x-helper-environment "toolchain-funcs"' in recipe
        assert "the src_prepare body calls the default helper" in report
        assert "the src_prepare body calls the die helper" in report
        assert "the src_compile body calls the emake helper" in report
        assert "the src_prepare body calls the tc-getCC helper" in report
        assert "the ninja helper" not in report
        assert "the src_install body calls the einstalldocs helper" in report
        assert "the pkg_postinst function runs at install time through Portage" in report

        # a phase the ebuild leaves out is the one the eclasses supply
        assert "helper the unpack phase" in report
        assert "helper the configure phase" in report

        # every phase body runs behind the prologue that rebuilds the Portage paths
        for phase, body in (("prepare", "Makefile"), ("build", "ninja ${MAKEFLAGS}"),
                            ("check", "./demo --selftest"), ("package", "einstalldocs")):
            assert f"step {phase} /bin/sh <<STEP" in recipe
            assert body in recipe
        assert 'ED="$HOLY_DEST"' in recipe and 'WORKDIR="$HOLY_SRC"' in recipe
        assert "PN=holy-demo" in recipe and "PV=1.0" in recipe and "PR=2" in recipe
        assert "P=holy-demo-1.0-r2" in recipe and "PVR=1.0-r2" in recipe
        assert 'cd "$HOLY_SRC" || exit 1' in recipe
        assert "step unpack /bin/sh <<UNPACK" in recipe
        assert "takes the place of WORKDIR" in report

        # an unreviewed step still needs a decision
        run("build", package / "conv" / "holy-demo.recipe", "--output", package / "unreviewed",
            "--noninteractive", status=3)

        # an ebuild with no revision gets release one, and a 9999 one is still carried
        write(package / "holy-demo-1.0.ebuild", """EAPI=7

DESCRIPTION="No revision here"
SRC_URI="mirror://example/holy-demo-${PV}.tar.xz"
LICENSE="MIT"
""")
        out, recipe, report = convert(package, "holy-demo-1.0", "holy-demo")
        assert 'release "1"' in recipe
        assert 'x-eapi "7"' in recipe
        assert "helper the unpack phase" in report
        assert "the source mirror://example/holy-demo-1.0.tar.xz is a mirror URI" in report

        # an epoch is preserved and dropped, like the Debian revision
        write(package / "holy-demo-2:1.0.ebuild", """EAPI=8

DESCRIPTION="An epoch is a packaging revision order"
SRC_URI="https://example.org/holy-demo-1.0.tar.xz"
LICENSE="MIT"
""")
        out, recipe, report = convert(package, "holy-demo-2:1.0", "holy-demo")
        assert 'version "1.0"' in recipe
        assert "the epoch 2: of the file name is preserved and dropped" in report

        # a malformed ebuild and unusable arguments
        write(package / "noebuild", "EAPI=8\n")
        run("convert", package / "noebuild", "--source", "gentoo", "--output", root / "nope",
            status=2)
        run("convert", package / "holy-demo-1.0-r2.ebuild", "--source", "gentoo", status=2)
        run("convert", package / "holy-demo-1.0-r2.ebuild", "--source", "local",
            "--output", root / "nope", status=2)
        run("convert", package / "holy-demo-1.0-r2.ebuild", "--source", "gentoo:extra",
            "--output", root / "nope", status=2)
        run("convert", root / "absent" / "holy-demo-9.9.ebuild", "--source", "gentoo",
            "--output", root / "nope", status=6)

        # import takes the same conversion path
        write(package / "holy-import-1.0.ebuild", """EAPI=8

DESCRIPTION="An import fixture"
SRC_URI="https://example.org/holy-import-1.0.tar.xz"
LICENSE="MIT"
RDEPEND="app-misc/holo"
""")
        run("import", package / "holy-import-1.0.ebuild", "--source", "gentoo",
            "--format", "gentoo", "--output", root / "imported", status=3)
        assert (root / "imported" / "holy-import.recipe").is_file()
        assert (root / "imported" / "conversion").is_file()
        assert 'depend "holo"' in (root / "imported" / "holy-import.recipe").read_text()
    return 0


if __name__ == "__main__":
    sys.exit(main())
