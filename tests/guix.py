#!/usr/bin/env python3
"""converts Guix package definitions into holy recipes, builds the mechanical one
and refuses the definitions that name no origin."""
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path


binary = str(Path(sys.argv[1]).resolve())

ALPHABET = "0123456789abcdfghijklmnopqrstuvwxyz"


def base32(data):
    """the Guix base32 form of a digest, which omits the letters hex can confuse"""
    bits = 0
    value = 0
    out = []
    for byte in data:
        value = (value << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(ALPHABET[(value >> bits) & 31])
    if bits:
        out.append(ALPHABET[(value << (5 - bits)) & 31])
    return "".join(out)


def call(*args, status=0):
    result = subprocess.run([binary, *map(str, args)], capture_output=True, text=True,
                           errors="replace")
    assert result.returncode == status, (args, result.returncode, result.stdout, result.stderr)
    return result.stdout


def convert(definition, out, status=0):
    return call("convert", definition, "--source", "guix", "--output", out, status=status)


def source_tree(root, name, version):
    directory = root / f"{name}-{version}"
    directory.mkdir(parents=True)
    (directory / "configure").write_text(
        "#!/bin/sh\n"
        "# a hand written configure so the fixture needs no autotools\n"
        "prefix=/usr\n"
        "for argument in \"$@\"; do\n"
        "  case $argument in\n"
        "    --prefix=*) prefix=${argument#--prefix=} ;;\n"
        "  esac\n"
        "done\n"
        "printf 'prefix=%s\\n' \"$prefix\" > config.prefix\n"
        "exit 0\n")
    (directory / "configure").chmod(0o755)
    # the configure script writes the prefix it was given, which is the build root, so
    # the install target reads it back instead of guessing a prefix of its own
    (directory / "Makefile").write_text(
        "CFLAGS ?= -O2 -pipe -static\n"
        "PREFIX = $(shell sed -n 's/^prefix=//p' config.prefix)\n"
        "all: bin/%(name)s\n"
        "bin/%(name)s: main.c\n"
        "\tmkdir -p bin\n"
        "\t$(CC) $(CFLAGS) -o $@ main.c\n"
        "install: all\n"
        "\tmkdir -p $(DESTDIR)$(PREFIX)/bin\n"
        "\tcp bin/%(name)s $(DESTDIR)$(PREFIX)/bin/\n" % {"name": name})
    (directory / "main.c").write_text(
        '#include <stdio.h>\nint main(void){printf("%s\\n");return 0;}\n' % name)
    return directory


def main():
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        tree = source_tree(root, "guixfruit", "4.2.0")
        archive = root / "guixfruit-4.2.0.tar.gz"
        subprocess.run(["tar", "czf", str(archive), "-C", str(root), tree.name], check=True)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        encoded = base32(bytes.fromhex(digest))

        # a definition whose fields are all literal converts natively, and the recipe it
        # produced builds a real package
        simple = root / "guixfruit.scm"
        simple.write_text(
            '(define-public guixfruit\n'
            '  (package\n'
            '    (name "guixfruit")\n'
            '    (version "4.2.0")\n'
            '    (source (origin\n'
            '              (method url-fetch)\n'
            '              (uri "%s")\n'
            '              (sha256 (base32 "%s"))))\n'
            '    (build-system gnu-build-system)\n'
            '    (native-inputs (list pkg-config))\n'
            '    (inputs (list zlib openssl))\n'
            '    (arguments (list #:configure-flags (list "--with-x=y")))\n'
            '    (synopsis "a fixture program for the Guix converter")\n'
            '    (home-page "https://example.org/guixfruit")\n'
            '    (license (list license:asl2.0))))\n' % (archive, encoded))
        out = root / "simple"
        report = convert(simple, out)
        assert "converted guixfruit status native" in report, report
        recipe = (out / "guixfruit.recipe").read_text()
        assert 'name "guixfruit"\n' in recipe, recipe
        assert 'version "4.2.0"\n' in recipe, recipe
        assert 'x-guix-build-system "gnu-build-system"\n' in recipe, recipe
        assert 'source source "%s"\n' % archive in recipe, recipe
        # the base32 digest is decoded into the hex a Holy source records
        assert 'source-sha256 source "%s"\n' % digest in recipe, recipe
        assert 'build-depend "pkg-config" "any" "-"\n' in recipe, recipe
        assert 'depend "zlib" "any" "-"\n' in recipe, recipe
        assert 'depend "openssl" "any" "-"\n' in recipe, recipe
        assert 'output "guixfruit" runtime\n' in recipe, recipe
        # the gnu build system becomes the four tools it runs, in order
        assert "step prepare /bin/sh <<PREPARE" in recipe, recipe
        assert "step configure /bin/sh <<CONFIGURE" in recipe, recipe
        # a guix build configures the payload prefix and stages the install
        assert "./configure --prefix=/usr --build=\"$HOLY_BUILD_TARGET\"" in recipe, recipe
        assert "'--with-x=y'" in recipe, recipe
        assert "make -j \"$HOLY_JOBS\"" in recipe, recipe
        assert "make install DESTDIR=\"$HOLY_DEST\"" in recipe, recipe
        summary = (out / "conversion").read_text()
        assert "status native\n" in summary, summary
        assert "the origin digest is base32 where a Holy source records hex" in summary, summary
        assert "the guix gnu-build-system runs autoreconf, configure, make and make install" \
               in summary, summary
        assert "dependency runtime 2 build 1" in summary, summary

        built = root / "built"
        call("build", out / "guixfruit.recipe", "--output", built, "--yes")
        artifacts = sorted(p.name for p in built.glob("*.holy"))
        assert artifacts == ["guixfruit--x86_64--nolibc.holy"], artifacts
        artifact = built / artifacts[0]
        call("verify", "local:" + str(artifact))
        identity = call("info", "local:" + str(artifact))
        assert "name guixfruit\n" in identity, identity
        assert "version 4.2.0\n" in identity, identity
        listing = call("manifest", "local:" + str(artifact))
        assert "usr/bin/guixfruit" in listing, listing
        # a runtime input is a package requirement of the payload, while a build input
        # is a need of the build and not of the installed package
        requirements = call("requirements", "local:" + str(artifact))
        for name in ("zlib", "openssl"):
            assert '"package" "%s"' % name in requirements, (name, requirements)
        assert "pkg-config" not in requirements, requirements

        # a definition that computes its uri, turns its tests off and names a build
        # system this reader does not replace is review-required
        rich = root / "Rich.scm"
        rich.write_text('''(define-public rich
  (package
    (name "rich")
    (version "0.9")
    (source (origin
              (method git-fetch)
              (uri (git-reference (url "https://example.org/rich.git"))
                    (commit "0123456789abcdef0123456789abcdef01234567"))
              (sha256 (base32 "%s"))))
    (build-system trivial-build-system)
    (inputs (list (list "zlib" "1.3")))
    (arguments (list #:tests? #f
                    #:phases '((modify-phases ...))
                    #:configure-flags (list (list (string-append "--with-" "computed")))))
    (synopsis "a definition that computes what it names")
    (home-page "https://example.org/rich")
    (license (list license:gpl3+))
    (modulo (+ 2 2) 3)))
''' % encoded)
        rich_out = root / "rich"
        report = convert(rich, rich_out, status=3)
        assert "converted rich status review-required" in report, report
        recipe = (rich_out / "rich.recipe").read_text()
        assert 'name "rich"\n' in recipe, recipe
        assert 'version "0.9"\n' in recipe, recipe
        assert 'x-guix-build-system "trivial-build-system"\n' in recipe, recipe
        summary = (rich_out / "conversion").read_text()
        assert "the origin is not a url-fetch" in summary, summary
        assert "the trivial-build-system runs a build procedure" in summary, summary
        assert "the definition states its own phase list" in summary, summary
        assert "the #:configure-flags argument holds a value that is not a literal string" \
               in summary, summary
        assert "the definition computes a value with modulo" in summary, summary
        assert "the definition turns its test suite off" in summary, summary
        # a version constraint is a constraint, not a second name
        assert 'depend "zlib" "any" "-"\n' in recipe, recipe
        assert "1.3" not in recipe, recipe
        # a git origin has no address this reader can fetch
        assert 'source source "-"' in recipe or "source source" not in recipe, recipe

        # a definition that states no package, no name, no version or no origin
        for body, wanted in (
                ('(define-public thing\n  (foo (bar)))\n', "states no package"),
                ('(package (version "1.0"))\n', "no name this converter can read"),
                ('(package (name "noname")\n  (source (origin (method url-fetch)\n'
                 '    (uri "https://example.org/a-1.0.tar.gz")\n'
                 '    (sha256 (base32 "%s")))))\n' % encoded,
                 "states no version"),
                ('(package (name "noorigin") (version "1.0")\n'
                 '  (build-system gnu-build-system))\n', "states no origin"),
                ('(package (name "nodigest") (version "1.0")\n'
                 '  (source (origin (method url-fetch) (uri "https://example.org/a.tar.gz")))\n'
                 '  (build-system gnu-build-system))\n', "no uri or no sha256"),
                ('(package (name "badbase32") (version "1.0")\n'
                 '  (source (origin (method url-fetch) (uri "https://example.org/a.tar.gz")\n'
                 '    (sha256 (base32 "tooshort"))))\n'
                 '  (build-system gnu-build-system))\n', "not a base32 SHA-256")):
            case = root / ("case" + str(abs(hash(body)) % 100000) + ".scm")
            case.write_text(body)
            result = subprocess.run([binary, "convert", case, "--source", "guix", "--output",
                                     root / (case.stem + "-out")], capture_output=True, text=True)
            # a missing field is a refusal, while a definition that computes what it
            # names is a report
            report = ""
            if result.returncode == 3:
                report = (root / (case.stem + "-out") / "conversion").read_text()
            assert wanted in result.stderr or wanted in report, (wanted, result.stderr, report)

        # a file that is not there, and one that is not text
        result = subprocess.run([binary, "convert", root / "absent.scm", "--source", "guix",
                                 "--output", root / "absent-out"], capture_output=True, text=True)
        assert result.returncode == 6, result
        assert "definition unavailable" in result.stderr, result.stderr
        binary_formula = root / "Binary.scm"
        binary_formula.write_bytes(b"\x00\x01\x02(package)\n")
        result = subprocess.run([binary, "convert", binary_formula, "--source", "guix",
                                 "--output", root / "binary-out"], capture_output=True, text=True)
        assert result.returncode == 2, result
        assert "Scheme text" in result.stderr, result.stderr
        result = subprocess.run([binary, "convert", simple, "--source", "local", "--output",
                                 root / "local-out"], capture_output=True, text=True)
        assert result.returncode == 2, result
        assert "needs the source name" in result.stderr, result.stderr
        assert not (root / "local-out").exists()

    print("guix fixtures passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
