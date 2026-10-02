#!/usr/bin/env python3
"""runs an upstream evaluator for an exact foreign expansion, behind consent."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


binary = str(Path(sys.argv[1]).resolve())


def run(*args, status=0, stdin=None):
    result = subprocess.run([binary, *map(str, args)], text=True, capture_output=True,
                           input=stdin, errors="replace")
    assert result.returncode == status, (args, result.returncode, result.stdout, result.stderr)
    return result.stdout


def write(path, text, mode=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    if mode is not None:
        path.chmod(mode)


PKGBUILD = """pkgbase=eval-demo
pkgver=2.5
pkgrel=3
pkgdesc=A conversion fixture for an upstream evaluator
arch=(x86_64)
license=MIT
build() {
  make
}
package() {
  make DESTDIR="$pkgdir" install
}
"""

# an upstream evaluator stand-in: it reads the recipe and writes the fields it expanded
AGREEING = """#!/bin/sh
input=$1
printf 'pkgbase = %s\\n' "$(sed -n 's/^pkgbase=//p' "$input" | head -1)"
printf 'pkgver = %s\\n' "$(sed -n 's/^pkgver=//p' "$input" | head -1)"
printf 'pkgrel = %s\\n' "$(sed -n 's/^pkgrel=//p' "$input" | head -1)"
"""

# a computed version, which is what a text reader cannot know and an evaluator can
DISAGREEING = """#!/bin/sh
input=$1
printf 'pkgbase = %s\\n' "$(sed -n 's/^pkgbase=//p' "$input" | head -1)"
printf 'pkgver = %s.1\\n' "$(sed -n 's/^pkgver=//p' "$input" | head -1)"
printf 'pkgrel = 4\\n'
"""


def main():
    for tool in ("sed",):
        if not shutil.which(tool):
            print(f"{tool} required for the evaluator fixture", file=sys.stderr)
            return 6
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        package = root / "src"
        package.mkdir()
        write(package / "PKGBUILD", PKGBUILD)
        agreeing = root / "eval-agreeing"
        write(agreeing, AGREEING, 0o755)
        disagreeing = root / "eval-disagreeing"
        write(disagreeing, DISAGREEING, 0o755)

        # an evaluator is a build and import tool dependency of the working environment,
        # so it runs only when the operator approved the program by its digest
        program_digest = hashlib.sha256(agreeing.read_bytes()).hexdigest()
        out = run("convert", package / "PKGBUILD", "--source", "demo",
                  "--output", root / "conv",
                  "--evaluator", agreeing, "--evaluator-arg", "PKGBUILD", "--yes")
        assert f"evaluator {agreeing} sha256 {program_digest}" in out
        assert "status 0" in out and "output-sha256 " in out
        assert "converted eval-demo status native" in out
        recipe = root / "conv" / "eval-demo.recipe"
        assert recipe.is_file()
        # the exact expansion agrees with the text reading, so it says so
        assert f"evaluator {agreeing} agrees with the text reading" in out
        captured = root / "conv" / "evaluator-output"
        assert captured.is_file()
        assert hashlib.sha256(captured.read_bytes()).hexdigest() in out
        assert "pkgbase = eval-demo" in captured.read_text()

        # a computed version is the case an evaluator exists for, and the difference is
        # shown before any build
        out = run("convert", package / "PKGBUILD", "--source", "demo",
                  "--output", root / "diff",
                  "--evaluator", disagreeing, "--evaluator-arg", "PKGBUILD", "--yes")
        assert 'evaluator-version evaluator="2.5.1" text="2.5"' in out
        assert 'evaluator-release evaluator="4" text="3"' in out
        assert "disagrees with the text reading on 2 fields" in out
        assert (root / "diff" / "evaluator-output").is_file()

        # without a terminal and without --yes, running code is a decision
        run("convert", package / "PKGBUILD", "--source", "demo", "--output", root / "ask",
            "--evaluator", agreeing, "--evaluator-arg", "PKGBUILD", status=3)
        assert not (root / "ask").exists()
        run("convert", package / "PKGBUILD", "--source", "demo", "--output", root / "ask",
            "--evaluator", agreeing, "--evaluator-arg", "PKGBUILD", "--noninteractive",
            status=3)

        # a program that is not there, or not an executable file, is an argument error
        run("convert", package / "PKGBUILD", "--source", "demo", "--output", root / "bad",
            "--evaluator", root / "absent", "--evaluator-arg", "PKGBUILD", "--yes", status=2)
        write(root / "not-executable", "text\n")
        run("convert", package / "PKGBUILD", "--source", "demo", "--output", root / "bad",
            "--evaluator", root / "not-executable", "--evaluator-arg", "PKGBUILD", "--yes",
            status=2)
        # a relative program path names nothing this manager can verify
        run("convert", package / "PKGBUILD", "--source", "demo", "--output", root / "bad",
            "--evaluator", "eval-agreeing", "--evaluator-arg", "PKGBUILD", "--yes", status=2)
        # an evaluator with no argument reads no recipe, and an argument without a
        # program is not a call
        run("convert", package / "PKGBUILD", "--source", "demo", "--output", root / "bad",
            "--evaluator", agreeing, "--yes", status=2)
        run("convert", package / "PKGBUILD", "--source", "demo", "--output", root / "bad",
            "--evaluator-arg", "PKGBUILD", "--yes", status=2)
        # the options of an ordinary conversion are unchanged
        run("convert", package / "PKGBUILD", "--source", "demo", "--output", root / "plain")
        assert (root / "plain" / "eval-demo.recipe").is_file()
        run("convert", package / "PKGBUILD", "--source", "demo", status=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
