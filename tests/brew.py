#!/usr/bin/env python3
"""converts Homebrew formulas into holy recipes, builds the mechanical one and
refuses the formulas that name no source."""
import hashlib
import io
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


binary = str(Path(sys.argv[1]).resolve())


def call(*args, status=0):
    result = subprocess.run([binary, *map(str, args)], capture_output=True, text=True,
                           errors="replace")
    assert result.returncode == status, (args, result.returncode, result.stdout, result.stderr)
    return result.stdout


def convert(formula, out, status=0):
    return call("convert", formula, "--source", "brew", "--output", out, status=status)


def source_tree(root, name, version):
    directory = root / f"{name}-{version}"
    directory.mkdir(parents=True)
    (directory / "Makefile").write_text(
        "CFLAGS ?= -O2 -pipe -static\n"
        "all: bin/%(name)s\n"
        "bin/%(name)s: main.c\n"
        "\tmkdir -p bin\n"
        "\t$(CC) $(CFLAGS) -o $@ main.c\n"
        "install: bin/%(name)s\n"
        "\tmkdir -p $(DESTDIR)/usr/bin\n"
        "\tcp bin/%(name)s $(DESTDIR)/usr/bin/\n" % {"name": name})
    (directory / "main.c").write_text(
        '#include <stdio.h>\nint main(void){printf("%s\\n");return 0;}\n' % name)
    return directory


def main():
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        tree = source_tree(root, "brewfruit", "3.1")
        archive = root / "brewfruit-3.1.tar.gz"
        subprocess.run(["tar", "czf", str(archive), "-C", str(root), tree.name], check=True)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()

        # a formula that is only a source url and a build command converts natively,
        # and the recipe it produced builds a real package
        simple = root / "Brewfruit.rb"
        simple.write_text(
            "class Brewfruit < Formula\n"
            '  desc "a fixture program for the Homebrew converter"\n'
            '  homepage "https://example.org/brewfruit"\n'
            '  url "%s"\n'
            '  sha256 "%s"\n'
            '  license "MIT"\n'
            '  revision 4\n'
            '  depends_on "pkg-config"\n'
            '  depends_on "zlib" => :build\n'
            "  def install\n"
            '    system "make", "DESTDIR=$HOLY_DEST", "install"\n'
            "  end\n"
            "end\n" % (archive, digest))
        out = root / "simple"
        report = convert(simple, out)
        assert "converted brewfruit status native" in report, report
        recipe = (out / "brewfruit.recipe").read_text()
        assert 'name "brewfruit"\n' in recipe, recipe
        # a formula records no version, so the source url states it
        assert 'version "3.1"\n' in recipe, recipe
        # the revision is the release a package record holds
        assert 'release "4"\n' in recipe, recipe
        assert 'source source "%s"\n' % archive in recipe, recipe
        assert 'source-sha256 source "%s"\n' % digest in recipe, recipe
        assert 'build-depend "zlib" "any" "-"\n' in recipe, recipe
        assert 'depend "pkg-config" "any" "-"\n' in recipe, recipe
        assert 'output "brewfruit" runtime\n' in recipe, recipe
        assert "step build /bin/sh <<BUILD\ncd \"$HOLY_SRC\" || exit 1\n"
        assert "'make' \"DESTDIR=$HOLY_DEST\" 'install'\nBUILD\n" in recipe, recipe
        summary = (out / "conversion").read_text()
        assert "status native\n" in summary, summary
        assert "license MIT" in summary, summary
        assert "the revision 4 becomes the release" in summary, summary
        assert "the version 3.1 comes from the source url" in summary, summary
        assert "dependency runtime 1 build 1 optional 0 sources 1" in summary, summary

        built = root / "built"
        call("build", out / "brewfruit.recipe", "--output", built, "--yes")
        artifacts = sorted(p.name for p in built.glob("*.holy"))
        # a static payload carries no runtime, so the group is the one the recipe named
        assert artifacts == ["brewfruit--x86_64--nolibc.holy"], artifacts
        artifact = built / artifacts[0]
        call("verify", "local:" + str(artifact))
        identity = call("info", "local:" + str(artifact))
        assert "name brewfruit\n" in identity, identity
        assert "version 3.1\n" in identity, identity
        assert "release 4\n" in identity, identity
        assert "arch x86_64\n" in identity, identity
        assert "libc nolibc\n" in identity, identity
        listing = call("manifest", "local:" + str(artifact))
        assert "usr/bin/brewfruit" in listing, listing
        target = root / "root"
        target.mkdir()
        call("db", "init", "--root", target)
        call("cache", "stage", "local:" + str(artifact), "--root", target)
        artifact_digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        # the depends_on the formula stated is a package requirement, so the set is
        # unresolved until a source provides it
        requirements = call("requirements", "local:" + str(artifact))
        assert 'require "brewfruit-req-0" "brewfruit" "package" "pkg-config" "any" "any" ' \
               '"any" "-" "recipe-depend" "holy-recipe"' in requirements, requirements
        result = subprocess.run([binary, "db", "plan-set", artifact_digest, "--root", target],
                                capture_output=True, text=True)
        assert result.returncode == 4, result
        assert "unresolved requirement brewfruit-req-0" in result.stderr, result.stderr
        provider_tree = root / "provider"
        (provider_tree / "HOLY").mkdir(parents=True)
        (provider_tree / "DATA/usr/bin").mkdir(parents=True)
        # a script needs an interpreter, so the provider carries a static shell
        (provider_tree / "DATA/bin").mkdir(parents=True)
        shell_source = root / "sh.c"
        shell_source.write_text("int main(void) { return 0; }\n")
        shell = False
        for compiler in ("cc", "gcc", "clang"):
            built_shell = subprocess.run([compiler, "-static", str(shell_source), "-o", str(
                provider_tree / "DATA/bin/sh")], capture_output=True)
            if built_shell.returncode == 0:
                shell = True
                break
        assert shell, "a static shell is required for the script provider fixture"
        (provider_tree / "DATA/usr/bin/pkg-config").write_text("#!/bin/sh\nexit 0\n")
        (provider_tree / "DATA/usr/bin/pkg-config").chmod(0o755)
        (provider_tree / "HOLY/meta").write_text(
            "format holy-package-1\nname pkg-config\nversion 1\nrelease 1\nos linux\n"
            "arch x86_64\nlibc nolibc\n")
        for field, body in (("deps", ""), ("hooks", ""), ("origin", ""), ("transform", ""),
                            ("provides", "provide package pkg-config x86_64 nolibc - metadata\n")):
            (provider_tree / "HOLY" / field).write_text(body)
        call("manifest", "generate", provider_tree, "--output", root / "provider-files")
        (provider_tree / "HOLY/files").write_text((root / "provider-files").read_text())
        call("pack", provider_tree, "--output", root / "provider.holy")
        provider_digest = hashlib.sha256((root / "provider.holy").read_bytes()).hexdigest()
        call("cache", "stage", "local:" + str(root / "provider.holy"), "--root", target)
        plan = call("db", "plan-set", artifact_digest, provider_digest, "--root", target)
        assert "requirement brewfruit-req-0 consumer %s provider %s package pkg-config" % (
            artifact_digest, provider_digest) in plan, plan
        plan_hash = [line.split()[10] for line in plan.splitlines()
                     if line.startswith("plan-set ")][0]
        applied = call("db", "apply-set", plan_hash, artifact_digest, provider_digest,
                       "--root", target)
        assert "artifacts 2" in applied, applied
        assert (target / "usr/bin/brewfruit").is_file(), sorted(
            str(p.relative_to(target)) for p in target.rglob("*") if p.is_file())
        call("db", "check", "--all", "--root", target)

        # a formula with Ruby this converter does not translate keeps the formula
        # beside the recipe and names every line it could not carry
        rich = root / "Rich.rb"
        rich.write_text('''class Rich < Formula
  desc "a formula that mixes shell, Ruby and platform blocks"
  url "https://example.org/rich-2.0.tar.gz"
  sha256 "%s"
  head "https://github.com/example/rich.git", branch: "main"
  mirror "https://mirror.example.org/rich-2.0.tar.gz"
  depends_on "readline" => :recommended
  uses_from_macos "CoreFoundation"
  on_macos do
    system "clang", "-arch", "-64", "install"
  end
  on_linux do
    system "meson", "setup", "build", "--prefix=#{prefix}"
  end
  resource "rich-data" do
    url "https://example.org/rich-data-2.0.tar.gz"
    sha256 "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  end
  bottle do
    sha256 cellar: :any, sonoma: "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"
  end
  def install
    system "./configure", "--prefix=#{prefix}", "--libdir=#{libexec}"
    system "make", "install"
    system "make", "install", "PREFIX=#{weird_value}"
    inreplace "Makefile", "PREFIX=/usr", "PREFIX=#{prefix}"
  end
  test do
    assert_equal "2.0", shell_output("#{bin}/rich --version")
  end
end
''' % digest)
        rich_out = root / "rich"
        report = convert(rich, rich_out, status=3)
        assert "converted rich status review-required" in report, report
        recipe = (rich_out / "rich.recipe").read_text()
        # the Homebrew prefix is the build root, so the interpolation becomes a
        # build path rather than a cellar
        assert '"--prefix=$HOLY_DEST"' in recipe, recipe
        assert '"--libdir=$HOLY_DEST/libexec"' in recipe, recipe
        assert "#{" not in recipe.split("source-sha256")[0], recipe
        # an interpolation this reader does not model is kept and named
        assert "'PREFIX=#{weird_value}'" in recipe, recipe
        # a resource with a pinned digest is a fetched source
        assert 'source "resource-rich-data" "https://example.org/rich-data-2.0.tar.gz"\n' \
               in recipe, recipe
        summary = (rich_out / "conversion").read_text()
        assert "status review-required\n" in summary, summary
        assert "the head at line 5 is a development checkout" in summary, summary
        assert "the directive mirror at line 6 is not one this converter reads" in summary, summary
        assert "the dependency readline at line 7 is recommended" in summary, summary
        assert "the macOS framework CoreFoundation at line 8" in summary, summary
        assert "the on_macos block at line 9" in summary, summary
        assert "the on_linux block at line 12 is carried" in summary, summary
        assert "the resource rich-data at line 15 becomes a fetched source" in summary, summary
        assert "the bottle block at line 19 is a prebuilt foreign binary" in summary, summary
        assert "the install statement at line 26 is Ruby" in summary, summary
        assert "the test block at line 28 is Ruby" in summary, summary
        assert "the interpolation at line 25 names a Homebrew value" in summary, summary
        # the Ruby that did not translate travels beside the recipe with its digest
        assert "preserved homebrew-install.rb " in summary, summary
        assert (rich_out / "homebrew-install.rb").read_text() == rich.read_text()
        # the Ruby this converter could not translate is the helper environment the
        # build needs, and its ordered digest reaches the recipe
        assert "helper-environment homebrew-ruby" in summary, summary
        env_digest = summary.split("helper-environment-sha256 ")[1].split()[0]
        assert f'x-helper-environment-sha256 "{env_digest}"' in recipe, recipe
        # the build needs an interpreter for it
        assert 'build-depend "ruby" "any" "-"\n' in recipe, recipe
        assert "the install body keeps 1 Ruby statements" in summary, summary

        # a formula that states no source names no version and no build
        for body, wanted in (
                ('class NoSource < Formula\n  desc "nothing to fetch"\nend\n',
                 "states no url"),
                ('class NoDigest < Formula\n  url "https://example.org/x-1.0.tar.gz"\nend\n',
                 "states no sha256"),
                ('class Casky < Cask\n  url "https://example.org/app.zip"\n  sha256 "aa"\nend\n',
                 "inherits from a cask"),
                ('class Broken < Formula\n  url "https://example.org/b-1.0.tar.gz"\n'
                 '  sha256 "aa"\n  def install\n    system "make"\n',
                 "block that never ends")):
            case = root / (wanted.split()[0] + str(len(body)) + ".rb")
            case.write_text(body)
            result = subprocess.run([binary, "convert", case, "--source", "brew", "--output",
                                     root / (case.stem + "-out")], capture_output=True, text=True)
            if wanted == "inherits from a cask":
                # a cask still names its source, so the report carries the refusal
                assert result.returncode == 3, (wanted, result)
                assert "inherits from a cask" in (root / (case.stem + "-out") / "conversion").read_text()
                continue
            # a formula with no source, no digest or an unterminated block is refused
            # with the reason, and a cask is a report instead, since it names a source
            assert result.returncode in (1, 2, 3), (wanted, result)
            if result.returncode == 3:
                report = (root / (case.stem + "-out") / "conversion").read_text()
                assert wanted.split()[0] in report or wanted in report, (wanted, report)
            else:
                assert wanted in result.stderr, (wanted, result.stderr)

        # a file that is not there, and one that is not text
        result = subprocess.run([binary, "convert", root / "absent.rb", "--source", "brew",
                                 "--output", root / "absent-out"], capture_output=True, text=True)
        assert result.returncode == 6, result
        assert "formula unavailable" in result.stderr, result.stderr
        binary_formula = root / "Binary.rb"
        binary_formula.write_bytes(b"\x00\x01\x02class Nope < Formula\n")
        result = subprocess.run([binary, "convert", binary_formula, "--source", "brew",
                                 "--output", root / "binary-out"], capture_output=True, text=True)
        assert result.returncode == 2, result
        assert "Ruby text" in result.stderr, result.stderr
        # a conversion without a source name is refused before the file is read
        result = subprocess.run([binary, "convert", simple, "--source", "local", "--output",
                                 root / "local-out"], capture_output=True, text=True)
        assert result.returncode == 2, result
        assert "needs the source name" in result.stderr, result.stderr
        result = subprocess.run([binary, "convert", simple, "--source", "a/b", "--output",
                                 root / "slash-out"], capture_output=True, text=True)
        assert result.returncode == 2, result
        assert "invalid source name" in result.stderr, result.stderr
        assert not (root / "slash-out").exists()

    print("homebrew fixtures passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
