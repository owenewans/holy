#!/usr/bin/env python3
import hashlib
import os
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile

binary = str(pathlib.Path(sys.argv[1]).resolve())
compiler = shutil.which(os.environ.get("FIXTURE_CC", "cc")) or shutil.which("gcc")


def call(*args, status=0):
    result = subprocess.run([binary, *map(str, args)], capture_output=True, text=True)
    assert result.returncode == status, (args, result.returncode, result.stdout, result.stderr)
    return result.stdout


def pack_snap(source, image, offset=8):
    """a snap is a SquashFS image behind a header of its offset and its size"""
    filesystem = image.with_suffix(".squashfs")
    subprocess.run(["mksquashfs", str(source), str(filesystem), "-noappend", "-quiet"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    body = filesystem.read_bytes()
    image.write_bytes(struct.pack("<II", offset, len(body)) + b"\0" * (offset - 8) + body)
    filesystem.unlink()
    return image


def fixture_tree(root, name, manifest, command, escaping_link=True):
    source = root / name
    (source / "bin").mkdir(parents=True)
    (source / "meta").mkdir()
    (source / "bin" / "fixture").write_bytes(command)
    (source / "bin" / "fixture").chmod(0o755)
    (source / "libdata").write_text("snap payload\n")
    (source / "runner").write_text("#!/bin/sh\nexit 0\n")
    (source / "runner").chmod(0o755)
    if escaping_link:
        source.joinpath("system-link").symlink_to("/usr/lib/outside")
    (source / "meta" / "snap.yaml").write_text(manifest)
    (source / "meta" / "gui.desktop").write_text(
        "[Desktop Entry]\nType=Application\nName=Fixture\nExec=fixture\n")
    return source


MANIFEST = """name: fixture
version: '1.4.2'
summary: a snap the fixture builds
base: core22
grade: stable
confinement: strict
architectures:
  - build-on: amd64
  - build-on: arm64
environment:
  FIXTURE_MODE: strict
command: bin/fixture
command-chain:
  - bin/fixture --chained
plugs:
  home:
    read: [ all ]
  network-bind:
  opengl:
hooks:
  install:
  configure:
system-usernames:
  snap_daemon: shared
apps:
  fixture:
    command: bin/fixture
layout:
  /usr/lib/x86_64-linux-gnu:
    bind: $SNAP/usr/lib/x86_64-linux-gnu
parts:
  fixture:
    plugin: dump
    stage-packages:
      - libstdc++6
"""

with tempfile.TemporaryDirectory() as scratch:
    root = pathlib.Path(scratch)
    dynamic = fixture_tree(root, "snaproot", MANIFEST, pathlib.Path("/bin/true").read_bytes())
    image = pack_snap(dynamic, root / "fixture.snap")
    entry = root / "entry.c"
    entry.write_text("int main(void) { return 0; }\n")
    built = subprocess.run([compiler, "-static", str(entry), "-o", str(root / "static-fixture")],
                           capture_output=True, text=True) if compiler else None
    self_contained = bool(built and built.returncode == 0)

    info = call("snap", "inspect", image)
    assert "type snap\n" in info
    assert "squashfs-offset 8\n" in info
    assert "compression 4\n" in info
    assert f"sha256 {hashlib.sha256(image.read_bytes()).hexdigest()}\n" in info
    bare = root / "bare.snap"
    bare.write_bytes(struct.pack("<II", 8, 11) + b"not squashfs")
    call("snap", "inspect", bare, status=2)
    shifted = root / "shifted.snap"
    shifted.write_bytes(struct.pack("<II", 4096, 11) + image.read_bytes()[8:])
    call("snap", "inspect", shifted, status=2)

    if os.geteuid() != 0:
        output = root / "extracted"
        call("snap", "extract", image, "--output", output)
        assert (output / "original").read_bytes() == image.read_bytes()
        assert (output / "snap" / "meta" / "snap.yaml").read_text() == MANIFEST
        receipt = (output / "conversion").read_text()
        assert "format holy-snap-extract-1\n" in receipt
        assert "state extracted-unclassified\n" in receipt
        no_tool = root / "no-tool"
        no_tool.mkdir()
        result = subprocess.run([binary, "snap", "extract", str(image), "--output",
                                 str(root / "missing-tool")],
                                capture_output=True, text=True,
                                env={**os.environ, "PATH": str(no_tool)})
        assert result.returncode == 6, (result.returncode, result.stdout, result.stderr)
        assert not (root / "missing-tool" / "conversion").exists()

        imported = root / "imported"
        staged = subprocess.run([binary, "import", str(image), "--source", "vendor",
                                 "--format", "snap", "--output", str(imported)],
                                capture_output=True, text=True)
        assert staged.returncode == 3, (staged.stdout, staged.stderr)
        assert "without snapd" in staged.stderr, staged.stderr
        artifacts = sorted(p.name for p in imported.glob("*.holy"))
        assert artifacts == ["fixture--x86_64--glibc.holy"], artifacts
        artifact = imported / artifacts[0]
        identity = call("info", "local:" + str(artifact))
        assert "name fixture\n" in identity and "version 1.4.2\n" in identity, identity
        call("verify", "local:" + str(artifact))
        manifest = call("manifest", "local:" + str(artifact))
        for path in ("usr/bin/fixture",
                     "usr/lib/holy/private/fixture/snap/meta/snap.yaml",
                     "usr/lib/holy/private/fixture/usr/bin/fixture.snap",
                     "usr/share/holy/fixture/conversion"):
            assert path in manifest, path
        # the runtime the snap asks for stays a requirement a source has to satisfy
        requirements = call("requirements", "local:" + str(artifact))
        assert 'require "snap-base" "fixture" "package" "core22" "x86_64" "any"' in \
            requirements, requirements
        assert '"libc.so.6"' in requirements
        # the link whose target cannot travel is recorded rather than dropped
        assert 'require "snap-link-0" "fixture" "file" "/usr/lib/outside"' in requirements, \
            requirements
        report = (imported / "package").read_text()
        assert "format holy-snap-package-1\n" in report
        assert "status review-required\n" in report
        assert "base-required core22 is the runtime snapd would mount from a snap store" in \
            report, report
        assert "confinement strict is dropped" in report, report
        assert "plugs 3 interfaces are dropped" in report, report
        assert "hooks 2 the manifest declares" in report, report
        assert "command-chain 1 entries" in report, report
        assert "environment 1 variables" in report, report
        assert "path-view-required 1 links" in report, report
        assert "scripts 1 files carry an interpreter" in report, report
        assert "payload files" in report
        call("fetch", "local:" + str(artifact), "--extract", "--output",
             str(root / "unpacked"))
        data = root / "unpacked/DATA"
        launcher = (data / "usr/bin/fixture").read_text()
        assert "holypkg run vendor:fixture" in launcher
        assert '-- /usr/lib/holy/private/fixture/usr/bin/fixture.snap "$@"' in launcher, launcher
        # the manifest travels whole, so a converted snap keeps its own metadata
        assert (data / "usr/lib/holy/private/fixture/snap/meta/snap.yaml").read_text() == MANIFEST
        assert (data / "usr/lib/holy/private/fixture/snap/meta/gui.desktop").read_text() \
            .startswith("[Desktop Entry]")
        assert not (data / "usr/lib/holy/private/fixture/snap/system-link").exists()

        # a payload whose ELF states no loader search path cannot be placed, because
        # this manager will not guess where the loader would look for its library
        unresolved = root / "unresolved root"
        (unresolved / "usr/bin").mkdir(parents=True)
        call("db", "init", "--root", unresolved)
        call("cache", "stage", "local:" + str(artifact), "--root", unresolved)
        refused = subprocess.run([binary, "db", "plan-set",
                                  hashlib.sha256(artifact.read_bytes()).hexdigest(),
                                  "--root", str(unresolved)], capture_output=True, text=True)
        assert refused.returncode != 0, refused
        assert "snap-base" in refused.stderr or "unknown-loader-search" in refused.stderr, \
            refused.stderr
        assert not (unresolved / "usr/bin/fixture").exists()

        # a self-contained payload installs once its declared runtime and its shell
        # are available, and the run context starts the private entry point
        if self_contained:
            plain = fixture_tree(root, "staticroot", MANIFEST,
                                 (root / "static-fixture").read_bytes(), escaping_link=False)
            static_image = pack_snap(plain, root / "static.snap")
            staged = root / "static"
            result = subprocess.run([binary, "import", str(static_image), "--source", "vendor",
                                     "--format", "snap", "--output", str(staged)],
                                    capture_output=True, text=True)
            assert result.returncode == 3, (result.stdout, result.stderr)
            # the manifest names the package, so the second image converts to the
            # same name with the runtime its payload actually has
            static_artifact = staged / "fixture--x86_64--nolibc.holy"
            assert static_artifact.is_file(), sorted(p.name for p in staged.glob("*.holy"))
            trees = {}
            for name, payload, arch, libc in (("core22", "usr/lib/core22/runtime", "x86_64", "glibc"),
                                              ("sh", "bin/sh", "x86_64", "nolibc")):
                tree = root / (name + "-tree")
                (tree / "HOLY").mkdir(parents=True)
                target = tree / "DATA" / payload
                target.parent.mkdir(parents=True, exist_ok=True)
                if name == "core22":
                    target.write_text("base runtime fixture\n")
                else:
                    shutil.copyfile(root / "static-fixture", target)
                    target.chmod(0o755)
                (tree / "HOLY/meta").write_text(
                    "format holy-package-1\nname %s\nversion 1\nrelease 1\nos linux\n"
                    "arch %s\nlibc %s\n" % (name, arch, libc))
                for field in ("deps", "provides", "hooks", "origin", "transform"):
                    (tree / "HOLY" / field).write_text("")
                # the generator reads the tree it walks, so its output lands beside it
                call("manifest", "generate", tree, "--output", root / (name + "-files"))
                (tree / "HOLY/files").write_text((root / (name + "-files")).read_text())
                call("pack", tree, "--output", root / (name + ".holy"))
                trees[name] = root / (name + ".holy")
            target = root / "target root"
            (target / "usr/bin").mkdir(parents=True)
            call("db", "init", "--root", target)
            digests = [hashlib.sha256(static_artifact.read_bytes()).hexdigest()]
            for name in ("core22", "sh"):
                digests.append(hashlib.sha256(trees[name].read_bytes()).hexdigest())
                call("cache", "stage", "local:" + str(trees[name]), "--root", target)
            call("cache", "stage", "local:" + str(static_artifact), "--root", target)
            plan = call("db", "plan-set", *digests, "--root", target)
            plan_sha = [line.split()[10] for line in plan.splitlines()
                        if line.startswith("plan-set ")][0]
            applied = call("db", "apply-set", plan_sha, *digests, "--root", target)
            assert "artifacts 3" in applied, applied
            assert (target / "usr/bin/fixture").read_text() == launcher.replace("fixture",
                                                                                "fixture")
            assert (target / "usr/lib/holy/private/fixture/snap/meta/snap.yaml").read_text() \
                == MANIFEST
            assert (target / "usr/lib/core22/runtime").read_text() == "base runtime fixture\n"
            started = subprocess.run(
                [binary, "run", "local:fixture", "--root", str(target), "--",
                 "/usr/lib/holy/private/fixture/usr/bin/fixture.snap"],
                capture_output=True, text=True)
            assert started.returncode == 0, (started.returncode, started.stdout, started.stderr)
    else:
        call("snap", "extract", image, "--output", root / "root-denied", status=6)

    if os.geteuid() != 0:
        # a snap without a command has no entry point a package could name
        plain = root / "plain"
        (plain / "bin").mkdir(parents=True)
        (plain / "meta").mkdir()
        (plain / "bin" / "fixture").write_bytes(pathlib.Path("/bin/true").read_bytes())
        (plain / "bin" / "fixture").chmod(0o755)
        (plain / "meta" / "snap.yaml").write_text("name: plain\nversion: '1'\nbase: core22\n")
        result = subprocess.run([binary, "import", str(pack_snap(plain, root / "plain.snap")),
                                 "--source", "vendor", "--format", "snap",
                                 "--output", str(root / "plain-out")],
                                capture_output=True, text=True)
        assert result.returncode == 3, (result.stdout, result.stderr)
        assert "names no command" in result.stderr, result.stderr
        assert not list((root / "plain-out").glob("*.holy"))
        # a manifest whose name the package format cannot record is refused
        bad = root / "bad"
        (bad / "bin").mkdir(parents=True)
        (bad / "meta").mkdir()
        (bad / "bin" / "fixture").write_bytes(pathlib.Path("/bin/true").read_bytes())
        (bad / "bin" / "fixture").chmod(0o755)
        (bad / "meta" / "snap.yaml").write_text(
            "name: 'bad name'\nversion: '1'\nbase: core22\ncommand: bin/fixture\n")
        result = subprocess.run([binary, "import", str(pack_snap(bad, root / "bad.snap")),
                                 "--source", "vendor", "--format", "snap",
                                 "--output", str(root / "bad-out")],
                                capture_output=True, text=True)
        assert result.returncode == 2, (result.stdout, result.stderr)
        assert "not a package name" in result.stderr, result.stderr
        # a command that names a path outside the snap is refused
        outside = root / "outside"
        (outside / "bin").mkdir(parents=True)
        (outside / "meta").mkdir()
        (outside / "meta" / "snap.yaml").write_text(
            "name: outside\nversion: '1'\nbase: core22\ncommand: ../bin/fixture\n")
        result = subprocess.run([binary, "import", str(pack_snap(outside, root / "outside.snap")),
                                 "--source", "vendor", "--format", "snap",
                                 "--output", str(root / "outside-out")],
                                capture_output=True, text=True)
        assert result.returncode == 3, (result.stdout, result.stderr)
        assert "cannot place" in result.stderr, result.stderr
        # a snap with no readable manifest is refused rather than packaged blind
        bare_root = root / "bare-root"
        (bare_root / "bin").mkdir(parents=True)
        (bare_root / "meta").mkdir()
        (bare_root / "bin" / "fixture").write_bytes(pathlib.Path("/bin/true").read_bytes())
        (bare_root / "bin" / "fixture").chmod(0o755)
        result = subprocess.run([binary, "import", str(pack_snap(bare_root, root / "bare.snap")),
                                 "--source", "vendor", "--format", "snap",
                                 "--output", str(root / "bare-out")],
                                capture_output=True, text=True)
        assert result.returncode == 3, (result.stdout, result.stderr)
        assert "no readable meta/snap.yaml" in result.stderr, result.stderr

    # the offset a snap states is honoured, so a padded image extracts too
    if os.geteuid() != 0:
        padded = pack_snap(dynamic, root / "padded.snap", offset=512)
        info = call("snap", "inspect", padded)
        assert "squashfs-offset 512\n" in info
        output = root / "padded-out"
        call("snap", "extract", padded, "--output", output)
        assert (output / "snap" / "meta" / "snap.yaml").read_text() == MANIFEST

print("snap inspect/extract/import fixtures passed")