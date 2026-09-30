#!/usr/bin/env python3
"""converts Solus eopkg artifacts into native packages, and records what a Solus
installation would also do that this conversion does not."""
import hashlib
import io
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile


binary = str(pathlib.Path(sys.argv[1]).resolve())


def call(*args, status=0):
    result = subprocess.run([binary, *map(str, args)], capture_output=True, text=True)
    assert result.returncode == status, (args, result.returncode, result.stdout, result.stderr)
    return result.stdout


METADATA = """<?xml version="1.0" encoding="utf-8"?>
<PISI>
  <Source>
    <Name>{name}</Name>
    <Packager>
      <Name>Solus Build Server</Name>
      <Email>packages@solus-project.org</Email>
    </Packager>
  </Source>
  <Package>
    <Name>{name}</Name>
    <Version>{version}</Version>
    <Architecture>{arch}</Architecture>
    <Summary xml:lang="en">{summary}</Summary>
    <Description xml:lang="en">A longer description the native manifest has no field
for.</Description>
    <PartOf>system.devel</PartOf>
    <License>{license}</License>
    <Url>{url}</Url>
    <RuntimeDependencies>
{dependencies}    </RuntimeDependencies>
    <BuildDependencies>
      <Dependency>cmake</Dependency>
    </BuildDependencies>
    <Conflicts>
      <Conflicts>solus-toolchain</Conflicts>
    </Conflicts>
    <Replaces>
      <Replaces>legacy-{name}</Replaces>
    </Replaces>
    <Provides>
      <Provides>libfixture.so.1</Provides>
    </Provides>
    <History>
      <Update release="1">
        <Date>2024-01-01</Date>
        <Version>{version}</Version>
        <Comment>Initial import</Comment>
      </Update>
    </History>
  </Package>
</PISI>
"""


def read_record(artifact, name):
    """one HOLY record, read out of the archive the manager wrote"""
    contents = subprocess.run(["lz4", "-dc", str(artifact)], check=True,
                              capture_output=True).stdout
    with tarfile.open(fileobj=io.BytesIO(contents)) as archive:
        return archive.extractfile(name).read().decode()


def dependencies(entries):
    return "".join('      <Dependency releaseFrom="%s">%s</Dependency>\n' % (release, name)
                   for name, release in entries)


def eopkg(path, name="fixture", version="1.2.3", arch="x86_64", payload=None,
          depends=(("libfixture-runtime", "10"),), members=(),
          metadata=None, drop_metadata=False, drop_install=False):
    """one eopkg: a ZIP carrying the metadata, the file list and an install tar"""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        if not drop_metadata:
            archive.writestr("metadata.xml", metadata if metadata is not None else
                             METADATA.format(name=name, version=version, arch=arch,
                                              summary="a small fixture program",
                                              license="GPL-3.0-or-later",
                                              url="https://example.org/fixture",
                                              dependencies=dependencies(depends)))
        archive.writestr("files.xml",
                         '<?xml version="1.0" encoding="utf-8"?>\n<PISI><Files>\n'
                         '  <File><Path>usr/bin/%s</Path><Type>executable</Type></File>\n'
                         '</Files></PISI>\n' % name)
        if not drop_install:
            if payload is None:
                tar = io.BytesIO()
                with tarfile.open(fileobj=tar, mode="w") as inner:
                    info = tarfile.TarInfo("./usr/bin/%s" % name)
                    info.size = len(b"#!/bin/sh\nexit 0\n")
                    info.mode = 0o755
                    info.mtime = 0
                    inner.addfile(info, io.BytesIO(b"#!/bin/sh\nexit 0\n"))
                    info = tarfile.TarInfo("./usr/share/doc/%s/README" % name)
                    info.size = len(b"the fixture documentation\n")
                    info.mode = 0o644
                    info.mtime = 0
                    inner.addfile(info, io.BytesIO(b"the fixture documentation\n"))
                    info = tarfile.TarInfo("./usr/bin/%s-run" % name)
                    info.type = tarfile.SYMTYPE
                    info.linkname = name
                    info.mode = 0o777
                    info.mtime = 0
                    inner.addfile(info)
                payload = tar.getvalue()
            archive.writestr("install.tar", payload)
        for member, body in members:
            archive.writestr(member, body)
    path.write_bytes(buffer.getvalue())
    return path


def main():
    with tempfile.TemporaryDirectory() as scratch:
        root = pathlib.Path(scratch)
        package = eopkg(root / "fixture.eopkg")
        out = root / "converted"
        report = call("import", package, "--source", "eopkg", "--format", "eopkg",
                      "--output", out, status=3)
        artifact = out / "fixture--noarch--nolibc.holy"
        assert "imported fixture--noarch--nolibc.holy artifact" in report, report
        assert artifact.is_file(), sorted(p.name for p in out.iterdir())
        call("verify", "local:" + str(artifact))
        identity = call("info", "local:" + str(artifact))
        assert "name fixture\n" in identity and "version 1.2.3\n" in identity, identity
        # Solus states no release of its own, so the native revision starts at one
        assert "release 1\n" in identity, identity
        assert "x-version-family eopkg\n" in identity, identity
        # the x- records the converter carries are in the metadata, not in info
        assert read_record(artifact, "HOLY/meta") == (
            'format holy-package-1\n'
            'name "fixture"\n'
            'version "1.2.3"\n'
            'release "1"\n'
            'os linux\n'
            'arch "noarch"\n'
            'libc "nolibc"\n'
            'x-version-family eopkg\n'
            'x-source-family eopkg\n'
            'x-converter holy-eopkg-1\n'
            'x-source-arch "x86_64"\n'
            'x-eopkg-format "1.2"\n'
            'x-eopkg-component "system.devel"\n'), read_record(artifact, "HOLY/meta")

        # the original artifact travels whole beside the package
        assert (out / "original").read_bytes() == package.read_bytes()
        listing = call("manifest", "local:" + str(artifact))
        for path in ("usr/lib/holy/private/fixture/eopkg/usr/bin/fixture",
                     "usr/lib/holy/private/fixture/eopkg/usr/share/doc/fixture/README",
                     "usr/lib/holy/private/fixture/eopkg/usr/bin/fixture-run"):
            assert path in listing, path

        # each runtime dependency becomes a package requirement, and a Solus
        # releaseFrom attribute becomes the original expression rather than a version
        requirements = call("requirements", "local:" + str(artifact))
        assert 'require "eopkg-depend-0" "fixture" "package" "libfixture-runtime" "any" ' \
               '"any" "any" "-" "10" "eopkg-metadata.xml"' in requirements, requirements

        # the payload and the reports are both written, and the report names what a
        # Solus installation would do that this one does not
        package_report = (out / "package").read_text()
        assert "format holy-eopkg-package-1\n" in package_report
        assert "status review-required\n" in package_report
        assert "depends 1; each becomes an exact package requirement" in package_report
        assert "dependency libfixture-runtime line " in package_report
        assert "releaseFrom 10" in package_report, package_report
        assert "conflicts 1 counted" in package_report
        assert "replaces 1 counted" in package_report
        assert "provides 1 counted" in package_report
        assert "packager 2 source identity records" in package_report
        assert "description the metadata states one" in package_report
        assert "history 1 update records" in package_report
        assert "file-list the artifact declares one" in package_report
        # a build dependency is not a runtime one, so it is not a requirement
        assert "cmake" not in requirements, requirements

        # the install script, a delta, a signature and an unmodelled member are named
        rich = eopkg(root / "rich.eopkg", name="rich", members=(
            ("EOPKG-SETUP", "#!/bin/sh\ncomar -c 2a1b3c4d\neopkg_check\n"),
            ("delta-1.0-2.bin", "not a patch this manager applies"),
            ("EOPKG-SIGNATURE", "not a signature this manager trusts"),
            ("extra-member.txt", "a member this reader does not model"),
        ))
        rich_out = root / "rich-out"
        call("import", rich, "--source", "eopkg", "--format", "eopkg", "--output", rich_out,
             status=3)
        rich_report = (rich_out / "package").read_text()
        assert "install-script the artifact states one" in rich_report, rich_report
        assert "delta the artifact states one" in rich_report, rich_report
        assert "signature the artifact states one" in rich_report, rich_report
        assert "unknown 1 archive members" in rich_report, rich_report
        assert "artifact 7 members" in rich_report, rich_report

        # the payload installs as ordinary files and nothing executes
        target = root / "target"
        (target / "usr/bin").mkdir(parents=True)
        call("db", "init", "--root", target)
        call("cache", "stage", "local:" + str(artifact), "--root", target)
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        runtime_tree = root / "trees/libfixture-runtime"
        (runtime_tree / "HOLY").mkdir(parents=True)
        (runtime_tree / "DATA/usr/lib").mkdir(parents=True)
        (runtime_tree / "DATA/usr/lib/libfixture-runtime.so").write_text("the runtime\n")
        # a generated launcher needs a shell, so the provider carries a static one
        (runtime_tree / "DATA/bin").mkdir(parents=True)
        shell_source = root / "sh.c"
        shell_source.write_text("int main(void) { return 0; }\n")
        shell = False
        for compiler in ("cc", "gcc", "clang"):
            if not shutil.which(compiler):
                continue
            built = subprocess.run([compiler, "-static", str(shell_source), "-o", str(
                runtime_tree / "DATA/bin/sh")], capture_output=True, text=True)
            if built.returncode == 0:
                shell = True
                break
        assert shell, "a static shell is required for the launcher fixtures"
        (runtime_tree / "DATA/bin/sh").chmod(0o755)
        (runtime_tree / "HOLY/meta").write_text(
            "format holy-package-1\nname libfixture-runtime\nversion 1\nrelease 1\nos linux\n"
            "arch x86_64\nlibc nolibc\n")
        for field in ("deps", "hooks", "origin", "transform"):
            (runtime_tree / "HOLY" / field).write_text("")
        # the requirement the Solus metadata states is exact, so the provider has to
        # state the dependency name for the set to close
        (runtime_tree / "HOLY/provides").write_text(
            "provide package libfixture-runtime x86_64 nolibc - fixture\n")
        call("manifest", "generate", runtime_tree, "--output", root / "runtime-files")
        (runtime_tree / "HOLY/files").write_text((root / "runtime-files").read_text())
        call("pack", runtime_tree, "--output", root / "runtime.holy")
        runtime_digest = hashlib.sha256((root / "runtime.holy").read_bytes()).hexdigest()
        call("cache", "stage", "local:" + str(root / "runtime.holy"), "--root", target)
        # the set needs the provider the metadata names, so the exact requirements
        # are what close it
        plan = call("db", "plan-set", digest, runtime_digest, "--root", target)
        assert "provider" in plan, plan
        plan_sha = [line.split()[10] for line in plan.splitlines()
                    if line.startswith("plan-set ")][0]
        applied = call("db", "apply-set", plan_sha, digest, runtime_digest, "--root", target)
        assert "artifacts 2" in applied, applied
        installed = target / "usr/lib/holy/private/fixture/eopkg/usr/bin/fixture"
        assert installed.is_file(), sorted(str(p.relative_to(target))
                                           for p in target.rglob("*") if p.is_file())
        # a Solus layout is recorded, not claimed, so nothing lands in the public tree
        assert not (target / "usr/share/doc/fixture").exists()
        assert (target / "usr/lib/holy/private/fixture/eopkg/usr/bin/fixture-run").is_symlink()
        call("db", "check", "--all", "--root", target)

        # a metadata without a name, a version or an architecture is refused
        for field, wanted in (("Name", "package name or version"),
                              ("Version", "package name or version"),
                              ("Architecture", "no architecture")):
            case = eopkg(root / ("bad-" + field + ".eopkg"), name="bad")
            body = (root / ("bad-" + field + ".eopkg")).read_bytes()
            with zipfile.ZipFile(io.BytesIO(body)) as archive:
                names = archive.namelist()
                texts = {n: archive.read(n) for n in names}
            text = texts["metadata.xml"].decode()
            text = "\n".join(line for line in text.splitlines()
                             if not line.strip().startswith("<" + field))
            texts["metadata.xml"] = text.encode()
            with zipfile.ZipFile(case, "w", zipfile.ZIP_DEFLATED) as archive:
                for name, value in texts.items():
                    archive.writestr(name, value)
            result = subprocess.run([binary, "import", case, "--source", "eopkg", "--format",
                                     "eopkg", "--output", root / (field + "-out")],
                                    capture_output=True, text=True)
            assert result.returncode == 2, (field, result)
            assert wanted in result.stderr, (field, result.stderr)
            assert not (root / (field + "-out")).exists() or \
                not list((root / (field + "-out")).glob("*.holy"))

        # an architecture this manager does not place is a decision, not a guess
        arm = eopkg(root / "arm.eopkg", name="arm", arch="riscv64")
        result = subprocess.run([binary, "import", arm, "--source", "eopkg", "--format",
                                 "eopkg", "--output", root / "arm-out"],
                                capture_output=True, text=True)
        assert result.returncode == 3, result
        assert "requires classification" in result.stderr, result.stderr

        # an artifact without metadata or without an install tar is refused
        for missing, wanted in (("drop_metadata", "no metadata.xml"),
                                ("drop_install", "no install tar")):
            case = eopkg(root / (missing + ".eopkg"), **{missing: True})
            result = subprocess.run([binary, "import", case, "--source", "eopkg", "--format",
                                     "eopkg", "--output", root / (missing + "-out")],
                                    capture_output=True, text=True)
            assert result.returncode == 2, (wanted, result)
            assert wanted in result.stderr, (wanted, result.stderr)

        # metadata that is not a document, and a document that ends inside an element
        for body, wanted in (("not xml at all", "no package name or version"),
                             ("<PISI><Package><Name>fixture</Name>", "not a document"),
                             ("<PISI><Package", "not a document"),
                             ("<PISI><!-- unterminated", "not a document")):
            case = eopkg(root / "broken.eopkg", metadata=body)
            result = subprocess.run([binary, "import", case, "--source", "eopkg", "--format",
                                     "eopkg", "--output", root / "broken-out"],
                                    capture_output=True, text=True)
            assert result.returncode == 2, (body, result)
            assert wanted in result.stderr, (body, result.stderr)

        # a tar member that leaves the private tree is refused rather than placed
        tar = io.BytesIO()
        with tarfile.open(fileobj=tar, mode="w") as inner:
            info = tarfile.TarInfo("../outside")
            info.size = len(b"escaped\n")
            info.mode = 0o644
            info.mtime = 0
            inner.addfile(info, io.BytesIO(b"escaped\n"))
        escape = eopkg(root / "escape.eopkg", payload=tar.getvalue())
        result = subprocess.run([binary, "import", escape, "--source", "eopkg", "--format",
                                 "eopkg", "--output", root / "escape-out"],
                                capture_output=True, text=True)
        assert result.returncode == 1, result
        assert "cannot place" in result.stderr, result.stderr

        # a payload that is not an archive at all is refused
        notar = eopkg(root / "notar.eopkg", payload=b"this is not a tar\n")
        result = subprocess.run([binary, "import", notar, "--source", "eopkg", "--format",
                                 "eopkg", "--output", root / "notar-out"],
                                capture_output=True, text=True)
        assert result.returncode == 1, result
        assert "cannot be read" in result.stderr, result.stderr

        # an artifact that is not there
        result = subprocess.run([binary, "import", root / "absent.eopkg", "--source", "eopkg",
                                 "--format", "eopkg", "--output", root / "absent-out"],
                                capture_output=True, text=True)
        assert result.returncode == 6, result
        assert "regular file this manager can read" in result.stderr, result.stderr

    print("eopkg fixtures passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
