#!/usr/bin/env python3
"""converts WinGet manifests into native packages and installs what they carry."""
import hashlib
import pathlib
import shutil
import subprocess
import sys
import tempfile
import zipfile


binary = str(pathlib.Path(sys.argv[1]).resolve())


def call(*args, status=0):
    result = subprocess.run([binary, *map(str, args)], capture_output=True, text=True)
    assert result.returncode == status, (args, result.returncode, result.stdout, result.stderr)
    return result.stdout


def manifest(directory, name, entries, overrides="", drop=()):
    """a manifest beside the artifact it names, with the digest the manifest pins"""
    archive = directory / f"{name}_fixture.zip"
    with zipfile.ZipFile(archive, "w") as opened:
        for entry, body in entries.items():
            opened.writestr(entry, body)
    lines = [
        f"PackageIdentifier: {name}",
        "PackageVersion: 1.2.3",
        f"PackageFamilyNames: {name}_123",
        "Publisher: Fixture",
        "PublisherUrl: https://example.org/fixture",
        "InstallerType: zip",
        f"InstallerUrl: https://example.org/{archive.name}",
        f"InstallerSha256: {hashlib.sha256(archive.read_bytes()).hexdigest().upper()}",
        "InstallerSwitches:",
        "  Custom: silent",
        "InstallerScope: user",
        "ElevationRequirement: elevationRequired",
        "ReleaseDate: 2024-05-01",
        "InstallLocationRequired: true",
        "ManifestType: installer",
        "ManifestVersion: 1.6.0",
        "UpdateBehavior: install",
        "Tags:",
        "  - fixture",
    ]
    if "dependencies" not in drop:
        lines += [
            "PackageDependencies:",
            "  - Package: Fixture.Runtime",
            "    Architecture: x64",
            "    MinimumOSVersion: 10.0.17763.0",
        ]
    if overrides:
        lines.append(overrides)
    (directory / f"{name}.yaml").write_text("\n".join(lines) + "\n")
    return archive


def main():
    with tempfile.TemporaryDirectory() as scratch:
        root = pathlib.Path(scratch)
        catalog = root / "catalog"
        catalog.mkdir()
        manifest(catalog, "Fixture.Tool", {
            "tool/tool.exe": "MZ a program for another operating system\n",
            "tool/README.txt": "the tool reads its configuration\n",
        })

        out = root / "converted"
        report = call("import", catalog / "Fixture.Tool.yaml", "--source", "winget", "--format",
                      "winget", "--output", out, status=3)
        artifact = out / "Fixture.Tool--noarch--nolibc.holy"
        assert "imported Fixture.Tool--noarch--nolibc.holy artifact" in report, report
        assert artifact.is_file(), sorted(p.name for p in out.iterdir())
        call("verify", "local:" + str(artifact))
        identity = call("info", "local:" + str(artifact))
        assert "name Fixture.Tool\n" in identity and "version 1.2.3\n" in identity, identity
        assert "arch noarch\n" in identity and "libc nolibc\n" in identity, identity

        listing = call("manifest", "local:" + str(artifact))
        for path in ("usr/lib/holy/private/Fixture.Tool/tool/tool.exe",
                     "usr/lib/holy/private/Fixture.Tool/tool/README.txt"):
            assert path in listing, path

        # the manifest travels whole beside the package
        assert (out / "original").read_bytes() == (catalog / "Fixture.Tool.yaml").read_bytes()
        package = (out / "package").read_text()
        assert "format holy-winget-package-1\n" in package
        assert "status review-required\n" in package
        assert "artifact https://example.org/Fixture.Tool_fixture.zip" in package
        assert "verified against the digest the manifest pins" in package
        assert "artifact-placed the payload carries 2 files" in package
        # a WinGet digest is written in upper case and still verified
        assert (catalog / "Fixture.Tool.yaml").read_text().count(hashlib.sha256(
            (catalog / "Fixture.Tool_fixture.zip").read_bytes()).hexdigest().upper()) == 1
        # nothing runs the artifact and no runtime is promised
        assert "nothing runs the artifact" in package
        assert "a package cannot promise a Wine" in package
        # the installer switches, the Windows keys and the catalog keys are counted
        assert "installer 8 PowerShell installer keys are dropped" in package
        assert "integration 3 Windows integration keys are dropped" in package
        assert "update 1 keys that check or rewrite the upstream version" in package
        assert "belong to a\nWinGet catalog" in package
        # every key of this manifest is read, counted or carried, so nothing is unknown
        assert "unknown" not in package, package
        # the dependency block names a package of the same catalog
        requirements = call("requirements", "local:" + str(artifact))
        assert 'require "winget-depend-0" "Fixture.Tool" "package" "Fixture.Runtime"' in \
            requirements, requirements
        assert "depends 1 packages of the same catalog" in package

        # the payload installs as ordinary files and nothing executes
        target = root / "target"
        (target / "usr/bin").mkdir(parents=True)
        call("db", "init", "--root", target)
        call("cache", "stage", "local:" + str(artifact), "--root", target)
        runtime = root / "trees/runtime"
        (runtime / "HOLY").mkdir(parents=True)
        (runtime / "DATA/usr/lib/fixture").mkdir(parents=True)
        (runtime / "DATA/usr/lib/fixture/note").write_text("fixture runtime\n")
        (runtime / "HOLY/meta").write_text(
            "format holy-package-1\nname Fixture.Runtime\nversion 1\nrelease 1\nos linux\n"
            "arch noarch\nlibc nolibc\n")
        for field in ("deps", "provides", "hooks", "origin", "transform"):
            (runtime / "HOLY" / field).write_text("")
        call("manifest", "generate", runtime, "--output", root / "runtime-files")
        (runtime / "HOLY/files").write_text((root / "runtime-files").read_text())
        call("pack", runtime, "--output", root / "runtime.holy")
        call("cache", "stage", "local:" + str(root / "runtime.holy"), "--root", target)
        digests = [hashlib.sha256(artifact.read_bytes()).hexdigest(),
                   hashlib.sha256((root / "runtime.holy").read_bytes()).hexdigest()]
        plan = call("db", "plan-set", *digests, "--root", target)
        plan_sha = [line.split()[10] for line in plan.splitlines()
                    if line.startswith("plan-set ")][0]
        applied = call("db", "apply-set", plan_sha, *digests, "--root", target)
        assert "artifacts 2" in applied, applied
        assert (target / "usr/lib/holy/private/Fixture.Tool/tool/tool.exe").read_text() == \
            "MZ a program for another operating system\n"
        assert not (target / "usr/bin/Fixture.Tool").exists()
        call("db", "check", "--all", "--root", target)

        # a digest the manifest does not pin is refused, in either case
        for value, wanted in (("0" * 64, "the manifest pins"),
                              (hashlib.sha256(b"other").hexdigest(), "has the digest")):
            case = root / ("case-" + wanted.split()[0])
            case.mkdir()
            manifest(case, "Fixture.Bad", {"bad/bad.exe": "MZ\n"})
            body = (case / "Fixture.Bad.yaml").read_text()
            for line in body.splitlines():
                if line.startswith("InstallerSha256:"):
                    body = body.replace(line, f"InstallerSha256: {value}")
            (case / "Fixture.Bad.yaml").write_text(body)
            result = subprocess.run([binary, "import", case / "Fixture.Bad.yaml", "--source",
                                     "winget", "--format", "winget", "--output",
                                     root / (case.name + "-out")],
                                    capture_output=True, text=True)
            assert result.returncode == 6, result
            assert wanted in result.stderr, result.stderr
            assert not list((root / (case.name + "-out")).glob("*.holy"))

        # a manifest without an identifier, a version, an address or a digest is refused
        for field in ("PackageIdentifier", "PackageVersion", "InstallerUrl", "InstallerSha256"):
            case = root / ("missing-" + field)
            case.mkdir()
            manifest(case, "Fixture.Missing", {"m/m.exe": "MZ\n"})
            body = (case / "Fixture.Missing.yaml").read_text()
            (case / "Fixture.Missing.yaml").write_text("\n".join(
                line for line in body.splitlines() if not line.startswith(field + ":")) + "\n")
            result = subprocess.run([binary, "import", case / "Fixture.Missing.yaml", "--source",
                                     "winget", "--format", "winget", "--output",
                                     root / (case.name + "-out")],
                                    capture_output=True, text=True)
            assert result.returncode == 2, (field, result)
            assert "needs" in result.stderr, (field, result.stderr)

        # an artifact that is not beside the manifest is a missing capability
        absent = root / "absent"
        absent.mkdir()
        manifest(absent, "Fixture.Absent", {"a/a.exe": "MZ\n"})
        (absent / "Fixture.Absent_fixture.zip").unlink()
        result = subprocess.run([binary, "import", absent / "Fixture.Absent.yaml", "--source",
                                 "winget", "--format", "winget", "--output", root / "absent-out"],
                                capture_output=True, text=True)
        assert result.returncode == 6, result
        assert "is not beside the manifest" in result.stderr, result.stderr

        # an artifact with an escaping path is refused rather than placed
        escape = root / "escape"
        escape.mkdir()
        manifest(escape, "Fixture.Escape", {"../outside.exe": "MZ\n"})
        result = subprocess.run([binary, "import", escape / "Fixture.Escape.yaml", "--source",
                                 "winget", "--format", "winget", "--output", root / "escape-out"],
                                capture_output=True, text=True)
        assert result.returncode == 3, result
        assert "cannot place" in result.stderr, result.stderr

        # a manifest without a dependency block names none, and nothing is invented
        plain = root / "plain"
        plain.mkdir()
        manifest(plain, "Fixture.Plain", {"p/p.exe": "MZ\n"}, drop=("dependencies",))
        call("import", plain / "Fixture.Plain.yaml", "--source", "winget", "--format", "winget",
             "--output", root / "plain-out", status=3)
        plain_requirements = call("requirements", "local:" + str(
            root / "plain-out/Fixture.Plain--noarch--nolibc.holy"))
        assert plain_requirements.strip() == "requirements 0", plain_requirements

        # text that is not a manifest is refused rather than half read
        broken = root / "broken"
        broken.mkdir()
        (broken / "Fixture.Broken.yaml").write_text("# a comment\n")
        result = subprocess.run([binary, "import", broken / "Fixture.Broken.yaml", "--source",
                                 "winget", "--format", "winget", "--output", root / "broken-out"],
                                capture_output=True, text=True)
        assert result.returncode == 2, result
        assert "reads no other form" in result.stderr, result.stderr
        result = subprocess.run([binary, "import", root / "absent.yaml", "--source", "winget",
                                 "--format", "winget", "--output", root / "absent2-out"],
                                capture_output=True, text=True)
        assert result.returncode == 6, result
        assert "manifest unavailable" in result.stderr, result.stderr

    print("winget manifest fixtures passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
