#!/usr/bin/env python3
"""converts Scoop manifests into native packages and installs what they carry."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile


binary = str(Path(sys.argv[1]).resolve())


def call(*args, status=0):
    result = subprocess.run([binary, *map(str, args)], capture_output=True, text=True)
    assert result.returncode == status, (args, result.returncode, result.stdout, result.stderr)
    return result.stdout


def manifest(directory, name, entries, overrides=None):
    """a manifest beside the artifact it names, with the digest the manifest pins"""
    archive = directory / f"{name}-fixture.zip"
    with zipfile.ZipFile(archive, "w") as opened:
        for entry, body in entries.items():
            opened.writestr(entry, body)
    body = {
        "version": "2.4.1",
        "description": "A Scoop conversion fixture",
        "homepage": "https://example.org/fixture",
        "license": "MIT",
        "url": f"https://example.org/{archive.name}",
        "hash": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "depends": "holyruntime/1.0 other/2.3",
        "notes": ["reads its configuration from the working directory"],
        "checkver": "https://example.org/fixture/version",
        "autoupdate": {"url": "https://example.org/fixture-{{version}}.zip"},
        "env_add_path": ["."],
        "env_set": {"FIXTURE_HOME": "$dir"},
        "persist": ["config"],
        "installer": {"script": ["$dir\\fixture.exe", "Write-Host done"]},
    }
    if overrides:
        body.update(overrides)
    (directory / f"{name}.json").write_text(json.dumps(body, indent=2))
    return archive


def main():
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        bucket = root / "bucket"
        bucket.mkdir()
        manifest(bucket, "holyscoop", {
            "holyscoop-2.4.1/holyscoop.exe": "MZ a program for another operating system\n",
            "holyscoop-2.4.1/README.txt": "holyscoop reads its configuration\n",
        }, {"extract_dir": "holyscoop", "bin": "holyscoop.exe"})

        # the artifact is verified against the digest the manifest pins, and carried
        out = root / "converted"
        report = call("import", bucket / "holyscoop.json", "--source", "bucket", "--format",
                      "scoop", "--output", out, status=3)
        artifact = out / "holyscoop--noarch--nolibc.holy"
        assert "imported holyscoop--noarch--nolibc.holy artifact" in report, report
        assert artifact.is_file(), sorted(p.name for p in out.iterdir())
        call("verify", "local:" + str(artifact))
        call("info", "local:" + str(artifact))

        identity = call("info", "local:" + str(artifact))
        assert "name holyscoop\n" in identity and "version 2.4.1\n" in identity, identity
        assert "arch noarch\n" in identity and "libc nolibc\n" in identity, identity

        manifest_text = call("manifest", "local:" + str(artifact))
        for path in ("usr/lib/holy/private/holyscoop/holyscoop/holyscoop.exe",
                     "usr/lib/holy/private/holyscoop/holyscoop/README.txt"):
            assert path in manifest_text, path

        # the manifest travels whole, so an installed copy can be compared with it
        assert (out / "original").read_bytes() == (bucket / "holyscoop.json").read_bytes()
        package = (out / "package").read_text()
        assert "format holy-scoop-package-1\n" in package
        assert "status review-required\n" in package
        assert "artifact https://example.org/holyscoop-fixture.zip" in package
        assert "verified against the digest the manifest pins" in package
        assert "artifact-placed the payload carries 2 files" in package
        assert "extract-dir holyscoop is the directory the manifest places" in package
        assert "program holyscoop.exe is in the payload" in package
        # nothing runs, and no runtime this manager does not provide is promised
        assert "nothing runs the artifact" in package
        assert "a package cannot promise a Wine" in package
        assert "so no such requirement is recorded" in package
        # the installer and the Windows integration are dropped with a count
        assert "installer 1 PowerShell installer keys are dropped" in package
        assert "integration 3 Windows integration keys are dropped" in package
        assert "update 2 keys that check or rewrite the upstream version" in package
        # a bucket dependency is a requirement, since a target has to find it
        requirements = call("requirements", "local:" + str(artifact))
        assert 'require "scoop-depend-0" "holyscoop" "package" "holyruntime"' in requirements
        assert 'require "scoop-depend-1" "holyscoop" "package" "other"' in requirements
        assert "depends 2 apps of the same bucket" in package

        # the payload installs as ordinary files and nothing executes
        target = root / "target"
        (target / "usr/bin").mkdir(parents=True)
        call("db", "init", "--root", target)
        call("cache", "stage", "local:" + str(artifact), "--root", target)
        # the two bucket apps have no provider here, so the set names what is missing
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        refused = subprocess.run([binary, "db", "plan-set", digest, "--root", str(target)],
                                 capture_output=True, text=True)
        assert refused.returncode == 4, refused
        assert "unresolved requirement scoop-depend-0" in refused.stderr, refused.stderr
        assert not (target / "usr/lib").exists()

        # a manifest whose apps are absent is refused, and a fake provider is not
        # invented to satisfy them
        runtimes = root / "runtimes"
        for name in ("holyruntime", "other"):
            tree = runtimes / name
            (tree / "HOLY").mkdir(parents=True)
            (tree / "DATA/usr/lib" / name).mkdir(parents=True)
            (tree / "DATA/usr/lib" / name / "note").write_text(f"{name} fixture\n")
            (tree / "HOLY/meta").write_text(
                "format holy-package-1\nname %s\nversion 1\nrelease 1\nos linux\n"
                "arch noarch\nlibc nolibc\n" % name)
            for field in ("deps", "provides", "hooks", "origin", "transform"):
                (tree / "HOLY" / field).write_text("")
            # the generator reads the tree it walks, so its output lands beside it
            call("manifest", "generate", tree, "--output", root / (name + "-files"))
            (tree / "HOLY/files").write_text((root / (name + "-files")).read_text())
            call("pack", tree, "--output", root / (name + ".holy"))
            call("cache", "stage", "local:" + str(root / (name + ".holy")), "--root", target)
        digests = [digest]
        for name in ("holyruntime", "other"):
            digests.append(hashlib.sha256((root / (name + ".holy")).read_bytes()).hexdigest())
        plan = call("db", "plan-set", *digests, "--root", target)
        plan_sha = [line.split()[10] for line in plan.splitlines()
                    if line.startswith("plan-set ")][0]
        applied = call("db", "apply-set", plan_sha, *digests, "--root", target)
        assert "artifacts 3" in applied, applied
        program = (target / "usr/lib/holy/private/holyscoop/holyscoop/holyscoop.exe")
        assert program.read_text() == "MZ a program for another operating system\n"
        assert (target / "usr/lib/holyruntime/note").read_text() == "holyruntime fixture\n"
        # nothing in the payload is executable on this system, and no launcher exists
        assert not (target / "usr/bin/holyscoop").exists()
        assert not program.stat().st_mode & 0o111

        # an artifact whose digest the manifest does not pin is refused
        wrong = root / "wrong"
        wrong.mkdir()
        manifest(wrong, "holyscoopbad", {"bad/bad.exe": "MZ\n"})
        body = json.loads((wrong / "holyscoopbad.json").read_text())
        body["hash"] = "0" * 64
        (wrong / "holyscoopbad.json").write_text(json.dumps(body))
        result = subprocess.run([binary, "import", wrong / "holyscoopbad.json", "--source",
                                 "bucket", "--format", "scoop", "--output", root / "wrong-out"],
                                capture_output=True, text=True)
        assert result.returncode == 6, result
        assert "the manifest pins" in result.stderr, result.stderr
        assert not list((root / "wrong-out").glob("*.holy"))

        # an artifact that is not beside the manifest is a missing capability
        absent = root / "absent"
        absent.mkdir()
        manifest(absent, "holyscoopsparse", {"x/y.exe": "MZ\n"})
        (absent / "holyscoopsparse-fixture.zip").unlink()
        result = subprocess.run([binary, "import", absent / "holyscoopsparse.json", "--source",
                                 "bucket", "--format", "scoop", "--output", root / "absent-out"],
                                capture_output=True, text=True)
        assert result.returncode == 6, result
        assert "is not beside the manifest" in result.stderr, result.stderr

        # a manifest with no digest, no url or no version is refused
        for field, value in (("hash", None), ("url", None), ("version", None)):
            case = root / ("case-" + field)
            case.mkdir()
            manifest(case, "holyscoopcase", {"c/c.exe": "MZ\n"})
            body = json.loads((case / "holyscoopcase.json").read_text())
            if value is None:
                del body[field]
            (case / "holyscoopcase.json").write_text(json.dumps(body))
            result = subprocess.run([binary, "import", case / "holyscoopcase.json", "--source",
                                     "bucket", "--format", "scoop", "--output",
                                     root / (case.name + "-out")],
                                    capture_output=True, text=True)
            assert result.returncode == 2, (field, result)
            assert "holyscoopcase" not in result.stderr

        # an artifact with an escaping path is refused rather than placed
        escape = root / "escape"
        escape.mkdir()
        manifest(escape, "holyscoopescape", {"../outside.exe": "MZ\n"})
        result = subprocess.run([binary, "import", escape / "holyscoopescape.json", "--source",
                                 "bucket", "--format", "scoop", "--output",
                                 root / "escape-out"], capture_output=True, text=True)
        assert result.returncode == 3, result
        assert "cannot place" in result.stderr, result.stderr

        # an artifact that is a plain file travels as one payload entry
        plain = root / "plain"
        plain.mkdir()
        archive = plain / "holyscoopplain-fixture.bin"
        archive.write_bytes(b"MZ a single file artifact\n")
        (plain / "holyscoopplain.json").write_text(json.dumps({
            "version": "1.0",
            "url": f"https://example.org/{archive.name}",
            "hash": hashlib.sha256(archive.read_bytes()).hexdigest(),
        }, indent=2))
        call("import", plain / "holyscoopplain.json", "--source", "bucket", "--format", "scoop",
             "--output", root / "plain-out", status=3)
        plain_manifest = call("manifest", "local:" + str(root /
                                                          "plain-out/holyscoopplain--noarch--nolibc.holy"))
        assert "usr/lib/holy/private/holyscoopplain/holyscoopplain-fixture.bin" in plain_manifest

        # a manifest that is not JSON, or not an object, is refused
        broken = root / "broken"
        broken.mkdir()
        (broken / "holyscoopbroken.json").write_text("id: holyscoopbroken\n")
        result = subprocess.run([binary, "import", broken / "holyscoopbroken.json", "--source",
                                 "bucket", "--format", "scoop", "--output", root / "broken-out"],
                                capture_output=True, text=True)
        assert result.returncode == 2, result
        assert "reads no other form" in result.stderr, result.stderr
        result = subprocess.run([binary, "import", root / "absent.json", "--source", "bucket",
                                 "--format", "scoop", "--output", root / "absent2-out"],
                                capture_output=True, text=True)
        assert result.returncode == 6, result
        assert "manifest unavailable" in result.stderr, result.stderr

    print("scoop manifest fixtures passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
