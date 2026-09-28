#!/usr/bin/env python3
import hashlib
import io
import os
import plistlib
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


def archive(path, *, digest=None, omit=False, extra=None, traversal=False, link=False,
            package="fixture", version="1.2_3", depends=None):
    body = b"XBPS fixture data\n"
    actual = hashlib.sha256(body).hexdigest()
    props = {
        "pkgname": package, "pkgver": f"{package}-{version}", "version": version,
        "architecture": "noarch", "run_depends": depends if depends is not None else ["glibc>=2.40_1"],
        "shlib-requires": [], "provides": [f"{package}-{version}"],
    }
    files = {"files": [{"file": f"/usr/bin/{package}", "sha256": digest or actual,
                        "size": len(body)}]}
    if link:
        files["links"] = [{"file": f"/usr/bin/{package}-link", "target": package}]
    if extra:
        files.update(extra)
    with tarfile.open(path, "w:gz") as tar:
        for name, data, mode in (
            ("./props.plist", plistlib.dumps(props), 0o644),
            ("./files.plist", plistlib.dumps(files), 0o644),
            (f"./usr/bin/{package}", body, 0o644),
        ):
            if omit and name.endswith("fixture"):
                continue
            if traversal and name.endswith("fixture"):
                name = "./usr/../outside"
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), mode
            tar.addfile(info, io.BytesIO(data))
        if link:
            info = tarfile.TarInfo(f"./usr/bin/{package}-link")
            info.type = tarfile.SYMTYPE
            info.linkname = package
            tar.addfile(info)


def run(binary, archive_path, output):
    return subprocess.run([binary, "import", str(archive_path), "--source", "void",
                           "--format", "xbps", "--output", str(output)],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def main():
    binary = os.path.abspath(sys.argv[1])
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        archive_path = root / "fixture.xbps"
        archive(archive_path)
        result = run(binary, archive_path, root / "good")
        assert result.returncode == 0, result.stderr
        assert (root / "good" / "conversion").is_file()
        assert len(list((root / "good").glob("*.holy"))) == 1
        artifact = next((root / "good").glob("*.holy"))
        requirements = subprocess.run([binary, "requirements", "local:" + str(artifact)],
                                      capture_output=True, text=True, check=True).stdout
        assert '"package" "glibc" "any" "any" "ge" "2.40_1"' in requirements
        archive(archive_path, link=True)
        result = run(binary, archive_path, root / "linked")
        assert result.returncode == 0, result.stderr
        for index, changes in enumerate((
            {"digest": "0" * 64},
            {"omit": True},
            {"extra": {"conf_files": [{"file": "/etc/fixture"}]}},
            {"traversal": True},
        )):
            archive(archive_path, **changes)
            result = run(binary, archive_path, root / f"bad-{index}")
            assert result.returncode != 0, (index, result.stdout)
            assert not (root / f"bad-{index}" / "conversion").exists()
        packages = []
        for label, name, version, depends in (
            ("consumer", "consumer", "1.0_1", ["provider>=1.0_2"]),
            ("older", "provider", "1.0_1", []),
            ("newer", "provider", "1.0_2", []),
        ):
            archive(archive_path, package=name, version=version, depends=depends)
            result = run(binary, archive_path, root / label)
            assert result.returncode == 0, result.stderr
            packages.append(next((root / label).glob("*.holy")))
        def solve(*items):
            return subprocess.run([binary, "solve", *("local:" + str(item) for item in items)],
                                  capture_output=True, text=True)
        assert solve(packages[0], packages[1]).returncode == 4
        result = solve(packages[0], packages[2])
        assert result.returncode == 0, result.stderr
        assert hashlib.sha256(packages[2].read_bytes()).hexdigest() in result.stdout
        archive(archive_path, package="consumer", version="1.0_1",
                depends=["provider>=1.0<2.0"])
        result = run(binary, archive_path, root / "range")
        assert result.returncode == 0, result.stderr
        ranged = next((root / "range").glob("*.holy"))
        result = solve(ranged, packages[2])
        assert result.returncode == 3, (result.returncode, result.stderr)
    print("XBPS import and rejection fixtures passed")


if __name__ == "__main__":
    main()
