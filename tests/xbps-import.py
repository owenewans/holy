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


def archive(path, *, digest=None, omit=False, extra=None, traversal=False, link=False):
    body = b"#!/bin/sh\nexit 0\n"
    actual = hashlib.sha256(body).hexdigest()
    props = {
        "pkgname": "fixture", "pkgver": "fixture-1.2_3", "version": "1.2_3",
        "architecture": "noarch", "run_depends": ["glibc>=2.40_1"],
        "shlib-requires": [], "provides": ["fixture-1.2_3"],
    }
    files = {"files": [{"file": "/usr/bin/fixture", "sha256": digest or actual,
                        "size": len(body)}]}
    if link:
        files["links"] = [{"file": "/usr/bin/fixture-link", "target": "fixture"}]
    if extra:
        files.update(extra)
    with tarfile.open(path, "w:gz") as tar:
        for name, data, mode in (
            ("./props.plist", plistlib.dumps(props), 0o644),
            ("./files.plist", plistlib.dumps(files), 0o644),
            ("./usr/bin/fixture", body, 0o755),
        ):
            if omit and name.endswith("fixture"):
                continue
            if traversal and name.endswith("fixture"):
                name = "./usr/../outside"
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), mode
            tar.addfile(info, io.BytesIO(data))
        if link:
            info = tarfile.TarInfo("./usr/bin/fixture-link")
            info.type = tarfile.SYMTYPE
            info.linkname = "fixture"
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
    print("XBPS import and rejection fixtures passed")


if __name__ == "__main__":
    main()
