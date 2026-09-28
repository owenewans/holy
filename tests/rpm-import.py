#!/usr/bin/env python3
import os
import io
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


def build(root, fmt, script=""):
    spec = root / "SPECS" / "holy-rpm-fixture.spec"
    spec.write_text("""Name: holy-rpm-fixture
Version: 1.0
Release: 1
Summary: Holy RPM import fixture
License: MIT
BuildArch: noarch
Requires: sample-lib >= 1.2
%description
Local RPM import fixture.
%install
mkdir -p %{buildroot}/etc %{buildroot}/usr/share/holy-rpm-fixture
printf 'config\\n' > %{buildroot}/etc/holy-rpm-fixture.conf
printf 'payload\\n' > %{buildroot}/usr/share/holy-rpm-fixture/data
ln %{buildroot}/usr/share/holy-rpm-fixture/data %{buildroot}/usr/share/holy-rpm-fixture/data-hardlink
ln -s data %{buildroot}/usr/share/holy-rpm-fixture/data-symlink
touch %{buildroot}/usr/share/holy-rpm-fixture/empty
""" + script + """
%files
%config(noreplace) /etc/holy-rpm-fixture.conf
/usr/share/holy-rpm-fixture/data
/usr/share/holy-rpm-fixture/data-hardlink
/usr/share/holy-rpm-fixture/data-symlink
/usr/share/holy-rpm-fixture/empty
""")
    subprocess.run(["rpmbuild", "-bb", "--define", f"_rpmformat {fmt}",
                    "--define", f"_topdir {root}", str(spec)],
                   check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return root / "RPMS" / "noarch" / "holy-rpm-fixture-1.0-1.noarch.rpm"


def run(binary, package, output):
    return subprocess.run([binary, "import", str(package), "--source", "rpm-fixture",
                           "--format", "rpm", "--output", str(output)],
                          text=True, capture_output=True)


def main():
    if not shutil.which("rpmbuild"):
        print("rpmbuild required for RPM import fixture", file=sys.stderr)
        return 6
    binary = os.path.abspath(sys.argv[1])
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        (root / "SPECS").mkdir()
        package = build(root, 4)
        good = root / "good"
        result = run(binary, package, good)
        assert result.returncode == 0, result.stderr
        artifact = good / "holy-rpm-fixture--noarch--nolibc.holy"
        assert artifact.is_file() and (good / "conversion").is_file()
        contents = subprocess.run(["lz4", "-dc", str(artifact)], check=True,
                                  capture_output=True).stdout
        with tarfile.open(fileobj=io.BytesIO(contents)) as archive:
            def read(name):
                return archive.extractfile(name).read().decode()
            assert 'x-version-family rpm' in read('HOLY/meta')
            assert 'file "etc/holy-rpm-fixture.conf"' in read('HOLY/files')
            assert ' config ' in read('HOLY/files')
            assert 'data-hardlink' in read('HOLY/files')
            assert 'data-symlink' in read('HOLY/files')
            assert '"foreign" "sample-lib ge 1.2"' in read('HOLY/deps')
            assert 'rpmlib(' not in read('HOLY/deps')
            assert 'rpmlib(' in read('HOLY/origin')
            assert 'verification unverified' in read('HOLY/origin')
        truncated = root / "truncated.rpm"
        truncated.write_bytes(package.read_bytes()[:-16])
        assert run(binary, truncated, root / "truncated").returncode != 0
        package = build(root, 4, "%post\nprintf 'script\\n'\n")
        result = run(binary, package, root / "script")
        assert result.returncode == 3, result.stderr
        package = build(root, 6)
        result = run(binary, package, root / "v6")
        assert result.returncode == 0, result.stderr
        assert (root / "v6" / "holy-rpm-fixture--noarch--nolibc.holy").is_file()
        truncated.write_bytes(package.read_bytes()[:-16])
        assert run(binary, truncated, root / "truncated-v6").returncode != 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
