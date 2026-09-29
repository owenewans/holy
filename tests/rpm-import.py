#!/usr/bin/env python3
import os
import io
import hashlib
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


def build_provider(root, version, epoch=0):
    spec = root / "SPECS" / "holy-rpm-provider.spec"
    spec.write_text(f"""Name: holy-rpm-provider
Version: {version}
Release: 1
Epoch: {epoch}
Summary: Holy RPM provider fixture
License: MIT
BuildArch: noarch
Provides: sample-lib = {str(epoch) + ':' if epoch else ''}{version}-1
%description
Local RPM provider fixture.
%install
mkdir -p %{{buildroot}}/usr/share/holy-rpm-provider
printf 'provider\\n' > %{{buildroot}}/usr/share/holy-rpm-provider/data
%files
/usr/share/holy-rpm-provider/data
""")
    subprocess.run(["rpmbuild", "-bb", "--define", "_rpmformat 4",
                    "--define", f"_topdir {root}", str(spec)],
                   check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return root / "RPMS" / "noarch" / f"holy-rpm-provider-{version}-1.noarch.rpm"


def run(binary, package, output):
    return subprocess.run([binary, "import", str(package), "--source", "rpm-fixture",
                           "--format", "rpm", "--output", str(output)],
                          text=True, capture_output=True)


def main():
    for tool in ("rpmbuild", "lz4"):
        if not shutil.which(tool):
            print(f"{tool} required for RPM import fixture", file=sys.stderr)
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
            assert '"package" "sample-lib" "any" "any" "ge" "1.2"' in read('HOLY/deps')
            assert 'rpmlib(' not in read('HOLY/deps')
            assert 'rpmlib(' in read('HOLY/origin')
            assert 'verification unverified' in read('HOLY/origin')
        providers = []
        for version in ("1.1", "1.3"):
            provider_rpm = build_provider(root, version)
            target = root / f"provider-{version}"
            result = run(binary, provider_rpm, target)
            assert result.returncode == 0, result.stderr
            providers.append(target / "holy-rpm-provider--noarch--nolibc.holy")
        solve = lambda *items: subprocess.run([binary, "solve", *["local:" + str(item)
                                  for item in items]], text=True, capture_output=True)
        assert solve(artifact, providers[0]).returncode == 4
        result = solve(artifact, *providers)
        assert result.returncode == 0, result.stderr
        assert 'selected ' + hashlib.sha256(providers[1].read_bytes()).hexdigest() in result.stdout
        epoch_rpm = build_provider(root, "0.1", epoch=1)
        epoch_output = root / "provider-epoch"
        result = run(binary, epoch_rpm, epoch_output)
        assert result.returncode == 0, result.stderr
        epoch_package = epoch_output / "holy-rpm-provider--noarch--nolibc.holy"
        assert solve(artifact, epoch_package).returncode == 0
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
