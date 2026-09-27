#!/usr/bin/env python3
import bz2
import gzip
import hashlib
import io
import lzma
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile

if len(sys.argv) != 2:
    print("usage: static-import.py STATIC-HOLYPKG", file=sys.stderr)
    sys.exit(2)
binary = pathlib.Path(sys.argv[1]).resolve()
commands = {}
for name in ("doas", "unshare", "mount", "chroot", "sh", "zstd", "lz4", "readelf"):
    commands[name] = shutil.which(name)
    if not commands[name]:
        print("required test tool unavailable: " + name, file=sys.stderr)
        sys.exit(6)
if subprocess.run([commands["doas"], "-n", commands["unshare"], "--mount", "--pid", "--fork", "true"]).returncode:
    sys.exit(6)
headers = subprocess.run([commands["readelf"], "-l", binary], capture_output=True, check=True).stdout
assert b"INTERP" not in headers, "static client required"

with tempfile.TemporaryDirectory(prefix="holy-static-import-") as scratch:
    root = pathlib.Path(scratch)
    for name in ("usr/bin", "input", "tmp", "proc"):
        (root / name).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(binary, root / "usr/bin/holypkg")
    (root / "usr/bin/holypkg").chmod(0o755)
    identity = str(os.getuid()) + ":" + str(os.getgid())

    def guest(*args, status=0):
        command = [commands["doas"], "-n", commands["unshare"], "--mount", "--pid", "--fork",
                   "--propagation", "private", "--", commands["sh"], "-c",
                   '"$2" -t proc -o nosuid,nodev,noexec proc "$1/proc" || exit 6; '
                   'root=$1; chroot=$3; identity=$4; shift 4; '
                   'exec "$chroot" --userspec="$identity" "$root" /usr/bin/holypkg "$@"',
                   "holy-static-import", str(root), commands["mount"], commands["chroot"], identity,
                   *map(str, args)]
        result = subprocess.run(command, capture_output=True, timeout=30)
        assert result.returncode == status, (args, result.returncode, result.stdout, result.stderr)
        return result.stdout

    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data in ((".PKGINFO", b"pkgname = codec-fixture\npkgver = 1-1\narch = any\n"),
                           ("value", b"decoded without dynamic libc or helper programs\n")):
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            entry.uid, entry.gid = os.getuid(), os.getgid()
            entry.mode = 0o644
            archive.addfile(entry, io.BytesIO(data))
    raw = stream.getvalue()
    variants = {"tar": raw, "gzip": gzip.compress(raw), "bzip2": bz2.compress(raw), "xz": lzma.compress(raw)}
    for codec in ("zstd", "lz4"):
        variants[codec] = subprocess.run([commands[codec], "-q", "-c"], input=raw,
                                         capture_output=True, check=True).stdout

    guest("db", "init", "--root", "/")
    for codec, data in variants.items():
        (root / "input" / codec).write_bytes(data)
        guest("import", "/input/" + codec, "--source", "fixture", "--format", "pacman",
              "--output", "/converted-" + codec)
        output = root / ("converted-" + codec)
        assert (output / "original").read_bytes() == data
        receipt = (output / "conversion").read_text()
        assert "original-sha256 " + hashlib.sha256(data).hexdigest() in receipt
        assert "state complete\n" in receipt
        artifact = next(output.glob("*.holy"))
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        assert digest in receipt
        guest("cache", "stage", "local:/" + str(artifact.relative_to(root)), "--root", "/")
        plan = guest("db", "plan-set", digest, "--root", "/").decode().split(" sha256 ")[1].split()[0]
        guest("db", "apply-set", plan, digest, "--root", "/")
        guest("db", "check", "--all", "--root", "/")
        assert (root / "value").read_bytes() == b"decoded without dynamic libc or helper programs\n"
        guest("db", "rm", digest, "--root", "/")
        assert not (root / "value").exists()
        if codec != "tar":
            (root / "input" / (codec + "-truncated")).write_bytes(data[:len(data) // 2])
            guest("import", "/input/" + codec + "-truncated", "--source", "fixture", "--format", "pacman",
                  "--output", "/bad-" + codec, status=2)
            assert not (root / ("bad-" + codec) / "conversion").exists()
        print("static import/install/remove passed codec=" + codec, flush=True)
    for name in ("lib", "lib64", "usr/lib", "usr/lib64", "bin"):
        assert not (root / name).exists()
    assert list((root / "usr/bin").iterdir()) == [root / "usr/bin/holypkg"]
    print("static import chroot passed holypkg=" + hashlib.sha256(binary.read_bytes()).hexdigest())
