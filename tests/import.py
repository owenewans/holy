#!/usr/bin/env python3
import hashlib
import io
import os
import pathlib
import shlex
import subprocess
import sys
import tarfile
import tempfile

binary = str(pathlib.Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory() as scratch:
    tmp = pathlib.Path(scratch)
    uid, gid = os.getuid(), os.getgid()

    def run(*args, status=0):
        result = subprocess.run([binary, *map(str, args)], capture_output=True)
        assert result.returncode == status, (args, result.returncode, result.stdout, result.stderr)
        return result.stdout.decode()

    def package(name, members, extra="", mode="w:gz", arch="any", package_name="sample", version="1:2.0-3"):
        path = tmp / (name + ".pkg")
        metadata = ("pkgname = " + package_name + "\npkgver = " + version + "\narch = " + arch + "\n" + extra).encode()
        with tarfile.open(path, mode) as archive:
            all_members = [(".PKGINFO", metadata, "file", None, 0o644)] + members
            for member, data, kind, target, permissions in all_members:
                entry = tarfile.TarInfo(member)
                entry.uid, entry.gid = uid, gid
                entry.uname, entry.gname = "foreign-owner", "foreign-group"
                entry.mode = permissions
                if kind == "dir":
                    entry.type = tarfile.DIRTYPE
                elif kind == "symlink":
                    entry.type, entry.linkname = tarfile.SYMTYPE, target
                elif kind == "hardlink":
                    entry.type, entry.linkname = tarfile.LNKTYPE, target
                else:
                    entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data) if kind == "file" else None)
        return path

    def convert(path, name, status=0):
        output = tmp / name
        text = run("import", path, "--source", "fixture", "--format", "pacman", "--output", output, status=status)
        assert (output / "original").read_bytes() == path.read_bytes()
        artifacts = list(output.glob("*.holy"))
        if status:
            assert not artifacts, (status, artifacts)
            assert not (output / "conversion").exists()
        else:
            records = [shlex.split(line) for line in (output / "conversion").read_text().splitlines()]
            assert ["state", "complete"] in records
            assert ["original-sha256", hashlib.sha256(path.read_bytes()).hexdigest()] in records
            outputs = [row for row in records if row[0] == "output"]
            assert len(outputs) == len(artifacts)
            for row in outputs:
                assert hashlib.sha256((output / row[1]).read_bytes()).hexdigest() == row[2]
            for artifact in artifacts:
                run("verify", "local:" + str(artifact))
                run("scan", "local:" + str(artifact))
        return output, artifacts, text

    payload = [
        ("usr/", b"", "dir", None, 0o755),
        ("usr/share/", b"", "dir", None, 0o755),
        ("usr/share/value", b"native import\n", "file", None, 0o644),
    ]
    original = package("data", payload, "license = MIT\noptdepend = optional: extra functionality\n")
    output, artifacts, text = convert(original, "data-output")
    assert len(artifacts) == 1 and "arch noarch libc nolibc" in text
    artifact = artifacts[0]
    run("import", original, "--source", "fixture", "--format", "pacman", "--output", output, status=1)
    root = tmp / "root"
    root.mkdir()
    run("db", "init", "--root", root)
    run("cache", "stage", "local:" + str(artifact), "--root", root)
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    plan = run("db", "plan-set", digest, "--root", root).split(" sha256 ")[1].split()[0]
    run("db", "apply-set", plan, digest, "--root", root)
    run("db", "check", "--all", "--root", root)
    assert (root / "usr/share/value").read_bytes() == b"native import\n"
    run("db", "rm", digest, "--root", root)
    assert not (root / "usr/share/value").exists()

    for codec in ("w", "w:gz", "w:bz2", "w:xz"):
        foreign = package("codec-" + codec.replace(":", "-"), payload, mode=codec)
        convert(foreign, "out-" + codec.replace(":", "-"),
                status=6 if codec in os.environ.get("HOLY_TEST_MISSING_CODECS", "").split(",") else 0)

    for name, members in [
        ("duplicate", payload + [payload[-1]]),
        ("traversal", [("../outside", b"bad", "file", None, 0o644)]),
        ("absolute", [("/outside", b"bad", "file", None, 0o644)]),
        ("symlink-parent", [("usr", b"", "symlink", "/tmp", 0o777), payload[-1]]),
        ("symlink-escape", payload + [("usr/share/link", b"", "symlink", "../../../outside", 0o777)]),
        ("missing-hardlink", [("alias", b"", "hardlink", "absent", 0o644)]),
        ("metadata-link", [(".PKGINFO", b"", "symlink", "/etc/passwd", 0o777)]),
    ]:
        convert(package(name, members), name + "-output", status=2)
    assert not (tmp / "outside").exists()
    convert(package("duplicate-key", payload, "pkgver = 9-1\n"), "duplicate-key-output", status=2)
    convert(package("backup", payload, "backup = usr/share/value\n"), "backup-output", status=3)
    convert(package("future-type", payload, "xdata = pkgtype=future\n"), "future-type-output", status=3)
    convert(package("unknown-executable", [("tool", b"not an ELF", "file", None, 0o755)]), "unknown-output", status=3)

    sentinel = tmp / "executed"
    hook = ("touch " + str(sentinel) + "\n").encode()
    _, artifacts, _ = convert(package("hook", payload + [(".INSTALL", hook, "file", None, 0o644)]), "hook-output")
    assert not sentinel.exists()
    assert len(artifacts) == 1
    run("fetch", "local:" + str(artifacts[0]), "--extract", "--output", tmp / "hook-extracted")
    assert (tmp / "hook-extracted/HOLY/foreign/pacman/INSTALL").read_bytes() == hook

    _, artifacts, _ = convert(package("unknown-field", payload, "future_semantic = preserve\nconflict = other<2\n"), "unknown-field-output")
    assert "foreign" in run("requirements", "local:" + str(artifacts[0]))
    run("solve", "local:" + str(artifacts[0]), status=3)
    _, artifacts, _ = convert(package("unknown-xdata", payload,
        "xdata = pkgtype=pkg\nxdata = future=semantic\n"), "unknown-xdata-output")
    assert "foreign" in run("requirements", "local:" + str(artifacts[0]))
    run("solve", "local:" + str(artifacts[0]), status=3)
    _, artifacts, _ = convert(package("links", payload + [
        ("usr/share/hard", b"", "hardlink", "usr/share/value", 0o644),
        ("usr/share/link", b"", "symlink", "value", 0o777),
    ]), "links-output")
    assert "hardlink" in run("manifest", "local:" + str(artifacts[0]))

    source = tmp / "hello.c"
    source.write_text('#include <stdio.h>\nint main(void) { return puts("import probe") < 0; }\n')
    subprocess.run(["gcc", "-o", str(tmp / "hello"), str(source)], check=True)
    assembly = tmp / "exit.s"
    assembly.write_text(".global _start\n_start:\n mov $1, %eax\n xor %ebx, %ebx\n int $0x80\n")
    subprocess.run(["as", "--32", "-o", str(tmp / "exit.o"), str(assembly)], check=True)
    subprocess.run(["ld", "-m", "elf_i386", "-o", str(tmp / "exit32"), str(tmp / "exit.o")], check=True)
    mixed = payload + [
        ("usr/bin/", b"", "dir", None, 0o755),
        ("usr/bin/hello", (tmp / "hello").read_bytes(), "file", None, 0o755),
        ("usr/bin/exit32", (tmp / "exit32").read_bytes(), "file", None, 0o755),
    ]
    _, artifacts, text = convert(package("mixed", mixed, arch="x86_64"), "mixed-output")
    assert len(artifacts) == 3, text
    assert "arch x86_64 libc glibc" in text and "arch x86 libc nolibc" in text and "arch noarch libc nolibc" in text
    for artifact in artifacts:
        assert "split-" in run("requirements", "local:" + str(artifact))
    _, consumers, _ = convert(package("version-consumer", payload, "depend = provider>=2:1.0-2\n"), "version-consumer-output")
    _, older, _ = convert(package("version-old", payload, package_name="provider", version="2:1.0-1"), "version-old-output")
    _, newer, _ = convert(package("version-new", payload, package_name="provider", version="2:1.0-3"), "version-new-output")
    result = run("solve", "local:" + str(consumers[0]), "local:" + str(older[0]), "local:" + str(newer[0]))
    assert "selected " + hashlib.sha256(newer[0].read_bytes()).hexdigest() in result
    assert "selected " + hashlib.sha256(older[0].read_bytes()).hexdigest() not in result
    run("solve", "local:" + str(consumers[0]), "local:" + str(older[0]), status=4)
    _, virtual, _ = convert(package("version-virtual", payload, "provides = provider=2:1.0-3\n",
        package_name="implementation", version="0.1-1"), "version-virtual-output")
    result = run("solve", "local:" + str(consumers[0]), "local:" + str(virtual[0]))
    assert "selected " + hashlib.sha256(virtual[0].read_bytes()).hexdigest() in result
    assert "name implementation\n" in run("info", "local:" + str(virtual[0]))
    print("pacman import fixtures passed")
