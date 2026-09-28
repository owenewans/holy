#!/usr/bin/env python3
import hashlib
import io
import lzma
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile

binary = str(pathlib.Path(sys.argv[1]).resolve())

with tempfile.TemporaryDirectory() as scratch:
    tmp = pathlib.Path(scratch)

    def run(*args, status=0):
        result = subprocess.run([binary, *map(str, args)], capture_output=True)
        assert result.returncode == status, (args, result.returncode,
                                             result.stdout, result.stderr)
        return result.stdout.decode()

    def package(name, members, mode="w:xz"):
        path = tmp / name
        with tarfile.open(path, mode) as archive:
            for member, body, kind, target, permissions in members:
                entry = tarfile.TarInfo(member)
                entry.uid, entry.gid = os.getuid(), os.getgid()
                entry.mode = permissions
                if kind == "dir":
                    entry.type = tarfile.DIRTYPE
                elif kind == "symlink":
                    entry.type, entry.linkname = tarfile.SYMTYPE, target
                elif kind == "hardlink":
                    entry.type, entry.linkname = tarfile.LNKTYPE, target
                else:
                    entry.size = len(body)
                archive.addfile(entry, io.BytesIO(body) if kind == "file" else None)
        return path

    base = [
        ("install/", b"", "dir", None, 0o755),
        ("install/slack-desc", b"fixture-one: test package\n", "file", None, 0o644),
        ("usr/", b"", "dir", None, 0o755),
        ("usr/share/", b"", "dir", None, 0o755),
        ("usr/share/fixture-one", b"slackware import\n", "file", None, 0o644),
    ]

    def convert(path, directory, status=0):
        output = tmp / directory
        run("import", path, "--source", "slack", "--format", "slackware",
            "--output", output, status=status)
        assert (output / "original").read_bytes() == path.read_bytes()
        artifacts = list(output.glob("*.holy"))
        if status:
            assert not artifacts and not (output / "conversion").exists()
        else:
            assert artifacts and "family slackware" in (output / "conversion").read_text()
            for artifact in artifacts:
                run("verify", "local:" + str(artifact))
                run("scan", "local:" + str(artifact))
        return artifacts

    original = package("fixture-one-1.0-noarch-2_slack15.0.txz", base)
    artifact = convert(original, "basic")[0]
    convert(package("fixture-one-1.0-noarch-1.tgz", base, "w:gz"), "gzip")
    convert(package("fixture-one-1.0-noarch-1.tbz", base, "w:bz2"), "bzip2")
    convert(package("misnamed-1.0-noarch-1.txz", base, "w:gz"), "misnamed", status=2)
    plain = package("plain-1.0-noarch-1.txz", base, "w")
    legacy = tmp / "fixture-one-1.0-noarch-1.tlz"
    legacy.write_bytes(lzma.compress(plain.read_bytes(), format=lzma.FORMAT_ALONE))
    convert(legacy, "lzma")
    info = run("info", "local:" + str(artifact))
    assert "name fixture-one" in info and "release 2_slack15.0" in info
    run("fetch", "local:" + str(artifact), "--extract", "--output", tmp / "extracted")
    assert (tmp / "extracted/HOLY/foreign/slackware/slack-desc").read_bytes().startswith(b"fixture-one:")
    assert not (tmp / "extracted/DATA/install").exists()
    root = tmp / "root"
    root.mkdir()
    run("db", "init", "--root", root)
    run("cache", "stage", "local:" + str(artifact), "--root", root)
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    plan = run("db", "plan-set", digest, "--root", root).split(" sha256 ")[1].split()[0]
    run("db", "apply-set", plan, digest, "--root", root)
    run("db", "check", "--all", "--root", root)
    assert (root / "usr/share/fixture-one").read_bytes() == b"slackware import\n"
    run("db", "rm", digest, "--root", root)

    marker = tmp / "executed"
    hook = f"touch {marker}\n".encode()
    scripted = package("scripted-2.0-noarch-1.tgz", base +
                       [("install/doinst.sh", hook, "file", None, 0o755)], "w:gz")
    script_artifact = convert(scripted, "scripted")[0]
    assert not marker.exists()
    run("fetch", "local:" + str(script_artifact), "--extract", "--output", tmp / "scripted-extract")
    assert (tmp / "scripted-extract/HOLY/foreign/slackware/doinst.sh").read_bytes() == hook
    assert "foreign-script slackware" in (tmp / "scripted-extract/HOLY/hooks").read_text()

    linked = package("linked-1.0-noarch-1.txz", base +
                     [("usr/share/alias", b"", "hardlink", "usr/share/fixture-one", 0o644)])
    link_artifact = convert(linked, "linked")[0]
    assert "slackware-hardlink" in run("manifest", "local:" + str(link_artifact))

    required = package("required-1-noarch-1.txz", base +
                       [("install/slack-required", b"other>=2\n", "file", None, 0o644)])
    required_artifact = convert(required, "required")[0]
    assert "foreign" in run("requirements", "local:" + str(required_artifact))
    run("solve", "local:" + str(required_artifact), status=3)

    for name, members in [
        ("duplicate", base + [base[-1]]),
        ("traversal", base + [("../outside", b"bad", "file", None, 0o644)]),
        ("symlink-escape", base + [("usr/share/link", b"", "symlink", "../../../outside", 0o777)]),
        ("metadata-link", base + [("install/doinst.sh", b"", "symlink", "/etc/passwd", 0o777)]),
    ]:
        convert(package(f"{name}-1-noarch-1.txz", members), name, status=2)
    assert not (tmp / "outside").exists()
    convert(package("bad-1-arm-1.txz", base), "unknown-arch", status=3)
    convert(package("bad-1-noarch-1.txz", base +
                    [("usr/bin/tool", b"not an ELF", "file", None, 0o755)]),
            "unknown-abi", status=3)
    source = tmp / "hello.c"
    source.write_text('#include <stdio.h>\nint main(void) { return puts("hello") < 0; }\n')
    subprocess.run(["gcc", "-o", str(tmp / "hello"), str(source)], check=True)
    assembly = tmp / "exit.s"
    assembly.write_text(".global _start\n_start:\n mov $1, %eax\n xor %ebx, %ebx\n int $0x80\n")
    subprocess.run(["as", "--32", "-o", str(tmp / "exit.o"), str(assembly)], check=True)
    subprocess.run(["ld", "-m", "elf_i386", "-o", str(tmp / "exit32"), str(tmp / "exit.o")], check=True)
    mixed = base + [
        ("usr/bin/", b"", "dir", None, 0o755),
        ("usr/bin/hello", (tmp / "hello").read_bytes(), "file", None, 0o755),
        ("usr/bin/exit32", (tmp / "exit32").read_bytes(), "file", None, 0o755),
    ]
    artifacts = convert(package("mixed-1.0-x86_64-1.txz", mixed), "mixed")
    assert len(artifacts) == 3
    infos = [run("info", "local:" + str(artifact)) for artifact in artifacts]
    assert any("arch x86_64\nlibc glibc" in info for info in infos)
    assert any("arch x86\nlibc nolibc" in info for info in infos)
    assert any("arch noarch\nlibc nolibc" in info for info in infos)
    convert(package("mixed-1.0-noarch-1.txz", mixed), "false-noarch", status=3)
    invalid = package("invalid.txz", base)
    run("import", invalid, "--source", "slack", "--format", "slackware",
        "--output", tmp / "invalid-name", status=2)
    print("Slackware import fixtures passed")
