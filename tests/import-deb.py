#!/usr/bin/env python3
import hashlib
import io
import lzma
import os
import pathlib
import platform
import subprocess
import sys
import tarfile
import tempfile

binary = str(pathlib.Path(sys.argv[1]).resolve())


def tar(members, mode="w:gz"):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode=mode) as archive:
        for name, body, kind in members:
            entry = tarfile.TarInfo(name)
            entry.uid, entry.gid = os.getuid(), os.getgid()
            entry.mode = 0o755 if kind == "dir" else 0o644
            if kind == "dir":
                entry.type = tarfile.DIRTYPE
            else:
                entry.size = len(body)
            archive.addfile(entry, io.BytesIO(body) if kind == "file" else None)
    return output.getvalue()


def ar(members):
    output = bytearray(b"!<arch>\n")
    for name, body in members:
        assert len(name) <= 15
        output.extend(f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{0o100644:<8}{len(body):<10}`\n".encode())
        output.extend(body)
        if len(body) % 2:
            output.extend(b"\n")
    return bytes(output)


with tempfile.TemporaryDirectory() as scratch:
    tmp = pathlib.Path(scratch)

    def run(*args, status=0):
        result = subprocess.run([binary, *map(str, args)], capture_output=True)
        assert result.returncode == status, (args, result.returncode, result.stdout, result.stderr)
        return result.stdout.decode()

    def foreign(name, control=None, data=None, order=None):
        control = control or b"Package: debfixture\nVersion: 1:2.0-3\nArchitecture: all\nDescription: fixture\n"
        data = data or [("usr/", b"", "dir"), ("usr/share/", b"", "dir"),
                        ("usr/share/debfixture", b"deb import\n", "file")]
        members = order or [("debian-binary", b"2.0\n"),
                            ("control.tar.gz", tar([("./control", control, "file")])),
                            ("data.tar.gz", tar(data))]
        path = tmp / (name + ".deb")
        path.write_bytes(ar(members))
        return path

    def convert(path, name, status=0):
        output = tmp / name
        run("import", path, "--source", "fixture", "--format", "deb", "--output", output, status=status)
        assert (output / "original").read_bytes() == path.read_bytes()
        artifacts = list(output.glob("*.holy"))
        if status:
            assert not artifacts and not (output / "conversion").exists()
        else:
            assert len(artifacts) == 1
            assert "family deb" in (output / "conversion").read_text()
            assert hashlib.sha256(path.read_bytes()).hexdigest() in (output / "conversion").read_text()
            run("verify", "local:" + str(artifacts[0]))
            run("scan", "local:" + str(artifacts[0]))
        return artifacts

    artifact = convert(foreign("basic"), "basic-output")[0]
    for codec, mode in (("plain", "w"), ("gzip", "w:gz"), ("xz", "w:xz"), ("bzip2", "w:bz2")):
        control_part = tar([("control", b"Package: debfixture\nVersion: 1\nArchitecture: all\n", "file")],
                           mode if codec != "bzip2" else "w")
        data_part = tar([("item", b"x", "file")], mode)
        extension = {"plain": "", "gzip": ".gz", "xz": ".xz", "bzip2": ".bz2"}[codec]
        convert(foreign(codec, order=[("debian-binary", b"2.0\n"),
            ("control.tar" + (extension if codec != "bzip2" else ""), control_part),
            ("data.tar" + extension, data_part)]), codec + "-output")
    lzma_data = lzma.compress(tar([("item", b"x", "file")], "w"), format=lzma.FORMAT_ALONE)
    convert(foreign("lzma", order=[("debian-binary", b"2.0\n"),
        ("control.tar", tar([("control", b"Package: debfixture\nVersion: 1\nArchitecture: all\n", "file")], "w")),
        ("data.tar.lzma", lzma_data)]), "lzma-output")
    run("fetch", "local:" + str(artifact), "--extract", "--output", tmp / "extracted")
    assert (tmp / "extracted/HOLY/foreign/deb/control").read_bytes().startswith(b"Package: debfixture")
    root = tmp / "root"
    root.mkdir()
    run("db", "init", "--root", root)
    run("cache", "stage", "local:" + str(artifact), "--root", root)
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    plan = run("db", "plan-set", digest, "--root", root).split(" sha256 ")[1].split()[0]
    run("db", "apply-set", plan, digest, "--root", root)
    run("db", "check", "--all", "--root", root)
    assert (root / "usr/share/debfixture").read_bytes() == b"deb import\n"
    run("db", "rm", digest, "--root", root)

    convert(foreign("depends", control=b"Package: debfixture\nVersion: 1\nArchitecture: all\nDepends: other (>= 2) | else\n"), "depends-output")
    dependency = next((tmp / "depends-output").glob("*.holy"))
    assert "foreign" in run("requirements", "local:" + str(dependency))
    run("solve", "local:" + str(dependency), status=6)
    sentinel = tmp / "hook-ran"
    hook = ("#!/bin/sh\necho unexpected > " + str(sentinel) + "\n").encode()
    hook_control = tar([("control", b"Package: debfixture\nVersion: 1\nArchitecture: all\n", "file"),
                        ("postinst", hook, "file")])
    hook_artifact = convert(foreign("hook", order=[("debian-binary", b"2.0\n"),
        ("control.tar.gz", hook_control), ("data.tar.gz", tar([("value", b"x", "file")]))]),
        "hook-output")[0]
    run("fetch", "local:" + str(hook_artifact), "--extract", "--output", tmp / "hook-extracted")
    assert (tmp / "hook-extracted/HOLY/foreign/deb/postinst").read_bytes() == hook
    assert not sentinel.exists()
    convert(foreign("conffiles", order=[("debian-binary", b"2.0\n"),
        ("control.tar.gz", tar([("control", b"Package: debfixture\nVersion: 1\nArchitecture: all\n", "file"),
                                ("conffiles", b"/etc/example\n", "file")])),
        ("data.tar.gz", tar([("etc/", b"", "dir"), ("etc/example", b"x", "file")]))]),
        "conffiles-output", status=3)
    convert(foreign("duplicate", data=[("usr/", b"", "dir"), ("usr/share/a", b"x", "file"),
                                      ("usr/share/a", b"y", "file")]), "duplicate-output", status=2)
    convert(foreign("traversal", data=[("../outside", b"x", "file")]), "traversal-output", status=2)
    convert(foreign("bad-version", order=[("debian-binary", b"3.0\n"),
        ("control.tar.gz", tar([("control", b"Package: x\nVersion: 1\nArchitecture: all\n", "file")])),
        ("data.tar.gz", tar([("file", b"x", "file")]))]), "bad-version-output", status=2)
    convert(foreign("bad-order", order=[("debian-binary", b"2.0\n"),
        ("data.tar.gz", tar([("file", b"x", "file")]))]), "bad-order-output", status=2)
    convert(foreign("duplicate-field", control=b"Package: debfixture\nVersion: 1\nVersion: 2\nArchitecture: all\n"),
        "duplicate-field-output", status=2)
    if platform.machine() == "x86_64":
        source = tmp / "hello.c"
        source.write_text("int main(void) { return 0; }\n")
        subprocess.run(["gcc", "-o", str(tmp / "hello"), str(source)], check=True)
        elf_data = [("usr/", b"", "dir"), ("usr/bin/", b"", "dir"),
                    ("usr/bin/hello", (tmp / "hello").read_bytes(), "file")]
        convert(foreign("wrong-arch", data=elf_data), "wrong-arch-output", status=3)
        convert(foreign("elf", control=b"Package: debfixture\nVersion: 1\nArchitecture: amd64\n",
                        data=elf_data), "elf-output")
    thin = tmp / "thin.deb"
    thin.write_bytes(b"!<thin>\n")
    convert(thin, "thin-output", status=2)
