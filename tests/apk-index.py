#!/usr/bin/env python3
import gzip
import io
import pathlib
import subprocess
import sys
import tarfile
import tempfile

binary = str(pathlib.Path(sys.argv[1]).resolve())

with tempfile.TemporaryDirectory() as scratch:
    tmp = pathlib.Path(scratch)

    def tar(members):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for name, data in members:
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
        return gzip.compress(stream.getvalue(), mtime=0)

    def run(*args, status=0):
        result = subprocess.run([binary, *map(str, args)], capture_output=True, text=True)
        assert result.returncode == status, (args, result.returncode,
                                             result.stdout, result.stderr)
        return result.stdout

    def index(name, rows, signed=False, member="APKINDEX"):
        source = tmp / name
        prefix = tar([(".SIGN.RSA.fixture.rsa.pub", b"not verified")]) if signed else b""
        source.write_bytes(prefix + tar([("DESCRIPTION", b"fixture\n"), (member, rows)]))
        return source

    def convert(source, directory, status=0):
        output = tmp / directory
        run("apk", "index", source, "--source", "alpine-main", "--base",
            "https://example.org/alpine/main/x86_64/", "--output", output,
            status=status)
        assert (output / "original").read_bytes() == source.read_bytes()
        if status:
            assert not (output / "conversion").exists()
        else:
            assert "state complete" in (output / "conversion").read_text()
        return output

    rows = (b"C:Q1hashone=\nP:alpha\nV:1.2-r0\nA:x86_64\nS:100\nD:beta>=1\n"
            b"\nC:Q1hashtwo=\nP:beta\nV:2.0-r1\nA:x86_64\nS:200\n"
            b"p:cmd:beta=2.0-r1\n\n")
    signed = convert(index("signed.tar.gz", rows, True), "signed")
    assert run("apk", "search", "alpha", "--catalog", signed) == "alpha 1.2-r0 x86_64\n"
    info = run("apk", "info", "alpha", "--catalog", signed)
    assert "depend beta>=1\n" in info and "checksum Q1hashone=\n" in info
    assert "file-coverage unavailable" in (signed / "conversion").read_text()
    run("apk", "info", "missing", "--catalog", signed, status=4)
    convert(index("unsigned.tar.gz", rows), "unsigned")

    edited = bytearray((signed / "catalog").read_bytes())
    edited[-2] = ord("2")
    (signed / "catalog").write_bytes(edited)
    run("apk", "search", "alpha", "--catalog", signed, status=2)

    convert(index("duplicate.tar.gz", rows + rows), "duplicate", status=2)
    convert(index("missing.tar.gz", b"P:alpha\nV:1\nA:x86_64\nS:1\n"),
            "missing", status=2)
    convert(index("traversal.tar.gz", rows, member="../APKINDEX"),
            "traversal", status=2)
    truncated = index("truncated.tar.gz", rows)
    truncated.write_bytes(truncated.read_bytes()[:-8])
    convert(truncated, "truncated", status=2)
    run("apk", "index", tmp / "unsigned.tar.gz", "--source", "alpine-main",
        "--base", "https://user:pass@example.org/alpine/", "--output",
        tmp / "bad-url", status=2)
    assert not (tmp / "bad-url").exists()
    print("APK index fixtures passed")
