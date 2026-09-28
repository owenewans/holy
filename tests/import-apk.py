#!/usr/bin/env python3
import gzip
import hashlib
import io
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

    def tar(members):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, body, kind in members:
                entry = tarfile.TarInfo(name)
                entry.uid, entry.gid = os.getuid(), os.getgid()
                entry.mode = 0o755 if kind == "dir" else 0o644
                if kind == "dir":
                    entry.type = tarfile.DIRTYPE
                else:
                    entry.size = len(body)
                archive.addfile(entry, io.BytesIO(body) if kind == "file" else None)
        return gzip.compress(data.getvalue(), mtime=0)

    def package(name, payload=None, fields=b"", signed=False, bad_hash=False, script=False,
                pkgname=b"example", pkgver=b"1.2-r0"):
        if payload is None:
            payload = [("usr/", b"", "dir"),
                       ("usr/share/", b"", "dir"),
                       ("usr/share/example", b"apk import\n", "file")]
        data = tar(payload)
        digest = hashlib.sha256(data).hexdigest()
        if bad_hash:
            digest = "0" * 64
        info = (b"pkgname = " + pkgname + b"\npkgver = " + pkgver + b"\narch = noarch\n"
                + b"datahash = " + digest.encode() + b"\n" + fields)
        control_members = [(".PKGINFO", info, "file")]
        if script:
            control_members.append((".post-install", b"exit 0\n", "file"))
        control = tar(control_members)
        signature = tar([(".SIGN.RSA.fixture.rsa.pub", b"untrusted", "file")]) if signed else b""
        path = tmp / name
        path.write_bytes(signature + control + data)
        return path

    def convert(source, name, status=0):
        output = tmp / name
        run("import", source, "--source", "alpine", "--format", "apk", "--output", output,
            status=status)
        assert (output / "original").read_bytes() == source.read_bytes()
        artifacts = list(output.glob("*.holy"))
        if status:
            assert not artifacts and not (output / "conversion").exists()
            return None
        assert len(artifacts) == 1
        assert "family apk" in (output / "conversion").read_text()
        run("verify", "local:" + str(artifacts[0]))
        run("scan", "local:" + str(artifacts[0]))
        return artifacts[0]

    artifact = convert(package("example.apk"), "basic")
    info = run("info", "local:" + str(artifact))
    assert "name example" in info and "version 1.2-r0" in info
    extracted = tmp / "extracted"
    run("fetch", "local:" + str(artifact), "--extract", "--output", extracted)
    assert (extracted / "DATA/usr/share/example").read_bytes() == b"apk import\n"
    assert (extracted / "HOLY/foreign/apk/.PKGINFO").exists()
    root = tmp / "root"
    root.mkdir()
    run("db", "init", "--root", root)
    run("cache", "stage", "local:" + str(artifact), "--root", root)
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    plan = run("db", "plan-set", digest, "--root", root).split(" sha256 ")[1].split()[0]
    run("db", "apply-set", plan, digest, "--root", root)
    run("db", "check", "--all", "--root", root)
    assert (root / "usr/share/example").read_bytes() == b"apk import\n"
    run("db", "rm", digest, "--root", root)

    signed = convert(package("signed.apk", signed=True, script=True,
                             fields=(b"depend = helper so:libc.musl-x86_64.so.1 "
                                     b"cmd:helper helper>=2\nprovides = virtual-helper\n")),
                     "signed")
    run("fetch", "local:" + str(signed), "--extract", "--output", tmp / "signed-extract")
    assert (tmp / "signed-extract/HOLY/foreign/apk/.SIGN.RSA.fixture.rsa.pub").exists()
    assert "foreign-script apk" in (tmp / "signed-extract/HOLY/hooks").read_text()
    requirements = run("requirements", "local:" + str(signed))
    assert '"package" "helper"' in requirements
    assert '"soname" "libc.musl-x86_64.so.1"' in requirements
    assert '"command" "helper"' in requirements
    assert '"package" "helper" "any" "any" "ge" "2"' in requirements
    assert '"foreign" "virtual-helper"' in requirements
    run("solve", "local:" + str(signed), status=6)

    old = convert(package("library-old.apk", pkgname=b"library", pkgver=b"1.2-r0"), "library-old")
    new = convert(package("library-new.apk", pkgname=b"library", pkgver=b"1.2-r2"), "library-new")
    app = convert(package("versioned.apk", pkgname=b"versioned",
                          fields=b"depend = library>=1.2-r1\n"), "versioned")
    solution = run("solve", "local:" + str(app), "local:" + str(old), "local:" + str(new))
    assert hashlib.sha256(new.read_bytes()).hexdigest() in solution
    assert hashlib.sha256(old.read_bytes()).hexdigest() not in solution

    convert(package("bad-hash.apk", bad_hash=True), "bad-hash", status=2)
    convert(package("traversal.apk", payload=[("../outside", b"bad", "file")]),
            "traversal", status=2)
    assert not (tmp / "outside").exists()
    truncated = package("truncated.apk")
    truncated.write_bytes(truncated.read_bytes()[:-8])
    convert(truncated, "truncated", status=2)
    extra = package("extra.apk")
    extra.write_bytes(extra.read_bytes() + tar([("more", b"bad", "file")]))
    convert(extra, "extra", status=2)
    print("APK v2 import fixtures passed")
