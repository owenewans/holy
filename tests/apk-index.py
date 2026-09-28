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
            b"p:cmd:beta=2.0-r1 so:libbeta.so.1 so:libbeta.so.10\n\n")
    signed = convert(index("signed.tar.gz", rows, True), "signed")
    assert run("apk", "search", "alpha", "--catalog", signed) == "alpha 1.2-r0 x86_64\n"
    info = run("apk", "info", "alpha", "--catalog", signed)
    assert "depend beta>=1\n" in info and "checksum Q1hashone=\n" in info
    assert "file-coverage unavailable" in (signed / "conversion").read_text()
    assert run("apk", "providers", "soname:libbeta.so.1", "--catalog", signed) == (
        "beta 2.0-r1 x86_64 index-hint\n")
    assert "sonames-sha256 " in (signed / "conversion").read_text()
    run("apk", "providers", "soname:libbeta.so.2", "--catalog", signed, status=4)
    run("apk", "providers", "file:/usr/lib/libbeta.so.1", "--catalog", signed, status=2)
    duplicate_provider = convert(index("duplicate-provider.tar.gz", rows + (
        b"C:Q1hashthree=\nP:gamma\nV:1.0-r0\nA:x86_64\nS:90\n"
        b"p:so:libbeta.so.1\n\n")), "duplicate-provider")
    run("apk", "fetch-provider", "soname:libbeta.so.1", "x86_64",
        "--catalog", duplicate_provider, "--output", tmp / "ambiguous-provider", status=3)
    assert not (tmp / "ambiguous-provider").exists()
    run("apk", "fetch-provider", "soname:libbeta.so.1", "x86",
        "--catalog", duplicate_provider, "--output", tmp / "wrong-arch-provider", status=4)
    assert not (tmp / "wrong-arch-provider").exists()
    run("apk", "info", "missing", "--catalog", signed, status=4)
    convert(index("unsigned.tar.gz", rows), "unsigned")

    private_key = tmp / "fixture.key"
    public_key = tmp / "fixture.rsa.pub"
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                    "rsa_keygen_bits:2048", "-out", str(private_key)],
                   capture_output=True, check=True)
    subprocess.run(["openssl", "pkey", "-in", str(private_key), "-pubout",
                    "-out", str(public_key)], capture_output=True, check=True)
    payload = tar([("APKINDEX", rows)])
    payload_path = tmp / "index-payload.gz"
    payload_path.write_bytes(payload)
    signature = subprocess.run(["openssl", "dgst", "-sha256", "-sign",
                                str(private_key), str(payload_path)],
                               capture_output=True, check=True).stdout
    signed_index = tmp / "verified.tar.gz"
    signed_index.write_bytes(tar([(".SIGN.RSA256.fixture.rsa.pub", signature)]) + payload)
    assert "verified APKINDEX rsa-sha256" in run("apk", "verify-index",
                                                  signed_index, "--public-key", public_key)
    run("apk", "verify-index", tmp / "unsigned.tar.gz", "--public-key",
        public_key, status=4)
    changed = bytearray(signed_index.read_bytes())
    changed[-13] ^= 1
    (tmp / "changed.tar.gz").write_bytes(changed)
    run("apk", "verify-index", tmp / "changed.tar.gz", "--public-key",
        public_key, status=4)
    wrong_dir = tmp / "wrong"
    wrong_dir.mkdir()
    wrong_key = wrong_dir / public_key.name
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                    "rsa_keygen_bits:2048", "-out", str(wrong_dir / "private.key")],
                   capture_output=True, check=True)
    subprocess.run(["openssl", "pkey", "-in", str(wrong_dir / "private.key"),
                    "-pubout", "-out", str(wrong_key)], capture_output=True, check=True)
    run("apk", "verify-index", signed_index, "--public-key", wrong_key, status=4)

    saved_sonames = (signed / "sonames").read_bytes()
    edited_sonames = bytearray(saved_sonames)
    edited_sonames[-3] ^= 1
    (signed / "sonames").write_bytes(edited_sonames)
    run("apk", "providers", "soname:libbeta.so.1", "--catalog", signed, status=2)
    (signed / "sonames").write_bytes(saved_sonames)
    edited = bytearray((signed / "catalog").read_bytes())
    edited[-2] = ord("2")
    (signed / "catalog").write_bytes(edited)
    run("apk", "search", "alpha", "--catalog", signed, status=2)
    run("apk", "providers", "soname:libbeta.so.1", "--catalog", signed, status=2)

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
