#!/usr/bin/env python3
import base64
import gzip
import hashlib
import http.server
import io
import os
import pathlib
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading

binary = str(pathlib.Path(sys.argv[1]).resolve())


def member(items):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, content in items:
            entry = tarfile.TarInfo(name)
            entry.size = len(content)
            archive.addfile(entry, io.BytesIO(content))
    return gzip.compress(output.getvalue(), mtime=0)


def run(*args, status=0):
    result = subprocess.run([binary, *map(str, args)], capture_output=True, text=True)
    assert result.returncode == status, (args, result.returncode, result.stderr)
    return result


with tempfile.TemporaryDirectory() as scratch:
    tmp = pathlib.Path(scratch)
    serve = tmp / "serve"
    serve.mkdir()
    data = member([("usr/share/fixture", b"payload\n")])
    datahash = hashlib.sha256(data).hexdigest()
    control = member([(".PKGINFO", (
        "pkgname = fixture\npkgver = 1.2-r0\narch = x86_64\n"
        f"datahash = {datahash}\n").encode())])
    package = control + data
    (serve / "fixture-1.2-r0.apk").write_bytes(package)
    checksum = "Q1" + base64.b64encode(hashlib.sha1(control).digest()).decode()
    rows = (f"C:{checksum}\nP:fixture\nV:1.2-r0\nA:x86_64\n"
            f"S:{len(package)}\n\n").encode()
    (tmp / "APKINDEX.tar.gz").write_bytes(member([("APKINDEX", rows)]))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-days", "1", "-keyout", str(tmp / "key.pem"), "-out",
                    str(tmp / "cert.pem"), "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost"],
                   capture_output=True, check=True)

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(serve), **kwargs)

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(tmp / "cert.pem", tmp / "key.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    os.environ["NO_PROXY"] = "localhost,127.0.0.1"
    os.environ["no_proxy"] = os.environ["NO_PROXY"]
    try:
        base = f"https://localhost:{server.server_port}/"
        catalog = tmp / "catalog"
        run("apk", "index", tmp / "APKINDEX.tar.gz", "--source", "fixture",
            "--base", base, "--output", catalog)

        def fetch(output, status=0, extra=()):
            return run("apk", "fetch", "fixture", "1.2-r0", "x86_64",
                       "--catalog", catalog, "--output", tmp / output,
                       "--ca-file", tmp / "cert.pem", *extra, status=status)

        fetch("accepted", extra=("--sha256", hashlib.sha256(package).hexdigest()))
        assert (tmp / "accepted/original").read_bytes() == package
        assert "state complete" in (tmp / "accepted/selection").read_text()
        fetch("bad-hash", status=4, extra=("--sha256", "0" * 64))
        assert not (tmp / "bad-hash").exists()
        (serve / "fixture-1.2-r0.apk").write_bytes(package[:-1])
        fetch("truncated", status=4)
        assert not (tmp / "truncated").exists()
        (serve / "fixture-1.2-r0.apk").write_bytes(package)
        catalog_file = catalog / "catalog"
        record = catalog / "conversion"
        original_catalog = catalog_file.read_text()
        original_record = record.read_text()
        catalog_file.write_text(original_catalog.replace(checksum, "Q1" + "A" * 27 + "="))
        record.write_text(original_record.replace(
            hashlib.sha256(original_catalog.encode()).hexdigest(),
            hashlib.sha256(catalog_file.read_bytes()).hexdigest()))
        fetch("bad-control", status=4)
        assert not (tmp / "bad-control").exists()
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    print("APK HTTPS fetch fixtures passed")
