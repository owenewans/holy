#!/usr/bin/env python3
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


def tar(items):
    content = io.BytesIO()
    with tarfile.open(fileobj=content, mode="w:gz") as archive:
        for name, body in items:
            entry = tarfile.TarInfo(name)
            entry.size = len(body)
            archive.addfile(entry, io.BytesIO(body))
    return content.getvalue()


def deb(package_name="fixture"):
    control = (f"Package: {package_name}\nVersion: 1:2.0-3\nArchitecture: all\n"
               "Description: fixture\n").encode()
    members = [("debian-binary", b"2.0\n"),
               ("control.tar.gz", tar([("control", control)])),
               ("data.tar.gz", tar([("usr/share/fixture", b"apt fixture\n")]))]
    result = bytearray(b"!<arch>\n")
    for name, body in members:
        result.extend(f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{0o100644:<8}{len(body):<10}`\n".encode())
        result.extend(body)
        if len(body) & 1:
            result.extend(b"\n")
    return bytes(result)


def run(*args, status=0):
    process = subprocess.run([binary, *map(str, args)], capture_output=True, text=True)
    assert process.returncode == status, (args, process.returncode, process.stdout, process.stderr)
    return process.stdout


with tempfile.TemporaryDirectory() as scratch:
    tmp = pathlib.Path(scratch)
    serve = tmp / "serve"
    package_path = serve / "pool/main/f/fixture/fixture_2.0_all.deb"
    package_path.parent.mkdir(parents=True)
    package = deb()
    package_path.write_bytes(package)
    digest = hashlib.sha256(package).hexdigest()
    row = ("Package: fixture\nVersion: 1:2.0-3\nArchitecture: all\n"
           "Filename: pool/main/f/fixture/fixture_2.0_all.deb\n"
           f"Size: {len(package)}\nSHA256: {digest}\n"
           "Depends: first (>= 2),\n second | third\nDescription: fixture\n long text\n\n").encode()
    packages = tmp / "Packages.gz"
    packages.write_bytes(gzip.compress(row, mtime=0))
    bad_rows = [
        row + row,
        row.replace(b"pool/main/f/fixture/fixture_2.0_all.deb", b"../outside.deb"),
        row.replace(b"SHA256: " + digest.encode() + b"\n", b""),
        row.replace(b"Size: ", b"Size: 0"),
        row.replace(b"Filename: pool", b"Filename: ../pool"),
    ]

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

    class Server(http.server.ThreadingHTTPServer):
        def handle_error(self, *_args):
            pass

    server = Server(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(tmp / "cert.pem", tmp / "key.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    os.environ["NO_PROXY"] = "localhost,127.0.0.1"
    os.environ["no_proxy"] = os.environ["NO_PROXY"]
    try:
        base = f"https://localhost:{server.server_port}/"

        def index(name, body, status=0):
            source = tmp / (name + ".gz")
            source.write_bytes(body)
            output = tmp / name
            run("apt", "index", source, "--sha256", hashlib.sha256(body).hexdigest(),
                "--source", "debian", "--base", base, "--output", output, status=status)
            return output

        catalog = index("catalog", packages.read_bytes())
        assert (catalog / "original").read_bytes() == packages.read_bytes()
        assert run("apt", "search", "fixture", "--catalog", catalog) == "fixture 1:2.0-3 all\n"
        info = run("apt", "info", "fixture", "--catalog", catalog)
        assert 'depends "first (>= 2), second | third"' in info
        assert f"sha256 {digest}\n" in info
        run("apt", "info", "missing", "--catalog", catalog, status=4)
        for n, body in enumerate(bad_rows):
            index("invalid-" + str(n), gzip.compress(body, mtime=0), status=2)
        run("apt", "index", packages, "--sha256", "0" * 64,
            "--source", "debian", "--base", base,
            "--output", tmp / "wrong-pin", status=4)
        original = (catalog / "original").read_bytes()
        (catalog / "original").write_bytes(original + b"bad")
        run("apt", "search", "fixture", "--catalog", catalog, status=2)
        (catalog / "original").write_bytes(original)

        fetched = tmp / "fetched"
        run("apt", "fetch", "fixture", "1:2.0-3", "all", "--catalog", catalog,
            "--output", fetched, "--ca-file", tmp / "cert.pem", "--import")
        assert (fetched / "original").read_bytes() == package
        assert "imported yes\nstate complete\n" in (fetched / "selection").read_text()
        native = list((fetched / "converted").glob("*.holy"))
        assert len(native) == 1
        run("verify", "local:" + str(native[0]))
        run("apt", "fetch", "fixture", "1:2.0-3", "all", "--catalog", catalog,
            "--output", tmp / "no-ca", status=6)

        wrong_hash = row.replace(digest.encode(), b"0" * 64)
        wrong = index("wrong-hash", gzip.compress(wrong_hash, mtime=0))
        run("apt", "fetch", "fixture", "1:2.0-3", "all", "--catalog", wrong,
            "--output", tmp / "mismatch", "--ca-file", tmp / "cert.pem", status=4)
        assert not (tmp / "mismatch/selection").exists()

        other = deb("other")
        package_path.write_bytes(other)
        other_hash = hashlib.sha256(other).hexdigest()
        changed = row.replace(digest.encode(), other_hash.encode()).replace(
            f"Size: {len(package)}".encode(), f"Size: {len(other)}".encode())
        wrong_identity = index("wrong-identity", gzip.compress(changed, mtime=0))
        run("apt", "fetch", "fixture", "1:2.0-3", "all", "--catalog", wrong_identity,
            "--output", tmp / "bad-identity", "--ca-file", tmp / "cert.pem",
            "--import", status=4)
        assert not (tmp / "bad-identity/selection").exists()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

print("apt index/fetch/import fixtures passed")
