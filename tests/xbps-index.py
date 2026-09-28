#!/usr/bin/env python3
import hashlib
import http.server
import io
import os
import pathlib
import plistlib
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading


binary = str(pathlib.Path(sys.argv[1]).resolve())


def run(*args, status=0):
    result = subprocess.run([binary, *map(str, args)], capture_output=True, text=True)
    assert result.returncode == status, (args, result.returncode, result.stderr)
    return result.stdout


def tar_bytes(entries, mode="w"):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode=mode) as archive:
        for name, data in entries:
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
    return buffer.getvalue()


def repodata(package, *, package_hash=None, package_name="fixture", broken=False):
    digest = package_hash or hashlib.sha256(package).hexdigest()
    row = {"architecture": "x86_64", "pkgver": "fixture-1.0_1",
           "filename-sha256": digest, "filename-size": len(package),
           "run_depends": [], "shlib-requires": []}
    index = b"<broken" if broken else plistlib.dumps({package_name: row})
    data = tar_bytes((("index.plist", index),
                      ("index-meta.plist", plistlib.dumps({"signature-type": "rsa"})),
                      ("stage.plist", b"")))
    return subprocess.run(["zstd", "-q", "-c"], input=data,
                          capture_output=True, check=True).stdout


def main():
    with tempfile.TemporaryDirectory() as scratch:
        root = pathlib.Path(scratch)
        serve = root / "serve"
        serve.mkdir()
        body = b"fixture data\n"
        props = plistlib.dumps({"pkgname": "fixture", "pkgver": "fixture-1.0_1",
                                "version": "1.0_1", "architecture": "x86_64"})
        files = plistlib.dumps({"files": [{"file": "/usr/share/fixture",
                                           "sha256": hashlib.sha256(body).hexdigest(),
                                           "size": len(body)}]})
        package = tar_bytes((("./props.plist", props), ("./files.plist", files),
                             ("./usr/share/fixture", body)), "w:gz")
        package_hash = hashlib.sha256(package).hexdigest()
        (serve / "fixture-1.0_1.x86_64.xbps").write_bytes(package)
        index = repodata(package)
        index_hash = hashlib.sha256(index).hexdigest()
        (serve / "x86_64-repodata").write_bytes(index)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-days", "1", "-keyout", str(root / "key.pem"),
                        "-out", str(root / "cert.pem"), "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=DNS:localhost"],
                       capture_output=True, check=True)

        class Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(serve), **kwargs)

            def log_message(self, *_args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / "cert.pem", root / "key.pem")
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        os.environ["NO_PROXY"] = "localhost,127.0.0.1"
        os.environ["no_proxy"] = os.environ["NO_PROXY"]
        try:
            base = f"https://localhost:{server.server_port}/"
            catalog = root / "catalog"
            run("xbps", "index", serve / "x86_64-repodata", "--sha256", index_hash,
                "--source", "fixture", "--base", base, "--output", catalog)
            assert "fixture 1.0_1 x86_64" in run("xbps", "search", "fi", "--catalog", catalog)
            assert package_hash in run("xbps", "info", "fixture", "--catalog", catalog)
            run("xbps", "index", serve / "x86_64-repodata", "--sha256", "0" * 64,
                "--source", "fixture", "--base", base, "--output", root / "wrong-pin", status=1)
            synced = root / "synced"
            run("xbps", "sync", base, "x86_64", "--sha256", index_hash,
                "--source", "fixture", "--output", synced, "--ca-file", root / "cert.pem")
            assert package_hash in run("xbps", "info", "fixture", "--catalog", synced)
            fetched = root / "fetched"
            run("xbps", "fetch", "fixture", "1.0_1", "x86_64", "--catalog", synced,
                "--output", fetched, "--ca-file", root / "cert.pem")
            assert (fetched / package_hash).read_bytes() == package
            converted = root / "converted"
            run("import", fetched / package_hash, "--source", "fixture", "--format", "xbps",
                "--output", converted)
            assert len(list(converted.glob("*.holy"))) == 1
            (catalog / "catalog").write_bytes(b"tampered")
            run("xbps", "info", "fixture", "--catalog", catalog, status=6)
            malformed = root / "malformed-repodata"
            malformed.write_bytes(repodata(package, broken=True))
            run("xbps", "index", malformed, "--sha256", hashlib.sha256(malformed.read_bytes()).hexdigest(),
                "--source", "fixture", "--base", base, "--output", root / "bad-index", status=2)
            wrong = root / "wrong-repodata"
            wrong.write_bytes(repodata(package, package_hash="0" * 64))
            wrong_catalog = root / "wrong-catalog"
            run("xbps", "index", wrong, "--sha256", hashlib.sha256(wrong.read_bytes()).hexdigest(),
                "--source", "fixture", "--base", base, "--output", wrong_catalog)
            run("xbps", "fetch", "fixture", "1.0_1", "x86_64", "--catalog", wrong_catalog,
                "--output", root / "wrong-fetch", "--ca-file", root / "cert.pem", status=4)
            alien_props = plistlib.dumps({"pkgname": "other", "pkgver": "other-1.0_1",
                                          "version": "1.0_1", "architecture": "x86_64"})
            alien_package = tar_bytes((("./props.plist", alien_props),
                                       ("./files.plist", files),
                                       ("./usr/share/fixture", body)), "w:gz")
            (serve / "fixture-1.0_1.x86_64.xbps").write_bytes(alien_package)
            alien_index = root / "alien-repodata"
            alien_index.write_bytes(repodata(alien_package))
            alien_catalog = root / "alien-catalog"
            run("xbps", "index", alien_index, "--sha256", hashlib.sha256(alien_index.read_bytes()).hexdigest(),
                "--source", "fixture", "--base", base, "--output", alien_catalog)
            run("xbps", "fetch", "fixture", "1.0_1", "x86_64", "--catalog", alien_catalog,
                "--output", root / "alien-fetch", "--ca-file", root / "cert.pem", status=4)
        finally:
            server.shutdown()
            thread.join()
    print("XBPS index, HTTPS sync, fetch and rejection fixtures passed")


if __name__ == "__main__":
    main()
