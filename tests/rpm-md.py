#!/usr/bin/env python3
import gzip
import hashlib
import http.server
import importlib.util
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading


binary = str(Path(sys.argv[1]).resolve())


def run(*args, status=0):
    result = subprocess.run([binary, *map(str, args)], text=True, capture_output=True)
    assert result.returncode == status, (args, result.returncode, result.stderr)
    return result.stdout


def sha(data):
    return hashlib.sha256(data).hexdigest()


def metadata(package, href):
    primary = (f'''<?xml version="1.0"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" packages="1">
  <package type="rpm"><name>holy-rpm-fixture</name><arch>noarch</arch>
    <version epoch="0" ver="1.0" rel="1"/>
    <checksum type="sha256" pkgid="YES">{sha(package)}</checksum>
    <size package="{len(package)}"/>
    <location href="{href}"/>
  </package>
</metadata>''').encode()
    packed = gzip.compress(primary, mtime=0)
    repomd = (f'''<?xml version="1.0"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary">
  <checksum type="sha256">{sha(packed)}</checksum>
  <location href="repodata/primary.xml.gz"/>
</data></repomd>''').encode()
    return repomd, packed


def main():
    for tool in ("rpmbuild", "openssl"):
        if not shutil.which(tool):
            print(f"{tool} required for rpm-md fixture", file=sys.stderr)
            return 6
    spec = importlib.util.spec_from_file_location("rpm_import", "tests/rpm-import.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        (root / "SPECS").mkdir()
        package = module.build(root, 4).read_bytes()
        serve = root / "serve"
        (serve / "repodata").mkdir(parents=True)
        (serve / "Packages").mkdir()
        filename = "holy-rpm-fixture-1.0-1.noarch.rpm"
        href = "Packages/" + filename
        (serve / href).write_bytes(package)
        repomd, primary = metadata(package, href)
        (serve / "repodata/repomd.xml").write_bytes(repomd)
        (serve / "repodata/primary.xml.gz").write_bytes(primary)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-days", "1", "-keyout", str(root / "key.pem"),
                        "-out", str(root / "cert.pem"), "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=DNS:localhost"],
                       check=True, capture_output=True)

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
            pinned = sha(repomd)
            catalog = root / "catalog"
            run("rpm", "index", serve / "repodata/repomd.xml",
                serve / "repodata/primary.xml.gz", "--sha256", pinned,
                "--source", "fixture", "--base", base, "--output", catalog)
            assert "holy-rpm-fixture 1.0-1 noarch" in run("rpm", "search", "fixture", "--catalog", catalog)
            assert sha(package) in run("rpm", "info", "holy-rpm-fixture", "--catalog", catalog)
            fetched = root / "fetched"
            run("rpm", "fetch", "holy-rpm-fixture", "1.0-1", "noarch", "--catalog",
                catalog, "--output", fetched, "--ca-file", root / "cert.pem", "--import")
            assert (fetched / sha(package)).read_bytes() == package
            assert (fetched / "converted/holy-rpm-fixture--noarch--nolibc.holy").is_file()
            synced = root / "synced"
            run("rpm", "sync", base, "--sha256", pinned, "--source", "fixture",
                "--output", synced, "--ca-file", root / "cert.pem")
            assert "holy-rpm-fixture" in run("rpm", "search", "holy", "--catalog", synced)
            run("rpm", "index", serve / "repodata/repomd.xml",
                serve / "repodata/primary.xml.gz", "--sha256", "0" * 64,
                "--source", "fixture", "--base", base, "--output", root / "bad-pin", status=1)
            (catalog / "catalog").write_text("tampered\n")
            run("rpm", "search", "holy", "--catalog", catalog, status=6)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
    return 0


if __name__ == "__main__":
    sys.exit(main())
