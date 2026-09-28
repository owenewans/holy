#!/usr/bin/env python3
import base64
import gzip
import hashlib
import http.server
import io
import os
import pathlib
import shutil
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
    (serve / "APKINDEX.tar.gz").write_bytes((tmp / "APKINDEX.tar.gz").read_bytes())
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

        root = tmp / "root"
        root.mkdir()
        run("db", "init", "--root", root)
        config = tmp / "source.conf"
        config.write_text(f'[source fixture]\ntype apk\nrepo main "{base}"\n')

        def register():
            plan = run("source", "plan", "--config", config, "--root", root).stdout
            path = tmp / "source.plan"
            path.write_text(plan)
            run("source", "apply", path, "--sha256",
                hashlib.sha256(plan.encode()).hexdigest(), "--root", root)

        register()
        index_hash = hashlib.sha256((serve / "APKINDEX.tar.gz").read_bytes()).hexdigest()
        sync = ("apk", "sync", "fixture", "main", "--root", root,
                "--output", tmp / "bound-catalog", "--ca-file", tmp / "cert.pem")
        run(*sync, status=3)
        assert not (tmp / "bound-catalog").exists()
        run(*sync, "--sha256", "0" * 64, status=4)
        run(*sync, "--accept-unsigned", index_hash)
        pinned_sync = list(sync)
        pinned_sync[pinned_sync.index("--output") + 1] = root / "pinned-catalog"
        run(*pinned_sync, "--sha256", index_hash)
        assert run("apk", "search", "fixture", "--source", "fixture", "--repo",
                   "main", "--root", root).stdout == "fixture 1.2-r0 x86_64\n"
        assert "checksum " in run("apk", "info", "fixture", "--source",
                                  "fixture", "--repo", "main", "--root", root).stdout
        run("apk", "bind", "fixture", "main", tmp / "bound-catalog", "--root",
            root, status=3)
        run("apk", "bind", "fixture", "main", tmp / "bound-catalog", "--root",
            root, "--accept-unsigned", index_hash)
        bound_auto = ("apk", "fetch", "fixture", "1.2-r0", "x86_64",
                      "--source", "fixture", "--repo", "main", "--root", root,
                      "--output", tmp / "bound-auto", "--ca-file", tmp / "cert.pem")
        run(*bound_auto)
        assert (tmp / "bound-auto/original").read_bytes() == package
        saved_catalog = (tmp / "bound-catalog/catalog").read_bytes()
        (tmp / "bound-catalog/catalog").write_bytes(saved_catalog + b"broken")
        run("apk", "search", "fixture", "--source", "fixture", "--repo",
            "main", "--root", root, status=6)
        (tmp / "bound-catalog/catalog").write_bytes(saved_catalog)
        run("apk", "bind", "fixture", "main", root / "pinned-catalog", "--root",
            root, "--accept-unsigned", index_hash)
        copied = tmp / "copied-root"
        shutil.copytree(root, copied)
        assert run("apk", "search", "fixture", "--source", "fixture", "--repo",
                   "main", "--root", copied).stdout == "fixture 1.2-r0 x86_64\n"
        bound = (tmp / "bound-catalog/conversion").read_text()
        source_id = next(line.split()[1] for line in bound.splitlines()
                         if line.startswith("source-id "))
        assert len(source_id) == 64 and "repo \"main\"" in bound
        bound_fetch = ("apk", "fetch", "fixture", "1.2-r0", "x86_64",
                       "--catalog", tmp / "bound-catalog", "--output",
                       tmp / "bound-package", "--root", root, "--ca-file",
                       tmp / "cert.pem")
        run(*bound_fetch)
        assert (tmp / "bound-package/original").read_bytes() == package
        assert f"source-id {source_id}" in (tmp / "bound-package/selection").read_text()
        assert "source-binding checked" in (tmp / "bound-package/selection").read_text()
        config.write_text(f'[source renamed]\ntype apk\nrepo main "{base}"\n')
        register()
        assert run("apk", "search", "fixture", "--source", "renamed", "--repo",
                   "main", "--root", root).stdout == "fixture 1.2-r0 x86_64\n"
        renamed_fetch = list(bound_fetch)
        renamed_fetch[renamed_fetch.index("--output") + 1] = tmp / "renamed-source"
        run(*renamed_fetch, "--source", "renamed")
        assert (tmp / "renamed-source/original").read_bytes() == package
        assert "active-source-name \"renamed\"" in (
            tmp / "renamed-source/selection").read_text()
        config.write_text(f'[source renamed]\ntype apk\nrepo main "{base}"\ntrust require\n')
        register()
        rejected_sync = list(sync)
        rejected_sync[rejected_sync.index("fixture")] = "renamed"
        rejected_sync[rejected_sync.index("--output") + 1] = tmp / "require-rejected"
        run(*rejected_sync, "--sha256", index_hash, status=6)
        assert not (tmp / "require-rejected").exists()
        run("apk", "search", "fixture", "--source", "renamed", "--repo",
            "main", "--root", root, status=6)
        config.write_text('[source fixture]\ntype apk\nrepo main "https://localhost:1/"\n')
        register()
        changed_fetch = list(bound_fetch)
        changed_fetch[changed_fetch.index("--output") + 1] = tmp / "changed-source"
        run(*changed_fetch, status=6)
        assert not (tmp / "changed-source").exists()

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
