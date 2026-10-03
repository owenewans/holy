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
            entry.uid, entry.gid = os.getuid(), os.getgid()
            archive.addfile(entry, io.BytesIO(content))
    return gzip.compress(output.getvalue(), mtime=0)


def origin(package):
    data = subprocess.run(["lz4", "-d", "-c", str(package)],
                          capture_output=True, check=True).stdout
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        return archive.extractfile("HOLY/origin").read().decode()


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
    signed_dir = serve / "signed"
    signed_dir.mkdir()
    signing_key = tmp / "index.key"
    signing_pub = tmp / "fixture.rsa.pub"
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                    "rsa_keygen_bits:2048", "-out", str(signing_key)],
                   capture_output=True, check=True)
    subprocess.run(["openssl", "pkey", "-in", str(signing_key), "-pubout",
                    "-out", str(signing_pub)], capture_output=True, check=True)
    (tmp / "control.gz").write_bytes(control)
    package_signature = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(signing_key),
         str(tmp / "control.gz")], capture_output=True, check=True).stdout
    signed_package = member([(".SIGN.RSA256.fixture.rsa.pub", package_signature)]) + package
    (signed_dir / "fixture-1.2-r0.apk").write_bytes(signed_package)
    signed_rows = (f"C:{checksum}\nP:fixture\nV:1.2-r0\nA:x86_64\n"
                   f"S:{len(signed_package)}\np:so:libfixture.so.1\n\n").encode()
    (tmp / "signed-index-payload.gz").write_bytes(member([("APKINDEX", signed_rows)]))
    signature = subprocess.run(["openssl", "dgst", "-sha256", "-sign",
                                str(signing_key), str(tmp / "signed-index-payload.gz")],
                               capture_output=True, check=True).stdout
    signed_bytes = member([(".SIGN.RSA256.fixture.rsa.pub", signature)]) + (
        tmp / "signed-index-payload.gz").read_bytes()
    (signed_dir / "APKINDEX.tar.gz").write_bytes(signed_bytes)
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
        fetch("imported", extra=("--import",))
        assert "imported yes\n" in (tmp / "imported/selection").read_text()
        imported_origin = origin(next((tmp / "imported/converted").glob("*.holy")))
        assert "verification unverified\n" in imported_origin
        assert f"index-sha256 {hashlib.sha256((tmp / 'APKINDEX.tar.gz').read_bytes()).hexdigest()}\n" in imported_origin
        assert f'source-url "{base}fixture-1.2-r0.apk"\n' in imported_origin
        fetch("invalid-soname-flags", status=2,
              extra=("--require-soname", "libfixture.so.1"))
        fetch("false-soname", status=4,
              extra=("--import", "--require-soname", "libfixture.so.1"))
        assert not (tmp / "false-soname/selection").exists()
        assert list((tmp / "false-soname/converted").glob("*.holy"))
        fetch("file-present", extra=("--import", "--require-file", "/usr/share/fixture"))
        assert "file-provider verified-payload\n" in (tmp / "file-present/selection").read_text()
        fetch("file-absent", status=4,
              extra=("--import", "--require-file", "/usr/share/missing"))
        assert not (tmp / "file-absent/selection").exists()
        fetch("invalid-file", status=2,
              extra=("--import", "--require-file", "/usr/../fixture"))
        assert not (tmp / "invalid-file").exists()
        library = tmp / "libfixture.so.1"
        subprocess.run(["cc", "-shared", "-fPIC", "-x", "c", "-",
                        "-Wl,-soname,libfixture.so.1", "-o", str(library)],
                       input=b"#include <stdio.h>\nint fixture(void) { return puts(\"fixture\"); }\n",
                       capture_output=True, check=True)
        elf_data = member([("usr/lib/libfixture.so.1", library.read_bytes())])
        elf_control = member([(".PKGINFO", (
            "pkgname = fixturelib\npkgver = 1.0-r0\narch = x86_64\n"
            f"datahash = {hashlib.sha256(elf_data).hexdigest()}\n").encode())])
        elf_package = elf_control + elf_data
        (serve / "elf").mkdir()
        (serve / "elf/fixturelib-1.0-r0.apk").write_bytes(elf_package)
        elf_checksum = "Q1" + base64.b64encode(hashlib.sha1(elf_control).digest()).decode()
        elf_index = tmp / "elf-index.tar.gz"
        elf_index.write_bytes(member([("APKINDEX", (
            f"C:{elf_checksum}\nP:fixturelib\nV:1.0-r0\nA:x86_64\n"
            f"S:{len(elf_package)}\np:so:libfixture.so.1\n\n").encode())]))
        elf_catalog = tmp / "elf-catalog"
        run("apk", "index", elf_index, "--source", "fixture",
            "--base", base + "elf/", "--output", elf_catalog)
        assert run("apk", "providers", "soname:libfixture.so.1", "--catalog",
                   elf_catalog).stdout == "fixturelib 1.0-r0 x86_64 index-hint\n"
        run("apk", "fetch", "fixturelib", "1.0-r0", "x86_64", "--catalog",
            elf_catalog, "--output", tmp / "verified-soname", "--ca-file",
            tmp / "cert.pem", "--import", "--require-soname", "libfixture.so.1",
            "--require-file", "/usr/lib/libfixture.so.1")
        assert "soname-provider verified-payload\n" in (
            tmp / "verified-soname/selection").read_text()
        run("apk", "fetch-provider", "soname:libfixture.so.1", "x86_64",
            "--catalog", elf_catalog, "--output", tmp / "provider-package",
            "--ca-file", tmp / "cert.pem")
        assert "soname-provider verified-payload\n" in (
            tmp / "provider-package/selection").read_text()
        assert list((tmp / "provider-package/converted").glob("*.holy"))

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
        run("apk", "fetch", "fixture", "1.2-r0", "x86_64", "--catalog",
            tmp / "bound-catalog", "--output", tmp / "unbound-package",
            "--root", root, "--ca-file", tmp / "cert.pem", status=6)
        bound_fetch = ("apk", "fetch", "fixture", "1.2-r0", "x86_64",
                       "--catalog", root / "pinned-catalog", "--output",
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
        run("source", "plan", "--config", config, "--root", root, status=2)
        config.write_text('[source fixture]\ntype apk\nrepo main "https://localhost:1/"\n')
        register()
        changed_fetch = list(bound_fetch)
        changed_fetch[changed_fetch.index("--output") + 1] = tmp / "changed-source"
        run(*changed_fetch, status=6)
        assert not (tmp / "changed-source").exists()

        signed_root = tmp / "signed-root"
        signed_root.mkdir()
        run("db", "init", "--root", signed_root)
        signed_conf = tmp / "signed.conf"
        signed_conf.write_text(f'[source signed]\ntype apk\nrepo main "{base}signed/"\n'
                               f'repo extra "{base}signed/"\n'
                               f'trust require\npublic-key "{signing_pub}"\n')
        signed_plan = run("source", "plan", "--config", signed_conf,
                          "--root", signed_root).stdout
        (tmp / "signed.plan").write_text(signed_plan)
        run("source", "apply", tmp / "signed.plan", "--sha256",
            hashlib.sha256(signed_plan.encode()).hexdigest(), "--root", signed_root)
        signed_sync = ("apk", "sync", "signed", "main", "--root", signed_root,
                       "--output", tmp / "signed-catalog", "--ca-file", tmp / "cert.pem")
        run(*signed_sync, status=6)
        wrong_key_dir = tmp / "wrong-key"
        wrong_key_dir.mkdir()
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                        "rsa_keygen_bits:2048", "-out", str(wrong_key_dir / "private.key")],
                       capture_output=True, check=True)
        subprocess.run(["openssl", "pkey", "-in", str(wrong_key_dir / "private.key"),
                        "-pubout", "-out", str(wrong_key_dir / signing_pub.name)],
                       capture_output=True, check=True)
        run(*signed_sync, "--public-key", wrong_key_dir / signing_pub.name, status=4)
        run(*signed_sync, "--public-key", signing_pub)
        assert "verification rsa-sha256" in (tmp / "signed-catalog/conversion").read_text()
        # the same key enrolled under a name, so one key file backs the source and the
        # commands that verify with it without repeating its path
        run("key", "add", "signing-key", signing_pub, "--root", signed_root)
        enrolled_sync = ("apk", "sync", "signed", "extra", "--root", signed_root,
                         "--output", tmp / "enrolled-catalog", "--ca-file", tmp / "cert.pem")
        run(*enrolled_sync, "--public-key", "signing-key")
        assert "verification rsa-sha256" in (tmp / "enrolled-catalog/conversion").read_text()
        absent = list(enrolled_sync)
        absent[absent.index("--output") + 1] = tmp / "absent-key-catalog"
        run(*absent, "--public-key", "absent-key", status=2)
        assert not (tmp / "absent-key-catalog").exists()
        absent = list(enrolled_sync)
        absent[absent.index("--output") + 1] = tmp / "absent-key-catalog"
        run(*absent, "--public-key", "absent-key", status=2)
        assert not (tmp / "absent-key-catalog").exists()
        run("sync", "signed", "--root", signed_root,
            "--output", tmp / "generic-ambiguous-sync", status=3)
        run("sync", "signed", "--repo", "main", "--root", signed_root,
            "--output", tmp / "generic-missing-key-sync", "--ca-file",
            tmp / "cert.pem", status=6)
        run("sync", "signed", "--repo", "main", "--root", signed_root,
            "--output", tmp / "generic-signed-catalog", "--ca-file",
            tmp / "cert.pem", "--public-key", signing_pub)
        assert "verification rsa-sha256" in (tmp / "generic-signed-catalog/conversion").read_text()
        run("apk", "bind", "signed", "main", tmp / "signed-catalog", "--root",
            signed_root, status=6)
        run("apk", "bind", "signed", "main", tmp / "signed-catalog", "--root",
            signed_root, "--public-key", signing_pub)
        run("apk", "sync", "signed", "extra", "--root", signed_root,
            "--output", tmp / "signed-catalog-extra", "--ca-file", tmp / "cert.pem",
            "--public-key", signing_pub)
        run("apk", "bind", "signed", "extra", tmp / "signed-catalog-extra",
            "--root", signed_root, "--public-key", signing_pub)
        run("fetch", "signed:fixture", "--root", signed_root,
            "--output", tmp / "generic-missing-version", status=3)
        run("fetch", "signed:fixture", "--version", "--arch", "x86_64",
            "--root", signed_root, "--output", tmp / "generic-bad-option", status=2)
        run("fetch", "signed:fixture", "--version", "1.2-r0", "--arch", "x86_64",
            "--root", signed_root, "--output", tmp / "generic-missing-repo", status=3)
        run("fetch", "signed:fixture", "--version", "1.2-r0", "--arch", "x86_64",
            "--repo", "main", "--root", signed_root,
            "--output", tmp / "generic-signed", "--ca-file", tmp / "cert.pem",
            "--public-key", signing_pub, "--import")
        assert (tmp / "generic-signed/original").read_bytes() == signed_package
        assert "imported yes\n" in (tmp / "generic-signed/selection").read_text()
        assert list((tmp / "generic-signed/converted").glob("*.holy"))
        run("fetch", "signed:fixture", "--version", "1.2-r0", "--arch", "x86_64",
            "--repo", "main", "--root", signed_root,
            "--output", tmp / "generic-invalid-extract", "--extract", status=2)
        assert run("apk", "search", "fixture", "--source", "signed", "--repo",
                   "main", "--root", signed_root).stdout == "fixture 1.2-r0 x86_64\n"
        generic_search = run("search", "fixture", "--source", "signed",
                             "--repo", "main", "--root", signed_root).stdout
        assert 'repo "main"\nfixture 1.2-r0 x86_64\nsource-id ' in generic_search
        assert 'fixture 1.2-r0 x86_64\n' in run(
            "search", "fixture", "--root", signed_root).stdout
        assert 'repo "extra"\nfixture 1.2-r0 x86_64\n' in run(
            "search", "fixture", "--source", "signed", "--repo", "extra",
            "--root", signed_root).stdout
        generic_info = run("info", "signed:fixture", "--repo", "main",
                           "--root", signed_root).stdout
        assert "package fixture\nversion 1.2-r0\n" in generic_info
        run("info", "signed:fixture", "--root", signed_root, status=3)
        run("search", "/usr/share/fixture", "--source", "signed", "--file",
            "--root", signed_root, status=6)
        assert run("apk", "providers", "soname:libfixture.so.1", "--source",
                   "signed", "--repo", "main", "--root", signed_root).stdout == (
                       "fixture 1.2-r0 x86_64 index-hint\n")
        saved_conversion = (tmp / "signed-catalog/conversion").read_text()
        (tmp / "signed-catalog/conversion").write_text(
            saved_conversion.replace("verification rsa-sha256", "verification rsa-sha1"))
        run("apk", "search", "fixture", "--source", "signed", "--repo",
            "main", "--root", signed_root, status=6)
        run("search", "fixture", "--source", "signed", "--repo", "main",
            "--root", signed_root, status=6)
        (tmp / "signed-catalog/conversion").write_text(saved_conversion)
        run("apk", "fetch", "fixture", "1.2-r0", "x86_64", "--source",
            "signed", "--repo", "main", "--root", signed_root, "--output",
            tmp / "signed-package", "--ca-file", tmp / "cert.pem", "--public-key",
            signing_pub, "--import")
        assert "index-verification rsa-sha256" in (
            tmp / "signed-package/selection").read_text()
        assert "verification rsa-sha256" in (
            tmp / "signed-package/selection").read_text()
        assert (tmp / "signed-package/original").read_bytes() == signed_package
        run("apk", "fetch", "fixture", "1.2-r0", "x86_64", "--source",
            "signed", "--repo", "main", "--root", signed_root, "--output",
            tmp / "signed-false-soname", "--ca-file", tmp / "cert.pem",
            "--public-key", signing_pub, "--import", "--require-soname",
            "libfixture.so.1", status=4)
        assert not (tmp / "signed-false-soname/selection").exists()
        run("apk", "fetch-provider", "soname:libfixture.so.1", "x86_64",
            "--source", "signed", "--repo", "main", "--root", signed_root,
            "--output", tmp / "signed-false-provider", "--ca-file", tmp / "cert.pem",
            "--public-key", signing_pub, status=4)
        assert not (tmp / "signed-false-provider/selection").exists()
        signed_origin = origin(next((tmp / "signed-package/converted").glob("*.holy")))
        assert "verification rsa-sha256\n" in signed_origin
        assert "public-key-sha256 " in signed_origin
        signed_native = next((tmp / "signed-package/converted").glob("*.holy"))
        (signed_root / "usr/share").mkdir(parents=True)
        run("add", "local:" + str(signed_native), "--associate-source", "signed",
            "--root", signed_root, "--yes")
        assert (signed_root / "usr/share/fixture").read_bytes() == b"payload\n"
        run("check", "signed:fixture", "--root", signed_root)
        run("rm", "signed:fixture", "--root", signed_root, "--yes")
        assert not (signed_root / "usr/share/fixture").exists()
        native_tree = tmp / "native-tree"
        native_meta = native_tree / "HOLY"
        native_data = native_tree / "DATA/usr/share"
        native_meta.mkdir(parents=True)
        native_data.mkdir(parents=True)
        (native_meta / "meta").write_text(
            "format holy-package-1\nname consumer\nversion 1\nrelease 1\n"
            "os linux\narch noarch\nlibc nolibc\n")
        (native_meta / "deps").write_text(
            "require dep-1 consumer package fixture any any any - fixture metadata\n")
        for field in ("provides", "hooks", "origin", "transform"):
            (native_meta / field).write_text("")
        (native_data / "consumer").write_bytes(b"consumer\n")
        native_files = tmp / "native-files"
        run("manifest", "generate", native_tree, "--output", native_files)
        native_files.rename(native_meta / "files")
        native_repo = tmp / "native-repo"
        native_repo.mkdir()
        run("pack", native_tree, "--output", native_repo / "consumer.holy")
        run("repo", "index", native_repo)
        run("repo", "seal", native_repo)
        signed_conf.write_text(signed_conf.read_text() +
                               "[source native]\ntype holy-http\n"
                               "url \"https://native.example/\"\n")
        native_plan = run("source", "plan", "--config", signed_conf,
                          "--root", signed_root).stdout
        (tmp / "native.plan").write_text(native_plan)
        run("source", "apply", tmp / "native.plan", "--sha256",
            hashlib.sha256(native_plan.encode()).hexdigest(), "--root", signed_root)
        native_id = next(line.split()[1] for line in
                         run("source", "list", "--root", signed_root).stdout.splitlines()
                         if '"native" active' in line)
        index_hash = (native_repo / "current").read_text().split()[1]
        (native_repo / "mirror-origin").write_text(
            "format holy-mirror-1\nurl \"https://native.example/\"\n"
            f"index-sha256 {index_hash}\nverification digest-pinned-unsigned\n"
            f"source-id {native_id}\n")
        run("source", "catalog", "bind", "native", native_repo,
            "--root", signed_root)
        run("add", "native:consumer", "--candidate-local",
            "signed=" + str(signed_native), "--root", signed_root, "--yes")
        assert (signed_root / "usr/share/consumer").read_bytes() == b"consumer\n"
        assert (signed_root / "usr/share/fixture").read_bytes() == b"payload\n"
        run("check", "--root", signed_root)
        run("apk", "fetch", "fixture", "1.2-r0", "x86_64", "--source",
            "signed", "--repo", "main", "--root", signed_root, "--output",
            tmp / "missing-package-key", "--ca-file", tmp / "cert.pem", status=6)
        run("apk", "fetch", "fixture", "1.2-r0", "x86_64", "--source",
            "signed", "--repo", "main", "--root", signed_root, "--output",
            tmp / "wrong-package-key", "--ca-file", tmp / "cert.pem",
            "--public-key", wrong_key_dir / signing_pub.name, status=6)
        (tmp / "wrong-control.gz").write_bytes(data)
        wrong_signature = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(signing_key),
             str(tmp / "wrong-control.gz")], capture_output=True, check=True).stdout
        bad_package = member([(".SIGN.RSA256.fixture.rsa.pub", wrong_signature)]) + package
        bad_rows = (f"C:{checksum}\nP:fixture\nV:1.2-r0\nA:x86_64\n"
                    f"S:{len(bad_package)}\n\n").encode()
        bad_payload = tmp / "bad-package-index.gz"
        bad_payload.write_bytes(member([("APKINDEX", bad_rows)]))
        bad_index_sig = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(signing_key),
             str(bad_payload)], capture_output=True, check=True).stdout
        (signed_dir / "APKINDEX.tar.gz").write_bytes(
            member([(".SIGN.RSA256.fixture.rsa.pub", bad_index_sig)]) +
            bad_payload.read_bytes())
        (signed_dir / "fixture-1.2-r0.apk").write_bytes(bad_package)
        bad_package_sync = list(signed_sync)
        bad_package_sync[bad_package_sync.index("--output") + 1] = tmp / "bad-package-catalog"
        run(*bad_package_sync, "--public-key", signing_pub)
        run("apk", "fetch", "fixture", "1.2-r0", "x86_64", "--source",
            "signed", "--repo", "main", "--root", signed_root, "--output",
            tmp / "bad-package", "--ca-file", tmp / "cert.pem", "--public-key",
            signing_pub, status=4)
        assert not (tmp / "bad-package").exists()
        changed_index = bytearray(signed_bytes)
        changed_index[-13] ^= 1
        (signed_dir / "APKINDEX.tar.gz").write_bytes(changed_index)
        (signed_dir / "fixture-1.2-r0.apk").write_bytes(signed_package)
        changed_sync = list(signed_sync)
        changed_sync[changed_sync.index("--output") + 1] = tmp / "changed-signed-index"
        run(*changed_sync, "--public-key", signing_pub, status=4)
        assert not (tmp / "changed-signed-index").exists()
        (signed_dir / "APKINDEX.tar.gz").write_bytes(signed_bytes)
        nohash_control = member([(".PKGINFO",
                                  b"pkgname = fixture\npkgver = 1.2-r0\narch = x86_64\n")])
        (tmp / "nohash-control.gz").write_bytes(nohash_control)
        nohash_package_signature = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(signing_key),
             str(tmp / "nohash-control.gz")], capture_output=True, check=True).stdout
        nohash_package = member([(".SIGN.RSA256.fixture.rsa.pub",
                                  nohash_package_signature)]) + nohash_control + data
        nohash_checksum = "Q1" + base64.b64encode(
            hashlib.sha1(nohash_control).digest()).decode()
        nohash_rows = (f"C:{nohash_checksum}\nP:fixture\nV:1.2-r0\nA:x86_64\n"
                       f"S:{len(nohash_package)}\n\n").encode()
        nohash_index = tmp / "nohash-index.gz"
        nohash_index.write_bytes(member([("APKINDEX", nohash_rows)]))
        nohash_signature = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(signing_key),
             str(nohash_index)], capture_output=True, check=True).stdout
        (signed_dir / "APKINDEX.tar.gz").write_bytes(
            member([(".SIGN.RSA256.fixture.rsa.pub", nohash_signature)]) +
            nohash_index.read_bytes())
        (signed_dir / "fixture-1.2-r0.apk").write_bytes(nohash_package)
        nohash_sync = list(signed_sync)
        nohash_sync[nohash_sync.index("--output") + 1] = tmp / "nohash-catalog"
        run(*nohash_sync, "--public-key", signing_pub)
        run("apk", "fetch", "fixture", "1.2-r0", "x86_64", "--source",
            "signed", "--repo", "main", "--root", signed_root, "--output",
            tmp / "nohash-package", "--ca-file", tmp / "cert.pem", "--public-key",
            signing_pub, status=4)
        assert not (tmp / "nohash-package").exists()

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
