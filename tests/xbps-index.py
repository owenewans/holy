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


def repodata(package, *, package_hash=None, package_name="fixture", broken=False,
             public_key=None, claims=None, version="1.0_1"):
    digest = package_hash or hashlib.sha256(package).hexdigest()
    row = {"architecture": "x86_64", "pkgver": f"fixture-{version}",
           "filename-sha256": digest, "filename-size": len(package),
           "run_depends": [], "shlib-requires": [],
           "shlib-provides": ["libfixture.so.1"] if claims is None else claims}
    index = b"<broken" if broken else plistlib.dumps({package_name: row})
    meta = {"signature-type": "rsa"}
    if public_key:
        meta["public-key"] = public_key
        meta["public-key-size"] = 2048
    data = tar_bytes((("index.plist", index),
                      ("index-meta.plist", plistlib.dumps(meta)),
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
            assert package_hash in run("xbps", "providers", "libfixture.so.1",
                                       "--catalog", catalog)
            assert "coverage partial" in run("xbps", "providers", "libabsent.so.1",
                                              "--catalog", catalog)
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
            run("xbps", "fetch", "fixture", "1.0_1", "x86_64", "--catalog", synced,
                "--output", root / "invalid-soname-flags", "--require-soname",
                "libfixture.so.1", status=2)
            rejected = root / "rejected-soname"
            run("xbps", "fetch", "fixture", "1.0_1", "x86_64", "--catalog", synced,
                "--output", rejected, "--ca-file", root / "cert.pem", "--import",
                "--require-soname", "libfixture.so.1", status=4)
            assert not (rejected / "conversion").exists()
            assert list((rejected / "converted").glob("*.holy"))
            imported = root / "fetched-imported"
            run("xbps", "fetch", "fixture", "1.0_1", "x86_64", "--catalog", synced,
                "--output", imported, "--ca-file", root / "cert.pem", "--import")
            assert "imported yes" in (imported / "conversion").read_text()
            assert len(list((imported / "converted").glob("*.holy"))) == 1
            library = root / "libfixture.so.1"
            subprocess.run(["cc", "-shared", "-fPIC", "-x", "c", "-",
                            "-Wl,-soname,libfixture.so.1", "-o", str(library)],
                           input=b"#include <stdio.h>\nint fixture(void) { return puts(\"fixture\"); }\n",
                           capture_output=True, check=True)
            library_data = library.read_bytes()
            library_props = plistlib.dumps({"pkgname": "fixture", "pkgver": "fixture-1.0_2",
                                            "version": "1.0_2", "architecture": "x86_64"})
            library_files = plistlib.dumps({"files": [{"file": "/usr/lib/libfixture.so.1",
                "sha256": hashlib.sha256(library_data).hexdigest(), "size": len(library_data)}]})
            library_package = tar_bytes((("./props.plist", library_props),
                ("./files.plist", library_files),
                ("./usr/lib/libfixture.so.1", library_data)), "w:gz")
            (serve / "fixture-1.0_2.x86_64.xbps").write_bytes(library_package)
            library_index = root / "library-repodata"
            library_index.write_bytes(repodata(library_package, version="1.0_2"))
            library_catalog = root / "library-catalog"
            run("xbps", "index", library_index, "--sha256",
                hashlib.sha256(library_index.read_bytes()).hexdigest(), "--source", "fixture",
                "--base", base, "--output", library_catalog)
            verified = root / "verified-soname"
            run("xbps", "fetch", "fixture", "1.0_2", "x86_64", "--catalog",
                library_catalog, "--output", verified, "--ca-file", root / "cert.pem",
                "--import", "--require-soname", "libfixture.so.1")
            assert "soname-provider verified-payload" in (verified / "conversion").read_text()
            converted = root / "converted"
            run("import", fetched / package_hash, "--source", "fixture", "--format", "xbps",
                "--output", converted)
            assert len(list(converted.glob("*.holy"))) == 1
            private_key = root / "repo-private.pem"
            public_key = root / "repo-public.pem"
            subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                            "rsa_keygen_bits:2048", "-out", str(private_key)],
                           capture_output=True, check=True)
            subprocess.run(["openssl", "pkey", "-in", str(private_key), "-pubout",
                            "-out", str(public_key)], capture_output=True, check=True)
            signature = serve / "fixture-1.0_1.x86_64.xbps.sig2"
            subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(private_key),
                            "-out", str(signature),
                            str(serve / "fixture-1.0_1.x86_64.xbps")],
                           capture_output=True, check=True)
            signed_index = root / "signed-repodata"
            signed_index.write_bytes(repodata(package, public_key=public_key.read_bytes()))
            signed_hash = hashlib.sha256(signed_index.read_bytes()).hexdigest()
            signed_catalog = root / "signed-catalog"
            run("xbps", "index", signed_index, "--sha256", signed_hash,
                "--source", "fixture", "--base", base, "--output", signed_catalog,
                "--public-key", public_key)
            (serve / "x86_64-repodata").write_bytes(signed_index.read_bytes())
            signed_sync = root / "signed-sync"
            run("xbps", "sync", base, "x86_64", "--sha256", signed_hash,
                "--source", "fixture", "--output", signed_sync,
                "--ca-file", root / "cert.pem", "--public-key", public_key)
            assert "verification key-matched" in (signed_sync / "conversion").read_text()
            target = root / "target"
            target.mkdir()
            run("db", "init", "--root", target)
            config = root / "source.conf"
            config.write_text(f'[source fixture]\ntype xbps\nurl "{base}"\n'
                              f'trust require\npublic-key "{public_key}"\n')
            plan = root / "source.plan"
            plan.write_text(run("source", "plan", "--config", config, "--root", target))
            run("source", "apply", plan, "--sha256",
                hashlib.sha256(plan.read_bytes()).hexdigest(), "--root", target)
            registered = target / "cache"
            run("xbps", "sync-source", "fixture", "x86_64", "--root", target,
                "--sha256", signed_hash, "--output", registered,
                "--ca-file", root / "cert.pem", "--public-key", public_key)
            assert "source-id " in (registered / "conversion").read_text()
            assert package_hash in run("xbps", "info", "fixture", "--catalog", registered,
                                       "--source", "fixture", "--root", target)
            assert package_hash in run("xbps", "info", "fixture", "--source", "fixture",
                                       "--index-arch", "x86_64", "--root", target)
            assert package_hash in run("xbps", "providers", "libfixture.so.1",
                                       "--source", "fixture", "--index-arch", "x86_64",
                                       "--root", target)
            run("xbps", "fetch", "fixture", "1.0_1", "x86_64",
                "--source", "fixture", "--index-arch", "x86_64", "--root", target,
                "--output", root / "bound-fetch", "--ca-file", root / "cert.pem",
                "--public-key", public_key, "--import")
            assert (root / "bound-fetch" / package_hash).read_bytes() == package
            assert "source-id " in (root / "bound-fetch" / "conversion").read_text()
            assert "imported yes" in (root / "bound-fetch" / "conversion").read_text()
            run("xbps", "fetch", "fixture", "1.0_1", "x86_64",
                "--catalog", registered, "--output", root / "unbound-fetch",
                "--ca-file", root / "cert.pem", "--public-key", public_key)
            assert "source-id " not in (root / "unbound-fetch" / "conversion").read_text()
            run("xbps", "fetch", "fixture", "1.0_1", "x86_64",
                "--catalog", registered, "--output", root / "registered-fetch",
                "--source", "fixture", "--root", target,
                "--ca-file", root / "cert.pem", "--public-key", public_key)
            run("xbps", "fetch", "fixture", "1.0_1", "x86_64",
                "--catalog", registered, "--output", root / "missing-key-fetch",
                "--source", "fixture", "--root", target,
                "--ca-file", root / "cert.pem", status=6)
            run("xbps", "info", "fixture", "--catalog", signed_sync,
                "--source", "fixture", "--root", target, status=6)
            conversion = registered / "conversion"
            saved_conversion = conversion.read_bytes()
            conversion.write_bytes(saved_conversion + b"x-test changed\n")
            run("xbps", "info", "fixture", "--source", "fixture",
                "--index-arch", "x86_64", "--root", target, status=6)
            conversion.write_bytes(saved_conversion)
            renamed = root / "renamed.conf"
            renamed.write_text(config.read_text().replace("source fixture", "source void"))
            renamed_plan = root / "renamed.plan"
            renamed_plan.write_text(run("source", "plan", "--config", renamed,
                                        "--root", target))
            run("source", "apply", renamed_plan, "--sha256",
                hashlib.sha256(renamed_plan.read_bytes()).hexdigest(), "--root", target)
            assert package_hash in run("xbps", "info", "fixture", "--source", "void",
                                       "--index-arch", "x86_64", "--root", target)
            assert package_hash in run("xbps", "providers", "libfixture.so.1",
                                       "--source", "void", "--index-arch", "x86_64",
                                       "--root", target)
            moved_target = root / "moved-target"
            target.rename(moved_target)
            target = moved_target
            registered = target / "cache"
            assert package_hash in run("xbps", "info", "fixture", "--source", "void",
                                       "--index-arch", "x86_64", "--root", target)
            rotated = root / "rotated.conf"
            rotated.write_text(renamed.read_text().replace(base, "https://localhost:65535/"))
            rotated_plan = root / "rotated.plan"
            rotated_plan.write_text(run("source", "plan", "--config", rotated,
                                        "--root", target))
            run("source", "apply", rotated_plan, "--sha256",
                hashlib.sha256(rotated_plan.read_bytes()).hexdigest(), "--root", target)
            run("xbps", "info", "fixture", "--catalog", registered,
                "--source", "void", "--root", target, status=6)
            run("xbps", "info", "fixture", "--source", "void", "--index-arch",
                "x86_64", "--root", target, status=6)
            signed_fetch = root / "signed-fetch"
            run("xbps", "fetch", "fixture", "1.0_1", "x86_64", "--catalog", signed_catalog,
                "--output", signed_fetch, "--ca-file", root / "cert.pem",
                "--public-key", public_key)
            assert "verification rsa-sha256" in (signed_fetch / "conversion").read_text()
            wrong_key = root / "wrong-public.pem"
            wrong_private = root / "wrong-private.pem"
            subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                            "rsa_keygen_bits:2048", "-out", str(wrong_private)],
                           capture_output=True, check=True)
            subprocess.run(["openssl", "pkey", "-in", str(wrong_private), "-pubout",
                            "-out", str(wrong_key)], capture_output=True, check=True)
            run("xbps", "index", signed_index, "--sha256", signed_hash,
                "--source", "fixture", "--base", base, "--output", root / "wrong-key-index",
                "--public-key", wrong_key, status=4)
            run("xbps", "fetch", "fixture", "1.0_1", "x86_64", "--catalog", signed_catalog,
                "--output", root / "wrong-key-fetch", "--ca-file", root / "cert.pem",
                "--public-key", wrong_key, status=4)
            signature.write_bytes(b"invalid signature")
            run("xbps", "fetch", "fixture", "1.0_1", "x86_64", "--catalog", signed_catalog,
                "--output", root / "bad-signature-fetch", "--ca-file", root / "cert.pem",
                "--public-key", public_key, status=4)
            (catalog / "capabilities").write_bytes(b"tampered")
            run("xbps", "providers", "libfixture.so.1", "--catalog", catalog, status=6)
            run("xbps", "info", "fixture", "--catalog", catalog, status=6)
            (catalog / "catalog").write_bytes(b"tampered")
            run("xbps", "info", "fixture", "--catalog", catalog, status=6)
            malformed = root / "malformed-repodata"
            malformed.write_bytes(repodata(package, broken=True))
            run("xbps", "index", malformed, "--sha256", hashlib.sha256(malformed.read_bytes()).hexdigest(),
                "--source", "fixture", "--base", base, "--output", root / "bad-index", status=2)
            malformed_claim = root / "malformed-claim-repodata"
            malformed_claim.write_bytes(repodata(package, claims=["bad claim"]))
            run("xbps", "index", malformed_claim, "--sha256",
                hashlib.sha256(malformed_claim.read_bytes()).hexdigest(),
                "--source", "fixture", "--base", base,
                "--output", root / "bad-claim-index", status=2)
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
