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


def origin(package):
    data = subprocess.run(["lz4", "-d", "-c", str(package)],
                          capture_output=True, check=True).stdout
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        return archive.extractfile("HOLY/origin").read().decode()


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
    (serve / "dists/stable/main/binary-all").mkdir(parents=True)
    (serve / "dists/stable/main/binary-all/Packages.gz").write_bytes(packages.read_bytes())
    contents = serve / "dists/stable/main/Contents-all.gz"
    contents.write_bytes(gzip.compress(
        b"FILE LOCATION\nusr/share/fixture main/misc/fixture,main/other/fixture\n"
        b"usr/share/fixture file main/misc/fixture\n"
        b"usr/share/phantom main/misc/fixture\n", mtime=0))
    release = serve / "dists/stable/Release"
    release.write_text("Suite: stable\nDate: Mon, 28 Sep 2026 00:00:00 UTC\n"
                       "Valid-Until: Thu, 31 Dec 2099 00:00:00 UTC\n"
                       "SHA256:\n"
                       f" {'0' * 64} 100000000 other/Contents-amd64.gz\n"
                       f" {hashlib.sha256(packages.read_bytes()).hexdigest()} "
                       f"{packages.stat().st_size} main/binary-all/Packages.gz\n"
                       f" {hashlib.sha256(contents.read_bytes()).hexdigest()} "
                       f"{contents.stat().st_size} main/Contents-all.gz\n")
    gnupg = tmp / "gnupg"
    gnupg.mkdir(mode=0o700)
    subprocess.run(["gpg", "--homedir", str(gnupg), "--batch", "--passphrase", "",
                    "--quick-gen-key", "APT Fixture <apt@example.invalid>", "ed25519", "sign", "1d"],
                   capture_output=True, check=True)
    keyring = tmp / "trusted.gpg"
    keyring.write_bytes(subprocess.check_output(["gpg", "--homedir", str(gnupg),
                                                  "--export", "APT Fixture"], stderr=subprocess.DEVNULL))
    subprocess.run(["gpg", "--homedir", str(gnupg), "--batch", "--yes",
                    "--detach-sign", "--output", str(release.parent / "Release.gpg"),
                    str(release)], capture_output=True, check=True)
    inrelease = release.parent / "InRelease"
    subprocess.run(["gpg", "--homedir", str(gnupg), "--batch", "--yes",
                    "--clearsign", "--output", str(inrelease), str(release)],
                   capture_output=True, check=True)
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
        remote = tmp / "remote"
        packages_url = base + "dists/stable/main/binary-all/Packages.gz"
        run("apt", "sync", packages_url, "--sha256",
            hashlib.sha256(packages.read_bytes()).hexdigest(), "--source", "debian",
            "--base", base, "--output", remote, "--ca-file", tmp / "cert.pem")
        assert (remote / "original").read_bytes() == packages.read_bytes()
        assert run("apt", "search", "fixture", "--catalog", remote) == "fixture 1:2.0-3 all\n"
        run("apt", "sync", packages_url, "--sha256", "0" * 64,
            "--source", "debian", "--base", base, "--output", tmp / "remote-wrong",
            "--ca-file", tmp / "cert.pem", status=4)
        assert not (tmp / "remote-wrong").exists()
        run("apt", "sync", packages_url, "--sha256",
            hashlib.sha256(packages.read_bytes()).hexdigest(), "--source", "debian",
            "--base", base, "--output", tmp / "remote-no-ca", status=6)
        signed = tmp / "signed"
        run("apt", "sync-signed", base, "stable", "main", "all", "--source", "debian",
            "--keyring", keyring, "--output", signed, "--files",
            "--ca-file", tmp / "cert.pem")
        assert run("apt", "search", "/usr/share/fixture", "--file", "--catalog", signed) == (
            "fixture /usr/share/fixture\n")
        assert run("apt", "search", "/usr/share/fixture file", "--file", "--catalog",
                   signed) == "fixture /usr/share/fixture file\n"
        run("apt", "search", "/missing", "--file", "--catalog", signed, status=6)
        run("apt", "search", "/usr/share/fixture", "--file", "--catalog", catalog, status=6)
        good_contents = contents.read_bytes()
        good_release = release.read_bytes()
        good_signature = (release.parent / "Release.gpg").read_bytes()
        contents.write_bytes(b"plain text, not gzip")
        release.write_bytes(good_release.replace(
            f" {hashlib.sha256(good_contents).hexdigest()} {len(good_contents)} main/Contents-all.gz".encode(),
            f" {hashlib.sha256(contents.read_bytes()).hexdigest()} {contents.stat().st_size} main/Contents-all.gz".encode()))
        subprocess.run(["gpg", "--homedir", str(gnupg), "--batch", "--yes",
                        "--detach-sign", "--output", str(release.parent / "Release.gpg"),
                        str(release)], capture_output=True, check=True)
        run("apt", "sync-signed", base, "stable", "main", "all", "--source", "debian",
            "--keyring", keyring, "--output", tmp / "bad-contents", "--files",
            "--ca-file", tmp / "cert.pem", status=4)
        assert not (tmp / "bad-contents").exists()
        contents.write_bytes(good_contents)
        release.write_bytes(good_release)
        (release.parent / "Release.gpg").write_bytes(good_signature)
        assert "verification release-gpgv-user-key\n" in run(
            "apt", "info", "fixture", "--catalog", signed)
        missing_verifier = subprocess.run(
            [binary, "apt", "search", "fixture", "--catalog", str(signed)],
            capture_output=True, text=True, env={**os.environ, "PATH": "/nonexistent"})
        assert missing_verifier.returncode == 6, missing_verifier.stderr
        signed_package = tmp / "signed-package"
        run("apt", "fetch", "fixture", "1:2.0-3", "all", "--catalog", signed,
            "--output", signed_package, "--ca-file", tmp / "cert.pem", "--import",
            "--require-file", "/usr/share/fixture")
        assert "verification release-gpgv-user-key\n" in (signed_package / "selection").read_text()
        signed_origin = origin(next((signed_package / "converted").glob("*.holy")))
        assert "verification release-gpgv-user-key\n" in signed_origin
        assert f"keyring-sha256 {hashlib.sha256((signed / 'keyring').read_bytes()).hexdigest()}\n" in signed_origin
        assert f"signature-sha256 {hashlib.sha256((signed / 'release.gpg').read_bytes()).hexdigest()}\n" in signed_origin
        assert 'required-file "/usr/share/fixture"\n' in (
            signed_package / "selection").read_text()
        assert "file-provider verified-payload\n" in (signed_package / "selection").read_text()
        run("apt", "fetch", "fixture", "1:2.0-3", "all", "--catalog", signed,
            "--output", tmp / "false-file", "--ca-file", tmp / "cert.pem", "--import",
            "--require-file", "/usr/share/phantom", status=4)
        assert not (tmp / "false-file/selection").exists()
        run("apt", "fetch", "fixture", "1:2.0-3", "all", "--catalog", signed,
            "--output", tmp / "absent-file", "--ca-file", tmp / "cert.pem", "--import",
            "--require-file", "/missing", status=6)
        assert not (tmp / "absent-file").exists()
        run("apt", "fetch", "fixture", "1:2.0-3", "all", "--catalog", signed,
            "--output", tmp / "no-import", "--require-file", "/usr/share/fixture", status=2)
        inline = tmp / "inline"
        run("apt", "sync-signed", base, "stable", "main", "all", "--source", "debian",
            "--keyring", keyring, "--output", inline, "--inrelease", "--files",
            "--ca-file", tmp / "cert.pem")
        assert run("apt", "search", "/usr/share/fixture", "--catalog", inline,
                   "--file") == "fixture /usr/share/fixture\n"
        assert "verification inrelease-gpgv-user-key\n" in run(
            "apt", "info", "fixture", "--catalog", inline)
        inline_package = tmp / "inline-package"
        run("apt", "fetch", "fixture", "1:2.0-3", "all", "--catalog", inline,
            "--output", inline_package, "--ca-file", tmp / "cert.pem", "--import")
        assert "verification inrelease-gpgv-user-key\n" in (
            inline_package / "selection").read_text()
        inline_origin = origin(next((inline_package / "converted").glob("*.holy")))
        assert "verification inrelease-gpgv-user-key\n" in inline_origin
        assert f"signature-sha256 {hashlib.sha256((inline / 'inrelease').read_bytes()).hexdigest()}\n" in inline_origin
        inline_bytes = (inline / "inrelease").read_bytes()
        (inline / "inrelease").write_bytes(inline_bytes + b"damage")
        run("apt", "search", "fixture", "--catalog", inline, status=2)
        (inline / "inrelease").write_bytes(inline_bytes)
        file_bytes = (inline / "contents.gz").read_bytes()
        (inline / "contents.gz").write_bytes(file_bytes + b"damage")
        run("apt", "search", "fixture", "--catalog", inline, status=2)
        (inline / "contents.gz").write_bytes(file_bytes)
        file_proof = (inline / "file-proof").read_bytes()
        (inline / "file-proof").write_bytes(file_proof.replace(
            b"main/Contents-all.gz", b"other/Contents-all.gz"))
        run("apt", "search", "fixture", "--catalog", inline, status=2)
        (inline / "file-proof").write_bytes(file_proof)
        inline_release = (inline / "release").read_bytes()
        (inline / "release").write_bytes(b"unsigned\n")
        run("apt", "search", "fixture", "--catalog", inline, status=2)
        (inline / "release").write_bytes(inline_release)
        run("apt", "search", "fixture", "--catalog", inline)
        remote_inline = inrelease.read_bytes()
        inrelease.write_bytes(remote_inline + b"unsigned trailer\n")
        run("apt", "sync-signed", base, "stable", "main", "all", "--source", "debian",
            "--keyring", keyring, "--output", tmp / "inline-trailer",
            "--inrelease", "--ca-file", tmp / "cert.pem", status=4)
        assert not (tmp / "inline-trailer").exists()
        inrelease.write_bytes(remote_inline)
        signature = (signed / "release.gpg").read_bytes()
        (signed / "release.gpg").write_bytes(signature + b"damage")
        run("apt", "search", "fixture", "--catalog", signed, status=2)
        (signed / "release.gpg").write_bytes(signature)
        (signed / "keyring").write_bytes(b"wrong key")
        run("apt", "search", "fixture", "--catalog", signed, status=2)
        (signed / "keyring").write_bytes(keyring.read_bytes())
        proof = (signed / "release-proof").read_bytes()
        (signed / "release-proof").unlink()
        run("apt", "search", "fixture", "--catalog", signed, status=2)
        (signed / "release-proof").write_bytes(proof)

        signed_dir = release.parent
        signed_release = release.read_bytes()
        release.write_bytes(signed_release + b"tamper\n")
        run("apt", "sync-signed", base, "stable", "main", "all", "--source", "debian",
            "--keyring", keyring, "--output", tmp / "bad-signature",
            "--ca-file", tmp / "cert.pem", status=4)
        assert not (tmp / "bad-signature").exists()
        release.write_bytes(signed_release)

        release.write_text("Suite: stable\nValid-Until: Mon, 01 Jan 2024 00:00:00 UTC\n"
                           "SHA256:\n"
                           f" {hashlib.sha256(packages.read_bytes()).hexdigest()} "
                           f"{packages.stat().st_size} main/binary-all/Packages.gz\n")
        subprocess.run(["gpg", "--homedir", str(gnupg), "--batch", "--yes",
                        "--detach-sign", "--output", str(signed_dir / "Release.gpg"),
                        str(release)], capture_output=True, check=True)
        run("apt", "sync-signed", base, "stable", "main", "all", "--source", "debian",
            "--keyring", keyring, "--output", tmp / "expired",
            "--ca-file", tmp / "cert.pem", status=4)
        assert not (tmp / "expired").exists()
        release.write_text("Suite: testing\nSHA256:\n"
                           f" {hashlib.sha256(packages.read_bytes()).hexdigest()} "
                           f"{packages.stat().st_size} main/binary-all/Packages.gz\n")
        subprocess.run(["gpg", "--homedir", str(gnupg), "--batch", "--yes",
                        "--detach-sign", "--output", str(signed_dir / "Release.gpg"),
                        str(release)], capture_output=True, check=True)
        run("apt", "sync-signed", base, "stable", "main", "all", "--source", "debian",
            "--keyring", keyring, "--output", tmp / "wrong-suite",
            "--ca-file", tmp / "cert.pem", status=4)
        assert not (tmp / "wrong-suite").exists()
        release.write_bytes(signed_release)
        subprocess.run(["gpg", "--homedir", str(gnupg), "--batch", "--yes",
                        "--detach-sign", "--output", str(signed_dir / "Release.gpg"),
                        str(release)], capture_output=True, check=True)

        root = tmp / "root"
        root.mkdir()
        run("db", "init", "--root", root)
        config = tmp / "holy.conf"

        def register(alias, url):
            config.write_text(f"[source {alias}]\ntype apt\nurl \"{url}\"\n"
                              f"trust require\npublic-key \"{keyring}\"\n")
            plan = run("source", "plan", "--config", config, "--root", root)
            plan_path = tmp / "plan"
            plan_path.write_text(plan)
            run("source", "apply", plan_path, "--sha256",
                hashlib.sha256(plan_path.read_bytes()).hexdigest(), "--root", root)

        register("debian", base)
        bound = tmp / "bound"
        run("apt", "sync-source", "debian", "stable", "main", "all",
            "--root", root, "--keyring", keyring, "--output", bound,
            "--ca-file", tmp / "cert.pem")
        binding = next((root / "var/lib/holypkg/apt-catalogs").iterdir())
        assert "fixture 1:2.0-3 all\n" == run(
            "apt", "search", "fixture", "--source", "debian", "--suite", "stable",
            "--component", "main", "--index-arch", "all", "--root", root)
        bound_record = binding.read_bytes()
        binding.write_bytes(bound_record + b"tamper\n")
        run("apt", "search", "fixture", "--source", "debian", "--suite", "stable",
            "--component", "main", "--index-arch", "all", "--root", root, status=6)
        binding.unlink()
        run("apt", "bind", "debian", "stable", "main", "all", bound,
            "--root", root)
        assert binding.exists()
        run("apt", "bind", "debian", "stable", "contrib", "all", bound,
            "--root", root, status=4)
        wrong_keyring = tmp / "wrong-keyring.gpg"
        wrong_keyring.write_bytes(b"wrong keyring")
        run("apt", "sync-source", "debian", "stable", "main", "all",
            "--root", root, "--keyring", wrong_keyring,
            "--output", tmp / "wrong-bound-key", "--ca-file", tmp / "cert.pem", status=4)
        assert not (tmp / "wrong-bound-key").exists()
        bound_info = run("apt", "info", "fixture", "--catalog", bound,
                         "--source", "debian", "--root", root)
        assert "source-binding checked\n" in bound_info
        inline_bound = tmp / "inline-bound"
        run("apt", "sync-source", "debian", "stable", "main", "all",
            "--root", root, "--keyring", keyring, "--output", inline_bound,
            "--ca-file", tmp / "cert.pem", "--inrelease", "--files")
        assert "verification inrelease-gpgv-user-key\n" in run(
            "apt", "info", "fixture", "--source", "debian", "--suite", "stable",
            "--component", "main", "--index-arch", "all", "--root", root)
        assert run("apt", "search", "/usr/share/fixture", "--file", "--source", "debian",
                   "--suite", "stable", "--component", "main", "--index-arch", "all",
                   "--root", root) == "fixture /usr/share/fixture\n"
        bound_required = tmp / "bound-required"
        run("apt", "fetch", "fixture", "1:2.0-3", "all", "--source", "debian",
            "--suite", "stable", "--component", "main", "--index-arch", "all",
            "--root", root, "--output", bound_required, "--ca-file", tmp / "cert.pem",
            "--import", "--require-file", "/usr/share/fixture")
        assert "file-provider verified-payload\n" in (bound_required / "selection").read_text()
        run("apt", "bind", "debian", "stable", "main", "all", bound,
            "--root", root)
        assert "source-id " in bound_info
        conversion = (bound / "conversion").read_text()
        (bound / "conversion").write_text("\n".join(
            line for line in conversion.splitlines() if not line.startswith("source-id ")) + "\n")
        run("apt", "info", "fixture", "--catalog", bound,
            "--source", "debian", "--root", root, status=4)
        (bound / "conversion").write_text(conversion)
        bound_package = tmp / "bound-package"
        run("apt", "fetch", "fixture", "1:2.0-3", "all", "--source", "debian",
            "--suite", "stable", "--component", "main", "--index-arch", "all",
            "--root", root, "--output", bound_package,
            "--ca-file", tmp / "cert.pem", "--import")
        assert "source-binding checked\n" in (bound_package / "selection").read_text()
        run("apt", "info", "fixture", "--catalog", signed,
            "--source", "debian", "--root", root, status=4)
        register("renamed", base)
        assert "source-binding checked\n" in run(
            "apt", "info", "fixture", "--catalog", bound,
            "--source", "renamed", "--root", root)
        assert "fixture 1:2.0-3 all\n" == run(
            "apt", "search", "fixture", "--source", "renamed", "--suite", "stable",
            "--component", "main", "--index-arch", "all", "--root", root)
        run("apt", "info", "fixture", "--catalog", bound,
            "--source", "debian", "--root", root, status=6)
        register("renamed", base + "other/")
        run("apt", "info", "fixture", "--catalog", bound,
            "--source", "renamed", "--root", root, status=4)
        run("apt", "search", "fixture", "--source", "renamed", "--suite", "stable",
            "--component", "main", "--index-arch", "all", "--root", root, status=6)
        config.write_text(f"[source broken]\ntype apt\n"
                          f"repo main \"{base}\"\ntrust require\npublic-key \"{keyring}\"\n")
        run("source", "plan", "--config", config, "--root", root, status=2)
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
        pinned_origin = origin(native[0])
        assert "verification pinned-unverified\n" in pinned_origin
        assert f"index-sha256 {hashlib.sha256(packages.read_bytes()).hexdigest()}\n" in pinned_origin
        assert f'source-url "{base}"\n' in pinned_origin
        direct = tmp / "direct-import"
        run("import", fetched / "original", "--source", "debian", "--format", "deb",
            "--output", direct)
        assert "verification unverified\n" in origin(next(direct.glob("*.holy")))
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
