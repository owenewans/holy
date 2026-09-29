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


def metadata(entries):
    body = []
    for name, evr, arch, package, href, provides in entries:
        version = f'<version epoch="{evr[0]}" ver="{evr[1]}" rel="{evr[2]}"/>'
        offered = "".join(f'<rpm:entry name="{item}"/>' for item in provides)
        section = f"<rpm:provides>{offered}</rpm:provides>" if offered else ""
        body.append(f'''  <package type="rpm"><name>{name}</name><arch>{arch}</arch>
    {version}
    <checksum type="sha256" pkgid="YES">{sha(package)}</checksum>
    <size package="{len(package)}"/>
    <location href="{href}"/>
    {section}
  </package>''')
    primary = (f'''<?xml version="1.0"?>
<metadata xmlns="http://linux.duke.edu/metadata/common"
          xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="{len(entries)}">
{chr(10).join(body)}
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
        provider = module.build_provider(root, "1.3").read_bytes()
        serve = root / "serve"
        (serve / "repodata").mkdir(parents=True)
        (serve / "Packages").mkdir()
        filename = "holy-rpm-fixture-1.0-1.noarch.rpm"
        href = "Packages/" + filename
        (serve / href).write_bytes(package)
        provider_href = "Packages/holy-rpm-provider-1.3-1.noarch.rpm"
        (serve / provider_href).write_bytes(provider)
        repomd, primary = metadata([
            ("holy-rpm-fixture", ("0", "1.0", "1"), "noarch", package, href,
             ["holy-rpm-fixture", "sample-lib"]),
            ("holy-rpm-provider", ("0", "1.3", "1"), "noarch", provider,
             provider_href, ["holy-rpm-provider", "sample-lib"]),
        ])
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
            # exact capability lookup over the primary provides index
            listed = run("rpm", "providers", "sample-lib", "--catalog", catalog)
            assert "candidate holy-rpm-fixture 1.0-1 noarch" in listed
            assert "candidate holy-rpm-provider 1.3-1 noarch" in listed
            assert "listed 2 candidates" in listed
            assert "listed 0 candidates" in run("rpm", "providers", "libabsent.so.1",
                                                "--catalog", catalog)
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

            # registered source flow: plan, apply, sync, bound query, bound fetch
            target = root / "target"
            target.mkdir()
            run("db", "init", "--root", target)
            config = root / "holy.conf"
            config.write_text(
                "[source fixture]\ntype rpm-md\n"
                f"url \"{base}\"\n")
            plan = root / "source.plan"
            plan.write_text(run("source", "plan", "--config", config, "--root", target))
            run("source", "apply", plan, "--sha256", sha(plan.read_bytes()), "--root", target)
            assert "fixture" in run("source", "list", "--root", target)
            run("sync", "fixture", "--sha256", pinned, "--output", root / "bound",
                "--root", target, "--ca-file", root / "cert.pem")
            assert "holy-rpm-fixture 1.0-1 noarch" in run(
                "search", "fixture", "--source", "fixture", "--root", target)
            assert "candidate holy-rpm-provider 1.3-1 noarch" in run(
                "rpm", "providers", "sample-lib", "--source", "fixture", "--root", target)
            assert sha(package) in run("info", "fixture:holy-rpm-fixture", "--root", target)
            bound = root / "bound-fetch"
            run("fetch", "fixture:holy-rpm-fixture", "--version", "1.0-1",
                "--arch", "noarch", "--output", bound, "--root", target,
                "--ca-file", root / "cert.pem", "--import")
            assert (bound / "converted/holy-rpm-fixture--noarch--nolibc.holy").is_file()
            # a source change invalidates the binding; queries report it as unavailable
            config.write_text(
                "[source fixture]\ntype rpm-md\n"
                f"url \"{base}other/\"\n")
            # trust require is unavailable: this backend pins a hash, not a signature
            config.write_text(
                "[source fixture]\ntype rpm-md\n"
                f"url \"{base}\"\ntrust require\n")
            rejected = root / "require.plan"
            rejected.write_text(run("source", "plan", "--config", config, "--root", target,
                                    status=2))
            config.write_text(
                "[source fixture]\ntype rpm-md\n"
                f"url \"{base}other/\"\n")
            moved = root / "moved.plan"
            moved.write_text(run("source", "plan", "--config", config, "--root", target))
            run("source", "apply", moved, "--sha256", sha(moved.read_bytes()),
                "--root", target)
            run("search", "fixture", "--source", "fixture", "--root", target, status=6)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
    return 0


if __name__ == "__main__":
    sys.exit(main())
