#!/usr/bin/env python3
"""builds native recipe fixtures and inspects the produced .holy artifacts."""
import hashlib
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile


binary = str(Path(sys.argv[1]).resolve())


def run(*args, status=0):
    result = subprocess.run([binary, *map(str, args)], text=True, capture_output=True,
                           errors="replace")
    assert result.returncode == status, (args, result.returncode, result.stdout, result.stderr)
    return result.stdout


def read_metadata(artifact):
    contents = subprocess.run(["lz4", "-dc", str(artifact)], check=True,
                              capture_output=True).stdout
    with tarfile.open(fileobj=__import__("io").BytesIO(contents)) as archive:
        def read(name):
            return archive.extractfile(name).read().decode()
        names = sorted(member.name for member in archive.getmembers())
        return {name: read(name) for name in
                ("HOLY/meta", "HOLY/files", "HOLY/deps", "HOLY/provides", "HOLY/hooks",
                 "HOLY/origin", "HOLY/transform")}, names


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def main():
    for tool in ("lz4",):
        if not shutil.which(tool):
            print(f"{tool} required for recipe fixture", file=sys.stderr)
            return 6
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        out = root / "out"
        (out / "data").mkdir(parents=True)
        (out / "data" / "greeting").write_text("hello\n")

        # noarch data-only recipe, no steps at all
        write(root / "data.recipe", """format holy-recipe-1
name holy-recipe-data
version 1.0
release 1
arch noarch
libc nolibc
summary Recipe data fixture
output holy-recipe-data runtime
config etc/holy-recipe-data.conf
step package /bin/sh <<PACKAGE
mkdir -p "$HOLY_DEST/usr/share/holy-recipe-data" "$HOLY_DEST/etc"
printf 'greeting\\n' > "$HOLY_DEST/usr/share/holy-recipe-data/greeting"
printf 'config\\n' > "$HOLY_DEST/etc/holy-recipe-data.conf"
ln -s greeting "$HOLY_DEST/usr/share/holy-recipe-data/current"
PACKAGE
""")
        log = run("build", root / "data.recipe", "--output", out / "data-out", "--yes")
        assert "built holy-recipe-data--noarch--nolibc" in log
        artifact = out / "data-out" / "holy-recipe-data--noarch--nolibc.holy"
        metadata, names = read_metadata(artifact)
        assert 'name "holy-recipe-data"' in metadata["HOLY/meta"]
        assert 'arch "noarch"' in metadata["HOLY/meta"] and 'libc "nolibc"' in metadata["HOLY/meta"]
        assert "x-version-family holy" in metadata["HOLY/meta"]
        assert "installed-size 16" in metadata["HOLY/meta"]
        assert "format holy-recipe-origin-1" in metadata["HOLY/origin"]
        assert "greeting" in metadata["HOLY/files"]
        assert "config" in metadata["HOLY/files"]
        assert "build-environment recorded" in metadata["HOLY/transform"]
        assert "HOLY/foreign" not in " ".join(names)

        # a compiled payload: the scanner derives arch, libc and soname requirements
        write(root / "lib.recipe", """format holy-recipe-1
name holy-recipe-lib
version 2.1
release 3
arch x86_64
libc glibc
summary Recipe library fixture
build-depend cmd:make
depend holy-recipe-data
output holy-recipe-lib runtime
output holy-recipe-lib-doc docs
split holy-recipe-lib-doc usr/share/*
step build /bin/sh <<BUILD
printf '%s\\n' \\
  'int holy(void) { return 7; }' > lib.c
gcc -shared -fPIC -Wl,-soname,libholyrecipe.so.1 -o libholyrecipe.so.1 lib.c
BUILD
step package /bin/sh <<PACKAGE
mkdir -p "$HOLY_DEST/usr/lib" "$HOLY_DEST/usr/share/holy-recipe-lib"
cp -a "$HOLY_BUILD/libholyrecipe.so.1" "$HOLY_DEST/usr/lib/"
ln -s libholyrecipe.so.1 "$HOLY_DEST/usr/lib/libholyrecipe.so"
printf 'docs\\n' > "$HOLY_DEST/usr/share/holy-recipe-lib/README"
PACKAGE
""")
        log = run("build", root / "lib.recipe", "--output", out / "lib-out", "--yes")
        assert "built holy-recipe-lib--x86_64--glibc" in log
        assert "built holy-recipe-lib-doc--noarch--nolibc" in log
        library = out / "lib-out" / "holy-recipe-lib--x86_64--glibc.holy"
        docs = out / "lib-out" / "holy-recipe-lib-doc--noarch--nolibc.holy"
        library_meta, _ = read_metadata(library)
        docs_meta, _ = read_metadata(docs)
        assert 'arch "x86_64"' in library_meta["HOLY/meta"]
        assert 'libc "glibc"' in library_meta["HOLY/meta"]
        assert 'provide soname "libholyrecipe.so.1"' in library_meta["HOLY/provides"]
        assert "libc.so.6" in library_meta["HOLY/deps"]
        assert '"package" "holy-recipe-data"' in library_meta["HOLY/deps"]
        assert "libholyrecipe.so.1" in library_meta["HOLY/files"]
        assert 'symlink "usr/lib/libholyrecipe.so"' in library_meta["HOLY/files"]
        assert '"libholyrecipe.so.1"' in library_meta["HOLY/files"]
        assert "usr/lib" in library_meta["HOLY/files"]
        assert "README" in docs_meta["HOLY/files"]
        assert "libholyrecipe" not in docs_meta["HOLY/files"]

        # a runtime hook needs its script in the payload and a recorded digest
        write(root / "hook.recipe", """format holy-recipe-1
name holy-recipe-hook
version 1.0
release 1
arch noarch
libc nolibc
summary Recipe hook fixture
output holy-recipe-hook runtime
hook-install /bin/sh usr/share/holy-recipe-hook/hook.sh
step package /bin/sh <<PACKAGE
mkdir -p "$HOLY_DEST/usr/share/holy-recipe-hook"
printf '#!/bin/sh\\nexit 0\\n' > "$HOLY_DEST/usr/share/holy-recipe-hook/hook.sh"
chmod 0755 "$HOLY_DEST/usr/share/holy-recipe-hook/hook.sh"
printf 'data\\n' > "$HOLY_DEST/usr/share/holy-recipe-hook/data"
PACKAGE
""")
        run("build", root / "hook.recipe", "--output", out / "hook-out", "--yes")
        hook_meta, _ = read_metadata(out / "hook-out" / "holy-recipe-hook--noarch--nolibc.holy")
        assert 'hook postinstall "/bin/sh" "usr/share/holy-recipe-hook/hook.sh" sha256' in \
            hook_meta["HOLY/hooks"]

        # review gates: unreviewed steps need approval, failures are visible
        run("build", root / "data.recipe", "--output", out / "review", "--noninteractive",
            status=3)
        write(root / "fail.recipe", """format holy-recipe-1
name holy-recipe-fail
version 1.0
release 1
arch noarch
libc nolibc
output holy-recipe-fail runtime
step package /bin/sh <<PACKAGE
exit 4
PACKAGE
""")
        run("build", root / "fail.recipe", "--output", out / "fail-out", "--yes", status=1)

        # manifest rules: unknown keys, unknown phases, unpinned network sources
        write(root / "unknown.recipe", """format holy-recipe-1
name holy-recipe-unknown
version 1.0
release 1
arch noarch
libc nolibc
output holy-recipe-unknown runtime
mystery field
""")
        run("build", root / "unknown.recipe", "--output", out / "unknown", "--yes", status=2)
        write(root / "phase.recipe", """format holy-recipe-1
name holy-recipe-phase
version 1.0
release 1
arch noarch
libc nolibc
output holy-recipe-phase runtime
step package /bin/sh <<PACKAGE
exit 0
NOT_TERMINATED
""")
        run("build", root / "phase.recipe", "--output", out / "phase", "--yes", status=2)
        write(root / "unpinned.recipe", """format holy-recipe-1
name holy-recipe-unpinned
version 1.0
release 1
arch noarch
libc nolibc
output holy-recipe-unpinned runtime
source data https://example.invalid/data.tar.xz
step package /bin/sh <<PACKAGE
exit 0
PACKAGE
""")
        run("build", root / "unpinned.recipe", "--output", out / "unpinned", "--yes", status=2)
        run("build", root / "data.recipe", "--output", out / "vm", "--environment", "vm",
            status=6)

        # a local source with a verified digest is fetched by the engine
        local = root / "payload.txt"
        local.write_text("payload\n")
        digest = hashlib.sha256(local.read_bytes()).hexdigest()
        write(root / "local.recipe", f"""format holy-recipe-1
name holy-recipe-local
version 1.0
release 1
arch noarch
libc nolibc
summary Local source fixture
output holy-recipe-local runtime
source data payload.txt
source-sha256 data {digest}
step package /bin/sh <<PACKAGE
mkdir -p "$HOLY_DEST/usr/share/holy-recipe-local"
cp -a "$HOLY_SRC/data" "$HOLY_DEST/usr/share/holy-recipe-local/payload.txt"
PACKAGE
""")
        log = run("build", root / "local.recipe", "--output", out / "local-out", "--yes")
        assert f"fetched data sha256 {digest}" in log
        local_meta, _ = read_metadata(out / "local-out" / "holy-recipe-local--noarch--nolibc.holy")
        assert f"sha256 {digest}" in local_meta["HOLY/origin"]

        # the built artifact passes the normal local install path
        installed = root / "target"
        installed.mkdir()
        run("db", "init", "--root", installed)
        data_artifact = out / "data-out" / "holy-recipe-data--noarch--nolibc.holy"
        staged = run("cache", "stage", "local:" + str(data_artifact), "--root", installed)
        sha = hashlib.sha256(data_artifact.read_bytes()).hexdigest()
        assert sha in staged
        plan = run("db", "plan-set", sha, "--root", installed)
        plan_hash = plan.split("sha256 ")[1].split()[0]
        run("db", "apply-set", plan_hash, sha, "--root", installed)
        run("db", "check", sha, "--root", installed)
        assert (installed / "usr/share/holy-recipe-data/greeting").is_file()
        assert (installed / "usr/share/holy-recipe-data/current").is_symlink()
        owner = run("owner", "/usr/share/holy-recipe-data/greeting", "--root", installed)
        assert sha[:16] in owner or "greeting" in owner
        # the glibc-linked library needs its soname provider before installation
        run("cache", "stage", "local:" + str(library), "--root", installed)
        library_sha = hashlib.sha256(library.read_bytes()).hexdigest()
        run("db", "plan-set", library_sha, "--root", installed, status=4)
    return 0


if __name__ == "__main__":
    sys.exit(main())
