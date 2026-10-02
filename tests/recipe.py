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
        assert "build-environment host" in metadata["HOLY/transform"]
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

        # the clean environment runs each step in its own user, mount and network
        # namespace, with the host toolchain read-only and the build root writable
        clean_work = root / "clean-work"
        clean_work.mkdir()
        write(root / "clean.recipe", """format holy-recipe-1
name holy-recipe-clean
version 1.0
release 1
arch noarch
libc nolibc
summary Clean environment fixture
output holy-recipe-clean runtime
config etc/holy-recipe-clean.conf
step package /bin/sh <<PACKAGE
mkdir -p "$HOLY_DEST/usr/share/holy-recipe-clean" "$HOLY_DEST/etc"
test -x /bin/sh || exit 20
test ! -w /usr || exit 21
test -z "${HOME-}" || exit 22
printf 'clean\n' > "$HOLY_DEST/usr/share/holy-recipe-clean/value"
printf 'config\n' > "$HOLY_DEST/etc/holy-recipe-clean.conf"
printf '%s\n' "$(id -u)" > "$HOLY_OUT/uid"
printf '%s\n' "${FIXTURE_VAR:-unset}" > "$HOLY_OUT/var"
printf '%s\n' "$(test -r /mnt/fixture/marker && echo yes || echo no)" > "$HOLY_OUT/mount"
ls -A / > "$HOLY_OUT/listing"
ulimit -n > "$HOLY_OUT/open-files"
PACKAGE
""")
        mount_source = root / "fixture-mount"
        mount_source.mkdir()
        (mount_source / "marker").write_text("mounted\n")
        log = run("build", root / "clean.recipe", "--output", out / "clean-out",
                  "--environment", "clean", "--work", clean_work, "--keep", "--yes",
                  "--env", "FIXTURE_VAR=declared",
                  "--mount", f"{mount_source}:/mnt/fixture",
                  "--limit", "open-files=256", "--limit", "cpu=120")
        assert "build-environment root" in log
        assert f"uid {os.getuid()}" in log
        assert "network none" in log and "read-only 6" in log
        assert "mounts 1" in log and "devices 5" in log and "limits 2" in log
        clean_meta, _ = read_metadata(out / "clean-out" / "holy-recipe-clean--noarch--nolibc.holy")
        assert "build-environment root" in clean_meta["HOLY/transform"]
        assert "network none" in clean_meta["HOLY/transform"]
        # a step runs as the caller's own id inside the namespace, so a file it wrote is
        # owned by the caller and the step holds no privilege over the running system
        assert (clean_work / "out" / "uid").read_text().strip() == str(os.getuid())
        assert (clean_work / "out" / "uid").stat().st_uid == os.getuid()
        assert (clean_work / "out" / "var").read_text().strip() == "declared"
        assert (clean_work / "out" / "mount").read_text().strip() == "yes"
        assert int((clean_work / "out" / "open-files").read_text().strip()) == 256
        listing = set((clean_work / "out" / "listing").read_text().split())
        assert {"bin", "etc", "lib", "lib64", "sbin", "tmp", "usr", "mnt"} <= listing
        # the host home, /root and /proc are not in the root, so a step sees only what it
        # was given plus the build root
        assert "root" not in listing and "proc" not in listing and "srv" not in listing
        assert not (clean_work / "env" / "root").exists()
        # a declared dependency becomes a private root the step finds on PATH, so the
        # recipe runs a tool the host toolchain does not provide
        write(root / "tool.c", """#include <stdio.h>
int main(void) { return puts("built-by-dependency") < 0; }
""")
        subprocess.run(["gcc", "-o", str(root / "holy-recipe-tool"), str(root / "tool.c")],
                       check=True)
        loader = run("elf", root / "holy-recipe-tool").split("interpreter ", 1)[1].split()[0]
        assert loader.startswith("/")
        for name, files in (("holy-recipe-dep", {"usr/bin/holy-recipe-tool": root / "holy-recipe-tool"}),
                            ("holy-recipe-runtime", {
                                # both sit in the loader search path, since a soname the
                                # loader cannot reach is not a provider
                                loader.lstrip("/"): Path("/") / loader.lstrip("/"),
                                loader.lstrip("/").rsplit("/", 1)[0] + "/libc.so.6":
                                    Path(subprocess.run(["gcc", "-print-file-name=libc.so.6"],
                                                        text=True, capture_output=True,
                                                        check=True).stdout.strip())})):
            tree = root / f"tree-{name}"
            (tree / "HOLY").mkdir(parents=True)
            write(tree / "HOLY" / "meta",
                  f"format holy-package-1\nname {name}\nversion 1\nrelease 1\nos linux\n"
                  "arch x86_64\nlibc glibc\n")
            for part in ("deps", "provides", "hooks", "origin", "transform"):
                (tree / "HOLY" / part).write_text("")
            for path, source in files.items():
                target = tree / "DATA" / path
                target.parent.mkdir(parents=True, exist_ok=True)
                subprocess.run(["cp", "-L", str(source), str(target)], check=True)
            generated = run("manifest", "generate", tree,
                            "--output", out / f"{name}.files").split()
            (tree / "HOLY" / "files").write_text(Path(generated[1]).read_text())
            run("pack", tree, "--output", out / f"{name}.holy")
        dependency = out / "holy-recipe-dep.holy"
        runtime = out / "holy-recipe-runtime.holy"
        dependency_sha = hashlib.sha256(dependency.read_bytes()).hexdigest()
        runtime_sha = hashlib.sha256(runtime.read_bytes()).hexdigest()
        write(root / "dep.recipe", """format holy-recipe-1
name holy-recipe-depuser
version 1.0
release 1
arch noarch
libc nolibc
summary Declared dependency fixture
output holy-recipe-depuser runtime
build-depend cmd:holy-recipe-tool
step package /bin/sh <<PACKAGE
mkdir -p "$HOLY_DEST/usr/share/holy-recipe-depuser"
holy-recipe-tool > "$HOLY_DEST/usr/share/holy-recipe-depuser/tool-output"
printf '%s\n' "$PATH" > "$HOLY_OUT/path"
printf '%s\n' "$(test -w /deps && echo yes || echo no)" > "$HOLY_OUT/deps-write"
PACKAGE
""")
        dep_work = root / "dep-work"
        dep_work.mkdir()
        log = run("build", root / "dep.recipe", "--output", out / "dep-out",
                  "--environment", "clean", "--work", dep_work, "--keep", "--yes",
                  "--dependency", "local:" + str(dependency),
                  "--dependency", "local:" + str(runtime))
        assert "deps declared" in log
        assert f"build-dependency {dependency_sha} installed" in log
        assert f"build-dependency {runtime_sha} installed" in log
        assert (f"build-depend-satisfied cmd:holy-recipe-tool {dep_work}/deps/usr/bin/"
                "holy-recipe-tool") in log
        dep_meta, _ = read_metadata(out / "dep-out" / "holy-recipe-depuser--noarch--nolibc.holy")
        assert "deps declared" in dep_meta["HOLY/transform"]
        assert (f"build-depend-satisfied cmd:holy-recipe-tool {dep_work}/deps/usr/bin/"
                "holy-recipe-tool") in dep_meta["HOLY/transform"]
        step_path = (dep_work / "out" / "path").read_text().strip()
        assert step_path == f"{dep_work}/deps/usr/bin:{dep_work}/deps/bin:/usr/bin:/bin"
        # the dependency root is a read-only mount, so a step uses the tool and cannot
        # replace it
        assert (dep_work / "out" / "deps-write").read_text().strip() == "no"
        tool_output = out / "dep-out" / "holy-recipe-depuser--noarch--nolibc.holy"
        contents = subprocess.run(["lz4", "-dc", str(tool_output)], check=True,
                                  capture_output=True).stdout
        with tarfile.open(fileobj=__import__("io").BytesIO(contents)) as archive:
            assert archive.extractfile(
                "DATA/usr/share/holy-recipe-depuser/tool-output").read() == b"built-by-dependency\n"
        # a declared dependency nothing provides is refused before a step runs, and the
        # missing provider is named
        missing_work = root / "dep-missing-work"
        missing_work.mkdir()
        error = run("build", root / "dep.recipe", "--output", out / "dep-missing",
                    "--environment", "clean", "--work", missing_work, "--keep", "--yes",
                    "--dependency", "local:" + str(runtime), status=6)
        assert "declared build dependency cmd:holy-recipe-tool has no provider" not in error
        run("build", root / "dep.recipe", "--output", out / "dep-missing",
            "--environment", "clean", "--work", missing_work, "--keep", "--yes",
            "--dependency", "local:" + str(runtime), status=6)
        # a package dependency is satisfied by an installed artifact of that name, not by
        # a file on PATH
        write(root / "dep-pkg.recipe", """format holy-recipe-1
name holy-recipe-deppkg
version 1.0
release 1
arch noarch
libc nolibc
summary Package dependency fixture
output holy-recipe-deppkg runtime
build-depend holy-recipe-runtime
step package /bin/sh <<PACKAGE
mkdir -p "$HOLY_DEST/usr/share/holy-recipe-deppkg"
printf 'pkg\n' > "$HOLY_DEST/usr/share/holy-recipe-deppkg/value"
PACKAGE
""")
        pkg_work = root / "dep-pkg-work"
        pkg_work.mkdir()
        log = run("build", root / "dep-pkg.recipe", "--output", out / "dep-pkg",
                  "--environment", "clean", "--work", pkg_work, "--keep", "--yes",
                  "--dependency", "local:" + str(runtime))
        assert f"build-depend-satisfied holy-recipe-runtime {pkg_work}/deps" in log
        assert (out / "dep-pkg" / "holy-recipe-deppkg--noarch--nolibc.holy").is_file()
        unsatisfied_work = root / "dep-unsatisfied-work"
        unsatisfied_work.mkdir()
        run("build", root / "dep-pkg.recipe", "--output", out / "dep-pkg",
            "--environment", "clean", "--work", unsatisfied_work, "--keep", "--yes",
            "--dependency", "local:" + str(dependency), status=6)
        # the host environment has no build root, so a declared command the host does not
        # carry is reported before a step
        host_work = root / "dep-host-work"
        host_work.mkdir()
        run("build", root / "dep.recipe", "--output", out / "dep-host",
            "--work", host_work, "--keep", "--yes", status=6)
        write(root / "host-cmd.recipe", """format holy-recipe-1
name holy-recipe-hostcmd
version 1.0
release 1
arch noarch
libc nolibc
summary Host command fixture
build-depend cmd:sh
output holy-recipe-hostcmd runtime
step package /bin/sh <<PACKAGE
mkdir -p "$HOLY_DEST/usr/share/holy-recipe-hostcmd"
printf 'sh\n' > "$HOLY_DEST/usr/share/holy-recipe-hostcmd/value"
PACKAGE
""")
        log = run("build", root / "host-cmd.recipe", "--output", out / "host-cmd",
                  "--work", host_work, "--yes")
        assert "build-depend-satisfied cmd:sh host /" in log
        # a library the dependency root carries reaches a step that runs a tool from it,
        # since the loader names the paths the root itself holds
        write(root / "lib.c", "int helper(void) { return 41; }\n")
        write(root / "app.c", """#include <stdio.h>
int helper(void);
int main(void) { return printf("helper=%d\\n", helper()) > 0 ? 0 : 1; }
""")
        subprocess.run(["gcc", "-shared", "-fPIC", "-Wl,-soname,libholyrecipe.so.1",
                        "-o", str(root / "libholyrecipe.so.1"), str(root / "lib.c")],
                       check=True)
        subprocess.run(["gcc", "-o", str(root / "libapp"), str(root / "app.c"),
                        f"-L{root}", "-l:libholyrecipe.so.1"], check=True)
        lib_tree = root / "tree-holy-recipe-libdep"
        (lib_tree / "HOLY").mkdir(parents=True)
        write(lib_tree / "HOLY" / "meta", """format holy-package-1
name holy-recipe-libdep
version 1
release 1
os linux
arch x86_64
libc glibc
""")
        for part in ("deps", "provides", "hooks", "origin", "transform"):
            (lib_tree / "HOLY" / part).write_text("")
        (lib_tree / "DATA" / "usr" / "lib").mkdir(parents=True)
        (lib_tree / "DATA" / "usr" / "bin").mkdir(parents=True)
        subprocess.run(["cp", str(root / "libholyrecipe.so.1"),
                        str(lib_tree / "DATA" / "usr" / "lib")], check=True)
        subprocess.run(["ln", "-s", "libholyrecipe.so.1",
                        str(lib_tree / "DATA" / "usr" / "lib" / "libholyrecipe.so")],
                       check=True)
        subprocess.run(["cp", str(root / "libapp"),
                        str(lib_tree / "DATA" / "usr" / "bin" / "holy-recipe-libapp")],
                       check=True)
        generated = run("manifest", "generate", lib_tree,
                        "--output", out / "libdep.files").split()
        (lib_tree / "HOLY" / "files").write_text(Path(generated[1]).read_text())
        run("pack", lib_tree, "--output", out / "holy-recipe-libdep.holy")
        write(root / "libdep.recipe", """format holy-recipe-1
name holy-recipe-libuser
version 1.0
release 1
arch noarch
libc nolibc
summary Library dependency fixture
output holy-recipe-libuser runtime
build-depend cmd:holy-recipe-libapp
step package /bin/sh <<PACKAGE
mkdir -p "$HOLY_DEST/usr/share/holy-recipe-libuser"
holy-recipe-libapp > "$HOLY_DEST/usr/share/holy-recipe-libuser/app-output"
printf '%s\n' "$LD_LIBRARY_PATH" > "$HOLY_OUT/library-path"
PACKAGE
""")
        lib_work = root / "libdep-work"
        lib_work.mkdir()
        run("build", root / "libdep.recipe", "--output", out / "libdep-out",
            "--environment", "clean", "--work", lib_work, "--keep", "--yes",
            "--dependency", "local:" + str(out / "holy-recipe-libdep.holy"),
            "--dependency", "local:" + str(runtime))
        library_path = (lib_work / "out" / "library-path").read_text().strip()
        assert f"{lib_work}/deps/usr/lib" in library_path
        contents = subprocess.run(
            ["lz4", "-dc", str(out / "libdep-out" / "holy-recipe-libuser--noarch--nolibc.holy")],
            check=True, capture_output=True).stdout
        with tarfile.open(fileobj=__import__("io").BytesIO(contents)) as archive:
            assert archive.extractfile(
                "DATA/usr/share/holy-recipe-libuser/app-output").read() == b"helper=41\n"
        # the dependency root belongs to the clean environment only
        run("build", root / "dep.recipe", "--output", out / "dep-host",
            "--work", dep_work, "--keep", "--yes",
            "--dependency", "local:" + str(dependency), status=2)
        run("build", root / "dep.recipe", "--output", out / "dep-host",
            "--environment", "clean", "--work", missing_work, "--keep", "--yes",
            "--dependency", str(dependency), status=2)
        absent_work = root / "dep-absent-work"
        absent_work.mkdir()
        run("build", root / "dep.recipe", "--output", out / "dep-host",
            "--environment", "clean", "--work", absent_work, "--keep", "--yes",
            "--dependency", "local:" + str(root / "absent.holy"), status=6)
        # a step that writes into a read-only host directory fails, so the environment is
        # a boundary rather than a different working directory
        write(root / "clean-ro.recipe", """format holy-recipe-1
name holy-recipe-clean-ro
version 1.0
release 1
arch noarch
libc nolibc
summary Read-only fixture
output holy-recipe-clean-ro runtime
step package /bin/sh <<PACKAGE
mkdir -p "$HOLY_DEST/usr/share/x"
printf 'x\n' > "$HOLY_DEST/usr/share/x/value"
printf 'nope\n' > /usr/holy-wrote-here 2>/dev/null || exit 21
PACKAGE
""")
        read_only_work = root / "clean-ro-work"
        read_only_work.mkdir()
        run("build", root / "clean-ro.recipe", "--output", out / "clean-ro",
            "--environment", "clean", "--work", read_only_work, "--yes", status=21)
        assert not Path("/usr/holy-wrote-here").exists()
        # every parameter is explicit, so a malformed one is an argument error
        for bad in (("--uid", "zero"), ("--network", "off"), ("--device", "null"),
                    ("--mount", f"{mount_source}/mnt/fixture"),
                    ("--mount", f"{mount_source}:/mnt/fixture:ro"),
                    ("--limit", "cpu=0"), ("--limit", "cpu"),
                    ("--limit", "names=1"), ("--env", "1BAD=x"), ("--env", "NAMESET"),
                    ("--env", "NAME=")):
            run("build", root / "data.recipe", "--output", out / "bad",
                "--environment", "clean", "--work", clean_work, "--yes",
                *sum(([k, v] for k, v in [bad]), []), status=2)
        run("build", root / "data.recipe", "--output", out / "bad",
            "--environment", "trial", status=2)
        # a writable mount of the build root would name the same tree twice, since the
        # root already carries it writable
        run("build", root / "data.recipe", "--output", out / "bad",
            "--environment", "clean", "--work", clean_work, "--yes",
            "--mount", f"{clean_work}:/mnt/again:rw", status=2)
        # a mount source that does not exist is a report rather than a silent empty mount
        run("build", root / "data.recipe", "--output", out / "bad",
            "--environment", "clean", "--work", clean_work, "--yes",
            "--mount", "/nonexistent-mount-source:/mnt/fixed", status=126)
    return 0


if __name__ == "__main__":
    sys.exit(main())
