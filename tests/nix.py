#!/usr/bin/env python3
"""converts a captured Nix closure into one package per store path, and proves a
shared store path survives one of the two applications that require it."""
import hashlib
import pathlib
import shutil
import subprocess
import sys
import tempfile


binary = str(pathlib.Path(sys.argv[1]).resolve())


def call(*args, status=0):
    result = subprocess.run([binary, *map(str, args)], capture_output=True, text=True)
    assert result.returncode == status, (args, result.returncode, result.stdout, result.stderr)
    return result.stdout


# a Nix store hash is base32 over an alphabet without e, o, t and u, so each fixture
# digest is spelled from that alphabet rather than from a hex digest
def store_hash(seed):
    alphabet = "0123456789abcdfghijklmnpqrsvwxyz"
    return "".join(alphabet[(seed * step * step + step * 3) % 32] for step in range(1, 33))


LIBRARY = store_hash(3)
HELLO = store_hash(9)
TOOL = store_hash(15)
OUTSIDE = store_hash(21)


def store_path(root, digest, name, files):
    """one store path of the capture, as a directory beside the capture file. a program
    under bin is executable and carries a shebang, so the scanner reads it as a script
    that needs an interpreter rather than as an executable of an unknown format"""
    path = root / f"{digest}-{name}"
    for relative, body in files.items():
        target = path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        program = relative.startswith("bin/")
        if program and not body.startswith("#!"):
            body = "#!/bin/sh\n" + body
        target.write_text(body)
        target.chmod(0o755 if program else 0o644)
    return path


def symlinks(root, digest, name, entries):
    path = root / f"{digest}-{name}"
    for relative, target in entries.items():
        link = path / relative
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target)


def capture(root, body):
    path = root / "closure.capture"
    path.write_text(body)
    return path


def main():
    with tempfile.TemporaryDirectory() as scratch:
        root = pathlib.Path(scratch)

        # the object two applications share, the two applications themselves, and a
        # store path the capture declares a reference to without carrying it. the object
        # is the payload file a store path carries and the closure this fixture proves
        # is the graph of it, since the ABI linking case has its own fixture
        store_path(root, LIBRARY, "libfixture-1.0", {
            "lib/libfixture.so.1": f"the object both applications need: {LIBRARY}-libfixture-1.0\n",
            "include/libfixture.h": "the header the object was built from\n",
        })
        symlinks(root, LIBRARY, "libfixture-1.0", {"lib/libfixture.so": "libfixture.so.1"})
        store_path(root, HELLO, "hello-2.0", {
            "bin/hello": f"a program that names the object it needs: {LIBRARY}-libfixture-1.0\n",
            "share/doc/hello/README": "the documentation of the program\n",
        })
        store_path(root, TOOL, "tool-3.0", {
            "bin/tool": f"another program naming the same object: {LIBRARY}-libfixture-1.0\n",
        })
        store_path(root, OUTSIDE, "runtime-1.0", {
            "lib/libruntime.so.1": "a runtime the capture does not carry into the packages\n",
        })

        text = "\n".join([
            "# a captured closure: the output root, its store paths and the references",
            f"root {LIBRARY}-libfixture-1.0",
            f"path {LIBRARY}-libfixture-1.0",
            f"path {HELLO}-hello-2.0",
            f"path {TOOL}-tool-3.0",
            f"entry {HELLO}-hello-2.0 bin/hello",
            f"entry {TOOL}-tool-3.0 bin/tool",
            f"references {LIBRARY}-libfixture-1.0 {OUTSIDE}-runtime-1.0",
            f"references {HELLO}-hello-2.0 {LIBRARY}-libfixture-1.0",
            f"references {TOOL}-tool-3.0 {LIBRARY}-libfixture-1.0 {OUTSIDE}-runtime-1.0",
            "",
        ])
        path = capture(root, text)

        out = root / "converted"
        report = call("import", path, "--source", "nix", "--format", "nix", "--output", out,
                      status=3)
        # one native package per store path, each named for its own store path name
        for name in ("libfixture-1.0", "hello-2.0", "tool-3.0"):
            assert f"imported {name}--noarch--nolibc.holy store " in report, report
            assert (out / f"{name}--noarch--nolibc.holy").is_file(), sorted(
                p.name for p in out.iterdir())
        for artifact in out.glob("*.holy"):
            call("verify", "local:" + str(artifact))
            identity = call("info", "local:" + str(artifact))
            # Nix states no version, so the store hash is the identity of the package
            assert "version 0\n" in identity, identity
            assert "arch noarch\n" in identity and "libc nolibc\n" in identity, identity

        # the capture travels whole beside the packages it produced
        assert (out / "original").read_bytes() == path.read_bytes()
        package = (out / "package").read_text()
        assert "format holy-nix-closure-1\n" in package
        assert "status review-required\n" in package
        assert "package libfixture-1.0 store-path %s-libfixture-1.0 root" % LIBRARY in package
        assert f"capture {hashlib.sha256(path.read_bytes()).hexdigest()}" in package
        assert "Nix states no version, so every package records zero" in package
        # the shared object is a store path both applications name, not a copy each keeps
        assert "reference hello-2.0 -> %s-libfixture-1.0 inside" % LIBRARY in package
        assert "reference tool-3.0 -> %s-libfixture-1.0 inside" % LIBRARY in package
        # a store path the capture does not carry stays a requirement
        assert "reference tool-3.0 -> %s-runtime-1.0 outside" % OUTSIDE in package
        assert "package tool-3.0 " in package
        # the payload of each application names the object it needs, so the capture and
        # the payload agree about that edge, while the store path nothing names is
        # counted as unconfirmed rather than assumed
        assert "package hello-2.0 store-path" in package
        assert "package-references 1 unconfirmed 0 outside 0" in package
        assert "package-references 2 unconfirmed 1 outside 1" in package
        # nothing is executed and no store, daemon, profile or sandbox is promised
        assert "no Nix store, daemon, profile or sandbox is reproduced" in package
        assert "a view this manager does not build" in package
        # every record of this capture is read, so no record is left unmodelled
        assert "records of the capture this reader does not model" not in package, package

        requirements = call("requirements", "local:" + str(
            out / "hello-2.0--noarch--nolibc.holy"))
        assert 'require "nix-reference-0" "hello-2.0" "package" "libfixture-1.0"' in \
            requirements, requirements
        tool_requirements = call("requirements", "local:" + str(
            out / "tool-3.0--noarch--nolibc.holy"))
        assert 'require "nix-reference-0" "tool-3.0" "package" "libfixture-1.0"' in \
            tool_requirements, tool_requirements
        # the store path outside the capture is a requirement on its name, with the
        # store hash recorded as the identity the target has to satisfy
        assert 'require "nix-outside-1" "tool-3.0" "package" "runtime-1.0"' in \
            tool_requirements, tool_requirements
        assert f'"{OUTSIDE}" "nix-store-outside"' in tool_requirements, tool_requirements

        # each package carries its own store path whole under a private path
        listing = call("manifest", "local:" + str(out / "libfixture-1.0--noarch--nolibc.holy"))
        assert f"usr/lib/holy/private/libfixture-1.0/store/{LIBRARY}-libfixture-1.0/lib/" \
            "libfixture.so.1" in listing, listing
        # an absolute link target cannot travel in a payload, so the path it named is
        # a recorded file requirement rather than a dropped link
        entry_listing = call("manifest", "local:" + str(out / "hello-2.0--noarch--nolibc.holy"))
        assert "usr/lib/holy/private/hello-2.0/usr/bin/hello-2.0" in entry_listing, entry_listing
        assert "usr/bin/hello-2.0" in entry_listing, entry_listing

        # the store path outside the capture is a requirement a target has to satisfy, so
        # a set without a provider for it is refused rather than installed incomplete
        names = ["libfixture-1.0", "hello-2.0", "tool-3.0"]
        target = root / "target"
        (target / "usr/bin").mkdir(parents=True)
        call("db", "init", "--root", target)
        digests = []
        for name in names:
            artifact = out / f"{name}--noarch--nolibc.holy"
            digests.append(hashlib.sha256(artifact.read_bytes()).hexdigest())
            call("cache", "stage", "local:" + str(artifact), "--root", target)
        short = subprocess.run([binary, "db", "plan-set", digests[0], *digests[1:], "--root",
                                str(target)], capture_output=True, text=True)
        assert short.returncode == 4, short
        assert "nix-outside-0" in short.stderr, short.stderr
        assert not (target / "usr/lib/holy/private/libfixture-1.0").exists()

        # a native package that provides that store path name closes the requirement, and
        # a static shell is what the generated launchers need, so the shared object has
        # one owner and two dependents once the set is installed
        runtime_tree = root / "trees/runtime-1.0"
        (runtime_tree / "HOLY").mkdir(parents=True)
        runtime_file = runtime_tree / "DATA/usr/lib/holy/private/runtime-1.0/store/lib/libruntime.so.1"
        runtime_file.parent.mkdir(parents=True)
        runtime_file.write_text("a provider for the store path the capture does not carry\n")
        (runtime_tree / "DATA/bin").mkdir(parents=True)
        shell_source = root / "sh.c"
        shell_source.write_text("int main(void) { return 0; }\n")
        shell = None
        for compiler in ("cc", "gcc", "clang"):
            if not shutil.which(compiler):
                continue
            result = subprocess.run([compiler, "-static", str(shell_source), "-o", str(
                runtime_tree / "DATA/bin/sh")], capture_output=True, text=True)
            if result.returncode == 0:
                shell = True
                break
        assert shell, "a static shell is required for the launcher fixtures"
        (runtime_tree / "DATA/bin/sh").chmod(0o755)
        (runtime_tree / "HOLY/meta").write_text(
            "format holy-package-1\nname runtime-1.0\nversion 1\nrelease 1\nos linux\n"
            "arch x86_64\nlibc nolibc\n")
        for field in ("deps", "provides", "hooks", "origin", "transform"):
            (runtime_tree / "HOLY" / field).write_text("")
        # the store path the capture names is a package requirement, so the provider
        # has to state it
        (runtime_tree / "HOLY/provides").write_text(
            "provide package runtime-1.0 x86_64 nolibc - fixture\n")
        call("manifest", "generate", runtime_tree, "--output", root / "runtime-files")
        (runtime_tree / "HOLY/files").write_text((root / "runtime-files").read_text())
        call("pack", runtime_tree, "--output", root / "runtime.holy")
        digests.append(hashlib.sha256((root / "runtime.holy").read_bytes()).hexdigest())
        call("cache", "stage", "local:" + str(root / "runtime.holy"), "--root", target)
        private = target / f"usr/lib/holy/private/libfixture-1.0/store/{LIBRARY}-libfixture-1.0"
        # each application is a root of its own set, so the object they share is reached
        # once and the second set leaves the first installation alone
        for name in ("hello-2.0", "tool-3.0"):
            root_digest = digests[names.index(name)]
            rest = [digest for digest in digests if digest != root_digest]
            plan = call("db", "plan-set", root_digest, *rest, "--root", target)
            plan_sha = [line.split()[10] for line in plan.splitlines()
                        if line.startswith("plan-set ")][0]
            applied = call("db", "apply-set", plan_sha, root_digest, *rest, "--root", target)
            # the application, the object it references and the provider that closes the
            # store path outside the capture
            assert "artifacts 3" in applied, (name, applied)
        call("db", "check", "--all", "--root", target)
        assert (private / "lib/libfixture.so.1").is_file(), sorted(
            str(p.relative_to(target)) for p in target.rglob("*") if p.is_file())
        # a launcher is named for the store path, since that is the name it carries
        assert (target / "usr/bin/hello-2.0").is_file(), sorted(
            str(p.relative_to(target)) for p in target.rglob("*") if p.is_file())
        assert (target / "usr/bin/tool-3.0").is_file()

        # the object is reached by the references the applications declare, so removing
        # one application leaves the object and the other
        owner = call("db", "owner", f"usr/lib/holy/private/libfixture-1.0/store/"
                        f"{LIBRARY}-libfixture-1.0/lib/libfixture.so.1", "--root", target)
        assert digests[names.index("libfixture-1.0")] in owner, owner
        call("db", "rm", digests[names.index("hello-2.0")], "--root", target)
        assert (private / "lib/libfixture.so.1").is_file(), "the object has another owner"
        assert not (target / "usr/bin/hello-2.0").exists()
        assert (target / "usr/bin/tool-3.0").exists()
        call("db", "check", "--all", "--root", target)

        # the object is refused while the surviving application still needs it
        refused = subprocess.run([binary, "db", "rm",
                                  digests[names.index("libfixture-1.0")], "--root",
                                  str(target)], capture_output=True, text=True)
        assert refused.returncode == 3, refused
        assert "still required by" in refused.stderr, refused.stderr
        assert digests[names.index("tool-3.0")] in refused.stderr, refused.stderr
        assert (private / "lib/libfixture.so.1").is_file(), "a refused removal took the object"
        call("db", "check", "--all", "--root", target)

        # a store path that is not beside the capture is a missing capability
        absent = root / "absent"
        absent.mkdir()
        missing = capture(absent, f"root {LIBRARY}-libfixture-1.0\n"
                                  f"path {LIBRARY}-libfixture-1.0\n")
        result = subprocess.run([binary, "import", missing, "--source", "nix", "--format",
                                 "nix", "--output", root / "absent-out"],
                                capture_output=True, text=True)
        assert result.returncode == 6, result
        assert "is not beside the capture" in result.stderr, result.stderr

        # a capture with no output root, or none at all, is refused before anything is written
        for body, wanted in (("path %s-libfixture-1.0\n" % LIBRARY, "one output root"),
                             ("# nothing here\n", "one output root"),
                             ("root %s-libfixture-1.0\n" % LIBRARY, "one output root")):
            case = root / ("no-root-" + wanted.split()[0] + str(abs(hash(body))))
            case.mkdir()
            empty = capture(case, body)
            result = subprocess.run([binary, "import", empty, "--source", "nix", "--format",
                                     "nix", "--output", case / "out"],
                                    capture_output=True, text=True)
            assert result.returncode == 2, (body, result)
            assert wanted in result.stderr, (body, result.stderr)

        # a store path name the package format cannot record is refused rather than
        # rewritten, and so is a second store path of one name
        for body, wanted in (
                (f"path {LIBRARY}-+fixture\nroot {LIBRARY}-+fixture\n", "not a package name"),
                (f"path {LIBRARY}-fixture\npath {HELLO}-fixture\nroot {LIBRARY}-fixture\n",
                 "two store paths"),
                (f"path notastorepath\nroot notastorepath\n", "not a Nix store path")):
            case = pathlib.Path(tempfile.mkdtemp(dir=root))
            broken = capture(case, body)
            result = subprocess.run([binary, "import", broken, "--source", "nix", "--format",
                                     "nix", "--output", case / "out"],
                                    capture_output=True, text=True)
            assert result.returncode == 2, (body, result)
            assert wanted in result.stderr, (body, result.stderr)
            assert not list((case / "out").glob("*.holy")) if (case / "out").exists() else True

        # a reference for a store path the capture does not declare loses a closure
        # member, so it is refused instead of half read
        stray = root / "stray"
        stray.mkdir()
        body = capture(stray, f"path {LIBRARY}-fixture\n"
                              f"root {LIBRARY}-fixture\n"
                              f"references {HELLO}-hello-2.0 {LIBRARY}-fixture\n")
        result = subprocess.run([binary, "import", body, "--source", "nix", "--format", "nix",
                                 "--output", stray / "out"], capture_output=True, text=True)
        assert result.returncode == 2, result
        assert "does not declare" in result.stderr, result.stderr

        # an entry point that is not an executable file of its own store path is refused
        stale = root / "stale"
        stale.mkdir()
        (stale / f"{LIBRARY}-fixture" / "lib").mkdir(parents=True)
        (stale / f"{LIBRARY}-fixture/lib/libfixture.so.1").write_text("not executable\n")
        body = capture(stale, f"root {LIBRARY}-fixture\npath {LIBRARY}-fixture\n"
                              f"entry {LIBRARY}-fixture lib/libfixture.so.1\n")
        result = subprocess.run([binary, "import", body, "--source", "nix", "--format", "nix",
                                 "--output", stale / "out"], capture_output=True, text=True)
        assert result.returncode == 3, result
        assert "not an executable file in its own store path" in result.stderr, result.stderr

        # a capture that is not a capture at all is a missing capability
        result = subprocess.run([binary, "import", root / "no-such.capture", "--source", "nix",
                                 "--format", "nix", "--output", root / "none-out"],
                                capture_output=True, text=True)
        assert result.returncode == 6, result
        assert "closure capture unavailable" in result.stderr, result.stderr

    print("nix closure fixtures passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
