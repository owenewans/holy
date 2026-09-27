#!/usr/bin/env python3
import hashlib
import pathlib
import subprocess
import sys
import tempfile

binary = str(pathlib.Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory(prefix="holy-versions-") as scratch:
    tmp = pathlib.Path(scratch)

    def run(*args, status=0):
        result = subprocess.run([binary, *map(str, args)], capture_output=True, text=True)
        assert result.returncode == status, (args, result.returncode, result.stdout, result.stderr)
        return result.stdout

    def package(label, name, version, deps="", family="pacman", arch="noarch", libc="nolibc"):
        tree = tmp / label
        (tree / "HOLY").mkdir(parents=True)
        (tree / "DATA").mkdir()
        (tree / "DATA" / name).write_text(version)
        metadata = "format holy-package-1\nname " + name + "\nversion " + version
        metadata += "\nrelease 1\nos linux\narch " + arch + "\nlibc " + libc + "\n"
        if family:
            metadata += "x-version-family " + family + "\n"
        (tree / "HOLY/meta").write_text(metadata)
        for field in ("deps", "provides", "hooks", "origin", "transform"):
            (tree / "HOLY" / field).write_text(deps if field == "deps" else "")
        run("manifest", "generate", tree, "--output", tmp / (label + ".files"))
        (tmp / (label + ".files")).rename(tree / "HOLY/files")
        artifact = tmp / (label + ".holy")
        run("pack", tree, "--output", artifact)
        return artifact, hashlib.sha256(artifact.read_bytes()).hexdigest()

    def dependency(relation, version, arch="any", libc="any"):
        return "require dep app package library " + arch + " " + libc + " " + relation + " " + version + " original fixture\n"

    old, old_hash = package("old", "library", "1:2.0-1")
    new, new_hash = package("new", "library", "1:2.0-3")
    foreign, _ = package("foreign", "library", "999:99-99", family="rpm")
    unknown, _ = package("unknown", "library", "999:99-99", family=None)
    wrong_arch, _ = package("wrong-arch", "library", "1:2.0-3", arch="x86")
    for relation, version, expected in (
        ("ge", "1:2.0-2", new_hash), ("gt", "1:2.0-1", new_hash),
        ("le", "1:2.0-2", old_hash), ("lt", "1:2.0-3", old_hash),
        ("eq", "1:2.0-3", new_hash),
    ):
        app, _ = package("app-" + relation, "app", "1-1", dependency(relation, version))
        text = run("solve", "local:" + str(app), "local:" + str(old), "local:" + str(new),
                   "local:" + str(foreign), "local:" + str(unknown))
        assert "selected " + expected in text
        assert "selected " + (old_hash if expected == new_hash else new_hash) not in text
        rejected = old_hash if expected == new_hash else new_hash
        run("solve", "local:" + str(app), "local:" + str(old), "local:" + str(new),
            "--choose", "dep=" + rejected, status=3)

    app, app_hash = package("app", "app", "1-1", dependency("ge", "1:2.0-2", "noarch", "nolibc"))
    run("solve", "local:" + str(app), "local:" + str(old), status=4)
    run("solve", "local:" + str(app), "local:" + str(foreign), status=4)
    run("solve", "local:" + str(app), "local:" + str(unknown), status=4)
    run("solve", "local:" + str(app), "local:" + str(wrong_arch), status=4)
    wrong_libc, _ = package("wrong-libc", "library", "1:2.0-3", arch="x86_64", libc="glibc")
    scope, _ = package("scope", "app", "1-1", dependency("any", "-", "any", "nolibc"))
    run("solve", "local:" + str(scope), "local:" + str(wrong_libc), status=4)
    run("solve", "local:" + str(scope), "local:" + str(new))
    for family in (None, "future", "rpm"):
        unsupported, _ = package("unsupported-" + str(family), "app", "1-1", dependency("ge", "1"), family)
        run("solve", "local:" + str(unsupported), "local:" + str(new), status=6)
    release, _ = package("no-release", "app", "1-1", dependency("eq", "1:2.0"))
    run("solve", "local:" + str(release), "local:" + str(old), "local:" + str(new), status=3)
    run("solve", "local:" + str(release), "local:" + str(old), "local:" + str(new),
        "--choose", "dep=" + new_hash)
    root = tmp / "root"
    root.mkdir()
    run("db", "init", "--root", root)
    for artifact in (old, new, app):
        run("cache", "stage", "local:" + str(artifact), "--root", root)
    plan = run("db", "plan-set", app_hash, old_hash, new_hash, "--root", root).split(" sha256 ")[1].split()[0]
    run("db", "apply-set", plan, app_hash, old_hash, new_hash, "--root", root)
    run("db", "check", "--all", "--root", root)
    assert (root / "library").read_text() == "1:2.0-3"
    second, second_hash = package("second", "second", "1-1", dependency("eq", "1:2.0").replace(" app package", " second package"))
    run("cache", "stage", "local:" + str(second), "--root", root)
    reuse = run("db", "plan-set", second_hash, "--root", root).split(" sha256 ")[1].split()[0]
    run("db", "apply-set", reuse, second_hash, "--root", root)
    run("db", "check", "--all", "--root", root)
    run("db", "plan-update", new_hash, old_hash, "--root", root, status=4)
    assert (root / "library").read_text() == "1:2.0-3"
    run("db", "rm", new_hash, "--root", root, status=3)
    run("db", "rm", second_hash, "--root", root)
    run("db", "rm", app_hash, "--root", root)
    run("db", "rm", new_hash, "--root", root)
    print("version-constrained solver and transaction fixtures passed")
