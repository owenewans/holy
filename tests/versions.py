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

    def package(label, name, version, deps="", family="pacman", arch="noarch", libc="nolibc", provides=""):
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
            (tree / "HOLY" / field).write_text(deps if field == "deps" else provides if field == "provides" else "")
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
    claim = "provide package library any any 2:1.0-3 fixture\n"
    alias, alias_hash = package("alias", "implementation", "0.1-1", provides=claim)
    lower, lower_hash = package("lower-alias", "other-implementation", "999-1",
        provides="provide package library any any 2:1.0-1 fixture\n")
    unversioned, _ = package("unversioned-alias", "unversioned", "999-1",
        provides="provide package library any any - fixture\n")
    alias_app, alias_app_hash = package("alias-app", "app", "1-1", dependency("ge", "2:1.0-2"))
    selected = run("solve", "local:" + str(alias_app), "local:" + str(alias), "local:" + str(lower), "local:" + str(unversioned))
    assert "selected " + alias_hash in selected and "selected " + lower_hash not in selected
    run("solve", "local:" + str(alias_app), "local:" + str(unversioned), status=4)
    mismatch, _ = package("scope-lie", "scope-lie", "1-1",
        provides="provide package library x86 musl 2:1.0-3 fixture\n")
    run("solve", "local:" + str(alias_app), "local:" + str(mismatch), status=6)
    assert "name implementation\n" in run("info", "local:" + str(alias))
    alternate, alternate_hash = package("alternate", "alternate", "5-1", provides=claim)
    run("solve", "local:" + str(alias_app), "local:" + str(alias), "local:" + str(alternate), status=3)
    chosen = run("solve", "local:" + str(alias_app), "local:" + str(alias), "local:" + str(alternate),
        "--choose", "dep=" + alternate_hash)
    assert "selected " + alternate_hash in chosen and "selected " + alias_hash not in chosen
    scoped_alias, _ = package("scoped-alias", "implementation", "1-1", arch="x86", provides=claim)
    scoped_app, _ = package("scoped-alias-app", "app", "1-1", dependency("ge", "2:1.0-2", "noarch", "nolibc"))
    run("solve", "local:" + str(scoped_app), "local:" + str(scoped_alias), status=4)
    alien_alias, _ = package("alien-alias", "implementation", "1-1", family="rpm", provides=claim)
    run("solve", "local:" + str(alias_app), "local:" + str(alien_alias), status=4)
    alias_root = tmp / "alias-root"
    alias_root.mkdir()
    run("db", "init", "--root", alias_root)
    for artifact in (alias, alias_app):
        run("cache", "stage", "local:" + str(artifact), "--root", alias_root)
    plan = run("db", "plan-set", alias_hash, "--root", alias_root).split(" sha256 ")[1].split()[0]
    run("db", "apply-set", plan, alias_hash, "--root", alias_root)
    record = alias_root / "var/lib/holypkg/installed" / alias_hash
    assert (record / "provides").read_text() == claim
    assert "provides " + hashlib.sha256(claim.encode()).hexdigest() in (record / "state").read_text()
    plan = run("db", "plan-set", alias_app_hash, "--root", alias_root).split(" sha256 ")[1].split()[0]
    run("db", "apply-set", plan, alias_app_hash, "--root", alias_root)
    graph = (alias_root / "var/lib/holypkg/installed" / alias_app_hash / "graph").read_text()
    assert '"package" "library"' in graph and alias_hash in graph
    cache = alias_root / "var/cache/holypkg/objects/sha256" / (alias_hash + ".holy")
    cache.unlink()
    run("db", "check", "--all", "--root", alias_root)
    for corrupted in (claim + "bad\n", ""):
        (record / "provides").write_text(corrupted)
        run("db", "status", "--root", alias_root, status=1)
    (record / "provides").write_text(claim)
    (record / "provides").chmod(0o666)
    run("db", "status", "--root", alias_root, status=1)
    (record / "provides").chmod(0o600)
    (record / "provides").unlink()
    run("db", "status", "--root", alias_root, status=1)
    (record / "provides").symlink_to(alias)
    run("db", "status", "--root", alias_root, status=1)
    (record / "provides").unlink()
    (record / "provides").write_text(claim)
    run("cache", "stage", "local:" + str(alias), "--root", alias_root)
    replacement, replacement_hash = package("drop-claim", "implementation", "0.2-1")
    run("cache", "stage", "local:" + str(replacement), "--root", alias_root)
    run("db", "plan-update", alias_hash, replacement_hash, "--root", alias_root, status=4)
    run("db", "rm", alias_app_hash, "--root", alias_root)
    state = (record / "state").read_text()
    legacy = state.replace("holy-instance-4", "holy-instance-2")
    legacy = "\n".join(line for line in legacy.splitlines() if not line.startswith(("provides ", "source-record "))) + "\n"
    (record / "state").write_text(legacy)
    (record / "provides").unlink()
    run("db", "status", "--root", alias_root)
    cache.unlink()
    run("db", "plan-set", alias_app_hash, "--root", alias_root, status=6)
    run("cache", "stage", "local:" + str(alias), "--root", alias_root)
    legacy_plan = run("db", "plan-set", alias_app_hash, "--root", alias_root).split(" sha256 ")[1].split()[0]
    run("db", "apply-set", legacy_plan, alias_app_hash, "--root", alias_root)
    run("db", "check", "--all", "--root", alias_root)
    upgraded, upgraded_hash = package("keep-claim", "implementation", "0.3-1", provides=claim)
    run("cache", "stage", "local:" + str(upgraded), "--root", alias_root)
    update = run("db", "plan-update", alias_hash, upgraded_hash, "--root", alias_root).split(" sha256 ")[1].split()[0]
    run("db", "apply-update", update, alias_hash, upgraded_hash, "--root", alias_root)
    run("db", "check", "--all", "--root", alias_root)
    updated_record = record.parent / upgraded_hash
    assert (updated_record / "provides").read_text() == claim
    assert "format holy-instance-4\n" in (updated_record / "state").read_text()
    graph = (record.parent / alias_app_hash / "graph").read_text()
    assert upgraded_hash in graph and alias_hash not in graph
    run("db", "rm", alias_app_hash, "--root", alias_root)
    run("db", "rm", upgraded_hash, "--root", alias_root)
    deb_old, _ = package("deb-old", "deblib", "1.0~rc1", family="deb")
    deb_new, deb_new_hash = package("deb-new", "deblib", "1.0", family="deb")
    deb_wrong, _ = package("deb-wrong-family", "deblib", "99.0", family="pacman")
    deb_app, _ = package("deb-app", "app", "1", dependency("ge", "1.0").replace("library", "deblib"), family="deb")
    run("solve", "local:" + str(deb_app), "local:" + str(deb_old), status=4)
    run("solve", "local:" + str(deb_app), "local:" + str(deb_wrong), status=4)
    assert "selected " + deb_new_hash in run("solve", "local:" + str(deb_app),
        "local:" + str(deb_old), "local:" + str(deb_new), "local:" + str(deb_wrong))
    print("version constraints, virtual capabilities and transaction fixtures passed")
