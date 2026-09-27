#!/usr/bin/env python3
import hashlib
import io
import os
import pathlib
import shlex
import subprocess
import sys
import tarfile
import tempfile

binary = str(pathlib.Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory(prefix="holy-hardlink-updates-") as scratch:
    tmp = pathlib.Path(scratch)

    def run(*args, status=0, env=None):
        result = subprocess.run([binary, *map(str, args)], capture_output=True, text=True, env=env)
        assert result.returncode == status, (args, result.returncode, result.stdout, result.stderr)
        return result.stdout

    def package(label, payload, mode=0o640):
        source = tmp / (label + ".pkg")
        dirs = {str(parent) for path in payload for parent in pathlib.PurePosixPath(path).parents if str(parent) != "."}
        with tarfile.open(source, "w") as archive:
            metadata = ("pkgname = links\npkgver = " + label + "-1\narch = any\n").encode()
            for path in [".PKGINFO", *sorted(dirs), *sorted(payload)]:
                entry = tarfile.TarInfo(path)
                entry.uid, entry.gid = os.getuid(), os.getgid()
                entry.mode = mode
                data = metadata if path == ".PKGINFO" else payload.get(path)
                if path in dirs:
                    entry.type, entry.mode = tarfile.DIRTYPE, 0o755
                elif isinstance(data, str):
                    entry.type, entry.linkname = tarfile.LNKTYPE, data
                    data = None
                elif isinstance(data, tuple):
                    entry.type, entry.linkname, entry.mode = tarfile.SYMTYPE, data[1], 0o777
                    data = None
                else:
                    entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data) if data is not None else None)
        output = tmp / label
        run("import", source, "--source", "fixture", "--format", "pacman", "--output", output)
        artifact, = output.glob("*.holy")
        return artifact, hashlib.sha256(artifact.read_bytes()).hexdigest(), payload, mode

    old = package("1", {"opt/a": "opt/z", "opt/b": "opt/z", "opt/z": b"old\n", "opt/keep": b"keep\n"})
    new = package("2", {"opt/a": "opt/z", "opt/b": "opt/z", "opt/z": b"new\n", "opt/keep": b"keep\n"})
    added = package("3", {**new[2], "opt/new/d": "opt/z"})
    moved = package("4", {"opt/a": "opt/new/q", "opt/z": "opt/new/q", "opt/new/d": "opt/new/q",
                          "opt/new/q": b"new\n", "opt/keep": b"keep\n"})
    split = package("5", {path: b"new\n" if path != "opt/keep" else b"keep\n" for path in moved[2]})
    merged = package("6", {"opt/a": b"new\n", "opt/z": "opt/a", "opt/new/d": "opt/a",
                           "opt/new/q": "opt/a", "opt/keep": b"keep\n"})
    linked = package("7", {"opt/a": ("symlink", "keep"), "opt/keep": b"keep\n"})
    mode_changed = package("8", new[2], mode=0o600)
    versions = [old, new, added, moved, split, merged, linked, mode_changed]

    def prepare(label, installed=old):
        root = tmp / label
        root.mkdir()
        run("db", "init", "--root", root)
        for artifact, _, _, _ in versions:
            run("cache", "stage", "local:" + str(artifact), "--root", root)
        plan = run("db", "plan-set", installed[1], "--root", root).split(" sha256 ")[1].split()[0]
        run("db", "apply-set", plan, installed[1], "--root", root)
        return root

    def check(root, current, previous=None):
        run("db", "check", "--all", "--root", root)
        groups = {}
        for path, value in current[2].items():
            node = root / path
            if isinstance(value, tuple):
                assert node.is_symlink() and os.readlink(node) == value[1]
                continue
            target = value if isinstance(value, str) else path
            assert node.read_bytes() == current[2][target]
            st = node.stat()
            assert st.st_mode & 0o777 == current[3]
            identity = st.st_dev, st.st_ino
            if target in groups:
                assert groups[target] == identity, (path, target)
            else:
                assert identity not in groups.values(), (path, groups)
                groups[target] = identity
        if previous:
            for path in previous[2].keys() - current[2].keys():
                assert not os.path.lexists(root / path)
        assert not list(root.rglob(".holy-update-*"))
        assert not (root / "var/lib/holypkg/transactions/update").exists()

    def plan(root, before, after):
        record = run("db", "plan-update", before[1], after[1], "--root", root)
        if any(isinstance(value, str) for value in after[2].values()):
            assert "group-stage " in record
        return record.split(" sha256 ")[1].split()[0]

    root = prepare("regular")
    outside = tmp / "external"
    os.link(root / "opt/z", outside)
    previous = old
    for following in [new, added, moved, split, merged, linked, mode_changed, old]:
        approved = plan(root, previous, following)
        run("db", "apply-update", approved, previous[1], following[1], "--root", root)
        check(root, following, previous)
        assert outside.read_bytes() == b"old\n"
        previous = following
    run("db", "rm", previous[1], "--root", root)
    invalid = prepare("unexpected-sharing", split)
    (invalid / "opt/z").unlink()
    os.link(invalid / "opt/a", invalid / "opt/z")
    run("db", "check", "--all", "--root", invalid, status=4)
    run("db", "plan-update", split[1], merged[1], "--root", invalid, status=4)
    assert (invalid / "opt/a").stat().st_ino == (invalid / "opt/z").stat().st_ino

    print("hardlink content, membership, anchor moves, split/merge, modes and downgrade passed")

    dynamic = "interpreter /" in run("elf", binary)
    if dynamic or os.environ.get("HOLY_TEST_STATIC_UPDATE_FAULT") == "1":
        environment = os.environ.copy()
        if dynamic:
            library = tmp / "fault.so"
            subprocess.run(["gcc", "-shared", "-fPIC", "-o", str(library),
                str(pathlib.Path(__file__).with_name("update-fault.c")), "-ldl"], check=True)
            environment["LD_PRELOAD"] = str(library)
        for phase in ("intent-after", "hardlink-before", "hardlink-after", "payload-before", "payload-after",
                      "database-before", "database-after", "generation-after", "group-cleanup", "committed", "no-space", "staging-partial"):
            root = prepare("fault-" + phase)
            approved = plan(root, old, new)
            environment.update(HOLY_UPDATE_FAULT=phase, HOLY_UPDATE_NEW=new[1])
            run("db", "apply-update", approved, old[1], new[1], "--root", root,
                env=environment, status=5 if phase == "no-space" else -9)
            run("db", "status", "--root", root, status=5)
            if phase == "staging-partial":
                partial, = root.rglob(".holy-update-*")
                before = partial.read_bytes()
                run("db", "recover", "--update", "--root", root, status=5)
                assert partial.read_bytes() == before and (root / "opt/a").read_bytes() == b"old\n"
                partial.unlink()
            run("db", "recover", "--update", "--root", root)
            check(root, new, old)
        for before, after in ((new, moved), (moved, split), (split, merged), (old, mode_changed)):
            preview_root = prepare("count-" + before[1][:8], before)
            record = run("db", "plan-update", before[1], after[1], "--root", preview_root)
            records = [shlex.split(line) for line in record.splitlines()]
            steps = sum(1 for i, row in enumerate(records) if row and row[0] == "change" and row[2] != "retain"
                        and records[i + 1][1] != "dir" and records[i + 2][1] != "dir")
            assert steps
            for step in range(1, steps + 1):
                root = prepare("step-" + before[1][:8] + "-" + str(step), before)
                approved = plan(root, before, after)
                environment.update(HOLY_UPDATE_FAULT="steps", HOLY_UPDATE_STEP=str(step), HOLY_UPDATE_NEW=after[1])
                run("db", "apply-update", approved, before[1], after[1], "--root", root, env=environment, status=-9)
                run("db", "recover", "--update", "--root", root)
                check(root, after, before)
            environment.pop("HOLY_UPDATE_STEP")
        for damaged in ("old-group", "witness", "alias-stage"):
            root = prepare("damaged-" + damaged)
            approved = plan(root, old, new)
            environment.update(HOLY_UPDATE_FAULT="hardlink-after" if damaged == "old-group" else "payload-after",
                               HOLY_UPDATE_NEW=new[1])
            run("db", "apply-update", approved, old[1], new[1], "--root", root, env=environment, status=-9)
            witness, = root.rglob(".holy-update-*-group")
            if damaged == "old-group":
                path, source = root / "opt/b", root / "opt/z"
            elif damaged == "witness":
                path, source = witness, root / "opt/a"
            else:
                path = next(path for path in root.rglob(".holy-update-*") if not path.name.endswith("-group"))
                source = witness
            content, mode = path.read_bytes(), path.stat().st_mode & 0o777
            path.unlink()
            path.write_bytes(content)
            path.chmod(mode)
            original = [(root / name).read_bytes() for name in ("opt/a", "opt/b", "opt/z")]
            run("db", "recover", "--update", "--root", root, status=5)
            assert original == [(root / name).read_bytes() for name in ("opt/a", "opt/b", "opt/z")]
            assert path.stat().st_ino != source.stat().st_ino
            path.unlink()
            os.link(source, path)
            run("db", "recover", "--update", "--root", root)
            check(root, new, old)
        print("hardlink update per-file interruption, topology drift and recovery passed")
    else:
        print("hardlink update fault injection skipped for uninstrumented static client")
