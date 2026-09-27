#!/usr/bin/env python3
import hashlib
import io
import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile

binary = str(pathlib.Path(sys.argv[1]).resolve())
helper = str(pathlib.Path(sys.argv[2]).resolve()) if len(sys.argv) > 2 else None
with tempfile.TemporaryDirectory(prefix="holy-hardlinks-") as scratch:
    tmp = pathlib.Path(scratch)

    def run(*args, status=0, env=None):
        result = subprocess.run([binary, *map(str, args)], capture_output=True, text=True, env=env)
        assert result.returncode == status, (args, result.returncode, result.stdout, result.stderr)
        return result.stdout

    anchor = "opt/links/z-anchor"
    aliases = ["opt/links/a-first", "opt/other/last"]
    data = b"hardlink payload\n"
    source = tmp / "links.pkg"
    def foreign(path, content, arch="any", permissions=0o640):
        directories = {str(parent) for name in [anchor, *aliases]
                       for parent in pathlib.PurePosixPath(name).parents if str(parent) != "."}
        with tarfile.open(path, "w") as archive:
            for name in [".PKGINFO", *sorted(directories), *aliases, anchor]:
                entry = tarfile.TarInfo(name)
                entry.uid, entry.gid = os.getuid(), os.getgid()
                entry.mode = permissions
                payload = None
                if name == ".PKGINFO":
                    payload = ("pkgname = links\npkgver = 1-1\narch = " + arch + "\n").encode()
                elif name in aliases:
                    entry.type, entry.linkname = tarfile.LNKTYPE, anchor
                elif name == anchor:
                    payload = content
                else:
                    entry.type, entry.mode = tarfile.DIRTYPE, 0o755
                if payload is not None:
                    entry.size = len(payload)
                archive.addfile(entry, io.BytesIO(payload) if payload is not None else None)

    foreign(source, data)
    run("import", source, "--source", "fixture", "--format", "pacman", "--output", tmp / "converted")
    artifact, = (tmp / "converted").glob("*.holy")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()

    def prepare(label):
        root = tmp / label
        root.mkdir()
        run("db", "init", "--root", root)
        run("cache", "stage", "local:" + str(artifact), "--root", root)
        plan = run("db", "plan-set", digest, "--root", root).split(" sha256 ")[1].split()[0]
        return root, plan

    def check_path(root, path, status=0):
        if helper:
            result = subprocess.run([helper, "--check-path",
                str(root / "var/lib/holypkg/installed" / digest / "files"), str(root), path], capture_output=True)
            assert result.returncode == status, (path, result.returncode, result.stderr)

    def intact(root):
        states = [(root / path).stat() for path in [anchor, *aliases]]
        assert len({(s.st_dev, s.st_ino) for s in states}) == 1
        assert all((root / path).read_bytes() == data for path in [anchor, *aliases])
        run("db", "check", "--all", "--root", root)

    def repair(root):
        plan = run("db", "repair-plan", digest, "--root", root).split(" sha256 ")[1].split()[0]
        run("db", "repair", digest, "--plan", plan, "--root", root)
        intact(root)

    root, plan = prepare("root")
    run("db", "apply-set", plan, digest, "--root", root)
    intact(root)
    check_path(root, aliases[0])
    for missing in ([aliases[0]], [anchor], [anchor, aliases[1]], [anchor, *aliases]):
        survivors = [path for path in [anchor, *aliases] if path not in missing]
        inode = (root / survivors[0]).stat().st_ino if survivors else None
        for path in missing:
            (root / path).unlink()
        report = [json.loads(line) for line in run("db", "check", "--all", "--root", root, "--json", status=4).splitlines()]
        assert report
        repair(root)
        if inode is not None:
            assert (root / anchor).stat().st_ino == inode
    copied = root / aliases[0]
    copied.unlink()
    copied.write_bytes(data)
    copied.chmod(0o640)
    run("db", "check", "--all", "--root", root, status=4)
    check_path(root, aliases[0], status=4)
    check_path(root, anchor, status=4)
    run("db", "repair-plan", digest, "--root", root, status=4)
    run("db", "rm", digest, "--root", root, status=4)
    assert (root / anchor).exists()
    copied.unlink()
    os.link(root / anchor, copied)
    outside = tmp / "external-link"
    os.link(root / anchor, outside)
    run("db", "rm", digest, "--root", root)
    assert outside.read_bytes() == data
    assert all(not (root / path).exists() for path in [anchor, *aliases])
    program = tmp / "probe.c"
    program.write_text("int main(void) { return 0; }\n")
    subprocess.run(["gcc", "-o", str(tmp / "dynamic"), str(program)], check=True)
    assembly = tmp / "probe.S"
    assembly.write_text(".global _start\n_start:\n mov $60, %eax\n xor %edi, %edi\n syscall\n")
    subprocess.run(["gcc", "-nostdlib", "-static", "-o", str(tmp / "static"), str(assembly)], check=True)
    for kind in ("static", "dynamic"):
        elf_source = tmp / (kind + ".pkg")
        foreign(elf_source, (tmp / kind).read_bytes(), "x86_64", 0o755)
        output = tmp / (kind + "-output")
        run("import", elf_source, "--source", "fixture", "--format", "pacman", "--output", output)
        elf_artifact, = output.glob("*.holy")
        facts = run("scan", "local:" + str(elf_artifact))
        assert "scanned 3 ELF files" in facts
        for path in [anchor, *aliases]:
            assert "elf " + path + " " in facts
            if kind == "dynamic":
                assert "needed " + path + " libc.so.6" in facts
        if kind == "static":
            saved_artifact, saved_digest = artifact, digest
            artifact = elf_artifact
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            elf_root, elf_plan = prepare("elf-root")
            run("db", "apply-set", elf_plan, digest, "--root", elf_root)
            for path in [anchor, *aliases]:
                subprocess.run([str(elf_root / path)], check=True)
            run("db", "check", "--all", "--root", elf_root)
            run("db", "rm", digest, "--root", elf_root)
            artifact, digest = saved_artifact, saved_digest

    saved_paths, saved_artifact, saved_digest = (anchor, aliases), artifact, digest
    anchor = "usr/share/man/man1/links.1"
    aliases = ["usr/share/man/man1/first.1", "usr/share/man/man1/last.1"]
    manual = b'.TH LINKS 1\n.SH NAME\nlinks \\- hardlink fixture\n'
    foreign(tmp / "manual.pkg", manual)
    run("import", tmp / "manual.pkg", "--source", "fixture", "--format", "pacman", "--output", tmp / "manual-output")
    artifact, = (tmp / "manual-output").glob("*.holy")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    docs_root, docs_plan = prepare("docs-root")
    run("db", "apply-set", docs_plan, digest, "--root", docs_root)
    run("docs", "--root", docs_root, "--output", tmp / "bundle")
    bundle = (tmp / "bundle").read_text()
    assert "packages 1 pages 3 aliases 0 missing-man 0" in bundle
    for path in [anchor, *aliases]:
        assert 'path "' + path + '"' in bundle
    broken = docs_root / aliases[0]
    broken.unlink()
    broken.write_bytes(manual)
    broken.chmod(0o640)
    run("docs", "--root", docs_root, "--output", tmp / "broken-bundle", status=4)
    assert not (tmp / "broken-bundle").exists()
    anchor, aliases = saved_paths
    artifact, digest = saved_artifact, saved_digest

    unpacked = subprocess.run(["lz4", "-dc", str(artifact)], capture_output=True, check=True).stdout
    rewritten = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(unpacked)) as original, tarfile.open(fileobj=rewritten, mode="w") as output:
        for entry in original:
            content = original.extractfile(entry).read() if entry.isfile() and not entry.islnk() else None
            if entry.name == "HOLY/files":
                rows = content.decode().splitlines()
                changed = []
                for row in rows:
                    fields = shlex.split(row)
                    if fields[0] == "hardlink" and fields[1] == aliases[0]:
                        fields[0] = "file"
                        fields.pop()
                    changed.append(" ".join(json.dumps(field) for field in fields))
                content = ("\n".join(changed) + "\n").encode()
                entry.size = len(content)
            elif entry.name == "DATA/" + aliases[0]:
                entry.type, entry.linkname, entry.size = tarfile.REGTYPE, "", len(data)
                content = data
            output.addfile(entry, io.BytesIO(content) if content is not None else None)
    malformed = tmp / "multiple-anchors.holy"
    with malformed.open("wb") as stream:
        subprocess.run(["lz4", "-z", "-q"], input=rewritten.getvalue(), stdout=stream, check=True)
    malformed_check = subprocess.run([binary, "verify", "local:" + str(malformed)], capture_output=True)
    assert malformed_check.returncode == 2 and b"multiple regular anchors" in malformed_check.stderr

    collision_root, collision_plan = prepare("collision")
    (collision_root / "opt/links").mkdir(parents=True)
    occupied = collision_root / aliases[0]
    occupied.write_bytes(data)
    occupied.chmod(0o640)
    run("db", "apply-set", collision_plan, digest, "--root", collision_root, status=4)
    assert occupied.read_bytes() == data and not (collision_root / anchor).exists()
    escaped_root, escaped_plan = prepare("escaped")
    external = tmp / "outside-directory"
    external.mkdir()
    (escaped_root / "opt").symlink_to(external, target_is_directory=True)
    run("db", "apply-set", escaped_plan, digest, "--root", escaped_root, status=4)
    assert not list(external.iterdir())

    if os.environ.get("HOLY_TEST_HARDLINK_MOUNTS") == "1":
        needed = {name: shutil.which(name) for name in ("doas", "unshare", "mount", "setpriv", "sh")}
        if not all(needed.values()):
            print("hardlink mount fixture requires doas, unshare, mount, setpriv and sh", file=sys.stderr)
            sys.exit(6)
        mount_root, mount_plan = prepare("cross-filesystem")
        (mount_root / "opt/other").mkdir(parents=True)
        script = ('"$7" -t tmpfs -o "uid=$2,gid=$3,mode=0755" tmpfs "$1/opt/other" || exit 6; '
                  'exec "$8" --reuid "$2" --regid "$3" --clear-groups '
                  '"$4" db apply-set "$5" "$6" --root "$1"')
        result = subprocess.run([needed["doas"], "-n", needed["unshare"], "--mount", "--fork",
            "--propagation", "private", "--", needed["sh"], "-c", script, "holy-hardlink-mount",
            str(mount_root), str(os.getuid()), str(os.getgid()), binary, mount_plan, digest,
            needed["mount"], needed["setpriv"]], capture_output=True, env={**os.environ, "LC_ALL": "C"})
        assert result.returncode == 5 and b"cross-device" in result.stderr.lower(), result.stderr
        assert (mount_root / anchor).read_bytes() == data
        assert not (mount_root / aliases[1]).exists()
        run("db", "recover", "--continue-set", "--root", mount_root)
        intact(mount_root)
        print("hardlink cross-filesystem failure and recovery passed")
    else:
        print("hardlink cross-filesystem fixture requires HOLY_TEST_HARDLINK_MOUNTS=1")

    dynamic = "interpreter /" in run("elf", binary)
    injected = os.environ.get("HOLY_TEST_STATIC_UPDATE_FAULT") == "1"
    if dynamic or injected:
        environment = os.environ.copy()
        if dynamic:
            library = tmp / "fault.so"
            subprocess.run(["gcc", "-shared", "-fPIC", "-o", str(library),
                str(pathlib.Path(__file__).with_name("update-fault.c")), "-ldl"], check=True)
            environment["LD_PRELOAD"] = str(library)
        for phase in ("hardlink-before", "hardlink-after", "hardlink-no-space"):
            root, plan = prepare(phase)
            environment["HOLY_UPDATE_FAULT"] = phase
            run("db", "apply-set", plan, digest, "--root", root, env=environment,
                status=5 if phase == "hardlink-no-space" else -9)
            run("db", "status", "--root", root, status=5)
            assert (root / anchor).read_bytes() == data
            if phase == "hardlink-after":
                broken = root / aliases[0]
                broken.unlink()
                broken.write_bytes(data)
                broken.chmod(0o640)
                run("db", "recover", "--continue-set", "--root", root, status=5)
                assert broken.stat().st_ino != (root / anchor).stat().st_ino
                assert not (root / aliases[1]).exists()
                broken.unlink()
                os.link(root / anchor, broken)
            elif phase == "hardlink-before":
                (root / anchor).write_bytes(b"changed")
                run("db", "recover", "--continue-set", "--root", root, status=5)
                assert (root / anchor).read_bytes() == b"changed"
                (root / anchor).write_bytes(data)
            run("db", "recover", "--continue-set", "--root", root)
            intact(root)
            (root / anchor).unlink()
            plan = run("db", "repair-plan", digest, "--root", root).split(" sha256 ")[1].split()[0]
            environment["HOLY_UPDATE_FAULT"] = "hardlink-after"
            run("db", "repair", digest, "--plan", plan, "--root", root, env=environment, status=-9)
            run("db", "recover", "--repair", "--root", root)
            intact(root)
            environment["HOLY_UPDATE_FAULT"] = "hardlink-remove"
            run("db", "rm", digest, "--root", root, env=environment, status=-9)
            remaining = root / aliases[1]
            remaining.unlink()
            remaining.write_bytes(data)
            remaining.chmod(0o640)
            run("db", "recover", "--continue", "--root", root, status=5)
            assert (root / anchor).exists() and remaining.exists()
            remaining.unlink()
            os.link(root / anchor, remaining)
            run("db", "recover", "--continue", "--root", root)
            assert all(not (root / path).exists() for path in [anchor, *aliases])
        print("hardlink interruption, ENOSPC and recovery fixtures passed")
    else:
        print("hardlink fault injection skipped for uninstrumented static client")
    print("hardlink install, inode checks, missing-only repair and removal passed")
