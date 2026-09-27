#!/usr/bin/env python3
import hashlib
import json
import os
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile

if len(sys.argv) != 4 or sys.argv[2] not in ("i686", "x86", "x86_64"):
    print("usage: target.py STATIC-HOLYPKG i686|x86_64 MUSL-CC", file=sys.stderr)
    sys.exit(2)
binary = pathlib.Path(sys.argv[1]).resolve()
arch = "x86" if sys.argv[2] in ("i686", "x86") else "x86_64"
compiler = pathlib.Path(sys.argv[3]).resolve()
bits, machine, emulator, cpu = (32, 3, "qemu-i386", "pentium2") if arch == "x86" else (64, 62, "qemu-x86_64", "qemu64")
runner = shutil.which(emulator)
reader = shutil.which("readelf")
if not runner or not reader or not compiler.is_file() or not binary.is_file():
    print("required target test tool unavailable", file=sys.stderr)
    sys.exit(6)


def inspect(path):
    header = path.read_bytes()[:20]
    assert header[:6] == b"\x7fELF" + bytes((1 if bits == 32 else 2, 1)), path
    assert struct.unpack_from("<H", header, 18)[0] == machine, path
    segments = subprocess.run([reader, "-l", path], check=True, capture_output=True).stdout
    assert b"INTERP" not in segments, path


def execute(path, *args):
    result = subprocess.run([runner, "-cpu", cpu, str(path), *map(str, args)],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, (args, result.returncode, result.stdout, result.stderr)
    return result.stdout


def run(*args):
    return execute(binary, *args)


inspect(binary)
assert "class ELF" + str(bits) + "\n" in run("elf", binary)
with tempfile.TemporaryDirectory(prefix="holy-target-") as scratch:
    tmp = pathlib.Path(scratch)
    tree, root = tmp / "tree", tmp / "root"
    (tree / "HOLY").mkdir(parents=True)
    (tree / "DATA/usr/bin").mkdir(parents=True)
    root.mkdir()
    source = tmp / "probe.c"
    source.write_text('#include <stdio.h>\nint main(void) { printf("pointer-bits %u\\n", (unsigned)(sizeof(void *) * 8)); return 0; }\n')
    payload = tree / "DATA/usr/bin/probe"
    subprocess.run([str(compiler), "-O2", "-static", "-std=c99", str(source), "-o", str(payload)], check=True)
    inspect(payload)
    assert execute(payload) == "pointer-bits " + str(bits) + "\n"
    (tree / "HOLY/meta").write_text("format holy-package-1\nname target-probe\nversion 1\nrelease 1\nos linux\narch " + arch + "\nlibc nolibc\n")
    for name in ("deps", "provides", "hooks", "origin", "transform"):
        (tree / "HOLY" / name).write_text("")
    run("manifest", "generate", tree, "--output", tmp / "files")
    shutil.copyfile(tmp / "files", tree / "HOLY/files")
    package = tmp / "probe.holy"
    run("pack", tree, "--output", package)
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    run("db", "init", "--root", root)
    run("cache", "stage", "local:" + str(package), "--root", root)
    plan = run("db", "plan-set", digest, "--root", root).split(" sha256 ")[1].split()[0]
    run("db", "apply-set", plan, digest, "--root", root)
    run("db", "check", "--all", "--root", root)
    installed = root / "usr/bin/probe"
    assert execute(installed) == "pointer-bits " + str(bits) + "\n"
    run("db", "rm", digest, "--root", root)
    assert not os.path.lexists(installed)
    print(json.dumps({"schema": "holy-target-test-1", "result": "pass", "arch": arch,
                      "elf_class": bits, "e_machine": machine, "cpu": cpu,
                      "emulator": runner, "holypkg_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                      "package_sha256": digest, "coverage": ["static-c", "pack", "install", "check", "execute", "remove"],
                      "not_tested": ["boot", "dynamic-libc", "hardware"]}))
