#!/usr/bin/env python3
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

if len(sys.argv) not in (6, 8):
    print("usage: libc-abi.py STATIC-HOLYPKG MUSL32-PACKAGE MUSL32-CC MUSL64-PACKAGE MUSL64-CC [GLIBC32-PACKAGE GLIBC64-PACKAGE]", file=sys.stderr)
    sys.exit(2)
binary, package32, cc32, package64, cc64 = map(lambda path: pathlib.Path(path).resolve(), sys.argv[1:6])
glibc = list(map(lambda path: pathlib.Path(path).resolve(), sys.argv[6:]))
commands = {name: shutil.which(name) for name in ("doas", "chroot", "unshare", "mount", "sh", "patchelf", *(("gcc",) if glibc else ()))}
if not all(commands.values()) or not all(path.is_file() for path in (binary, package32, cc32, package64, cc64, *glibc)):
    print("missing libc ABI fixture input", file=sys.stderr)
    sys.exit(6)
if os.uname().machine != "x86_64":
    print("mixed ELF32/ELF64 runtime fixture requires an x86_64 kernel", file=sys.stderr)
    sys.exit(6)
if subprocess.run([commands["doas"], "-n", "true"]).returncode:
    sys.exit(6)
identity = str(os.getuid()) + ":" + str(os.getgid())


def checked(command, status=0, **kwargs):
    result = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=60, **kwargs)
    assert result.returncode == status, (command, result.returncode, result.stdout, result.stderr)
    return result.stdout


with tempfile.TemporaryDirectory(prefix="holy-libc-abi-") as scratch:
    tmp = pathlib.Path(scratch)
    root = tmp / "root"
    for directory in ("usr/bin", "tmp", "proc"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "lib").symlink_to("usr/lib")
    (root / "lib64").symlink_to("usr/lib64")
    shutil.copyfile(binary, root / "usr/bin/holypkg")
    (root / "usr/bin/holypkg").chmod(0o755)

    def run(*args, status=0):
        return checked([binary, *args], status=status)

    def guest(*args, status=0):
        return checked([commands["doas"], "-n", commands["unshare"], "--mount", "--pid", "--fork",
                        "--propagation", "private", "--", commands["sh"], "-c",
                        '"$2" -t proc -o nosuid,nodev,noexec proc "$1/proc" || exit 6; '
                        'root=$1; chroot=$3; identity=$4; shift 4; '
                        'exec "$chroot" --userspec="$identity" "$root" /usr/bin/holypkg "$@"',
                        "holy-libc-abi", root, commands["mount"], commands["chroot"], identity, *args], status=status)

    def launch(variant):
        return [commands["doas"], "-n", commands["chroot"], "--userspec=" + identity,
                str(root), "/usr/bin/libc-probe-" + variant]

    assert "runtime nolibc\n" in run("elf", binary)
    run("db", "init", "--root", root)
    source = tmp / "probe.c"
    source.write_text('''#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
static void *worker(void *unused)
{
    char *value = malloc(32);
    (void)unused;
    if (value) strcpy(value, "thread-ok");
    return value;
}
int main(int argc, char **argv)
{
    pthread_t thread;
    struct timespec now;
    void *value;
    char input[128];
    (void)argv;
    if (clock_gettime(CLOCK_MONOTONIC, &now) || pthread_create(&thread, NULL, worker, NULL) ||
        pthread_join(thread, &value) || !value) return 1;
    if (argc > 1) {
        if (!fgets(input, sizeof input, stdin)) return 2;
        printf("%s <- %s", HOLY_VARIANT, input);
    } else printf("%s %s\\n", HOLY_VARIANT, (char *)value);
    free(value);
    return 0;
}
''')
    runtimes, applications, loaders, links = {}, {}, {}, {}
    variants = [
        ("musl32", 32, "x86", "musl", "i686-linux-musl", "ld-musl-i386.so.1", package32, [cc32]),
        ("musl64", 64, "x86_64", "musl", "x86_64-linux-musl", "ld-musl-x86_64.so.1", package64, [cc64]),
    ]
    if glibc:
        variants += [
            ("glibc32", 32, "x86", "glibc", "i686-linux-gnu", "ld-linux.so.2", glibc[0], [commands["gcc"], "-m32", "-march=i686"]),
            ("glibc64", 64, "x86_64", "glibc", "x86_64-linux-gnu", "ld-linux-x86-64.so.2", glibc[1], [commands["gcc"], "-m64", "-march=x86-64"]),
        ]
    for variant, bits, arch, libc, target, loader_name, package, compiler in variants:
        tree = tmp / ("tree-" + variant)
        (tree / "HOLY").mkdir(parents=True)
        (tree / "DATA/usr/bin").mkdir(parents=True)
        executable = tree / ("DATA/usr/bin/libc-probe-" + variant)
        checked([*compiler, "-O2", "-pthread", '-DHOLY_VARIANT="' + variant + '"', source, "-o", executable])
        loader = "/usr/lib/holy/" + target + "/" + loader_name
        needed = loader if libc == "musl" else "/usr/lib/holy/" + target + "/libc.so.6"
        checked([commands["patchelf"], "--set-interpreter", loader, "--replace-needed",
                 "libc.so" if libc == "musl" else "libc.so.6", needed, executable])
        elf = run("elf", executable)
        assert "class ELF" + str(bits) + "\n" in elf
        assert "runtime " + libc + "\n" in elf
        (tree / "HOLY/meta").write_text("format holy-package-1\nname libc-probe\nversion 1\nrelease 1\nos linux\narch " + arch + "\nlibc " + libc + "\n")
        for name in ("deps", "provides", "hooks", "origin", "transform"):
            (tree / "HOLY" / name).write_text("")
        run("manifest", "generate", tree, "--output", tmp / ("files-" + variant))
        shutil.copyfile(tmp / ("files-" + variant), tree / "HOLY/files")
        application = tmp / ("probe-" + variant + ".holy")
        run("pack", tree, "--output", application)
        for artifact in (package, application):
            run("cache", "stage", "local:" + str(artifact), "--root", root)
        runtimes[variant] = hashlib.sha256(package.read_bytes()).hexdigest()
        applications[variant] = hashlib.sha256(application.read_bytes()).hexdigest()
        loaders[variant] = [root / loader.lstrip("/")]
        if libc == "glibc":
            loaders[variant].append(root / needed.lstrip("/"))
        links[variant] = root / (("usr/lib64/" if variant == "glibc64" else "usr/lib/") + loader_name)
    tree = tmp / "profile"
    (tree / "HOLY").mkdir(parents=True)
    (tree / "DATA").mkdir()
    (tree / "HOLY/meta").write_text("format holy-package-1\nname libc-abi-profile\nversion 1\nrelease 1\nos linux\narch noarch\nlibc nolibc\n")
    for name in ("files", "provides", "hooks", "origin", "transform"):
        (tree / "HOLY" / name).write_text("")
    (tree / "HOLY/deps").write_text("".join(
        "require " + variant + " libc-abi-profile package libc-probe " + arch + " " + libc + " any - libc-probe metadata\n"
        for variant, bits, arch, libc, *_ in variants))
    profile = tmp / "profile.holy"
    run("pack", tree, "--output", profile)
    run("cache", "stage", "local:" + str(profile), "--root", root)
    artifacts = [hashlib.sha256(profile.read_bytes()).hexdigest(), *runtimes.values(), *applications.values()]
    answers = [item for variant, bits, *_ in variants if bits == 32
               for digest in (runtimes[variant], applications[variant]) for item in ("--accept-arch", digest)]
    run("db", "plan-set", *artifacts, "--root", root, status=3)
    plan = run("db", "plan-set", *artifacts, *answers, "--root", root).split(" sha256 ")[1].split()[0]
    run("db", "apply-set", plan, *artifacts, *answers, "--root", root)

    def probes():
        for variant in runtimes:
            assert checked(launch(variant)) == variant + " thread-ok\n"
        for sender in runtimes:
            for receiver in runtimes:
                if sender == receiver:
                    continue
                with subprocess.Popen(launch(sender), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as producer:
                    output = checked([*launch(receiver), "read"], stdin=producer.stdout)
                    producer.stdout.close()
                    assert producer.wait(timeout=60) == 0, producer.stderr.read()
                assert output == receiver + " <- " + sender + " thread-ok\n"

    probes()
    missing_sets = [(variant,) for variant in runtimes] + [tuple(runtimes)]
    if glibc:
        missing_sets += [("musl32", "musl64"), ("glibc32", "glibc64")]
    for missing in missing_sets:
        for variant in missing:
            for loader in loaders[variant]:
                loader.unlink()
            links[variant].unlink()
        guest("db", "check", "--all", "--root", "/", status=4)
        for variant in missing:
            report = guest("db", "check", applications[variant], "--root", "/", "--json", status=4)
            assert '"code":"broken-provider"' in report
            repair = guest("db", "repair-plan", runtimes[variant], "--root", "/").split(" sha256 ")[1].split()[0]
            guest("db", "repair", runtimes[variant], "--plan", repair, "--root", "/")
        guest("db", "check", "--all", "--root", "/")
        probes()
    print(json.dumps({"schema": "holy-libc-abi-test-1", "result": "pass",
                      "holypkg_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                      "runtime_sha256": runtimes, "application_sha256": applications,
                      "probe_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                      "kernel": os.uname().release, "coverage": ["ELF32", "ELF64", "threads", "clock", "pipe-both-directions", "local-recovery"],
                      "not_tested": ["i686-kernel-boot", "hardware", *([] if glibc else ["glibc32", "glibc64"])]}))
