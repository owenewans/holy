#!/usr/bin/env python3
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

if len(sys.argv) != 6:
    print("usage: musl-abi.py STATIC-HOLYPKG MUSL32-PACKAGE MUSL32-CC MUSL64-PACKAGE MUSL64-CC", file=sys.stderr)
    sys.exit(2)
binary, package32, cc32, package64, cc64 = map(lambda path: pathlib.Path(path).resolve(), sys.argv[1:])
commands = {name: shutil.which(name) for name in ("doas", "chroot", "unshare", "mount", "sh", "patchelf")}
if not all(commands.values()) or not all(path.is_file() for path in (binary, package32, cc32, package64, cc64)):
    print("missing musl ABI fixture input", file=sys.stderr)
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


with tempfile.TemporaryDirectory(prefix="holy-musl-abi-") as scratch:
    tmp = pathlib.Path(scratch)
    root = tmp / "root"
    for directory in ("usr/bin", "tmp", "proc"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "lib").symlink_to("usr/lib")
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
                        "holy-musl-abi", root, commands["mount"], commands["chroot"], identity, *args], status=status)

    def launch(bits):
        return [commands["doas"], "-n", commands["chroot"], "--userspec=" + identity,
                str(root), "/usr/bin/musl-probe" + str(bits)]

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
        printf("musl%u <- %s", (unsigned)(sizeof(void *) * 8), input);
    } else printf("musl%u %s\\n", (unsigned)(sizeof(void *) * 8), (char *)value);
    free(value);
    return 0;
}
''')
    runtimes, applications, loaders, links = {}, {}, {}, {}
    for bits, arch, target, suffix, package, compiler in (
        (32, "x86", "i686-linux-musl", "i386", package32, cc32),
        (64, "x86_64", "x86_64-linux-musl", "x86_64", package64, cc64),
    ):
        tree = tmp / ("tree" + str(bits))
        (tree / "HOLY").mkdir(parents=True)
        (tree / "DATA/usr/bin").mkdir(parents=True)
        executable = tree / ("DATA/usr/bin/musl-probe" + str(bits))
        checked([compiler, "-O2", "-pthread", source, "-o", executable])
        loader = "/usr/lib/holy/" + target + "/ld-musl-" + suffix + ".so.1"
        checked([commands["patchelf"], "--set-interpreter", loader, "--replace-needed", "libc.so", loader, executable])
        assert "class ELF" + str(bits) + "\n" in run("elf", executable)
        (tree / "HOLY/meta").write_text("format holy-package-1\nname musl-probe\nversion 1\nrelease 1\nos linux\narch " + arch + "\nlibc musl\n")
        for name in ("deps", "provides", "hooks", "origin", "transform"):
            (tree / "HOLY" / name).write_text("")
        run("manifest", "generate", tree, "--output", tmp / ("files" + str(bits)))
        shutil.copyfile(tmp / ("files" + str(bits)), tree / "HOLY/files")
        application = tmp / ("probe" + str(bits) + ".holy")
        run("pack", tree, "--output", application)
        for artifact in (package, application):
            run("cache", "stage", "local:" + str(artifact), "--root", root)
        runtimes[bits] = hashlib.sha256(package.read_bytes()).hexdigest()
        applications[bits] = hashlib.sha256(application.read_bytes()).hexdigest()
        loaders[bits] = root / loader.lstrip("/")
        links[bits] = root / ("usr/lib/ld-musl-" + suffix + ".so.1")
    tree = tmp / "profile"
    (tree / "HOLY").mkdir(parents=True)
    (tree / "DATA").mkdir()
    (tree / "HOLY/meta").write_text("format holy-package-1\nname musl-abi-profile\nversion 1\nrelease 1\nos linux\narch noarch\nlibc nolibc\n")
    for name in ("files", "provides", "hooks", "origin", "transform"):
        (tree / "HOLY" / name).write_text("")
    (tree / "HOLY/deps").write_text(
        "require probe32 musl-abi-profile package musl-probe x86 musl any - musl-probe metadata\n"
        "require probe64 musl-abi-profile package musl-probe x86_64 musl any - musl-probe metadata\n")
    profile = tmp / "profile.holy"
    run("pack", tree, "--output", profile)
    run("cache", "stage", "local:" + str(profile), "--root", root)
    artifacts = [hashlib.sha256(profile.read_bytes()).hexdigest(), *runtimes.values(), *applications.values()]
    answers = ["--accept-arch", runtimes[32], "--accept-arch", applications[32]]
    run("db", "plan-set", *artifacts, "--root", root, status=3)
    plan = run("db", "plan-set", *artifacts, *answers, "--root", root).split(" sha256 ")[1].split()[0]
    run("db", "apply-set", plan, *artifacts, *answers, "--root", root)

    def probes():
        for bits in (32, 64):
            assert checked(launch(bits)) == "musl" + str(bits) + " thread-ok\n"
        for sender, receiver in ((32, 64), (64, 32)):
            with subprocess.Popen(launch(sender), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as producer:
                output = checked([*launch(receiver), "read"], stdin=producer.stdout)
                producer.stdout.close()
                assert producer.wait(timeout=60) == 0, producer.stderr.read()
            assert output == "musl" + str(receiver) + " <- musl" + str(sender) + " thread-ok\n"

    probes()
    for missing in ((32,), (64,), (32, 64)):
        for bits in missing:
            loaders[bits].unlink()
            links[bits].unlink()
        guest("db", "check", "--all", "--root", "/", status=4)
        for bits in missing:
            report = guest("db", "check", applications[bits], "--root", "/", "--json", status=4)
            assert '"code":"broken-provider"' in report
            repair = guest("db", "repair-plan", runtimes[bits], "--root", "/").split(" sha256 ")[1].split()[0]
            guest("db", "repair", runtimes[bits], "--plan", repair, "--root", "/")
        guest("db", "check", "--all", "--root", "/")
        probes()
    print(json.dumps({"schema": "holy-musl-abi-test-1", "result": "pass",
                      "holypkg_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                      "runtime_sha256": runtimes, "coverage": ["ELF32", "ELF64", "threads", "clock", "pipe-both-directions", "local-recovery"],
                      "not_tested": ["i686-kernel-boot", "glibc32", "hardware"]}))
