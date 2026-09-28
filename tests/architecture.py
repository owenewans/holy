#!/usr/bin/env python3
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import sys
import tempfile

binary = str(pathlib.Path(sys.argv[1]).resolve())
host = platform.machine()
target = "x86" if host == "x86_64" else "x86_64"
with tempfile.TemporaryDirectory(prefix="holy-architecture-") as scratch:
    tmp = pathlib.Path(scratch)

    def run(*args, status=0, env=None):
        result = subprocess.run([binary, *map(str, args)], capture_output=True, text=True, env=env)
        assert result.returncode == status, (args, result.returncode, result.stdout, result.stderr)
        return result.stdout

    def package(name, arch, dependency=None, version="1", privileged=False):
        tree = tmp / (name + "-" + version)
        (tree / "HOLY").mkdir(parents=True)
        (tree / "DATA/opt").mkdir(parents=True)
        payload = tree / "DATA/opt" / name
        if privileged:
            assembly = tmp / (name + "-" + version + ".s")
            object_file = tmp / (name + "-" + version + ".o")
            if arch == "x86":
                assembly.write_text(".global _start\n_start:\n mov $0, %ebx\n mov $1, %eax\n int $0x80\n")
                bits, machine = "--32", "elf_i386"
            else:
                assembly.write_text(".global _start\n_start:\n mov $0, %edi\n mov $60, %eax\n syscall\n")
                bits, machine = "--64", "elf_x86_64"
            subprocess.run(["as", bits, "-o", str(object_file), str(assembly)], check=True)
            subprocess.run(["ld", "-m", machine, "-o", str(payload), str(object_file)], check=True)
            payload.chmod(0o4755)
        else:
            payload.write_text(name + " " + version + "\n")
        (tree / "HOLY/meta").write_text("format holy-package-1\nname " + name + "\nversion " + version + "\nrelease 1\nos linux\narch " + arch + "\nlibc nolibc\n")
        for field in ("deps", "provides", "hooks", "origin", "transform"):
            (tree / "HOLY" / field).write_text("")
        if dependency:
            (tree / "HOLY/deps").write_text("require link " + name + " package " + dependency + " any any any - " + dependency + " metadata\n")
        manifest = tmp / (tree.name + ".files")
        run("manifest", "generate", tree, "--output", manifest)
        (tree / "HOLY/files").write_bytes(manifest.read_bytes())
        artifact = tmp / (tree.name + ".holy")
        run("pack", tree, "--output", artifact)
        return artifact, hashlib.sha256(artifact.read_bytes()).hexdigest()

    app = package("arch-app", target, "arch-lib")
    library = package("arch-lib", target)
    next_library = package("arch-lib", target, version="2")
    privileged_library = package("arch-lib", target, version="3", privileged=True)
    consumer = package("arch-consumer", "noarch", "arch-lib")
    updated_consumer = package("arch-consumer", "noarch", "arch-lib", version="2")
    artifacts = [app, library, next_library, privileged_library, consumer, updated_consumer]
    answers = ["--accept-arch", app[1], "--accept-arch", library[1]]

    def prepare(label):
        root = tmp / label
        root.mkdir()
        run("db", "init", "--root", root)
        for artifact, _ in artifacts:
            run("cache", "stage", "local:" + str(artifact), "--root", root)
        return root

    def plan(root, *flags):
        return run("db", "plan-set", app[1], library[1], *flags, "--root", root).split(" sha256 ")[1].split()[0]

    def check(root):
        output = run("db", "check", "--all", "--root", root, "--json")
        rows = [json.loads(line) for line in output.splitlines()]
        for digest in (app[1], library[1]):
            record = next(row for row in rows if row.get("artifact") == digest)
            assert record["state"] == "pass"
            assert record["architecture"] == {"code": "accepted-arch-mismatch", "host": host,
                                               "target": target, "execution": "unverified", "scope": "artifact"}
            instance = root / "var/lib/holypkg/installed" / digest
            assert "arch " + target + "\n" in (instance / "meta").read_text()
            assert "format holy-instance-5\n" in (instance / "state").read_text()
        assert "accepted-arch-mismatch" in run("db", "check", app[1], "--root", root)

    root = prepare("normal")
    run("db", "plan-set", app[1], library[1], "--root", root, status=3)
    run("db", "plan-set", app[1], library[1], *answers[:2], "--root", root, status=3)
    run("db", "plan-set", app[1], library[1], *answers, *answers[:2], "--root", root, status=2)
    run("db", "plan-set", app[1], library[1], *answers, "--accept-arch", "0" * 64, "--root", root, status=3)
    approved = plan(root, *answers)
    assert approved == plan(root, *answers[2:], *answers[:2])
    run("db", "apply-set", approved, app[1], library[1], "--root", root, status=3)
    assert not (root / "opt/arch-app").exists()
    run("db", "apply-set", approved, app[1], library[1], *answers, "--root", root)
    check(root)
    instance = root / "var/lib/holypkg/installed" / app[1]
    state = (instance / "state").read_text()
    (instance / "state").write_text(state.replace("architecture " + host + " " + target, "architecture " + host + " noarch"))
    run("db", "check", "--all", "--root", root, status=1)
    (instance / "state").write_text(state)
    reuse = run("db", "plan-set", consumer[1], "--root", root).split(" sha256 ")[1].split()[0]
    run("db", "apply-set", reuse, consumer[1], "--root", root)
    check(root)
    run("db", "plan-update", consumer[1], updated_consumer[1],
        "--accept-arch", updated_consumer[1], "--root", root, status=2)
    update = run("db", "plan-update", consumer[1], updated_consumer[1], "--root", root).split(" sha256 ")[1].split()[0]
    run("db", "apply-update", update, consumer[1], updated_consumer[1], "--root", root)
    check(root)
    run("db", "plan-update", library[1], next_library[1], "--root", root, status=3)
    run("db", "plan-update", library[1], next_library[1], "--accept-arch", library[1],
        "--root", root, status=2)
    replacement = run("db", "plan-update", library[1], next_library[1],
                      "--accept-arch", next_library[1], "--root", root)
    assert "accept-arch " + next_library[1] + "\narchitecture " + host + " " + target + "\n" in replacement
    update = replacement.split(" sha256 ")[1].split()[0]
    run("db", "apply-update", update, library[1], next_library[1], "--root", root, status=3)
    run("db", "apply-update", update, library[1], next_library[1],
        "--accept-arch", next_library[1], "--root", root)
    check_output = run("db", "check", next_library[1], "--root", root, "--json")
    assert any(row.get("architecture", {}).get("target") == target
               for row in map(json.loads, check_output.splitlines()))
    run("db", "check", "--all", "--root", root)
    run("db", "plan-update", next_library[1], privileged_library[1],
        "--accept-arch", privileged_library[1], "--root", root, status=3)
    run("db", "plan-update", next_library[1], privileged_library[1],
        "--accept-privileged", privileged_library[1], "--root", root, status=3)
    combined = run("db", "plan-update", next_library[1], privileged_library[1],
                   "--accept-arch", privileged_library[1],
                   "--accept-privileged", privileged_library[1], "--root", root)
    combined_plan = combined.split(" sha256 ")[1].split()[0]
    reversed_plan = run("db", "plan-update", next_library[1], privileged_library[1],
                        "--accept-privileged", privileged_library[1],
                        "--accept-arch", privileged_library[1], "--root", root)
    assert reversed_plan.split(" sha256 ")[1].split()[0] == combined_plan
    run("db", "apply-update", combined_plan, next_library[1], privileged_library[1],
        "--accept-privileged", privileged_library[1],
        "--accept-arch", privileged_library[1], "--root", root)
    assert (root / "opt/arch-lib").stat().st_mode & 0o4000
    run("db", "check", "--all", "--root", root)
    run("db", "rm", updated_consumer[1], "--root", root)
    run("db", "rm", app[1], "--root", root)
    run("db", "rm", privileged_library[1], "--root", root)

    cli_root = tmp / "cli-add"
    cli_root.mkdir()
    run("db", "init", "--root", cli_root)
    add = ("add", "local:" + str(app[0]), "--candidate",
           "local:" + str(privileged_library[0]), "--root", cli_root, "--yes")
    run(*add, status=3)
    assert not (cli_root / "opt/arch-app").exists()
    run(*add, "--accept-arch", app[1], status=3)
    run(*add, "--accept-arch", app[1], "--accept-arch", privileged_library[1],
        status=3)
    run(*add, "--accept-arch", app[1], "--accept-arch", privileged_library[1],
        "--accept-privileged", privileged_library[1])
    assert (cli_root / "opt/arch-lib").stat().st_mode & 0o4000
    run("db", "check", "--all", "--root", cli_root)

    dynamic = "interpreter /" in run("elf", binary)
    if dynamic or os.environ.get("HOLY_TEST_STATIC_UPDATE_FAULT") == "1":
        environment = os.environ.copy()
        if dynamic:
            fault = tmp / "fault.so"
            subprocess.run(["gcc", "-shared", "-fPIC", "-o", str(fault),
                            str(pathlib.Path(__file__).with_name("update-fault.c")), "-ldl"], check=True)
            environment["LD_PRELOAD"] = str(fault)
        for stage in ("set-journal", "set-instance"):
            root = prepare(stage)
            approved = plan(root, *answers)
            environment.update(HOLY_UPDATE_FAULT=stage, HOLY_UPDATE_NEW=min(app[1], library[1]))
            run("db", "apply-set", approved, app[1], library[1], *answers, "--root", root, env=environment, status=-9)
            journal = root / "var/lib/holypkg/transactions/set-journal"
            saved = journal.read_text()
            assert "format holy-set-journal-3\n" in saved and "accept-arch " + app[1] in saved
            journal.write_text(saved.replace("host " + host + "\n", "host unavailable\n"))
            run("db", "recover", "--continue-set", "--root", root, status=5)
            journal.write_text(saved)
            run("db", "recover", "--continue-set", "--root", root)
            check(root)
        if dynamic:
            root = prepare("update-architecture")
            approved = plan(root, *answers)
            run("db", "apply-set", approved, app[1], library[1], *answers, "--root", root)
            replacement = run("db", "plan-update", library[1], next_library[1],
                              "--accept-arch", next_library[1], "--root", root)
            update = replacement.split(" sha256 ")[1].split()[0]
            environment.update(HOLY_UPDATE_FAULT="no-space", HOLY_UPDATE_NEW=next_library[1])
            run("db", "apply-update", update, library[1], next_library[1],
                "--accept-arch", next_library[1], "--root", root, env=environment, status=5)
            journal = root / "var/lib/holypkg/transactions/update/journal"
            saved = journal.read_text()
            assert "format holy-update-journal-3\n" in saved
            assert "accept-arch " + next_library[1] + "\n" in saved
            journal.write_text(saved.replace("accept-arch " + next_library[1],
                                             "accept-arch " + library[1]))
            run("db", "recover", "--update", "--root", root, status=5)
            journal.write_text(saved)
            run("db", "recover", "--update", "--root", root)
            run("db", "check", "--all", "--root", root)
            root = prepare("update-architecture-privileged")
            approved = plan(root, *answers)
            run("db", "apply-set", approved, app[1], library[1], *answers, "--root", root)
            replacement = run("db", "plan-update", library[1], privileged_library[1],
                              "--accept-arch", privileged_library[1],
                              "--accept-privileged", privileged_library[1], "--root", root)
            update = replacement.split(" sha256 ")[1].split()[0]
            environment.update(HOLY_UPDATE_FAULT="database-after", HOLY_UPDATE_NEW=privileged_library[1])
            run("db", "apply-update", update, library[1], privileged_library[1],
                "--accept-arch", privileged_library[1],
                "--accept-privileged", privileged_library[1],
                "--root", root, env=environment, status=-9)
            journal = root / "var/lib/holypkg/transactions/update/journal"
            saved = journal.read_text()
            assert "format holy-update-journal-4\n" in saved
            assert "accept-arch " + privileged_library[1] + "\n" in saved
            assert "accept-privileged " + privileged_library[1] + "\n" in saved
            for decision in ("accept-arch ", "accept-privileged "):
                journal.write_text(saved.replace(decision + privileged_library[1],
                                                 decision + library[1]))
                run("db", "recover", "--update", "--root", root, status=5)
            journal.write_text(saved)
            run("db", "recover", "--update", "--root", root)
            assert (root / "opt/arch-lib").stat().st_mode & 0o4000
            run("db", "check", "--all", "--root", root)
        print("architecture journal and partial installation recovery passed")
    else:
        print("architecture fault injection skipped for uninstrumented static client")
    print("artifact-scoped architecture approval, state, provider reuse and cached updates passed")
