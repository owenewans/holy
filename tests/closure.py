#!/usr/bin/env python3
"""a closure object two applications share, and the second one after the first is
removed: the object has one owner and several dependents, so removing an
application leaves it and removing the object is refused until the caller accepts
the broken dependents."""
import hashlib
import pathlib
import shutil
import subprocess
import sys
import tempfile


binary = str(pathlib.Path(sys.argv[1]).resolve())
runtime = "/usr/lib/holy/x86_64-linux-gnu"
loader = f"{runtime}/ld-linux-x86-64.so.2"
libc = f"{runtime}/libc.so.6"
library = f"{runtime}/libclosure.so.1"


def call(*args, status=0):
    result = subprocess.run([binary, *map(str, args)], capture_output=True, text=True)
    assert result.returncode == status, (args, result.returncode, result.stdout, result.stderr)
    return result.stdout


def tree_for(root, name, libc_class="glibc"):
    tree = root / "trees" / name
    (tree / "HOLY").mkdir(parents=True)
    (tree / "DATA").mkdir()
    (tree / "HOLY/meta").write_text(
        "format holy-package-1\nname %s\nversion 1\nrelease 1\nos linux\narch x86_64\n"
        "libc %s\n" % (name, libc_class))
    for field in ("deps", "provides", "hooks", "origin", "transform"):
        (tree / "HOLY" / field).write_text("")
    return tree


def pack(root, tree, name):
    # the generator reads the tree it walks, so its output lands beside it
    call("manifest", "generate", tree, "--output", root / (name + "-files"))
    (tree / "HOLY/files").write_text((root / (name + "-files")).read_text())
    call("pack", tree, "--output", root / (name + ".holy"))
    return hashlib.sha256((root / (name + ".holy")).read_bytes()).hexdigest()


def patch(*args):
    result = subprocess.run(["patchelf", *map(str, args)], capture_output=True, text=True)
    assert result.returncode == 0, (args, result.stdout, result.stderr)


def main():
    for tool in ("cc", "patchelf", "lz4"):
        if not shutil.which(tool):
            print(f"{tool} required for the closure fixture", file=sys.stderr)
            return 6
    with tempfile.TemporaryDirectory() as scratch:
        root_dir = pathlib.Path(scratch)
        target = root_dir / "root"
        (target / "usr/bin").mkdir(parents=True)
        call("db", "init", "--root", target)

        sources = root_dir / "sources"
        sources.mkdir()
        # the runtime that every dynamic payload of this closure needs
        source = sources / "closure.c"
        source.write_text("int closure_answer(void) { return 42; }\n")
        application = sources / "main.c"
        application.write_text(
            '#include <stdio.h>\nextern int closure_answer(void);\n'
            'int main(void) { printf("%s %d\\n", PROGRAM, closure_answer()); return 0; }\n')
        built = sources / "libclosure.so"
        subprocess.run(["cc", "-shared", "-fPIC", "-Wl,-soname,libclosure.so.1",
                        "-o", str(built), str(source)], check=True)
        probe = sources / "probe"
        subprocess.run(["cc", "-DPROGRAM=\"probe\"", "-o", str(probe), str(application),
                        str(built)], check=True)
        host_loader = subprocess.run(["patchelf", "--print-interpreter", str(probe)],
                                     capture_output=True, text=True).stdout.strip()
        assert host_loader.startswith("/"), host_loader
        binaries = {}
        for name in ("closure-one", "closure-two"):
            path = sources / name
            subprocess.run(["cc", f"-DPROGRAM=\"{name}\"", "-o", str(path), str(application),
                            str(built)], check=True)
            patch("--set-interpreter", loader, "--replace-needed", "libc.so.6", libc,
                  "--replace-needed", "libclosure.so.1", library, str(path))
            binaries[name] = path

        tree = tree_for(root_dir, "closure-runtime")
        (tree / ("DATA" + runtime)).mkdir(parents=True)
        (tree / "DATA/usr/lib64").mkdir(parents=True)
        shutil.copy(host_loader, tree / ("DATA" + loader))
        located = subprocess.run(["cc", "-print-file-name=libc.so.6"], capture_output=True,
                                 text=True).stdout.strip()
        shutil.copy(located, tree / ("DATA" + libc))
        patch("--set-interpreter", loader, "--replace-needed", "ld-linux-x86-64.so.2", loader,
              str(tree / ("DATA" + libc)))
        (tree / "DATA/usr/lib64/ld-linux-x86-64.so.2").symlink_to(
            "../lib/holy/x86_64-linux-gnu/ld-linux-x86-64.so.2")
        runtime_hash = pack(root_dir, tree, "closure-runtime")

        # the closure object itself, one owner and no other
        tree = tree_for(root_dir, "closure-object")
        (tree / ("DATA" + runtime)).mkdir(parents=True)
        shutil.copy(built, tree / ("DATA" + library))
        patch("--replace-needed", "libc.so.6", libc, str(tree / ("DATA" + library)))
        object_hash = pack(root_dir, tree, "closure-object")

        # two applications that name the same object
        application_hash = {}
        for name, path in binaries.items():
            tree = tree_for(root_dir, name)
            (tree / "DATA/usr/bin").mkdir(parents=True)
            shutil.copy(path, tree / "DATA/usr/bin" / name)
            application_hash[name] = pack(root_dir, tree, name)

        for name in ("closure-runtime", "closure-object", "closure-one", "closure-two"):
            call("cache", "stage", "local:" + str(root_dir / (name + ".holy")), "--root", target)

        # a plan selects what the root needs, so each application is a root of its
        # own set and the object they share is installed once
        for name in ("closure-one", "closure-two"):
            selected = [application_hash[name], object_hash, runtime_hash]
            plan = call("db", "plan-set", *selected, "--root", target)
            # the object is reached by an exact path, which is what a closure
            # reference names, and the plan names it for this application
            assert f"needed-path {library}" in plan, plan
            assert f"provider {object_hash}" in plan, plan
            plan_sha = [line.split()[10] for line in plan.splitlines()
                        if line.startswith("plan-set ")][0]
            applied = call("db", "apply-set", plan_sha, *selected, "--root", target)
            assert "artifacts 3" in applied, (name, applied)
        call("db", "check", "--all", "--root", target)

        # one owner, two dependents, and each application names the object it needs
        owner = call("db", "owner", library, "--root", target)
        assert object_hash in owner, owner
        for name in ("closure-one", "closure-two"):
            assert (target / "usr/bin" / name).exists(), name
        assert not (target / "usr/bin/closure-object").exists()

        # removing one application leaves the object and the other application
        call("db", "rm", application_hash["closure-one"], "--root", target)
        assert (target / "usr/lib/holy/x86_64-linux-gnu/libclosure.so.1").exists()
        assert not (target / "usr/bin/closure-one").exists()
        assert (target / "usr/bin/closure-two").exists()
        call("db", "check", "--all", "--root", target)

        # the object is refused while an application still needs it
        result = subprocess.run([binary, "db", "rm", object_hash, "--root", str(target)],
                                capture_output=True, text=True)
        assert result.returncode == 3, result
        assert "still required by" in result.stderr, result.stderr
        assert application_hash["closure-two"] in result.stderr, result.stderr
        assert (target / "usr/lib/holy/x86_64-linux-gnu/libclosure.so.1").exists()

        # accepting the broken dependents removes the object, and the report says so
        result = subprocess.run([binary, "db", "rm", object_hash, "--accept-broken",
                                 "--root", str(target)], capture_output=True, text=True)
        assert result.returncode == 0, result
        assert "accepted broken dependents" in result.stderr, result.stderr
        assert not (target / "usr/lib/holy/x86_64-linux-gnu/libclosure.so.1").exists()
        broken = subprocess.run([binary, "db", "check", "--all", "--root", str(target),
                                 "--json"], capture_output=True, text=True)
        assert broken.returncode == 4, broken
        assert '"code":"broken-provider"' in broken.stdout, broken.stdout

        # restoring the object makes the surviving application whole again
        plan = call("db", "plan-set", object_hash, "--root", target)
        plan_sha = [line.split()[10] for line in plan.splitlines()
                    if line.startswith("plan-set ")][0]
        call("db", "apply-set", plan_sha, object_hash, "--root", target)
        call("db", "check", "--all", "--root", target)
        assert (target / "usr/bin/closure-two").exists()

    print("closure object fixtures passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
