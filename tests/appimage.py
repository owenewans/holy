#!/usr/bin/env python3
import hashlib
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

binary = str(pathlib.Path(sys.argv[1]).resolve())
compiler = shutil.which(os.environ.get("FIXTURE_CC", "cc")) or shutil.which("gcc")
# the desktop entry the images ship, and the version one of them states
DESKTOP = ("[Desktop Entry]\nType=Application\nName=Demo\nExec=AppRun %U\n"
           "TryExecup=/usr/lib/demo\nIcon=demo\n")


def call(*args, status=0):
    result = subprocess.run([binary, *map(str, args)], capture_output=True, text=True)
    assert result.returncode == status, (args, result.returncode, result.stdout, result.stderr)
    return result.stdout


def compile_into(compiler, arguments, output):
    result = subprocess.run([compiler, *arguments], capture_output=True, text=True)
    return result.returncode == 0 and output.is_file()


def squashfs(source, filesystem, runtime, name):
    filesystem = pathlib.Path(filesystem)
    subprocess.run(["mksquashfs", str(source), str(filesystem), "-noappend", "-quiet"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    image = filesystem.parent / name
    image.write_bytes(runtime + filesystem.read_bytes())
    return image


with tempfile.TemporaryDirectory() as scratch:
    root = pathlib.Path(scratch)
    runtime = bytearray(pathlib.Path("/bin/true").read_bytes())
    runtime[8:11] = b"AI\x02"
    runtime = bytes(runtime)
    filesystem = root / "filesystem.squashfs"

    # the unclassified image: a dynamic payload, a bundled library that satisfies
    # its own DT_NEEDED, an interpreter script, and a link the payload cannot carry
    source = root / "AppDir"
    (source / "usr/lib").mkdir(parents=True)
    (source / "usr/bin").mkdir(parents=True)
    (source / "AppRun").write_bytes(pathlib.Path("/bin/true").read_bytes())
    (source / "AppRun").chmod(0o755)
    (source / "program").write_bytes(pathlib.Path("/bin/true").read_bytes())
    (source / "hello").write_text("appimage fixture\n")
    (source / "launch").write_text("#!/bin/sh\nexit 0\n")
    (source / "launch").chmod(0o755)
    (source / "system-link").symlink_to("/usr/lib/external")
    private_library = False
    if compiler:
        library = root / "demo-lib.c"
        library.write_text("int demo(void) { return 7; }\n")
        program = root / "demo.c"
        program.write_text("int demo(void);\nint main(void) { return demo(); }\n")
        if compile_into(compiler, ["-shared", "-fPIC", "-Wl,-soname,libdemo.so.1",
                                   str(library), "-o", str(source / "usr/lib/libdemo.so")],
                        source / "usr/lib/libdemo.so"):
            shutil.copyfile(source / "usr/lib/libdemo.so", source / "usr/lib/libdemo.so.1")
            private_library = compile_into(
                compiler, ["-L" + str(source / "usr/lib"), "-ldemo", str(program),
                           "-o", str(source / "usr/bin/demo-program")],
                source / "usr/bin/demo-program")
            if private_library:
                (source / "usr/bin/demo-program").chmod(0o755)
            else:
                (source / "usr/lib/libdemo.so").unlink()
                (source / "usr/lib/libdemo.so.1").unlink()
        else:
            (source / "usr/lib/libdemo.so").unlink(missing_ok=True)
    image = squashfs(source, filesystem, runtime, "fixture.AppImage")

    def run(*args, status=0, env=None):
        result = subprocess.run([binary, "appimage", *map(str, args)],
                                capture_output=True, text=True, env=env)
        assert result.returncode == status, (args, result.returncode, result.stdout, result.stderr)
        return result.stdout

    def import_image(path, output, source_name, status=3):
        result = subprocess.run([binary, "import", str(path), "--source", source_name,
                                 "--format", "appimage", "--output", str(output)],
                                capture_output=True, text=True)
        assert result.returncode == status, (result.returncode, result.stdout, result.stderr)
        return result

    def unpack(artifact, into):
        call("fetch", "local:" + str(artifact), "--extract", "--output", str(into))
        return into / "DATA"

    info = run("inspect", image)
    assert "type appimage-2\n" in info
    assert f"squashfs-offset {len(runtime)}\n" in info
    assert f"sha256 {hashlib.sha256(image.read_bytes()).hexdigest()}\n" in info

    if os.geteuid() != 0:
        output = root / "extracted"
        run("extract", image, "--output", output)
        assert (output / "original").read_bytes() == image.read_bytes()
        assert (output / "AppDir" / "hello").read_text() == "appimage fixture\n"
        assert "state extracted-unclassified\n" in (output / "conversion").read_text()
        classification = (output / "classification").read_text()
        assert 'elf "program" x86_64 glibc' in classification
        assert 'entrypoint AppRun\n' in classification
        assert 'interpreter "AppRun" "/lib64/ld-linux-x86-64.so.2"' in classification
        assert 'needed "AppRun" "libc.so.6"' in classification
        assert 'version-required "AppRun" "libc.so.6"' in classification
        assert 'script "launch" "/bin/sh"' in classification
        assert 'path-view-required "system-link" "/usr/lib/external"' in classification
        assert 'runtime-probes plugins dlopen services graphics audio unknown\n' in classification
        assert list(output.glob("*.holy")) == []
        imported = root / "imported"
        staged = import_image(image, imported, "fixture")
        assert "extracted " in staged.stdout
        assert (imported / "original").read_bytes() == image.read_bytes()
        assert 'source-name "fixture"\n' in (imported / "conversion").read_text()
        artifacts = sorted(p.name for p in imported.glob("*.holy"))
        assert artifacts == ["fixture--x86_64--glibc.holy"], artifacts
        artifact = imported / artifacts[0]
        # an image that states no version records zero and says so
        identity = call("info", "local:" + str(artifact))
        assert "version 0\n" in identity and "arch x86_64\n" in identity, identity
        report = (imported / "package").read_text()
        assert "status review-required\n" in report
        assert "version the payload states none, so the package records zero\n" in report
        assert "path-view-required 1 links" in report
        assert "carries neither" in report
        assert "scripts 1 files carry an interpreter" in report
        assert "dropped the image-level sandbox" in report
        assert "changed the launch conditions" in report
        assert "carries no image-level" in staged.stderr
        verify = call("verify", "local:" + str(artifact))
        assert "verified 10 regular files, 1 symlinks, 15 directories, 0 hardlinks" in verify, verify
        manifest = call("manifest", "local:" + str(artifact))
        for path in ("usr/bin/fixture",
                     "usr/lib/holy/private/fixture/appdir/AppRun",
                     "usr/lib/holy/private/fixture/appdir/usr/bin/demo-program",
                     "usr/lib/holy/private/fixture/appdir/usr/lib/libdemo.so.1",
                     "usr/lib/holy/private/fixture/usr/bin/fixture.appimage",
                     "usr/share/holy/fixture/classification",
                     "usr/share/holy/fixture/conversion"):
            assert path in manifest, path
        requirements = call("requirements", "local:" + str(artifact))
        assert 'require "appimage-needed-0" "fixture" "soname" "libc.so.6"' in requirements
        assert ('require "appimage-link-0" "fixture" "file" "/usr/lib/external" "any" "any"'
                in requirements), requirements
        assert "requirements 2\n" in requirements
        # a payload carries no absolute link, so the link is not in the manifest
        assert "usr/lib/holy/private/fixture/appdir/system-link" not in manifest
        if private_library:
            # a library the payload carries is satisfied privately and names no
            # requirement, while the target system still has to provide libc
            assert '"libdemo.so.1"' not in requirements, requirements
            assert '"libdemo.so.1"' in call("provides", "local:" + str(artifact))
        else:
            assert '"libdemo.so.1"' in requirements
        provides = call("provides", "local:" + str(artifact))
        assert 'provide "package" "fixture" "x86_64" "glibc"' in provides
        data = unpack(artifact, root / "unpacked")
        launcher = (data / "usr/bin/fixture").read_text()
        assert launcher.startswith("#!/bin/sh\n")
        assert "holypkg run fixture:fixture" in launcher
        assert "-- /usr/lib/holy/private/fixture/usr/bin/fixture.appimage \"$@\"\n" in launcher
        assert (data / "usr/lib/holy/private/fixture/appdir/hello").read_text() == "appimage fixture\n"
        assert (data / "usr/share/holy/fixture/classification").read_text() == classification
        assert not (data / "usr/lib/holy/private/fixture/appdir/system-link").exists()
        assert os.readlink(data / "usr/lib/holy/private/fixture/usr/bin/fixture.appimage") == \
            "../../appdir/AppRun"
        run("extract", image, "--output", output, status=1)
        no_tool = root / "no-tool"
        no_tool.mkdir()
        run("extract", image, "--output", root / "missing-tool", status=6,
            env={**os.environ, "PATH": str(no_tool)})
        assert not (root / "missing-tool" / "conversion").exists()

        # a converted image can carry runtime requirements the target does not
        # have yet, and the manager refuses the set instead of installing it
        bare = root / "bare root"
        bare.mkdir()
        call("db", "init", "--root", bare)
        call("cache", "stage", "local:" + str(artifact), "--root", bare)
        unsolved = subprocess.run([binary, "db", "plan-set",
                                   hashlib.sha256(artifact.read_bytes()).hexdigest(),
                                   "--root", str(bare)], capture_output=True, text=True)
        assert unsolved.returncode == 4, unsolved
        assert "appimage-needed-0" in unsolved.stderr, unsolved.stderr
        assert not (bare / "usr/bin/fixture").exists()
    else:
        run("extract", image, "--output", root / "root-denied", status=6)

    if os.geteuid() != 0:
        # the complete image: a version in the desktop entry, an app tree and an
        # entry point the run context starts. the payload is static, so the only
        # thing under test is the packaging and the launch context.
        full = root / "FullDir"
        (full / "app").mkdir(parents=True)
        (full / "usr" / "bin").mkdir(parents=True)
        (full / "app" / "resource").write_text("payload resource\n")
        (full / "vendor.desktop").write_text(DESKTOP + "X-AppImage-Version=1.2.3\n")
        entry = root / "entry.c"
        entry.write_text("int main(void) { return 0; }\n")
        self_contained = compiler and compile_into(
            compiler, ["-static", str(entry), "-o", str(full / "AppRun")], full / "AppRun")
        if not self_contained:
            shutil.copyfile("/bin/true", full / "AppRun")
        (full / "AppRun").chmod(0o755)
        shutil.copyfile(full / "AppRun", full / "usr" / "bin" / "helper")
        (full / "usr" / "bin" / "helper").chmod(0o755)
        complete = squashfs(full, root / "complete.squashfs", runtime, "vendor.AppImage")
        output = root / "converted"
        import_image(complete, output, "vendor")
        # a static payload records the runtime it actually has, not the one the
        # host libc would suggest
        expected_libc = "nolibc" if self_contained else "glibc"
        artifacts = sorted(p.name for p in output.glob("*.holy"))
        assert artifacts == ["vendor--x86_64--" + expected_libc + ".holy"], artifacts
        artifact = output / artifacts[0]
        identity = call("info", "local:" + str(artifact))
        assert "name vendor\n" in identity and "version 1.2.3\n" in identity, identity
        manifest = call("manifest", "local:" + str(artifact))
        for path in ("usr/bin/vendor",
                     "usr/share/applications/vendor.desktop",
                     "usr/lib/holy/private/vendor/appdir/app/resource",
                     "usr/lib/holy/private/vendor/appdir/usr/bin/helper",
                     "usr/lib/holy/private/vendor/usr/bin/vendor.appimage"):
            assert path in manifest, path
        call("verify", "local:" + str(artifact))
        data = unpack(artifact, root / "complete-payload")
        desktop = (data / "usr/share/applications/vendor.desktop").read_text()
        assert "Exec=/usr/bin/vendor %F\n" in desktop, desktop
        assert "TryExecup=/usr/bin/vendor\n" in desktop, desktop
        assert "X-AppImage-Version=1.2.3\n" in desktop
        assert "Icon=demo\n" in desktop
        assert "Name=Demo\n" in desktop
        launcher = (data / "usr/bin/vendor").read_text()
        assert "holypkg run vendor:vendor" in launcher
        assert "--view /app=/usr/lib/holy/private/vendor/appdir/app" in launcher
        assert "-- /usr/lib/holy/private/vendor/usr/bin/vendor.appimage \"$@\"" in launcher
        report = (output / "package").read_text()
        assert "version the payload states" not in report, report
        assert "desktop-entry rewritten to /usr/bin/vendor" in report
        assert "runtime probes static inspection cannot close" in report

        # the package installs once the runtime it names is available, and the run
        # context starts the private entry point the launcher names. the launcher
        # is a shell script, so a converted image needs a shell on the target too;
        # a provider claim counts only for a real payload file, so the fixture is
        # a static program at the path the launcher names.
        target = root / "target root"
        (target / "usr/bin").mkdir(parents=True)
        call("db", "init", "--root", target)
        call("cache", "stage", "local:" + str(artifact), "--root", target)
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        runtime_tree = root / "runtime"
        (runtime_tree / "HOLY").mkdir(parents=True)
        (runtime_tree / "DATA/bin").mkdir(parents=True)
        shell_source = root / "sh.c"
        shell_source.write_text("int main(void) { return 0; }\n")
        interpreter = compiler and compile_into(
            compiler, ["-static", str(shell_source), "-o",
                       str(runtime_tree / "DATA/bin/sh")], runtime_tree / "DATA/bin/sh")
        if interpreter:
            (runtime_tree / "DATA/bin/sh").chmod(0o755)
            (runtime_tree / "HOLY/meta").write_text("format holy-package-1\nname fixture-shell\n"
                                               "version 1\nrelease 1\nos linux\n"
                                               "arch x86_64\nlibc nolibc\n")
            for name in ("deps", "provides", "hooks", "origin", "transform"):
                (runtime_tree / "HOLY" / name).write_text("")
            call("manifest", "generate", runtime_tree, "--output", root / "runtime-files")
            (runtime_tree / "HOLY/files").write_text((root / "runtime-files").read_text())
            call("pack", runtime_tree, "--output", root / "runtime.holy")
            runtime_digest = hashlib.sha256((root / "runtime.holy").read_bytes()).hexdigest()
            call("cache", "stage", "local:" + str(root / "runtime.holy"), "--root", target)
            plan = call("db", "plan-set", digest, runtime_digest, "--root", target)
            plan_sha = [line.split()[10] for line in plan.splitlines()
                        if line.startswith("plan-set ")][0]
            applied = call("db", "apply-set", plan_sha, digest, runtime_digest, "--root", target)
            assert "artifacts 2" in applied, applied
            assert (target / "usr/bin/vendor").is_file()
            assert (target / "usr/share/applications/vendor.desktop").is_file()
            assert (target / "usr/lib/holy/private/vendor/appdir/AppRun").is_file()
            assert (target / "usr/share/holy/vendor/classification").is_file()
            assert (target / "usr/lib/holy/private/vendor/usr/bin/vendor.appimage").is_symlink()
            assert (target / "usr/bin/vendor").read_text() == launcher
            started = subprocess.run([binary, "run", "local:vendor", "--root", str(target),
                                      "--",
                                      "/usr/lib/holy/private/vendor/usr/bin/vendor.appimage"],
                                     capture_output=True, text=True)
            assert started.returncode == 0, (started.returncode, started.stdout, started.stderr)
            # a directory view over the private app tree resolves the image's own path
            (target / "app").mkdir()
            viewed = subprocess.run([binary, "run", "local:vendor", "--root", str(target),
                                     "--view", "/app=/usr/lib/holy/private/vendor/appdir/app",
                                     "--", "/usr/lib/holy/private/vendor/usr/bin/vendor.appimage"],
                                    capture_output=True, text=True)
            assert viewed.returncode == 0, (["run", "local:vendor", "--root", str(target),
                                      "--view", "/app=usr/lib/holy/private/vendor/appdir/app",
                                      "--", "/usr/lib/holy/private/vendor/usr/bin/vendor.appimage"],
                                     viewed.returncode, viewed.stdout, viewed.stderr)
            # a private command outside a bin directory is refused, not guessed
            refused = subprocess.run([binary, "run", "local:vendor", "--root", str(target),
                                      "--", "/usr/lib/holy/private/vendor/appdir/AppRun"],
                                     capture_output=True, text=True)
            assert refused.returncode != 0, (refused.returncode, refused.stdout)
            refused = subprocess.run([binary, "run", "local:vendor", "--root", str(target),
                                      "--", "/usr/lib/holy/private/vendor/vendor.appimage"],
                                     capture_output=True, text=True)
            assert refused.returncode != 0, (refused.returncode, refused.stdout)
            # the launcher itself refuses to run as root, because the converted
            # payload is not a sandbox
            if os.geteuid() == 0:
                root_run = subprocess.run(["/bin/sh", str(target / "usr/bin/vendor")],
                                          capture_output=True, text=True)
                assert root_run.returncode == 1, root_run
                assert "not a sandbox" in root_run.stderr, root_run.stderr
        else:
            # without a compiler there is no interpreter fixture, so the set the
            # converted package needs cannot be staged here
            unresolved = subprocess.run([binary, "db", "plan-set", digest, "--root", str(target)],
                                        capture_output=True, text=True)
            assert unresolved.returncode == 4, unresolved
            assert not (target / "usr/bin/vendor").exists()

        # an image whose payload mixes architectures cannot become one package
        mixed = root / "MixedDir"
        mixed.mkdir()
        shutil.copyfile("/bin/true", mixed / "AppRun")
        (mixed / "AppRun").chmod(0o755)
        if compiler:
            built = subprocess.run([compiler, "-m32", "-shared", "-fPIC", str(root / "demo-lib.c"),
                                    "-o", str(mixed / "lib32.so")], capture_output=True, text=True)
            if built.returncode == 0:
                (mixed / "lib32.so").chmod(0o755)
                image32 = squashfs(mixed, root / "mixed.squashfs", runtime, "mixed.AppImage")
                refused = import_image(image32, root / "mixed", "vendor")
                assert "more than one architecture" in refused.stderr, refused.stderr
                assert not list((root / "mixed").glob("*.holy"))

        # a file name the manifest cannot carry, and images without a usable entry
        unnamed = root / "odd name.AppImage"
        unnamed.write_bytes(runtime + filesystem.read_bytes())
        refused = import_image(unnamed, root / "unnamed", "vendor", status=2)
        assert "not a package name" in refused.stderr, refused.stderr
        entryless = root / "EntryDir"
        entryless.mkdir()
        (entryless / "data").write_text("no entry point\n")
        refused = import_image(squashfs(entryless, root / "entryless.squashfs", runtime,
                                        "entryless.AppImage"),
                               root / "entryless", "vendor")
        assert "no AppRun entry point" in refused.stderr, refused.stderr
        assert not list((root / "entryless").glob("*.holy"))
        plain = root / "PlainDir"
        plain.mkdir()
        (plain / "AppRun").write_text("not executable\n")
        refused = import_image(squashfs(plain, root / "plain.squashfs", runtime,
                                        "plain.AppImage"),
                               root / "plain", "vendor", status=2)
        assert "not executable" in refused.stderr, refused.stderr
        link = root / "LinkDir"
        link.mkdir()
        shutil.copyfile("/bin/true", link / "real")
        (link / "real").chmod(0o755)
        os.symlink("real", link / "AppRun")
        refused = import_image(squashfs(link, root / "link.squashfs", runtime,
                                        "link.AppImage"),
                               root / "link", "vendor")
        assert "not an ordinary file" in refused.stderr, refused.stderr

    broken = root / "broken.AppImage"
    broken.write_bytes(runtime + b"not squashfs")
    run("inspect", broken, status=2)
    old = root / "type1.AppImage"
    old.write_bytes(bytes(runtime[:10]) + b"\x01" + bytes(runtime[11:]) +
                    filesystem.read_bytes())
    run("inspect", old, status=2)
    duplicate = root / "duplicate.AppImage"
    duplicate.write_bytes(runtime + filesystem.read_bytes() + filesystem.read_bytes())
    run("inspect", duplicate, status=3)

print("appimage inspect/extract/import fixtures passed")
