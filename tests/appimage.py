#!/usr/bin/env python3
import hashlib
import os
import pathlib
import subprocess
import sys
import tempfile

binary = str(pathlib.Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory() as scratch:
    root = pathlib.Path(scratch)
    source = root / "AppDir"
    source.mkdir()
    (source / "hello").write_text("appimage fixture\n")
    (source / "program").write_bytes(pathlib.Path("/bin/true").read_bytes())
    (source / "AppRun").write_bytes(pathlib.Path("/bin/true").read_bytes())
    (source / "AppRun").chmod(0o755)
    script = source / "launch"
    script.write_text("#!/bin/sh\nexit 0\n")
    script.chmod(0o755)
    (source / "system-link").symlink_to("/usr/lib/external")
    filesystem = root / "filesystem.squashfs"
    subprocess.run(["mksquashfs", str(source), str(filesystem), "-noappend", "-quiet"],
                   check=True, stdout=subprocess.DEVNULL)
    runtime = bytearray(pathlib.Path("/bin/true").read_bytes())
    runtime[8:11] = b"AI\x02"
    image = root / "fixture.AppImage"
    image.write_bytes(runtime + filesystem.read_bytes())

    def run(*args, status=0, env=None):
        result = subprocess.run([binary, "appimage", *map(str, args)],
                                capture_output=True, text=True, env=env)
        assert result.returncode == status, (args, result.returncode, result.stdout, result.stderr)
        return result.stdout

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
        staged = subprocess.run([binary, "import", str(image), "--source", "fixture",
                                 "--format", "appimage", "--output", str(imported)],
                                capture_output=True, text=True)
        assert staged.returncode == 3, (staged.stdout, staged.stderr)
        assert (imported / "original").read_bytes() == image.read_bytes()
        assert 'source-name "fixture"\n' in (imported / "conversion").read_text()
        assert not list(imported.glob("*.holy"))
        run("extract", image, "--output", output, status=1)
        no_tool = root / "no-tool"
        no_tool.mkdir()
        run("extract", image, "--output", root / "missing-tool", status=6,
            env={**os.environ, "PATH": str(no_tool)})
        assert not (root / "missing-tool" / "conversion").exists()
    else:
        run("extract", image, "--output", root / "root-denied", status=6)

    broken = root / "broken.AppImage"
    broken.write_bytes(runtime + b"not squashfs")
    run("inspect", broken, status=2)
    old = root / "type1.AppImage"
    old.write_bytes(bytes(runtime[:10]) + b"\x01" + bytes(runtime[11:]) + filesystem.read_bytes())
    run("inspect", old, status=2)
    duplicate = root / "duplicate.AppImage"
    duplicate.write_bytes(runtime + filesystem.read_bytes() + filesystem.read_bytes())
    run("inspect", duplicate, status=3)

print("appimage inspect/extract fixtures passed")
