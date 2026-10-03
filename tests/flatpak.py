#!/usr/bin/env python3
"""converts Flatpak manifests into holy recipes and builds the produced manifests."""
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile


binary = str(Path(sys.argv[1]).resolve())


def run(*args, status=0):
    result = subprocess.run([binary, *map(str, args)], text=True, capture_output=True,
                           errors="replace")
    assert result.returncode == status, (args, result.returncode, result.stdout, result.stderr)
    return result.stdout


def read_metadata(artifact):
    contents = subprocess.run(["lz4", "-dc", str(artifact)], check=True,
                              capture_output=True).stdout
    with tarfile.open(fileobj=io.BytesIO(contents)) as archive:
        def read(name):
            return archive.extractfile(name).read().decode()
        names = sorted(member.name for member in archive.getmembers())
        return {name: read(name) for name in
                ("HOLY/meta", "HOLY/files", "HOLY/deps", "HOLY/provides", "HOLY/hooks",
                 "HOLY/origin", "HOLY/transform")}, names


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def source_tree(root, name, version):
    directory = root / f"{name}-{version}"
    directory.mkdir(parents=True)
    write(directory / "Makefile", """CFLAGS ?= -O2 -pipe
all: bin/%(name)s
bin/%(name)s: main.c
\tmkdir -p bin
\t$(CC) $(CFLAGS) -o $@ main.c
install: bin/%(name)s
\tmkdir -p $(DESTDIR)/usr/bin $(DESTDIR)/usr/share/%(name)s
\tcp bin/%(name)s $(DESTDIR)/usr/bin/
\tprintf 'from the template\\n' > $(DESTDIR)/usr/share/%(name)s/greeting
""" % {"name": name})
    write(directory / "main.c", '#include <stdio.h>\nint main(void){printf("hi\\n");return 0;}\n')
    return directory


def archive_of(directory, root):
    archive = root / f"{directory.name}.tar.gz"
    subprocess.run(["tar", "czf", str(archive), "-C", str(directory.parent), directory.name],
                   check=True)
    return archive


def convert(directory, file_name=None, name="Holy", status=0, source="flathub", fmt=None):
    if file_name is None:
        file_name = sorted(p.name for p in directory.glob("*.json"))[0]
    args = ["convert", directory / file_name, "--source", source,
            "--output", directory / "conv"]
    if fmt:
        args = ["import", directory / file_name, "--source", source, "--format", fmt,
                "--output", directory / "conv"]
    out = run(*args, status=status)
    return out, (directory / "conv" / f"{name}.recipe").read_text(), \
        (directory / "conv" / "conversion").read_text()


def main():
    if not shutil.which("lz4"):
        print("lz4 required for the flatpak fixture", file=sys.stderr)
        return 6
    for tool in ("cc", "make", "tar", "patch"):
        if not shutil.which(tool):
            print(f"{tool} required for the flatpak fixture", file=sys.stderr)
            return 6
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        tree = source_tree(root, "holy-flatpak-demo", "1.0")
        archive = archive_of(tree, root)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()

        # a manifest that builds a program through a template this converter spells out
        meson = root / "meson"
        meson.mkdir(parents=True)
        write(meson / "org.example.Meson.json", f"""{{
  "id": "org.example.Meson",
  "branch": "stable",
  "runtime": "org.holy.Platform//45",
  "runtime-version": "45",
  "sdk": "org.holy.Sdk//45",
  "command": "bin/holy-flatpak-demo",
  "arch": "x86_64",
  "summary": "A Flatpak manifest built with meson",
  "url": "https://example.org/meson",
  "modules": [
    {{
      "name": "holy-flatpak-demo",
      "buildsystem": "meson",
      "build-options": {{
        "env": {{ "CC": "cc" }},
        "append-path": ["/app/bin"],
        "cflags": ["-O2"]
      }},
      "sources": [
        {{ "type": "archive", "url": "https://example.org/holy-flatpak-demo-1.0.tar.gz",
           "sha256": "{digest}" }}
      ]
    }}
  ]
}}
""")
        out, recipe, report = convert(meson, name="Meson")
        assert "converted Meson status native" in out
        assert 'name "Meson"' in recipe and 'arch "x86_64"' in recipe and "libc any" in recipe
        assert "the machine x86_64 of the manifest or its branch" in report
        assert 'version "0"' in recipe
        assert 'summary "A Flatpak manifest built with meson"' in recipe
        assert 'homepage "https://example.org/meson"' in recipe
        assert 'x-source-family flatpak' in recipe and 'x-converter flatpak-1' in recipe
        assert 'x-app-id "org.example.Meson"' in recipe
        assert 'x-flatpak-branch "stable"' in recipe
        assert 'x-flatpak-command "bin/holy-flatpak-demo"' in recipe
        # the sdk builds the modules and the runtime is what the program runs on
        assert 'build-depend "Sdk" "any" "-"' in recipe
        assert 'depend "Platform" "any" "-"' in recipe
        assert "the sdk org.holy.Sdk//45 builds the modules" in report
        assert "so they are separate requirements" in report
        # the command is a path under /app, and a Holy payload installs under /usr
        assert "is a path under /app" in report
        # the archive is a source with the digest the manifest pins
        assert 'source "holy-flatpak-demo-0" "https://example.org/holy-flatpak-demo-1.0.tar.gz"' \
            in recipe
        assert f'source-sha256 "holy-flatpak-demo-0" "{digest}"' in recipe
        # the environment of the module and the meson template spelled out
        assert 'export CC="cc"' in recipe and 'export CFLAGS="-O2"' in recipe
        assert 'PATH="/app/bin:$PATH"' in recipe
        assert 'meson setup build --prefix="$PREFIX" --libdir=lib' in recipe
        assert 'meson compile -C build -j "$HOLY_JOBS"' in recipe
        assert 'DESTDIR="$HOLY_DEST" meson install -C build' in recipe
        assert 'cd "$HOLY_SRC/holy-flatpak-demo-0" || exit 1' in recipe
        assert "the meson template of module holy-flatpak-demo is replaced" in report
        assert "status native" in report and "unknown 0" in report
        assert hashlib.sha256((meson / "org.example.Meson.json").read_bytes()).hexdigest() in report

        # the same manifest reaches the converter through import --format
        imported = run("import", meson / "org.example.Meson.json", "--source", "flathub",
                       "--format", "flatpak", "--output", root / "imported")
        assert (root / "imported" / "Meson.recipe").is_file(), imported

        # a manifest whose modules build with the other templates, with a patch, an
        # inline file and a shell source, and with permissions the build cannot keep
        simple = root / "simple"
        simple.mkdir(parents=True)
        patch = source_tree(root, "holy-flatpak-simple", "2.1")
        write(patch / "greeting.txt", "before\n")
        write(patch / "version.txt", "after\n")
        diff = subprocess.run(["diff", "-u", "greeting.txt", "version.txt"], cwd=str(patch),
                              capture_output=True, text=True).stdout
        write(simple / "greeting.patch",
              diff.replace("--- greeting.txt", "--- a/greeting.txt")
              .replace("+++ version.txt", "+++ b/greeting.txt"))
        simple_archive = archive_of(patch, root)
        shutil.copy(simple_archive, simple / simple_archive.name)
        write(simple / "org.example.Simple.json", f"""{{
  "id": "org.example.Simple",
  "runtime": "org.holy.Platform//45",
  "sdk": "org.holy.Sdk//45",
  "finish-args": ["--share=network", "--socket=x11"],
  "cleanup": ["appstream"],
  "modules": [
    {{
      "name": "app",
      "buildsystem": "simple",
      "sources": [
        {{ "type": "archive", "url": "{simple_archive.name}" }},
        {{ "type": "patch", "path": "greeting.patch" }},
        {{ "type": "shell", "commands": ["printf 'shell source\\n' > shell-ran"] }}
      ],
      "build-commands": [
        "make",
        "install -Dm644 greeting.txt /app/share/greeting"
      ]
    }},
    {{
      "name": "extra",
      "buildsystem": "make",
      "sources": [
        {{ "type": "inline", "contents": "inline body", "dest-filename": "extra.txt" }},
        {{ "type": "inline", "dest-filename": "extra.c",
           "contents": "int main(void) {{ return 0; }}\\n" }},
        {{ "type": "inline", "dest-filename": "Makefile",
           "contents": "all:\\n\\t$(CC) -o extra extra.c\\ninstall: all\\n\\tmkdir -p $(DESTDIR)/usr/bin\\n\\tcp extra $(DESTDIR)/usr/bin/\\n" }}
      ]
    }},
    {{
      "name": "unknown-system",
      "buildsystem": "gradle"
    }}
  ]
}}
""")
        out, recipe, report = convert(simple, name="Simple", status=3)
        # the patch applies before the module builds, in the tree the engine extracted
        assert 'step prepare /bin/sh <<STEP' in recipe
        assert f'cd "$HOLY_SRC/{simple_archive.name}" || exit 1' in recipe
        assert f'source "{simple_archive.name}" "{simple_archive.name}"' in recipe
        assert 'patch -p1 -i "$HOLY_SRC/greeting.patch"' in recipe
        assert (simple / "conv" / "greeting.patch").is_file()
        assert "the patch greeting.patch applies with -p1" in report
        # a path under /app becomes the payload, so a build command writes nowhere else
        assert 'install -Dm644 greeting.txt $DESTDIR/share/greeting' in recipe
        assert "/app/share/greeting" not in recipe
        assert "writes under /app, so the path becomes $DESTDIR" in report
        # the inline source travels beside the recipe and the make template is spelled out
        assert 'source "extra.txt" "extra.txt"' in recipe
        assert (simple / "conv" / "extra.txt").read_text() == "inline body\n", \
            (simple / "conv" / "extra.txt").read_bytes()
        assert 'make DESTDIR="$HOLY_DEST" install' in recipe
        assert "the make template of module extra is replaced" in report
        # the shell source runs inside the step of its module
        assert "printf 'shell source" in recipe, recipe
        assert "shell-ran" in recipe
        # the permissions and the cleanup are reported and kept out of the recipe
        assert "the permission --share=network is a Flatpak sandbox decision" in report
        assert "the permission --socket=x11 is a Flatpak sandbox decision" in report
        assert 'x-flatpak-finish-args "--share=network --socket=x11"' in recipe
        assert "the cleanup step appstream runs after the build" in report
        # a buildsystem with no Holy phase is a helper, not a guess
        assert "the gradle buildsystem of module unknown-system is a flatpak-builder template" \
            in report
        assert "helper 1" in report
        # flatpak-builder is the helper environment this converter does not run
        assert "helper-environment flatpak-builder" in report
        env_digest = report.split("helper-environment-sha256 ")[1].split()[0]
        assert f'x-helper-environment-sha256 "{env_digest}"' in recipe
        # the modules no longer share one prefix
        assert "shares one prefix across its 3 modules" in report
        assert "status review-required" in report
        # the unreviewed recipe still builds through the normal engine
        run("build", simple / "conv" / "Simple.recipe", "--output", root / "simple-out", "--yes")
        artifacts = sorted(p.name for p in (root / "simple-out").glob("*.holy"))
        assert artifacts, "the converted recipe produced no artifact"

        # a manifest with an autotools module keeps its own shell
        autotools = root / "autotools"
        autotools.mkdir(parents=True)
        write(autotools / "org.example.Autotools.json", """{
  "id": "org.example.Autotools",
  "version": "3.2",
  "runtime": "org.holy.Platform",
  "sdk": "org.holy.Sdk",
  "arch": "x86_64",
  "modules": [
    {
      "name": "autotools",
      "buildsystem": "autotools",
      "build-options": { "prefix": "/usr", "flags": ["--disable-static"] },
      "sources": [ { "type": "file", "path": "absent.patch" } ]
    }
  ]
}
""")
        out, recipe, report = convert(autotools, name="Autotools", status=3)
        assert 'version "3.2"' in recipe and 'arch "x86_64"' in recipe
        assert 'the version 3.2 of the manifest' in report
        assert "./configure --prefix=\"$PREFIX\" --disable-static" in recipe
        assert "the prefix /usr of module autotools is kept" in report
        assert "absent.patch is not beside the manifest" in report
        assert 'source "absent.patch"' not in recipe
        assert "the manifest states no summary" not in report

        # a module the manifest limits by architecture is a choice this converter does
        # not make, since the target it will be installed into is what the limit is read
        # against
        limited = root / "limited"
        limited.mkdir(parents=True)
        write(limited / "org.example.Limited.json", """{
  "id": "org.example.Limited",
  "version": "1.0",
  "modules": [
    {
      "name": "app",
      "buildsystem": "simple",
      "only-arches": [ "x86_64" ],
      "build-commands": [ "true" ]
    }
  ]
}
""")
        out, recipe, report = convert(limited, name="Limited", status=3)
        assert "status review-required" in out
        assert "the module app limits itself by architecture with only-arches, which the " \
               "converter does not decide" in report

        # a branch names the machine when the manifest states none
        branch = root / "branch"
        branch.mkdir(parents=True)
        write(branch / "org.example.Branch.json", """{
  "id": "org.example.Branch/i386/beta",
  "branch": "i386/beta",
  "modules": [ { "name": "app", "buildsystem": "simple",
                 "build-commands": ["true"] } ]
}
""")
        out, recipe, report = convert(branch, name="Branch")
        assert 'arch "i686"' in recipe
        assert 'x-app-id "org.example.Branch/i386/beta"' in recipe
        assert 'x-flatpak-branch "i386/beta"' in recipe

        # a manifest that is not JSON, or states no id, is refused
        yaml = root / "yaml"
        yaml.mkdir(parents=True)
        write(yaml / "org.example.Yaml.yaml", "id: org.example.Yaml\nmodules: []\n")
        result = subprocess.run([binary, "convert", str(yaml / "org.example.Yaml.yaml"),
                                 "--source", "flathub", "--output", str(yaml / "conv")],
                                capture_output=True, text=True)
        assert result.returncode == 2, result
        assert "this converter reads no other form" in result.stderr, result.stderr
        write(yaml / "org.example.NoId.json", '{ "modules": [] }\n')
        result = subprocess.run([binary, "convert", str(yaml / "org.example.NoId.json"),
                                 "--source", "flathub", "--output", str(yaml / "conv2")],
                                capture_output=True, text=True)
        assert result.returncode == 2, result
        assert "needs a literal id" in result.stderr, result.stderr
        write(yaml / "org.example.Broken.json", '{ "id": "org.example.Broken", "modules": [ }\n')
        result = subprocess.run([binary, "convert", str(yaml / "org.example.Broken.json"),
                                 "--source", "flathub", "--output", str(yaml / "conv3")],
                                capture_output=True, text=True)
        assert result.returncode == 2, result
        assert "reads no other form" in result.stderr, result.stderr
        result = subprocess.run([binary, "convert", str(root / "absent.json"), "--source",
                                 "flathub", "--output", str(root / "conv4")],
                                capture_output=True, text=True)
        assert result.returncode == 6, result
        assert "manifest unavailable" in result.stderr, result.stderr

        # a manifest with no module builds nothing, and says so
        empty = root / "empty"
        empty.mkdir(parents=True)
        write(empty / "org.example.Empty.json",
              '{ "id": "org.example.Empty", "modules": [] }\n')
        out, recipe, report = convert(empty, name="Empty", status=3)
        assert "names no module" in report
        assert "step build" not in recipe

    print("flatpak manifest fixtures passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
