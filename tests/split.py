#!/usr/bin/env python3
"""proposes the split outputs of a prepared package tree, and proves that a path no
rule settles is reported as a decision rather than assigned by a file extension."""
import pathlib
import shutil
import subprocess
import sys
import tempfile


binary = str(pathlib.Path(sys.argv[1]).resolve())


def call(*args, status=0):
    result = subprocess.run([binary, *map(str, args)], capture_output=True, text=True)
    assert result.returncode == status, (args, result.returncode, result.stdout, result.stderr)
    return result.stdout


def build(sources, name, arch="x86_64"):
    """one prepared tree, as manifest generate and pack expect it"""
    tree = sources / f"tree-{name}"
    (tree / "HOLY").mkdir(parents=True)
    (tree / "DATA").mkdir()
    (tree / "HOLY/meta").write_text(
        f"format holy-package-1\nname {name}\nversion 1\nrelease 1\nos linux\n"
        f"arch {arch}\nlibc nolibc\n")
    for field in ("deps", "provides", "hooks", "origin", "transform", "files"):
        (tree / "HOLY" / field).write_text("")
    return tree


def put(tree, relative, body, mode=0o644):
    target = tree / "DATA" / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body)
    target.chmod(mode)


def compiler():
    for name in ("cc", "gcc", "clang"):
        if shutil.which(name):
            return name
    return None


def compile_into(cc, arguments, output):
    output.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run([cc, *map(str, arguments)], capture_output=True, text=True)
    assert result.returncode == 0, (arguments, result.stdout, result.stderr)
    return output


def read(path):
    records = {}
    for line in path.read_text().splitlines():
        fields = line.split(" ", 2)
        records.setdefault(fields[0], []).append(line)
    return path.read_text()


def main():
    cc = compiler()
    if not cc:
        print("a host compiler required for the split fixture", file=sys.stderr)
        return 6
    with tempfile.TemporaryDirectory() as scratch:
        root = pathlib.Path(scratch)
        sources = root / "sources"
        sources.mkdir()

        # the payload a real project installs: a program, a versioned object, an
        # unversioned plugin, a static archive, headers, pkg-config metadata,
        # documentation, a license and a payload link
        tree = build(sources, "fixture")
        main_source = sources / "main.c"
        main_source.write_text("int main(void) { return 0; }\n")
        library_source = sources / "lib.c"
        library_source.write_text("int answer(void) { return 42; }\n")
        program = compile_into(cc, ["-static", str(main_source), "-o",
                                    str(tree / "DATA/usr/bin/fixture")],
                               tree / "DATA/usr/bin/fixture")
        program.chmod(0o755)
        library = compile_into(cc, ["-shared", "-fPIC", "-Wl,-soname,libfixture.so.1",
                                    str(library_source), "-o",
                                    str(tree / "DATA/usr/lib/libfixture.so.1")],
                               tree / "DATA/usr/lib/libfixture.so.1")
        library.chmod(0o755)
        plugin = compile_into(cc, ["-shared", "-fPIC", str(library_source), "-o",
                                   str(tree / "DATA/usr/lib/pluginfixture.so")],
                              tree / "DATA/usr/lib/pluginfixture.so")
        plugin.chmod(0o755)
        (tree / "DATA/usr/lib/libfixture.so").symlink_to("libfixture.so.1")
        object_file = compile_into(cc, ["-c", str(library_source), "-o",
                                        str(sources / "lib.o")], sources / "lib.o")
        archive = tree / "DATA/usr/lib/libfixture.a"
        archive.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(["ar", "rcs", str(archive), str(object_file)],
                                capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        put(tree, "usr/include/fixture.h", "int answer(void);\n")
        put(tree, "usr/lib/pkgconfig/fixture.pc", "Name: fixture\nVersion: 1\n")
        put(tree, "usr/share/man/man1/fixture.1", ".TH FIXTURE 1\n")
        put(tree, "usr/share/doc/fixture/README", "the manual page fixture\n")
        put(tree, "usr/share/licenses/fixture", "MIT\n")

        # a license and a runtime data file are not documentation, however a general
        # pattern would match them
        proposal = root / "proposal"
        report = call("split", tree, "--output", proposal, status=3)
        assert "paths 10 runtime 4 devel 2 docs 2 debug 0 decisions 2" in report, report
        body = proposal.read_text()
        assert body.startswith('format holy-split-1\nname "fixture"\n'), body
        # the runtime output keeps the program, the versioned object, the payload link
        # and the license
        for path, output, reason in (
                ("usr/bin/fixture", "fixture", "executable"),
                ("usr/lib/libfixture.so.1", "fixture", "versioned shared object"),
                ("usr/lib/libfixture.so", "fixture", "payload link"),
                ("usr/share/licenses/fixture", "fixture", "runtime payload")):
            assert f'path "{path}" "{output}" "{reason}"' in body, (path, body)
        # headers and pkg-config metadata are proposed for the development output
        assert 'path "usr/include/fixture.h" "fixture-devel" "header"' in body, body
        assert 'path "usr/lib/pkgconfig/fixture.pc" "fixture-devel" "pkg-config metadata"' \
            in body, body
        # man pages and reference documents are proposed for the documentation output
        assert 'path "usr/share/man/man1/fixture.1" "fixture-doc" "documentation"' in body, body
        assert 'path "usr/share/doc/fixture/README" "fixture-doc" "documentation"' in body, body
        # an unversioned object and a static archive are decisions, not assignments:
        # a file extension is not a sufficient criterion and a tree states no
        # metadata or dlopen probe that would settle either
        assert 'decision "usr/lib/pluginfixture.so" "unversioned-object" suggested "fixture"' \
            in body, body
        assert 'decision "usr/lib/libfixture.a" "static-archive" suggested "fixture-devel"' \
            in body, body
        assert "unversioned-object\n" in report and "static-archive\n" in report, report
        # the outputs the proposal declares are the ones it assigns
        assert 'output "fixture" runtime\n' in body, body
        assert 'output "fixture-devel" devel\n' in body, body
        assert 'output "fixture-doc" docs\n' in body, body

        # an explicit rule outranks the heuristic, so the same tree proposes no
        # decision once the operator states where the object and the archive belong
        ruled = root / "ruled"
        report = call("split", tree, "--output", ruled, "--split", "fixture",
                      "usr/lib/pluginfixture.so", "--split", "fixture-devel",
                      "usr/lib/libfixture.a")
        assert "decisions 0" in report, report
        body = ruled.read_text()
        assert 'path "usr/lib/pluginfixture.so" "fixture" "explicit rule"' in body, body
        assert 'path "usr/lib/libfixture.a" "fixture-devel" "explicit rule"' in body, body
        assert "decision " not in body, body

        # two rules naming different outputs for one path is a contradiction the
        # operator has to settle, so the path is a decision rather than a guess
        repeated = root / "repeated"
        report = call("split", tree, "--output", repeated, "--split", "fixture",
                      "usr/lib/*", "--split", "fixture-devel", "usr/lib/*", status=3)
        assert "decisions 5" in report, report
        body = repeated.read_text()
        assert 'decision "usr/lib/pluginfixture.so" "repeated"' in body, body
        assert 'decision "usr/lib/libfixture.a" "repeated"' in body, body

        # a link that leaves the tree it installs into is a decision, and so is an
        # absolute one, because a payload carries neither
        for target, name in (("../../../outside", "escape"), ("/usr/bin/escape", "absolute")):
            link = tree / f"DATA/usr/bin/{name}"
            link.symlink_to(target)
            escaped = root / f"escaped-{name}"
            report = call("split", tree, "--output", escaped, status=3)
            assert f'decision "usr/bin/{name}" "escaping-link"' in escaped.read_text(), target
            assert f"decision usr/bin/{name} escaping-link\n" in report, report
            link.unlink()

        # a rule may only name an output this proposal declares
        unknown = root / "unknown"
        result = subprocess.run([binary, "split", tree, "--output", str(unknown), "--split",
                                 "elsewhere", "usr/lib/*"], capture_output=True, text=True)
        assert result.returncode == 2, result
        assert "undeclared output elsewhere" in result.stderr, result.stderr

        # a tree without HOLY/meta, and a tree that is not there
        bare = build(sources, "bare")
        for field in ("deps", "provides", "hooks", "origin", "transform", "files"):
            (bare / "HOLY" / field).write_text("")
        (bare / "HOLY/meta").unlink()
        result = subprocess.run([binary, "split", bare, "--output", str(root / "bare.txt")],
                                capture_output=True, text=True)
        assert result.returncode == 2, result
        assert "HOLY/meta" in result.stderr, result.stderr
        result = subprocess.run([binary, "split", root / "absent", "--output",
                                 str(root / "absent.txt")], capture_output=True, text=True)
        assert result.returncode == 6, result
        assert "prepared tree unavailable" in result.stderr, result.stderr

        # a data-only tree proposes one runtime output and no development or
        # documentation output, because a declared output that receives nothing is
        # what a build rejects
        data = build(sources, "dataonly")
        put(data, "usr/share/fixture/data", "runtime data\n")
        plain = root / "plain"
        report = call("split", data, "--output", plain)
        assert "paths 1 runtime 1 devel 0 docs 0 debug 0 decisions 0" in report, report
        body = plain.read_text()
        assert 'output "dataonly" runtime\n' in body, body
        assert 'output "dataonly-devel"' not in body, body
        assert 'output "dataonly-doc"' not in body, body
        assert 'output "dataonly-debug"' not in body, body

        # a debug output is cut from the runtime files by build-id, so a payload
        # built with a note names the debug file and keeps the build-id the stripped
        # artifact is matched against, and one without a note is a decision
        program_source = sources / "program.c"
        program_source.write_text("int main(void) { return 0; }\n")
        debugged = build(sources, "debugged")
        noted = compile_into(cc, ["-g", "-O0", "-Wl,--build-id", str(program_source), "-o",
                                   str(debugged / "DATA/usr/bin/debugged")],
                             debugged / "DATA/usr/bin/debugged")
        noted.chmod(0o755)
        put(debugged, "usr/include/debugged.h", "int answer(void);\n")
        proposal = root / "debugged"
        report = call("split", debugged, "--output", proposal, "--debug")
        assert "debug 1 decisions 0" in report, report
        body = proposal.read_text()
        assert 'output "debugged-debug" debug\n' in body, body
        assert 'debug "usr/bin/debugged" "' in body, body
        identity = call("elf", noted).splitlines()
        build_id = [line.split()[1] for line in identity if line.startswith("build-id ")][0]
        assert f'debug "usr/bin/debugged" "{build_id}"\n' in body, body
        # the note is what a stripped artifact keeps, so the tool that cuts the pair
        # is named rather than invented per file
        assert "objcopy --only-keep-debug" in body, body
        assert "--add-gnu-debuglink" in body, body
        # the header is still development material, and the program is a runtime file
        # the debug output is cut from
        assert 'path "usr/include/debugged.h" "debugged-devel" "header"' in body, body
        assert 'path "usr/bin/debugged" "debugged" "runtime artifact for a debug file"' \
            in body, body
        assert "no-build-id" not in body, body

        # a payload without a build-id note cannot be tied to a debug file, so the
        # path is a decision rather than an untraceable debug entry
        unnoted = build(sources, "unnoted")
        plain_program = compile_into(cc, ["-g", "-O0", str(program_source), "-o",
                                           str(unnoted / "DATA/usr/bin/unnoted")],
                                     unnoted / "DATA/usr/bin/unnoted")
        plain_program.chmod(0o755)
        proposal = root / "unnoted"
        report = call("split", unnoted, "--output", proposal, "--debug", status=3)
        assert "debug 0" in report, report
        body = proposal.read_text()
        assert 'decision "usr/bin/unnoted" "no-build-id" suggested "unnoted"' in body, body
        assert "no build-id note ties a debug file" in body, body
        assert "\ndebug " not in body, body

    print("split proposal fixtures passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
