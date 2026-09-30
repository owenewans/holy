#!/usr/bin/env python3
"""cuts a debug output from a runtime artifact with objcopy, then proves with GDB that
the source location and stack trace a user sees come from the artifact that installs."""
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


def compiler():
    for name in ("cc", "gcc", "clang"):
        if shutil.which(name):
            return name
    return None


def run_gdb(cwd, session):
    """gdb reads a command file from disk, since a pipe is not seekable"""
    script = cwd / "session.gdb"
    script.write_text(session + "\n")
    result = subprocess.run(["gdb", "--batch", "--nx", "-x", str(script)],
                            capture_output=True, text=True, cwd=str(cwd))
    return result.stdout + result.stderr


def build_id(path, note_only=False):
    """the build-id a stripped artifact keeps, read back with the manager under test.
    a separate debug file keeps the note and loses the segments a loadable artifact
    needs, so it is read with the note-only reader."""
    args = ("elf", path) + (("--build-id",) if note_only else ())
    result = subprocess.run([binary, *args], capture_output=True, text=True)
    assert result.returncode == 0, (args, result.returncode, result.stdout, result.stderr)
    for line in result.stdout.splitlines():
        if line.startswith("build-id "):
            return line.split()[1]
    return None


def main():
    for tool in ("objcopy", "gdb"):
        if not shutil.which(tool):
            print(f"{tool} required for the debug split fixture", file=sys.stderr)
            return 6
    cc = compiler()
    if not cc:
        print("a host compiler required for the debug split fixture", file=sys.stderr)
        return 6
    with tempfile.TemporaryDirectory() as scratch:
        root = pathlib.Path(scratch)
        sources = root / "sources"
        sources.mkdir()

        # a program with a real frame above main, so a stack trace has a source
        # location to disagree about
        program = sources / "program.c"
        program.write_text(
            "#include <stdio.h>\n"
            "static int inner(int value) { return value * 2; }\n"
            "static int middle(int value) { return inner(value) + 1; }\n"
            "int main(void) { printf(\"%d\\n\", middle(20)); return 0; }\n")
        program.chmod(0o644)
        # a debugger looks for a separate debug file beside the artifact and then in
        # its search path, so the artifact, the debug file and the sources each live
        # in their own directory and a case that must find no debug file is a real
        # absence rather than an accident of layout
        artifacts = root / "artifacts"
        artifacts.mkdir()
        binary_path = artifacts / "debugged"
        result = subprocess.run([cc, "-g", "-O0", "-no-pie", "-Wl,--build-id",
                                 str(program), "-o", str(binary_path)],
                                capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        identity = build_id(binary_path)
        assert identity, "the fixture program states no build-id"

        # the runtime artifact is stripped and given a debuglink; the debug file keeps
        # the sections and the note, which is what ties the two together
        debug_file = artifacts / "debugged.debug"
        result = subprocess.run(["objcopy", "--only-keep-debug", str(binary_path),
                                 str(debug_file)], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert build_id(debug_file, note_only=True) == identity, \
            "the debug file lost the build-id"
        stripped = artifacts / "debugged.runtime"
        shutil.copyfile(binary_path, stripped)
        stripped.chmod(0o755)
        result = subprocess.run(["objcopy", "--strip-debug",
                                 "--add-gnu-debuglink=" + str(debug_file), str(stripped)],
                                capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert build_id(stripped) == identity, "the stripped artifact lost the build-id"
        assert stripped.stat().st_size < binary_path.stat().st_size, "nothing was stripped"
        sections = subprocess.run(["readelf", "-S", "--wide", str(stripped)],
                                  capture_output=True, text=True).stdout
        assert ".debug_info" not in sections, sections
        # the section also carries a CRC, so the dump is bytes and the name is searched
        # in the printable part of it
        debuglink = subprocess.run(["readelf", "--string-dump=.gnu_debuglink", str(stripped)],
                                   capture_output=True).stdout
        assert debug_file.name.encode() in debuglink, debuglink

        # a stack trace from the stripped artifact resolves to the recorded line
        # through the debug file, and it matches the file the build left behind
        session = "\n".join([
            "set pagination off",
            "set confirm off",
            f"file {stripped}",
            f"directory {sources}",
            "break inner",
            "run",
            "bt",
            "info line *$pc",
            "quit",
        ])
        trace = run_gdb(artifacts, session)
        assert "Breakpoint 1 at" in trace, trace
        assert "inner" in trace, trace
        assert "middle" in trace, trace
        assert "main" in trace, trace
        # the recorded line is the one the source states, not a guess
        expected = next(number for number, line in
                        enumerate(program.read_text().splitlines(), 1)
                        if line.startswith("static int inner"))
        assert f"program.c:{expected}" in trace, (expected, trace)
        assert "No such file or directory" not in trace, trace

        # the same artifact without its debug file has no source line, which is what
        # makes the debug output load-bearing rather than a convenience copy
        alone = root / "alone"
        alone.mkdir()
        unpaired = alone / stripped.name
        shutil.copyfile(stripped, unpaired)
        unpaired.chmod(0o755)
        session = "\n".join([
            "set pagination off",
            "set confirm off",
            f"file {unpaired}",
            f"directory {sources}",
            "break inner",
            "run",
            "info line *$pc",
            "quit",
        ])
        bare_trace = run_gdb(alone, session)
        assert f"program.c:{expected}" not in bare_trace, bare_trace
        # the symbol is still there, so what is missing is the line table and nothing
        # else, which is what a separate debug file carries
        assert "inner" in bare_trace, bare_trace
        assert "No line number information available" in bare_trace, bare_trace

    print("debug split fixtures passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
