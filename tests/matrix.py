#!/usr/bin/env python3
"""the compiler, SDK, language, network and system cases, each run against a named tool or
a pinned artifact.

Every case records what it ran, how long it took, the log it left behind and one of four
outcomes: pass, fail, missing (a named tool or artifact this host does not have) or
unpinned (an artifact a case needs that profiles/matrix-sources does not carry a digest
for). A missing or unpinned case never turns the run green, so the report says what the
host could not prove instead of hiding it.
"""
import argparse
import json
import os
import pty
import re
import select
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
PINS = PROJECT / "profiles" / "matrix-sources"


def pinned():
    pins = {}
    if PINS.is_file():
        for line in PINS.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 4 or len(parts[0]) != 64:
                raise SystemExit(f"holy-matrix: malformed pin line: {line}")
            pins[parts[1]] = {"sha256": parts[0], "url": parts[2], "license": parts[3]}
    return pins


PINS = pinned()


class Case:
    def __init__(self, name, group):
        self.name = name
        self.group = group
        self.status = "pass"
        self.reason = ""
        self.seconds = 0.0
        self.artifact = None
        self.log = ""

    def missing(self, reason):
        self.status = "missing"
        self.reason = reason

    def unpinned(self, url):
        self.status = "unpinned"
        self.reason = f"no pinned digest for {url}"

    def fail(self, reason):
        self.status = "fail"
        self.reason = reason


def run(argv, cwd=None, timeout=300, env=None, log=None, pipe=True, stdin=None):
    """run one command. pipe=False sends its output to the log file, because a process
    that forks a helper of its own holds a pipe open long after the work is done. stdin
    feeds a program that reads commands from its input, and then the output is captured
    either way since there is nothing to stream it into."""
    start = time.monotonic()
    merged = dict(os.environ)
    merged.setdefault("TERM", "dumb")
    if env:
        merged.update(env)
    if stdin is not None:
        pipe = True
    stream = None
    shape = {"capture_output": True, "text": True, "errors": "replace"} if pipe else {}
    if not pipe:
        if log:
            Path(log).parent.mkdir(parents=True, exist_ok=True)
            stream = open(log, "w")
        shape["stdout"] = stream or subprocess.DEVNULL
        shape["stderr"] = subprocess.STDOUT if stream else subprocess.DEVNULL
    try:
        done = subprocess.run(argv, cwd=cwd, timeout=timeout, env=merged,
                              input=stdin, **shape)
        code, out, err = done.returncode, done.stdout or "", done.stderr or ""
    except subprocess.TimeoutExpired:
        code, out, err = 124, "", f"timeout after {timeout}s"
    finally:
        if stream:
            stream.close()
    seconds = round(time.monotonic() - start, 3)
    if log and pipe:
        Path(log).parent.mkdir(parents=True, exist_ok=True)
        Path(log).write_text(f"$ {' '.join(argv)}\n\n{out}\n{err}\n")
    return code, out, err, seconds


def need(case, tool):
    path = shutil.which(tool)
    if not path:
        case.missing(f"{tool} not installed")
    return path


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


# ---------------------------------------------------------------- C and C++

C_MAIN = r"""
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>

static void *worker(void *argument)
{
    printf("thread %d\n", (int)(long)argument);
    return NULL;
}

int main(void)
{
    pthread_t first, second;
    printf("hello from %s\n", getenv("HOLY_MATRIX_LIBC") ? getenv("HOLY_MATRIX_LIBC") : "host libc");
    fflush(stdout);
    if (pthread_create(&first, NULL, worker, (void *)1) || pthread_create(&second, NULL, worker, (void *)2))
        return 1;
    pthread_join(first, NULL);
    pthread_join(second, NULL);
    return 0;
}
"""

CXX_MAIN = r"""
#include <cstdio>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

extern "C" int helper_answer(void);

int main()
{
    std::vector<std::thread> pool;
    for (int i = 0; i < 4; ++i) pool.emplace_back([i] { std::printf("worker %d\n", i); });
    for (auto &thread : pool) thread.join();
    try {
        throw std::runtime_error("expected");
    } catch (const std::exception &error) {
        std::printf("caught %s\n", error.what());
    }
    std::printf("helper %d\n", helper_answer());
    return 0;
}
"""

CXX_HELPER = r"""
extern "C" int helper_answer(void) { return 42; }
"""


def c_case(case, work, compiler, extra=()):
    if not shutil.which(compiler):
        case.missing(f"{compiler} not installed")
        return
    source = write(work / "c" / "main.c", C_MAIN)
    binary = work / "c" / "main"
    code, out, err, _ = run([compiler, "-std=c99", "-Wall", "-Wextra", "-Werror", "-pedantic",
                             "-pthread", "-o", str(binary), str(source), *extra],
                            log=work / "logs" / f"{case.name}.compile.log")
    if code:
        case.fail(f"{compiler} refused the fixture: {err.strip().splitlines()[-1:]}")
        return
    code, out, err, _ = run([str(binary)], log=work / "logs" / f"{case.name}.run.log",
                            env={"HOLY_MATRIX_LIBC": Path(compiler).name})
    if code or "hello from" not in out or out.count("thread ") != 2:
        case.fail(f"the fixture did not run: rc={code}")
        return
    code, out, _, _ = run(["file", "-b", str(binary)])
    interpreter = ""
    if "interpreter" in out:
        interpreter = out.split("interpreter ")[1].split(",")[0].strip()
    case.reason = f"interpreter {interpreter or 'none (static)'}"


def musl_case(case, work):
    compiler = os.environ.get("MUSL_CC") or shutil.which("musl-gcc")
    if not compiler:
        case.missing("no musl compiler; MUSL_CC names one")
        return
    c_case(case, work, compiler)


def c_headers_case(case, work, compiler):
    if not shutil.which(compiler):
        case.missing(f"{compiler} not installed")
        return
    source = write(work / "c" / "headers.c",
                   "#include <stdio.h>\n#include <pthread.h>\n#include <stdlib.h>\nint main(void){return 0;}\n")
    probe = work / "c" / "headers"
    code, out, err, _ = run([compiler, "-std=c99", "-Wall", "-Wextra", "-Werror", "-pedantic",
                             "-c", "-o", str(probe.with_suffix(".o")), str(source)],
                            log=work / "logs" / f"{case.name}.log")
    if code:
        case.fail(f"headers did not compile: {err.strip().splitlines()[-1:]}")
        return
    code, out, _, _ = run([compiler, str(source.with_suffix(".o")), "-o", str(probe)],
                          log=work / "logs" / f"{case.name}.link.log")
    if code:
        case.fail(f"crt objects and the linker did not produce a binary")
        return
    case.reason = "headers, crt objects, libc and the linker"


def cxx_case(case, work, compiler):
    directory = work / "cxx"
    write(directory / "main.cpp", CXX_MAIN)
    write(directory / "helper.cpp", CXX_HELPER)
    library = directory / "libhelper.so"
    code, out, err, _ = run([compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-fPIC",
                             "-shared", "-o", str(library), str(directory / "helper.cpp")],
                            log=work / "logs" / f"{case.name}.lib.log")
    if code:
        case.fail(f"the shared library did not build: {err.strip().splitlines()[-1:]}")
        return
    binary = directory / "main"
    code, out, err, _ = run([compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pthread",
                             "-o", str(binary), str(directory / "main.cpp"),
                             f"-L{directory}", "-lhelper", f"-Wl,-rpath,{directory}"],
                            log=work / "logs" / f"{case.name}.build.log")
    if code:
        case.fail(f"the program did not link: {err.strip().splitlines()[-1:]}")
        return
    code, out, err, _ = run([str(binary)], log=work / "logs" / f"{case.name}.run.log")
    if code or "caught expected" not in out or "helper 42" not in out or out.count("worker ") != 4:
        case.fail(f"exceptions, threads or the shared library did not work: rc={code}")
        return
    case.reason = "exceptions, four threads and a shared library"


# ---------------------------------------------------------------- rust and go

RUST_CARGO = """[package]
name = "holy-matrix"
version = "0.1.0"
edition = "2021"

[lib]
name = "holy_matrix"
crate-type = ["cdylib", "rlib"]

[dependencies]
"""

RUST_LIB = """
#[no_mangle]
pub extern "C" fn holy_matrix_answer() -> i32 { 42 }
"""

RUST_BIN = """
fn holy_matrix_answer() -> i32 { 42 }

#[cfg(test)]
mod tests {
    #[test]
    fn answer_is_known() { assert_eq!(super::holy_matrix_answer(), 42); }
}

fn main() { println!("answer {}", holy_matrix_answer()); }
"""

GO_PURE = """package main

import "fmt"

func answer() int { return 42 }

func main() { fmt.Println("answer", answer()) }
"""

GO_CGO = """package main

/*
#include <stdio.h>
static int helper(void) { return 42; }
*/
import "C"

import "fmt"

func main() { fmt.Println("answer", int(C.helper())) }
"""


def rust_case(case, work):
    if not need(case, "cargo"):
        return
    project = work / "rust" / "holy-matrix"
    write(project / "Cargo.toml", RUST_CARGO)
    write(project / "src" / "lib.rs", RUST_LIB)
    write(project / "src" / "main.rs", RUST_BIN)
    env = {"CARGO_HOME": str(work / "rust" / "cargo-home"), "CARGO_NET_OFFLINE": "true"}
    code, out, err, _ = run(["cargo", "build", "--release"], cwd=project, env=env,
                            log=work / "logs" / f"{case.name}.build.log")
    if code:
        case.fail(f"cargo build failed: {err.strip().splitlines()[-1:]}")
        return
    library = project / "target" / "release" / "libholy_matrix.so"
    binary = project / "target" / "release" / "holy-matrix"
    if not library.is_file() or not binary.is_file():
        case.missing("the cdylib or the binary was not produced")
        return
    code, out, _, _ = run([str(binary)], log=work / "logs" / f"{case.name}.run.log")
    if code or "answer 42" not in out:
        case.fail(f"the binary did not run: rc={code}")
        return
    code, out, err, _ = run(["cargo", "test", "--release"], cwd=project, env=env,
                            log=work / "logs" / f"{case.name}.test.log")
    if code or "1 passed" not in out:
        case.fail(f"cargo test did not pass: rc={code}")
        return
    code, out, _, _ = run(["file", "-b", str(library)])
    case.reason = f"bin, cdylib and one test; {out.strip().split(',')[0]}"


def rust_musl_case(case, work):
    if not need(case, "rustc"):
        case.missing("rustc not installed")
        return
    code, out, _, _ = run(["rustc", "--print", "target-libdir"])
    case.reason = ("rustc reports its sysroot, but no musl target is installed here, so a "
                   "musl Rust build is untested; rustup target add "
                   "x86_64-unknown-linux-musl is what supplies one")


def go_toolchain():
    """the go binary whose compile tool carries the same version, since a host can hold a
    go command beside the toolchain of another release."""

    def agrees(binary):
        version = subprocess.run([binary, "version"], capture_output=True, text=True).stdout
        if " does not match " in version:
            return False
        parts = version.split()
        compiled = subprocess.run([binary, "tool", "compile", "-V"], capture_output=True,
                                  text=True).stdout.split()
        return len(parts) > 2 and len(compiled) > 2 and compiled[2] == parts[2]

    candidates = [shutil.which("go")]
    for pattern in ("usr/lib64/go*/go/bin/go", "usr/lib/go*/go/bin/go"):
        candidates.extend(str(path) for path in sorted(Path("/").glob(pattern)))
    for binary in candidates:
        if binary and Path(binary).is_file() and agrees(binary):
            return binary
    return None


def go_case(case, work, cgo):
    go = go_toolchain()
    if not go:
        case.missing("no go binary agrees with its own GOROOT toolchain")
        return
    name = "go-cgo" if cgo else "go-pure"
    directory = work / name
    write(directory / "go.mod", f"module holymatrix/{name}\n\ngo 1.21\n")
    write(directory / "main.go", GO_CGO if cgo else GO_PURE)
    env = {"GOFLAGS": "-mod=mod", "GOCACHE": str(work / "go" / "cache"),
           "GOPATH": str(work / "go" / "path"), "GOTOOLCHAIN": "local"}
    code, out, err, _ = run([go, "build", "-o", name, "."], cwd=directory, env=env,
                            log=work / "logs" / f"{name}.build.log")
    if code:
        case.fail(f"go build failed: {err.strip().splitlines()[-1:]}")
        return
    code, out, _, _ = run([str(directory / name)], log=work / "logs" / f"{name}.run.log")
    if code or "answer 42" not in out:
        case.fail(f"the program did not run: rc={code}")
        return
    case.reason = "cgo with the assigned C compiler" if cgo else "a pure Go build"


# ---------------------------------------------------------------- build systems

BUILD_MAIN = r"""
#include <stdio.h>
int fixture_answer(void);
int main(void) { printf("answer %d\n", fixture_answer()); return 0; }
"""

BUILD_HELPER = "int fixture_answer(void) { return 42; }\n"


def build_project(work):
    directory = work / "build"
    write(directory / "main.c", BUILD_MAIN)
    write(directory / "helper.c", BUILD_HELPER)
    write(directory / "Makefile",
          "CC ?= cc\nCFLAGS ?= -O2 -Wall -Wextra -Werror\n"
          "all: fixture\nfixture: main.o helper.o\n\t$(CC) -o $@ $^\n"
          "%.o: %.c\n\t$(CC) $(CFLAGS) -c -o $@ $<\nclean:\n\trm -f fixture *.o\n")
    write(directory / "CMakeLists.txt",
          "cmake_minimum_required(VERSION 3.13)\nproject(holy_matrix C)\n"
          "set(CMAKE_C_STANDARD 99)\nadd_library(helper helper.c)\n"
          "add_executable(fixture main.c)\ntarget_link_libraries(fixture helper)\n")
    write(directory / "meson.build",
          "project('holy-matrix', 'c', default_options: ['c_std=c99'])\n"
          "helper = static_library('helper', 'helper.c')\n"
          "executable('fixture', 'main.c', link_with: helper)\n")
    return directory


def make_case(case, work, directory):
    code, out, err, _ = run(["make", "-s"], cwd=directory, log=work / "logs" / f"{case.name}.log")
    if code:
        case.fail(f"make failed: {err.strip().splitlines()[-1:]}")
        return
    code, out, _, _ = run([str(directory / "fixture")])
    if code or "answer 42" not in out:
        case.fail(f"the make build did not run: rc={code}")
        return
    case.reason = "one fixture built and run"


def cmake_case(case, work, directory):
    if not need(case, "cmake"):
        case.missing("cmake not installed")
        return
    build = directory / "cmake-build"
    code, out, err, _ = run(["cmake", "-S", str(directory), "-B", str(build), "-G", "Unix Makefiles"],
                            log=work / "logs" / f"{case.name}.configure.log")
    if code:
        case.fail(f"cmake configure failed: {err.strip().splitlines()[-1:]}")
        return
    code, out, err, _ = run(["cmake", "--build", str(build)], log=work / "logs" / f"{case.name}.build.log")
    if code:
        case.fail(f"cmake build failed: {err.strip().splitlines()[-1:]}")
        return
    code, out, _, _ = run([str(build / "fixture")])
    if code or "answer 42" not in out:
        case.fail(f"the cmake build did not run: rc={code}")
        return
    case.reason = "one fixture configured, built and run"


def meson_case(case, work, directory):
    if not need(case, "meson"):
        case.missing("meson not installed")
        return
    if not need(case, "ninja"):
        case.missing("ninja not installed")
        return
    build = directory / "meson-build"
    code, out, err, _ = run(["meson", "setup", str(build), str(directory), "--wipe"],
                            log=work / "logs" / f"{case.name}.configure.log")
    if code:
        code, out, err, _ = run(["meson", "setup", str(build), str(directory)],
                                log=work / "logs" / f"{case.name}.configure.log")
        if code:
            case.fail(f"meson setup failed: {err.strip().splitlines()[-1:]}")
            return
    code, out, err, _ = run(["ninja", "-C", str(build)], log=work / "logs" / f"{case.name}.build.log")
    if code:
        case.fail(f"ninja failed: {err.strip().splitlines()[-1:]}")
        return
    code, out, _, _ = run([str(build / "fixture")])
    if code or "answer 42" not in out:
        case.fail(f"the meson build did not run: rc={code}")
        return
    case.reason = "one fixture built with meson and ninja and run"


# ---------------------------------------------------------------- debuggers

DEBUG_SOURCE = """
#include <stdio.h>

static int level_two(int value)
{
    return value * 2;
}

int main(void)
{
    int answer = level_two(21);
    printf("answer %d\\n", answer);
    return 0;
}
"""


def debug_case(case, work, tool, script):
    if not need(case, tool):
        return
    directory = work / "debug"
    source = write(directory / "main.c", DEBUG_SOURCE)
    binary = directory / "main"
    code, out, err, _ = run(["gcc", "-g", "-O0", "-o", str(binary), str(source)],
                            log=work / "logs" / f"{case.name}.build.log")
    if code:
        case.fail(f"the debug fixture did not build: {err.strip().splitlines()[-1:]}")
        return
    argv = [tool, "-b"] + script + [str(binary)]
    code, out, err, _ = run(argv, timeout=120, log=work / "logs" / f"{case.name}.log")
    combined = out + err
    if code:
        case.fail(f"{tool} returned {code}: {combined.strip().splitlines()[-1:]}")
        return
    if "level_two" not in combined or "main" not in combined:
        case.fail(f"{tool} printed no stack trace through level_two and main")
        return
    case.reason = "breakpoint in level_two with a stack trace through main"


def rizin_case(case, work):
    if shutil.which("rizin"):
        directory = work / "rizin"
        source = write(directory / "main.c", DEBUG_SOURCE)
        binary = directory / "main"
        code, out, err, _ = run(["gcc", "-g", "-O0", "-o", str(binary), str(source)])
        if code:
            case.fail(f"the fixture did not build: {err.strip().splitlines()[-1:]}")
            return
        code, out, err, _ = run(["rizin", "-q", "-c", "aaa; afl; iS", "-A", str(binary)],
                                timeout=120, log=work / "logs" / f"{case.name}.log")
        if code or "main" not in out:
            case.fail(f"rizin did not list the fixture symbols: rc={code}")
            return
        case.reason = "symbols and sections read without an interactive session"
        return
    case.missing("rizin not installed")


# ---------------------------------------------------------------- languages

PY_EXT = r"""
#include <Python.h>

static PyObject *answer(PyObject *self, PyObject *args)
{
    (void)self; (void)args;
    return PyLong_FromLong(42);
}

static PyMethodDef methods[] = {
    {"answer", answer, METH_NOARGS, "the fixture answer"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module = {PyModuleDef_HEAD_INIT, "holy_matrix", NULL, -1, methods};

PyMODINIT_FUNC PyInit_holy_matrix(void) { return PyModule_Create(&module); }
"""

PY_MAIN = """
import ctypes, sqlite3, ssl, sys
import holy_matrix
assert holy_matrix.answer() == 42
assert ssl.OPENSSL_VERSION.startswith("OpenSSL")
sqlite3.connect(":memory:").execute("create table t (x integer)").execute("insert into t values (1)")
print("answer", holy_matrix.answer(), ssl.OPENSSL_VERSION.split()[1])
"""


def python_case(case, work, config):
    if not shutil.which("python3"):
        case.missing("python3 not installed")
        return
    directory = work / "python"
    directory.mkdir(parents=True, exist_ok=True)
    code, out, err, _ = run([config, "-c", "import ssl, sqlite3, ctypes"], timeout=60,
                            log=work / "logs" / f"{case.name}.import.log")
    if code:
        case.fail(f"ssl, sqlite3 or ctypes did not import: {err.strip().splitlines()[-1:]}")
        return
    extension = write(directory / "holy_matrix.c", PY_EXT)
    flags = Path(config).with_name(Path(config).name.replace("python3", "python3-config", 1))
    if not flags.is_file():
        case.missing("python3-config not installed")
        return
    includes = subprocess.run([str(flags), "--includes"], capture_output=True,
                              text=True).stdout.split()
    ldflags = subprocess.run([str(flags), "--ldflags"], capture_output=True, text=True).stdout.split()
    if not includes:
        case.missing("no python development headers")
        return
    code, out, err, _ = run(["gcc", "-shared", "-fPIC", "-o", str(directory / "holy_matrix.so"),
                             str(extension), *includes, *ldflags],
                            log=work / "logs" / f"{case.name}.extension.log")
    if code:
        case.fail(f"the C extension did not build: {err.strip().splitlines()[-1:]}")
        return
    write(directory / "run.py", PY_MAIN)
    code, out, err, _ = run([config, str(directory / "run.py")], timeout=120,
                            env={"PYTHONPATH": str(directory)},
                            log=work / "logs" / f"{case.name}.run.log")
    if code or "answer 42" not in out:
        case.fail(f"the extension did not import or the modules were not usable: rc={code}")
        return
    case.reason = "ssl, sqlite3, ctypes and a loaded C extension"


def python_venv_case(case, work, config):
    if not shutil.which("python3"):
        case.missing("python3 not installed")
        return
    venv = work / "python" / "venv"
    code, out, err, _ = run([config, "-m", "venv", str(venv)], timeout=180,
                            log=work / "logs" / f"{case.name}.log")
    if code:
        case.fail(f"venv did not create: {err.strip().splitlines()[-1:]}")
        return
    binary = venv / "bin" / "python"
    if not binary.is_file():
        binary = venv / "Scripts" / "python.exe"
    code, out, err, _ = run([str(binary), "-c", "import ssl, sqlite3; print('venv ok')"], timeout=120,
                            log=work / "logs" / f"{case.name}.run.log")
    if code or "venv ok" not in out:
        case.fail(f"the venv interpreter did not import ssl and sqlite3: rc={code}")
        return
    case.reason = "a venv interpreter importing ssl and sqlite3"


NODE_JS = """
const https = require('node:https');
const fs = require('node:fs');
const addon = require(process.argv[2]);
if (addon.answer() !== 42) { throw new Error('addon answered ' + addon.answer()); }
console.log('answer', addon.answer(), process.version);
"""

NODE_ADDON = """
#include <node_api.h>

static napi_value answer(napi_env env, napi_callback_info info)
{
    napi_value value;
    napi_create_int32(env, 42, &value);
    return value;
}

NAPI_MODULE_INIT()
{
    napi_value fn;
    napi_create_function(env, "answer", NAPI_AUTO_LENGTH, answer, NULL, &fn);
    napi_set_named_property(env, exports, "answer", fn);
    return exports;
}
"""


def node_case(case, work, js):
    if not shutil.which("node"):
        case.missing("node not installed")
        return
    directory = work / "node"
    write(directory / "run.js", NODE_JS)
    if not js:
        code, out, err, _ = run(["node", "-e", "console.log('node', process.version)"], timeout=60,
                                log=work / "logs" / f"{case.name}.log")
        if code or "node v" not in out:
            case.fail(f"node did not run: rc={code}")
            return
        case.reason = f"{out.strip()}"
        return
    headers = PINS.get("node-v24.21.0-headers.tar.gz")
    if not headers:
        case.unpinned("node headers")
        return
    case.artifact = headers
    node_root = work / "node" / "headers"
    node_root.mkdir(parents=True, exist_ok=True)
    archive = work / "node" / headers["url"].rsplit("/", 1)[1]
    if not archive.is_file():
        code, out, err, _ = run(["curl", "-fsSL", "-o", str(archive), headers["url"]], timeout=300,
                                log=work / "logs" / f"{case.name}.fetch.log")
        if code:
            case.fail(f"the pinned node headers did not download: {err.strip()[:200]}")
            return
    digest = subprocess.run(["sha256sum", str(archive)], capture_output=True,
                            text=True).stdout.split()[0]
    if digest != headers["sha256"]:
        case.fail(f"node headers digest {digest} is not the pinned one")
        return
    code, out, err, _ = run(["tar", "-xf", str(archive), "-C", str(node_root)], timeout=300)
    if code:
        case.fail(f"the node headers did not unpack: rc={code}")
        return
    source = write(directory / "addon.c", NODE_ADDON)
    library = directory / "holy_matrix.node"
    include = node_root / "node-v24.21.0" / "include" / "node"
    code, out, err, _ = run(["gcc", "-shared", "-fPIC", "-o", str(library), str(source),
                             f"-I{include}", "-Wl,--unresolved-symbols=ignore-all"],
                            log=work / "logs" / f"{case.name}.addon.log")
    if code:
        code, out, err, _ = run(["g++", "-shared", "-fPIC", "-o", str(library), str(source),
                                 f"-I{include}", "-undefined", "dynamic_lookup"])
    if code:
        case.fail(f"the native addon did not build: {err.strip().splitlines()[-1:]}")
        return
    code, out, err, _ = run(["node", str(directory / "run.js"), str(library)], timeout=120,
                            log=work / "logs" / f"{case.name}.run.log")
    if code or "answer 42" not in out:
        case.fail(f"the addon did not load: rc={code} {err.strip()[:200]}")
        return
    case.reason = "a native addon loaded against the pinned headers, so the ABI is named"


# ---------------------------------------------------------------- network and system

def git_fixture_case(case, work):
    for tool in ("git", "curl", "openssl"):
        if not need(case, tool):
            return
    server = work / "https"
    server.mkdir(parents=True, exist_ok=True)
    code, out, err, _ = run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                             "-keyout", str(server / "key.pem"), "-out", str(server / "cert.pem"),
                             "-subj", "/CN=localhost",
                             "-addext", "subjectAltName=DNS:localhost"],
                            log=work / "logs" / f"{case.name}.openssl.log")
    if code:
        case.fail(f"openssl did not create the fixture certificate: rc={code}")
        return
    serve = work / "serve"
    write(serve / "index.txt", "fixture\n")
    port_file = work / "port"
    if port_file.exists():
        port_file.unlink()
    script = (
        "import http.server, ssl, sys, os\n"
        "os.chdir(sys.argv[1])\n"
        "server = http.server.HTTPServer(('127.0.0.1', 0), http.server.SimpleHTTPRequestHandler)\n"
        "ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\n"
        "ctx.load_cert_chain(sys.argv[2], sys.argv[3])\n"
        "server.socket = ctx.wrap_socket(server.socket, server_side=True)\n"
        "print(server.server_port, flush=True)\n"
        "server.serve_forever()\n")
    handle = subprocess.Popen([sys.executable, "-u", "-c", script, str(serve),
                               str(server / "cert.pem"), str(server / "key.pem")],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        port = handle.stdout.readline().strip()
        if not port.isdigit():
            case.fail("the fixture server did not report a port")
            return
        code, out, err, _ = run(["curl", "-fsS", "--cacert", str(server / "cert.pem"),
                                 f"https://localhost:{port}/index.txt"], timeout=60,
                                log=work / "logs" / f"{case.name}.curl.log")
        if code or "fixture" not in out:
            case.fail(f"curl did not fetch the fixture over a verified TLS connection: rc={code}")
            return
        code, out, err, _ = run(["openssl", "s_client", "-connect", f"localhost:{port}",
                                 "-CAfile", str(server / "cert.pem"), "-brief"],
                                timeout=60, log=work / "logs" / f"{case.name}.s_client.log")
        if code or "Verification: OK" not in (out + err):
            case.fail(f"openssl did not verify the fixture certificate: rc={code}")
            return
        bare = serve / "fixture-repo.git"
        # the seed and both clones are disposable, and a work directory kept across runs
        # would otherwise hand git a destination that is already there
        for name in ("seed", "cloned", "cloned-badsha"):
            shutil.rmtree(work / name, ignore_errors=True)
        run(["git", "init", "--quiet", "--bare", "-b", "main", str(bare)], timeout=60)
        seed = work / "seed"
        run(["git", "init", "--quiet", "-b", "main", str(seed)], timeout=60)
        write(seed / "README.md", "fixture repository\n")
        for cmd in (["add", "README.md"],
                    ["-c", "user.email=fixture@holy.invalid", "-c", "user.name=fixture",
                     "commit", "--quiet", "-m", "fixture"]):
            run(["git", "-C", str(seed)] + cmd, timeout=60)
        run(["git", "-C", str(seed), "push", "--quiet", str(bare), "main:main"], timeout=60)
        run(["git", "-C", str(bare), "update-server-info"], timeout=60)
        # the fixture serves the bare repository over the same verified TLS listener, so
        # the clone is a git transport case and not a filesystem copy
        clone = work / "cloned"
        code, out, err, _ = run(["git", "-c", f"http.sslCAInfo={server / 'cert.pem'}",
                                 "-c", "http.sslVerify=true", "clone", "--quiet",
                                 f"https://localhost:{port}/fixture-repo.git", str(clone)],
                                timeout=120, log=work / "logs" / f"{case.name}.git.log")
        if code or not (clone / "README.md").is_file():
            case.fail(f"git clone over verified TLS failed: {err.strip().splitlines()[-1:]}")
            return
        code, out, err, _ = run(["git", "-C", str(clone), "-c",
                                 f"http.sslCAInfo={server / 'cert.pem'}",
                                 "fetch", "--quiet", "origin"],
                                timeout=120, log=work / "logs" / f"{case.name}.fetch.log")
        if code:
            case.fail(f"git fetch failed: {err.strip().splitlines()[-1:]}")
            return
        bad = work / "cloned-badsha"
        code, out, err, _ = run(["git", "-c", "http.sslCAInfo=/dev/null", "clone", "--quiet",
                                 f"https://localhost:{port}/fixture-repo.git", str(bad)], timeout=120)
        if code == 0:
            case.fail("a clone against an empty CA bundle was accepted")
            return
        case.reason = "clone and fetch over a verified fixture CA, and a refused bad CA"
    finally:
        handle.terminate()
        try:
            handle.wait(timeout=10)
        except subprocess.TimeoutExpired:
            handle.kill()


def dns_case(case, work, cc):
    source = write(work / "dns" / "main.c", r"""
#include <netdb.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    struct addrinfo hints, *result = NULL;
    if (argc < 2) return 2;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(argv[1], "443", &hints, &result)) return 1;
    printf("resolved %s family %d\n", argv[1], result->ai_family);
    freeaddrinfo(result);
    return 0;
}
""")
    binary = work / "dns" / "main"
    code, out, err, _ = run([cc, "-o", str(binary), str(source)],
                            log=work / "logs" / f"{case.name}.build.log")
    if code:
        case.fail(f"the resolver probe did not build: {err.strip().splitlines()[-1:]}")
        return
    code, out, err, _ = run([str(binary), "localhost"], timeout=60,
                            log=work / "logs" / f"{case.name}.log")
    if code or "resolved localhost" not in out:
        case.fail(f"{cc} did not resolve a name through its libc: rc={code}")
        return
    case.reason = "a name resolved through the libc this compiler links"


LOCALE_MAIN = r"""
#include <langinfo.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    const char *wanted = getenv("HOLY_MATRIX_LOCALE") ? getenv("HOLY_MATRIX_LOCALE")
                                                       : "en_US.UTF-8";
    const char *taken = setlocale(LC_ALL, wanted);
    if (!taken) { printf("setlocale %s refused\n", wanted); return 1; }
    printf("locale %s codeset %s\n", taken, nl_langinfo(CODESET));
    /* a collation the locale archive actually answers, rather than the name alone */
    printf("collated %d\n", strcoll("a", "b") < 0);
    return 0;
}
"""

NSS_MAIN = r"""
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int main(void)
{
    struct passwd *user;
    struct group *group;
    gid_t groups[64];
    int count = (int) (sizeof groups / sizeof *groups), i;
    const char *wanted = getenv("HOLY_MATRIX_ACCOUNT") ? getenv("HOLY_MATRIX_ACCOUNT")
                                                        : "root";
    user = getpwnam(wanted);
    if (!user) { printf("no user %s\n", wanted); return 1; }
    group = getgrgid(user->pw_gid);
    if (!group) { printf("no group %ld\n", (long)user->pw_gid); return 1; }
    if (getgrouplist(wanted, user->pw_gid, groups, &count) < 0) {
        printf("getgrouplist failed\n");
        return 1;
    }
    printf("user %s uid %ld group %s groups %d\n", user->pw_name, (long)user->pw_uid,
           group->gr_name, count);
    for (i = 0; i < count; ++i) printf("  group %s\n", getgrgid(groups[i])->gr_name);
    return 0;
}
"""

PAM_MAIN = r"""
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int converse(int count, const struct pam_message **messages,
                   struct pam_response **responses, void *data)
{
    struct pam_response *reply = calloc((size_t)count, sizeof *reply);
    (void)messages; (void)data;
    if (!reply) return PAM_BUF_ERR;
    *responses = reply;
    return PAM_SUCCESS;
}

int main(int argc, char **argv)
{
    struct pam_conv conversation = {converse, NULL};
    struct pam_handle *handle = NULL;
    const char *service = argc > 1 ? argv[1] : "other";
    int status = pam_start(service, "root", &conversation, &handle);
    if (status != PAM_SUCCESS) { printf("pam_start %s -> %d\n", service, status); return 1; }
    status = pam_get_item(handle, PAM_SERVICE, (const void **)&status);
    (void)status;
    printf("pam service %s handle ok\n", service);
    pam_end(handle, PAM_SUCCESS);
    return 0;
}
"""


def c_probe(case, work, name, source, argv, env=None, expect=(), libraries=()):
    path = write(work / "probe" / f"{name}.c", source)
    binary = work / "probe" / name
    code, out, err, _ = run([*argv, "-o", str(binary), str(path), *libraries],
                            log=work / "logs" / f"{case.name}.build.log")
    if code:
        case.fail(f"the probe did not build: {err.strip().splitlines()[-1:]}")
        return None
    code, out, err, _ = run([str(binary)], timeout=60, env=env,
                            log=work / "logs" / f"{case.name}.run.log")
    if code:
        case.fail(f"the probe did not run: rc={code} {out.strip()[:120]}")
        return None
    for needle in expect:
        if needle not in out:
            case.fail(f"the probe did not report {needle}: {out.strip()[:200]}")
            return None
    return out.strip()


def locale_case(case, work):
    """a name in locale -a proves nothing, so the case asks the libc to load the locale
    archive, read its codeset and collate with it."""
    code, out, _, _ = run(["locale", "-a"])
    if "en_us.utf8" not in out.lower():
        case.missing("the host has no en_US.UTF-8 locale")
        return
    answer = c_probe(case, work, "locale", LOCALE_MAIN, ["gcc", "-std=c99", "-Wall",
                     "-Wextra", "-Werror", "-pedantic"],
                     env={"HOLY_MATRIX_LOCALE": "en_US.UTF-8"},
                     expect=("codeset UTF-8", "collated 1"))
    if answer is None:
        return
    case.reason = f"{len(out.split())} locales; {answer.splitlines()[0]}"


def nss_case(case, work):
    """the passwd and group databases have to answer through NSS, not through a file the
    probe happens to have been handed."""
    account = os.environ.get("HOLY_MATRIX_ACCOUNT", "root")
    answer = c_probe(case, work, "nss", NSS_MAIN, ["gcc", "-std=c99", "-Wall", "-Wextra",
                     "-Werror", "-pedantic", "-D_GNU_SOURCE"], env={"HOLY_MATRIX_ACCOUNT": account},
                     expect=("user ", "group "))
    if answer is None:
        return
    case.reason = answer.splitlines()[0]


def pam_case(case, work):
    if not Path("/etc/pam.d").is_dir():
        case.missing("/etc/pam.d absent; this host has no PAM stack to probe")
        return
    answer = c_probe(case, work, "pam", PAM_MAIN, ["gcc", "-std=c99", "-Wall", "-Wextra",
                     "-Werror", "-pedantic", "-D_GNU_SOURCE"], libraries=("-lpam",))
    if answer is None:
        return
    case.reason = answer


def firefox_case(case, work, headless):
    browser = shutil.which("firefox") or shutil.which("firefox-esr")
    if not browser:
        case.missing("firefox not installed")
        return
    page = write(work / "page.html", "<!doctype html><html><body><h1>holy matrix</h1></body></html>")
    shot = work / "screenshot.png"
    # a profile is locked by the browser that holds it, so each case gets its own
    profile = work / f"firefox-profile-{'headless' if headless else 'session'}"
    # the compositor cannot map its software framebuffer when the profile directory the
    # browser creates for itself is missing, so the case lays it down first
    profile.mkdir(parents=True, exist_ok=True)
    argv = [browser, "--profile", str(profile), "--no-remote",
            "--screenshot", str(shot), page.as_uri()]
    if headless:
        code, out, err, _ = run(argv, timeout=420, log=work / "logs" / f"{case.name}.log",
                                pipe=False)
        if code or not shot.is_file() or shot.stat().st_size < 1024:
            case.fail(f"the headless screenshot did not land: rc={code}")
            return
        code, out, _, _ = run(["file", "-b", str(shot)])
        case.reason = f"{out.strip()}; {shot.stat().st_size} bytes"
        return
    if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
        case.missing("no DISPLAY or WAYLAND_DISPLAY for a GUI session")
        return
    # a window on the session display is what this host can prove: the browser is started
    # on the page and has to stay up. driving it needs a window tool, which is named when
    # the host has none rather than assumed
    browser_argv = [browser, "--profile", str(profile), "--no-remote", page.as_uri()]
    log = work / "logs" / f"{case.name}.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    handle = subprocess.Popen(browser_argv, stdout=open(log, "w"), stderr=subprocess.STDOUT)
    try:
        handle.wait(timeout=12)
        case.fail(f"the browser exited in the session after {handle.returncode}s")
        return
    except subprocess.TimeoutExpired:
        pass
    finally:
        handle.terminate()
        try:
            handle.wait(timeout=15)
        except subprocess.TimeoutExpired:
            handle.kill()
    window_tool = next((name for name in ("xdotool", "wmctrl", "ydotool") if shutil.which(name)), None)
    case.reason = ("a window stayed up on the session display for 12s"
                   + (f", driven with {window_tool}" if window_tool else
                      "; input and font checks need a window tool this host lacks"))


def vulkan_case(case, work, software):
    nodes = sorted(Path("/dev/dri").glob("renderD*"))
    if software:
        if not shutil.which("vulkaninfo"):
            case.missing("vulkaninfo not installed")
            return
        code, out, err, _ = run(["vulkaninfo", "--summary"], timeout=120,
                                log=work / "logs" / f"{case.name}.log")
        if code or "GPU id" not in out and "deviceName" not in out:
            case.fail(f"no Vulkan loader device was reported: rc={code}")
            return
        case.reason = "the loader enumerated a device under software rendering"
        return
    if not nodes:
        case.missing("no /dev/dri render node")
        return
    if not shutil.which("vulkaninfo"):
        case.missing("vulkaninfo not installed")
        return
    code, out, err, _ = run(["vulkaninfo", "--summary"], timeout=120,
                            log=work / "logs" / f"{case.name}.log")
    if code:
        case.fail(f"the Vulkan loader reported no device: rc={code}")
        return
    case.reason = f"loader enumerated a device on {nodes[0]}"


def opengl_case(case, work):
    if not os.environ.get("DISPLAY"):
        case.missing("DISPLAY required for an OpenGL presentation probe")
        return
    if not shutil.which("glxinfo"):
        case.missing("glxinfo not installed")
        return
    code, out, err, _ = run(["glxinfo", "-B"], timeout=60, log=work / "logs" / f"{case.name}.log")
    if code or "direct rendering: Yes" not in out:
        case.fail(f"no accelerated OpenGL context: rc={code}")
        return
    case.reason = "an accelerated OpenGL context in the session"


def fetch_pin(case, work, pin):
    """the pinned bytes, fetched once and checked against the digest the pin records. a
    URL that serves something else is a failure, not a newer version."""
    archive = work / "pins" / pin["url"].rsplit("/", 1)[1]
    archive.parent.mkdir(parents=True, exist_ok=True)
    if archive.is_file():
        digest = subprocess.run(["sha256sum", str(archive)], capture_output=True,
                                text=True).stdout.split()[0]
        if digest == pin["sha256"]:
            return archive
        archive.unlink()
    code, out, err, _ = run(["curl", "-fsSL", "--retry", "2", "-o", str(archive), pin["url"]],
                            timeout=1800, log=work / "logs" / f"{case.name}.fetch.log")
    if code:
        case.fail(f"the pinned artifact did not download: {err.strip()[:200]}")
        return None
    digest = subprocess.run(["sha256sum", str(archive)], capture_output=True,
                            text=True).stdout.split()[0]
    if digest != pin["sha256"]:
        case.fail(f"{pin['url']} served {digest}, not the pinned {pin['sha256']}")
        return None
    return archive


def unpack_root(case, work, archive, name):
    """the tree a release archive unpacks into, under a name the caller picks, since a github
    tarball unpacks into a directory named after its tag rather than after the file the URL
    ended with. an existing tree is kept, so a build that is already there is not redone."""
    target = work / name
    if target.is_dir():
        return target
    code, out, err, _ = run(["tar", "-tf", str(archive)], timeout=600)
    roots = {line.split("/", 1)[0] for line in out.splitlines() if "/" in line}
    if code or len(roots) != 1 or not roots.pop():
        case.fail(f"{archive.name} has no single top directory: rc={code}")
        return None
    root = out.split("/", 1)[0]
    code, out, err, _ = run(["tar", "-xf", str(archive), "-C", str(work)], timeout=1800)
    if code:
        case.fail(f"{archive.name} did not unpack: rc={code}")
        return None
    (work / root).rename(target)
    return target


def pinned_source_case(case, work, name, url, license_id):
    """a foreign source case proves two things: the pin exists, and the URL still serves
    the bytes the pin names. what is built from them is a separate case."""
    pin = PINS.get(name)
    if not pin:
        case.unpinned(url)
        return
    case.artifact = pin
    if not fetch_pin(case, work, pin):
        return
    case.reason = f"{license_id}; {name} fetched and matching {pin['sha256'][:16]}"


def rizin_build_case(case, work):
    """rizin is built from its pinned source and then opened without an interactive
    session, since a hung analysis would look like a pass."""
    pin = PINS.get("rizin-0.8.1.tar.gz")
    if not pin:
        case.unpinned("https://github.com/rizinorg/rizin/archive/refs/tags/v0.8.1.tar.gz")
        return
    case.artifact = pin
    archive = fetch_pin(case, work, pin)
    if not archive:
        return
    if not shutil.which("meson") or not shutil.which("ninja"):
        case.missing("meson and ninja are needed to build rizin")
        return
    source = work / "rizin"
    if not (source / "meson.build").is_file():
        source = unpack_root(case, work, archive, "rizin")
        if not source:
            return
    # rizin installs one directory per tool, so the executable is found in the build tree
    # rather than assumed at a fixed place inside it
    def rizin_binary():
        found = sorted((source / "build" / "binrz").glob("rizin*/rizin"))
        return found[0] if found else None

    binary = rizin_binary()
    if not binary:
        code, out, err, _ = run(["meson", "setup", str(source / "build"), str(source),
                                 "--buildtype=release"], timeout=600,
                                log=work / "logs" / f"{case.name}.setup.log")
        if code:
            case.fail(f"meson setup failed: {rc_text(err)}")
            return
        code, out, err, _ = run(["ninja", "-C", str(source / "build")], timeout=3600,
                                log=work / "logs" / f"{case.name}.build.log")
        if code:
            case.fail(f"ninja failed: {rc_text(err)}")
            return
        binary = rizin_binary()
    if not binary:
        case.missing("the rizin build produced no rizin executable")
        return
    directory = work / "rizin-fixture"
    source_file = write(directory / "main.c", DEBUG_SOURCE)
    elf = directory / "main"
    code, out, err, _ = run(["gcc", "-g", "-O0", "-o", str(elf), str(source_file)],
                            log=work / "logs" / f"{case.name}.fixture.log")
    if code:
        case.fail(f"the rizin fixture did not build: {rc_text(err)}")
        return
    # -q with a command list and no terminal is the whole point: a session that waits for
    # a prompt would hang the run instead of reporting it
    code, out, err, _ = run([str(binary), "-q", "-c", "aaa;afl~main;iS~.text", str(elf)],
                            timeout=300, log=work / "logs" / f"{case.name}.log")
    if code or "main" not in out or ".text" not in out:
        case.fail(f"rizin did not list the fixture functions and sections headlessly: rc={code}")
        return
    functions = [line for line in out.splitlines() if "main" in line]
    case.reason = ("built from the pinned source, then " + functions[0].strip().split()[-1]
                   + " found with its .text section, no interactive session")


def rc_text(err):
    lines = err.strip().splitlines()
    return lines[-1] if lines else ""


CHESS_MOVES = ["e2e4", "g1f3"]
BOARD_RANKS = "rnbqkpnr"


def xboard_game(engine, moves, timeout=300):
    """drive the engine through its xboard line protocol on a pty and return its lines. its
    stdout is block buffered to a pipe, so a driver that waits for an answer before sending
    the next command would wait forever without one."""
    master, slave = pty.openpty()
    process = subprocess.Popen([str(engine), "-x"], stdin=slave, stdout=slave, stderr=slave,
                               close_fds=True, env={"TERM": "dumb", "PATH": "/usr/bin:/bin"})
    os.close(slave)
    lines = []
    pending = ""

    def collect(seconds):
        nonlocal pending
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.2)
            if not ready:
                continue
            try:
                chunk = os.read(master, 4096).decode("utf-8", "replace")
            except OSError:
                return
            pending += chunk
            while "\n" in pending:
                line, pending = pending.split("\n", 1)
                lines.append(line.rstrip("\r"))

    def wait_for(pattern, limit, start=0):
        expression = re.compile(pattern)
        deadline = time.monotonic() + limit
        while True:
            for line in lines[start:]:
                if expression.search(line):
                    return True
            if time.monotonic() >= deadline:
                return False
            collect(0.3)

    try:
        os.write(master, b"protover 2\n")
        wait_for(r"feature done=1", 60)
        for move in moves:
            # the engine answers a move with its own reply in the ply count form, and each
            # answer is looked for past the lines that were already read for the last one
            start = len(lines)
            os.write(master, f"usermove {move}\n".encode())
            if not wait_for(r"^\d+\. \.\.\. ", 120, start):
                break
        os.write(master, b"quit\n")
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
    finally:
        os.close(master)
    return lines, process.returncode


def chess_case(case, work, bits):
    """an open-source game built for one ABI and played over its own line protocol. the two
    ABIs are separate ids because a 32-bit run on an x86_64 host says nothing about the
    64-bit binary."""
    pin = PINS.get("gnuchess-6.2.9.tar.gz")
    if not pin:
        case.unpinned("https://ftp.gnu.org/gnu/chess/gnuchess-6.2.9.tar.gz")
        return
    if not need(case, "gcc"):
        return
    case.artifact = pin
    archive = fetch_pin(case, work, pin)
    if not archive:
        return
    # each ABI configures its own tree, since one tree holds one answer to what -m32 means
    source = unpack_root(case, work, archive, f"chess-{bits}")
    if not source:
        return
    engine = source / "src" / "gnuchess"
    if not engine.is_file():
        env = None
        if bits == "i686":
            # the gnuchess frontend is C++, so a 32-bit build needs g++ emitting i386 as
            # much as it needs gcc, and configure reads every one of these variables
            if not need(case, "g++"):
                return
            env = {"CFLAGS": "-m32", "CXXFLAGS": "-m32", "LDFLAGS": "-m32"}
        code, out, err, _ = run(["./configure"], cwd=source, env=env, timeout=900,
                                log=work / "logs" / f"{case.name}.configure.log")
        if code:
            case.fail(f"gnuchess configure failed: {rc_text(err)}")
            return
        code, out, err, _ = run(["make", "-j4"], cwd=source, timeout=1800,
                                log=work / "logs" / f"{case.name}.build.log")
        if code:
            case.fail(f"gnuchess did not build: {rc_text(err)}")
            return
    if not engine.is_file():
        case.missing("the gnuchess build produced no engine")
        return
    code, out, _, _ = run(["file", "-b", str(engine)])
    machine = "Intel i386" if bits == "i686" else "x86-64"
    if machine not in out:
        case.fail(f"the engine is not a {bits} object: {out.strip()[:80]}")
        return
    try:
        lines, status = xboard_game(engine, CHESS_MOVES)
    except Exception as error:
        case.fail(f"the engine session failed: {type(error).__name__}: {error}")
        return
    write(work / "logs" / f"{case.name}.log", "\n".join(lines) + "\n")
    plies = [line for line in lines if re.match(r"^\d+\. ", line)]
    replies = [line for line in lines if re.match(r"^\d+\. \.\.\. ", line)]
    refused = [line for line in lines if "Illegal" in line or "Error" in line]
    if refused:
        case.fail(f"the engine refused a move: {refused[:1]}")
        return
    if len(replies) != len(CHESS_MOVES):
        case.fail(f"the engine answered {len(replies)} of {len(CHESS_MOVES)} moves: {plies[:4]}")
        return
    if status not in (0, None):
        case.fail(f"the engine exited with {status} after the game")
        return
    interpreter = ""
    code, out, _, _ = run(["file", "-b", str(engine)])
    if "interpreter" in out:
        interpreter = out.split("interpreter ")[1].split(",")[0].strip()
    case.reason = (f"{len(replies)} engine replies to {' and '.join(CHESS_MOVES)} on {bits}"
                   f" ({replies[-1].split('... ')[-1]}); "
                   f"interpreter {interpreter or 'none (static)'}")


def wine_tool():
    """the loader a host calls wine. a build made for one architecture installs only that
    name, so asking for wine64 after wine is not a second preference but the same tool."""
    return shutil.which("wine") or shutil.which("wine64")


def wine_prefix(case, work, wine):
    """a prefix of this work directory, booted once. WINEPREFIX is set per command, so two
    cases sharing a work directory share a prefix and a report says which one it used."""
    prefix = work / "wineprefix"
    env = {"WINEPREFIX": str(prefix), "WINEDEBUG": "-all",
           "WINEDLLOVERRIDES": "mscoree,mshtml="}
    if (prefix / "drive_c" / "windows" / "system32").is_dir():
        return env
    code, out, err, _ = run([wine, "wineboot", "-u"], timeout=1800, env=env,
                            log=work / "logs" / f"{case.name}.boot.log")
    if code or not (prefix / "drive_c" / "windows" / "system32").is_dir():
        case.fail(f"the wine prefix did not come up: rc={code}")
        return None
    return env


def wine_case(case, work, bits):
    """a pinned Windows console program under wine. the two PE architectures are separate
    ids, since a 64-bit program running says nothing about the 32-bit side."""
    pin_name = f"ripgrep-14.1.1-{bits}-pc-windows-msvc.zip"
    pin = PINS.get(pin_name)
    if not pin:
        case.unpinned(f"https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/{pin_name}")
        return
    wine = wine_tool()
    if not wine:
        case.missing("wine not installed")
        return
    case.artifact = pin
    archive = fetch_pin(case, work, pin)
    if not archive:
        return
    env = wine_prefix(case, work, wine)
    if not env:
        return
    directory = work / f"wine-{bits}"
    directory.mkdir(parents=True, exist_ok=True)
    program = directory / f"ripgrep-14.1.1-{bits}-pc-windows-msvc" / "rg.exe"
    if not program.is_file():
        code, out, err, _ = run([sys.executable, "-c", "import zipfile,sys;zipfile.ZipFile(sys.argv[1])"
                                 ".extractall(sys.argv[2])", str(archive), str(directory)],
                                timeout=300, log=work / "logs" / f"{case.name}.unpack.log")
        if code or not program.is_file():
            case.fail(f"the pinned zip did not yield rg.exe: rc={code}")
            return
    if bits == "i686" and not (work / "wineprefix" / "drive_c" / "windows" / "syswow64"
                               / "ntdll.dll").is_file():
        # a wine built with --disable-win32 has no 32-bit side at all, and the loader says so
        # by name, so the case reports the absence instead of running the 64-bit one twice
        case.missing("this wine has no syswow64 ntdll.dll, so no 32-bit Windows program can "
                     "start; build it with both architectures")
        return
    fixture = write(program.parent / "holy-matrix.txt", "the answer is 42\nholy matrix\n")
    code, out, err, _ = run([wine, program.name, "--version"], cwd=program.parent, env=env,
                            timeout=600, log=work / "logs" / f"{case.name}.version.log")
    combined = out + err
    if code or "ripgrep 14.1.1" not in combined:
        case.fail(f"the {bits} Windows program did not report its version: rc={code}")
        return
    code, out, err, _ = run([wine, program.name, "-n", "answer", fixture.name],
                            cwd=program.parent, env=env, timeout=600,
                            log=work / "logs" / f"{case.name}.search.log")
    combined = out + err
    if code or "the answer is 42" not in combined:
        case.fail(f"the {bits} Windows program did not search its fixture: rc={code}")
        return
    case.reason = f"a {bits} Windows console program searched the fixture under {Path(wine).name}"


LLAMA_PROMPT = "The capital of France is"
LLAMA_ANSWER = "Paris"


def llama_case(case, work, vulkan):
    """llama.cpp built from its pin, asked the pinned model one question and made to answer
    it. the CPU run and the Vulkan run are separate ids, because a software device and a
    real one are different facts."""
    engine = PINS.get("llama.cpp-b6100.tar.gz")
    model = PINS.get("tinyllama-q4.gguf")
    if not engine:
        case.unpinned("https://github.com/ggml-org/llama.cpp/archive/refs/tags/b6100.tar.gz")
        return
    if not model:
        case.unpinned("https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/"
                      "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf")
        return
    if not need(case, "cmake"):
        return
    if vulkan and not any(Path("/dev/dri").glob("renderD*")):
        case.missing("no /dev/dri render node for a Vulkan run")
        return
    case.artifact = {"sha256": engine["sha256"], "url": engine["url"],
                     "license": f"{engine['license']} engine, {model['license']} model",
                     "model_sha256": model["sha256"], "model_url": model["url"]}
    engine_archive = fetch_pin(case, work, engine)
    if not engine_archive:
        return
    model_file = fetch_pin(case, work, model)
    if not model_file:
        return
    source = unpack_root(case, work, engine_archive, "llama")
    if not source:
        return
    build = source / ("build-vulkan" if vulkan else "build-cpu")
    cli = build / "bin" / "llama-cli"
    if not cli.is_file():
        flags = ["-DCMAKE_BUILD_TYPE=Release", "-DLLAMA_CURL=OFF", "-DGGML_NATIVE=OFF",
                 "-DLLAMA_BUILD_TESTS=OFF"]
        if vulkan:
            flags.append("-DGGML_VULKAN=ON")
        code, out, err, _ = run(["cmake", "-S", str(source), "-B", str(build), *flags],
                                timeout=900, log=work / "logs" / f"{case.name}.configure.log")
        if code:
            case.fail(f"cmake configure failed: {rc_text(err)}")
            return
        code, out, err, _ = run(["cmake", "--build", str(build), "-j4", "--target", "llama-cli"],
                                timeout=7200, log=work / "logs" / f"{case.name}.build.log")
        if code:
            case.fail(f"the llama.cpp build failed: {rc_text(err)}")
            return
    if not cli.is_file():
        case.missing("the llama.cpp build produced no llama-cli")
        return
    device = None
    if vulkan:
        code, out, err, _ = run([str(cli), "--list-devices"], timeout=300,
                                log=work / "logs" / f"{case.name}.devices.log")
        # the listing names each device as VulkanN: description, and the model load line
        # repeats the name it used, so the case takes the name from the listing and reads the
        # description back off the run that answered the question
        for line in out.splitlines():
            if line.strip().startswith("Vulkan") and ":" in line:
                device = line.split(":", 1)[0].strip()
                break
        if not device:
            case.fail("this llama.cpp build reported no Vulkan device")
            return
    argv = [str(cli), "-m", str(model_file), "-p", LLAMA_PROMPT, "-n", "16", "-t", "4",
            "--seed", "1", "--temp", "0", "--no-warmup", "-no-cnv"]
    if vulkan:
        argv += ["-dev", device]
    code, out, err, _ = run(argv, timeout=1800, log=work / "logs" / f"{case.name}.log")
    combined = out + err
    if code:
        case.fail(f"llama-cli returned {code}: {rc_text(err)}")
        return
    answer = ""
    for line in combined.splitlines():
        # the prompt is echoed with a space in front of it, so the line is stripped before
        # the continuation is read off the end of it
        if line.strip().startswith(LLAMA_PROMPT):
            answer = line.strip()[len(LLAMA_PROMPT):].strip()
    if LLAMA_ANSWER not in answer:
        case.fail(f"the model answered {answer[:60]!r}, not {LLAMA_ANSWER!r}")
        return
    rate = ""
    for line in combined.splitlines():
        if "eval time" in line and "per token" in line:
            rate = line.split("per token,")[1].split("tokens per second")[0].strip()
    if not rate:
        case.fail("llama-cli printed no token rate, so nothing was generated")
        return
    if vulkan:
        loaded = [line for line in combined.splitlines() if "using device" in line]
        if not loaded or f"using device {device}" not in loaded[0]:
            case.fail(f"the model was not loaded on the Vulkan device: {loaded[:1]}")
            return
        name = loaded[0].split(f"using device {device}", 1)[1].split(" - ")[0].strip()
        case.reason = f"{LLAMA_ANSWER} through {name} at {rate} tokens per second"
        return
    case.reason = f"{LLAMA_ANSWER} on the CPU at {rate} tokens per second"


CASES = [
    ("cc-headers-gcc", "sdk", lambda c, w: c_headers_case(c, w, "gcc")),
    ("cc-headers-tcc", "sdk", lambda c, w: c_headers_case(c, w, "tcc")),
    ("cc-headers-clang", "sdk", lambda c, w: c_headers_case(c, w, "clang")),
    ("cc-gcc-musl", "sdk", lambda c, w: musl_case(c, w)),
    ("cc-gcc-glibc", "sdk", lambda c, w: c_case(c, w, "gcc")),
    ("cc-clang-glibc", "sdk", lambda c, w: c_case(c, w, "clang")),
    ("cxx-gcc", "sdk", lambda c, w: cxx_case(c, w, "g++")),
    ("cxx-clang", "sdk", lambda c, w: cxx_case(c, w, "clang++")),
    ("rust-cargo", "sdk", rust_case),
    ("rust-musl-target", "sdk", rust_musl_case),
    ("go-pure", "sdk", lambda c, w: go_case(c, w, False)),
    ("go-cgo", "sdk", lambda c, w: go_case(c, w, True)),
    ("build-make", "build", lambda c, w: make_case(c, w, build_project(w))),
    ("build-cmake", "build", lambda c, w: cmake_case(c, w, build_project(w))),
    ("build-meson", "build", lambda c, w: meson_case(c, w, build_project(w))),
    ("debug-gdb", "debug", lambda c, w: debug_case(c, w, "gdb",
                                                  ["-ex", "break level_two", "-ex", "run",
                                                   "-ex", "bt", "-ex", "info frame"])),
    ("debug-lldb", "debug", lambda c, w: debug_case(c, w, "lldb",
                                                   ["-o", "breakpoint set -n level_two",
                                                    "-o", "run", "-o", "bt"])),
    ("debug-rizin", "debug", rizin_case),
    ("python-imports", "language", lambda c, w: python_case(c, w, sys.executable)),
    ("python-venv", "language", lambda c, w: python_venv_case(c, w, sys.executable)),
    ("node-run", "language", lambda c, w: node_case(c, w, False)),
    ("node-native-addon", "language", lambda c, w: node_case(c, w, True)),
    ("network-git-curl-openssl", "network", git_fixture_case),
    ("network-dns-glibc", "network", lambda c, w: dns_case(c, w, "gcc")),
    ("system-locale", "system", locale_case),
    ("system-nss", "system", nss_case),
    ("system-pam", "system", pam_case),
    ("gui-firefox-headless", "gui", lambda c, w: firefox_case(c, w, True)),
    ("gui-firefox-session", "gui", lambda c, w: firefox_case(c, w, False)),
    ("graphics-vulkan-software", "graphics", lambda c, w: vulkan_case(c, w, True)),
    ("graphics-vulkan-hardware", "graphics", lambda c, w: vulkan_case(c, w, False)),
    ("graphics-opengl", "graphics", opengl_case),
    ("gaming-game-x86_64", "gaming", lambda c, w: chess_case(c, w, "x86_64")),
    ("gaming-game-i686", "gaming", lambda c, w: chess_case(c, w, "i686")),
    ("gaming-wine-x86_64", "gaming", lambda c, w: wine_case(c, w, "x86_64")),
    ("gaming-wine-i686", "gaming", lambda c, w: wine_case(c, w, "i686")),
    ("workstation-llama", "workstation", lambda c, w: llama_case(c, w, False)),
    ("workstation-llama-vulkan", "workstation", lambda c, w: llama_case(c, w, True)),
    ("foreign-rizin-source", "foreign",
     lambda c, w: pinned_source_case(c, w, "rizin-0.8.1.tar.gz",
                                    "https://github.com/rizinorg/rizin/archive/refs/tags/v0.8.1.tar.gz",
                                    "BSD-3-Clause")),
    ("foreign-wine-source", "foreign",
     lambda c, w: pinned_source_case(c, w, "wine-10.0.tar.xz",
                                    "https://dl.winehq.org/wine/source/10.0/wine-10.0.tar.xz",
                                    "LGPL-2.1")),
    ("foreign-zed-source", "foreign",
     lambda c, w: pinned_source_case(c, w, "zed-1.22.0.tar.gz",
                                    "https://github.com/zed-industries/zed/archive/refs/tags/v1.22.0.tar.gz",
                                    "GPL-3.0-or-later")),
    ("debug-rizin-built", "debug", rizin_build_case),
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default="")
    parser.add_argument("--work", default="")
    parser.add_argument("--output", default="out/matrix.json")
    parser.add_argument("--require", action="store_true",
                        help="treat a missing or unpinned case as a failure of the run")
    options = parser.parse_args()
    wanted = {name for name in options.only.split(",") if name}
    temporary = None
    # the cases hand paths to other tools and to a file URI, so the work directory is
    # absolute whatever the caller typed
    if options.work:
        work = Path(options.work).resolve()
        work.mkdir(parents=True, exist_ok=True)
    else:
        temporary = tempfile.TemporaryDirectory(prefix="holy-matrix-")
        work = Path(temporary.name).resolve()
    (work / "logs").mkdir(exist_ok=True)
    results = []
    try:
        for name, group, body in CASES:
            if wanted and name not in wanted:
                continue
            case = Case(name, group)
            started = time.monotonic()
            try:
                body(case, work)
            except Exception as error:  # a case that raises is a failure, not a crash
                case.fail(f"{type(error).__name__}: {error}")
            case.seconds = round(time.monotonic() - started, 3)
            case.log = str((work / "logs" / f"{case.name}.log").resolve())
            results.append(case)
            print(f"{case.status:9} {case.name:28} {case.seconds:8.3f}s  {case.reason}",
                  file=sys.stdout)
    finally:
        if temporary:
            temporary.cleanup()
    counts = {}
    for case in results:
        counts[case.status] = counts.get(case.status, 0) + 1
    groups = {}
    for case in results:
        entry = groups.setdefault(case.group, {"pass": 0, "fail": 0, "missing": 0, "unpinned": 0})
        entry[case.status] += 1
    report = {
        "schema": "holy-matrix-report-1",
        "work": str(work.resolve()),
        "counts": counts,
        "groups": groups,
        "cases": [{"name": case.name, "group": case.group, "status": case.status,
                   "seconds": case.seconds, "reason": case.reason, "log": case.log,
                   "artifact": case.artifact} for case in results],
    }
    output = Path(options.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"\nholy-matrix: {counts.get('pass', 0)} pass, {counts.get('fail', 0)} fail, "
          f"{counts.get('missing', 0)} missing, {counts.get('unpinned', 0)} unpinned "
          f"-> {output}")
    if counts.get("fail"):
        return 4
    if options.require and (counts.get("missing") or counts.get("unpinned")):
        return 6
    return 0


if __name__ == "__main__":
    raise SystemExit(main())