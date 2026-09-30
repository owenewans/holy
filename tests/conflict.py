#!/usr/bin/env python3
"""reports the conflicts one installed set can leave behind: two providers of one
SONAME, two providers of one package name, two declared owners of one file path and
two private programs of one name."""
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile


binary = str(pathlib.Path(sys.argv[1]).resolve())


def call(*args, status=0):
    result = subprocess.run([binary, *map(str, args)], capture_output=True, text=True)
    assert result.returncode == status, (args, result.returncode, result.stdout, result.stderr)
    return result.stdout


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def program(relative):
    """a path a run PATH lookup would resolve, which a package claims as a program"""
    parts = relative.split("/")
    return parts[-2:-1] and parts[-2] in ("bin", "sbin")


def build(root, tree, name, *, files, provides="", deps="", arch="noarch", libc="nolibc",
          label=None):
    """one package tree, packed and staged in the target cache"""
    import shutil
    shutil.rmtree(tree, ignore_errors=True)
    (tree / "HOLY").mkdir(parents=True)
    (tree / "DATA").mkdir(parents=True)
    (tree / "HOLY/meta").write_text(
        "format holy-package-1\nname %s\nversion 1\nrelease 1\nos linux\narch %s\nlibc %s\n"
        % (name, arch, libc))
    for field, body in (("deps", deps), ("provides", provides),
                        ("hooks", ""), ("origin", ""), ("transform", "")):
        (tree / "HOLY" / field).write_text(body)
    for relative, body in files.items():
        path = tree / "DATA" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(body, bytes):
            path.write_bytes(body)
        else:
            path.write_text(body)
        path.chmod(0o755 if program(relative) else 0o644)
    label = label or name
    call("manifest", "generate", tree, "--output", root / (label + "-files"))
    (tree / "HOLY/files").write_text((root / (label + "-files")).read_text())
    artifact = root / (label + ".holy")
    call("pack", tree, "--output", artifact)
    call("cache", "stage", "local:" + str(artifact), "--root", root)
    return digest(artifact)


def install(root, plan_digests):
    """plan and apply one set; every candidate is selected, so two roots conflict"""
    out = call("db", "plan-set", *plan_digests, "--root", root)
    plan = [line.split()[10] for line in out.splitlines() if line.startswith("plan-set ")][0]
    call("db", "apply-set", plan, *plan_digests, "--root", root)
    return out


def plan_of(text):
    """the plan hash a plan-set line carries, which apply-set and the journal name"""
    return [line.split()[10] for line in text.splitlines() if line.startswith("plan-set ")][0]


def findings(root):
    """the report over a root that has a conflict, which is status 1"""
    text = call("conflict", "--root", root, "--json", status=1)
    return [record for record in (json.loads(line) for line in text.splitlines())
            if record["type"] == "finding"]


def main():
    with tempfile.TemporaryDirectory() as scratch:
        base = pathlib.Path(scratch)
        root = base / "root"
        (root / "usr/share").mkdir(parents=True)
        tree = base / "tree"
        call("db", "init", "--root", root)

        # a clean root has no conflicts
        report = call("conflict", "--root", root, "--json")
        summary = [json.loads(line) for line in report.splitlines()][-1]
        assert summary["type"] == "summary" and summary["findings"] == 0, summary
        assert summary["installed"] == 0, summary

        # one library and one application that needs it
        lib = build(root, tree, "conflictor", files={"usr/share/conflictor": "the library\n"},
                    provides="provide package conflictor noarch nolibc - metadata\n"
                             "provide soname libconflictor.so.1 noarch nolibc - metadata\n")
        app = build(root, tree, "consumer", files={"usr/share/consumer": "the application\n"},
                    deps="require dep-1 consumer package conflictor noarch nolibc any - "
                         "conflictor metadata\n")
        out = install(root, [app, lib])
        assert "requirement dep-1 consumer %s provider %s package conflictor" % (
            app, lib) in out, out
        # one owner and one dependent, so nothing collides
        call("conflict", "--root", root, "--json")
        text = call("conflict", "--root", root)
        assert "conflicts 0 read-only" in text, text
        assert "installed 2" in text, text

        # a second library with the same SONAME, installed as its own root
        rival = build(root, tree, "conflictor-rival",
                      files={"usr/share/conflictor-rival": "the rival library\n"},
                      provides="provide package conflictor-rival noarch nolibc - metadata\n"
                               "provide soname libconflictor.so.1 noarch nolibc - metadata\n")
        call("db", "plan-set", rival, "--root", root)
        out = call("db", "apply-set",
                   [line.split()[10] for line in
                    call("db", "plan-set", rival, "--root", root).splitlines()
                    if line.startswith("plan-set ")][0], rival, "--root", root)
        assert "committed-set" in out, out
        found = findings(root)
        names = sorted((record["kind"], record["name"], record["reason"]) for record in found)
        assert names == [("soname", "libconflictor.so.1", "duplicate-provider")], found
        soname = found[0]
        assert [provider["artifact"] for provider in soname["providers"]] == sorted(
            [lib, rival]), soname
        for provider in soname["providers"]:
            assert provider["arch"] == "noarch" and provider["libc"] == "nolibc", provider
        text = call("conflict", "--root", root, status=1)
        assert "conflict soname \"libconflictor.so.1\" providers 2 reason duplicate-provider" \
               in text, text
        assert "conflicts 1 read-only" in text, text
        # the application still resolves, and its provider is the one the set chose
        assert "provider %s" % lib in text, text

        # a different SONAME from another runtime is a different capability, since
        # noarch carries no runtime
        musl_rival = build(root, base / "tree2", "conflictor-musl",
                           files={"usr/share/conflictor-musl": "the musl library\n"},
                           provides="provide package conflictor-musl noarch nolibc - metadata\n"
                                    "provide soname libconflictor-musl.so.1 noarch nolibc - metadata\n")
        install(root, [musl_rival])
        found = findings(root)
        assert [record["kind"] for record in found] == ["soname"], found
        assert found[0]["name"] == "libconflictor.so.1", found[0]

        # two artifacts of different names both claiming one package name, which is
        # what a mixed provider looks like once both are installed
        other_root = base / "other-root"
        (other_root / "usr/share").mkdir(parents=True)
        call("db", "init", "--root", other_root)
        mixed_a = build(other_root, base / "tree3", "alpha", files={"usr/share/alpha": "a\n"},
                        provides="provide package shared noarch nolibc - metadata\n")
        mixed_b = build(other_root, base / "tree4", "beta", files={"usr/share/beta": "b\n"},
                        provides="provide package shared noarch nolibc - metadata\n")
        install(other_root, [mixed_a])
        install(other_root, [mixed_b])
        found = findings(other_root)
        assert [(record["kind"], record["name"], record["reason"]) for record in found] == [
            ("package", "shared", "mixed-providers")], found
        assert sorted(provider["artifact"] for provider in found[0]["providers"]) == sorted(
            [mixed_a, mixed_b]), found[0]
        # the slot of each name is its own, so the set is not otherwise a conflict
        text = call("conflict", "--root", other_root, status=1)
        assert "installed 2" in text, text

        # the selection itself can offer one capability twice, and the plan states it
        # before a file is staged
        set_root = base / "set-root"
        (set_root / "usr/share").mkdir(parents=True)
        call("db", "init", "--root", set_root)
        twin_a = build(set_root, base / "tree5", "twin-a",
                       files={"usr/share/twin-a.so.1": "a\n"},
                       provides="provide package twin-a noarch nolibc - metadata\n"
                                "provide soname libtwin.so.1 noarch nolibc - metadata\n")
        twin_b = build(set_root, base / "tree6", "twin-b",
                       files={"usr/share/twin-b.so.1": "b\n"},
                       provides="provide package twin-b noarch nolibc - metadata\n"
                                "provide soname libtwin.so.1 noarch nolibc - metadata\n")
        twin_app = build(set_root, base / "tree5b", "twin-app",
                         files={"usr/share/twin-app": "the application\n"},
                         deps="require dep-1 twin-app package twin-a noarch nolibc any - "
                              "twin-a metadata\n"
                              "require dep-2 twin-app package twin-b noarch nolibc any - "
                              "twin-b metadata\n")
        out = call("db", "plan-set", twin_app, twin_a, twin_b, "--root", set_root)
        assert 'conflict soname "libtwin.so.1" providers 2 reason duplicate-provider' in out, out
        assert "provider %s arch \"noarch\" libc \"nolibc\"" % twin_a in out, out
        assert "provider %s" % twin_b in out, out
        assert "set-conflicts generation 0 artifacts 3 capabilities 4 conflicts 1 read-only" in out, out
        twin_plan = plan_of(out)
        # a selection with nothing twice states that too
        lone = build(set_root, base / "tree7", "lone", files={"usr/share/lone": "alone\n"},
                     provides="provide soname liblone.so.1 noarch nolibc - metadata\n")

        out = call("db", "plan-set", lone, "--root", set_root)
        assert "conflict " not in out, out
        assert "set-conflicts generation 0 artifacts 1 capabilities 1 conflicts 0 read-only" in out, out
        # two offers of one SONAME with different ABIs is a mismatch, not a duplicate
        abi_a = build(set_root, base / "tree8", "abi-twin-a", files={"usr/share/abi-twin-a": "a\n"},
                      provides="provide package abi-twin-a noarch nolibc - metadata\n"
                               "provide soname libabitwin.so.1 x86_64 glibc - metadata\n")
        abi_b = build(set_root, base / "tree9", "abi-twin-b", files={"usr/share/abi-twin-b": "b\n"},
                      provides="provide package abi-twin-b noarch nolibc - metadata\n"
                               "provide soname libabitwin.so.1 x86_64 musl - metadata\n")
        abi_app = build(set_root, base / "tree9b", "abi-twin-app",
                        files={"usr/share/abi-twin-app": "the application\n"},
                        deps="require dep-1 abi-twin-app package abi-twin-a noarch nolibc any - "
                             "abi-twin-a metadata\n"
                             "require dep-2 abi-twin-app package abi-twin-b noarch nolibc any - "
                             "abi-twin-b metadata\n")
        out = call("db", "plan-set", abi_app, abi_a, abi_b, "--root", set_root)
        assert 'conflict soname "libabitwin.so.1" providers 2 reason abi-mismatch' in out, out
        # the transaction states the same facts before the first payload file lands
        out = call("db", "apply-set", twin_plan, twin_app, twin_a, twin_b, "--root", set_root)
        assert out.index("conflict soname") < out.index("applied"), out
        assert "committed-set" in out, out
        found = findings(set_root)
        assert [(record["kind"], record["name"], record["reason"]) for record in found] == [
            ("soname", "libtwin.so.1", "duplicate-provider")], found
        assert "installed 3" in call("conflict", "--root", set_root, status=1)

        # two providers of one SONAME with different ABIs is a mismatch, not a duplicate
        abi_root = base / "abi-root"
        (abi_root / "usr/share").mkdir(parents=True)
        call("db", "init", "--root", abi_root)
        abi_a = build(abi_root, base / "tree5", "abi-a", files={"usr/share/abi-a": "a\n"},
                      provides="provide soname libabi.so.1 x86_64 glibc - metadata\n",
                      arch="x86_64", libc="glibc")
        abi_b = build(abi_root, base / "tree6", "abi-b", files={"usr/share/abi-b": "b\n"},
                      provides="provide soname libabi.so.1 x86_64 musl - metadata\n",
                      arch="x86_64", libc="musl")
        # one set carries one root, so the second ABI arrives in the set after the first
        install(abi_root, [abi_a])
        install(abi_root, [abi_b])
        found = findings(abi_root)
        assert [(record["kind"], record["reason"]) for record in found] == [
            ("soname", "abi-mismatch")], found
        assert "reason abi-mismatch" in call("conflict", "--root", abi_root, status=1)

        # two declared owners of one public file path
        file_root = base / "file-root"
        (file_root / "usr/share").mkdir(parents=True)
        call("db", "init", "--root", file_root)
        path_a = build(file_root, base / "tree7", "path-a",
                       files={"usr/share/shared-a.conf": "a\n"},
                       provides="provide file /usr/share/shared.conf noarch nolibc - metadata\n")
        path_b = build(file_root, base / "tree8", "path-b",
                       files={"usr/share/shared-b.conf": "b\n"},
                       provides="provide file /usr/share/shared.conf noarch nolibc - metadata\n")
        install(file_root, [path_a])
        install(file_root, [path_b])
        found = findings(file_root)
        assert [(record["kind"], record["name"]) for record in found] == [
            ("file", "/usr/share/shared.conf")], found
        assert found[0]["reason"] == "duplicate-provider", found[0]

        # two private programs of one name, which a run PATH resolves by sort order
        private_root = base / "private-root"
        (private_root / "usr/share").mkdir(parents=True)
        call("db", "init", "--root", private_root)
        shell = None
        source = base / "sh.c"
        source.write_text("int main(void) { return 0; }\n")
        for compiler in ("cc", "gcc", "clang"):
            if subprocess.run(["which", compiler], capture_output=True).returncode:
                continue
            built = subprocess.run([compiler, "-static", str(source), "-o", str(
                base / "sh")], capture_output=True)
            if built.returncode == 0:
                shell = base / "sh"
                break
        assert shell, "a static shell is required for the private program fixtures"
        source.write_text('#include <stdio.h>\nint main(void) { puts("tool"); return 0; }\n')
        tool = None
        for compiler in ("cc", "gcc", "clang"):
            if subprocess.run(["which", compiler], capture_output=True).returncode:
                continue
            built = subprocess.run([compiler, "-static", str(source), "-o", str(base / "tool")],
                                   capture_output=True)
            if built.returncode == 0:
                tool = base / "tool"
                break
        assert tool, "a static program is required for the private program fixtures"
        first = build(private_root, base / "tree9", "private-a", arch="x86_64", files={
            "usr/lib/holy/private/private-a/usr/bin/tool": tool.read_bytes()})
        second = build(private_root, base / "tree10", "private-b", arch="x86_64", files={
            "usr/lib/holy/private/private-b/usr/bin/tool": tool.read_bytes()})
        install(private_root, [first])
        install(private_root, [second])
        found = findings(private_root)
        kinds = sorted((record["kind"], record["name"], record["reason"]) for record in found)
        assert kinds == [("private-command", "tool", "shadowed-path")], found
        # a private program each package owns alone is not a conflict
        single = build(private_root, base / "tree11", "private-c", arch="x86_64", files={
            "usr/lib/holy/private/private-c/usr/bin/other": tool.read_bytes()})
        install(private_root, [single])
        assert "conflicts 1 read-only" in call("conflict", "--root", private_root, status=1)
        # one selection that takes both programs of one name states the shadowing,
        # since a run PATH built from both private trees resolves it by sort order
        pair_root = base / "private-set-root"
        (pair_root / "usr/share").mkdir(parents=True)
        call("db", "init", "--root", pair_root)
        pair_a = build(pair_root, base / "tree12", "pair-a", arch="x86_64", provides=(
            "provide package pair-a x86_64 nolibc - metadata\n"), files={
            "usr/lib/holy/private/pair-a/usr/bin/tool": tool.read_bytes()})
        pair_b = build(pair_root, base / "tree13", "pair-b", arch="x86_64", provides=(
            "provide package pair-b x86_64 nolibc - metadata\n"), files={
            "usr/lib/holy/private/pair-b/usr/bin/tool": tool.read_bytes()})
        pair_app = build(pair_root, base / "tree14", "pair-app", arch="x86_64",
                         files={"usr/share/pair-app": "the application\n"},
                         deps="require dep-1 pair-app package pair-a x86_64 nolibc any - "
                              "pair-a metadata\n"
                              "require dep-2 pair-app package pair-b x86_64 nolibc any - "
                              "pair-b metadata\n")
        out = call("db", "plan-set", pair_app, pair_a, pair_b, "--root", pair_root)
        assert 'conflict private-command "tool" providers 2 reason shadowed-path' in out, out
        assert "set-conflicts generation 0 artifacts 3 capabilities 4 conflicts 1 read-only" in out, out

        # a report over a root with no database, and over a pending transaction
        empty = base / "empty-root"
        empty.mkdir()
        result = subprocess.run([binary, "conflict", "--root", empty], capture_output=True, text=True)
        assert result.returncode == 1, result
        assert "invalid-state" in result.stderr, result.stderr
        generation = int((private_root / "var/lib/holypkg/generation").read_text())
        journal = private_root / "var/lib/holypkg/transactions/journal"
        journal.write_text("format holy-journal-1\nstage applying\ngeneration %d\n"
                           "artifact %s\nplan %064d\n" % (generation, first, 2))
        result = subprocess.run([binary, "conflict", "--root", private_root],
                                capture_output=True, text=True)
        assert result.returncode == 5, result
        assert "incomplete-transaction" in result.stderr, result.stderr
        result = subprocess.run([binary, "conflict", "--root", private_root, "--json"],
                                capture_output=True, text=True)
        assert '"code":"incomplete-transaction"' in result.stdout, result.stdout
        journal.unlink()
        call("conflict", "--root", private_root, status=1)

        # an invalid argument is refused before the root is read
        result = subprocess.run([binary, "conflict", "--root"], capture_output=True, text=True)
        assert result.returncode == 2, result
        assert "usage: holypkg conflict" in result.stderr, result.stderr

    print("conflict fixtures passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
