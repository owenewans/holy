#!/usr/bin/env python3
"""a read-only file index over the installed set: which artifact owns a path and
which artifacts provide a name, with several candidates named rather than chosen."""
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


def build(root, tree, name, *, files, provides="", deps="", arch="noarch", libc="nolibc"):
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
    call("manifest", "generate", tree, "--output", root / (name + "-files"))
    (tree / "HOLY/files").write_text((root / (name + "-files")).read_text())
    artifact = root / (name + ".holy")
    call("pack", tree, "--output", artifact)
    call("cache", "stage", "local:" + str(artifact), "--root", root)
    return hashlib.sha256(artifact.read_bytes()).hexdigest()


def install(root, *digests):
    out = call("db", "plan-set", *digests, "--root", root)
    plan = [line.split()[10] for line in out.splitlines() if line.startswith("plan-set ")][0]
    call("db", "apply-set", plan, *digests, "--root", root)
    return out


def records(text):
    return [json.loads(line) for line in text.splitlines()]


def main():
    with tempfile.TemporaryDirectory() as scratch:
        base = pathlib.Path(scratch)
        root = base / "root"
        root.mkdir()
        tree = base / "tree"
        call("db", "init", "--root", root)

        # an empty root has an index with nothing in it
        report = records(call("index", "--root", root, "--json"))
        summary = report[-1]
        assert summary["type"] == "summary" and summary["artifacts"] == 0, summary
        assert summary["paths"] == 0 and summary["capabilities"] == 0, summary

        # a library, a second provider of its SONAME and an application that needs
        # one of them
        # the capability the index looks up is a declared one, so the fixtures are
        # text payloads: a requirement that names a package closes the set, while the
        # soname both providers declare is the ambiguity the index reports
        lib = build(root, tree, "indexlib", files={"usr/lib/libindex.so.1": "the library\n"},
                    provides="provide package indexlib noarch nolibc - metadata\n"
                             "provide soname libindex.so.1 noarch nolibc - metadata\n")
        # the rival keeps the soname but places its file elsewhere, so a set can hold
        # both providers: a path is owned by one artifact and a name by several
        rival = build(root, base / "tree2", "indexrival",
                      files={"usr/lib/rival/libindex.so.1": "the rival\n"},
                      provides="provide package indexrival noarch nolibc - metadata\n"
                               "provide soname libindex.so.1 noarch nolibc - metadata\n")
        app = build(root, base / "tree3", "indexapp", files={"usr/bin/indexapp": "the app\n"},
                    deps="require dep-1 indexapp package indexlib any any any - indexlib "
                         "metadata\n")
        out = install(root, app, lib)
        assert "requirement dep-1 consumer %s provider %s package indexlib" % (
            app, lib) in out, out
        # only the library the set chose is installed, so the index has one owner of
        # the path and one candidate for the soname
        text = call("index", "--root", root)
        assert "artifacts 2" in text, text
        assert "capability %s soname \"libindex.so.1\"" % lib in text, text
        assert "capability %s soname" % rival not in text, text

        # a path the index knows has one owner, named with its artifact
        found = call("index", "--root", root, "--path", "/usr/lib/libindex.so.1")
        assert 'owner %s "usr/lib/libindex.so.1"' % lib in found, found
        assert "candidates 1" in found, found
        # a leading slash is optional, since a manifest records the relative path
        assert call("index", "--root", root, "--path", "usr/lib/libindex.so.1") == found
        assert 'owner %s "usr/bin/indexapp"' % app in call(
            "index", "--root", root, "--path", "/usr/bin/indexapp")
        # a directory is shared, so it owns nothing
        result = subprocess.run([binary, "index", "--root", str(root), "--path", "/usr/lib"],
                                capture_output=True, text=True)
        assert result.returncode == 6, result
        assert "candidates 0" in result.stdout, result.stdout
        # a path no artifact owns is reported as unavailable
        result = subprocess.run([binary, "index", "--root", str(root), "--path", "/absent"],
                                capture_output=True, text=True)
        assert result.returncode == 6, result

        # a capability with one provider is a single candidate
        text = call("index", "--root", root, "--capability", "soname", "--name", "libindex.so.1")
        assert "candidate %s soname \"libindex.so.1\" arch \"noarch\" libc \"nolibc\"" % lib in text, text
        assert "candidates 1" in text, text
        # a capability no artifact provides is unavailable
        result = subprocess.run([binary, "index", "--root", str(root), "--capability", "soname",
                                 "--name", "absent.so.1"], capture_output=True, text=True)
        assert result.returncode == 6, result

        # a second provider of one SONAME names both candidates and chooses neither
        install(root, rival)
        text = call("index", "--root", root, "--capability", "soname", "--name", "libindex.so.1",
                    status=1)
        assert "candidate %s soname" % lib in text, text
        assert "candidate %s soname" % rival in text, text
        assert "candidates 2" in text, text
        # a path is owned by one artifact, so the rival's own path has one owner while
        # its soname has two candidates
        found = call("index", "--root", root, "--path", "/usr/lib/rival/libindex.so.1")
        assert "candidates 1" in found, found
        assert 'owner %s "usr/lib/rival/libindex.so.1"' % rival in found, found
        assert lib not in found, found

        # the conflict report and the index agree on what two artifacts both offer
        call("conflict", "--root", root, status=1)

        # the json form carries the same records
        events = records(call("index", "--root", root, "--capability", "soname", "--name",
                              "libindex.so.1", "--json", status=1))
        candidates = [event for event in events if event["type"] == "candidate"]
        assert len(candidates) == 2, events
        assert sorted(event["artifact"] for event in candidates) == sorted([lib, rival]), events
        for event in candidates:
            assert event["kind"] == "soname" and event["name"] == "libindex.so.1", event
            assert event["arch"] == "noarch" and event["libc"] == "nolibc", event
        assert events[-1]["type"] == "summary" and events[-1]["candidates"] == 2, events[-1]
        everything = records(call("index", "--root", root, "--json"))
        artifacts = [event for event in everything if event["type"] == "artifact"]
        assert len(artifacts) == 3, everything
        names = sorted(event["name"] for event in artifacts)
        assert names == ["indexapp", "indexlib", "indexrival"], names

        # an argument that names no subject, both subjects, or a relative path
        for args, wanted in ((["--path"], "usage: holypkg index"),
                             (["--path", "/a", "--capability", "soname", "--name", "b"],
                              "usage: holypkg index"),
                             (["--capability", "soname"], "usage: holypkg index"),
                             (["--name", "b"], "usage: holypkg index"),
                             (["--path", "/usr/../etc"], "usage: holypkg index"),
                             (["--path", "/"], "usage: holypkg index"),
                             (["--nonsense"], "usage: holypkg index")):
            result = subprocess.run([binary, "index", "--root", str(root), *args],
                                    capture_output=True, text=True)
            assert result.returncode == 2, (args, result)
            assert wanted in result.stderr, (args, result.stderr)
        assert (base / "empty").mkdir() or True
        result = subprocess.run([binary, "index", "--root", str(base / "empty")],
                                capture_output=True, text=True)
        assert result.returncode == 1, result
        assert "invalid-state" in result.stderr, result.stderr

    print("file index fixtures passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
