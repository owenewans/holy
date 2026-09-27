#!/usr/bin/env python3
import hashlib
import json
import os
import subprocess
import sys
import tempfile


def run(*argv, code=0):
    result = subprocess.run(argv, capture_output=True, text=True)
    if result.returncode != code:
        raise AssertionError((argv, result.returncode, result.stdout, result.stderr))
    return result.stdout


def sample_hash(path):
    with open(path, "rb") as stream:
        head = hashlib.sha256(stream.read(1048576)).hexdigest()
        stream.seek(-1048576, os.SEEK_END)
        tail = hashlib.sha256(stream.read(1048576)).hexdigest()
    return head, tail


def main(binary):
    for tool in ("/usr/sbin/sfdisk", "/sbin/mkfs.fat", "/sbin/mke2fs",
                 "/sbin/blkid", "/sbin/losetup"):
        if not os.access(tool, os.X_OK):
            raise SystemExit(f"required tool missing: {tool}")
    with tempfile.TemporaryDirectory(prefix="holy-installer-disk-") as directory:
        image = os.path.join(directory, "disk image.img")
        config = os.path.join(directory, "config")
        plan = os.path.join(directory, "plan")
        with open(image, "wb") as stream:
            stream.truncate(1 << 30)
        with open(config, "w") as stream:
            stream.write(f'[disk]\nimage "{image}"\nlayout gpt-ext4\n')
        before = sample_hash(image)
        run(binary, "disk", "plan", "--config", config, "--output", plan)
        assert sample_hash(image) == before
        assert os.stat(plan).st_mode & 0o777 == 0o600
        run(binary, "disk", "apply", "--plan", plan, "--confirm", image + "x", code=3)
        assert sample_hash(image) == before

        link = os.path.join(directory, "plan-link")
        os.symlink(plan, link)
        run(binary, "disk", "apply", "--plan", link, "--confirm", image, code=2)
        fifo = os.path.join(directory, "plan-fifo")
        os.mkfifo(fifo)
        run(binary, "disk", "apply", "--plan", fifo, "--confirm", image, code=2)
        include = os.path.join(directory, "plan-include")
        with open(include, "w") as stream:
            stream.write('include "' + plan + '"\n')
        run(binary, "disk", "apply", "--plan", include, "--confirm", image, code=2)
        with open(image, "r+b") as stream:
            stream.seek(512)
            stream.write(b"x")
        run(binary, "disk", "apply", "--plan", plan, "--confirm", image, code=3)
        with open(image, "r+b") as stream:
            stream.seek(512)
            stream.write(b"\0")
        assert sample_hash(image) == before

        with open(plan + ".journal", "w") as stream:
            stream.write("prepared\n")
        run(binary, "disk", "apply", "--plan", plan, "--confirm", image, code=5)
        assert sample_hash(image) == before
        os.unlink(plan + ".journal")

        run(binary, "disk", "apply", "--plan", plan, "--confirm", image)
        assert open(plan + ".journal").read().splitlines()[-1] == "committed"
        table = json.loads(run("/usr/sbin/sfdisk", "--json", image))["partitiontable"]
        assert table["label"] == "gpt"
        assert [(p["start"], p["size"]) for p in table["partitions"]] == [
            (2048, 2048), (4096, 524288), (528384, 1566720)]
        fat = run("/sbin/blkid", "-p", "-O", str(4096 * 512),
                  "-S", str(524288 * 512), image)
        root = run("/sbin/blkid", "-p", "-O", str(528384 * 512),
                   "-S", str(1566720 * 512), image)
        assert 'TYPE="vfat"' in fat and 'TYPE="ext4"' in root
        print("installer disk image: plan, identity, journal, GPT, FAT32, ext4 passed")


if __name__ == "__main__":
    main(os.path.abspath(sys.argv[1]))
