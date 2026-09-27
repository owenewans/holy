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


def region_hash(path, offset, size):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        stream.seek(offset)
        while size:
            data = stream.read(min(size, 1048576))
            assert data
            digest.update(data)
            size -= len(data)
    return digest.hexdigest()


def main(binary):
    for tool in ("/usr/sbin/sfdisk", "/sbin/mkfs.fat", "/sbin/mke2fs",
                 "/sbin/blkid", "/sbin/losetup", "/usr/bin/limine"):
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
        shown = run(binary, "disk", "show", "--plan", plan)
        assert f"disk image {image}\n" in shown
        assert "ESP 4096+524288 FAT32" in shown
        assert f"head-sha256 {before[0]}\n" in shown
        assert f"tail-sha256 {before[1]}\n" in shown
        assert sample_hash(image) == before
        assert os.stat(plan).st_mode & 0o777 == 0o600
        run(binary, "disk", "apply", "--plan", plan, "--confirm", image + "x", code=3)
        assert sample_hash(image) == before

        link = os.path.join(directory, "plan-link")
        os.symlink(plan, link)
        run(binary, "disk", "apply", "--plan", link, "--confirm", image, code=2)
        run(binary, "disk", "show", "--plan", link, code=2)
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
        esp_image = os.path.join(directory, "esp.fat")
        root_image = os.path.join(directory, "root.ext4")
        run("/sbin/mkfs.fat", "-C", "-F", "32", "-s", "4", esp_image, "262144")
        with open(root_image, "wb") as stream:
            stream.truncate(1566720 * 512)
        run("/sbin/mke2fs", "-q", "-t", "ext4", "-F", root_image)
        final_plan = os.path.join(directory, "final-plan")
        before = sample_hash(image)
        with open(image, "r+b") as stream:
            stream.seek(1024 + 128 + 32)
            saved_lba = stream.read(1)
            stream.seek(1024 + 128 + 32)
            stream.write(b"X")
        run(binary, "disk", "finalize-plan", "--disk-plan", plan,
            "--esp", esp_image, "--root-image", root_image,
            "--output", final_plan, code=6)
        with open(image, "r+b") as stream:
            stream.seek(1024 + 128 + 32)
            stream.write(saved_lba)
        assert sample_hash(image) == before
        run(binary, "disk", "finalize-plan", "--disk-plan", plan,
            "--esp", esp_image, "--root-image", root_image,
            "--output", final_plan)
        assert sample_hash(image) == before
        run(binary, "disk", "finalize-apply", "--plan", final_plan,
            "--confirm", image + "x", code=3)
        assert sample_hash(image) == before
        with open(root_image, "r+b") as stream:
            stream.seek(8192)
            previous = stream.read(1)
            stream.seek(8192)
            stream.write(b"X")
        run(binary, "disk", "finalize-apply", "--plan", final_plan,
            "--confirm", image, code=3)
        assert sample_hash(image) == before
        with open(root_image, "r+b") as stream:
            stream.seek(8192)
            stream.write(previous)
        with open(final_plan + ".journal", "w") as stream:
            stream.write("prepared\n")
        run(binary, "disk", "finalize-apply", "--plan", final_plan,
            "--confirm", image, code=5)
        assert sample_hash(image) == before
        os.unlink(final_plan + ".journal")
        run(binary, "disk", "finalize-apply", "--plan", final_plan,
            "--confirm", image)
        assert open(final_plan + ".journal").read().splitlines()[-1] == "committed"
        assert region_hash(image, 4096 * 512, 524288 * 512) == \
            region_hash(esp_image, 0, 524288 * 512)
        assert region_hash(image, 528384 * 512, 1566720 * 512) == \
            region_hash(root_image, 0, 1566720 * 512)
        run("/usr/sbin/sfdisk", "--verify", image)
        run(binary, "disk", "finalize-apply", "--plan", final_plan,
            "--confirm", image, code=3)
        print("installer disk image: plan, identity, journal, GPT, FAT32, ext4, finalize passed")


if __name__ == "__main__":
    main(os.path.abspath(sys.argv[1]))
