#!/usr/bin/env python3
"""the kernel rollback contract, proved on a real disk under QEMU.

An installed system carries two kernel slots and a limine.conf whose default_entry names
the current one. This test takes that disk, does what a bad kernel update does to it, and
checks what the machine actually does:

  1. refused: the current slot stops matching the digest its entry carries. limine warns
     and waits, and any key but Y returns to the menu. the previous slot is then chosen
     from that menu and the guest boots with its probes passing, naming the kernel that
     answered
  2. failed: the current slot carries a kernel that boots but does not satisfy the guest,
     so the guest reports a failure and the machine comes back to the same menu. the
     previous slot is chosen again and the guest passes

The serial line is a socket rather than a file, because choosing a slot means pressing
keys. A run with only one kernel cannot tell the two slots apart, so the second kernel is
required input rather than an optional extra.
"""
import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ESP_OFFSET = 4096 * 512
# the loader draws its menu on the serial line it was given, so the arrows it documents
# are the keys the operator sends there
UP = "\x1b[A"
DOWN = "\x1b[B"
ENTER = "\r"


def digest(path):
    """limine reads a path suffix as blake2b-512, so the digest written into the config
    is the one limine checks rather than a shorter hash it would panic on."""
    if not shutil.which("b2sum"):
        raise RuntimeError("b2sum required for the rollback contract")
    return subprocess.run(["b2sum", str(path)], capture_output=True,
                          text=True).stdout.split()[0]


def finish(status, message, report, path):
    report["status"] = "pass" if status == 0 else "missing-requirement" if status == 6 else "fail"
    report["message"] = message
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("holy-rollback: " + message, file=sys.stderr if status else sys.stdout)
    raise SystemExit(status)


def read_esp(image, name, out):
    subprocess.run(["mcopy", "-i", f"{image}@@{ESP_OFFSET}", f"::/{name}", str(out)],
                   check=True, capture_output=True)


def write_esp(image, name, source):
    subprocess.run(["mcopy", "-o", "-i", f"{image}@@{ESP_OFFSET}", str(source), f"::/{name}"],
                   check=True, capture_output=True)


def remove_esp(image, name):
    subprocess.run(["mdel", "-i", f"{image}@@{ESP_OFFSET}", f"::/{name}"], capture_output=True)


class Serial:
    def __init__(self, path):
        self.path = path
        self.buffer = ""
        self.handle = None

    def __enter__(self):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            handle = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                handle.connect(self.path)
                handle.setblocking(False)
                self.handle = handle
                return self
            except OSError:
                handle.close()
                time.sleep(0.2)
        raise RuntimeError("the guest serial socket never appeared")

    def __exit__(self, *unused):
        if self.handle:
            self.handle.close()

    def read(self, seconds=0.5):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                chunk = self.handle.recv(65536)
                if chunk:
                    self.buffer += chunk.decode("utf-8", "replace")
                    continue
            except BlockingIOError:
                pass
            except OSError:
                break
            time.sleep(0.05)
        return self.buffer

    def since(self, mark):
        return self.buffer[mark:]

    def send(self, text):
        self.handle.sendall(text.encode())


def drive(qemu, image, socket_path, seconds, steps, reboot=False):
    """one boot. a step is (from_index, needle, keystrokes, settle_seconds): once the
    needle appears in the transcript after from_index, the keystrokes go out and the next
    step starts matching after that point. the transcript is everything the guest wrote."""
    argv = [qemu, "-accel", "tcg", "-m", "1024", "-display", "none", "-monitor", "none",
            "-net", "none", "-boot", "c"]
    if not reboot:
        argv.append("-no-reboot")
    argv += ["-serial", f"unix:{socket_path},server=on,wait=off",
             "-drive", f"file={image},format=raw,if=virtio,snapshot=on"]
    process = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    transcript = ""
    try:
        with Serial(socket_path) as line:
            step = 0
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline and process.poll() is None:
                transcript += line.read(0.4)
                if step < len(steps):
                    start, needle, keystrokes, settle = steps[step]
                    if needle in transcript[start:]:
                        for group in keystrokes:
                            if isinstance(group, tuple):
                                time.sleep(group[1])
                                line.send(group[0])
                            else:
                                line.send(group)
                        step += 1
                        deadline = max(deadline, time.monotonic() + settle)
    finally:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
    return transcript


def set_default(config, slot):
    text, count = re.subn(r"(?m)^default_entry:.*$", f"default_entry: Holy {slot}", config)
    if count != 1:
        raise ValueError("the config carries no single default_entry line")
    return text


def set_slot_digest(config, slot, kind, value):
    pattern = re.compile(rf"(?m)^(\s*{kind}:.*-{slot}(?:\.img)?)#[0-9a-f]+$")
    text, count = pattern.subn(lambda match: f"{match.group(1)}#{value}", config)
    if count != 1:
        raise ValueError(f"the config carries no single {kind} for slot {slot}")
    return text


def guest_markers(transcript):
    """a disk image asks the guest to reboot after its first boot, so a first boot that
    passed is reported as first-boot pass and only the second boot prints result pass.
    both count as the guest working."""
    # the serial line ends lines with cr, so the anchor is the marker itself
    kernels = re.findall(r"HOLY-BOOT-1 kernel (\S+)", transcript)
    return {
        "booted": "HOLY-BOOT-1 boot 1" in transcript,
        "passed": ("HOLY-BOOT-1 result pass" in transcript or
                   "HOLY-BOOT-1 first-boot pass" in transcript),
        "failed": "HOLY-BOOT-1 result fail" in transcript,
        "kernels": sorted(set(kernels)),
        "kernel": kernels[0] if kernels else None,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--disk", required=True, help="a disk.raw carrying two slots")
    parser.add_argument("--other-kernel", required=True,
                        help="a kernel the guest can tell apart from the installed one")
    parser.add_argument("--qemu", default="qemu-system-i386")
    parser.add_argument("--output", default="out/rollback.json")
    parser.add_argument("--seconds", type=int, default=240)
    options = parser.parse_args()

    report = {"schema": "holy-rollback-report-1", "boots": []}
    output = Path(options.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    disk = Path(options.disk).resolve()
    other = Path(options.other_kernel).resolve()
    if not disk.is_file():
        finish(6, f"{disk} is not a disk image", report, output)
    if not other.is_file():
        finish(6, f"{other} is not a kernel image", report, output)
    for tool in ("mcopy", "b2sum"):
        if not shutil.which(tool):
            finish(6, f"{tool} required for the rollback contract", report, output)
    qemu = shutil.which(options.qemu)
    if not qemu:
        finish(6, f"{options.qemu} not installed", report, output)

    work = Path(tempfile.mkdtemp(prefix="holy-rollback-")).resolve()
    # the disk is copied and booted with snapshot=on, so a trial writes to a throwaway
    # layer and the bytes the build produced are never touched
    image = work / "rollback.raw"
    shutil.copyfile(disk, image)
    os.chmod(image, 0o644)

    read_esp(image, "limine.conf", work / "limine.conf")
    config = (work / "limine.conf").read_text()
    installed = re.search(r"(?m)^\s*kernel_path:.*-a#([0-9a-f]+)$", config)
    if not installed:
        finish(4, "the disk carries no two-slot limine.conf", report, output)
    installed_digest = installed.group(1)
    other_digest = digest(other)
    report["installed_slot"] = "a"
    report["installed_kernel_blake2b"] = installed_digest
    report["replacement_kernel_blake2b"] = other_digest
    report["replacement_source"] = str(other)

    # 1. the current slot stops matching the digest its entry carries. limine warns and
    #    waits; a key that is not Y returns to the menu, and the other slot boots.
    read_esp(image, "vmlinuz-a", work / "vmlinuz-a")
    pristine = (work / "vmlinuz-a").read_bytes()
    broken = bytearray(pristine)
    broken[0x1000:0x1040] = b"\x00" * 64
    (work / "vmlinuz-a").write_bytes(bytes(broken))
    write_esp(image, "vmlinuz-a", work / "vmlinuz-a")
    transcript = drive(qemu, image, str(work / "serial1"), options.seconds,
                       steps=[(0, "does not match", ["n", (DOWN + ENTER, 2.0)],
                              options.seconds)])
    warned = "does not match" in transcript
    refused = warned and "Press Y to continue" in transcript
    markers = guest_markers(transcript)
    report["boots"].append({"boot": "refused-entry", "warned": warned, "waited": refused,
                            "kernel": markers["kernel"], "passed": markers["passed"],
                            "serial": transcript[-1500:]})
    if not refused:
        finish(4, "limine neither warned nor waited for a key on a digest mismatch:\n"
             + transcript[-800:], report, output)
    if not markers["booted"] or not markers["passed"]:
        finish(4, "the previous slot did not boot the guest with its probes passing:\n"
             + transcript[-800:], report, output)
    if markers["kernel"] != "7.2.7":
        report["boots"][-1]["installed_release"] = markers["kernel"]

    # 2. the current slot now carries a kernel that boots and fails a probe. the guest
    #    reports the failure, dinit asks what to do, and the previous slot is chosen from
    #    the menu the reboot brings up. the trial starts from a fresh copy of the disk, so
    #    the second contract does not inherit the first one's guest state.
    shutil.copyfile(disk, image)
    os.chmod(image, 0o644)
    (work / "vmlinuz-a").write_bytes(pristine)
    shutil.copyfile(other, work / "vmlinuz-b")
    write_esp(image, "vmlinuz-a", work / "vmlinuz-a")
    write_esp(image, "vmlinuz-b", other)
    config = set_default(config, "b")
    # slot a is restored whole, so its digest is the one the build recorded
    config = set_slot_digest(config, "a", "kernel_path", installed_digest)
    config = set_slot_digest(config, "b", "kernel_path", other_digest)
    (work / "limine.conf").write_text(config)
    write_esp(image, "limine.conf", work / "limine.conf")
    report["boots"].append({"boot": "setup", "default": "Holy b",
                            "slot_a_kernel_blake2b": installed_digest,
                            "slot_b_kernel_blake2b": other_digest})

    transcript = drive(qemu, image, str(work / "serial2"), options.seconds, reboot=True,
                       steps=[(0, "All services have stopped", ["r", (UP + ENTER, 8.0)],
                              options.seconds)])
    failed_boot = guest_markers(transcript)
    report["boots"].append({"boot": "failing-kernel", "kernel": failed_boot["kernel"],
                            "kernels": failed_boot["kernels"],
                            "failed": failed_boot["failed"], "passed": failed_boot["passed"],
                            "serial": transcript[-1500:]})
    if not failed_boot["booted"]:
        finish(4, "the replacement kernel did not start the guest:\n" + transcript[-800:],
               report, output)
    if not failed_boot["failed"]:
        finish(4, "the replacement kernel passed the probes, so nothing was rolled back:\n"
             + transcript[-800:], report, output)
    # 3. one machine, three turns: the replacement kernel boots and fails, the operator
    #    reboots from dinit's prompt, the loader's menu comes up on the failing slot, and
    #    the arrow moves the highlight to the previous one before enter boots it. the
    #    guest writes its witness on the failing first boot and checks it on the rolled
    #    back second one, so the two are the same contract rather than two separate runs.
    shutil.copyfile(disk, image)
    os.chmod(image, 0o644)
    (work / "vmlinuz-a").write_bytes(pristine)
    write_esp(image, "vmlinuz-a", work / "vmlinuz-a")
    write_esp(image, "vmlinuz-b", other)
    # limine repaints the whole menu on every countdown tick and drops keys that arrive in
    # the middle of a repaint, so the arrow goes out once the countdown is on the line and
    # the enter only once the comment names the slot the arrow selected. the comment is
    # what the loader prints under the menu for the entry the highlight sits on.
    transcript = drive(qemu, image, str(work / "serial3"), options.seconds, reboot=True,
                       steps=[(0, "All services have stopped", ["r"], 25),
                              (0, "Booting automatically in", [UP], 20),
                              (0, "slot a", [ENTER], options.seconds)])
    rolled = guest_markers(transcript)
    report["boots"].append({"boot": "rolled-back", "kernel": rolled["kernel"],
                            "kernels": rolled["kernels"], "passed": rolled["passed"],
                            "serial": transcript[-1500:]})
    if not rolled["booted"] or not rolled["passed"]:
        finish(4, "the previous slot did not answer after the failing kernel:\n"
             + transcript[-800:], report, output)
    if not rolled["kernel"]:
        finish(4, "the rolled back boot named no kernel release, so nothing says which "
                  "slot answered:\n" + transcript[-800:], report, output)
    report["boots"][-1]["rolled_back_release"] = rolled["kernel"]

    shutil.rmtree(work, ignore_errors=True)
    finish(0, "a mismatched slot is refused and a failing kernel is rolled back to the "
              "previous slot, which boots with its probes passing", report, output)


if __name__ == "__main__":
    main()