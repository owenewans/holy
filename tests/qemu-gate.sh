#!/bin/sh
set -eu
export QEMU_ACCEL=tcg
export FIRMWARE=bios
unset KERNEL_IMAGE INITRAMFS ROOT_IMAGE ROOT_DISK KERNEL_VERSION

python3 - <<'PY'
import importlib.util
spec = importlib.util.spec_from_file_location('holy_qemu', 'tests/qemu.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
frames, valid = runner.boot_frames([
    'HOLY-BOOT-1 boot 1', 'identity', 'recovered',
    'HOLY-BOOT-1 boot 2', 'recovered'], True)
assert valid and {'identity', 'recovered'} <= frames[0]
assert not {'identity', 'recovered'} <= frames[1]
for lines in (['HOLY-BOOT-1 boot 2'], ['HOLY-BOOT-1 boot 1', 'HOLY-BOOT-1 boot 1'],
              ['HOLY-BOOT-1 boot 1', 'HOLY-BOOT-1 boot 2', 'HOLY-BOOT-1 boot 3']):
    assert not runner.boot_frames(lines, True)[1]
PY

tmp=$(mktemp -d "${TMPDIR:-/tmp/opencode}/holy-qemu-fixture-XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
plan=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
for arch in i686 x86_64; do
    if ARCH="$arch" ISO="$tmp/missing.iso" BOOT_PLAN="$plan" \
       REPORT_DIR="$tmp" sh tests/qemu.sh > "$tmp/out" 2> "$tmp/err"; then
        exit 1
    else
        test "$?" -eq 6
    fi
done
truncate -s 1048576 "$tmp/blank.iso"
for arch in i686 x86_64; do
    if ARCH="$arch" ISO="$tmp/blank.iso" BOOT_PLAN="$plan" \
       QEMU_TIMEOUT=2 REPORT_DIR="$tmp" sh tests/qemu.sh \
       > "$tmp/out" 2> "$tmp/err"; then
        exit 1
    else
        test "$?" -eq 4
    fi
    report=$(sed -n 's/^holy-qemu: fail report //p' "$tmp/out")
    test -f "$report"
    grep -qx 'result fail' "$report"
    grep -qx "arch $arch" "$report"
    grep -qx 'firmware bios' "$report"
    grep -qx 'accelerator tcg' "$report"
    python3 - "$report.json" "$tmp/blank.iso" <<'PY'
import hashlib, json, pathlib, sys
report = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert report['result'] == 'fail'
assert report['reason'] == 'boot-timeout'
assert report['network'] == 'disabled'
assert report['missing_markers']
assert set(report['checks'].values()) == {'unknown'}
assert report['inputs']['iso']['sha256'] == hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest()
PY
done
ARCH=x86_64 ISO="$tmp/blank.iso" BOOT_PLAN="$plan" REPORT_DIR="$tmp" \
    python3 - <<'PY'
import json, os, pathlib, signal, subprocess, time
p = subprocess.Popen(['sh', 'tests/qemu.sh'], stdout=subprocess.PIPE, text=True)
try:
    children = pathlib.Path(f'/proc/{p.pid}/task/{p.pid}/children')
    deadline = time.monotonic() + 10
    while not children.read_text().strip():
        assert p.poll() is None and time.monotonic() < deadline
        time.sleep(0.05)
    p.send_signal(signal.SIGTERM)
    output, _ = p.communicate(timeout=10)
    assert p.returncode == 4, output
    report_path = output.strip().split(' report ', 1)[1]
    report = json.loads(pathlib.Path(report_path + '.json').read_text())
    assert report['result'] == 'fail' and report['reason'] == 'cancelled'
    assert report['cancel_signal'] == signal.SIGTERM
    assert not pathlib.Path(f'/proc/{report["pid"]}').exists()
finally:
    if p.poll() is None:
        p.terminate()
        p.wait(timeout=10)
PY
printf 'qemu negative gate fixtures passed\n'
