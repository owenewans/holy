#!/bin/sh
set -eu
export QEMU_ACCEL=tcg
export FIRMWARE=bios
unset KERNEL_IMAGE INITRAMFS ROOT_IMAGE ROOT_DISK BOOT_MEDIA KERNEL_VERSION

python3 - <<'PY'
import importlib.util
import json
import subprocess
import tempfile
from pathlib import Path
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
with tempfile.TemporaryDirectory() as scratch:
    base = Path(scratch) / 'base.qcow2'
    child = Path(scratch) / 'child.qcow2'
    subprocess.run(['qemu-img', 'create', '-q', '-f', 'qcow2', str(base), '8M'], check=True)
    assert runner.disk_format('qemu-img', base) == 'qcow2'
    subprocess.run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'qcow2',
                    '-b', str(base), str(child)], check=True)
    try:
        runner.disk_format('qemu-img', child)
    except SystemExit as exc:
        assert exc.code == 6
    else:
        raise AssertionError('backing chain accepted')
PY

tmp=$(mktemp -d "${TMPDIR:-/tmp/opencode}/holy-qemu-fixture-XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
plan=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
for case_name in missing-disk forbidden-iso; do
    iso=
    expected=6
    if test "$case_name" = forbidden-iso; then iso="$tmp/unused.iso"; expected=2; fi
    if ARCH=x86_64 BOOT_MEDIA=disk ISO="$iso" BOOT_PLAN="$plan" \
       REPORT_DIR="$tmp" sh tests/qemu.sh > "$tmp/out" 2> "$tmp/err"; then
        exit 1
    else
        test "$?" -eq "$expected"
    fi
    case "$case_name" in
        missing-disk) grep -q 'disk boot requires ROOT_DISK' "$tmp/err" ;;
        forbidden-iso) grep -q 'disk boot must not provide an ISO' "$tmp/err" ;;
    esac
done
for arch in i686 x86_64; do
    if ARCH="$arch" ISO="$tmp/missing.iso" BOOT_PLAN="$plan" \
       REPORT_DIR="$tmp" sh tests/qemu.sh > "$tmp/out" 2> "$tmp/err"; then
        exit 1
    else
        test "$?" -eq 6
    fi
done
truncate -s 1048576 "$tmp/blank.iso"
if ARCH=i686 ISO="$tmp/blank.iso" BOOT_PLAN="$plan" REPORT_DIR="$tmp" \
   INSTALL_FIRMWARE=both python3 tests/install-vm.py > "$tmp/out" 2> "$tmp/err"; then
    exit 1
else
    test "$?" -eq 2
fi
grep -q 'i686 supports BIOS' "$tmp/err"
if ARCH=x86_64 ISO="$tmp/blank.iso" BOOT_PLAN="$plan" \
   LIBC_BOOT_STATE=remove-both REPORT_DIR="$tmp" sh tests/qemu.sh \
   > "$tmp/out" 2> "$tmp/err"; then
    exit 1
else
    test "$?" -eq 2
fi
grep -q 'remove-both requires persistent root' "$tmp/err"
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
qemu-img create -q -f qcow2 "$tmp/base.qcow2" 8M
base_hash=$(sha256sum "$tmp/base.qcow2" | cut -d ' ' -f 1)
if ARCH=x86_64 ISO="$tmp/blank.iso" ROOT_DISK="$tmp/base.qcow2" \
   BOOT_PLAN="$plan" REPORT_DIR="$tmp" QEMU_TIMEOUT=2 \
   QEMU_PROBE_TIMEOUT=1 sh tests/qemu.sh > "$tmp/out" 2> "$tmp/err"; then
    exit 1
else
    test "$?" -eq 4
fi
report=$(sed -n 's/^holy-qemu: fail report //p' "$tmp/out")
python3 - "$report.json" "$base_hash" <<'PY'
import json, pathlib, sys
report = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert report['inputs']['root_disk']['format'] == 'qcow2'
assert report['inputs']['root_disk']['sha256'] == sys.argv[2]
assert report['overlay']['base_unchanged']
assert report['overlay']['backing_format'] == 'qcow2'
assert report['probe_timeout_seconds'] == 1
assert report['probes'] == []
PY
test "$(sha256sum "$tmp/base.qcow2" | cut -d ' ' -f 1)" = "$base_hash"
ARCH=x86_64 ISO="$tmp/blank.iso" BOOT_PLAN="$plan" REPORT_DIR="$tmp" \
    QEMU_TIMEOUT=5 QEMU_PROBE_TIMEOUT=1 python3 - <<'PY'
import json, os, pathlib, subprocess, time
parent = pathlib.Path(os.environ['REPORT_DIR'])
existing = set(parent.glob('holy-qemu-x86_64-*'))
runner = subprocess.Popen(['sh', 'tests/qemu.sh'], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)
try:
    deadline = time.monotonic() + 5
    serial = None
    while time.monotonic() < deadline:
        paths = [path / 'serial.log' for path in parent.glob('holy-qemu-x86_64-*')
                 if path not in existing and (path / 'serial.log').exists()]
        if paths:
            serial = paths[0]
            break
        assert runner.poll() is None
        time.sleep(0.02)
    assert serial is not None
    with serial.open('a') as stream:
        stream.write('HOLY-BOOT-1 stage identity\n')
        stream.flush()
        os.fsync(stream.fileno())
    output, stderr = runner.communicate(timeout=10)
    assert runner.returncode == 4, (output, stderr)
    report_path = output.strip().split(' report ', 1)[1]
    report = json.loads(pathlib.Path(report_path + '.json').read_text())
    assert report['reason'] == 'probe-timeout', report['reason']
    assert report['timed_out_probe'] == 'identity'
    assert report['probes'][0]['stage'] == 'identity'
    assert report['probes'][0]['status'] == 'unknown'
finally:
    if runner.poll() is None:
        runner.terminate()
        runner.wait(timeout=10)
PY
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
