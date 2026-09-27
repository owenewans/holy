#!/usr/bin/env python3
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time


def digest(path):
    checksum = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            checksum.update(block)
    return checksum.hexdigest()


def error(message, status):
    print('holy-qemu: ' + message, file=sys.stderr)
    raise SystemExit(status)


def accelerator():
    choice = os.environ.get('QEMU_ACCEL', 'auto')
    if choice not in ('auto', 'kvm', 'tcg'):
        error('QEMU_ACCEL must be auto, kvm or tcg', 2)
    if choice == 'tcg':
        return choice
    try:
        fd = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC)
        try:
            available = fcntl.ioctl(fd, 0xAE00) == 12
        finally:
            os.close(fd)
    except OSError:
        available = False
    if available:
        return 'kvm'
    if choice == 'kvm':
        error('KVM unavailable', 6)
    return 'tcg'


def quit_qemu(path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(2)
        channel.connect(str(path))
        with channel.makefile('rwb') as stream:
            if 'QMP' not in json.loads(stream.readline()):
                raise ValueError('missing QMP greeting')
            for command in ('qmp_capabilities', 'quit'):
                stream.write(json.dumps({'execute': command}).encode() + b'\n')
                stream.flush()
                while True:
                    reply = json.loads(stream.readline())
                    if 'error' in reply:
                        raise ValueError(str(reply['error']))
                    if 'return' in reply:
                        break


def main():
    arch = os.environ.get('ARCH', '')
    if arch not in ('i686', 'x86_64'):
        error('ARCH must be i686 or x86_64', 2)
    qemu = shutil.which('qemu-system-' + ('i386' if arch == 'i686' else arch))
    iso = Path(os.environ.get('ISO', ''))
    if not qemu or not iso.is_file():
        error('QEMU and readable ISO required', 6)
    plan = os.environ.get('BOOT_PLAN', '')
    if len(plan) != 64 or any(c not in '0123456789abcdef' for c in plan):
        error('BOOT_PLAN must be SHA-256', 2)
    limit = os.environ.get('QEMU_TIMEOUT', '120')
    if not limit.isascii() or not limit.isdecimal() or not 1 <= int(limit) <= 600:
        error('QEMU_TIMEOUT must be 1..600 seconds', 2)
    firmware = os.environ.get('FIRMWARE', 'bios')
    if firmware not in ('bios', 'uefi'):
        error('FIRMWARE must be bios or uefi', 2)
    firmware_files = {}
    if firmware == 'uefi':
        for field in ('UEFI_CODE', 'UEFI_VARS'):
            path = Path(os.environ.get(field, ''))
            if not path.is_file():
                error(field + ' must name a firmware file', 6)
            firmware_files[field] = path
    accel = accelerator()
    report_dir = Path(os.environ.get('REPORT_DIR', tempfile.gettempdir()))
    if not report_dir.is_dir():
        error('missing report directory', 6)
    run = Path(tempfile.mkdtemp(prefix='holy-qemu-' + arch + '-', dir=report_dir)).resolve()
    inputs = {'iso': {'source': str(iso.resolve())}}
    shutil.copyfile(iso, run / 'input.iso')
    os.chmod(run / 'input.iso', 0o444)
    inputs['iso']['sha256'] = digest(run / 'input.iso')
    for field in ('KERNEL_IMAGE', 'INITRAMFS', 'ROOT_IMAGE'):
        if field in os.environ:
            path = Path(os.environ[field])
            inputs[field.lower()] = {'source': str(path.resolve()), 'sha256': digest(path)}
    args = [qemu, '-accel', accel, '-m', '1024', '-display', 'none', '-monitor', 'none',
            '-net', 'none', '-no-reboot', '-boot', 'd', '-cdrom', str(run / 'input.iso'),
            '-serial', 'file:' + str(run / 'serial.log')]
    for field, path in firmware_files.items():
        dest = run / (field.lower() + '.fd')
        shutil.copyfile(path, dest)
        inputs[field.lower()] = {'source': str(path.resolve()), 'sha256': digest(dest)}
        args += ['-drive', 'if=pflash,format=raw,' +
                 ('readonly=on,' if field == 'UEFI_CODE' else '') + 'file=' + str(dest)]
    expected = {f'HOLY-BOOT-1 plan {plan}', f'HOLY-BOOT-1 arch {arch}', 'HOLY-BOOT-1 pid1 dinit',
                'HOLY-BOOT-1 shell busybox', 'HOLY-BOOT-1 pkg holypkg',
                'HOLY-BOOT-1 static-core verified',
                'HOLY-BOOT-1 device mdevd-coldplug',
                'HOLY-BOOT-1 transaction install-check-remove', 'HOLY-BOOT-1 result pass'}
    if 'KERNEL_VERSION' in os.environ:
        expected.add('HOLY-BOOT-1 kernel ' + os.environ['KERNEL_VERSION'])
    cancelled = []

    def request_stop(number, frame):
        if not cancelled:
            cancelled.append(number)

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    started = time.monotonic()
    reason = 'boot-timeout'
    result = 'fail'
    seen = set()
    with tempfile.TemporaryDirectory(prefix='holy-qmp-') as control:
        qmp = Path(control) / 'control'
        args += ['-qmp', 'unix:' + str(qmp) + ',server=on,wait=off']
        with open(run / 'qemu.stdout', 'wb') as stdout, open(run / 'qemu.stderr', 'wb') as stderr:
            process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
            try:
                while time.monotonic() - started < int(limit):
                    if cancelled:
                        reason = 'cancelled'
                        break
                    serial = run / 'serial.log'
                    if serial.exists():
                        complete = serial.read_text(errors='replace').rsplit('\n', 1)[0]
                        seen = set(complete.splitlines())
                    if 'HOLY-BOOT-1 result fail' in seen:
                        reason = 'guest-failure'
                        break
                    if expected <= seen:
                        reason = 'probes-complete'
                        break
                    if process.poll() is not None:
                        reason = 'early-exit'
                        break
                    time.sleep(0.1)
                if process.poll() is None:
                    try:
                        quit_qemu(qmp)
                    except (OSError, ValueError) as exc:
                        reason = 'qmp-failure: ' + str(exc)
                        process.terminate()
                try:
                    code = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    reason = 'shutdown-timeout'
                    process.kill()
                    code = process.wait()
                if reason == 'probes-complete' and code == 0:
                    result = 'pass'
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
    report = {'schema': 'holy-qemu-report-2', 'arch': arch, 'accelerator': accel,
              'firmware': firmware, 'network': 'disabled', 'plan': plan, 'inputs': inputs,
              'argv': args, 'pid': process.pid, 'exit': code,
              'cancel_signal': cancelled[0] if cancelled else None,
              'elapsed_seconds': time.monotonic() - started,
              'boot_timeout_seconds': int(limit), 'shutdown_timeout_seconds': 5,
              'reason': reason, 'result': result, 'missing_markers': sorted(expected - seen),
              'checks': {marker: 'pass' if marker in seen else 'unknown' for marker in sorted(expected)},
              'not_tested': ['libc-recovery', 'installer', 'hardware', 'network', 'kernel-update']}
    (run / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    (run / 'report').write_text(
        f'format holy-qemu-report-2\narch {arch}\niso-sha256 {inputs["iso"]["sha256"]}\n'
        f'plan {plan}\naccelerator {accel}\nfirmware {firmware}\nexit {code}\n'
        f'reason {reason}\nresult {result}\n')
    print(f'holy-qemu: {result} report {run}/report')
    return 0 if result == 'pass' else 4


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError) as exc:
        error(str(exc), 1)
