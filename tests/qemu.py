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


def boot_frames(lines, disk):
    if not disk:
        return [set(lines)], True
    frames = []
    for line in lines:
        if line.startswith('HOLY-BOOT-1 boot '):
            if len(frames) == 2 or line != f'HOLY-BOOT-1 boot {len(frames) + 1}':
                return frames, False
            frames.append(set())
        if frames:
            frames[-1].add(line)
    return frames, True


def main():
    arch = os.environ.get('ARCH', '')
    if arch not in ('i686', 'x86_64'):
        error('ARCH must be i686 or x86_64', 2)
    qemu = shutil.which('qemu-system-' + ('i386' if arch == 'i686' else arch))
    media = os.environ.get('BOOT_MEDIA', 'iso')
    if media not in ('iso', 'disk'):
        error('BOOT_MEDIA must be iso or disk', 2)
    iso = Path(os.environ.get('ISO', ''))
    if not qemu or (media == 'iso' and not iso.is_file()):
        error('QEMU and selected readable boot input required', 6)
    if media == 'disk' and os.environ.get('ISO'):
        error('disk boot must not provide an ISO', 2)
    plan = os.environ.get('BOOT_PLAN', '')
    if len(plan) != 64 or any(c not in '0123456789abcdef' for c in plan):
        error('BOOT_PLAN must be SHA-256', 2)
    limit = os.environ.get('QEMU_TIMEOUT', '120')
    if not limit.isascii() or not limit.isdecimal() or not 1 <= int(limit) <= 600:
        error('QEMU_TIMEOUT must be 1..600 seconds', 2)
    firmware = os.environ.get('FIRMWARE', 'bios')
    if firmware not in ('bios', 'uefi'):
        error('FIRMWARE must be bios or uefi', 2)
    profile = os.environ.get('IMAGE_PROFILE', 'dual-libc')
    state = os.environ.get('LIBC_BOOT_STATE', 'present')
    if profile not in ('static-core', 'dual-libc') or state not in ('present', 'glibc', 'musl', 'both'):
        error('unsupported image profile or libc boot state', 2)
    if profile == 'static-core' and state != 'present':
        error('libc boot state requires dual-libc profile', 2)
    disk_path = os.environ.get('ROOT_DISK', '')
    if media == 'disk' and not disk_path:
        error('disk boot requires ROOT_DISK', 6)
    qemu_img = shutil.which('qemu-img')
    if disk_path and (profile != 'dual-libc' or not Path(disk_path).is_file() or not qemu_img):
        error('disk recovery requires dual-libc, a regular raw ROOT_DISK and qemu-img', 6)
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
    inputs = {}
    if media == 'iso':
        inputs['iso'] = {'source': str(iso.resolve())}
        shutil.copyfile(iso, run / 'input.iso')
        os.chmod(run / 'input.iso', 0o444)
        inputs['iso']['sha256'] = digest(run / 'input.iso')
    if disk_path:
        base = run / 'root.raw'
        shutil.copyfile(disk_path, base)
        os.chmod(base, 0o444)
        inputs['root_disk'] = {'source': str(Path(disk_path).resolve()), 'sha256': digest(base), 'format': 'raw'}
        subprocess.run([qemu_img, 'create', '-q', '-f', 'qcow2', '-F', 'raw', '-b',
                        str(base), str(run / 'root.qcow2')], check=True)
    for field in ('KERNEL_IMAGE', 'INITRAMFS', 'ROOT_IMAGE'):
        if field in os.environ:
            path = Path(os.environ[field])
            inputs[field.lower()] = {'source': str(path.resolve()), 'sha256': digest(path)}
    args = [qemu, '-accel', accel, '-m', '1024', '-display', 'none', '-monitor', 'none',
            '-net', 'none', '-boot', 'c' if media == 'disk' else 'd',
            '-serial', 'file:' + str(run / 'serial.log')]
    if media == 'iso':
        args += ['-cdrom', str(run / 'input.iso')]
    if disk_path:
        args += ['-blockdev', json.dumps({'driver': 'qcow2', 'node-name': 'holy-root',
                 'file': {'driver': 'file', 'filename': str(run / 'root.qcow2')}}),
                 '-device', 'virtio-blk-pci,drive=holy-root' + (',bootindex=1' if media == 'disk' else '')]
    else:
        args += ['-no-reboot']
    for field, path in firmware_files.items():
        dest = run / (field.lower() + '.fd')
        shutil.copyfile(path, dest)
        inputs[field.lower()] = {'source': str(path.resolve()), 'sha256': digest(dest)}
        args += ['-drive', 'if=pflash,format=raw,' +
                 ('readonly=on,' if field == 'UEFI_CODE' else '') + 'file=' + str(dest)]
    expected = {f'HOLY-BOOT-1 plan {plan}', f'HOLY-BOOT-1 arch {arch}', 'HOLY-BOOT-1 pid1 dinit',
                'HOLY-BOOT-1 shell busybox', 'HOLY-BOOT-1 pkg holypkg',
                 'HOLY-BOOT-1 static-core verified', 'HOLY-BOOT-1 docs installed-man-bundle',
                'HOLY-BOOT-1 device mdevd-coldplug',
                'HOLY-BOOT-1 transaction install-check-remove', 'HOLY-BOOT-1 result pass'}
    if profile == 'dual-libc':
        expected.update({f'HOLY-BOOT-1 profile {profile}', f'HOLY-BOOT-1 libc-initial {state}',
                         f'HOLY-BOOT-1 libc-recovery {state}', 'HOLY-BOOT-1 libc-probes glibc-musl-pipe'})
        for abi in ('glibc', 'musl'):
            if state in (abi, 'both'):
                expected.update({f'HOLY-BOOT-1 missing-libc {abi}', f'HOLY-BOOT-1 restored-libc {abi}'})
    if 'KERNEL_VERSION' in os.environ:
        expected.add('HOLY-BOOT-1 kernel ' + os.environ['KERNEL_VERSION'])
    if media == 'disk':
        expected.add('HOLY-BOOT-1 esp mounted-writable')
    expected_boots = [expected]
    if disk_path:
        first = expected - {'HOLY-BOOT-1 result pass'}
        first.update({'HOLY-BOOT-1 boot 1', 'HOLY-BOOT-1 root ext4',
                      'HOLY-BOOT-1 first-boot pass', 'HOLY-BOOT-1 reboot requested'})
        second = {marker for marker in expected if not marker.startswith((
            'HOLY-BOOT-1 libc-initial ', 'HOLY-BOOT-1 libc-recovery ',
            'HOLY-BOOT-1 missing-libc ', 'HOLY-BOOT-1 restored-libc '))}
        second.update({'HOLY-BOOT-1 boot 2', 'HOLY-BOOT-1 root ext4',
                       'HOLY-BOOT-1 libc-initial restored', 'HOLY-BOOT-1 libc-recovery restored'})
        expected_boots = [first, second]
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
    frames = []
    first_completed = None
    deadline = started + int(limit)
    with tempfile.TemporaryDirectory(prefix='holy-qmp-') as control:
        qmp = Path(control) / 'control'
        args += ['-qmp', 'unix:' + str(qmp) + ',server=on,wait=off']
        with open(run / 'qemu.stdout', 'wb') as stdout, open(run / 'qemu.stderr', 'wb') as stderr:
            process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
            try:
                while time.monotonic() < deadline:
                    if cancelled:
                        reason = 'cancelled'
                        break
                    serial = run / 'serial.log'
                    if serial.exists():
                        complete = serial.read_text(errors='replace').rsplit('\n', 1)[0]
                        seen = set(complete.splitlines())
                        frames, valid = boot_frames(complete.splitlines(), bool(disk_path))
                        if not valid:
                            reason = 'invalid-boot-sequence'
                            break
                    if 'HOLY-BOOT-1 result fail' in seen:
                        reason = 'guest-failure'
                        break
                    if disk_path and first_completed is None and frames and expected_boots[0] <= frames[0]:
                        first_completed = time.monotonic() - started
                        deadline = time.monotonic() + int(limit)
                        reason = 'reboot-timeout'
                    if len(frames) == len(expected_boots) and all(
                            wanted <= actual for wanted, actual in zip(expected_boots, frames)):
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
    base_unchanged = not disk_path or digest(run / 'root.raw') == inputs['root_disk']['sha256']
    if not base_unchanged:
        reason, result = 'changed-read-only-base', 'fail'
    boots = []
    for index, wanted in enumerate(expected_boots):
        actual = frames[index] if index < len(frames) else set()
        boots.append({'boot': index + 1, 'missing_markers': sorted(wanted - actual),
                      'checks': {marker: 'pass' if marker in actual else 'unknown' for marker in sorted(wanted)}})
    report = {'schema': 'holy-qemu-report-2', 'arch': arch, 'accelerator': accel,
              'firmware': firmware, 'profile': profile, 'libc_boot_state': state,
              'network': 'disabled', 'plan': plan, 'inputs': inputs,
              'argv': args, 'pid': process.pid, 'exit': code,
              'cancel_signal': cancelled[0] if cancelled else None,
              'elapsed_seconds': time.monotonic() - started,
              'boot_timeout_seconds': int(limit), 'shutdown_timeout_seconds': 5,
              'root_storage': 'ext4-overlay' if disk_path else 'ram', 'boots': boots,
              'boot_media': media,
              'first_boot_completed_seconds': first_completed,
              'reason': reason, 'result': result,
              'missing_markers': ([f'boot-{b["boot"]}: {marker}' for b in boots for marker in b['missing_markers']]
                                  if disk_path else sorted(expected - seen)),
              'checks': {marker: 'pass' if marker in seen else 'unknown' for marker in sorted(expected)},
              'not_tested': (['libc-recovery'] if profile != 'dual-libc' or state == 'present' else []) +
                            ([] if disk_path else ['libc-recovery-reboot']) +
                            (['i686-libc'] if arch != 'i686' or profile != 'dual-libc' else []) +
                            ['installer', 'hardware', 'network', 'kernel-update']}
    if disk_path:
        report['overlay'] = {'path': str(run / 'root.qcow2'), 'sha256': digest(run / 'root.qcow2'),
                             'base_unchanged': base_unchanged}
    (run / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    (run / 'report').write_text(
        f'format holy-qemu-report-2\narch {arch}\nboot-media {media}\niso-sha256 {inputs.get("iso", {}).get("sha256", "none")}\n'
        f'plan {plan}\naccelerator {accel}\nfirmware {firmware}\nexit {code}\n'
        f'reason {reason}\nresult {result}\n')
    print(f'holy-qemu: {result} report {run}/report')
    return 0 if result == 'pass' else 4


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        error(str(exc), 1)
