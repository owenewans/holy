#!/usr/bin/env python3
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

from qemu import accelerator, digest, quit_qemu


def require(condition, message, status=6):
    if not condition:
        print('holy-install-vm: ' + message, file=sys.stderr)
        raise SystemExit(status)


def command(*args):
    subprocess.run(args, check=True)


def boot(qemu, accel, run, overlay, iso, stage, expected, seconds,
         firmware=None):
    serial = run / (stage + '.serial.log')
    qmp = run / (stage + '.qmp')
    args = [qemu, '-accel', accel, '-m', '1024', '-display', 'none',
            '-monitor', 'none', '-net', 'none', '-boot', 'd' if iso else 'c',
            '-serial', 'file:' + str(serial)]
    if iso:
        args.extend(['-cdrom', str(iso)])
    if firmware:
        code, variables = firmware
        args.extend(['-drive', 'if=pflash,format=raw,readonly=on,file=' + str(code),
                     '-drive', 'if=pflash,format=raw,file=' + str(variables)])
    args.extend(['-blockdev', json.dumps({'driver': 'qcow2', 'node-name': 'holy-target',
                 'file': {'driver': 'file', 'filename': str(overlay)}}),
                 '-device', 'virtio-blk-pci,drive=holy-target,serial=HOLY-INSTALL-VM-1' +
                            ('' if iso else ',bootindex=1'),
                 '-qmp', 'unix:' + str(qmp) + ',server=on,wait=off'])
    started = time.monotonic()
    reason = 'timeout'
    lines = set()
    with (run / (stage + '.stdout')).open('wb') as stdout, \
            (run / (stage + '.stderr')).open('wb') as stderr:
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL,
                                   stdout=stdout, stderr=stderr)
        try:
            while time.monotonic() - started < seconds:
                if serial.exists():
                    data = serial.read_text(errors='replace')
                    lines = set(data.rsplit('\n', 1)[0].splitlines())
                    if any(line.endswith('result fail') for line in lines):
                        reason = 'guest-failure'
                        break
                    if expected <= lines:
                        reason = 'markers-complete'
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
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    return {'result': 'pass' if reason == 'markers-complete' and code == 0 else 'fail',
            'reason': reason, 'exit': code, 'elapsed_seconds': time.monotonic() - started,
            'argv': args, 'serial': str(serial), 'serial_sha256': digest(serial),
            'missing_markers': sorted(expected - lines)}


def main():
    require(os.environ.get('ARCH') == 'x86_64', 'x86_64 target required', 2)
    iso = Path(os.environ.get('ISO', ''))
    report_dir = Path(os.environ.get('REPORT_DIR', ''))
    plan = os.environ.get('BOOT_PLAN', '')
    require(iso.is_file() and report_dir.is_dir(),
            'ISO and report directory required')
    require(len(plan) == 64 and all(c in '0123456789abcdef' for c in plan),
            'BOOT_PLAN must be SHA-256', 2)
    qemu = shutil.which('qemu-system-x86_64')
    qemu_img = shutil.which('qemu-img')
    require(qemu and qemu_img, 'QEMU and qemu-img required')
    firmware = os.environ.get('INSTALL_FIRMWARE', 'both')
    require(firmware in ('bios', 'both'), 'INSTALL_FIRMWARE must be bios or both', 2)
    code = Path(os.environ.get('UEFI_CODE') or '/usr/share/qemu/edk2-x86_64-code.fd')
    variables = Path(os.environ.get('UEFI_VARS') or '/usr/share/qemu/edk2-i386-vars.fd')
    if firmware == 'both':
        require(code.is_file() and variables.is_file(),
                'UEFI_CODE and UEFI_VARS firmware files required')
    accel = accelerator()
    run = Path(tempfile.mkdtemp(prefix='holy-install-vm-', dir=report_dir)).resolve()
    frozen_iso = run / 'input.iso'
    shutil.copyfile(iso, frozen_iso)
    frozen_iso.chmod(0o444)
    disk = run / 'target.raw'
    with disk.open('wb') as stream:
        stream.truncate(1 << 30)
    base_hash = digest(disk)
    disk.chmod(0o444)
    overlay = run / 'target.qcow2'
    command(qemu_img, 'create', '-q', '-f', 'qcow2', '-F', 'raw', '-b', str(disk), str(overlay))
    expected_install = {
        'HOLY-INSTALL-1 devices target-and-media',
        'HOLY-INSTALL-1 disk prepared',
        'HOLY-INSTALL-1 root mounted',
        'HOLY-INSTALL-1 package-set committed',
        'HOLY-INSTALL-1 account prepared',
        'HOLY-INSTALL-1 esp files-and-package-state',
        'HOLY-INSTALL-1 result pass',
    }
    expected_boot = {
        'HOLY-BOOT-1 installed-disk ext4',
        'HOLY-BOOT-1 user-login authenticated',
        'HOLY-BOOT-1 root ext4',
        'HOLY-BOOT-1 plan ' + plan,
        'HOLY-BOOT-1 pid1 dinit',
        'HOLY-BOOT-1 shell busybox',
        'HOLY-BOOT-1 static-core verified',
        'HOLY-BOOT-1 esp mounted-writable',
        'HOLY-BOOT-1 docs installed-man-bundle',
        'HOLY-BOOT-1 pkg holypkg',
        'HOLY-BOOT-1 transaction install-check-remove',
        'HOLY-BOOT-1 installer root-plan-apply',
        'HOLY-BOOT-1 result pass',
    }
    first = boot(qemu, accel, run, overlay, frozen_iso, 'install', expected_install, 600)
    disk_plans = re.findall(r'^HOLY-INSTALL-1 disk-plan ([0-9a-f]{64})\r?$',
                            Path(first['serial']).read_text(errors='replace'), re.MULTILINE)
    guest_disk_plan = disk_plans[0] if len(disk_plans) == 1 else None
    second = third = None
    if first['result'] == 'pass':
        overlay.chmod(0o444)
        bios_overlay = run / 'bios.qcow2'
        command(qemu_img, 'create', '-q', '-f', 'qcow2', '-F', 'qcow2',
                '-b', str(overlay), str(bios_overlay))
        second = boot(qemu, accel, run, bios_overlay, None,
                      'installed-bios', expected_boot, 180)
        if second['result'] == 'pass' and firmware == 'both':
            code_copy = run / 'uefi-code.fd'
            vars_copy = run / 'uefi-vars.fd'
            shutil.copyfile(code, code_copy)
            code_copy.chmod(0o444)
            shutil.copyfile(variables, vars_copy)
            uefi_overlay = run / 'uefi.qcow2'
            command(qemu_img, 'create', '-q', '-f', 'qcow2', '-F', 'qcow2',
                    '-b', str(overlay), str(uefi_overlay))
            third = boot(qemu, accel, run, uefi_overlay, None,
                         'installed-uefi', expected_boot, 180,
                         (code_copy, vars_copy))
    unchanged = digest(disk) == base_hash
    result = ('pass' if unchanged and guest_disk_plan and second and second['result'] == 'pass' and
              (firmware == 'bios' or third and third['result'] == 'pass') else 'fail')
    report = {'schema': 'holy-install-vm-4', 'result': result, 'arch': 'x86_64',
              'accelerator': accel, 'boot_plan': plan,
              'inputs': {'iso_sha256': digest(frozen_iso), 'target_base_sha256': base_hash,
                         'guest_disk_plan_sha256': guest_disk_plan},
              'base_unchanged': unchanged, 'overlay_sha256': digest(overlay),
              'firmware': {'mode': firmware,
                           'code_sha256': digest(code_copy) if third else None,
                           'vars_input_sha256': digest(variables) if third else None},
              'install': first, 'installed_boot': second, 'uefi_boot': third,
              'coverage': ['live-iso', 'guest-partitioning', 'guest-filesystems',
                           'guest-limine-bios-install', 'guest-root-package-set',
                           'guest-esp-files', 'guest-user-password-login',
                           'bios-installed-disk-boot'] +
                          (['uefi-installed-disk-boot'] if third and third['result'] == 'pass' else []),
              'not_tested': ['i686-installed-boot', 'account-menu', 'doas', 'pam-nss', 'network'] +
                            (['uefi-installed-boot'] if firmware == 'bios' else [])}
    (run / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print('holy-install-vm:', result, 'report', run / 'report.json')
    return 0 if result == 'pass' else 4


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        print('holy-install-vm: ' + str(exc), file=sys.stderr)
        sys.exit(1)
