#!/usr/bin/env python3
"""Validate retained evidence for the x86_64 disk recovery matrix."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

from qemu import boot_frames


def sha256(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def inspect(path):
    report = json.loads(path.read_text())
    state = report['libc_boot_state']
    firmware = report['firmware']
    if state not in ('present', 'glibc', 'musl', 'both') or firmware not in ('bios', 'uefi'):
        raise ValueError(f'{path}: unsupported matrix case')
    required = {'schema': 'holy-qemu-report-2', 'arch': 'x86_64',
                'profile': 'dual-libc', 'root_storage': 'ext4-overlay',
                'network': 'disabled', 'result': 'pass', 'reason': 'probes-complete', 'exit': 0}
    if any(report.get(key) != value for key, value in required.items()):
        raise ValueError(f'{path}: incomplete disk recovery run')
    if report['missing_markers'] or report.get('cancel_signal'):
        raise ValueError(f'{path}: missing markers or cancelled run')
    serial = path.parent / 'serial.log'
    lines = serial.read_text(errors='replace').splitlines()
    frames, valid = boot_frames(lines, True)
    if not valid or len(frames) != 2 or 'HOLY-BOOT-1 result fail' in lines:
        raise ValueError(f'{path}: invalid serial boot sequence')
    common = {'root ext4', 'arch x86_64', 'pid1 dinit', 'shell busybox',
              'pkg holypkg', 'static-core verified', 'device mdevd-coldplug',
              'transaction install-check-remove', 'libc-probes glibc-musl-pipe',
              'profile dual-libc', 'plan ' + report['plan']}
    first = common | {'boot 1', 'libc-initial ' + state, 'libc-recovery ' + state,
                      'first-boot pass', 'reboot requested'}
    for abi in ('glibc', 'musl'):
        if state in (abi, 'both'):
            first |= {'missing-libc ' + abi, 'restored-libc ' + abi}
    second = common | {'boot 2', 'libc-initial restored', 'libc-recovery restored', 'result pass'}
    boots = report['boots']
    if len(boots) != 2:
        raise ValueError(f'{path}: incomplete per-boot report')
    for number, (wanted, actual, boot) in enumerate(zip((first, second), frames, boots), 1):
        markers = {'HOLY-BOOT-1 ' + marker for marker in wanted}
        if not markers <= actual or boot['boot'] != number or boot['missing_markers'] or any(
                boot['checks'].get(marker) != 'pass' for marker in markers):
            raise ValueError(f'{path}: incomplete evidence for boot {number}')
    inputs = report['inputs']
    snapshots = {'iso': 'input.iso', 'root_disk': 'root.raw'}
    if firmware == 'uefi':
        snapshots['uefi_code'] = 'uefi_code.fd'
    for key, name in snapshots.items():
        if sha256(path.parent / name) != inputs[key]['sha256']:
            raise ValueError(f'{path}: changed {key} snapshot')
    if sha256(path.parent / 'root.qcow2') != report['overlay']['sha256']:
        raise ValueError(f'{path}: changed recovery overlay')
    return {'state': state, 'firmware': firmware, 'report': str(path.resolve()),
            'report_sha256': sha256(path), 'serial_sha256': sha256(serial),
            'iso_sha256': inputs['iso']['sha256'], 'root_sha256': inputs['root_disk']['sha256'],
            'plan': report['plan'], 'accelerator': report['accelerator'],
            'elapsed_seconds': report['elapsed_seconds'], 'result': 'pass'}


def matrix(paths):
    cases = {}
    for path in paths:
        case = inspect(path)
        key = case['state'], case['firmware']
        if key in cases:
            raise ValueError(f'duplicate matrix case: {key}')
        cases[key] = case
    expected = {(state, firmware) for state in ('present', 'glibc', 'musl', 'both')
                for firmware in ('bios', 'uefi')}
    if cases.keys() != expected:
        raise ValueError(f'missing matrix cases: {sorted(expected - cases.keys())}')
    for state in ('present', 'glibc', 'musl', 'both'):
        left, right = cases[state, 'bios'], cases[state, 'uefi']
        if any(left[key] != right[key] for key in ('plan', 'iso_sha256', 'root_sha256')):
            raise ValueError(f'{state}: BIOS and UEFI used different image inputs')
    return {'schema': 'holy-recovery-matrix-1', 'result': 'pass', 'arch': 'x86_64',
            'cases': [cases[key] for key in sorted(cases)], 'boots': 16,
            'not_tested': ['i686', 'installer', 'network-recovery', 'hardware',
                           'kernel-update', 'forced-package-removal']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('reports', nargs='+', type=Path)
    args = parser.parse_args()
    try:
        result = matrix(args.reports)
        with args.output.open('x') as stream:
            json.dump(result, stream, indent=2)
            stream.write('\n')
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f'holy-recovery-matrix: {error}', file=sys.stderr)
        return 4
    print(f'holy-recovery-matrix: 8 cases, 16 boots passed; {args.output}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
