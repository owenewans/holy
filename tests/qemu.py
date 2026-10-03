#!/usr/bin/env python3
import fcntl
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
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


def copy_consistency(before, after, copied):
    """how a copied boot input compares with the source it was copied from"""
    if before != after:
        return 'input-changed-during-copy'
    return 'verified' if before == copied else 'copy-mismatch'


def copy_input(source, destination):
    """copies one boot input and records the bytes read on both sides of the copy, so a
    source that changes while it is copied cannot pass as a faithful copy"""
    before = digest(source)
    shutil.copyfile(source, destination)
    after = digest(source)
    copied = digest(destination)
    return {'source_sha256': before, 'source_after_sha256': after, 'sha256': copied,
            'copy_consistency': copy_consistency(before, after, copied)}


def disk_format(qemu_img, path):
    details = json.loads(subprocess.check_output(
        [qemu_img, 'info', '--output=json', str(path)], text=True))
    kind = details.get('format')
    if kind not in ('raw', 'qcow2') or details.get('backing-filename'):
        error('ROOT_DISK must be a self-contained raw or qcow2 image', 6)
    return kind


def main():
    network = os.environ.get('NETWORK_RECOVERY', 'off')
    if network == 'fixture' and os.environ.get('HOLY_QEMU_NETNS') != '1':
        if not shutil.which('unshare') or not shutil.which('ip'):
            error('unshare and ip required for isolated fixture network', 6)
        descriptor, resolver = tempfile.mkstemp(prefix='holy-qemu-resolv-')
        with os.fdopen(descriptor, 'w') as stream:
            stream.write('nameserver 127.0.0.1\n')
        environment = os.environ.copy()
        environment['HOLY_QEMU_NETNS'] = '1'
        environment['HOLY_QEMU_HOST_NETNS'] = str(os.stat('/proc/self/ns/net').st_ino)
        environment['HOLY_QEMU_RESOLV'] = resolver
        os.execvpe('unshare', ['unshare', '--map-root-user', '--net', '--mount',
                              '--propagation', 'private', '--',
                              sys.executable, str(Path(__file__).resolve())], environment)
    namespace_evidence = None
    if network == 'fixture':
        host_namespace = os.environ.get('HOLY_QEMU_HOST_NETNS', '')
        current_namespace = str(os.stat('/proc/self/ns/net').st_ino)
        if not host_namespace or host_namespace == current_namespace:
            error('fixture network namespace was not isolated', 6)
        subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
        resolver = os.environ.get('HOLY_QEMU_RESOLV', '')
        if not resolver or not Path(resolver).is_file():
            error('fixture resolver file missing', 6)
        subprocess.run(['mount', '--bind', resolver, '/etc/resolv.conf'], check=True)
        os.unlink(resolver)
        routes = subprocess.check_output(['ip', '-4', 'route', 'show'], text=True).splitlines()
        if routes:
            error('fixture network namespace has an external route', 6)
        namespace_evidence = {'host_inode': host_namespace, 'fixture_inode': current_namespace,
                              'fixture_routes': routes}
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
    probe_limit = os.environ.get('QEMU_PROBE_TIMEOUT', limit)
    if not probe_limit.isascii() or not probe_limit.isdecimal() or not 1 <= int(probe_limit) <= 600:
        error('QEMU_PROBE_TIMEOUT must be 1..600 seconds', 2)
    firmware = os.environ.get('FIRMWARE', 'bios')
    if firmware not in ('bios', 'uefi'):
        error('FIRMWARE must be bios or uefi', 2)
    profile = os.environ.get('IMAGE_PROFILE', 'dual-libc')
    state = os.environ.get('LIBC_BOOT_STATE', 'present')
    if profile not in ('static-core', 'dual-libc') or state not in ('present', 'glibc', 'musl', 'both', 'remove-both'):
        # the builder records the state in the same vocabulary, so a state it wrote and
        # this runner refuses is a name to settle rather than a value to guess at
        error('unsupported image profile or libc boot state: profile=%s state=%s; '
              'this runner takes profile static-core or dual-libc and state '
              'present, glibc, musl, both or remove-both' % (profile, state), 2)
    if profile == 'static-core' and state != 'present':
        error('libc boot state requires dual-libc profile', 2)
    module_probe = os.environ.get('KERNEL_MODULE_PROBE', 'off')
    if module_probe not in ('on', 'off'):
        error('KERNEL_MODULE_PROBE must be on or off', 2)
    if network not in ('off', 'fixture'):
        error('NETWORK_RECOVERY must be off or fixture', 2)
    if network == 'fixture' and (profile != 'dual-libc' or state != 'both' or media != 'iso'):
        error('network fixture requires dual-libc, both absent and ISO boot', 2)
    disk_path = os.environ.get('ROOT_DISK', '')
    if state == 'remove-both' and (not disk_path or network != 'off'):
        error('remove-both requires persistent root without network fixture', 2)
    if media == 'disk' and not disk_path:
        error('disk boot requires ROOT_DISK', 6)
    qemu_img = shutil.which('qemu-img')
    if disk_path and (profile != 'dual-libc' or not Path(disk_path).is_file() or not qemu_img):
        error('disk recovery requires dual-libc, a regular ROOT_DISK and qemu-img', 6)
    keep_value = os.environ.get('QEMU_KEEP', '0')
    if keep_value not in ('0', '1'):
        error('QEMU_KEEP must be 0 or 1', 2)
    keep = keep_value == '1'
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
        inputs['iso'].update(copy_input(iso, run / 'input.iso'))
        os.chmod(run / 'input.iso', 0o444)
    if disk_path:
        format_name = disk_format(qemu_img, disk_path)
        base = run / ('root-base.' + format_name)
        inputs['root_disk'] = {'source': str(Path(disk_path).resolve()),
                               'format': format_name}
        inputs['root_disk'].update(copy_input(disk_path, base))
        os.chmod(base, 0o444)
        if disk_format(qemu_img, base) != format_name:
            error('copied root disk changed format', 6)
        subprocess.run([qemu_img, 'create', '-q', '-f', 'qcow2', '-F', format_name, '-b',
                        str(base), str(run / 'root.qcow2')], check=True)
    for field in ('KERNEL_IMAGE', 'INITRAMFS', 'ROOT_IMAGE'):
        if field in os.environ:
            path = Path(os.environ[field])
            inputs[field.lower()] = {'source': str(path.resolve()), 'sha256': digest(path)}
    requests = []
    dns_queries = []
    dns_socket = None
    server = None
    network_inputs = {}
    network_args = ['-net', 'none']
    if network == 'fixture':
        dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns_socket.bind(('127.0.0.1', 53))
        dns_socket.settimeout(0.2)
        dns_stopped = threading.Event()

        def serve_dns():
            while not dns_stopped.is_set():
                try:
                    data, peer = dns_socket.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    return
                if len(data) < 17 or struct.unpack('!H', data[4:6])[0] != 1:
                    continue
                cursor, labels = 12, []
                while cursor < len(data) and 0 < data[cursor] <= 63:
                    size = data[cursor]
                    if cursor + size + 1 >= len(data):
                        break
                    labels.append(data[cursor + 1:cursor + size + 1])
                    cursor += size + 1
                if cursor + 5 > len(data) or data[cursor] != 0:
                    continue
                kind, group = struct.unpack('!HH', data[cursor + 1:cursor + 5])
                name = b'.'.join(labels).lower()
                if name != b'fixture.holy.test' or group != 1:
                    continue
                dns_queries.append({'name': name.decode(), 'type': kind})
                question = data[12:cursor + 5]
                answer = b''
                if kind == 1:
                    answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + socket.inet_aton('10.0.2.2')
                response = data[:2] + struct.pack('!HHHHH', 0x8180, 1, bool(answer), 0, 0)
                dns_socket.sendto(response + question + answer, peer)

        dns_thread = threading.Thread(target=serve_dns, daemon=True)
        dns_thread.start()
        source_dir = Path(os.environ.get('NETWORK_DIR', ''))
        for name in ('ca.pem', 'key.pem', 'glibc.holy', 'musl.holy'):
            if not (source_dir / name).is_file():
                error('network fixture missing ' + name, 6)
        network_dir = run / 'network'
        network_dir.mkdir(mode=0o700)
        for name in ('ca.pem', 'key.pem', 'glibc.holy', 'musl.holy'):
            shutil.copyfile(source_dir / name, network_dir / name)
            os.chmod(network_dir / name, 0o600 if name == 'key.pem' else 0o444)
        class Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *arguments, **keywords):
                super().__init__(*arguments, directory=str(network_dir), **keywords)

            def do_GET(self):
                if self.path not in ('/glibc.holy', '/musl.holy'):
                    self.send_error(404)
                    return
                super().do_GET()

            def do_HEAD(self):
                self.send_error(404)

            def log_message(self, *arguments):
                pass

            def send_response(self, code, message=None):
                requests.append({'method': self.command, 'path': self.path, 'status': code})
                return super().send_response(code, message)

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 8443), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(network_dir / 'ca.pem', network_dir / 'key.pem')
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        network_args = ['-netdev', 'user,id=holy-net,ipv6=off',
                        '-device', 'virtio-net-pci,netdev=holy-net']
        network_inputs = {name: digest(network_dir / name)
                          for name in ('ca.pem', 'glibc.holy', 'musl.holy')}
    args = [qemu, '-accel', accel, '-m', '1024', '-display', 'none', '-monitor', 'none',
            *network_args, '-boot', 'c' if media == 'disk' else 'd',
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
                 'HOLY-BOOT-1 static-core verified', 'HOLY-BOOT-1 installer static-cli',
                 'HOLY-BOOT-1 docs installed-man-bundle',
                'HOLY-BOOT-1 device mdevd-coldplug',
                'HOLY-BOOT-1 transaction install-check-remove',
                'HOLY-BOOT-1 installer root-plan-apply', 'HOLY-BOOT-1 result pass'}
    if profile == 'dual-libc':
        expected.update({f'HOLY-BOOT-1 profile {profile}', f'HOLY-BOOT-1 libc-initial {state}',
                         'HOLY-BOOT-1 libc-probes glibc-musl-pipe'})
        if state != 'remove-both':
            expected.add(f'HOLY-BOOT-1 libc-recovery {state}')
        for abi in ('glibc', 'musl'):
            if state in (abi, 'both'):
                expected.update({f'HOLY-BOOT-1 missing-libc {abi}', f'HOLY-BOOT-1 restored-libc {abi}'})
                if network == 'fixture':
                    expected.add(f'HOLY-BOOT-1 downloaded-libc {abi}')
    if network == 'fixture':
        expected.add('HOLY-BOOT-1 network fixture-static-ip')
        expected.add('HOLY-BOOT-1 network fixture-dns')
    if 'KERNEL_VERSION' in os.environ:
        expected.add('HOLY-BOOT-1 kernel ' + os.environ['KERNEL_VERSION'])
    if module_probe == 'on':
        expected.add('HOLY-BOOT-1 kernel-module dummy-loaded')
    if media == 'disk':
        expected.add('HOLY-BOOT-1 esp mounted-writable')
    expected_boots = [expected]
    if disk_path:
        first = expected - {'HOLY-BOOT-1 result pass'}
        first.update({'HOLY-BOOT-1 boot 1', 'HOLY-BOOT-1 root ext4',
                      'HOLY-BOOT-1 first-boot pass', 'HOLY-BOOT-1 reboot requested'})
        if state == 'remove-both':
            first.update({f'HOLY-BOOT-1 removed-libc {abi}' for abi in ('glibc', 'musl')})
            second = expected - {'HOLY-BOOT-1 libc-initial remove-both'}
            second.update({'HOLY-BOOT-1 boot 2', 'HOLY-BOOT-1 root ext4',
                           'HOLY-BOOT-1 libc-initial removed-both',
                           'HOLY-BOOT-1 libc-recovery removed-both'})
            for abi in ('glibc', 'musl'):
                second.update({f'HOLY-BOOT-1 missing-libc {abi}',
                               f'HOLY-BOOT-1 reinstalled-libc {abi}',
                               f'HOLY-BOOT-1 restored-libc {abi}'})
        else:
            second = {marker for marker in expected if not marker.startswith((
                'HOLY-BOOT-1 libc-initial ', 'HOLY-BOOT-1 libc-recovery ',
                'HOLY-BOOT-1 missing-libc ', 'HOLY-BOOT-1 restored-libc '))}
            second.update({'HOLY-BOOT-1 boot 2', 'HOLY-BOOT-1 root ext4',
                           'HOLY-BOOT-1 libc-initial restored', 'HOLY-BOOT-1 libc-recovery restored'})
        expected_boots = [first, second]
        expected |= first | second
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
    serial_lines = []
    probe_history = []
    active_probe = None
    probe_deadline = None
    probe_boot = 1
    started_stages = set()
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
                        content = serial.read_text(errors='replace')
                        complete = content.rsplit('\n', 1)[0] if '\n' in content else ''
                        lines = complete.splitlines()
                        if lines[:len(serial_lines)] != serial_lines:
                            reason = 'serial-log-changed'
                            break
                        now = time.monotonic()
                        for line in lines[len(serial_lines):]:
                            if line == 'HOLY-BOOT-1 boot 2':
                                if active_probe:
                                    active_probe['duration_seconds'] = now - active_probe['started_at']
                                    active_probe['status'] = 'pass'
                                active_probe = None
                                probe_deadline = None
                                probe_boot = 2
                            if not line.startswith('HOLY-BOOT-1 stage '):
                                continue
                            name = line.removeprefix('HOLY-BOOT-1 stage ')
                            if name not in ('identity', 'login', 'esp', 'static-core',
                                            'installer', 'devices', 'kernel-module', 'libc-recovery',
                                            'network-setup', 'documentation', 'packages',
                                            'installer-transaction', 'libc-removal',
                                            'reboot', 'result'):
                                reason = 'invalid-probe-stage'
                                break
                            if (probe_boot, name) in started_stages:
                                continue
                            started_stages.add((probe_boot, name))
                            if active_probe:
                                active_probe['duration_seconds'] = now - active_probe['started_at']
                                active_probe['status'] = 'pass'
                            active_probe = {'boot': probe_boot, 'stage': name,
                                            'started_at': now,
                                            'duration_seconds': None, 'status': 'unknown'}
                            probe_history.append(active_probe)
                            probe_deadline = now + int(probe_limit)
                        if reason == 'invalid-probe-stage':
                            break
                        serial_lines = lines
                        seen = set(lines)
                        frames, valid = boot_frames(lines, bool(disk_path))
                        if not valid:
                            reason = 'invalid-boot-sequence'
                            break
                    if 'HOLY-BOOT-1 result fail' in seen:
                        reason = 'guest-failure'
                        if active_probe:
                            active_probe['duration_seconds'] = time.monotonic() - active_probe['started_at']
                            active_probe['status'] = 'fail'
                        break
                    if disk_path and first_completed is None and frames and expected_boots[0] <= frames[0]:
                        first_completed = time.monotonic() - started
                        deadline = time.monotonic() + int(limit)
                        reason = 'reboot-timeout'
                    if len(frames) == len(expected_boots) and all(
                            wanted <= actual for wanted, actual in zip(expected_boots, frames)):
                        reason = 'probes-complete'
                        if active_probe:
                            active_probe['duration_seconds'] = time.monotonic() - active_probe['started_at']
                            active_probe['status'] = 'pass'
                        break
                    if probe_deadline and time.monotonic() >= probe_deadline:
                        reason = 'probe-timeout'
                        if active_probe:
                            active_probe['duration_seconds'] = time.monotonic() - active_probe['started_at']
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
    if active_probe and active_probe['duration_seconds'] is None:
        active_probe['duration_seconds'] = time.monotonic() - active_probe['started_at']
    base_unchanged = not disk_path or digest(base) == inputs['root_disk']['sha256']
    if server:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)
        dns_stopped.set()
        dns_socket.close()
        dns_thread.join(timeout=5)
        wanted_requests = {f'/{abi}.holy' for abi in ('glibc', 'musl')}
        served = {entry['path'] for entry in requests if entry['status'] == 200}
        if not wanted_requests <= served or not any(item['type'] == 1 for item in dns_queries):
            reason, result = 'network-fixture-incomplete', 'fail'
    inconsistent = sorted(name for name, item in inputs.items()
                          if item.get('copy_consistency', 'verified') != 'verified')
    # a guest that printed no marker at all did not start, which is a different fault
    # from a guest that ran and missed the ones it owed, so the report says which
    if result == 'fail' and reason == 'boot-timeout' and not any(
            line.startswith('HOLY-BOOT-1') for line in serial_lines):
        reason = 'no-serial-output'
    if not base_unchanged:
        reason, result = 'changed-read-only-base', 'fail'
    elif inconsistent:
        reason, result = 'inconsistent-input-copy', 'fail'
    boots = []
    for index, wanted in enumerate(expected_boots):
        actual = frames[index] if index < len(frames) else set()
        boots.append({'boot': index + 1, 'missing_markers': sorted(wanted - actual),
                      'checks': {marker: 'pass' if marker in actual else 'unknown' for marker in sorted(wanted)}})
    report = {'schema': 'holy-qemu-report-2', 'arch': arch, 'accelerator': accel,
              'firmware': firmware, 'profile': profile, 'libc_boot_state': state,
              'kernel_module_probe': module_probe,
              'network': 'private-loopback-fixture-https' if server else 'disabled', 'plan': plan,
              'inputs': inputs, 'network_inputs': network_inputs, 'network_requests': requests,
              'dns_queries': dns_queries,
              'network_namespace': namespace_evidence,
              'argv': args, 'pid': process.pid, 'exit': code,
              'cancel_signal': cancelled[0] if cancelled else None,
              'elapsed_seconds': time.monotonic() - started,
              'boot_timeout_seconds': int(limit), 'probe_timeout_seconds': int(probe_limit),
              'shutdown_timeout_seconds': 5,
              'probes': [{'boot': probe['boot'], 'stage': probe['stage'],
                          'started_seconds': probe['started_at'] - started,
                          'duration_seconds': probe['duration_seconds'],
                          'status': probe['status']} for probe in probe_history],
              'timed_out_probe': active_probe['stage'] if reason == 'probe-timeout' else None,
              'timed_out_boot': active_probe['boot'] if reason == 'probe-timeout' else None,
              'root_storage': 'ext4-overlay' if disk_path else 'ram', 'boots': boots,
              'boot_media': media,
              'first_boot_completed_seconds': first_completed,
              'reason': reason, 'result': result,
              'inconsistent_inputs': inconsistent,
              'missing_markers': ([f'boot-{b["boot"]}: {marker}' for b in boots for marker in b['missing_markers']]
                                  if disk_path else sorted(expected - seen)),
              'checks': {marker: 'pass' if marker in seen else 'unknown' for marker in sorted(expected)},
              'not_tested': (['libc-recovery'] if profile != 'dual-libc' or state == 'present' else []) +
                            ([] if disk_path else ['libc-recovery-reboot']) +
                            (['i686-libc'] if arch != 'i686' or profile != 'dual-libc' else []) +
                            (['kernel-module-load'] if module_probe == 'off' else []) +
                            ['installer', 'hardware', 'public-network' if server else 'network', 'kernel-update']}
    if disk_path:
        report['overlay'] = {'path': str(run / 'root.qcow2'), 'sha256': digest(run / 'root.qcow2'),
                             'base_unchanged': base_unchanged,
                             'backing_format': inputs['root_disk']['format'],
                             'retained': keep}
    report['temporary_inputs_retained'] = keep
    (run / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    # a failing run says which markers it did not see, since a guest that printed its
    # own result and a wrong expectation look the same as a boot that hung otherwise
    absent = report['missing_markers']
    lines = [f'format holy-qemu-report-2\narch {arch}\nboot-media {media}\n'
             f'iso-sha256 {inputs.get("iso", {}).get("sha256", "none")}\nplan {plan}\n'
             f'accelerator {accel}\nfirmware {firmware}\nexit {code}\n'
             f'reason {reason}\nresult {result}']
    for marker in absent:
        lines.append('missing ' + marker)
    lines.append('missing-count %d\n' % len(absent))
    (run / 'report').write_text('\n'.join(lines))
    if not keep:
        for temporary in ('root.qcow2', 'root-base.raw', 'root-base.qcow2',
                          'uefi_code.fd', 'uefi_vars.fd', 'input.iso'):
            (run / temporary).unlink(missing_ok=True)
    print(f'holy-qemu: {result} report {run}/report')
    return 0 if result == 'pass' else 4


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        error(str(exc), 1)
