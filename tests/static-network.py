#!/usr/bin/env python3
import hashlib
import http.server
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

COVERAGE = ['static-network-setup', 'static-dns', 'static-https', 'certificate-rejection',
            'digest-rejection', 'native-archive-verification']


def digest(path):
    result = hashlib.sha256()
    with open(path, 'rb') as source:
        for chunk in iter(lambda: source.read(65536), b''):
            result.update(chunk)
    return result.hexdigest()


def namespace(work, uid, gid, host_namespace):
    assert os.geteuid() == 0
    assert os.stat('/proc/self/ns/net').st_ino != host_namespace
    root = work / 'root'
    subprocess.run(['chroot', str(root), '/usr/bin/busybox', 'ip', 'link', 'set', 'lo', 'up'], check=True)
    queries = []
    disconnects = []
    stopped = threading.Event()
    dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns.bind(('127.0.0.1', 53))
    dns.settimeout(0.2)

    def serve_dns():
        while not stopped.is_set():
            try:
                data, peer = dns.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if len(data) < 17 or struct.unpack('!H', data[4:6])[0] != 1:
                continue
            cursor, labels = 12, []
            while cursor < len(data) and 0 < data[cursor] <= 63:
                size = data[cursor]
                labels.append(data[cursor + 1:cursor + size + 1])
                cursor += size + 1
            if cursor + 5 > len(data) or data[cursor] != 0:
                continue
            kind, group = struct.unpack('!HH', data[cursor + 1:cursor + 5])
            name = b'.'.join(labels).lower()
            if name != b'fixture.holy.test' or group != 1:
                continue
            queries.append(kind)
            question = data[12:cursor + 5]
            answer = b''
            if kind == 1:
                answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + socket.inet_aton('127.0.0.1')
            response = data[:2] + struct.pack('!HHHHH', 0x8180, 1, bool(answer), 0, 0)
            dns.sendto(response + question + answer, peer)

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(work / 'serve'), **kwargs)

        def log_message(self, *args):
            pass

        def handle(self):
            try:
                super().handle()
            except (BrokenPipeError, ConnectionResetError) as error:
                disconnects.append(type(error).__name__)

    server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(work / 'cert.pem', work / 'key.pem')
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    dns_thread = threading.Thread(target=serve_dns, daemon=True)
    tls_thread = threading.Thread(target=server.serve_forever, daemon=True)
    dns_thread.start()
    tls_thread.start()
    records = []

    def client(arguments, expected):
        argv = ['chroot', f'--userspec={uid}:{gid}', f'--groups={gid}',
                str(root), '/usr/bin/holypkg', *arguments]
        started = time.monotonic()
        process = subprocess.run(argv, capture_output=True, text=True, timeout=20,
                                 env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin',
                                      'HOME': '/', 'LC_ALL': 'C', 'NO_PROXY': '*'})
        records.append({'argv': argv, 'expected_exit': expected,
                        'exit': process.returncode,
                        'elapsed_seconds': time.monotonic() - started,
                        'stdout': process.stdout, 'stderr': process.stderr})
        if process.returncode != expected:
            raise RuntimeError(f'client returned {process.returncode}, expected {expected}: {process.stderr}')
        return process.stdout

    result = {'status': 'fail', 'coverage': []}
    try:
        facts = client(['elf', '/usr/bin/holypkg'], 0)
        assert 'runtime nolibc\n' in facts and 'e_type 2\n' in facts
        result['libc'] = 'nolibc'
        result['coverage'].append('static-network-setup')
        expected = digest(work / 'serve/fixture.holy')
        url = f'https://fixture.holy.test:{server.server_port}/fixture.holy'
        base = ['fetch', url, '--sha256', expected]
        client([*base, '--output', '/bad-ca', '--ca-file', '/untrusted.pem'], 6)
        assert not list((root / 'bad-ca').iterdir())
        result['coverage'].append('certificate-rejection')
        client(['fetch', url, '--sha256', 'a' * 64, '--output', '/bad-hash',
                '--ca-file', '/ca.pem'], 4)
        assert not list((root / 'bad-hash').iterdir())
        result['coverage'].append('digest-rejection')
        client([*base, '--output', '/out', '--ca-file', '/ca.pem'], 0)
        assert digest(root / 'out' / f'{expected}.holy') == expected
        result['coverage'].append('static-https')
        client(['verify', f'local:/out/{expected}.holy'], 0)
        result['coverage'].append('native-archive-verification')
        assert 1 in queries
        result['coverage'].append('static-dns')
        assert all(not (root / name).exists() for name in ('lib', 'lib64', 'usr/lib'))
        result['status'] = 'pass'
    except Exception as error:
        result['error'] = f'{type(error).__name__}: {error}'
    finally:
        stopped.set()
        server.shutdown()
        server.server_close()
        dns.close()
        dns_thread.join(timeout=1)
        tls_thread.join(timeout=1)
    result.update({'dns_query_types': queries, 'commands': records,
                   'server_disconnects': disconnects,
                   'unexecuted': [case for case in COVERAGE if case not in result['coverage']]})
    print(json.dumps(result))
    return 0 if result['status'] == 'pass' else 1


def main():
    if len(sys.argv) == 6 and sys.argv[1] == '--namespace':
        return namespace(Path(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]))
    if len(sys.argv) != 4:
        print('usage: static-network.py STATIC-HOLYPKG PACKAGE REPORT', file=sys.stderr)
        return 2
    for tool in ('doas', 'unshare', 'ip', 'chroot', 'openssl'):
        if not shutil.which(tool):
            print(f'missing tool: {tool}', file=sys.stderr)
            return 6
    if subprocess.run(['doas', '-n', 'unshare', '--net', 'true']).returncode:
        return 6
    binary, package, report_path = map(lambda p: Path(p).resolve(), sys.argv[1:])
    if not binary.is_file() or not package.is_file():
        print('static binary and package inputs are required', file=sys.stderr)
        return 6
    report = {'schema': 'holy-static-network-test-1', 'arch': platform.machine(),
              'kernel': platform.release(), 'image': None,
              'libc': None, 'target_libc': 'nolibc', 'holypkg_sha256': digest(binary),
              'fixture_sha256': digest(__file__), 'source_url': package.as_uri(),
              'artifact_sha256': digest(package), 'network': 'private-loopback-fixture',
              'requested_coverage': COVERAGE, 'coverage': [], 'unexecuted': COVERAGE}
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='holy-static-network-') as directory:
        work = Path(directory)
        root = work / 'root'
        for name in ('usr/bin', 'tmp', 'etc', 'out', 'bad-ca', 'bad-hash'):
            (root / name).mkdir(parents=True, exist_ok=True)
        (work / 'serve').mkdir()
        shutil.copyfile(binary, root / 'usr/bin/holypkg')
        (root / 'usr/bin/holypkg').chmod(0o755)
        extracted = work / 'extracted'
        subprocess.run([str(binary), 'fetch', 'local:' + str(package), '--extract',
                        '--output', str(extracted)], check=True, capture_output=True)
        shutil.copyfile(extracted / 'DATA/usr/bin/busybox', root / 'usr/bin/busybox')
        (root / 'usr/bin/busybox').chmod(0o755)
        shutil.copyfile(package, work / 'serve/fixture.holy')
        report['holypkg_sha256'] = digest(root / 'usr/bin/holypkg')
        report['artifact_sha256'] = digest(work / 'serve/fixture.holy')
        (root / 'etc/resolv.conf').write_text('nameserver 127.0.0.1\noptions timeout:1 attempts:1\n')
        for name, subject in (('cert', 'fixture.holy.test'), ('untrusted', 'untrusted.test')):
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-days', '1', '-keyout', str(work / f'{name}.key'),
                            '-out', str(work / f'{name}.pem'), '-subj', f'/CN={subject}',
                            '-addext', f'subjectAltName=DNS:{subject}'], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (work / 'cert.key').rename(work / 'key.pem')
        shutil.copyfile(work / 'cert.pem', root / 'ca.pem')
        shutil.copyfile(work / 'untrusted.pem', root / 'untrusted.pem')
        report['ca_sha256'] = digest(work / 'cert.pem')
        argv = ['doas', '-n', 'unshare', '--net', '--', sys.executable,
                str(Path(__file__).resolve()), '--namespace', str(work),
                str(os.getuid()), str(os.getgid()), str(os.stat('/proc/self/ns/net').st_ino)]
        try:
            process = subprocess.run(argv, capture_output=True, text=True, timeout=100)
        except subprocess.TimeoutExpired as error:
            process = subprocess.CompletedProcess(argv, 1,
                (error.stdout or b'').decode(errors='replace'),
                (error.stderr or b'').decode(errors='replace') + '\nnamespace timeout')
        report.update({'exit': process.returncode, 'elapsed_seconds': time.monotonic() - started,
                       'log': process.stderr, 'status': 'fail'})
        try:
            report.update(json.loads(process.stdout))
        except (ValueError, TypeError):
            report['stdout'] = process.stdout
        if process.returncode:
            report['status'] = 'fail'
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(f'static network fixture {report["status"]}: {report_path}')
    return 0 if report['status'] == 'pass' else 1


if __name__ == '__main__':
    sys.exit(main())
