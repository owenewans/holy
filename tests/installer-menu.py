import errno
import fcntl
import hashlib
import json
import os
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path


def run_menu(installer, holypkg, root, digest, config, plan, source_id):
    image = Path(config + '.img')
    with image.open('wb') as stream:
        stream.truncate(1 << 30)

    def disk_sample():
        with image.open('rb') as stream:
            head = hashlib.sha256(stream.read(1048576)).digest()
            stream.seek(-1048576, os.SEEK_END)
            tail = hashlib.sha256(stream.read(1048576)).digest()
        return head, tail

    pid, master = pty.fork()
    if pid == 0:
        os.execv(installer, [installer, '--menu', '--config', config,
                             '--plan', plan, '--holypkg', holypkg])
    output = bytearray()
    cursor = 0

    def expect(marker):
        nonlocal cursor
        needle = marker.encode()
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            position = output.find(needle, cursor)
            if position >= 0:
                cursor = position + len(needle)
                return
            ready, _, _ = select.select([master], [], [], 1)
            if not ready:
                continue
            try:
                chunk = os.read(master, 4096)
            except OSError as exc:
                if exc.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            output.extend(chunk)
        raise AssertionError(f'missing {marker!r}: {output[-3000:]!r}')

    def send(value):
        os.write(master, value.encode())

    try:
        expect('Choice > ')
        send('2\n')
        expect('a add, d delete, x arch override, p setuid approval, s source, b back > ')
        send('b\n')
        expect('Choice > ')
        send('1\n')
        expect('Target root > ')
        send(root + '\n')
        expect('Choice > ')
        send('2\n')
        expect('a add, d delete, x arch override, p setuid approval, s source, b back > ')
        send('a\n')
        expect('SHA-256 > ')
        send(digest + '\n')
        expect('a add, d delete, x arch override, p setuid approval, s source, b back > ')
        send('x\n')
        expect('Number > ')
        send('1\n')
        expect('[arch override]')
        expect('a add, d delete, x arch override, p setuid approval, s source, b back > ')
        send('x\n')
        expect('Number > ')
        send('1\n')
        expect('a add, d delete, x arch override, p setuid approval, s source, b back > ')
        send('p\n')
        expect('Number > ')
        send('1\n')
        expect('[setuid approved]')
        expect('a add, d delete, x arch override, p setuid approval, s source, b back > ')
        send('p\n')
        expect('Number > ')
        send('1\n')
        expect('a add, d delete, x arch override, p setuid approval, s source, b back > ')
        send('s\n')
        expect('Number > ')
        send('1\n')
        expect('Source ID SHA-256 (empty clears) > ')
        send(source_id + '\n')
        expect('[source assigned]')
        expect('a add, d delete, x arch override, p setuid approval, s source, b back > ')
        send('b\n')
        expect('Packages: 1')
        expect('Choice > ')
        send('8\n')
        expect('Disk image (blank clears selection) > ')
        send(str(image) + '\n')
        expect('Choice > ')
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', 30, 90, 0, 0))
        os.kill(pid, signal.SIGWINCH)
        send('3\n')
        expect('plan-set generation')
        expect('Choice > ')
        send('4\n')
        expect('Config saved')
        expect('Choice > ')
        send('5\n')
        expect('holyinstall plan')
        expect('Choice > ')
        send('6\n')
        expect('Type yes to install > ')
        send('no\n')
        expect('Choice > ')
        assert not Path(root, 'usr/share/installer-fixture').exists()
        send('6\n')
        expect('Type yes to install > ')
        send('yes\n')
        expect('Package transaction complete')
        expect('Choice > ')
        before = disk_sample()
        send('9\n')
        expect('Disk plan ')
        expect('Choice > ')
        assert disk_sample() == before
        send('10\n')
        expect('Type the exact disk image path to erase > ')
        send(str(image) + '-wrong\n')
        expect('Disk apply failed (status 3)')
        expect('Choice > ')
        assert disk_sample() == before
        send('10\n')
        expect('Type the exact disk image path to erase > ')
        send(str(image) + '\n')
        expect('Disk image prepared')
        expect('Choice > ')
        send('7\n')
        _, status = os.waitpid(pid, 0)
        assert os.waitstatus_to_exitcode(status) == 0, output[-3000:]
        assert Path(root, 'usr/share/installer-fixture').read_text() == 'installed\n'
        assert f'source {digest} {source_id}\n' in Path(config).read_text()
        assert f'source-id {source_id}\n' in Path(root, 'var/lib/holypkg/installed', digest, 'state').read_text()
        assert Path(config).exists() and Path(plan).exists()
        disk_plan = Path(plan + '.disk')
        assert disk_plan.exists()
        assert Path(str(disk_plan) + '.journal').read_text().splitlines()[-1] == 'committed'
        table = json.loads(subprocess.check_output(['/usr/sbin/sfdisk', '--json', str(image)]))
        assert [(part['start'], part['size']) for part in table['partitiontable']['partitions']] == [
            (2048, 2048), (4096, 524288), (528384, 1566720)]
    finally:
        os.close(master)

    saved = Path(config).read_bytes()
    pid, master = pty.fork()
    if pid == 0:
        os.execv(installer, [installer, '--menu', '--config', config,
                             '--plan', plan, '--holypkg', holypkg])
    output = bytearray()
    deadline = time.monotonic() + 15
    while b'Packages: 1' not in output and time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], 1)
        if ready:
            output.extend(os.read(master, 4096))
    assert b'Packages: 1' in output and root.encode() in output and str(image).encode() in output, output[-3000:]
    os.write(master, b'7\n')
    _, status = os.waitpid(pid, 0)
    os.close(master)
    assert os.waitstatus_to_exitcode(status) == 0
    assert Path(config).read_bytes() == saved


if __name__ == '__main__':
    run_menu(*sys.argv[1:])
    print('installer text menu fixtures passed')
