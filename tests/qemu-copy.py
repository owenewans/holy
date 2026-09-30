#!/usr/bin/env python3
"""the copied boot inputs of a QEMU run compare with the sources they came from.

A run copies the ISO and the root disk into a run directory, marks the copies
read-only and boots an overlay on top of the disk copy, so the bytes the guest
sees are the ones the report has to name. This checks the measurement on a real
copy and the three consistency decisions, which no local run reaches for a source
that changes mid-copy.
"""
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import qemu


def main():
    with tempfile.TemporaryDirectory() as scratch:
        base = pathlib.Path(scratch)
        source = base / 'input.iso'
        source.write_bytes(b'\0holy-qemu-copy' * 4096)
        copied = base / 'run' / 'input.iso'
        copied.parent.mkdir()
        measured = qemu.copy_input(source, copied)
        assert measured['copy_consistency'] == 'verified', measured
        assert measured['source_sha256'] == measured['sha256'], measured
        assert measured['source_sha256'] == measured['source_after_sha256'], measured
        assert copied.read_bytes() == source.read_bytes()

        # an empty input and a missing one are not a copy
        empty = base / 'empty'
        empty.write_bytes(b'')
        assert qemu.copy_input(empty, base / 'empty-copy')['sha256'] == qemu.digest(empty)
        try:
            qemu.copy_input(base / 'absent', base / 'absent-copy')
        except OSError:
            pass
        else:
            raise AssertionError('a missing input must not copy')

        # the three decisions the runner reports
        verified = 'a' * 64
        other = 'b' * 64
        assert qemu.copy_consistency(verified, verified, verified) == 'verified'
        assert qemu.copy_consistency(verified, other, verified) == 'input-changed-during-copy'
        assert qemu.copy_consistency(verified, verified, other) == 'copy-mismatch'
    print('qemu input copy fixtures passed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
