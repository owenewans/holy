#!/usr/bin/env python3
import hashlib
import json
import os
import pathlib
import shutil
import stat
import sys


def main():
    if len(sys.argv) < 3:
        return 2
    destination = pathlib.Path(sys.argv[1])
    entries = []
    for requested in sys.argv[2:]:
        found = requested if '/' in requested else shutil.which(requested)
        if not found:
            print(f'holy-image: required tool unavailable: {requested}', file=sys.stderr)
            return 6
        path = pathlib.Path(found).resolve(strict=True)
        mode = path.stat().st_mode
        if not stat.S_ISREG(mode) or not os.access(path, os.X_OK):
            print(f'holy-image: invalid executable: {requested}', file=sys.stderr)
            return 6
        digest = hashlib.sha256()
        with path.open('rb') as source:
            for block in iter(lambda: source.read(1024 * 1024), b''):
                digest.update(block)
        entries.append({'name': requested, 'path': str(path), 'sha256': digest.hexdigest()})
    with destination.open('x', encoding='utf-8') as output:
        for entry in entries:
            output.write(json.dumps(entry, ensure_ascii=True, sort_keys=True, separators=(',', ':')) + '\n')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f'holy-image: host tool record failed: {error}', file=sys.stderr)
        raise SystemExit(6)
