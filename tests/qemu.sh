#!/bin/sh
set -eu
command -v python3 >/dev/null || { echo 'holy-qemu: python3 required' >&2; exit 6; }
exec python3 "$(dirname "$0")/qemu.py"
