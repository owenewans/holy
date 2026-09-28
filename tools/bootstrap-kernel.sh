#!/bin/sh
set -eu
test "$#" -eq 6 || {
    echo 'usage: bootstrap-kernel.sh HOLYPKG KERNEL_IMAGE VERSION ARCH MODULES_DIR OUTPUT' >&2
    exit 2
}
if test "${HOLY_KERNEL_NAMESPACE:-}" != 1; then
    test "$(id -u)" != 0 || { echo 'run as an ordinary user' >&2; exit 6; }
    export HOLY_KERNEL_NAMESPACE=1
    exec unshare --map-root-user -- sh "$0" "$@"
fi
test "$(id -u)" = 0 &&
    awk '$1 == 0 && $2 != 0 && $3 == 1 { ok = 1 } END { exit !ok }' /proc/self/uid_map || exit 6
umask 022
bin=$(realpath "$1")
kernel=$(realpath "$2")
version=$3
arch=$4
modules=$5
output=$6
case "$version" in ''|*[!a-zA-Z0-9._+-]*) exit 2 ;; esac
case "$arch" in x86_64|i686) ;; *) echo 'ARCH must be i686 or x86_64' >&2; exit 2 ;; esac
test -f "$kernel" && test ! -L "$kernel" || exit 6
if test "$modules" != -; then
    modules=$(realpath "$modules")
    test -d "$modules" && test -f "$modules/modules.dep" || exit 6
fi
python3 - "$kernel" "$arch" <<'PY'
import struct
import sys

with open(sys.argv[1], 'rb') as source:
    header = source.read(0x238)
if (len(header) < 0x238 or header[0x202:0x206] != b'HdrS' or
        struct.unpack_from('<H', header, 0x206)[0] < 0x20c):
    sys.exit('unsupported x86 kernel boot header')
actual = 'x86_64' if struct.unpack_from('<H', header, 0x236)[0] & 1 else 'i686'
if actual != sys.argv[2]:
    sys.exit(f'kernel target {actual} does not match {sys.argv[2]}')
PY
mkdir -p "$(dirname "$output")"
mkdir -m 0700 "$output"
out=$(realpath "$output")
tree="$out/tree"
mkdir -p "$tree/HOLY" "$tree/DATA/boot"
cp "$kernel" "$tree/DATA/boot/vmlinuz"
chmod 0644 "$tree/DATA/boot/vmlinuz"
printf 'format holy-kernel-bootstrap-1\narch %s\nversion %s\n' "$arch" "$version" > "$out/build.record"
kernel_hash=$(sha256sum "$kernel")
printf 'kernel-image-sha256 %s\n' "${kernel_hash%% *}" >> "$out/build.record"
printf 'input-kernel-sha256 %s\n' "${kernel_hash%% *}" > "$tree/HOLY/origin"
if test "$modules" != -; then
    destination="$tree/DATA/usr/lib/modules/$version"
    mkdir -p "$destination"
    cp -R "$modules/." "$destination/"
    find "$destination" -type d -exec chmod 0755 {} +
    python3 - "$destination" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
entries = {}
for line in (root / 'modules.dep').read_text().splitlines():
    name, separator, dependencies = line.partition(':')
    if not separator or name in entries or not name.startswith('kernel/') or not name.endswith('.ko'):
        sys.exit('invalid modules.dep entry: ' + line)
    paths = [name, *dependencies.split()]
    if any(not path.startswith('kernel/') or not path.endswith('.ko') or
           '..' in Path(path).parts or not (root / path).is_file() for path in paths):
        sys.exit('modules.dep references missing module: ' + line)
    entries[name] = paths[1:]
modules = {path.relative_to(root).as_posix() for path in root.rglob('*.ko')}
if modules != set(entries):
    sys.exit('modules.dep does not cover every kernel module')
if list(root.rglob('*.ko.xz')) or list(root.rglob('*.ko.zst')) or list(root.rglob('*.ko.gz')):
    sys.exit('compressed modules require explicit unpacking')
PY
    printf 'module-count %s\n' "$(find "$destination" -type f -name '*.ko' | wc -l)" >> "$out/build.record"
fi
if test "$arch" = i686; then package_arch=x86; else package_arch=x86_64; fi
printf 'format holy-package-1\nname linux\nversion %s\nrelease 1\nos linux\narch %s\nlibc nolibc\n' \
    "$version" "$package_arch" > "$tree/HOLY/meta"
for field in deps provides hooks transform; do : > "$tree/HOLY/$field"; done
"$bin" manifest generate "$tree" --output "$out/files"
mv "$out/files" "$tree/HOLY/files"
"$bin" pack "$tree" --output "$out/linux.holy"
"$bin" verify "local:$out/linux.holy" > "$out/verify.record"
"$bin" scan "local:$out/linux.holy" > "$out/scan.record"
artifact=$(sha256sum "$out/linux.holy")
printf 'artifact-sha256 %s\nresult built\nnot-tested boot\n' "${artifact%% *}" >> "$out/build.record"
printf '%s\n' "$out/linux.holy"
