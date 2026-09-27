#!/bin/sh
set -eu
test "$#" -eq 1 || { echo 'usage: image-docs.sh EXT4_IMAGE_DIRECTORY' >&2; exit 2; }
image=$(realpath "$1")
for tool in debugfs python3 qemu-system-x86_64 qemu-img; do
    command -v "$tool" >/dev/null || { echo "$tool required" >&2; exit 6; }
done
test -f "$image/root.ext4" && test -f "$image/holy-x86_64.iso" || exit 6
test "$(cat "$image/root/etc/holy/libc-boot-state")" = both || exit 6
unset KERNEL_IMAGE INITRAMFS ROOT_IMAGE KERNEL_VERSION
plan=$(cat "$image/boot-plan")
before=$(sha256sum "$image/root.ext4")
tmp=$(mktemp -d /tmp/opencode/holy-image-docs-negative.XXXXXX)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
printf 'changed documentation\n' > "$tmp/payload"
for scenario in bundle source; do
    case "$scenario" in
        bundle) target=/usr/share/holy/llm.txt ;;
        source) target=/usr/share/man/man8/holypkg.8 ;;
    esac
    mkdir "$tmp/$scenario"
    disk="$tmp/$scenario/root.ext4"
    cp --reflink=auto --sparse=always "$image/root.ext4" "$disk"
    chmod 0600 "$disk"
    debugfs -w -R "rm $target" "$disk" > "$tmp/edit.log" 2>&1
    debugfs -w -R "write $tmp/payload $target" "$disk" >> "$tmp/edit.log" 2>&1
    debugfs -R "cat $target" "$disk" 2>/dev/null > "$tmp/content"
    cmp "$tmp/payload" "$tmp/content"
    rc=0
    ARCH=x86_64 ISO="$image/holy-x86_64.iso" BOOT_PLAN="$plan" \
        IMAGE_PROFILE=dual-libc LIBC_BOOT_STATE=both BOOT_MEDIA=iso \
        ROOT_DISK="$disk" FIRMWARE=bios QEMU_ACCEL=tcg QEMU_TIMEOUT=120 \
        REPORT_DIR="$tmp/$scenario" sh tests/qemu.sh > "$tmp/runner.log" 2>&1 || rc=$?
    test "$rc" -eq 4 || { cat "$tmp/runner.log"; exit 1; }
    python3 - "$tmp/$scenario" <<'PY'
import json
from pathlib import Path
import sys
reports = list(Path(sys.argv[1]).glob('holy-qemu-*/report.json'))
assert len(reports) == 1
report = json.loads(reports[0].read_text())
assert report['result'] == 'fail' and report['reason'] == 'guest-failure'
serial = reports[0].with_name('serial.log').read_text()
assert 'HOLY-BOOT-1 failed documentation' in serial
assert 'HOLY-BOOT-1 docs installed-man-bundle' not in serial
PY
    printf 'image documentation fixture rejected changed %s\n' "$scenario"
done
test "$before" = "$(sha256sum "$image/root.ext4")"
