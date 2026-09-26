#!/bin/sh
set -eu

tmp=$(mktemp -d "${TMPDIR:-/tmp/opencode}/holy-qemu-fixture-XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
plan=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
for arch in i686 x86_64; do
    if ARCH="$arch" ISO="$tmp/missing.iso" BOOT_PLAN="$plan" \
       REPORT_DIR="$tmp" sh tests/qemu.sh > "$tmp/out" 2> "$tmp/err"; then
        exit 1
    else
        test "$?" -eq 6
    fi
done
truncate -s 1048576 "$tmp/blank.iso"
for arch in i686 x86_64; do
    if ARCH="$arch" ISO="$tmp/blank.iso" BOOT_PLAN="$plan" \
       QEMU_TIMEOUT=2 REPORT_DIR="$tmp" sh tests/qemu.sh \
       > "$tmp/out" 2> "$tmp/err"; then
        exit 1
    else
        test "$?" -eq 4
    fi
    report=$(sed -n 's/^holy-qemu: fail report //p' "$tmp/out")
    test -f "$report"
    grep -qx 'result fail' "$report"
    grep -qx "arch $arch" "$report"
    grep -qx 'firmware bios' "$report"
    grep -qx 'accelerator tcg' "$report"
done
printf 'qemu negative gate fixtures passed\n'
