#!/bin/sh
set -eu
test "$#" -eq 2 || exit 2
bin=$(realpath "$1")
package=$(realpath "$2")
test -x "$bin" && test -f "$package" || exit 6
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
"$bin" verify "local:$package" > "$tmp/verify"
"$bin" fetch "local:$package" --extract --output "$tmp/extract" > "$tmp/fetch"
tools="$tmp/extract/DATA/usr/bin"
for name in sfdisk mkfs.fat mke2fs limine mkfs.btrfs; do
    test -x "$tools/$name"
    "$bin" elf "$tools/$name" > "$tmp/$name.elf"
    grep -qx 'runtime nolibc' "$tmp/$name.elf"
    grep -qx 'e_type 2' "$tmp/$name.elf"
done
disk="$tmp/target.raw"
truncate -s 1G "$disk"
printf '%s\n' 'label: gpt' 'unit: sectors' 'first-lba: 2048' \
    'start=2048, size=2048, type=21686148-6449-6E6F-744E-656564454649' \
    'start=4096, size=524288, type=U' \
    'start=528384, size=1568735, type=L' | "$tools/sfdisk" "$disk" > "$tmp/partition"
"$tools/sfdisk" --verify "$disk" > "$tmp/verify-disk"
"$tools/mkfs.fat" -F 32 -s 4 --offset=4096 -n HOLYBOOT "$disk" 262144 > "$tmp/fat" 2>&1
"$tools/mke2fs" -q -t ext4 -F -b 4096 -E offset=270532608 "$disk" 196091 > "$tmp/ext4" 2>&1
# the btrfs tool prepares a filesystem no other tool in the package can, so the fixture
# reads the superblock it wrote instead of trusting the exit status alone
btrfs_disk="$tmp/btrfs.raw"
truncate -s 256M "$btrfs_disk"
"$tools/mkfs.btrfs" -q -f "$btrfs_disk" > "$tmp/btrfs" 2>&1
magic=$(dd if="$btrfs_disk" bs=1 skip=$((0x10040)) count=8 2>/dev/null)
test "$magic" = '_BHRfS_M'
"$tools/limine" bios-install "$disk" 1 > "$tmp/limine" 2>&1
"$tools/sfdisk" --verify "$disk" > "$tmp/verify-final"
grep -q 'installed successfully' "$tmp/limine"
printf 'storage bootstrap fixture passed artifact=%s\n' "$(sha256sum "$package" | cut -d ' ' -f 1)"
