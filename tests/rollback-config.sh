#!/bin/sh
# the kernel rollback contract, checked as the configuration it is. the generator has to
# produce a config the checker accepts, the checker has to refuse every shape that cannot
# roll back, and a rollback needs two different kernels, which a fresh install does not
# have until an update writes the second slot.
set -eu

bin=${1:-./holypkg}
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
generate=$repo/tools/limine-rollback.sh
check=$repo/tools/check-limine-rollback.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

command -v b2sum >/dev/null 2>&1 || { echo 'b2sum required' >&2; exit 6; }

# a stand-in for a kernel and an initramfs. the loader never sees these bytes, so their
# size only has to be different enough that two of them hash differently
kernel_new() { head -c 300000 /dev/urandom > "$1"; }
initramfs() { head -c 90000 /dev/urandom > "$1"; }

kernel_new "$tmp/vmlinuz-a"
kernel_new "$tmp/vmlinuz-b"
initramfs "$tmp/initramfs-a.img"
cp "$tmp/initramfs-a.img" "$tmp/initramfs-b.img"
cmdline='console=ttyS0,115200 rdinit=/init panic=1 holy.root=/dev/vda3 holy.rootfstype=ext4'

expect() {
    want=$1; shift
    rc=0
    "$@" >"$tmp/out" 2>"$tmp/err" || rc=$?
    if test "$rc" != "$want"; then
        printf 'rollback fixture: %s returned %s, expected %s\n' "$1" "$rc" "$want" >&2
        cat "$tmp/out" "$tmp/err" >&2
        exit 1
    fi
}

# the generator refuses a slot name that is not a or b, and a file that is not there,
# rather than writing an entry that cannot boot
expect 2 sh "$generate" c "$tmp/vmlinuz-a" "$tmp/initramfs-a.img" "$tmp/vmlinuz-b" \
    "$tmp/initramfs-b.img" "$cmdline"
grep -q 'CURRENT is a or b' "$tmp/err"
expect 1 sh "$generate" a "$tmp/absent" "$tmp/initramfs-a.img" "$tmp/vmlinuz-b" \
    "$tmp/initramfs-b.img" "$cmdline"
grep -q 'is not a file' "$tmp/err"

# two distinct kernels, and the current slot is named by path
sh "$generate" a "$tmp/vmlinuz-a" "$tmp/initramfs-a.img" "$tmp/vmlinuz-b" \
    "$tmp/initramfs-b.img" "$cmdline" > "$tmp/good.conf"
expect 0 sh "$check" "$tmp/good.conf" a
grep -q 'slots distinct' "$tmp/out"
expect 0 sh "$check" "$tmp/good.conf"
# the current slot is what a new boot lands on, so naming the other one is a failure
expect 4 sh "$check" "$tmp/good.conf" b
grep -q 'not the current slot b' "$tmp/err"

# a slot switch is one token in the file, and it is the whole rollback
sed 's|^default_entry: Holy a$|default_entry: Holy b|' "$tmp/good.conf" > "$tmp/flipped.conf"
expect 0 sh "$check" "$tmp/flipped.conf" b
expect 4 sh "$check" "$tmp/flipped.conf" a

# every shape the loader would refuse, or that leaves nothing to choose, is refused by
# name rather than at the machine
sed 's/^timeout: 5/timeout: 0/' "$tmp/good.conf" > "$tmp/timeout0.conf"
expect 4 sh "$check" "$tmp/timeout0.conf" a
grep -q 'without a menu' "$tmp/err"

sed 's/^timeout: 5/timeout: no/' "$tmp/good.conf" > "$tmp/timeoutno.conf"
expect 4 sh "$check" "$tmp/timeoutno.conf" a

sed 's/^hash_mismatch_panic: no/hash_mismatch_panic: yes/' "$tmp/good.conf" > "$tmp/panic.conf"
expect 4 sh "$check" "$tmp/panic.conf" a
grep -q 'panics instead of returning' "$tmp/err"

{ cat "$tmp/good.conf"; printf 'remember_last_entry: yes\n'; } > "$tmp/remember.conf"
expect 4 sh "$check" "$tmp/remember.conf" a
grep -q 'remember_last_entry' "$tmp/err"

sed 's|^default_entry: Holy a$|default_entry: 1|' "$tmp/good.conf" > "$tmp/index.conf"
expect 4 sh "$check" "$tmp/index.conf" a
grep -q 'a position rather than a slot path' "$tmp/err"

sed 's|^default_entry: Holy a$|default_entry: Holy c|' "$tmp/good.conf" > "$tmp/absent.conf"
expect 4 sh "$check" "$tmp/absent.conf"

# a leading slash is how limine reads the start of a new entry, so a default written
# that way names nothing and every boot stops in the menu. this is the shape the old
# generator wrote, and the checker required, so it is refused by name
sed 's|^default_entry: Holy a$|default_entry: /Holy a|' "$tmp/good.conf" > "$tmp/slash.conf"
expect 4 sh "$check" "$tmp/slash.conf" a
grep -q 'a leading slash makes limine read it as a new entry' "$tmp/err"

# one entry is not a rollback
sed '/^\/Holy b$/,$d' "$tmp/good.conf" > "$tmp/one.conf"
expect 4 sh "$check" "$tmp/one.conf" a
grep -q 'one entry is not a rollback' "$tmp/err"

# a digest of another length is a config the loader panics on
sed 's/\(#[0-9a-f]\{64\}\)[0-9a-f]*/\1/' "$tmp/good.conf" > "$tmp/short.conf"
expect 4 sh "$check" "$tmp/short.conf" a
grep -q 'character digest, not 128' "$tmp/err"

# a path with no digest at all is a slot whose bytes nothing vouches for
sed 's|\(kernel_path: boot():/vmlinuz-a\)#[0-9a-f]*|\1|' "$tmp/good.conf" > "$tmp/nohash.conf"
expect 4 sh "$check" "$tmp/nohash.conf" a

# a fresh install has one kernel in both slots, which is reported rather than refused,
# and a rollback gate asks for the two to differ
cp "$tmp/vmlinuz-a" "$tmp/vmlinuz-b"
sh "$generate" a "$tmp/vmlinuz-a" "$tmp/initramfs-a.img" "$tmp/vmlinuz-b" \
    "$tmp/initramfs-b.img" "$cmdline" > "$tmp/fresh.conf"
expect 0 sh "$check" "$tmp/fresh.conf" a
grep -q 'slots identical' "$tmp/out"
grep -q 'not yet possible' "$tmp/err"
expect 4 sh "$check" "$tmp/fresh.conf" a --distinct
grep -q 'nothing to roll back to' "$tmp/err"

# the digests in the file are the digests of the files, so a slot cannot claim to be
# something it is not
for slot in a b; do
    for kind in vmlinuz initramfs; do
        case $kind in
            vmlinuz) name="$tmp/vmlinuz-$slot" ;;
            *) name="$tmp/initramfs-$slot.img" ;;
        esac
        grep -q "$(b2sum "$name" | cut -d' ' -f1)" "$tmp/good.conf" ||
            { printf 'rollback fixture: %s digest is not in the config\n' "$name" >&2; exit 1; }
    done
done

# a hash that does not match the file is what returns the machine to the menu, so the
# checker has to accept a config that carries one rather than refuse it as malformed.
# the digest keeps its length and loses only its first character, so this is a config
# the loader reads and then rejects at the file, not a config it cannot parse
other=$(printf 'f%.0s' $(seq 128))
awk -v repl="$other" '
    /vmlinuz-a#/ { sub(/#[0-9a-f]+$/, "#" repl) }
    { print }
' "$tmp/good.conf" > "$tmp/mismatch.conf"
grep -q "vmlinuz-a#$other" "$tmp/mismatch.conf" ||
    { printf 'rollback fixture: the digest was not replaced\n' >&2; exit 1; }
expect 0 sh "$check" "$tmp/mismatch.conf" a
grep -q 'slots distinct' "$tmp/out"

printf 'rollback config fixtures passed\n'
