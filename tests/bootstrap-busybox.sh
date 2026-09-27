#!/bin/sh
set -eu
bin=$1
command -v doas >/dev/null && doas -n true || {
    printf 'bootstrap chroot fixture requires noninteractive doas\n' >&2
    exit 6
}
package=$(realpath "$2")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
umask 022
mkdir -p "$tmp/root/usr/bin" "$tmp/root/usr/share/licenses/busybox" "$tmp/root/usr/share/licenses/musl"
"$bin" verify "local:$package" > "$tmp/out"
"$bin" db init --root "$tmp/root" > "$tmp/out"
"$bin" cache stage "local:$package" --root "$tmp/root" > "$tmp/out"
digest=$(sha256sum "$package")
digest=${digest%% *}
"$bin" db reserve "$digest" --root "$tmp/root" > "$tmp/out"
"$bin" db plan --root "$tmp/root" > "$tmp/out"
plan=$(sed -n 's/.* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
test "${#plan}" -eq 64
"$bin" db approve "$plan" --root "$tmp/root" > "$tmp/out"
"$bin" db apply --root "$tmp/root" > "$tmp/out"
"$bin" elf "$tmp/root/usr/bin/busybox" > "$tmp/out"
grep -qx 'runtime nolibc' "$tmp/out"
doas -n chroot --userspec="$(id -u):$(id -g)" "$tmp/root" /usr/bin/busybox ash -c '
    test ! -e /lib && test ! -e /lib64 && test ! -e /usr/lib || exit 1
    /usr/bin/busybox test -s /usr/share/licenses/busybox/LICENSE || exit 1
    /usr/bin/busybox test -s /usr/share/licenses/musl/COPYRIGHT || exit 1
    /usr/bin/busybox printf "static shell without dynamic libc\n"
' > "$tmp/shell"
grep -qx 'static shell without dynamic libc' "$tmp/shell"
"$bin" db check "$digest" --root "$tmp/root" > "$tmp/out"
"$bin" db rm "$digest" --root "$tmp/root" > "$tmp/out"
test ! -e "$tmp/root/usr/bin/busybox"
printf 'BusyBox static chroot fixture passed artifact=%s\n' "$digest"
