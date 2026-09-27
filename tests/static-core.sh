#!/bin/sh
set -eu
bin=$(realpath "$1")
package=$(realpath "$2")
command -v doas >/dev/null && doas -n true || {
    printf 'static core fixture requires noninteractive doas\n' >&2
    exit 6
}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
umask 022
root="$tmp/root"
mkdir -p "$root/usr/bin" "$root/tmp" "$root/input" \
    "$root/usr/share/licenses/busybox" "$root/usr/share/licenses/musl"
cp "$bin" "$root/usr/bin/holypkg"
cp "$package" "$root/input/busybox.holy"
uid=$(id -u)
gid=$(id -g)
guest() {
    doas -n chroot --userspec="$uid:$gid" "$root" /usr/bin/holypkg "$@"
}
test ! -e "$root/lib"
test ! -e "$root/lib64"
test ! -e "$root/usr/lib"
guest elf /usr/bin/holypkg > "$tmp/elf"
grep -qx 'runtime nolibc' "$tmp/elf"
grep -qx 'e_type 2' "$tmp/elf"
guest info local:/input/busybox.holy > "$tmp/out"
guest verify local:/input/busybox.holy > "$tmp/out"
guest db init --root / > "$tmp/out"
guest cache stage local:/input/busybox.holy --root / > "$tmp/out"
digest=$(sha256sum "$package")
digest=${digest%% *}
rm "$root/input/busybox.holy"
for iteration in 1 2; do
    guest cache verify "$digest" --root / > "$tmp/out"
    guest db reserve "$digest" --root / > "$tmp/out"
    guest db plan --root / > "$tmp/out"
    plan=$(sed -n 's/.* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
    test "${#plan}" -eq 64
    guest db approve "$plan" --root / > "$tmp/out"
    guest db apply --root / > "$tmp/out"
    guest db check "$digest" --root / > "$tmp/out"
    doas -n chroot --userspec="$uid:$gid" "$root" /usr/bin/busybox ash -c '
        test ! -e /lib && test ! -e /lib64 && test ! -e /usr/lib || exit 1
        /usr/bin/busybox test -s /usr/share/licenses/musl/COPYRIGHT || exit 1
        /usr/bin/busybox printf "static-core-pass\n"
    ' > "$tmp/shell"
    grep -qx static-core-pass "$tmp/shell"
    guest db rm "$digest" --root / > "$tmp/out"
    test ! -e "$root/usr/bin/busybox"
done
guest db status --root / > "$tmp/out"
grep -qx 'generation 4' "$tmp/out"
core=$(sha256sum "$bin")
core=${core%% *}
printf 'static core chroot fixture passed holypkg=%s busybox=%s\n' "$core" "$digest"
