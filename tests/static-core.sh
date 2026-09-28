#!/bin/sh
set -eu
bin=$(realpath "$1")
package=$(realpath "$2")
target32=0
if LC_ALL=C readelf -h "$bin" | grep -q 'Class:.*ELF32'; then
    LC_ALL=C readelf -h "$bin" | grep -q 'Machine:.*Intel 80386' || exit 6
    command -v setarch >/dev/null || exit 6
    target32=1
fi
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
    if test "$target32" = 1; then
        setarch i686 doas -n chroot --userspec="$uid:$gid" "$root" /usr/bin/holypkg "$@"
    else
        doas -n chroot --userspec="$uid:$gid" "$root" /usr/bin/holypkg "$@"
    fi
}
guest_shell() {
    if test "$target32" = 1; then
        setarch i686 doas -n chroot --userspec="$uid:$gid" "$root" /usr/bin/busybox ash -c "$1"
    else
        doas -n chroot --userspec="$uid:$gid" "$root" /usr/bin/busybox ash -c "$1"
    fi
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
    guest_shell '
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
if test -n "${3:-}"; then
    mkdir -p "$root/usr/share/man/man5" "$root/usr/share/man/man8" \
        "$root/usr/share/licenses/dinit"
    cp "$3" "$root/input/dinit.holy"
    guest cache stage local:/input/dinit.holy --root / > "$tmp/out"
    dinit=$(sha256sum "$3")
    dinit=${dinit%% *}
    rm "$root/input/dinit.holy"
    guest db reserve "$dinit" --root / > "$tmp/out"
    guest db plan --root / > "$tmp/out"
    plan=$(sed -n 's/.* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
    test "${#plan}" -eq 64
    guest db approve "$plan" --root / > "$tmp/out"
    guest db apply --root / > "$tmp/out"
    guest db check "$dinit" --root / > "$tmp/out"
    test "$(readlink "$root/usr/bin/reboot")" = shutdown
    test "$(readlink "$root/usr/share/man/man8/reboot.8")" = shutdown.8
    guest db rm "$dinit" --root / > "$tmp/out"
    test ! -e "$root/usr/bin/dinit"
    test ! -L "$root/usr/bin/reboot"
    test ! -L "$root/usr/share/man/man8/reboot.8"
    printf 'static core dinit transaction passed artifact=%s\n' "$dinit"
fi
core=$(sha256sum "$bin")
core=${core%% *}
printf 'static core chroot fixture passed holypkg=%s busybox=%s\n' "$core" "$digest"
