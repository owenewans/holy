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
"$bin" info "local:$package" > "$tmp/info"
arch=$(sed -n 's/^arch //p' "$tmp/info")
set --
case "$arch:$(uname -m)" in
    x86_64:x86_64|x86:i686) ;;
    *) set -- --accept-arch "$digest" ;;
esac
"$bin" db plan-set "$digest" "$@" --root "$tmp/root" > "$tmp/out"
plan=$(sed -n 's/.* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
test "${#plan}" -eq 64
"$bin" db apply-set "$plan" "$digest" "$@" --root "$tmp/root" > "$tmp/out"
"$bin" elf "$tmp/root/usr/bin/busybox" > "$tmp/out"
grep -qx 'runtime nolibc' "$tmp/out"
grep -qx "machine $arch" "$tmp/out"
"$tmp/root/usr/bin/busybox" --list > "$tmp/applets"
for applet in ip nslookup udhcpc; do grep -qx "$applet" "$tmp/applets"; done
if [ "$arch" = x86 ]; then
    command -v qemu-i386 >/dev/null || exit 6
    qemu-i386 -cpu pentium2 "$tmp/root/usr/bin/busybox" ash -c 'printf "i686 shell\n"' > "$tmp/emulator"
    grep -qx 'i686 shell' "$tmp/emulator"
fi
doas -n chroot --userspec="$(id -u):$(id -g)" "$tmp/root" /usr/bin/busybox ash -c '
    test ! -e /lib && test ! -e /lib64 && test ! -e /usr/lib || exit 1
    /usr/bin/busybox test -s /usr/share/licenses/busybox/LICENSE || exit 1
    /usr/bin/busybox test -s /usr/share/licenses/musl/COPYRIGHT || exit 1
    test -n "$(/usr/bin/busybox ip link show lo)" || exit 1
    /usr/bin/busybox printf "static shell without dynamic libc\n"
' > "$tmp/shell"
grep -qx 'static shell without dynamic libc' "$tmp/shell"
"$bin" db check "$digest" --root "$tmp/root" > "$tmp/out"
"$bin" db rm "$digest" --root "$tmp/root" > "$tmp/out"
test ! -e "$tmp/root/usr/bin/busybox"
printf 'BusyBox static chroot fixture passed artifact=%s\n' "$digest"
