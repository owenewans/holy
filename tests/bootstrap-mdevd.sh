#!/bin/sh
set -eu
test "$#" -eq 2 || exit 2
bin=$(realpath "$1")
package=$(realpath "$2")
for tool in doas unshare chroot timeout; do
    command -v "$tool" >/dev/null || { echo "$tool required" >&2; exit 6; }
done
doas -n unshare --net true || exit 6
umask 022
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/root"
mkdir -p "$root/usr/bin" "$root/usr/include/mdevd" "$root/usr/share/doc/mdevd" \
    "$root/usr/share/licenses/mdevd" "$root/usr/share/licenses/skalibs" "$root/etc" "$root/dev"
"$bin" db init --root "$root" > "$tmp/out"
"$bin" cache stage "local:$package" --root "$root" > "$tmp/out"
digest=$(sha256sum "$package")
digest=${digest%% *}
"$bin" db reserve "$digest" --root "$root" > "$tmp/out"
"$bin" db plan --root "$root" > "$tmp/out"
plan=$(sed -n 's/.* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
test "${#plan}" -eq 64
"$bin" db approve "$plan" --root "$root" > "$tmp/out"
"$bin" db apply --root "$root" > "$tmp/out"
test ! -e "$root/lib" && test ! -e "$root/lib64" && test ! -e "$root/usr/lib"
printf 'root:x:0:0:root:/:/usr/bin/false\n' > "$root/etc/passwd"
printf 'root:x:0:\n' > "$root/etc/group"
printf 'null root:root 0666\n' > "$root/etc/mdev.conf"
probe() {
    doas -n timeout -k 2 10 unshare --net chroot --userspec="$(id -u):$(id -g)" \
        "$root" /usr/bin/mdevd -N -f /etc/mdev.conf
}
probe > "$tmp/probe.log" 2>&1 || { cat "$tmp/probe.log" >&2; exit 1; }
printf '[ root:root 0666\n' > "$root/etc/mdev.conf"
rc=0
probe > "$tmp/invalid.log" 2>&1 || rc=$?
test "$rc" -eq 2 || { cat "$tmp/invalid.log" >&2; exit 1; }
"$bin" db check "$digest" --root "$root" > "$tmp/out"
"$bin" db rm "$digest" --root "$root" > "$tmp/out"
test ! -e "$root/usr/bin/mdevd" && test ! -e "$root/usr/bin/mdevd-coldplug"
printf 'mdevd static install/config/remove fixture passed artifact=%s\n' "$digest"
