#!/bin/sh
set -eu
test "$#" -eq 2 || exit 2
if test "${HOLY_DOAS_CHECK_NAMESPACE:-}" != 1; then
    test "$(id -u)" != 0 || exit 6
    export HOLY_DOAS_CHECK_NAMESPACE=1
    exec unshare --map-root-user -- sh "$0" "$@"
fi
test "$(id -u)" = 0 || exit 6
bin=$(realpath "$1")
package=$(realpath "$2")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/root"
mkdir -p "$root/usr/bin" "$root/usr/share/man/man1" \
    "$root/usr/share/man/man5" "$root/usr/share/licenses/doas"
"$bin" verify "local:$package" > "$tmp/verify"
"$bin" db init --root "$root" > "$tmp/out"
"$bin" cache stage "local:$package" --root "$root" > "$tmp/out"
digest=$(sha256sum "$package")
digest=${digest%% *}
set -- "$digest"
if "$bin" info "local:$package" | grep -qx 'arch x86' && test "$(uname -m)" = x86_64; then
    set -- "$@" --accept-arch "$digest"
fi
if "$bin" db plan-set "$@" --root "$root" > "$tmp/out" 2> "$tmp/error"; then
    printf 'unapproved setuid package was accepted\n' >&2
    exit 1
else
    test "$?" -eq 3
fi
grep -q 'decision-required privileged' "$tmp/error"
"$bin" db plan-set "$@" --accept-privileged "$digest" --root "$root" > "$tmp/out"
plan=$(sed -n 's/.* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
test "${#plan}" -eq 64
if "$bin" db apply-set "$plan" "$@" --root "$root" > "$tmp/out" 2> "$tmp/error"; then
    printf 'unapproved setuid plan was applied\n' >&2
    exit 1
else
    test "$?" -eq 3
fi
test ! -e "$root/usr/bin/doas"
"$bin" db apply-set "$plan" "$@" --accept-privileged "$digest" --root "$root" > "$tmp/out"
test "$(stat -c '%a %u:%g' "$root/usr/bin/doas")" = '4755 0:0'
grep -qx "privileged $digest" "$root/var/lib/holypkg/installed/$digest/state"
"$bin" elf "$root/usr/bin/doas" > "$tmp/elf"
grep -qx 'runtime nolibc' "$tmp/elf"
"$bin" db check "$digest" --root "$root" > "$tmp/out"
"$bin" db rm "$digest" --root "$root" > "$tmp/out"
test ! -e "$root/usr/bin/doas"
printf 'doas static setuid package fixture passed artifact=%s\n' "$digest"
