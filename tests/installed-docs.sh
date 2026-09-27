#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
umask 022
root="$tmp/root"
tree="$tmp/tree"
mkdir -p "$root/usr/share/man/man1" "$root/usr/share/man/ru/man1" "$root/etc"
printf 'private-config-value\n' > "$root/etc/private"
expect() {
    wanted=$1
    shift
    rc=0
    "$@" > "$tmp/out" 2> "$tmp/err" || rc=$?
    test "$rc" -eq "$wanted" || { cat "$tmp/out" "$tmp/err"; exit 1; }
}
"$bin" db init --root "$root" > "$tmp/out"
expect 0 "$bin" docs --root "$root" --output "$tmp/empty"
grep -qx 'summary generation 0 packages 0 pages 0 aliases 0 missing-man 0 omitted 0' "$tmp/empty"
for name in first second nodocs; do
    rm -rf "$tree"
    mkdir -p "$tree/HOLY" "$tree/DATA/usr/share"
    printf 'format holy-package-1\nname %s\nversion 1.2\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' "$name" > "$tree/HOLY/meta"
    for field in deps provides hooks origin transform; do : > "$tree/HOLY/$field"; done
    case "$name" in
        first)
            mkdir -p "$tree/DATA/usr/share/man/man1"
            printf '.TH PROBE 1\n.SH NAME\nprobe \\- first provider\n' > "$tree/DATA/usr/share/man/man1/probe.1"
            printf '.TH COMPRESSED 1\n.SH NAME\ncompressed \\- compressed source\n' | gzip -n > "$tree/DATA/usr/share/man/man1/compressed.1.gz"
            ln -s probe.1 "$tree/DATA/usr/share/man/man1/alias.1"
            printf 'unknown codec\n' > "$tree/DATA/usr/share/man/man1/unsupported.1.lz"
            ;;
        second)
            mkdir -p "$tree/DATA/usr/share/man/ru/man1"
            printf '.TH PROBE 1\n.SH NAME\nprobe \\- second provider\n' > "$tree/DATA/usr/share/man/ru/man1/probe.1"
            ;;
        nodocs) printf 'ordinary data\n' > "$tree/DATA/usr/share/data" ;;
    esac
    "$bin" manifest generate "$tree" --output "$tmp/files" > "$tmp/out"
    mv "$tmp/files" "$tree/HOLY/files"
    "$bin" pack "$tree" --output "$tmp/$name.holy" > "$tmp/out"
    "$bin" cache stage "local:$tmp/$name.holy" --root "$root" > "$tmp/out"
    digest=$(sha256sum "$tmp/$name.holy" | cut -d ' ' -f 1)
    "$bin" db reserve "$digest" --root "$root" > "$tmp/out"
    expect 5 "$bin" docs --root "$root" --output "$tmp/pending"
    test ! -e "$tmp/pending"
    "$bin" db plan --root "$root" > "$tmp/out"
    plan=$(sed -n 's/.* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
    "$bin" db approve "$plan" --root "$root" > "$tmp/out"
    "$bin" db apply --root "$root" > "$tmp/out"
done
expect 0 "$bin" docs --root "$root" --output "$tmp/bundle"
grep -qx 'summary generation 3 packages 3 pages 3 aliases 1 missing-man 1 omitted 1' "$tmp/bundle"
grep -q '^omitted-man .*unsupported-name-or-codec$' "$tmp/bundle"
test "$(grep -c '^page name "probe" section "1"' "$tmp/bundle")" -eq 2
grep -q 'compressed source' "$tmp/bundle"
grep -q '^missing-man .*package "nodocs" version "1.2" source-id "-"$' "$tmp/bundle"
! grep -q 'private-config-value' "$tmp/bundle"
cp "$tmp/bundle" "$tmp/expected"
if test "${HOLY_DOCS_CHROOT:-0}" = 1; then
    command -v doas >/dev/null && doas -n true || exit 6
    test ! -e "$root/lib" && test ! -e "$root/lib64" && test ! -e "$root/usr/lib"
    cp "$bin" "$root/docs-client"
    expect 0 doas -n chroot --userspec="$(id -u):$(id -g)" "$root" \
        /docs-client docs --root / --output /bundle
    cmp "$root/bundle" "$tmp/expected"
    rm "$root/docs-client" "$root/bundle"
fi
expect 1 "$bin" docs --root "$root" --output "$tmp/bundle"
cmp "$tmp/bundle" "$tmp/expected"
cp "$root/usr/share/man/man1/probe.1" "$tmp/page"
printf changed > "$root/usr/share/man/man1/probe.1"
expect 4 "$bin" docs --root "$root" --output "$tmp/changed"
test ! -e "$tmp/changed"
cp "$tmp/page" "$root/usr/share/man/man1/probe.1"
rm "$root/usr/share/man/man1/alias.1"
ln -s /etc/private "$root/usr/share/man/man1/alias.1"
expect 4 "$bin" docs --root "$root" --output "$tmp/alias"
test ! -e "$tmp/alias"
rm "$root/usr/share/man/man1/alias.1"
ln -s probe.1 "$root/usr/share/man/man1/alias.1"
mv "$root/usr/share/man/man1" "$tmp/man1"
ln -s "$tmp/man1" "$root/usr/share/man/man1"
expect 4 "$bin" docs --root "$root" --output "$tmp/traversal"
test ! -e "$tmp/traversal"
test "$(cat "$root/var/lib/holypkg/generation")" = 3
printf 'installed documentation fixtures passed\n'
