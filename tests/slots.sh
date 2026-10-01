#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/root"
tree="$tmp/tree"
mkdir -p "$root/usr/share"
expect() {
    wanted=$1
    shift
    if "$@" > "$tmp/out" 2> "$tmp/err"; then actual=0; else actual=$?; fi
    test "$actual" -eq "$wanted" || { cat "$tmp/out" "$tmp/err"; exit 1; }
}
plan() { sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out"; }
plan_set() {
    expect 0 "$bin" db plan-set "$@" --root "$root"
    approved=$(plan)
    expect 0 "$bin" db apply-set "$approved" "$@" --root "$root"
}

# one package tree per label, with the name, version, architecture and libc the case needs
package() {
    label=$1 name=$2 version=$3 arch=$4 libc=$5
    rm -rf "$tree"
    mkdir -p "$tree/HOLY" "$tree/DATA/usr/share"
    printf 'format holy-package-1\nname %s\nversion %s\nrelease 1\nos linux\narch %s\nlibc %s\n' \
        "$name" "$version" "$arch" "$libc" > "$tree/HOLY/meta"
    for field in deps provides hooks origin transform; do : > "$tree/HOLY/$field"; done
    printf '%s\n' "$label" > "$tree/DATA/usr/share/$label"
    "$bin" manifest generate "$tree" --output "$tmp/files" > "$tmp/out"
    mv "$tmp/files" "$tree/HOLY/files"
    "$bin" pack "$tree" --output "$tmp/$label.holy" > "$tmp/out"
    "$bin" cache stage "local:$tmp/$label.holy" --root "$root" > "$tmp/out"
    sha256sum "$tmp/$label.holy" | cut -d ' ' -f 1
}

"$bin" db init --root "$root" > "$tmp/out"
tool=$(package tool tool 1 noarch nolibc)
tool_next=$(package tool-x86_64 tool 1 x86_64 musl)
library=$(package library library 1 noarch nolibc)

# a root with nothing installed has no slots, and says so in both forms
expect 0 "$bin" db slots --root "$root"
test ! -s "$tmp/out"
expect 0 "$bin" db slots --root "$root" --json
grep -qxF '{"schema":"holy-db-slots-1","slots":[]}' "$tmp/out"

# two names are two slots
plan_set "$tool"
plan_set "$library"
expect 0 "$bin" db slots --root "$root"
grep -qx "slot library linux noarch nolibc source - occupied $library version 1 versions 1" "$tmp/out"
grep -qx "slot tool linux noarch nolibc source - occupied $tool version 1 versions 1" "$tmp/out"
expect 0 "$bin" db slots --root "$root" --json
grep -q -F '"schema":"holy-db-slots-1"' "$tmp/out"
test "$(grep -o -F '"name":"tool"' "$tmp/out" | wc -l)" -eq 1

# the source is part of the slot, so one name from two sources holds two slots
printf '[source alpha]\ntype holy-http\nurl "file://%s/mirror/"\n' "$tmp" > "$tmp/alpha.conf"
"$bin" source plan --config "$tmp/alpha.conf" --root "$root" > "$tmp/alpha.plan" 2> "$tmp/alpha.err"
alpha_plan=$(sha256sum "$tmp/alpha.plan" | cut -d ' ' -f 1)
alpha_source=$(sed -n 's/^add-source \([0-9a-f]*\) "alpha"$/\1/p' "$tmp/alpha.err")
test "${#alpha_source}" -eq 64
"$bin" source apply "$tmp/alpha.plan" --sha256 "$alpha_plan" --root "$root" > "$tmp/out"
expect 0 "$bin" db plan-set "$tool_next" --source "$tool_next=$alpha_source" --root "$root"
approved=$(plan)
expect 0 "$bin" db apply-set "$approved" "$tool_next" --source "$tool_next=$alpha_source" --root "$root"
expect 0 "$bin" db slots --root "$root"
grep -qx "slot tool linux x86_64 musl source $alpha_source occupied $tool_next version 1 versions 1" "$tmp/out"
grep -qx "slot tool linux noarch nolibc source - occupied $tool version 1 versions 1" "$tmp/out"
expect 0 "$bin" db slots --root "$root" --json
test "$(grep -o -F '"name":"tool"' "$tmp/out" | wc -l)" -eq 2
expect 0 "$bin" db check --all --root "$root"

# a replacement moves the slot: the family holds one version and the newest occupant
newer=$(package tool2 tool 2 noarch nolibc)
expect 0 "$bin" db plan-update "$tool" "$newer" --root "$root"
replacement=$(sed -n 's/^plan-update sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
test "${#replacement}" -eq 64
expect 0 "$bin" db apply-update "$replacement" "$tool" "$newer" --root "$root"
expect 0 "$bin" db slots --root "$root"
grep -qx "slot tool linux noarch nolibc source - occupied $newer version 2 versions 1" "$tmp/out"
test ! -d "$root/var/lib/holypkg/installed/$tool"
expect 0 "$bin" db check --all --root "$root"

# the slot a replacement moved keeps its arch and libc, so the report is stable
expect 0 "$bin" db slots --root "$root" --json
grep -q -F "\"occupied\":\"$newer\"" "$tmp/out"
grep -q -F "\"occupied\":\"$tool_next\"" "$tmp/out"

# a root with no database is reported as unavailable, the same as db status
if "$bin" db slots --root "$tmp/absent" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 1; fi
grep -qx 'holypkg: database status unavailable' "$tmp/err"
printf 'installed slot fixtures passed\n'