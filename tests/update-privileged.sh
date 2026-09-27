#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/root"
mkdir -p "$root/usr/bin"
case "$(uname -m)" in
    x86_64) arch=x86_64; bits=64; machine=elf_x86_64; exit_call='mov $60, %eax'; register=edi; instruction=syscall ;;
    i686) arch=x86; bits=32; machine=elf_i386; exit_call='mov $1, %eax'; register=ebx; instruction='int $0x80' ;;
    *) echo 'x86 or x86_64 required' >&2; exit 6 ;;
esac
expect() {
    expected=$1
    shift
    if "$@" > "$tmp/out" 2> "$tmp/err"; then actual=0; else actual=$?; fi
    test "$actual" -eq "$expected" || { cat "$tmp/out" "$tmp/err"; exit 1; }
}
package() {
    version=$1
    tree="$tmp/tree-$version"
    mkdir -p "$tree/HOLY" "$tree/DATA/usr/bin"
    printf 'format holy-package-1\nname privileged-update\nversion %s\nrelease 1\nos linux\narch %s\nlibc nolibc\n' \
        "$version" "$arch" > "$tree/HOLY/meta"
    for field in deps provides hooks origin transform; do : > "$tree/HOLY/$field"; done
    printf '.global _start\n_start:\n mov $%s, %%%s\n %s\n %s\n' \
        "$version" "$register" "$exit_call" "$instruction" > "$tmp/probe-$version.s"
    as --"$bits" -o "$tmp/probe-$version.o" "$tmp/probe-$version.s"
    ld -m "$machine" -o "$tree/DATA/usr/bin/privileged-update" "$tmp/probe-$version.o"
    if test "$version" != 3; then chmod 4755 "$tree/DATA/usr/bin/privileged-update"; fi
    "$bin" manifest generate "$tree" --output "$tmp/files" > /dev/null
    mv "$tmp/files" "$tree/HOLY/files"
    "$bin" pack "$tree" --output "$tmp/$version.holy" > /dev/null
    "$bin" cache stage "local:$tmp/$version.holy" --root "$root" > /dev/null
}
hash() { sha256sum "$tmp/$1.holy" | cut -d ' ' -f 1; }
plan_hash() { sed -n 's/^plan-update sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out"; }
"$bin" db init --root "$root" > /dev/null
package 1
package 2
package 3
old=$(hash 1)
next=$(hash 2)
plain=$(hash 3)
expect 3 "$bin" db plan-set "$old" --root "$root"
expect 0 "$bin" db plan-set "$old" --accept-privileged "$old" --root "$root"
set_plan=$(sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
expect 0 "$bin" db apply-set "$set_plan" "$old" --accept-privileged "$old" --root "$root"
test "$(stat -c '%a' "$root/usr/bin/privileged-update")" = 4755
expect 3 "$bin" db plan-update "$old" "$next" --root "$root"
grep -q 'decision-required privileged update' "$tmp/err"
expect 2 "$bin" db plan-update "$old" "$next" --accept-privileged "$plain" --root "$root"
expect 0 "$bin" db plan-update "$old" "$next" --accept-privileged "$next" --root "$root"
grep -qx "accept-privileged $next" "$tmp/out"
approved=$(plan_hash)
test "${#approved}" -eq 64
expect 3 "$bin" db apply-update "$approved" "$old" "$next" --root "$root"
test "$(stat -c '%a' "$root/usr/bin/privileged-update")" = 4755
if "$bin" elf "$bin" | grep -q '^interpreter /'; then
    gcc -shared -fPIC -o "$tmp/fault.so" "$(dirname "$0")/update-fault.c" -ldl
    expect 5 env LD_PRELOAD="$tmp/fault.so" HOLY_UPDATE_FAULT=no-space \
        HOLY_UPDATE_NEW="$next" "$bin" db apply-update "$approved" "$old" "$next" \
        --accept-privileged "$next" --root "$root"
    grep -qx "accept-privileged $next" "$root/var/lib/holypkg/transactions/update/journal"
    expect 0 "$bin" db recover --update --root "$root"
else
    expect 0 "$bin" db apply-update "$approved" "$old" "$next" \
        --accept-privileged "$next" --root "$root"
fi
test "$(stat -c '%a' "$root/usr/bin/privileged-update")" = 4755
grep -qx "privileged $next" "$root/var/lib/holypkg/installed/$next/state"
expect 0 "$bin" db check --all --root "$root"
expect 0 "$bin" db plan-update "$next" "$plain" --root "$root"
approved=$(plan_hash)
expect 0 "$bin" db apply-update "$approved" "$next" "$plain" --root "$root"
test "$(stat -c '%a' "$root/usr/bin/privileged-update")" = 755
if grep -q '^privileged ' "$root/var/lib/holypkg/installed/$plain/state"; then exit 1; fi
expect 0 "$bin" db check --all --root "$root"
printf 'privileged update approval and recovery fixtures passed\n'
