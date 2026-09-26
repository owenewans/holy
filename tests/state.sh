#!/bin/sh
set -eu
bin=$1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir "$tmp/root" "$tmp/other" "$tmp/symlink" "$tmp/writable"
if "$bin" db status --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test ! -s "$tmp/out"
"$bin" db init --root "$tmp/root" > "$tmp/out"
grep -qx 'generation 0' "$tmp/out"
db="$tmp/root/var/lib/holypkg"
test -d "$db/installed"
test -d "$db/transactions"
test -d "$db/index"
test "$(stat -c %a "$db/generation")" = 600
"$bin" db status --root "$tmp/root" > "$tmp/out"
grep -qx 'generation 0' "$tmp/out"
printf '7\n' > "$db/generation"
"$bin" db init --root "$tmp/root" > "$tmp/out"
grep -qx 'generation 7' "$tmp/out"
"$bin" db status --root "$tmp/root" > "$tmp/out"
grep -qx 'generation 7' "$tmp/out"
for invalid in '07' '-1' '18446744073709551616' 'garbage'; do
    printf '%s\n' "$invalid" > "$db/generation"
    if "$bin" db status --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
    test ! -s "$tmp/out"
    if "$bin" db init --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
    test ! -s "$tmp/out"
done
printf '7\n' > "$db/generation"
rm "$db/generation"
ln -s "$tmp/other" "$db/generation"
if "$bin" db status --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test ! -s "$tmp/out"
rm "$db/generation"
printf '7\n' > "$db/generation"
ln -s "$tmp/root/var" "$tmp/symlink/var"
if "$bin" db init --root "$tmp/symlink" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test ! -s "$tmp/out"
chmod 777 "$tmp/writable"
if "$bin" db init --root "$tmp/writable" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test ! -e "$tmp/writable/var"
test -z "$(find "$db" -name '.holy-tmp-*' -print)"
printf 'database fixtures passed\n'
