#!/bin/sh
set -eu
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
umask 077
out=$tmp/llm.txt
printf 'original\n' > "$out"
if sh tools/docs.sh "$out" man/holy.conf.5 "$tmp/missing.5" > "$tmp/stdout" 2> "$tmp/stderr"; then exit 1; fi
grep -qx original "$out"
sh tools/docs.sh "$out" man/*.[578]
test "$(stat -c %a "$out")" = 644
test "$(find "$tmp" -type f | wc -l)" -eq 3
for page in man/*.[578]; do
    name=${page##*/}
    digest=$(sha256sum "$page")
    digest=${digest%% *}
    grep -q "^$name source=holy version=development sha256=$digest$" "$out"
done
printf 'docs fixtures passed\n'
