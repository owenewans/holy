#!/bin/sh
set -eu
out=$1
shift
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT HUP INT TERM
for page do
    name=${page##*/}
    hash=$(sha256sum "$page" | cut -d ' ' -f 1)
    printf '%s source=holy version=development sha256=%s\n' "$name" "$hash" >> "$tmp"
    GROFF_NO_SGR=1 groff -Tascii -man "$page" | col -b >> "$tmp"
done
mv "$tmp" "$out"
