#!/bin/sh
set -eu
out=$1
shift
tmp=$(mktemp "${out}.tmp.XXXXXX")
render=
cleanup() {
    rm -f "$tmp"
    if [ -n "$render" ]; then rm -f "$render"; fi
}
trap cleanup EXIT HUP INT TERM
render=$(mktemp "${out}.render.XXXXXX")
for page do
    name=${page##*/}
    hash=$(sha256sum "$page")
    hash=${hash%% *}
    printf '%s source=holy version=development sha256=%s\n' "$name" "$hash" >> "$tmp"
    GROFF_NO_SGR=1 groff -Tascii -man "$page" > "$render"
    col -b < "$render" >> "$tmp"
done
chmod 0644 "$tmp"
mv "$tmp" "$out"
