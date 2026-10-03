#!/bin/sh
# llm.txt is generated from the man sources, which the specification makes normative.
# a man page edited without regenerating it ships a document that contradicts the source
# it claims to carry, so the committed file has to be what the sources produce.
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"
committed=llm.txt
pages=$(ls man/*.[578])
tmp=$(mktemp "${TMPDIR:-/tmp}/holy-llm.XXXXXX")
render=$(mktemp "${TMPDIR:-/tmp}/holy-llm-render.XXXXXX")
trap 'rm -f "$tmp" "$render"' EXIT HUP INT TERM
for page in $pages; do
    name=${page##*/}
    hash=$(sha256sum "$page")
    hash=${hash%% *}
    printf '%s source=holy version=development sha256=%s\n' "$name" "$hash" >> "$tmp"
    GROFF_NO_SGR=1 groff -Tascii -man "$page" > "$render"
    col -b < "$render" >> "$tmp"
done
chmod 0644 "$tmp"
if test ! -f "$committed"; then
    echo "holy-llm: $committed is missing; run make llm.txt" >&2
    exit 1
fi
if cmp -s "$committed" "$tmp"; then
    printf 'llm.txt matches the %d man sources\n' "$(printf '%s\n' $pages | wc -l)"
    exit 0
fi
echo "holy-llm: $committed does not match the man sources; run make llm.txt" >&2
diff -u "$committed" "$tmp" | head -20 >&2 || true
exit 1
