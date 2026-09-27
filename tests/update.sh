#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/root"
tree="$tmp/tree"
mkdir -p "$root/usr/share"
expect() {
    expected=$1
    shift
    if "$@" > "$tmp/out" 2> "$tmp/err"; then actual=0; else actual=$?; fi
    test "$actual" -eq "$expected" || { cat "$tmp/out" "$tmp/err"; exit 1; }
}
package() {
    label=$1 name=$2 path=$3 dependency=$4
    mkdir -p "$tree/$label/HOLY" "$tree/$label/DATA/usr/share"
    printf 'format holy-package-1\nname %s\nversion %s\nrelease 1\nos linux\narch noarch\nlibc nolibc\nsource-name forged\n' "$name" "$label" > "$tree/$label/HOLY/meta"
    for field in deps provides hooks origin transform; do : > "$tree/$label/HOLY/$field"; done
    if test -n "$dependency"; then
        printf 'require dep-1 %s package %s any any any - %s metadata\n' "$name" "$dependency" "$dependency" > "$tree/$label/HOLY/deps"
    fi
    printf '%s\n' "$label" > "$tree/$label/DATA/usr/share/$path"
    "$bin" manifest generate "$tree/$label" --output "$tmp/files" > "$tmp/out"
    mv "$tmp/files" "$tree/$label/HOLY/files"
    "$bin" pack "$tree/$label" --output "$tmp/$label.holy" > "$tmp/out"
    "$bin" cache stage "local:$tmp/$label.holy" --root "$root" > "$tmp/out"
}
hash() { sha256sum "$tmp/$1.holy" | cut -d ' ' -f 1; }
set_hash() { sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out"; }
install() {
    expect 0 "$bin" db plan-set "$@" --root "$root"
    plan=$(set_hash)
    expect 0 "$bin" db apply-set "$plan" "$@" --root "$root"
}
register() {
    expect 0 "$bin" source plan --config "$tmp/config" --root "$root"
    cp "$tmp/out" "$tmp/source-plan"
    digest=$(sha256sum "$tmp/source-plan" | cut -d ' ' -f 1)
    expect 0 "$bin" source apply "$tmp/source-plan" --sha256 "$digest" --root "$root"
}
"$bin" db init --root "$root" > "$tmp/out"
package base1 base payload ''
package base2 base payload ''
package app app app base
package extra extra extra ''
package missing base payload absent
package collision base extra ''
package rename other payload ''
old=$(hash base1) new=$(hash base2) app=$(hash app) extra=$(hash extra)
install "$app" "$old"
install "$extra"
expect 0 "$bin" db plan-update "$old" "$new" --root "$root"
cp "$tmp/out" "$tmp/plan"
expect 0 "$bin" db plan-update "$old" "$new" --root "$root"
cmp "$tmp/plan" "$tmp/out"
python3 - "$tmp/plan" "$old" "$new" "$app" "$extra" <<'PY'
import hashlib, pathlib, shlex, sys
data = pathlib.Path(sys.argv[1]).read_bytes()
header, record = data.split(b'\n', 1)
assert header.decode().split() == ['plan-update', 'sha256', hashlib.sha256(record).hexdigest(), 'read-only']
rows = [shlex.split(line) for line in record.decode().splitlines()]
old, new, app, extra = sys.argv[2:]
assert ['old', old] in rows and ['new', new] in rows
assert ['source', '-', 'local'] in rows
assert {r[1] for r in rows if r[0] == 'instance'} == {old, app, extra}
assert {r[1] for r in rows if r[0] == 'artifact'} == {new, app, extra}
assert ['edge', app, 'dep-1', new, '-', 'package', 'base'] in rows
assert any(r[0] == 'change' and r[2] == 'replace' for r in rows)
PY
grep -qx base1 "$root/usr/share/payload"
expect 0 "$bin" db check --all --root "$root"
expect 4 "$bin" db plan-update "$old" "$(hash missing)" --root "$root"
test ! -s "$tmp/out"
expect 4 "$bin" db plan-update "$old" "$(hash collision)" --root "$root"
expect 4 "$bin" db plan-update "$old" "$(hash rename)" --root "$root"
expect 3 "$bin" db plan-update "$old" "$old" --root "$root"
expect 6 "$bin" db plan-update "$new" "$old" --root "$root"
expect 2 "$bin" db plan-update invalid "$new" --root "$root"
printf 'user change\n' > "$root/usr/share/payload"
expect 4 "$bin" db plan-update "$old" "$new" --root "$root"
printf 'base1\n' > "$root/usr/share/payload"
printf 'user change\n' > "$root/usr/share/extra"
expect 4 "$bin" db plan-update "$old" "$new" --root "$root"
printf 'extra\n' > "$root/usr/share/extra"
expect 0 "$bin" db reserve "$new" --root "$root"
expect 5 "$bin" db plan-update "$old" "$new" --root "$root"
expect 0 "$bin" db cancel --root "$root"
cache="$root/var/cache/holypkg/objects/sha256"
mv "$cache/$old.holy" "$tmp/old-cache"
expect 6 "$bin" db plan-update "$old" "$new" --root "$root"
mv "$tmp/old-cache" "$cache/$old.holy"
expect 0 "$bin" db plan-update "$old" "$new" --root "$root"
cmp "$tmp/plan" "$tmp/out"
mkdir -p "$tmp/second/usr/share"
cp -a "$root/." "$tmp/second/"
expect 0 "$bin" db plan-update "$old" "$new" --root "$tmp/second"
if cmp -s "$tmp/plan" "$tmp/out"; then exit 1; fi
cat > "$tmp/config" <<'EOF'
[source official]
type holy-http
url https://source.example/holy
EOF
register
expect 0 "$bin" source list --root "$root"
source=$(sed -n 's/^source \([0-9a-f]*\) "official" active$/\1/p' "$tmp/out")
package sourced1 sourced sourced ''
package sourced2 sourced sourced ''
first=$(hash sourced1) second=$(hash sourced2)
install "$first" --source "$first=$source"
expect 0 "$bin" db plan-update "$first" "$second" --root "$root"
cp "$tmp/out" "$tmp/sourced-plan"
grep -qx "source $source \"official\"" "$tmp/out"
sed 's/source official/source renamed/' "$tmp/config" > "$tmp/renamed"
mv "$tmp/renamed" "$tmp/config"
register
expect 0 "$bin" db plan-update "$first" "$second" --root "$root"
grep -qx "source $source \"renamed\"" "$tmp/out"
if cmp -s "$tmp/sourced-plan" "$tmp/out"; then exit 1; fi
: > "$tmp/config"
register
expect 6 "$bin" db plan-update "$first" "$second" --root "$root"
expect 0 "$bin" db check --all --root "$root"
printf 'update plan fixtures passed\n'
