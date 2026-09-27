#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/root"
tree="$tmp/tree"
db="$root/var/lib/holypkg"
mkdir -p "$root/usr/share"
expect() {
    wanted=$1
    shift
    if "$@" > "$tmp/out" 2> "$tmp/err"; then actual=0; else actual=$?; fi
    test "$actual" -eq "$wanted" || { cat "$tmp/out" "$tmp/err"; exit 1; }
}
hash() { sha256sum "$tmp/$1.holy" | cut -d ' ' -f 1; }
plan() { sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out"; }
"$bin" db init --root "$root" > "$tmp/out"
expect 0 "$bin" orphan --root "$root" --json
grep -q '"installed":0,"explicit":0,"reachable":0,"orphans":0' "$tmp/out"
for name in a b app other detached; do
    rm -rf "$tree"
    mkdir -p "$tree/HOLY" "$tree/DATA/usr/share"
    printf 'format holy-package-1\nname %s\nversion 1\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' "$name" > "$tree/HOLY/meta"
    for field in deps provides hooks origin transform; do : > "$tree/HOLY/$field"; done
    case "$name" in a|other) dep=b ;; b|app) dep=a ;; *) dep= ;; esac
    if test -n "$dep"; then
        printf 'require edge-1 %s package %s any any any - %s metadata\n' "$name" "$dep" "$dep" > "$tree/HOLY/deps"
    fi
    printf '%s\n' "$name" > "$tree/DATA/usr/share/$name"
    "$bin" manifest generate "$tree" --output "$tmp/files" > "$tmp/out"
    mv "$tmp/files" "$tree/HOLY/files"
    "$bin" pack "$tree" --output "$tmp/$name.holy" > "$tmp/out"
    "$bin" cache stage "local:$tmp/$name.holy" --root "$root" > "$tmp/out"
done
a=$(hash a) b=$(hash b) app=$(hash app) other=$(hash other) detached=$(hash detached)
expect 0 "$bin" db plan-set "$app" "$a" "$b" --root "$root"
expected=$(plan)
expect 0 "$bin" db apply-set "$expected" "$app" "$a" "$b" --root "$root"
expect 0 "$bin" orphan --root "$root" --json
grep -q '"installed":3,"explicit":1,"reachable":3,"orphans":0' "$tmp/out"
expect 0 "$bin" db plan-set "$other" --root "$root"
expected=$(plan)
expect 0 "$bin" db apply-set "$expected" "$other" --root "$root"
expect 0 "$bin" db rm "$app" --root "$root"
expect 0 "$bin" orphan --root "$root" --json
grep -q '"installed":3,"explicit":1,"reachable":3,"orphans":0' "$tmp/out"
expect 0 "$bin" db rm "$other" --root "$root"
expect 0 "$bin" orphan --root "$root" --json
cp "$tmp/out" "$tmp/cycle.json"
python3 - "$tmp/cycle.json" "$a" "$b" <<'PY'
import json,sys
events=[json.loads(x) for x in open(sys.argv[1])]
assert [x['artifact'] for x in events[:-1]]==sorted(sys.argv[2:])
assert all(x['reason']=='unreachable-from-explicit' for x in events[:-1])
assert events[-1]['installed']==2 and events[-1]['reachable']==0 and events[-1]['orphans']==2
PY
expect 0 "$bin" db plan-set "$detached" --root "$root"
expected=$(plan)
expect 0 "$bin" db apply-set "$expected" "$detached" --root "$root"
expect 0 "$bin" orphan --json --root "$root"
grep -q '"installed":3,"explicit":1,"reachable":1,"orphans":2' "$tmp/out"
expect 0 "$bin" db reserve "$app" --root "$root"
expect 5 "$bin" orphan --root "$root" --json
grep -q '"code":"incomplete-transaction"' "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
expect 0 "$bin" db cancel --root "$root"
rm "$root/var/cache/holypkg/objects/sha256/"*.holy
if test "${HOLY_ORPHAN_CHROOT:-0}" = 1; then
    command -v doas >/dev/null && doas -n true || exit 6
    test ! -e "$root/lib" && test ! -e "$root/lib64" && test ! -e "$root/usr/lib"
    expect 0 "$bin" orphan --root "$root" --json
    cp "$tmp/out" "$tmp/expected-json"
    cp "$bin" "$root/orphan-client"
    expect 0 doas -n chroot --userspec="$(id -u):$(id -g)" "$root" /orphan-client orphan --root / --json
    cmp "$tmp/out" "$tmp/expected-json"
    rm "$root/orphan-client"
fi
snapshot() {
    python3 - "$root" <<'PY'
import hashlib,os,pathlib,stat,sys
for p in sorted(pathlib.Path(sys.argv[1]).rglob('*')):
 s=p.lstat()
 print(str(p),s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,
       hashlib.sha256(p.read_bytes()).hexdigest() if stat.S_ISREG(s.st_mode) else '')
PY
}
snapshot > "$tmp/before"
expect 0 "$bin" orphan --root "$root"
grep -q '^orphan .* "a" reason=dependency unreachable-from-explicit$' "$tmp/out"
grep -q '^orphan .* "b" reason=dependency unreachable-from-explicit$' "$tmp/out"
snapshot > "$tmp/after"
cmp "$tmp/before" "$tmp/after"
mv "$db/installed/$a" "$tmp/missing"
expect 4 "$bin" orphan --root "$root" --json
grep -q '"code":"missing-provider"' "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
mv "$tmp/missing" "$db/installed/$a"
cp "$db/installed/$a/graph" "$tmp/graph"
printf corrupt > "$db/installed/$a/graph"
expect 1 "$bin" orphan --root "$root" --json
test "$(wc -l < "$tmp/out")" -eq 1
cp "$tmp/graph" "$db/installed/$a/graph"
expect 0 "$bin" orphan --root "$root" --json
cp "$db/installed/$a/state" "$tmp/state"
python3 - "$db/installed/$a" <<'PY'
import hashlib,pathlib,re,sys
p=pathlib.Path(sys.argv[1]);data=b'format not-a-resolution\n'
(p/'graph').write_bytes(data)
s=(p/'state').read_text()
(p/'state').write_text(re.sub(r'graph [0-9a-f]{64}', 'graph '+hashlib.sha256(data).hexdigest(),s))
PY
expect 1 "$bin" orphan --root "$root" --json
test "$(wc -l < "$tmp/out")" -eq 1
cp "$tmp/state" "$db/installed/$a/state"
cp "$tmp/graph" "$db/installed/$a/graph"
cp "$db/installed/$detached/state" "$tmp/legacy-state"
mv "$db/installed/$detached/graph" "$tmp/legacy-graph"
mv "$db/installed/$detached/provides" "$tmp/legacy-provides"
sed -e 's/holy-instance-4/holy-instance-1/' -e '/^graph /d; /^provides /d; /^source-record /d' "$tmp/legacy-state" > "$db/installed/$detached/state"
expect 6 "$bin" orphan --root "$root" --json
grep -q '"code":"unknown-installed-graph"' "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
cp "$tmp/legacy-state" "$db/installed/$detached/state"
mv "$tmp/legacy-graph" "$db/installed/$detached/graph"
mv "$tmp/legacy-provides" "$db/installed/$detached/provides"
cp "$db/installed/$a/meta" "$tmp/meta"
python3 - "$db/installed/$a/meta" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1]);p.write_text(p.read_text().replace('name a\n','name "имя \\"тест\\""\n'))
PY
expect 0 "$bin" orphan --root "$root" --json
python3 - "$tmp/out" "$a" <<'PY'
import json,sys
records=[json.loads(x) for x in open(sys.argv[1])]
assert next(x['name'] for x in records if x.get('artifact')==sys.argv[2])=='имя "тест"'
PY
cp "$tmp/meta" "$db/installed/$a/meta"
expect 2 "$bin" orphan --root "$root" --root "$root"
expect 2 "$bin" orphan --json --json
printf 'orphan graph fixtures passed\n'
