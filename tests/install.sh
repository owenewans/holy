#!/bin/sh
set -eu
helper=$1
bin=$2
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -p "$tmp/payload/HOLY" "$tmp/payload/DATA/usr/bin" "$tmp/root/usr/bin"
cat > "$tmp/payload/HOLY/meta" <<'EOF'
format holy-package-1
name data
version 1
release 1
os linux
arch noarch
libc nolibc
EOF
for file in deps provides hooks origin transform; do : > "$tmp/payload/HOLY/$file"; done
printf 'content\n' > "$tmp/payload/DATA/usr/bin/data"
uid=$(id -u)
gid=$(id -g)
for path in usr usr/bin; do
    mode=$(stat -c %a "$tmp/payload/DATA/$path")
    printf 'dir %s %s root root %s %s 0 - none - -\n' \
        "$path" "$mode" "$uid" "$gid" >> "$tmp/payload/HOLY/files"
done
hash=$(sha256sum "$tmp/payload/DATA/usr/bin/data")
hash=${hash%% *}
printf 'file usr/bin/data 644 root root %s %s 8 %s none - -\n' \
    "$uid" "$gid" "$hash" >> "$tmp/payload/HOLY/files"
tar -cf "$tmp/data.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/data.tar" "$tmp/data.holy"
"$bin" pack "$tmp/payload" --output "$tmp/written.holy" > "$tmp/out"
grep -qx "packed $tmp/written.holy" "$tmp/out"
"$bin" verify "local:$tmp/written.holy" > "$tmp/out"
"$bin" manifest generate "$tmp/payload" --output "$tmp/generated-files" > "$tmp/out"
grep -qx "manifest $tmp/generated-files" "$tmp/out"
cp "$tmp/payload/HOLY/files" "$tmp/handwritten-files"
cp "$tmp/generated-files" "$tmp/payload/HOLY/files"
"$bin" pack "$tmp/payload" --output "$tmp/generated.holy" > "$tmp/out"
"$bin" verify "local:$tmp/generated.holy" > "$tmp/out"
mv "$tmp/handwritten-files" "$tmp/payload/HOLY/files"
if "$bin" manifest generate "$tmp/payload" --output "$tmp/generated-files" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 1; fi
test ! -s "$tmp/out"
if "$bin" manifest generate "$tmp/payload" --output "$tmp/payload/HOLY/files2" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 1; fi
test ! -e "$tmp/payload/HOLY/files2"
mkdir -p "$tmp/empty/HOLY" "$tmp/empty/DATA"
cp "$tmp/payload/HOLY/"* "$tmp/empty/HOLY/"
: > "$tmp/empty/HOLY/files"
"$bin" manifest generate "$tmp/empty" --output "$tmp/empty-files" > "$tmp/out"
test ! -s "$tmp/empty-files"
"$bin" pack "$tmp/empty" --output "$tmp/empty.holy" > "$tmp/out"
"$bin" verify "local:$tmp/empty.holy" > "$tmp/out"
touch -m -d '2001-01-01 00:00:00 UTC' "$tmp/payload/DATA/usr/bin/data"
"$bin" pack "$tmp/payload" --output "$tmp/written-again.holy" > "$tmp/out"
cmp "$tmp/written.holy" "$tmp/written-again.holy"
if "$bin" pack "$tmp/payload" --output "$tmp/payload/DATA/usr/bin/self.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 1; fi
test ! -e "$tmp/payload/DATA/usr/bin/self.holy"
if "$bin" pack "$tmp/payload" --output "$tmp/written.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 1; fi
test ! -s "$tmp/out"
test "$(find "$tmp" -name '*.holy-tmp-*' | wc -l)" -eq 0
ln -s ../../../outside "$tmp/payload/DATA/usr/bin/extra"
if "$bin" manifest generate "$tmp/payload" --output "$tmp/refused-files" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 1; fi
test ! -e "$tmp/refused-files"
if "$bin" pack "$tmp/payload" --output "$tmp/refused.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 1; fi
test ! -e "$tmp/refused.holy"
rm "$tmp/payload/DATA/usr/bin/extra"
cp -a "$tmp/payload" "$tmp/links"
ln -s usr/bin "$tmp/links/DATA/bin"
ln -s data "$tmp/links/DATA/usr/bin/alias"
ln -s 'missing "target"' "$tmp/links/DATA/usr/bin/dangling"
"$bin" manifest generate "$tmp/links" --output "$tmp/link-files" > "$tmp/out"
cp "$tmp/link-files" "$tmp/links/HOLY/files"
"$bin" pack "$tmp/links" --output "$tmp/links.holy" > "$tmp/out"
"$bin" verify "local:$tmp/links.holy" > "$tmp/out"
"$bin" fetch "local:$tmp/links.holy" --extract --output "$tmp/link-extract" > "$tmp/out"
test "$(readlink "$tmp/link-extract/DATA/bin")" = usr/bin
test "$(readlink "$tmp/link-extract/DATA/usr/bin/alias")" = data
test "$(readlink "$tmp/link-extract/DATA/usr/bin/dangling")" = 'missing "target"'
cmp "$tmp/link-extract/DATA/bin/alias" "$tmp/payload/DATA/usr/bin/data"
ln -s /usr/bin/data "$tmp/links/DATA/usr/bin/absolute"
"$bin" manifest generate "$tmp/links" --output "$tmp/absolute-files" > "$tmp/out"
cp "$tmp/absolute-files" "$tmp/links/HOLY/files"
"$bin" pack "$tmp/links" --output "$tmp/absolute.holy" > "$tmp/out"
"$bin" verify "local:$tmp/absolute.holy" > "$tmp/out"
ln -s /../outside "$tmp/links/DATA/usr/bin/escape"
if "$bin" manifest generate "$tmp/links" --output "$tmp/escape-files" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 1; fi
test ! -e "$tmp/escape-files"
if "$bin" pack "$tmp/links" --output "$tmp/escape.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 1; fi
test ! -e "$tmp/escape.holy"
printf 'spaced\n' > "$tmp/payload/DATA/usr/bin/a b"
printf 'unicode\n' > "$tmp/payload/DATA/usr/bin/é"
"$bin" manifest generate "$tmp/payload" --output "$tmp/spaced-files" > "$tmp/out"
cp "$tmp/payload/HOLY/files" "$tmp/handwritten-files"
cp "$tmp/spaced-files" "$tmp/payload/HOLY/files"
"$bin" pack "$tmp/payload" --output "$tmp/spaced.holy" > "$tmp/out"
"$bin" verify "local:$tmp/spaced.holy" > "$tmp/out"
mv "$tmp/handwritten-files" "$tmp/payload/HOLY/files"
rm "$tmp/payload/DATA/usr/bin/a b"
rm "$tmp/payload/DATA/usr/bin/é"
ln "$tmp/payload/DATA/usr/bin/data" "$tmp/payload/DATA/usr/bin/extra"
"$bin" manifest generate "$tmp/payload" --output "$tmp/hardlink-files" > "$tmp/out"
grep -q '^hardlink "usr/bin/extra" .* "usr/bin/data"$' "$tmp/hardlink-files"
if "$bin" pack "$tmp/payload" --output "$tmp/refused.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 1; fi
test ! -e "$tmp/refused.holy"
rm "$tmp/payload/DATA/usr/bin/extra"
printf 'unlisted\n' > "$tmp/payload/HOLY/extra"
if "$bin" pack "$tmp/payload" --output "$tmp/refused.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 1; fi
test ! -e "$tmp/refused.holy"
rm "$tmp/payload/HOLY/extra"
if command -v setfattr > /dev/null 2>&1; then
    setfattr -n user.holy-fixture -v value "$tmp/payload/DATA/usr/bin/data"
    if "$bin" manifest generate "$tmp/payload" --output "$tmp/refused-files" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 1; fi
    test ! -e "$tmp/refused-files"
    if "$bin" pack "$tmp/payload" --output "$tmp/refused.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 1; fi
    test ! -e "$tmp/refused.holy"
    setfattr -x user.holy-fixture "$tmp/payload/DATA/usr/bin/data"
fi
cp "$tmp/payload/HOLY/files" "$tmp/valid-files"
printf 'bad\n' > "$tmp/payload/HOLY/files"
if "$bin" pack "$tmp/payload" --output "$tmp/refused.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 1; fi
test ! -e "$tmp/refused.holy"
mv "$tmp/valid-files" "$tmp/payload/HOLY/files"
cp "$tmp/payload/DATA/usr/bin/data" "$tmp/valid-data"
cp "$tmp/payload/HOLY/files" "$tmp/valid-files"
printf '\177ELFfake' > "$tmp/payload/DATA/usr/bin/data"
elfhash=$(sha256sum "$tmp/payload/DATA/usr/bin/data")
elfhash=${elfhash%% *}
sed "s/$hash/$elfhash/" "$tmp/valid-files" > "$tmp/payload/HOLY/files"
if "$bin" pack "$tmp/payload" --output "$tmp/refused.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 1; fi
test ! -e "$tmp/refused.holy"
mv "$tmp/valid-data" "$tmp/payload/DATA/usr/bin/data"
mv "$tmp/valid-files" "$tmp/payload/HOLY/files"
"$helper" "$tmp/data.holy" "$tmp/root"
cmp "$tmp/root/usr/bin/data" "$tmp/payload/DATA/usr/bin/data"
if "$helper" "$tmp/data.holy" "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
cmp "$tmp/root/usr/bin/data" "$tmp/payload/DATA/usr/bin/data"
rm "$tmp/root/usr/bin/data"
rmdir "$tmp/root/usr/bin"
ln -s "$tmp/payload/DATA/usr/bin" "$tmp/root/usr/bin"
if "$helper" "$tmp/data.holy" "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
test -L "$tmp/root/usr/bin"
cmp "$tmp/payload/DATA/usr/bin/data" "$tmp/root/usr/bin/data"
mkdir -p "$tmp/system/usr/bin"
"$bin" db init --root "$tmp/system" > "$tmp/out"
"$bin" db check --all --root "$tmp/system" > "$tmp/out"
grep -qx 'checked 0 installed packages' "$tmp/out"
"$bin" db check --all --root "$tmp/system" --json > "$tmp/out"
python3 - "$tmp/out" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as stream:
    records = [json.loads(line) for line in stream]
assert records == [{'schema': 'holy-installed-check-1', 'type': 'summary',
                    'pass': 0, 'fail': 0, 'unknown': 0,
                    'coverage': 'data-manifest-and-direct-shebang'}]
PY
missing=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
if "$bin" db check "$missing" --root "$tmp/system" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
grep -qx '{"schema":"holy-installed-check-1","type":"error","code":"unavailable-instance","status":6}' "$tmp/out"
if "$bin" db check invalid --root "$tmp/system" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
grep -qx '{"schema":"holy-installed-check-1","type":"error","code":"invalid-argument","status":2}' "$tmp/out"
"$bin" cache stage "local:$tmp/data.holy" --root "$tmp/system" > "$tmp/out"
digest=$(sha256sum "$tmp/data.holy")
digest=${digest%% *}
"$bin" db reserve "$digest" --root "$tmp/system" > "$tmp/out"
"$bin" db plan --root "$tmp/system" > "$tmp/out"
plan=$(sed -n 's/.* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
test "${#plan}" -eq 64
"$bin" db approve "$plan" --root "$tmp/system" > "$tmp/out"
cp "$tmp/system/var/lib/holypkg/transactions/pending" "$tmp/approved-pending"
"$bin" db apply --root "$tmp/system" > "$tmp/out"
grep -qx "installed $digest generation 1 paths 3" "$tmp/out"
cmp "$tmp/system/usr/bin/data" "$tmp/payload/DATA/usr/bin/data"
db="$tmp/system/var/lib/holypkg"
for file in meta files deps origin state; do test -f "$db/installed/$digest/$file"; done
grep -qx "artifact $digest" "$db/installed/$digest/state"
grep -qx 'format holy-instance-4' "$db/installed/$digest/state"
graph_hash=$(sha256sum "$db/installed/$digest/graph")
graph_hash=${graph_hash%% *}
grep -qx "graph $graph_hash" "$db/installed/$digest/state"
grep -qx "root $digest" "$db/installed/$digest/graph"
cp "$db/installed/$digest/graph" "$tmp/saved-graph"
cp "$db/installed/$digest/state" "$tmp/graph-state"
printf 'corrupt\n' >> "$db/installed/$digest/graph"
if "$bin" db status --root "$tmp/system" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 1; fi
test ! -s "$tmp/out"
rm "$db/installed/$digest/graph"
if "$bin" db status --root "$tmp/system" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 1; fi
ln -s "$tmp/saved-graph" "$db/installed/$digest/graph"
if "$bin" db status --root "$tmp/system" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 1; fi
rm "$db/installed/$digest/graph"
mv "$db/installed/$digest/provides" "$tmp/saved-provides"
sed '/^graph /d; /^provides /d; /^source-record /d; s/holy-instance-4/holy-instance-1/' "$tmp/graph-state" > "$db/installed/$digest/state"
"$bin" db status --root "$tmp/system" > "$tmp/out"
cp "$tmp/saved-graph" "$db/installed/$digest/graph"
if "$bin" db status --root "$tmp/system" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 1; fi
cp "$tmp/graph-state" "$db/installed/$digest/state"
mv "$tmp/saved-provides" "$db/installed/$digest/provides"
chmod 666 "$db/installed/$digest/graph"
if "$bin" db status --root "$tmp/system" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 1; fi
chmod 600 "$db/installed/$digest/graph"
"$bin" db status --root "$tmp/system" > "$tmp/out"
grep -qx 'generation 1' "$tmp/out"
printf 'format holy-journal-1\nstage applying\ngeneration 0\nartifact %s\nplan %s\n' \
    "$digest" "$plan" > "$db/transactions/journal"
cp "$tmp/approved-pending" "$db/transactions/pending"
printf 'changed\n' > "$tmp/system/usr/bin/data"
if "$bin" db recover --finish-apply --root "$tmp/system" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 5; fi
test -f "$db/transactions/journal"
cp "$tmp/payload/DATA/usr/bin/data" "$tmp/system/usr/bin/data"
"$bin" db recover --finish-apply --root "$tmp/system" > "$tmp/out"
grep -qx "recovered install $digest generation 1" "$tmp/out"
test ! -e "$db/transactions/pending"
test ! -e "$db/transactions/journal"
printf 'format holy-journal-1\nstage applying\ngeneration 0\nartifact %s\nplan %s\n' \
    "$digest" "$plan" > "$db/transactions/journal"
"$bin" db recover --finish-apply --root "$tmp/system" > "$tmp/out"
grep -qx "recovered install $digest generation 1" "$tmp/out"
test ! -e "$db/transactions/journal"
"$bin" db check "$digest" --root "$tmp/system" > "$tmp/out"
grep -qx "intact $digest generation 1" "$tmp/out"
chmod 700 "$tmp/system/usr/bin"
if "$bin" db check "$digest" --root "$tmp/system" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
grep -qx 'holypkg: changed-file usr/bin' "$tmp/err"
if "$bin" db check "$digest" --root "$tmp/system" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
grep -q '"code":"changed-file"' "$tmp/out"
chmod 755 "$tmp/system/usr/bin"
"$bin" db check "$digest" --root "$tmp/system" > "$tmp/out"
"$bin" db check "$digest" --root "$tmp/system" --json > "$tmp/out"
python3 - "$tmp/out" "$digest" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as stream:
    artifact, summary = [json.loads(line) for line in stream]
assert artifact == {'schema': 'holy-installed-check-1', 'type': 'artifact',
                    'artifact': sys.argv[2], 'state': 'pass', 'code': None,
                    'generation': 1, 'findings': []}
assert summary == {'schema': 'holy-installed-check-1', 'type': 'summary',
                   'pass': 1, 'fail': 0, 'unknown': 0,
                   'coverage': 'data-manifest-and-direct-shebang'}
PY
"$bin" db owner /usr/bin/data --root "$tmp/system" > "$tmp/out"
grep -qx "$digest file usr/bin/data" "$tmp/out"
"$bin" db owner usr/bin --root "$tmp/system" > "$tmp/out"
grep -qx "$digest directory usr/bin" "$tmp/out"
if "$bin" db owner /usr/bin/absent --root "$tmp/system" > "$tmp/out"; then exit 1; else test "$?" -eq 6; fi
test ! -s "$tmp/out"
if "$bin" db owner ../usr/bin/data --root "$tmp/system" > "$tmp/out"; then exit 1; else test "$?" -eq 2; fi
test ! -s "$tmp/out"
printf 'changed\n' > "$tmp/system/usr/bin/data"
if "$bin" db check "$digest" --root "$tmp/system" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
grep -qx 'holypkg: changed-file usr/bin/data' "$tmp/err"
if "$bin" db check "$digest" --root "$tmp/system" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
python3 - "$tmp/out" "$digest" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as stream:
    artifact, summary = [json.loads(line) for line in stream]
assert artifact['artifact'] == sys.argv[2] and artifact['code'] == 'changed-file'
assert artifact['state'] == 'fail' and summary['fail'] == 1
assert artifact['findings'] == [{'code': 'changed-file', 'severity': 'error',
                                'path': 'usr/bin/data'}]
PY
cp "$tmp/payload/DATA/usr/bin/data" "$tmp/system/usr/bin/data"
"$bin" db check "$digest" --root "$tmp/system" > "$tmp/out"
rm "$tmp/system/usr/bin/data"
if "$bin" db check "$digest" --root "$tmp/system" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
python3 - "$tmp/out" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as stream:
    artifact, summary = [json.loads(line) for line in stream]
assert artifact['findings'] == [{'code': 'missing-file', 'severity': 'error',
                                'path': 'usr/bin/data'}]
assert summary['fail'] == 1
PY
cp "$db/installed/$digest/files" "$tmp/unescaped-files"
python3 - "$db/installed/$digest/files" <<'PY'
import sys
path = sys.argv[1]
with open(path, encoding='utf-8') as stream:
    text = stream.read()
with open(path, 'w', encoding='utf-8') as stream:
    stream.write(text.replace('usr/bin/data', r'"usr/bin/a\"b\\c\n\xff"'))
PY
if "$bin" db check "$digest" --root "$tmp/system" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
python3 - "$tmp/out" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as stream:
    artifact, summary = [json.loads(line) for line in stream]
assert artifact['findings'][0]['path'].encode('latin1') == b'usr/bin/a"b\\c\n\xff'
assert artifact['findings'][0]['code'] == 'missing-file'
PY
mv "$tmp/unescaped-files" "$db/installed/$digest/files"
ln -s "$tmp/payload/DATA/usr/bin/data" "$tmp/system/usr/bin/data"
if "$bin" db check "$digest" --root "$tmp/system" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
rm "$tmp/system/usr/bin/data"
cp "$tmp/payload/DATA/usr/bin/data" "$tmp/system/usr/bin/data"
"$bin" db check "$digest" --root "$tmp/system" > "$tmp/out"
cp "$db/installed/$digest/state" "$tmp/saved-state"
printf 'invalid\n' > "$db/installed/$digest/state"
if "$bin" db status --root "$tmp/system" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 1; fi
cp "$tmp/saved-state" "$db/installed/$digest/state"
test ! -e "$db/transactions/pending"
test ! -e "$db/transactions/journal"
mv "$tmp/payload/DATA/usr/bin/data" "$tmp/payload/DATA/usr/bin/data-v2"
sed 's@usr/bin/data @usr/bin/data-v2 @' "$tmp/payload/HOLY/files" > "$tmp/old-files"
cp "$tmp/payload/HOLY/files" "$tmp/saved-files"
mv "$tmp/old-files" "$tmp/payload/HOLY/files"
tar -cf "$tmp/duplicate.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/duplicate.tar" "$tmp/duplicate.holy"
duplicate=$(sha256sum "$tmp/duplicate.holy")
duplicate=${duplicate%% *}
"$bin" cache stage "local:$tmp/duplicate.holy" --root "$tmp/system" > "$tmp/out"
"$bin" db reserve "$duplicate" --root "$tmp/system" > "$tmp/out"
if "$bin" db plan --root "$tmp/system" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
grep -qx 'holypkg: installed package slot already active: data' "$tmp/err"
test ! -s "$tmp/out"
"$bin" db cancel --root "$tmp/system" > "$tmp/out"
mv "$tmp/saved-files" "$tmp/payload/HOLY/files"
mv "$tmp/payload/DATA/usr/bin/data-v2" "$tmp/payload/DATA/usr/bin/data"
sed 's/name data/name data2/' "$tmp/payload/HOLY/meta" > "$tmp/new-meta"
mv "$tmp/new-meta" "$tmp/payload/HOLY/meta"
mv "$tmp/payload/DATA/usr/bin/data" "$tmp/payload/DATA/usr/bin/data2"
sed 's@usr/bin/data @usr/bin/data2 @' "$tmp/payload/HOLY/files" > "$tmp/new-files"
mv "$tmp/new-files" "$tmp/payload/HOLY/files"
tar -cf "$tmp/data2.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/data2.tar" "$tmp/data2.holy"
digest2=$(sha256sum "$tmp/data2.holy")
digest2=${digest2%% *}
"$bin" cache stage "local:$tmp/data2.holy" --root "$tmp/system" > "$tmp/out"
"$bin" db reserve "$digest2" --root "$tmp/system" > "$tmp/out"
"$bin" db plan --root "$tmp/system" > "$tmp/out"
plan2=$(sed -n 's/.* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
"$bin" db approve "$plan2" --root "$tmp/system" > "$tmp/out"
"$bin" db apply --root "$tmp/system" > "$tmp/out"
grep -qx "installed $digest2 generation 2 paths 3" "$tmp/out"
test -f "$db/installed/$digest2/state"
test -f "$tmp/system/usr/bin/data2"
"$bin" db status --root "$tmp/system" > "$tmp/out"
grep -qx 'generation 2' "$tmp/out"
"$bin" db check "$digest2" --root "$tmp/system" > "$tmp/out"
"$bin" db check --all --root "$tmp/system" > "$tmp/out"
grep -qx "intact $digest generation 2" "$tmp/out"
grep -qx "intact $digest2 generation 2" "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 2
cp -a "$tmp/payload" "$tmp/claimed"
sed 's/name data2/name claimed/' "$tmp/payload/HOLY/meta" > "$tmp/claimed/HOLY/meta"
mv "$tmp/claimed/DATA/usr/bin/data2" "$tmp/claimed/DATA/usr/bin/data"
"$bin" manifest generate "$tmp/claimed" --output "$tmp/claimed-files" > "$tmp/out"
cp "$tmp/claimed-files" "$tmp/claimed/HOLY/files"
"$bin" pack "$tmp/claimed" --output "$tmp/claimed.holy" > "$tmp/out"
"$bin" cache stage "local:$tmp/claimed.holy" --root "$tmp/system" > "$tmp/out"
claimed=$(sha256sum "$tmp/claimed.holy")
claimed=${claimed%% *}
rm "$tmp/system/usr/bin/data"
"$bin" db reserve "$claimed" --root "$tmp/system" > "$tmp/out"
if "$bin" db plan --root "$tmp/system" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
grep -qx "holypkg: path already claimed by $digest" "$tmp/err"
test ! -e "$tmp/system/usr/bin/data"
test ! -e "$db/transactions/journal"
"$bin" db cancel --root "$tmp/system" > "$tmp/out"
cp "$tmp/payload/DATA/usr/bin/data2" "$tmp/system/usr/bin/data"
"$bin" db check --all --root "$tmp/system" --json > "$tmp/out"
python3 - "$tmp/out" "$digest" "$digest2" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as stream:
    a, b, summary = [json.loads(line) for line in stream]
assert [a['artifact'], b['artifact']] == sorted(sys.argv[2:])
assert [a['state'], b['state']] == ['pass', 'pass']
assert summary['pass'] == 2 and summary['fail'] == 0
PY
cp "$db/installed/$digest2/files" "$tmp/valid-installed-files"
printf 'malformed\n' > "$db/installed/$digest2/files"
if "$bin" db check --all --root "$tmp/system" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 1; fi
grep -qx '{"schema":"holy-installed-check-1","type":"error","code":"invalid-state","status":1}' "$tmp/out"
mv "$tmp/valid-installed-files" "$db/installed/$digest2/files"
printf 'changed\n' > "$tmp/system/usr/bin/data"
if "$bin" db check --all --root "$tmp/system" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
grep -qx "changed $digest generation 2" "$tmp/out"
grep -qx "intact $digest2 generation 2" "$tmp/out"
if "$bin" db check --all --root "$tmp/system" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
python3 - "$tmp/out" "$digest" "$digest2" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as stream:
    records = [json.loads(line) for line in stream]
assert {item['artifact']: item['state'] for item in records[:-1]} == {
    sys.argv[2]: 'fail', sys.argv[3]: 'pass'}
assert records[-1]['fail'] == 1 and records[-1]['pass'] == 1
findings = {item['artifact']: item['findings'] for item in records[:-1]}
assert findings[sys.argv[2]] == [{'code': 'changed-file', 'severity': 'error',
                                 'path': 'usr/bin/data'}]
assert findings[sys.argv[3]] == []
PY
cp "$tmp/payload/DATA/usr/bin/data2" "$tmp/system/usr/bin/data"
"$bin" db owner usr/bin --root "$tmp/system" > "$tmp/out"
grep -qx "$digest directory usr/bin" "$tmp/out"
grep -qx "$digest2 directory usr/bin" "$tmp/out"
test "$(head -n 1 "$tmp/out")" = "$(printf '%s\n%s\n' "$digest" "$digest2" | sort | head -n 1) directory usr/bin"
other=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
cp -a "$db/installed/$digest" "$db/installed/$other"
sed "s/$digest/$other/" "$db/installed/$digest/state" > "$db/installed/$other/state"
if "$bin" db owner usr/bin/data --root "$tmp/system" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
test ! -s "$tmp/out"
grep -qx 'holypkg: conflicting installed owners for usr/bin/data' "$tmp/err"
if "$bin" db rm "$digest" --root "$tmp/system" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
grep -qx "holypkg: conflicting installed ownership with $other" "$tmp/err"
test ! -e "$db/transactions/journal"
test -f "$db/installed/$digest/state"
test -f "$db/installed/$other/state"
cmp "$tmp/system/usr/bin/data" "$tmp/payload/DATA/usr/bin/data2"
printf 'format holy-journal-1\nstage removing\ngeneration 2\nartifact %s\nplan %064d\n' \
    "$digest" 0 > "$db/transactions/journal"
if "$bin" db recover --continue --root "$tmp/system" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 5; fi
grep -qx "holypkg: conflicting installed ownership with $other" "$tmp/err"
test -f "$db/transactions/journal"
test -f "$db/installed/$digest/state"
test -f "$db/installed/$other/state"
cmp "$tmp/system/usr/bin/data" "$tmp/payload/DATA/usr/bin/data2"
rm "$db/transactions/journal"
rm -r "$db/installed/$other"
printf 'changed\n' > "$tmp/system/usr/bin/data"
if "$bin" db rm "$digest" --root "$tmp/system" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
test ! -e "$db/transactions/journal"
test -f "$tmp/system/usr/bin/data2"
cp "$tmp/payload/DATA/usr/bin/data2" "$tmp/system/usr/bin/data"
"$bin" db rm "$digest" --root "$tmp/system" > "$tmp/out"
grep -qx "removed $digest generation 3" "$tmp/out"
test ! -e "$tmp/system/usr/bin/data"
test ! -e "$db/installed/$digest"
test -f "$tmp/system/usr/bin/data2"
"$bin" db check "$digest2" --root "$tmp/system" > "$tmp/out"
"$bin" db status --root "$tmp/system" > "$tmp/out"
grep -qx 'generation 3' "$tmp/out"
mkdir -p "$tmp/failure/usr/bin"
"$bin" db init --root "$tmp/failure" > "$tmp/out"
"$bin" cache stage "local:$tmp/data.holy" --root "$tmp/failure" > "$tmp/out"
"$bin" db reserve "$digest" --root "$tmp/failure" > "$tmp/out"
"$bin" db plan --root "$tmp/failure" > "$tmp/out"
failure_plan=$(sed -n 's/.* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
"$bin" db approve "$failure_plan" --root "$tmp/failure" > "$tmp/out"
printf 'keep\n' > "$tmp/failure/usr/bin/data"
if "$bin" db apply --root "$tmp/failure" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
grep -qx keep "$tmp/failure/usr/bin/data"
test ! -e "$tmp/failure/var/lib/holypkg/transactions/journal"
rm "$tmp/failure/usr/bin/data"
chmod 0555 "$tmp/failure/usr/bin"
if "$bin" db apply --root "$tmp/failure" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
test ! -e "$tmp/failure/var/lib/holypkg/transactions/journal"
printf 'format holy-journal-1\nstage applying\ngeneration 0\nartifact %s\nplan %s\n' \
    "$digest" "$failure_plan" > "$tmp/failure/var/lib/holypkg/transactions/journal"
if "$bin" db status --root "$tmp/failure" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 5; fi
grep -qx 'incomplete transaction; inspect journal' "$tmp/out"
if "$bin" db check --all --root "$tmp/failure" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 5; fi
if "$bin" db check --all --root "$tmp/failure" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 5; fi
grep -qx '{"schema":"holy-installed-check-1","type":"error","code":"incomplete-transaction","status":5}' "$tmp/out"
if "$bin" db recover --root "$tmp/failure" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 5; fi
test ! -e "$tmp/failure/usr/bin/data"
chmod 0755 "$tmp/failure/usr/bin"
printf 'user\n' > "$tmp/failure/usr/bin/data"
if "$bin" db recover --abort-empty --root "$tmp/failure" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 5; fi
test -f "$tmp/failure/var/lib/holypkg/transactions/journal"
grep -qx user "$tmp/failure/usr/bin/data"
rm "$tmp/failure/usr/bin/data"
"$bin" db recover --abort-empty --root "$tmp/failure" > "$tmp/out"
grep -qx "aborted empty apply $digest; approval retained" "$tmp/out"
test ! -e "$tmp/failure/var/lib/holypkg/transactions/journal"
"$bin" db apply --root "$tmp/failure" > "$tmp/out"
grep -qx "installed $digest generation 1 paths 3" "$tmp/out"
chmod 0555 "$tmp/failure/usr/bin"
if "$bin" db rm "$digest" --root "$tmp/failure" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
test ! -e "$tmp/failure/var/lib/holypkg/transactions/journal"
printf 'format holy-journal-1\nstage removing\ngeneration 1\nartifact %s\nplan %064d\n' \
    "$digest" 0 > "$tmp/failure/var/lib/holypkg/transactions/journal"
if "$bin" db status --root "$tmp/failure" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 5; fi
if "$bin" db recover --abort-empty --root "$tmp/failure" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 5; fi
test -f "$tmp/failure/usr/bin/data"
test -f "$tmp/failure/var/lib/holypkg/transactions/journal"
chmod 0755 "$tmp/failure/usr/bin"
cp "$tmp/failure/var/lib/holypkg/installed/$digest/files" "$tmp/recovery-files"
printf 'file usr/bin/later 644 root root %s %s 8 %s none - -\n' \
    "$uid" "$gid" "$hash" >> "$tmp/failure/var/lib/holypkg/installed/$digest/files"
printf 'changed\n' > "$tmp/failure/usr/bin/later"
if "$bin" db recover --continue --root "$tmp/failure" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 5; fi
test -f "$tmp/failure/usr/bin/data"
cmp "$tmp/failure/usr/bin/data" "$tmp/payload/DATA/usr/bin/data2"
grep -qx changed "$tmp/failure/usr/bin/later"
test -f "$tmp/failure/var/lib/holypkg/transactions/journal"
mv "$tmp/recovery-files" "$tmp/failure/var/lib/holypkg/installed/$digest/files"
rm "$tmp/failure/usr/bin/later"
printf 'changed\n' > "$tmp/failure/usr/bin/data"
if "$bin" db recover --continue --root "$tmp/failure" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 5; fi
test -f "$tmp/failure/var/lib/holypkg/transactions/journal"
rm "$tmp/failure/usr/bin/data"
"$bin" db recover --continue --root "$tmp/failure" > "$tmp/out"
grep -qx "recovered removal $digest generation 2" "$tmp/out"
test ! -e "$tmp/failure/usr/bin/data"
test ! -e "$tmp/failure/var/lib/holypkg/transactions/journal"
"$bin" db status --root "$tmp/failure" > "$tmp/out"
grep -qx 'generation 2' "$tmp/out"
mkdir "$tmp/transitions"
"$helper" --transitions "$tmp/transitions"
cat > "$tmp/transition-fault.c" <<'C'
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
int fstatat(int dir, const char *path, struct stat *st, int flags)
{
    int (*actual)(int, const char *, struct stat *, int);
    const char *phase = getenv("HOLY_TRANSITION_FAULT");
    void *symbol = dlsym(RTLD_NEXT, "fstatat");
    memcpy(&actual, &symbol, sizeof actual);
    if (!actual) abort();
    if (phase && !strcmp(phase, "race") && !strcmp(path, ".holy-update-first")) {
        int fd = openat(dir, "current", O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0 || write(fd, "intruder", 8) != 8 || close(fd)) abort();
    }
    return actual(dir, path, st, flags);
}
int renameat(int olddir, const char *old, int newdir, const char *next)
{
    int (*actual)(int, const char *, int, const char *), result;
    const char *phase = getenv("HOLY_TRANSITION_FAULT");
    void *symbol = dlsym(RTLD_NEXT, "renameat");
    memcpy(&actual, &symbol, sizeof actual);
    if (!actual) abort();
    if (phase && !strcmp(old, ".holy-update-next")) {
        if (!strcmp(phase, "fail")) { errno = ENOSPC; return -1; }
        if (!strcmp(phase, "before")) kill(getpid(), SIGKILL);
        result = actual(olddir, old, newdir, next);
        if (!result && !strcmp(phase, "after")) kill(getpid(), SIGKILL);
        return result;
    }
    return actual(olddir, old, newdir, next);
}
C
gcc -shared -fPIC -o "$tmp/transition-fault.so" "$tmp/transition-fault.c" -ldl
for phase in fail before after; do
    mkdir "$tmp/transition-$phase"
    rc=0
    env LD_PRELOAD="$tmp/transition-fault.so" HOLY_TRANSITION_FAULT="$phase" \
        "$helper" --transitions "$tmp/transition-$phase" > "$tmp/out" 2> "$tmp/err" || rc=$?
    if test "$phase" = fail; then test "$rc" -eq 4; else test "$rc" -eq 137; fi
    if test "$phase" = after; then
        test "$(cat "$tmp/transition-$phase/data/current")" = 'new payload'
    else
        test "$(cat "$tmp/transition-$phase/data/current")" = old
        test "$(cat "$tmp/transition-$phase/data/.holy-update-next")" = 'new payload'
    fi
    "$helper" --resume-transition "$tmp/transition-$phase"
    "$helper" --resume-transition "$tmp/transition-$phase"
    test "$(cat "$tmp/transition-$phase/data/current")" = 'new payload'
    test ! -e "$tmp/transition-$phase/data/.holy-update-next"
done
mkdir "$tmp/transition-race"
rc=0
env LD_PRELOAD="$tmp/transition-fault.so" HOLY_TRANSITION_FAULT=race \
    "$helper" --transitions "$tmp/transition-race" > "$tmp/out" 2> "$tmp/err" || rc=$?
test "$rc" -eq 4
test "$(cat "$tmp/transition-race/data/current")" = intruder
test "$(cat "$tmp/transition-race/data/.holy-update-first")" = old
rc=0
"$helper" --resume-addition "$tmp/transition-race" || rc=$?
test "$rc" -eq 4
rm "$tmp/transition-race/data/current"
"$helper" --resume-addition "$tmp/transition-race"
printf 'install payload fixtures passed\n'
