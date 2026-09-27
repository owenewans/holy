#!/bin/sh
set -eu
helper=$1
bin=$2
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
umask 022
mkdir -p "$tmp/old/HOLY" "$tmp/old/DATA/usr/share" "$tmp/root/usr/share"
cat > "$tmp/old/HOLY/meta" <<'EOF'
format holy-package-1
name update-fixture
version 1
release 1
os linux
arch noarch
libc nolibc
EOF
for file in deps provides hooks origin transform; do : > "$tmp/old/HOLY/$file"; done
for file in retained changed removed flip mode 'a b'; do
    printf 'old content\n' > "$tmp/old/DATA/usr/share/$file"
done
ln -s retained "$tmp/old/DATA/usr/share/reverse"
ln -s retained "$tmp/old/DATA/usr/share/link"
cp -a "$tmp/old" "$tmp/new"
sed 's/version 1/version 2/' "$tmp/old/HOLY/meta" > "$tmp/new/HOLY/meta"
printf 'new content\n' > "$tmp/new/DATA/usr/share/changed"
printf 'added content\n' > "$tmp/new/DATA/usr/share/added"
rm "$tmp/new/DATA/usr/share/removed" "$tmp/new/DATA/usr/share/flip" \
   "$tmp/new/DATA/usr/share/reverse" "$tmp/new/DATA/usr/share/link"
ln -s retained "$tmp/new/DATA/usr/share/flip"
ln -s changed "$tmp/new/DATA/usr/share/link"
printf 'regular now\n' > "$tmp/new/DATA/usr/share/reverse"
chmod 600 "$tmp/new/DATA/usr/share/mode"
pack() {
    "$bin" manifest generate "$tmp/$1" --output "$tmp/$1-files" > "$tmp/out"
    cp "$tmp/$1-files" "$tmp/$1/HOLY/files"
    "$bin" pack "$tmp/$1" --output "$tmp/$1.holy" > "$tmp/out"
}
expect() {
    code=$1
    shift
    if "$@" > "$tmp/record" 2> "$tmp/err"; then
        test "$code" -eq 0
    else
        test "$?" -eq "$code"
    fi
}
pack old
pack new
"$helper" "$tmp/old.holy" "$tmp/root"
printf 'user data\n' > "$tmp/root/usr/share/unlisted"
snapshot() {
    python3 - "$tmp/root" <<'PY'
import hashlib, json, os, stat, sys
root = sys.argv[1]
rows = []
for directory, dirs, files in os.walk(root):
    for name in sorted(dirs + files):
        path = os.path.join(directory, name)
        st = os.lstat(path)
        content = os.readlink(path) if stat.S_ISLNK(st.st_mode) else (
            hashlib.sha256(open(path, 'rb').read()).hexdigest() if stat.S_ISREG(st.st_mode) else None)
        rows.append((os.path.relpath(path, root), st.st_mode, st.st_uid, st.st_gid, content))
print(json.dumps(sorted(rows)))
PY
}
snapshot > "$tmp/before"
expect 0 "$helper" --file-plan "$tmp/old.holy" "$tmp/new.holy" "$tmp/root"
cp "$tmp/record" "$tmp/first"
expect 0 "$helper" --file-plan "$tmp/old.holy" "$tmp/new.holy" "$tmp/root"
cmp "$tmp/first" "$tmp/record"
snapshot > "$tmp/after"
cmp "$tmp/before" "$tmp/after"
python3 - "$tmp/record" "$tmp/old.holy" "$tmp/new.holy" <<'PY'
import hashlib, shlex, sys
rows = [shlex.split(line) for line in open(sys.argv[1])]
old, new = (hashlib.sha256(open(p, 'rb').read()).hexdigest() for p in sys.argv[2:])
assert rows[:3] == [['format', 'holy-file-plan-1'], ['old', old], ['new', new]]
changes = {}
paths = []
for i in range(3, len(rows), 3):
    change, before, after = rows[i:i+3]
    path = (before if before[1] != 'absent' else after)[2]
    digest = hashlib.sha256(b'holy-file-change-1\0' + old.encode() + b'\0' + new.encode() + b'\0' + path.encode() + b'\0').hexdigest()
    assert change[:2] == ['change', digest]
    assert before[0] == 'before' and after[0] == 'after'
    assert path not in changes
    changes[path] = change[2]
    paths.append(path)
assert paths == sorted(paths)
assert changes == {'usr': 'retain', 'usr/share': 'retain',
    **{'usr/share/' + p: k for p, k in {
        'retained': 'retain', 'changed': 'replace', 'removed': 'remove',
        'added': 'add', 'flip': 'replace', 'reverse': 'replace',
        'link': 'replace', 'mode': 'replace', 'a b': 'retain'}.items()}}
PY
cp "$tmp/new/DATA/usr/share/changed" "$tmp/root/usr/share/changed"
rm "$tmp/root/usr/share/removed"
expect 4 "$helper" --file-plan "$tmp/old.holy" "$tmp/new.holy" "$tmp/root"
expect 0 "$helper" --file-plan-recovery "$tmp/old.holy" "$tmp/new.holy" "$tmp/root"
cmp "$tmp/first" "$tmp/record"
mkdir -p "$tmp/final/usr/share"
"$helper" "$tmp/new.holy" "$tmp/final"
expect 0 "$helper" --file-plan-recovery "$tmp/old.holy" "$tmp/new.holy" "$tmp/final"
printf 'user modification\n' > "$tmp/final/usr/share/retained"
expect 4 "$helper" --file-plan-recovery "$tmp/old.holy" "$tmp/new.holy" "$tmp/final"
head -c 40 "$tmp/new.holy" > "$tmp/truncated.holy"
expect 2 "$helper" --file-plan "$tmp/old.holy" "$tmp/truncated.holy" "$tmp/root"
test ! -s "$tmp/record"
mkdir -p "$tmp/clean/usr/share"
"$helper" "$tmp/old.holy" "$tmp/clean"
cp -a "$tmp/old" "$tmp/directories"
mkdir "$tmp/directories/DATA/usr/share/new-directory"
pack directories
expect 0 "$helper" --file-plan "$tmp/old.holy" "$tmp/directories.holy" "$tmp/clean"
grep -q 'after dir "usr/share/new-directory"' "$tmp/record"
cp -a "$tmp/old" "$tmp/absolute"
ln -s /usr/share/retained "$tmp/absolute/DATA/usr/share/absolute"
pack absolute
expect 6 "$helper" --file-plan "$tmp/old.holy" "$tmp/absolute.holy" "$tmp/clean"
grep -q 'after symlink "usr/share/absolute"' "$tmp/record"
cp -a "$tmp/old" "$tmp/names"
name=$(printf 'line\nname')
printf 'escaped name\n' > "$tmp/names/DATA/usr/share/$name"
pack names
expect 0 "$helper" --file-plan "$tmp/old.holy" "$tmp/names.holy" "$tmp/clean"
grep -Fq 'after file "usr/share/line\x0aname"' "$tmp/record"
cp -a "$tmp/old" "$tmp/modes"
chmod 700 "$tmp/modes/DATA/usr/share"
pack modes
expect 6 "$helper" --file-plan "$tmp/old.holy" "$tmp/modes.holy" "$tmp/clean"
grep -q 'after dir "usr/share" 700' "$tmp/record"
cp -a "$tmp/old" "$tmp/hardlinks"
ln "$tmp/hardlinks/DATA/usr/share/retained" "$tmp/hardlinks/DATA/usr/share/hard"
python3 - "$tmp/hardlinks" "$tmp/hardlinks.tar" <<'PY'
import pathlib, shlex, sys, tarfile
tree = pathlib.Path(sys.argv[1])
manifest = tree / 'HOLY/files'
lines = manifest.read_text().splitlines()
for i, line in enumerate(lines):
    fields = shlex.split(line)
    if fields[1] == 'usr/share/retained':
        fields[11] = 'group1'
        lines[i] = ' '.join(fields)
        fields[0], fields[1] = 'hardlink', 'usr/share/hard'
        fields.append('usr/share/retained')
        lines.append(' '.join(fields))
        break
else:
    raise AssertionError('missing regular target')
manifest.write_text('\n'.join(lines) + '\n')
with tarfile.open(sys.argv[2], 'w', format=tarfile.PAX_FORMAT) as out:
    out.add(tree / 'HOLY', arcname='HOLY')
    for path in ['DATA', 'DATA/usr', 'DATA/usr/share']:
        out.add(tree / path, arcname=path, recursive=False)
    out.add(tree / 'DATA/usr/share/retained', arcname='DATA/usr/share/retained')
    for path in sorted((tree / 'DATA/usr/share').iterdir()):
        if path.name != 'retained':
            out.add(path, arcname='DATA/usr/share/' + path.name)
PY
lz4 -q "$tmp/hardlinks.tar" "$tmp/hardlinks.holy"
"$bin" verify "local:$tmp/hardlinks.holy" > "$tmp/out"
expect 0 "$helper" --file-plan "$tmp/old.holy" "$tmp/hardlinks.holy" "$tmp/clean"
grep -q 'after hardlink "usr/share/hard" .* "usr/share/retained" "group1"' "$tmp/record"
grep -q 'group-stage "usr/share/retained" ".holy-update-.*-group"' "$tmp/record"
printf 'file plan fixtures passed\n'
