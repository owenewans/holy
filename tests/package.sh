#!/bin/sh
set -eu
bin=$1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -p "$tmp/payload/HOLY" "$tmp/payload/DATA/usr/bin"
cat > "$tmp/payload/HOLY/meta" <<'EOF'
format holy-package-1
name fixture
version 1.0
release 1
os linux
arch x86_64
libc nolibc
EOF
printf 'hello\n' > "$tmp/payload/DATA/usr/bin/hello"
for member in deps provides hooks origin transform; do
    : > "$tmp/payload/HOLY/$member"
done
digest=$(sha256sum "$tmp/payload/DATA/usr/bin/hello" | cut -d ' ' -f 1)
mode=$(stat -c %a "$tmp/payload/DATA/usr/bin/hello")
uid=$(stat -c %u "$tmp/payload/DATA/usr/bin/hello")
gid=$(stat -c %g "$tmp/payload/DATA/usr/bin/hello")
printf 'file usr/bin/hello %s root root %s %s 6 %s none - -\n' \
    "$mode" "$uid" "$gid" "$digest" > "$tmp/payload/HOLY/files"
for dir in usr usr/bin; do
    dmode=$(stat -c %a "$tmp/payload/DATA/$dir")
    printf 'dir %s %s root root %s %s 0 - none - -\n' \
        "$dir" "$dmode" "$uid" "$gid" >> "$tmp/payload/HOLY/files"
done
tar -cf "$tmp/payload.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/payload.tar" "$tmp/package.holy"
"$bin" info "local:$tmp/package.holy" > "$tmp/out"
grep -qx 'name fixture' "$tmp/out"
grep -qx 'libc nolibc' "$tmp/out"
expected=$(sha256sum "$tmp/package.holy" | cut -d ' ' -f 1)
grep -qx "sha256 $expected" "$tmp/out"
mkdir "$tmp/fetched"
fetched=$("$bin" fetch "local:$tmp/package.holy" --output "$tmp/fetched")
test "$fetched" = "$tmp/fetched/$expected.holy"
cmp "$tmp/package.holy" "$fetched"
test "$("$bin" fetch "local:$tmp/package.holy" --output "$tmp/fetched")" = "$fetched"
printf 'damaged\n' > "$fetched"
if "$bin" fetch "local:$tmp/package.holy" --output "$tmp/fetched" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'existing object differs' "$tmp/err"
grep -qx damaged "$fetched"
rm "$fetched"
ln -s "$tmp/package.holy" "$fetched"
if "$bin" fetch "local:$tmp/package.holy" --output "$tmp/fetched" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'existing object differs' "$tmp/err"
test -L "$fetched"
rm "$fetched"
ln -s "$tmp/fetched" "$tmp/fetched-link"
if "$bin" fetch "local:$tmp/package.holy" --output "$tmp/fetched-link" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'output directory' "$tmp/err"
mkfifo "$tmp/pipe"
if "$bin" fetch "local:$tmp/pipe" --output "$tmp/fetched" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'input must be a regular file' "$tmp/err"
TMPDIR="$tmp" "$bin" fetch "local:$tmp/package.holy" --extract --output "$tmp/unpacked" > "$tmp/out"
cmp "$tmp/payload/HOLY/meta" "$tmp/unpacked/HOLY/meta"
cmp "$tmp/payload/DATA/usr/bin/hello" "$tmp/unpacked/DATA/usr/bin/hello"
test -z "$(find "$tmp" -maxdepth 1 -name 'holy-extract-*' -print)"
if "$bin" fetch "local:$tmp/package.holy" --extract --output "$tmp/unpacked" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'create extraction directory' "$tmp/err"
cp "$tmp/payload/HOLY/files" "$tmp/files-original"
chmod 4755 "$tmp/payload/DATA/usr/bin/hello"
sed "s@^file usr/bin/hello $mode @file usr/bin/hello 4755 @" \
    "$tmp/files-original" > "$tmp/payload/HOLY/files"
tar -cf "$tmp/setuid.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/setuid.tar" "$tmp/setuid.holy"
"$bin" fetch "local:$tmp/setuid.holy" --extract --output "$tmp/setuid-out" > "$tmp/out"
test "$(stat -c %a "$tmp/setuid-out/DATA/usr/bin/hello")" = 755
chmod "$mode" "$tmp/payload/DATA/usr/bin/hello"
mv "$tmp/files-original" "$tmp/payload/HOLY/files"
rm "$tmp/payload/HOLY/origin"
tar -cf "$tmp/missing-member.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/missing-member.tar" "$tmp/missing-member.holy"
if "$bin" info "local:$tmp/missing-member.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'missing HOLY/origin' "$tmp/err"
: > "$tmp/payload/HOLY/origin"
tar -cf "$tmp/duplicate-member.tar" -C "$tmp/payload" HOLY DATA
tar -rf "$tmp/duplicate-member.tar" -C "$tmp/payload" HOLY/origin
lz4 -q "$tmp/duplicate-member.tar" "$tmp/duplicate-member.holy"
if "$bin" info "local:$tmp/duplicate-member.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'repeated HOLY/origin' "$tmp/err"
rm "$tmp/payload/HOLY/origin"
ln -s meta "$tmp/payload/HOLY/origin"
tar -cf "$tmp/symlink-member.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/symlink-member.tar" "$tmp/symlink-member.holy"
if "$bin" info "local:$tmp/symlink-member.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'invalid or repeated HOLY/origin' "$tmp/err"
rm "$tmp/payload/HOLY/origin"
: > "$tmp/payload/HOLY/origin"
"$bin" verify "local:$tmp/package.holy" > "$tmp/out"
grep -qx 'verified 1 regular files, 0 symlinks, 2 directories, 0 hardlinks' "$tmp/out"
printf 'world\n' > "$tmp/payload/DATA/usr/bin/hello"
tar -cf "$tmp/payload.tar" -C "$tmp/payload" HOLY DATA
lz4 -q -f "$tmp/payload.tar" "$tmp/changed.holy"
if "$bin" verify "local:$tmp/changed.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'payload SHA-256 mismatch' "$tmp/err"
printf 'hello\n' > "$tmp/payload/DATA/usr/bin/hello"
tar -cf "$tmp/duplicate.tar" -C "$tmp/payload" HOLY DATA
tar -rf "$tmp/duplicate.tar" -C "$tmp/payload" DATA/usr/bin/hello
lz4 -q "$tmp/duplicate.tar" "$tmp/duplicate.holy"
if "$bin" verify "local:$tmp/duplicate.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'duplicate payload path' "$tmp/err"
cp "$tmp/payload/HOLY/files" "$tmp/files-original"
ln -s hello "$tmp/payload/DATA/usr/bin/link"
linkmode=$(stat -c %a "$tmp/payload/DATA/usr/bin/link")
printf 'symlink usr/bin/link %s root root %s %s 0 - none - - hello\n' \
    "$linkmode" "$uid" "$gid" >> "$tmp/payload/HOLY/files"
tar -cf "$tmp/symlink.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/symlink.tar" "$tmp/symlink.holy"
"$bin" verify "local:$tmp/symlink.holy" > "$tmp/out"
grep -qx 'verified 1 regular files, 1 symlinks, 2 directories, 0 hardlinks' "$tmp/out"
if "$bin" fetch "local:$tmp/symlink.holy" --extract --output "$tmp/symlink-out" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'unsupported or damaged extraction input' "$tmp/err"
test ! -e "$tmp/symlink-out"
rm "$tmp/payload/DATA/usr/bin/link"
ln -s ../../../escape "$tmp/payload/DATA/usr/bin/link"
tar -cf "$tmp/symlink.tar" -C "$tmp/payload" HOLY DATA
lz4 -q -f "$tmp/symlink.tar" "$tmp/unsafe-link.holy"
if "$bin" verify "local:$tmp/unsafe-link.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'unsafe symlink target' "$tmp/err"
rm "$tmp/payload/DATA/usr/bin/link"
mv "$tmp/files-original" "$tmp/payload/HOLY/files"
ln "$tmp/payload/DATA/usr/bin/hello" "$tmp/payload/DATA/usr/bin/hard"
cp "$tmp/payload/HOLY/files" "$tmp/files-original"
sed 's/^file \(.*\) none - -$/file \1 none - group1/' \
    "$tmp/files-original" > "$tmp/payload/HOLY/files"
printf 'hardlink usr/bin/hard %s root root %s %s 6 %s none - group1 usr/bin/hello\n' \
    "$mode" "$uid" "$gid" "$digest" >> "$tmp/payload/HOLY/files"
tar -cf "$tmp/hard.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/hard.tar" "$tmp/hard.holy"
"$bin" verify "local:$tmp/hard.holy" > "$tmp/out"
grep -qx 'verified 1 regular files, 0 symlinks, 2 directories, 1 hardlinks' "$tmp/out"
if "$bin" fetch "local:$tmp/hard.holy" --extract --output "$tmp/hard-out" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'unsupported or damaged extraction input' "$tmp/err"
test ! -e "$tmp/hard-out"
sed 's/group1 usr\/bin\/hello$/group2 usr\/bin\/hello/' \
    "$tmp/payload/HOLY/files" > "$tmp/files-mismatch"
mv "$tmp/files-mismatch" "$tmp/payload/HOLY/files"
tar -cf "$tmp/hard.tar" -C "$tmp/payload" HOLY DATA
lz4 -q -f "$tmp/hard.tar" "$tmp/hard-mismatch.holy"
if "$bin" verify "local:$tmp/hard-mismatch.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'hardlink group mismatch' "$tmp/err"
rm "$tmp/payload/DATA/usr/bin/hard"
mv "$tmp/files-original" "$tmp/payload/HOLY/files"
sed '/^dir usr\/bin /d' "$tmp/payload/HOLY/files" > "$tmp/files-without-dir"
cp "$tmp/payload/HOLY/files" "$tmp/files-original"
mv "$tmp/files-without-dir" "$tmp/payload/HOLY/files"
tar -cf "$tmp/omitted-dir.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/omitted-dir.tar" "$tmp/omitted-dir.holy"
if "$bin" verify "local:$tmp/omitted-dir.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'unlisted payload object' "$tmp/err"
mv "$tmp/files-original" "$tmp/payload/HOLY/files"
chmod 700 "$tmp/payload/DATA/usr/bin"
tar -cf "$tmp/changed-dir.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/changed-dir.tar" "$tmp/changed-dir.holy"
if "$bin" verify "local:$tmp/changed-dir.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'payload or attributes mismatch' "$tmp/err"
chmod "$dmode" "$tmp/payload/DATA/usr/bin"
cp "$tmp/package.holy" "$tmp/broken.holy"
printf 'not a frame' > "$tmp/broken.holy"
if "$bin" info "local:$tmp/broken.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'expected LZ4 frame' "$tmp/err"
sed 's/format holy-package-1/format future-format/' "$tmp/payload/HOLY/meta" > "$tmp/meta"
mv "$tmp/meta" "$tmp/payload/HOLY/meta"
tar -cf "$tmp/payload.tar" -C "$tmp/payload" HOLY DATA
lz4 -q -f "$tmp/payload.tar" "$tmp/future.holy"
if "$bin" info "local:$tmp/future.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'unsupported format' "$tmp/err"
sed 's/format future-format/format holy-package-1\nrequires-feature unknown-extension/' \
    "$tmp/payload/HOLY/meta" > "$tmp/meta"
mv "$tmp/meta" "$tmp/payload/HOLY/meta"
tar -cf "$tmp/payload.tar" -C "$tmp/payload" HOLY DATA
lz4 -q -f "$tmp/payload.tar" "$tmp/feature.holy"
if "$bin" info "local:$tmp/feature.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'unsupported feature' "$tmp/err"
tar -cf "$tmp/traversal.tar" --transform='s@^DATA/usr/bin/hello$@DATA/../../escape@' \
    -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/traversal.tar" "$tmp/traversal.holy"
if "$bin" info "local:$tmp/traversal.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'unsafe or unexpected archive path' "$tmp/err"
if "$bin" fetch "local:$tmp/traversal.holy" --extract --output "$tmp/traversal-out" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test ! -e "$tmp/traversal-out"
printf 'package fixtures passed\n'
