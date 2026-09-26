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
"$bin" verify "local:$tmp/package.holy" > "$tmp/out"
grep -qx 'verified 1 regular files, 0 symlinks, 2 directories' "$tmp/out"
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
grep -qx 'verified 1 regular files, 1 symlinks, 2 directories' "$tmp/out"
rm "$tmp/payload/DATA/usr/bin/link"
ln -s ../../../escape "$tmp/payload/DATA/usr/bin/link"
tar -cf "$tmp/symlink.tar" -C "$tmp/payload" HOLY DATA
lz4 -q -f "$tmp/symlink.tar" "$tmp/unsafe-link.holy"
if "$bin" verify "local:$tmp/unsafe-link.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'unsafe symlink target' "$tmp/err"
rm "$tmp/payload/DATA/usr/bin/link"
mv "$tmp/files-original" "$tmp/payload/HOLY/files"
ln "$tmp/payload/DATA/usr/bin/hello" "$tmp/payload/DATA/usr/bin/hard"
tar -cf "$tmp/hard.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/hard.tar" "$tmp/hard.holy"
if "$bin" verify "local:$tmp/hard.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'unsupported payload type' "$tmp/err"
rm "$tmp/payload/DATA/usr/bin/hard"
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
printf 'package fixtures passed\n'
