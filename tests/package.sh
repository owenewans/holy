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
tar -cf "$tmp/payload.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/payload.tar" "$tmp/package.holy"
"$bin" info "local:$tmp/package.holy" > "$tmp/out"
grep -qx 'name fixture' "$tmp/out"
grep -qx 'libc nolibc' "$tmp/out"
expected=$(sha256sum "$tmp/package.holy" | cut -d ' ' -f 1)
grep -qx "sha256 $expected" "$tmp/out"
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
printf 'package fixtures passed\n'
