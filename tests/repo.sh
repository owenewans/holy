#!/bin/sh
set -eu
bin=$1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir "$tmp/empty"
"$bin" repo index "$tmp/empty" > "$tmp/out"
grep -qx 'indexed 0 packages' "$tmp/out"
grep -qx 'format holy-index-prototype-1' "$tmp/empty/index"
"$bin" repo list "$tmp/empty" > "$tmp/out"
grep -qx 'listed 0 packages' "$tmp/out"
mkdir -p "$tmp/repo" "$tmp/payload/HOLY" "$tmp/payload/DATA"
cat > "$tmp/payload/HOLY/meta" <<'EOF'
format holy-package-1
name fixture
version 1.0
release 1
os linux
arch noarch
libc nolibc
EOF
for member in files deps provides hooks origin transform; do
    : > "$tmp/payload/HOLY/$member"
done
tar -cf "$tmp/fixture.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/fixture.tar" "$tmp/repo/fixture.holy"
"$bin" repo index "$tmp/repo" > "$tmp/out"
grep -qx 'indexed 1 packages' "$tmp/out"
hash=$(sha256sum "$tmp/repo/fixture.holy")
hash=${hash%% *}
size=$(stat -c %s "$tmp/repo/fixture.holy")
grep -qx 'format holy-index-prototype-1' "$tmp/repo/index"
grep -qx "package \"fixture\" \"1.0\" \"1\" \"linux\" \"noarch\" \"nolibc\" \"fixture.holy\" $hash $size" "$tmp/repo/index"
"$bin" repo list "$tmp/repo" > "$tmp/out"
grep -qx 'listed 1 packages' "$tmp/out"
grep -qx "package \"fixture\" \"1.0\" \"1\" \"linux\" \"noarch\" \"nolibc\" \"fixture.holy\" $hash $size" "$tmp/out"
test "$(stat -c %a "$tmp/repo/index")" = 644
cp "$tmp/repo/index" "$tmp/previous"
sed "s/$hash/$(printf '%064d' 0)/" "$tmp/previous" > "$tmp/repo/index"
if "$bin" repo list "$tmp/repo" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test ! -s "$tmp/out"
grep -q 'invalid or stale repository index' "$tmp/err"
cp "$tmp/previous" "$tmp/repo/index"
cat "$tmp/previous" >> "$tmp/repo/index"
if "$bin" repo list "$tmp/repo" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test ! -s "$tmp/out"
cp "$tmp/previous" "$tmp/repo/index"
"$bin" repo index "$tmp/repo" > "$tmp/out"
cmp "$tmp/previous" "$tmp/repo/index"
cp "$tmp/repo/fixture.holy" "$tmp/repo/second.holy"
if "$bin" repo index "$tmp/repo" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'duplicate package identity' "$tmp/err"
cmp "$tmp/previous" "$tmp/repo/index"
rm "$tmp/repo/second.holy"
sed -e 's/^name fixture$/name "fixture two"/' -e 's/^version 1.0$/version 2.0/' \
    "$tmp/payload/HOLY/meta" > "$tmp/new-meta"
mv "$tmp/new-meta" "$tmp/payload/HOLY/meta"
tar -cf "$tmp/variant.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/variant.tar" "$tmp/repo/variant.holy"
"$bin" repo index "$tmp/repo" > "$tmp/out"
grep -qx 'indexed 2 packages' "$tmp/out"
variant_hash=$(sha256sum "$tmp/repo/variant.holy")
variant_hash=${variant_hash%% *}
variant_size=$(stat -c %s "$tmp/repo/variant.holy")
grep -Fqx "package \"fixture\\x20two\" \"2.0\" \"1\" \"linux\" \"noarch\" \"nolibc\" \"variant.holy\" $variant_hash $variant_size" "$tmp/repo/index"
"$bin" repo list "$tmp/repo" > "$tmp/out"
grep -qx 'listed 2 packages' "$tmp/out"
cp "$tmp/repo/variant.holy" "$tmp/variant-original"
printf 'wrong\n' > "$tmp/repo/variant.holy"
if "$bin" repo list "$tmp/repo" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test ! -s "$tmp/out"
cp "$tmp/variant-original" "$tmp/repo/variant.holy"
cp "$tmp/repo/index" "$tmp/previous"
printf 'bad archive\n' > "$tmp/repo/bad.holy"
if "$bin" repo index "$tmp/repo" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
cmp "$tmp/previous" "$tmp/repo/index"
rm "$tmp/repo/bad.holy"
ln -s fixture.holy "$tmp/repo/link.holy"
if "$bin" repo index "$tmp/repo" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
cmp "$tmp/previous" "$tmp/repo/index"
rm "$tmp/repo/link.holy"
rm "$tmp/repo/index"
ln -s "$tmp/previous" "$tmp/repo/index"
if "$bin" repo list "$tmp/repo" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
if "$bin" repo index "$tmp/repo" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'index is not a regular file' "$tmp/err"
cmp "$tmp/previous" "$tmp/repo/index"
test -z "$(find "$tmp/repo" -name '.holy-tmp-*' -print)"
printf 'repository fixtures passed\n'
