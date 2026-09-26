#!/bin/sh
set -eu
bin=$1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -p "$tmp/payload/HOLY" "$tmp/payload/DATA"
for part in files deps provides hooks origin transform; do
    : > "$tmp/payload/HOLY/$part"
done
build() {
    name=$1 version=$2
    cat > "$tmp/payload/HOLY/meta" <<EOF
format holy-package-1
name $name
version $version
release 1
os linux
arch noarch
libc nolibc
EOF
    tar -cf "$tmp/$name-$version.tar" -C "$tmp/payload" HOLY DATA
    lz4 -q "$tmp/$name-$version.tar" "$tmp/$name-$version.holy"
}
printf 'require b-1 root package b any any any - b metadata\n' > "$tmp/payload/HOLY/deps"
build root 1
: > "$tmp/payload/HOLY/deps"
build b 1
build b 2
build unused 1
root_hash=$(sha256sum "$tmp/root-1.holy")
root_hash=${root_hash%% *}
b_hash=$(sha256sum "$tmp/b-1.holy")
b_hash=${b_hash%% *}
"$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" "local:$tmp/unused-1.holy" > "$tmp/out"
grep -qx "selected $root_hash" "$tmp/out"
grep -qx "selected $b_hash" "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 2
"$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" --json > "$tmp/out"
grep -Fqx "{\"schema\":\"holy-local-solve-1\",\"type\":\"selected\",\"sha256\":\"$root_hash\"}" "$tmp/out"
grep -Fqx "{\"schema\":\"holy-local-solve-1\",\"type\":\"selected\",\"sha256\":\"$b_hash\"}" "$tmp/out"
grep -Fqx '{"schema":"holy-local-solve-1","type":"summary","count":2}' "$tmp/out"
printf 'require c-1 b package c any any any - c metadata\n' > "$tmp/payload/HOLY/deps"
build b 3
: > "$tmp/payload/HOLY/deps"
build c 1
c_hash=$(sha256sum "$tmp/c-1.holy")
c_hash=${c_hash%% *}
"$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-3.holy" "local:$tmp/c-1.holy" > "$tmp/out"
grep -qx "selected $root_hash" "$tmp/out"
grep -qx "selected $c_hash" "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 3
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-3.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
test ! -s "$tmp/out"
printf 'provide package b noarch nolibc - metadata\n' > "$tmp/payload/HOLY/provides"
build alias 1
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/alias-1.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
test ! -s "$tmp/out"
: > "$tmp/payload/HOLY/provides"
if "$bin" solve "local:$tmp/root-1.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
test ! -s "$tmp/out"
if "$bin" solve "local:$tmp/root-1.holy" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"dependency-conflict"}' "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" "local:$tmp/b-2.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
test ! -s "$tmp/out"
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" "local:$tmp/b-2.holy" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"decision-required"}' "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
if "$bin" solve --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"invalid-query"}' "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
if "$bin" solve "local:$tmp/root-1.holy" bad --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"invalid-query"}' "$tmp/out"
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" "local:$tmp/b-1.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
test ! -s "$tmp/out"
printf 'require b-1 root soname b any any any - b metadata\n' > "$tmp/payload/HOLY/deps"
build root 2
if "$bin" solve "local:$tmp/root-2.holy" "local:$tmp/b-1.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
test ! -s "$tmp/out"
if "$bin" solve "local:$tmp/root-2.holy" "local:$tmp/b-1.holy" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"unsupported-input"}' "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
printf 'require b-1 root package b any any eq 1 b metadata\n' > "$tmp/payload/HOLY/deps"
build root 3
if "$bin" solve "local:$tmp/root-3.holy" "local:$tmp/b-1.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
test ! -s "$tmp/out"
: > "$tmp/payload/HOLY/deps"
printf 'postinstall /bin/sh script\n' > "$tmp/payload/HOLY/hooks"
build root 4
if "$bin" solve "local:$tmp/root-4.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
test ! -s "$tmp/out"
: > "$tmp/payload/HOLY/hooks"
printf 'patch binary\n' > "$tmp/payload/HOLY/transform"
build root 5
if "$bin" solve "local:$tmp/root-5.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
test ! -s "$tmp/out"
: > "$tmp/payload/HOLY/transform"
sed -i 's/arch noarch/arch x86_64/' "$tmp/payload/HOLY/meta"
tar -cf "$tmp/foreign.tar" -C "$tmp/payload" HOLY DATA
lz4 -q "$tmp/foreign.tar" "$tmp/foreign.holy"
if "$bin" solve "local:$tmp/foreign.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
test ! -s "$tmp/out"
printf 'broken\n' > "$tmp/broken.holy"
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" "local:$tmp/broken.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
test ! -s "$tmp/out"
printf 'local resolver fixtures passed\n'
