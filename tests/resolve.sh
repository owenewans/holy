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
mkdir "$tmp/repo"
cp "$tmp/root-1.holy" "$tmp/b-1.holy" "$tmp/unused-1.holy" "$tmp/repo/"
"$bin" repo index "$tmp/repo" > "$tmp/out"
if "$bin" repo solve "$tmp/repo" root --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"invalid-catalog"}' "$tmp/out"
"$bin" repo seal "$tmp/repo" > "$tmp/out"
generation=$(sha256sum "$tmp/repo/index")
generation=${generation%% *}
"$bin" repo solve "$tmp/repo" root --json > "$tmp/out"
grep -Fqx "{\"schema\":\"holy-local-solve-1\",\"type\":\"selected\",\"sha256\":\"$root_hash\"}" "$tmp/out"
grep -Fqx "{\"schema\":\"holy-local-solve-1\",\"type\":\"selected\",\"sha256\":\"$b_hash\"}" "$tmp/out"
grep -Fqx "{\"schema\":\"holy-local-solve-1\",\"type\":\"summary\",\"count\":2,\"generation\":\"$generation\"}" "$tmp/out"
"$bin" repo solve "$tmp/repo" root > "$tmp/out"
grep -qx "generation $generation" "$tmp/out"
if "$bin" repo solve "$tmp/repo" absent --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"unavailable-artifact"}' "$tmp/out"
mkdir "$tmp/repo-choice"
cp "$tmp/root-1.holy" "$tmp/b-1.holy" "$tmp/b-2.holy" "$tmp/repo-choice/"
"$bin" repo index "$tmp/repo-choice" > "$tmp/out"
"$bin" repo seal "$tmp/repo-choice" > "$tmp/out"
choice_generation=$(sha256sum "$tmp/repo-choice/index")
choice_generation=${choice_generation%% *}
b2_hash=$(sha256sum "$tmp/b-2.holy")
b2_hash=${b2_hash%% *}
if test "$#" -ge 2; then
    api=$2
    "$api" - "$tmp/root-1.holy" "$tmp/b-1.holy" "$tmp/unused-1.holy" > "$tmp/record"
    "$api" - "$tmp/root-1.holy" "$tmp/unused-1.holy" "$tmp/b-1.holy" > "$tmp/reordered"
    cmp "$tmp/record" "$tmp/reordered"
    grep -qx 'format holy-resolution-1' "$tmp/record"
    grep -qx 'scope artifact-candidates' "$tmp/record"
    grep -Fqx "edge \"$root_hash\" \"b-1\" \"$b_hash\" \"-\" \"package\" \"b\"" "$tmp/record"
    test "$(wc -l < "$tmp/record")" -eq 6
    "$api" "b-1=$b2_hash" "$tmp/root-1.holy" "$tmp/b-1.holy" "$tmp/b-2.holy" > "$tmp/chosen"
    grep -Fqx "edge \"$root_hash\" \"b-1\" \"$b2_hash\" \"-\" \"package\" \"b\"" "$tmp/chosen"
    if "$api" - "$tmp/root-1.holy" > "$tmp/record" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
    test ! -s "$tmp/record"
    "$api" --set "$tmp/root-1.holy" "$tmp/b-1.holy" "$tmp/unused-1.holy" > "$tmp/record"
    "$api" --set "$tmp/root-1.holy" "$tmp/unused-1.holy" "$tmp/b-1.holy" > "$tmp/reordered"
    cmp "$tmp/record" "$tmp/reordered"
    test "$(grep -c '^artifact ' "$tmp/record")" -eq 3
    if "$api" --set "$tmp/root-1.holy" "$tmp/b-1.holy" "$tmp/b-2.holy" > "$tmp/record" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
    test ! -s "$tmp/record"
    printf 'require missing-1 unused package missing any any any - missing metadata\n' > "$tmp/payload/HOLY/deps"
    build unused 2
    "$api" - "$tmp/root-1.holy" "$tmp/b-1.holy" "$tmp/unused-2.holy" > "$tmp/record"
    test "$(grep -c '^artifact ' "$tmp/record")" -eq 2
    if "$api" --set "$tmp/root-1.holy" "$tmp/b-1.holy" "$tmp/unused-2.holy" > "$tmp/record" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
    test ! -s "$tmp/record"
    printf 'require y-1 x package y any any any - y metadata\n' > "$tmp/payload/HOLY/deps"
    build x 1
    printf 'require x-1 y package x any any any - x metadata\n' > "$tmp/payload/HOLY/deps"
    build y 1
    "$api" --set "$tmp/root-1.holy" "$tmp/b-1.holy" "$tmp/x-1.holy" "$tmp/y-1.holy" > "$tmp/record"
    test "$(grep -c '^artifact ' "$tmp/record")" -eq 4
    test "$(grep -c '^edge ' "$tmp/record")" -eq 3
    : > "$tmp/payload/HOLY/deps"
fi
if "$bin" repo solve "$tmp/repo-choice" root --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"decision-required"}' "$tmp/out"
"$bin" repo solve "$tmp/repo-choice" root --choose "b-1=$b2_hash" --json > "$tmp/out"
grep -Fqx "{\"schema\":\"holy-local-solve-1\",\"type\":\"selected\",\"sha256\":\"$b2_hash\"}" "$tmp/out"
grep -Fqx "{\"schema\":\"holy-local-solve-1\",\"type\":\"summary\",\"count\":2,\"generation\":\"$choice_generation\"}" "$tmp/out"
if grep -Fq "\"sha256\":\"$b_hash\"" "$tmp/out"; then exit 1; fi
if "$bin" repo solve "$tmp/repo-choice" root --choose "b-1=$root_hash" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"decision-required"}' "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
if "$bin" repo solve "$tmp/repo-choice" root --choose broken --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"invalid-query"}' "$tmp/out"
printf 'corrupt\n' > "$tmp/repo/unused-1.holy"
if "$bin" repo solve "$tmp/repo" root --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"invalid-catalog"}' "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
cp "$tmp/unused-1.holy" "$tmp/repo/unused-1.holy"
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
b3_hash=$(sha256sum "$tmp/b-3.holy")
b3_hash=${b3_hash%% *}
"$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" "local:$tmp/b-3.holy" "local:$tmp/c-1.holy" --choose "b-1=$b3_hash" > "$tmp/out"
grep -qx "selected $c_hash" "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 3
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" "local:$tmp/b-3.holy" --choose "b-1=$b3_hash" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
test ! -s "$tmp/out"
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-3.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
test ! -s "$tmp/out"
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-3.holy" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"dependency-conflict","requirement":"c-1"}' "$tmp/out"
printf 'require d-1 b package d any any any - d metadata\n' > "$tmp/payload/HOLY/deps"
build b 4
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-3.holy" "local:$tmp/b-4.holy" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"dependency-conflict"}' "$tmp/out"
: > "$tmp/payload/HOLY/deps"
printf 'require root-1 b package root any any any - root metadata\n' > "$tmp/payload/HOLY/deps"
build b 5
"$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-5.holy" > "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 2
: > "$tmp/payload/HOLY/deps"
printf 'provide package b noarch nolibc - metadata\n' > "$tmp/payload/HOLY/provides"
build alias 1
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/alias-1.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
test ! -s "$tmp/out"
: > "$tmp/payload/HOLY/provides"
if "$bin" solve "local:$tmp/root-1.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
test ! -s "$tmp/out"
grep -q 'unresolved requirement b-1' "$tmp/err"
if "$bin" solve "local:$tmp/root-1.holy" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 4; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"dependency-conflict","requirement":"b-1"}' "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" "local:$tmp/b-2.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
test ! -s "$tmp/out"
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" "local:$tmp/b-2.holy" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"decision-required"}' "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
b2_hash=$(sha256sum "$tmp/b-2.holy")
b2_hash=${b2_hash%% *}
"$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" "local:$tmp/b-2.holy" --choose "b-1=$b2_hash" --json > "$tmp/out"
grep -Fqx "{\"schema\":\"holy-local-solve-1\",\"type\":\"selected\",\"sha256\":\"$b2_hash\"}" "$tmp/out"
if grep -Fq "\"sha256\":\"$b_hash\"" "$tmp/out"; then exit 1; fi
"$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" "local:$tmp/b-2.holy" --choose "b-1=$b_hash" > "$tmp/out"
grep -qx "selected $b_hash" "$tmp/out"
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" --choose "b-1=$root_hash" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"decision-required"}' "$tmp/out"
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" --choose "other=$b_hash" --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" --choose 'bad' --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"invalid-query"}' "$tmp/out"
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
cp "$tmp/root-2.holy" "$tmp/repo/"
"$bin" repo index "$tmp/repo" > "$tmp/out"
"$bin" repo seal "$tmp/repo" > "$tmp/out"
if "$bin" repo solve "$tmp/repo" root --json > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
grep -Fqx '{"schema":"holy-local-solve-1","type":"error","code":"decision-required"}' "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
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
"$bin" solve "local:$tmp/foreign.holy" > "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 1
printf 'broken\n' > "$tmp/broken.holy"
if "$bin" solve "local:$tmp/root-1.holy" "local:$tmp/b-1.holy" "local:$tmp/broken.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
test ! -s "$tmp/out"
printf 'local resolver fixtures passed\n'
