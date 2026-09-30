#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/root"
tree="$tmp/tree"
mkdir -p "$root"
expect() {
    wanted=$1
    shift
    if "$@" > "$tmp/out" 2> "$tmp/err"; then got=0; else got=$?; fi
    test "$got" -eq "$wanted" || { cat "$tmp/out" "$tmp/err"; exit 1; }
}
new() {
    rm -rf "$tree"
    mkdir -p "$tree/HOLY" "$tree/DATA"
    printf 'format holy-package-1\nname %s\nversion 1\nrelease 1\nos linux\narch %s\nlibc glibc\n' \
        "$1" "${2:-x86_64}" > "$tree/HOLY/meta"
    for name in deps provides hooks origin transform; do : > "$tree/HOLY/$name"; done
}
pack() {
    "$bin" manifest generate "$tree" --output "$tmp/files" > "$tmp/out"
    mv "$tmp/files" "$tree/HOLY/files"
    "$bin" pack "$tree" --output "$tmp/$1.holy" > "$tmp/out"
    "$bin" cache stage "local:$tmp/$1.holy" --root "$root" > "$tmp/out"
}
hash() { sha256sum "$tmp/$1.holy" | cut -d ' ' -f 1; }
for tool in gcc patchelf ld as; do
    command -v "$tool" > /dev/null || exit 6
done
printf 'int search_fixture(void) { return 0; }\n' > "$tmp/library.c"
printf 'extern int search_fixture(void); int main(void) { return search_fixture(); }\n' > "$tmp/main.c"
printf 'SEARCH_1 { global: search_fixture; local: *; };\n' > "$tmp/map"
gcc -shared -fPIC -Wl,-soname,libsearchfixture.so.1 -Wl,--version-script="$tmp/map" \
    -Wl,--no-as-needed -o "$tmp/libsearchfixture.so.1.2" "$tmp/library.c" -lc
gcc -o "$tmp/consumer" "$tmp/main.c" -Wl,--no-as-needed "$tmp/libsearchfixture.so.1.2"
test -z "$(patchelf --print-rpath "$tmp/consumer")"
host_loader=$(patchelf --print-interpreter "$tmp/consumer")
test -n "$host_loader"
"$bin" db init --root "$root" > "$tmp/out"
new search-provider
mkdir -p "$tree/DATA/usr/lib64"
cp "$tmp/libsearchfixture.so.1.2" "$tree/DATA/usr/lib64/libsearchfixture.so.1.2"
ln -s libsearchfixture.so.1.2 "$tree/DATA/usr/lib64/libsearchfixture.so.1"
pack search-provider
new search-runtime
mkdir -p "$tree/DATA/lib64" "$tree/DATA/usr/lib64"
cp -L "$host_loader" "$tree/DATA/lib64/ld-linux-x86-64.so.2"
cp -L "$(gcc -print-file-name=libc.so.6)" "$tree/DATA/usr/lib64/libc.so.6"
sha256sum "$tree/DATA/lib64/ld-linux-x86-64.so.2" \
    "$tree/DATA/usr/lib64/libc.so.6" > "$tree/HOLY/origin"
pack search-runtime
new search-consumer
mkdir -p "$tree/DATA/usr/bin"
cp "$tmp/consumer" "$tree/DATA/usr/bin/consumer"
patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 "$tree/DATA/usr/bin/consumer"
sha256sum "$tree/DATA/usr/bin/consumer" > "$tree/HOLY/origin"
pack search-consumer
consumer=$(hash search-consumer) provider=$(hash search-provider) runtime=$(hash search-runtime)
# a provider that keeps the name outside every searched directory leaves it unresolvable
new private-provider
mkdir -p "$tree/DATA/usr/lib/holy/x86_64-linux-gnu"
cp "$tmp/libsearchfixture.so.1.2" \
    "$tree/DATA/usr/lib/holy/x86_64-linux-gnu/libsearchfixture.so.1.2"
ln -s libsearchfixture.so.1.2 \
    "$tree/DATA/usr/lib/holy/x86_64-linux-gnu/libsearchfixture.so.1"
pack private-provider
expect 3 "$bin" db plan-set "$consumer" "$(hash private-provider)" "$runtime" --root "$root"
grep -q 'unknown-loader-search consumer=usr/bin/consumer requirement=libsearchfixture.so.1' \
    "$tmp/err"
grep -q 'search=/lib64:/usr/lib64:/lib:/usr/lib' "$tmp/err"
# the same name in a searched directory resolves without a runpath
expect 0 "$bin" db plan-set "$consumer" "$provider" "$runtime" --root "$root"
grep -q " soname libsearchfixture.so.1$" "$tmp/out"
plan=$(sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
test "${#plan}" -eq 64
expect 0 "$bin" db apply-set "$plan" "$consumer" "$provider" "$runtime" --root "$root"
expect 0 "$bin" db check --all --root "$root"
test -e "$root/usr/lib64/libsearchfixture.so.1"
expect 0 "$bin" index --root "$root" --path /usr/lib64/libsearchfixture.so.1 --json
grep -q "\"artifact\":\"$provider\"" "$tmp/out"
expect 0 "$bin" db rm "$consumer" --root "$root"
expect 0 "$bin" db rm "$provider" --root "$root"
expect 0 "$bin" db rm "$runtime" --root "$root"
# a 32 bit consumer searches the narrow list, so a 64 bit placement does not satisfy it
printf '.global search_fixture32\n.type search_fixture32,@function\nsearch_fixture32: ret\n' \
    | as --32 -o "$tmp/search32.o"
printf '.global libc_fixture32\n.type libc_fixture32,@function\nlibc_fixture32: ret\n' \
    | as --32 -o "$tmp/libc32.o"
ld -m elf_i386 -shared -soname libc.so.6 -o "$tmp/libc32.so" "$tmp/libc32.o"
gcc -m32 -nostdlib -shared -Wl,-soname,libsearchfixture32.so.1 -Wl,--no-as-needed \
    -o "$tmp/libsearchfixture32.so" "$tmp/search32.o" "$tmp/libc32.so"
printf 'extern int search_fixture32(void); int main(void) { return search_fixture32(); }\n' \
    > "$tmp/main32.c"
if ! gcc -m32 -nostdlib -o "$tmp/consumer32" "$tmp/main32.c" -Wl,--no-as-needed \
    "$tmp/libsearchfixture32.so" "$tmp/libc32.so" 2> "$tmp/err"; then
        exit 6
fi
new search32-provider x86
mkdir -p "$tree/DATA/usr/lib"
cp "$tmp/libsearchfixture32.so" "$tree/DATA/usr/lib/libsearchfixture32.so.1"
pack search32-provider
new search32-private x86
mkdir -p "$tree/DATA/usr/lib64"
cp "$tmp/libsearchfixture32.so" "$tree/DATA/usr/lib64/libsearchfixture32.so.1"
pack search32-private
loader32=$(patchelf --print-interpreter "$tmp/consumer32")
test -n "$loader32"
new search32-runtime x86
mkdir -p "$tree/DATA/usr/lib" "$tree/DATA$(dirname "$loader32")"
cp "$tmp/libc32.so" "$tree/DATA/usr/lib/libc.so.6"
cp -L "$loader32" "$tree/DATA$loader32"
pack search32-runtime
new search32-consumer x86
mkdir -p "$tree/DATA/usr/bin"
cp "$tmp/consumer32" "$tree/DATA/usr/bin/consumer32"
pack search32-consumer
consumer32=$(hash search32-consumer) provider32=$(hash search32-provider)
private32=$(hash search32-private) runtime32=$(hash search32-runtime)
# the host is x86_64 and the 32 bit set is not proven to run here, so the placement
# decision is stated
expect 3 "$bin" db plan-set "$consumer32" "$private32" "$runtime32" \
    --accept-arch "$consumer32" --accept-arch "$private32" --accept-arch "$runtime32" \
    --root "$root"
grep -q 'search=/lib:/usr/lib$' "$tmp/err"
expect 0 "$bin" db plan-set "$consumer32" "$provider32" "$runtime32" \
    --accept-arch "$consumer32" --accept-arch "$provider32" --accept-arch "$runtime32" \
    --root "$root"
printf 'default loader search fixtures passed\n'
