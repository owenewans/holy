#!/bin/sh
# the spec names tcc, gcc and clang for the core build, so each of them compiles it
# here and packs a package, which keeps a toolchain that breaks the C99 build from
# passing unnoticed.
set -eu
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT HUP INT TERM
make=${MAKE:-make}
for cc in tcc gcc clang; do
    command -v "$cc" >/dev/null 2>&1 || {
        echo "$cc required for the compiler fixture" >&2
        exit 6
    }
done
tree() {
    rm -rf "$1"
    mkdir -p "$1/HOLY" "$1/DATA/usr/bin"
    printf 'format holy-package-1\nname compiler-fixture\nversion 1\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' \
        > "$1/HOLY/meta"
    for field in deps provides hooks origin transform; do : > "$1/HOLY/$field"; done
    printf 'compiler fixture\n' > "$1/DATA/usr/bin/compiler-fixture"
}
for cc in tcc gcc clang; do
    if ! "$make" CC="$cc" holypkg > "$root/build-$cc.log" 2>&1; then
        cat "$root/build-$cc.log" >&2
        echo "$cc did not compile the core" >&2
        exit 1
    fi
    tree "$root/tree"
    # the generator refuses to replace an existing manifest, so its output is fresh
    rm -f "$root/tree-files"
    ./holypkg manifest generate "$root/tree" --output "$root/tree-files" > "$root/out"
    cp "$root/tree-files" "$root/tree/HOLY/files"
    # the packer publishes without replacement, so each artifact name is fresh
    rm -f "$root/fixture.holy"
    ./holypkg pack "$root/tree" --output "$root/fixture.holy" > "$root/out"
    ./holypkg verify "local:$root/fixture.holy" > "$root/out"
    ./holypkg manifest "local:$root/fixture.holy" > "$root/listing"
    grep -q 'usr/bin/compiler-fixture' "$root/listing" || {
        echo "$cc packed a fixture without its payload" >&2
        exit 1
    }
    echo "built and packed with $cc"
done
"$make" > "$root/build-default.log" 2>&1 || {
    cat "$root/build-default.log" >&2
    exit 1
}
echo "compiler fixtures passed"
