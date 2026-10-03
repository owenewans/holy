#!/bin/sh
# the spec names tcc, gcc and clang for the core build, so each of them compiles it
# here and packs a package, which keeps a toolchain that breaks the C99 build from
# passing unnoticed. a compiler builds its own copy of the tree, so the three run at
# once, their objects stay out of each other's way and the caller's own build is left
# as the compiler they invoked it with.
set -eu
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT HUP INT TERM
make=${MAKE:-make}
jobs=${JOBS:-$(nproc 2>/dev/null || echo 4)}
repo=$(pwd)
for cc in tcc gcc clang; do
    command -v "$cc" >/dev/null 2>&1 || {
        echo "$cc required for the compiler fixture" >&2
        exit 6
    }
    mkdir -p "$root/$cc" "$root/$cc-out"
    cp -a "$repo/Makefile" "$repo/src" "$repo/backends" "$root/$cc/"
done
tree() {
    rm -rf "$1"
    mkdir -p "$1/HOLY" "$1/DATA/usr/bin"
    printf 'format holy-package-1\nname compiler-fixture\nversion 1\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' \
        > "$1/HOLY/meta"
    for field in deps provides hooks origin transform; do : > "$1/HOLY/$field"; done
    printf 'compiler fixture\n' > "$1/DATA/usr/bin/compiler-fixture"
}
fixture() {
    binary="$root/$1/holypkg"
    out="$root/$1-out"
    tree "$out/tree"
    # the generator refuses to replace an existing manifest, so its output is fresh
    rm -f "$out/tree-files"
    "$binary" manifest generate "$out/tree" --output "$out/tree-files" > /dev/null
    cp "$out/tree-files" "$out/tree/HOLY/files"
    # the packer publishes without replacement, so each artifact name is fresh
    rm -f "$out/fixture.holy"
    "$binary" pack "$out/tree" --output "$out/fixture.holy" > /dev/null
    "$binary" verify "local:$out/fixture.holy" > /dev/null
    "$binary" manifest "local:$out/fixture.holy" > "$out/listing"
    grep -q 'usr/bin/compiler-fixture' "$out/listing"
}
pids=
for cc in tcc gcc clang; do
    (
        if ! "$make" -C "$root/$cc" -j"$jobs" CC="$cc" holypkg > "$root/build-$cc.log" 2>&1; then
            echo "$cc did not compile the core" >&2
            cat "$root/build-$cc.log" >&2
            exit 1
        fi
        if ! fixture "$cc"; then
            echo "$cc packed a fixture without its payload" >&2
            exit 1
        fi
        echo "built and packed with $cc"
    ) > "$root/report-$cc" 2>&1 &
    pids="$pids $!"
done
failed=
for pid in $pids; do
    wait "$pid" || failed=yes
done
for cc in tcc gcc clang; do
    if test -s "$root/report-$cc"; then
        if test -n "$failed"; then cat "$root/report-$cc" >&2; else cat "$root/report-$cc"; fi
    fi
done
if test -n "$failed"; then
    echo "compiler fixtures failed" >&2
    exit 1
fi
echo "compiler fixtures passed"
