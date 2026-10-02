#!/bin/sh
set -eu
bin=$(realpath "$1")
helper=$(realpath "$2")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
tree="$tmp/tree"

expect() {
    expected=$1
    shift
    if "$@" > "$tmp/out" 2> "$tmp/err"; then actual=0; else actual=$?; fi
    test "$actual" -eq "$expected" || {
        echo "GOT $actual WANT $expected" >&2
        cat "$tmp/out" "$tmp/err" >&2
        exit 1
    }
}

cc=${CC:-cc}
command -v "$cc" >/dev/null 2>&1 || { echo "$cc required for the private consumer fixture" >&2; exit 6; }

# one library with a SONAME, one program that names it and one that needs a library of
# its own as well, which is the shape the spec calls out: fixing the main executable
# alone is not handling every consumer
printf 'int answer(void) { return 42; }\n' > "$tmp/lib.c"
printf 'int helper(void) { return 7; }\n' > "$tmp/helper.c"
printf 'int answer(void);\n#include <stdio.h>\nint main(void) { printf("%%d\\n", answer()); return 0; }\n' > "$tmp/prog.c"
printf 'int answer(void);\nint helper(void);\n#include <stdio.h>\nint main(void) { printf("%%d\\n", helper() + answer()); return 0; }\n' > "$tmp/both.c"
mkdir -p "$tmp/pub" "$tmp/build"
"$cc" -shared -fPIC -Wl,-soname,libanswer.so.1 -o "$tmp/pub/libanswer.so.1" "$tmp/lib.c"
"$cc" -c -fPIC -o "$tmp/build/helper.o" "$tmp/helper.c"
"$cc" -shared -fPIC -Wl,-soname,libhelper.so.1 -o "$tmp/pub/libhelper.so.1" "$tmp/build/helper.o"
"$cc" -o "$tmp/pub/prog" "$tmp/prog.c" -L"$tmp/pub" -l:libanswer.so.1 -Wl,-rpath,"$tmp/pub"
"$cc" -o "$tmp/pub/both" "$tmp/both.c" -L"$tmp/pub" -l:libanswer.so.1 -l:libhelper.so.1 \
    -Wl,-rpath,"$tmp/pub"
test "$("$tmp/pub/prog")" = 42
test "$("$tmp/pub/both")" = 49

pack() {
    name=$1
    shift
    rm -rf "$tree"
    mkdir -p "$tree/HOLY"
    printf 'format holy-package-1\nname %s\nversion 1\nrelease 1\nos linux\narch x86_64\nlibc glibc\n' "$name" > "$tree/HOLY/meta"
    : > "$tree/HOLY/deps"
    for field in provides hooks origin transform; do : > "$tree/HOLY/$field"; done
    for pair in "$@"; do
        source=${pair%%:*}
        target=${pair#*:}
        mkdir -p "$tree/DATA/$(dirname "$target")"
        cp "$tmp/pub/$source" "$tree/DATA/$target"
    done
    "$bin" manifest generate "$tree" --output "$tmp/files" > "$tmp/out"
    mv "$tmp/files" "$tree/HOLY/files"
    "$bin" pack "$tree" --output "$tmp/$name.holy" > "$tmp/out"
}

# a placed shared library is what a consumer names, so the SONAME is the fact a private
# set is matched on: the library states one, and a program states none
pack libanswer libanswer.so.1:usr/lib/libanswer.so.1
expect 0 "$helper" --soname "$tmp/libanswer.holy" usr/lib/libanswer.so.1
grep -qx "soname libanswer.so.1" "$tmp/out"

pack prog prog:usr/bin/prog
expect 0 "$helper" --soname "$tmp/prog.holy" usr/bin/prog
grep -qx "soname -" "$tmp/out"

# a path the package does not ship is not found rather than guessed
expect 0 "$helper" --soname "$tmp/prog.holy" usr/bin/absent
grep -qx "soname -" "$tmp/out"

# every ELF payload that names the SONAME is a consumer, and one that needs two
# libraries is still found for the one that moved
expect 0 "$helper" --consumers "$tmp/prog.holy" libanswer.so.1
grep -qx "consumer usr/bin/prog needs libanswer.so.1" "$tmp/out"
grep -qx "consumers 1" "$tmp/out"

pack both both:usr/bin/both libhelper.so.1:usr/lib/libhelper.so.1
expect 0 "$helper" --consumers "$tmp/both.holy" libanswer.so.1
grep -qx "consumer usr/bin/both needs libanswer.so.1" "$tmp/out"
grep -qx "consumers 1" "$tmp/out"
expect 0 "$helper" --consumers "$tmp/both.holy" libhelper.so.1
grep -qx "consumer usr/bin/both needs libhelper.so.1" "$tmp/out"

# the library a set would displace is not its own consumer
expect 0 "$helper" --consumers "$tmp/libanswer.holy" libanswer.so.1
grep -qx "consumers 0" "$tmp/out"

# a SONAME nothing carries finds no consumer rather than matching a fuzzy name
expect 0 "$helper" --consumers "$tmp/both.holy" libabsent.so.9
grep -qx "consumers 0" "$tmp/out"

# a package of plain data carries nothing to walk
printf 'data\n' > "$tmp/pub/data"
pack data data:usr/share/data
expect 0 "$helper" --consumers "$tmp/data.holy" libanswer.so.1
grep -qx "consumers 0" "$tmp/out"

# an archive that is not one is refused rather than read as an empty package
expect 1 "$helper" --consumers "$tmp/prog.c" libanswer.so.1

echo "private consumer fixtures passed"