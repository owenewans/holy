#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

expect() {
    expected=$1
    shift
    if "$@" > "$tmp/out" 2> "$tmp/err"; then actual=0; else actual=$?; fi
    test "$actual" -eq "$expected" || { cat "$tmp/out" "$tmp/err"; exit 1; }
}

command -v patchelf >/dev/null 2>&1 || {
    echo "patchelf required for the rewrite fixture" >&2
    exit 6
}
cc=${CC:-cc}
command -v "$cc" >/dev/null 2>&1 || { echo "$cc required for the rewrite fixture" >&2; exit 6; }

# one shared library and two programs that need it, which is the shape a private
# placement leaves behind: the consumer keeps its public path and the library moves.
# the linker defaults differ between DT_RPATH and DT_RUNPATH, so each program is
# built with the tag the case is about.
printf 'int answer(void) { return 42; }\n' > "$tmp/lib.c"
printf 'int answer(void);\n#include <stdio.h>\nint main(void) { printf("%%d\\n", answer()); return 0; }\n' > "$tmp/prog.c"
mkdir -p "$tmp/pub" "$tmp/priv"
"$cc" -shared -fPIC -Wl,-soname,libanswer.so.1 -o "$tmp/pub/libanswer.so.1" "$tmp/lib.c"
"$cc" -o "$tmp/runpath.prog" "$tmp/prog.c" -L"$tmp/pub" -l:libanswer.so.1 \
    -Wl,--enable-new-dtags -Wl,-rpath,"$tmp/pub"
"$cc" -o "$tmp/rpath.prog" "$tmp/prog.c" -L"$tmp/pub" -l:libanswer.so.1 \
    -Wl,--disable-new-dtags -Wl,-rpath,"$tmp/pub"
test "$("$tmp/runpath.prog")" = 42
test "$("$tmp/rpath.prog")" = 42
grep -qx "runpath $tmp/pub" <("$bin" elf "$tmp/runpath.prog")
grep -qx "rpath $tmp/pub" <("$bin" elf "$tmp/rpath.prog")

# the plan states what the file has, what it asked for and the argv patchelf would run,
# and it changes nothing by itself
expect 0 "$bin" patch "$tmp/runpath.prog" --runpath "$tmp/priv"
grep -q "^rewrite $tmp/runpath.prog [0-9a-f]\{64\} runpath $tmp/pub -> $tmp/priv scope file$" "$tmp/out"
grep -q "rewrite-argv .*patchelf --no-sort --set-rpath $tmp/priv $tmp/runpath.prog$" "$tmp/out"
digest=$(sed -n 's/^rewrite [^ ]* \([0-9a-f]\{64\}\).*/\1/p' "$tmp/out")
test "$(sha256sum "$tmp/runpath.prog" | cut -d ' ' -f 1)" = "$digest"
test "$("$tmp/runpath.prog")" = 42

# a digest the caller got wrong changes nothing
expect 4 "$bin" patch "$tmp/runpath.prog" --runpath "$tmp/priv" \
    --sha256 0000000000000000000000000000000000000000000000000000000000000000
test "$("$tmp/runpath.prog")" = 42

# the file that changed after the plan is not rewritten with stale decisions
cp "$tmp/runpath.prog" "$tmp/moved.prog"
expect 0 "$bin" patch "$tmp/moved.prog" --runpath "$tmp/priv"
moved=$(sed -n 's/^rewrite [^ ]* \([0-9a-f]\{64\}\).*/\1/p' "$tmp/out")
printf 'x' >> "$tmp/moved.prog"
test "$(sha256sum "$tmp/moved.prog" | cut -d ' ' -f 1)" != "$moved"
expect 4 "$bin" patch "$tmp/moved.prog" --runpath "$tmp/priv" --sha256 "$moved"
test "$("$bin" elf "$tmp/moved.prog" | grep -c "^runpath $tmp/priv$")" -eq 0
test "$("$tmp/runpath.prog")" = 42

# the private library is reachable through the path the plan wrote
expect 0 "$bin" patch "$tmp/runpath.prog" --runpath "$tmp/priv" --sha256 "$digest"
grep -qx "runpath $tmp/priv" <("$bin" elf "$tmp/runpath.prog")
mv "$tmp/pub/libanswer.so.1" "$tmp/priv/libanswer.so.1"
test "$("$tmp/runpath.prog")" = 42

# DT_RPATH and DT_RUNPATH are one field to the tool, so the requested one is named by
# a flag rather than inferred from what the file happens to carry
expect 0 "$bin" patch "$tmp/rpath.prog" --rpath /opt/rpath
grep -q "rewrite-argv .* --force-rpath --set-rpath /opt/rpath $tmp/rpath.prog$" "$tmp/out"
digest=$(sed -n 's/^rewrite [^ ]* \([0-9a-f]\{64\}\).*/\1/p' "$tmp/out")
expect 0 "$bin" patch "$tmp/rpath.prog" --rpath /opt/rpath --sha256 "$digest"
grep -qx "rpath /opt/rpath" <("$bin" elf "$tmp/rpath.prog")
test "$("$bin" elf "$tmp/rpath.prog" | grep -c '^runpath ')" -eq 0

# a change the file already states is refused rather than run as a no-op
expect 1 "$bin" patch "$tmp/runpath.prog" --runpath "$tmp/priv"
grep -q "already states runpath" "$tmp/err"

# a replacement for a name the file does not carry is refused
expect 1 "$bin" patch "$tmp/runpath.prog" --needed libabsent.so.9=libabsent.so.10
grep -q "does not state libabsent.so.9 in DT_NEEDED" "$tmp/err"

# a replacement that renames nothing is refused rather than run as a no-op
expect 1 "$bin" patch "$tmp/runpath.prog" --needed libanswer.so.1=libanswer.so.1
grep -q "a replacement has to change libanswer.so.1" "$tmp/err"

# an ambiguous DT_NEEDED is settled by naming both ends, which the spec allows
expect 0 "$bin" patch "$tmp/runpath.prog" --needed libanswer.so.1=libanswer.so.2
digest=$(sed -n 's/^rewrite [^ ]* \([0-9a-f]\{64\}\).*/\1/p' "$tmp/out")
expect 0 "$bin" patch "$tmp/runpath.prog" --needed libanswer.so.1=libanswer.so.2 \
    --sha256 "$digest"
grep -qx "needed libanswer.so.2" <("$bin" elf "$tmp/runpath.prog")

# the interpreter is a field like the others, and the plan states what the file has
expect 0 "$bin" patch "$tmp/runpath.prog" --interpreter /lib/ld-musl-x86_64.so.1
grep -q "^rewrite .* interpreter /lib64/ld-linux-x86-64.so.2 -> /lib/ld-musl-x86_64.so.1 scope file$" "$tmp/out"

# a soname belongs to a library, so the plan states what the file carries
"$cc" -shared -fPIC -o "$tmp/plain.so" "$tmp/lib.c"
expect 0 "$bin" patch "$tmp/plain.so" --soname libplain.so.2
digest=$(sed -n 's/^rewrite [^ ]* \([0-9a-f]\{64\}\).*/\1/p' "$tmp/out")
expect 0 "$bin" patch "$tmp/plain.so" --soname libplain.so.2 --sha256 "$digest"
grep -qx "soname libplain.so.2" <("$bin" elf "$tmp/plain.so")
expect 1 "$bin" patch "$tmp/plain.so" --soname libplain.so.2
grep -q "already states soname libplain.so.2" "$tmp/err"

# a file that is not ELF is refused
echo not an elf > "$tmp/plain.txt"
expect 2 "$bin" patch "$tmp/plain.txt" --runpath /opt/rpath

# a static file states no dynamic table, so there is nothing to rewrite
"$cc" -static -o "$tmp/static.prog" "$tmp/prog.c" "$tmp/lib.c" 2>/dev/null || \
    "$cc" -o "$tmp/static.prog" "$tmp/prog.c" "$tmp/lib.c"
if "$bin" elf "$tmp/static.prog" | grep -q '^interpreter'; then
    expect 1 "$bin" patch "$tmp/static.prog" --soname libstatic.so.1
    grep -q "no PT_DYNAMIC" "$tmp/err"
fi

# the spec makes patchelf a package, so a host without one is a requirement failure
expect 6 "$bin" patch "$tmp/plain.so" --soname libother.so.1 --patchelf "$tmp/absent-tool"

# a relative or empty value is refused rather than resolved against the caller
expect 2 "$bin" patch "$tmp/plain.so" --soname ""
expect 2 "$bin" patch "$tmp/plain.so" --soname -leading-dash

echo "ELF rewrite fixtures passed"