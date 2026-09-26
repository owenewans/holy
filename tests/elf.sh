#!/bin/sh
set -eu
bin=$1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
printf '#include <stdio.h>\nint main(void) { return puts("ok") < 0; }\n' > "$tmp/main.c"
"${CC:-cc}" -o "$tmp/main" "$tmp/main.c"
"$bin" elf "$tmp/main" > "$tmp/out"
grep -qx 'class ELF64' "$tmp/out"
grep -qx 'machine x86_64' "$tmp/out"
grep -qx 'runtime glibc' "$tmp/out"
grep -qx 'needed libc.so.6' "$tmp/out"
grep -q '^version libc.so.6 GLIBC_' "$tmp/out"
gcc -Wl,-z,x86-64-v3 -o "$tmp/isa-v3" "$tmp/main.c"
"$bin" elf "$tmp/isa-v3" > "$tmp/out"
grep -qx 'isa x86-64-v3' "$tmp/out"
objcopy --strip-section-headers "$tmp/isa-v3" "$tmp/isa-v3-no-sections"
"$bin" elf "$tmp/isa-v3-no-sections" > "$tmp/out"
grep -qx 'isa x86-64-v3' "$tmp/out"
objcopy --remove-section .note.gnu.property "$tmp/isa-v3" "$tmp/isa-unknown"
"$bin" elf "$tmp/isa-unknown" > "$tmp/out"
grep -qx 'isa unknown' "$tmp/out"
cp "$tmp/isa-v3" "$tmp/isa-bad"
offset=$(readelf -W -S "$tmp/isa-bad" | awk '/\.note\.gnu\.property / {print $5; exit}')
test -n "$offset"
printf '\377\377\377\177' | dd of="$tmp/isa-bad" bs=1 seek=$((0x$offset + 20)) conv=notrunc status=none
if "$bin" elf "$tmp/isa-bad" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'invalid ELF input' "$tmp/err"
objcopy --strip-section-headers "$tmp/main" "$tmp/no-sections"
"$bin" elf "$tmp/no-sections" > "$tmp/out"
grep -qx 'machine x86_64' "$tmp/out"
grep -qx 'needed libc.so.6' "$tmp/out"
grep -q '^version libc.so.6 GLIBC_' "$tmp/out"
objcopy --remove-section .gnu.version_r "$tmp/main" "$tmp/missing-versions"
if "$bin" elf "$tmp/missing-versions" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'invalid ELF input' "$tmp/err"
"${CC:-cc}" -shared -fPIC -Wl,-soname,libfixture.so.1 -Wl,-rpath,'$ORIGIN' \
    -o "$tmp/plugin.so" "$tmp/main.c"
"$bin" elf "$tmp/plugin.so" > "$tmp/out"
grep -qx 'runtime unknown' "$tmp/out"
grep -qx 'soname libfixture.so.1' "$tmp/out"
grep -qE '^(rpath|runpath) \$ORIGIN$' "$tmp/out"
objcopy --remove-section .dynstr "$tmp/plugin.so" "$tmp/missing-dynstr.so"
if "$bin" elf "$tmp/missing-dynstr.so" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'invalid ELF input' "$tmp/err"
printf 'not ELF\n' > "$tmp/text"
if "$bin" elf "$tmp/text" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'not an ELF input' "$tmp/err"
head -c 18 "$tmp/main" > "$tmp/truncated"
if "$bin" elf "$tmp/truncated" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
printf 'ELF fixtures passed\n'
