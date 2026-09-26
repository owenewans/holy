#!/bin/sh
set -eu
bin=$1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
printf 'int main(void) { return 0; }\n' > "$tmp/main.c"
"${CC:-cc}" -o "$tmp/main" "$tmp/main.c"
"$bin" elf "$tmp/main" > "$tmp/out"
grep -qx 'class ELF64' "$tmp/out"
grep -qx 'machine x86_64' "$tmp/out"
grep -qx 'runtime glibc' "$tmp/out"
objcopy --strip-section-headers "$tmp/main" "$tmp/no-sections"
"$bin" elf "$tmp/no-sections" > "$tmp/out"
grep -qx 'machine x86_64' "$tmp/out"
"${CC:-cc}" -shared -fPIC -o "$tmp/plugin.so" "$tmp/main.c"
"$bin" elf "$tmp/plugin.so" > "$tmp/out"
grep -qx 'runtime unknown' "$tmp/out"
printf 'not ELF\n' > "$tmp/text"
if "$bin" elf "$tmp/text" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'not an ELF input' "$tmp/err"
head -c 18 "$tmp/main" > "$tmp/truncated"
if "$bin" elf "$tmp/truncated" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
printf 'ELF fixtures passed\n'
