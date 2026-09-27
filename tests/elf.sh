#!/bin/sh
set -eu
bin=$1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
printf '#include <stdio.h>\nint main(void) { return puts("ok") < 0; }\n' > "$tmp/main.c"
"${CC:-cc}" -o "$tmp/main" "$tmp/main.c"
"$bin" elf "$tmp/main" > "$tmp/out"
grep -qx 'class ELF64' "$tmp/out"
grep -qx 'e_machine 62' "$tmp/out"
grep -Eq '^e_type (2|3)$' "$tmp/out"
grep -qx 'machine x86_64' "$tmp/out"
grep -qx 'runtime glibc' "$tmp/out"
grep -qx 'needed libc.so.6' "$tmp/out"
grep -q '^version libc.so.6 GLIBC_' "$tmp/out"
grep -q '^symbol puts binding=1 .*section=0 .*version=GLIBC_.* provider=libc.so.6$' "$tmp/out"
gcc -Wl,--hash-style=gnu -o "$tmp/gnu-imports" "$tmp/main.c"
"$bin" elf "$tmp/gnu-imports" > "$tmp/out"
grep -q '^symbol puts binding=1 .*section=0 .*version=GLIBC_.* provider=libc.so.6$' "$tmp/out"
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
printf 'int holy_export(void) { return 1; }\n' > "$tmp/versioned.c"
printf 'HOLY_1 { global: holy_export; local: *; };\n' > "$tmp/version.map"
gcc -shared -fPIC -Wl,--version-script="$tmp/version.map" \
    -Wl,-soname,libholyfixture.so.1 -o "$tmp/versioned.so" "$tmp/versioned.c"
"$bin" elf "$tmp/versioned.so" > "$tmp/out"
grep -qx 'version-def HOLY_1' "$tmp/out"
grep -q '^symbol holy_export binding=1 type=2 .*version=HOLY_1 provider=none$' "$tmp/out"
cat > "$tmp/symbols.c" <<'EOF'
extern int holy_optional(void) __attribute__((weak));
int holy_export(void) { return holy_optional ? holy_optional() : 17; }
__attribute__((visibility("protected"))) int holy_protected(void) { return 3; }
EOF
printf 'HOLY_1 { global: holy_export; holy_protected; local: *; };\n' > "$tmp/symbols.map"
for hash in sysv gnu both; do
    gcc -nostdlib -shared -fPIC -Wl,--hash-style="$hash" \
        -Wl,--version-script="$tmp/symbols.map" -Wl,-soname,libsymbols.so.1 \
        -o "$tmp/symbols-$hash.so" "$tmp/symbols.c"
    objcopy --strip-section-headers "$tmp/symbols-$hash.so" "$tmp/symbols-$hash-stripped.so"
    "$bin" elf "$tmp/symbols-$hash.so" > "$tmp/out"
    "$bin" elf "$tmp/symbols-$hash-stripped.so" > "$tmp/stripped.out"
    cmp "$tmp/out" "$tmp/stripped.out"
    grep -q '^symbol holy_optional binding=2 .*section=0 .*version=none provider=none$' "$tmp/out"
    grep -q '^symbol holy_protected binding=1 type=2 visibility=3 .*version=HOLY_1 provider=none$' "$tmp/out"
done
printf 'extern int holy_export(void); int main(void) { return holy_export() != 17; }\n' > "$tmp/consumer.c"
gcc -o "$tmp/consumer" "$tmp/consumer.c" "$tmp/symbols-both.so"
ln -s symbols-both.so "$tmp/libsymbols.so.1"
LD_LIBRARY_PATH="$tmp" "$tmp/consumer"
"$bin" elf "$tmp/consumer" > "$tmp/out"
grep -q '^symbol holy_export binding=1 .*section=0 .*version=HOLY_1 provider=libsymbols.so.1$' "$tmp/out"
cat > "$tmp/compat.c" <<'EOF'
int holy_old(void) { return 1; }
int holy_new(void) { return 2; }
__asm__(".symver holy_old,holy_api@HOLY_1");
__asm__(".symver holy_new,holy_api@@HOLY_2");
EOF
printf 'HOLY_1 {}; HOLY_2 { global: holy_api; local: *; } HOLY_1;\n' > "$tmp/compat.map"
gcc -nostdlib -shared -fPIC -Wl,--version-script="$tmp/compat.map" \
    -o "$tmp/compat.so" "$tmp/compat.c"
objcopy --strip-section-headers "$tmp/compat.so" "$tmp/compat-stripped.so"
"$bin" elf "$tmp/compat-stripped.so" > "$tmp/out"
grep -q '^symbol holy_api .*hidden=1 version=HOLY_1 provider=none$' "$tmp/out"
grep -q '^symbol holy_api .*hidden=0 version=HOLY_2 provider=none$' "$tmp/out"
test "$(grep -c '^version-def HOLY_1$' "$tmp/out")" -eq 1
gcc -m32 -nostdlib -shared -fPIC -Wl,--hash-style=both \
    -Wl,--version-script="$tmp/symbols.map" -o "$tmp/symbols32.so" "$tmp/symbols.c"
objcopy --strip-section-headers "$tmp/symbols32.so" "$tmp/symbols32-stripped.so"
"$bin" elf "$tmp/symbols32-stripped.so" > "$tmp/out"
grep -qx 'class ELF32' "$tmp/out"
grep -q '^symbol holy_optional binding=2 .*section=0 ' "$tmp/out"
python3 - "$tmp" <<'PY'
import pathlib, struct, sys
root = pathlib.Path(sys.argv[1])
original = (root / 'symbols-both-stripped.so').read_bytes()
phoff = struct.unpack_from('<Q', original, 32)[0]
phsize, phnum = struct.unpack_from('<HH', original, 54)
segments = [struct.unpack_from('<IIQQQQQQ', original, phoff + i * phsize) for i in range(phnum)]
def offset(address):
    for p in segments:
        if p[0] == 1 and p[3] <= address < p[3] + p[5]:
            return p[2] + address - p[3]
    raise AssertionError('unmapped fixture address')
dynamic = next(p for p in segments if p[0] == 2)
tags = {}
for pos in range(dynamic[2], dynamic[2] + dynamic[5], 16):
    tag, value = struct.unpack_from('<QQ', original, pos)
    if tag == 0: break
    tags[tag] = (pos + 8, value)
changes = {
    'syment': (tags[11][0], '<Q', 1),
    'symtab-address': (tags[6][0], '<Q', 0xffffffffffffffff),
    'hash-count': (offset(tags[4][1]) + 4, '<I', 0xffffffff),
    'gnu-bloom': (offset(tags[0x6ffffef5][1]) + 8, '<I', 0xffffffff),
    'symbol-name': (offset(tags[6][1]) + 24, '<I', 0xffffffff),
    'version-index': (offset(tags[0x6ffffff0][1]) + 2, '<H', 0x7fff),
}
for name, (pos, fmt, value) in changes.items():
    data = bytearray(original)
    struct.pack_into(fmt, data, pos, value)
    (root / ('bad-symbol-' + name)).write_bytes(data)
PY
for file in "$tmp"/bad-symbol-*; do
    if "$bin" elf "$file" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
    grep -q 'invalid ELF input' "$tmp/err"
done
objcopy --strip-section-headers "$tmp/versioned.so" "$tmp/versioned-no-sections.so"
"$bin" elf "$tmp/versioned-no-sections.so" > "$tmp/out"
grep -qx 'version-def HOLY_1' "$tmp/out"
objcopy --remove-section .gnu.version_d "$tmp/versioned.so" "$tmp/missing-verdef.so"
if "$bin" elf "$tmp/missing-verdef.so" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'invalid ELF input' "$tmp/err"
objcopy --remove-section .dynstr "$tmp/plugin.so" "$tmp/missing-dynstr.so"
if "$bin" elf "$tmp/missing-dynstr.so" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'invalid ELF input' "$tmp/err"
printf '.global _start\n_start:\n xor %%ebx, %%ebx\n mov $1, %%eax\n int $0x80\n' > "$tmp/i386.s"
as --32 -o "$tmp/i386.o" "$tmp/i386.s"
ld -m elf_i386 -o "$tmp/i386" "$tmp/i386.o"
"$bin" elf "$tmp/i386" > "$tmp/out"
grep -qx 'class ELF32' "$tmp/out"
grep -qx 'e_machine 3' "$tmp/out"
grep -qx 'machine x86' "$tmp/out"
grep -qx 'runtime nolibc' "$tmp/out"
mkdir -p "$tmp/tree/HOLY" "$tmp/tree/DATA/usr/bin"
cp "$tmp/i386" "$tmp/tree/DATA/usr/bin/static32"
cat > "$tmp/tree/HOLY/meta" <<'EOF'
format holy-package-1
name static32
version 1
release 1
os linux
arch x86
libc nolibc
EOF
for field in deps provides hooks origin transform; do : > "$tmp/tree/HOLY/$field"; done
"$bin" manifest generate "$tmp/tree" --output "$tmp/static-files" > "$tmp/out"
cp "$tmp/static-files" "$tmp/tree/HOLY/files"
"$bin" pack "$tmp/tree" --output "$tmp/static32.holy" > "$tmp/out"
"$bin" scan "local:$tmp/static32.holy" > "$tmp/out"
grep -q '^elf usr/bin/static32 class=ELF32 machine=x86 e_machine=3 runtime=nolibc' "$tmp/out"
rm "$tmp/tree/DATA/usr/bin/static32"
sed -e 's/^arch x86$/arch x86_64/' -e 's/^libc nolibc$/libc glibc/' \
    "$tmp/tree/HOLY/meta" > "$tmp/meta64"
mv "$tmp/meta64" "$tmp/tree/HOLY/meta"
gcc -nostdlib -shared -fPIC -o "$tmp/no-libc.so" "$tmp/versioned.c"
cp "$tmp/no-libc.so" "$tmp/tree/DATA/usr/bin/plugin"
"$bin" manifest generate "$tmp/tree" --output "$tmp/plugin-files" > "$tmp/out"
cp "$tmp/plugin-files" "$tmp/tree/HOLY/files"
if "$bin" pack "$tmp/tree" --output "$tmp/unknown.holy" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'ELF runtime unknown' "$tmp/err"
test ! -e "$tmp/unknown.holy"
printf '.global _start\n_start:\n mov $60, %%eax\n xor %%edi, %%edi\n syscall\n' > "$tmp/x32.s"
as --x32 -o "$tmp/x32.o" "$tmp/x32.s"
ld -m elf32_x86_64 -o "$tmp/x32" "$tmp/x32.o"
"$bin" elf "$tmp/x32" > "$tmp/out"
grep -qx 'class ELF32' "$tmp/out"
grep -qx 'e_machine 62' "$tmp/out"
grep -qx 'machine x32' "$tmp/out"
grep -qx 'runtime nolibc' "$tmp/out"
printf 'not ELF\n' > "$tmp/text"
if "$bin" elf "$tmp/text" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -q 'not an ELF input' "$tmp/err"
head -c 18 "$tmp/main" > "$tmp/truncated"
if "$bin" elf "$tmp/truncated" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
printf 'ELF fixtures passed\n'
