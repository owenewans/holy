#!/bin/sh
set -eu
bin=$1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
umask 022
case $(uname -m) in
    x86_64) arch=x86_64; bits=64; emulation=elf_x86_64 ;;
    i686) arch=x86; bits=32; emulation=elf_i386 ;;
    *) printf 'static install fixture requires x86_64 or i686\n' >&2; exit 6 ;;
esac
mkdir -p "$tmp/tree/HOLY" "$tmp/tree/DATA/usr/bin" "$tmp/root/usr/bin"
for name in deps provides hooks origin transform; do : > "$tmp/tree/HOLY/$name"; done
cat > "$tmp/tree/HOLY/meta" <<EOF
format holy-package-1
name static-probe
version 1
release 1
os linux
arch $arch
libc nolibc
EOF
package() {
    rm -f "$tmp/files"
    "$bin" manifest generate "$tmp/tree" --output "$tmp/files" > "$tmp/out"
    cp "$tmp/files" "$tmp/tree/HOLY/files"
    "$bin" pack "$tmp/tree" --output "$tmp/$1.holy" > "$tmp/out"
    "$bin" cache stage "local:$tmp/$1.holy" --root "$tmp/root" > "$tmp/out"
    digest=$(sha256sum "$tmp/$1.holy")
    digest=${digest%% *}
    "$bin" db reserve "$digest" --root "$tmp/root" > "$tmp/out"
}
"$bin" db init --root "$tmp/root" > "$tmp/out"
printf 'exit 42\n' > "$tmp/tree/DATA/usr/bin/probe"
chmod 755 "$tmp/tree/DATA/usr/bin/probe"
package unknown
if "$bin" db plan --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
grep -q 'executable format unknown' "$tmp/err"
test ! -e "$tmp/root/usr/bin/probe"
test ! -e "$tmp/root/var/lib/holypkg/transactions/journal"
"$bin" db cancel --root "$tmp/root" > "$tmp/out"
if [ "$bits" = 64 ]; then
    printf '.global _start\n_start:\n mov $42, %%edi\n mov $60, %%eax\n syscall\n' > "$tmp/probe.s"
else
    printf '.global _start\n_start:\n mov $42, %%ebx\n mov $1, %%eax\n int $0x80\n' > "$tmp/probe.s"
fi
as --"$bits" -o "$tmp/probe.o" "$tmp/probe.s"
ld -m "$emulation" -o "$tmp/tree/DATA/usr/bin/probe" "$tmp/probe.o"
"$bin" elf "$tmp/tree/DATA/usr/bin/probe" > "$tmp/out"
grep -qx 'runtime nolibc' "$tmp/out"
grep -qx 'e_type 2' "$tmp/out"
package static
"$bin" db plan --root "$tmp/root" > "$tmp/out"
plan=$(sed -n 's/.* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
test "${#plan}" -eq 64
"$bin" db approve "$plan" --root "$tmp/root" > "$tmp/out"
"$bin" db apply --root "$tmp/root" > "$tmp/out"
cmp "$tmp/tree/DATA/usr/bin/probe" "$tmp/root/usr/bin/probe"
test -x "$tmp/root/usr/bin/probe"
if "$tmp/root/usr/bin/probe"; then exit 1; else test "$?" -eq 42; fi
"$bin" db check "$digest" --root "$tmp/root" > "$tmp/out"
"$bin" db owner usr/bin/probe --root "$tmp/root" > "$tmp/out"
grep -qx "$digest file usr/bin/probe" "$tmp/out"
"$bin" db rm "$digest" --root "$tmp/root" > "$tmp/out"
test ! -e "$tmp/root/usr/bin/probe"
test ! -e "$tmp/root/var/lib/holypkg/installed/$digest"
if [ "$bits" = 64 ]; then
    printf '.global _start\n_start:\n mov $42, %%ebx\n mov $1, %%eax\n int $0x80\n' > "$tmp/foreign.s"
    as --32 -o "$tmp/foreign.o" "$tmp/foreign.s"
    ld -m elf_i386 -o "$tmp/tree/DATA/usr/bin/probe" "$tmp/foreign.o"
    sed 's/arch x86_64/arch x86/' "$tmp/tree/HOLY/meta" > "$tmp/meta"
    mv "$tmp/meta" "$tmp/tree/HOLY/meta"
    package foreign
    if "$bin" db plan --root "$tmp/root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
    grep -q 'native host architecture' "$tmp/err"
    test ! -e "$tmp/root/usr/bin/probe"
    test ! -e "$tmp/root/var/lib/holypkg/transactions/journal"
    "$bin" db cancel --root "$tmp/root" > "$tmp/out"
fi
printf 'static install fixtures passed\n'
