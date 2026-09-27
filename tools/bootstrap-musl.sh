#!/bin/sh
set -eu
test "$#" -eq 3 || { echo 'usage: bootstrap-musl.sh HOLYPKG INPUTS OUTPUT' >&2; exit 2; }
test "$(id -u)" != 0 || exit 6
case "${ARCH:-x86_64}" in
    x86_64) arch=x86_64; target=x86_64-linux-musl; machine=x86_64; suffix=x86_64; flags=-m64; docs=musl ;;
    i686|x86) arch=x86; target=i686-linux-musl; machine=x86; suffix=i386; flags='-m32 -march=i686 -mtune=generic'; docs=musl-i686 ;;
    *) printf 'unsupported musl target: %s\n' "$ARCH" >&2; exit 6 ;;
esac
unset ARCH MAKEFLAGS MAKEOVERRIDES MFLAGS
case "$(uname -m)" in x86_64|i?86) ;; *) exit 6 ;; esac
bin=$(realpath "$1")
inputs=$(realpath "$2")
project=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
mkdir -p "$(dirname "$3")"
mkdir -m 0700 "$3"
out=$(realpath "$3")
started=$(date +%s)
finish() {
    rc=$?
    trap - EXIT
    printf 'exit %s\nelapsed-seconds %s\n' "$rc" "$(($(date +%s) - started))" >> "$out/build.record"
    exit "$rc"
}
trap finish EXIT
trap 'exit 1' HUP INT TERM
exec > "$out/build.log" 2>&1
printf 'format holy-musl-bootstrap-1\narch %s\ntarget %s\nlibc musl\ncompiler-flags %s\n' "$arch" "$target" "$flags" > "$out/build.record"
gcc --version >> "$out/build.record"
mkdir "$out/inputs" "$out/work"
cp "$inputs/musl-1.2.5.tar.gz" "$out/inputs/"
digest=$(awk '$2 == "musl-1.2.5.tar.gz" { print $1 }' "$project/profiles/static-sources")
test "${#digest}" -eq 64
printf '%s  %s\n' "$digest" "$out/inputs/musl-1.2.5.tar.gz" | sha256sum -c -
sha256sum "$out/inputs/musl-1.2.5.tar.gz" "$0" >> "$out/build.record"
tar -xf "$out/inputs/musl-1.2.5.tar.gz" -C "$out/work"
(
    cd "$out/work/musl-1.2.5"
    unset CPPFLAGS LDLIBS
    CC=gcc CFLAGS="$flags" LDFLAGS="$flags -Wl,-soname,libc.musl-$suffix.so.1" AR=ar RANLIB=ranlib \
        ./configure --target="$target" --prefix=/usr --syslibdir=/usr/lib
    make -j"${JOBS:-2}" lib/libc.so
)
loader="$out/work/musl-1.2.5/lib/libc.so"
if "$loader" > "$out/loader.stdout" 2> "$out/loader.stderr"; then exit 1; else test "$?" -eq 1; fi
grep -q 'Version 1.2.5' "$out/loader.stderr"
"$bin" elf "$loader" > "$out/loader.elf"
grep -qx 'runtime musl' "$out/loader.elf"
grep -qx "machine $machine" "$out/loader.elf"
tree="$out/tree"
mkdir -p "$tree/HOLY" "$tree/DATA/usr/lib/holy/$target" \
    "$tree/DATA/usr/share/licenses/$docs" "$tree/DATA/usr/share/doc/$docs"
cp "$loader" "$tree/DATA/usr/lib/holy/$target/ld-musl-$suffix.so.1"
ln -s "holy/$target/ld-musl-$suffix.so.1" "$tree/DATA/usr/lib/ld-musl-$suffix.so.1"
cp "$out/work/musl-1.2.5/COPYRIGHT" "$tree/DATA/usr/share/licenses/$docs/"
cp "$out/work/musl-1.2.5/README" "$tree/DATA/usr/share/doc/$docs/"
printf 'format holy-package-1\nname musl\nversion 1.2.5\nrelease 1\nos linux\narch %s\nlibc musl\n' "$arch" > "$tree/HOLY/meta"
for name in deps provides hooks transform; do : > "$tree/HOLY/$name"; done
printf 'source https://musl.libc.org/releases/musl-1.2.5.tar.gz\nsource-sha256 %s\ntarget %s\ncflags "%s"\nldflags "%s -Wl,-soname,libc.musl-%s.so.1"\n' "$digest" "$target" "$flags" "$flags" "$suffix" > "$tree/HOLY/origin"
sha256sum "$loader" >> "$tree/HOLY/origin"
"$bin" manifest generate "$tree" --output "$out/files"
mv "$out/files" "$tree/HOLY/files"
"$bin" pack "$tree" --output "$out/musl.holy"
"$bin" scan "local:$out/musl.holy"
sha256sum "$out/musl.holy" >> "$out/build.record"
printf 'result built-loader-probed\n' >> "$out/build.record"
