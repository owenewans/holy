#!/bin/sh
set -eu
umask 022
test "$#" -eq 3 || { echo 'usage: bootstrap-glibc.sh HOLYPKG INPUTS OUTPUT' >&2; exit 2; }
test "$(id -u)" != 0 && test "$(uname -m)" = x86_64 || exit 6
case "${ARCH:-x86_64}" in
    x86_64) arch=x86_64; target=x86_64-linux-gnu; flags='-m64 -march=x86-64 -mtune=generic'; loader_name=ld-linux-x86-64.so.2; public=usr/lib64; link=../lib/holy; docs=glibc ;;
    i686|x86) arch=x86; target=i686-linux-gnu; flags='-m32 -march=i686 -mtune=generic'; loader_name=ld-linux.so.2; public=usr/lib; link=holy; docs=glibc-i686 ;;
    *) printf 'unsupported glibc target: %s\n' "$ARCH" >&2; exit 6 ;;
esac
unset ARCH MAKEFLAGS MAKEOVERRIDES MFLAGS
for tool in gcc make gawk bison python3 tar sha256sum patchelf; do
    command -v "$tool" >/dev/null || { echo "$tool required" >&2; exit 6; }
done
bin=$(realpath "$1")
inputs=$(realpath "$2")
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
printf 'format holy-glibc-bootstrap-1\narch %s\ntarget %s\ncompiler-flags %s\nlibc glibc\n' "$arch" "$target" "$flags" > "$out/build.record"
gcc --version >> "$out/build.record"
mkdir "$out/inputs" "$out/work" "$out/build"
cp "$inputs/glibc-2.42.tar.xz" "$out/inputs/"
digest=d1775e32e4628e64ef930f435b67bb63af7599acb6be2b335b9f19f16509f17f
printf '%s  %s\n' "$digest" "$out/inputs/glibc-2.42.tar.xz" | sha256sum -c -
sha256sum "$out/inputs/glibc-2.42.tar.xz" "$0" >> "$out/build.record"
tar -xf "$out/inputs/glibc-2.42.tar.xz" -C "$out/work"
(
    cd "$out/build"
    unset CPPFLAGS LDFLAGS LDLIBS
    CC="gcc $flags" CXX="g++ $flags" CFLAGS="-O2 $flags" \
        "$out/work/glibc-2.42/configure" --prefix=/usr --host="$target" --build="$(gcc -dumpmachine)" \
        --libdir="/usr/lib/holy/$target" --disable-werror --without-gd
    make -j"${JOBS:-2}"
)
cp "$out/build/config.make" "$out/config.make"
sha256sum "$out/config.make" >> "$out/build.record"
tree="$out/tree"
runtime=/usr/lib/holy/$target
loader=$runtime/$loader_name
mkdir -p "$tree/HOLY" "$tree/DATA$runtime" "$tree/DATA/$public" \
    "$tree/DATA/usr/share/licenses/$docs" "$tree/DATA/usr/share/doc/$docs"
cp "$out/build/elf/ld.so" "$tree/DATA$loader"
cp "$out/build/libc.so" "$tree/DATA$runtime/libc.so.6"
printf 'source https://ftp.gnu.org/gnu/glibc/glibc-2.42.tar.xz\nsource-sha256 %s\nverification hash-pinned-https\n' "$digest" > "$tree/HOLY/origin"
printf 'target %s\ncflags "%s"\n' "$target" "$flags" >> "$tree/HOLY/origin"
"$bin" elf "$tree/DATA$loader" > "$out/loader.elf"
grep -qx "machine $arch" "$out/loader.elf"
sha256sum "$tree/DATA$runtime/libc.so.6" "$tree/DATA$loader" >> "$tree/HOLY/origin"
patchelf --set-interpreter "$loader" --replace-needed "$loader_name" "$loader" "$tree/DATA$runtime/libc.so.6"
printf 'bootstrap-patchelf interpreter %s\nbootstrap-patchelf needed %s %s\n' "$loader" "$loader_name" "$loader" >> "$tree/HOLY/origin"
patchelf --version >> "$tree/HOLY/origin"
sha256sum "$tree/DATA$runtime/libc.so.6" >> "$tree/HOLY/origin"
ln -s "$link/$target/$loader_name" "$tree/DATA/$public/$loader_name"
cp "$out/work/glibc-2.42/COPYING" "$out/work/glibc-2.42/COPYING.LIB" "$tree/DATA/usr/share/licenses/$docs/"
cp "$out/work/glibc-2.42/README" "$tree/DATA/usr/share/doc/$docs/"
printf 'format holy-package-1\nname glibc-bootstrap\nversion 2.42\nrelease 1\nos linux\narch %s\nlibc glibc\n' "$arch" > "$tree/HOLY/meta"
for name in deps provides hooks transform; do : > "$tree/HOLY/$name"; done
"$bin" manifest generate "$tree" --output "$out/files"
mv "$out/files" "$tree/HOLY/files"
"$bin" pack "$tree" --output "$out/glibc.holy"
"$bin" scan "local:$out/glibc.holy"
sha256sum "$out/glibc.holy" >> "$out/build.record"
printf 'result built\nnot-tested upstream-check boot runtime-probes\n' >> "$out/build.record"
