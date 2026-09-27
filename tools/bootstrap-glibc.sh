#!/bin/sh
set -eu
umask 022
test "$#" -eq 3 || { echo 'usage: bootstrap-glibc.sh HOLYPKG INPUTS OUTPUT' >&2; exit 2; }
test "$(id -u)" != 0 && test "$(uname -m)" = x86_64 || exit 6
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
printf 'format holy-glibc-bootstrap-1\narch x86_64\nlibc glibc\n' > "$out/build.record"
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
    CC=gcc CXX=g++ CFLAGS='-O2 -march=x86-64 -mtune=generic' \
        "$out/work/glibc-2.42/configure" --prefix=/usr \
        --libdir=/usr/lib/holy/x86_64-linux-gnu --disable-werror --without-gd
    make -j"${JOBS:-2}"
)
cp "$out/build/config.make" "$out/config.make"
sha256sum "$out/config.make" >> "$out/build.record"
tree="$out/tree"
runtime=/usr/lib/holy/x86_64-linux-gnu
loader=$runtime/ld-linux-x86-64.so.2
mkdir -p "$tree/HOLY" "$tree/DATA$runtime" "$tree/DATA/usr/lib64" \
    "$tree/DATA/usr/share/licenses/glibc" "$tree/DATA/usr/share/doc/glibc"
cp "$out/build/elf/ld.so" "$tree/DATA$loader"
cp "$out/build/libc.so" "$tree/DATA$runtime/libc.so.6"
printf 'source https://ftp.gnu.org/gnu/glibc/glibc-2.42.tar.xz\nsource-sha256 %s\nverification hash-pinned-https\n' "$digest" > "$tree/HOLY/origin"
sha256sum "$tree/DATA$runtime/libc.so.6" "$tree/DATA$loader" >> "$tree/HOLY/origin"
patchelf --set-interpreter "$loader" --replace-needed ld-linux-x86-64.so.2 "$loader" "$tree/DATA$runtime/libc.so.6"
printf 'bootstrap-patchelf interpreter %s\nbootstrap-patchelf needed ld-linux-x86-64.so.2 %s\n' "$loader" "$loader" >> "$tree/HOLY/origin"
patchelf --version >> "$tree/HOLY/origin"
sha256sum "$tree/DATA$runtime/libc.so.6" >> "$tree/HOLY/origin"
ln -s ../lib/holy/x86_64-linux-gnu/ld-linux-x86-64.so.2 "$tree/DATA/usr/lib64/ld-linux-x86-64.so.2"
cp "$out/work/glibc-2.42/COPYING" "$out/work/glibc-2.42/COPYING.LIB" "$tree/DATA/usr/share/licenses/glibc/"
cp "$out/work/glibc-2.42/README" "$tree/DATA/usr/share/doc/glibc/"
printf 'format holy-package-1\nname glibc-bootstrap\nversion 2.42\nrelease 1\nos linux\narch x86_64\nlibc glibc\n' > "$tree/HOLY/meta"
for name in deps provides hooks transform; do : > "$tree/HOLY/$name"; done
"$bin" manifest generate "$tree" --output "$out/files"
mv "$out/files" "$tree/HOLY/files"
"$bin" pack "$tree" --output "$out/glibc.holy"
"$bin" scan "local:$out/glibc.holy"
sha256sum "$out/glibc.holy" >> "$out/build.record"
printf 'result built\nnot-tested upstream-check boot runtime-probes\n' >> "$out/build.record"
