#!/bin/sh
set -eu
test "$#" -eq 3 || { echo 'usage: bootstrap-musl.sh HOLYPKG INPUTS OUTPUT' >&2; exit 2; }
test "$(id -u)" != 0 && test "$(uname -m)" = x86_64 || exit 6
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
printf 'format holy-musl-bootstrap-1\narch x86_64\nlibc musl\n' > "$out/build.record"
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
    unset CFLAGS CPPFLAGS LDLIBS
    CC=gcc LDFLAGS=-Wl,-soname,libc.musl-x86_64.so.1 ./configure --prefix=/usr --syslibdir=/usr/lib
    make -j"${JOBS:-2}" lib/libc.so
)
loader="$out/work/musl-1.2.5/lib/libc.so"
if "$loader" > "$out/loader.stdout" 2> "$out/loader.stderr"; then exit 1; else test "$?" -eq 1; fi
grep -q 'Version 1.2.5' "$out/loader.stderr"
"$bin" elf "$loader" > "$out/loader.elf"
grep -qx 'runtime musl' "$out/loader.elf"
tree="$out/tree"
mkdir -p "$tree/HOLY" "$tree/DATA/usr/lib/holy/x86_64-linux-musl" \
    "$tree/DATA/usr/share/licenses/musl" "$tree/DATA/usr/share/doc/musl"
cp "$loader" "$tree/DATA/usr/lib/holy/x86_64-linux-musl/ld-musl-x86_64.so.1"
ln -s holy/x86_64-linux-musl/ld-musl-x86_64.so.1 "$tree/DATA/usr/lib/ld-musl-x86_64.so.1"
cp "$out/work/musl-1.2.5/COPYRIGHT" "$tree/DATA/usr/share/licenses/musl/"
cp "$out/work/musl-1.2.5/README" "$tree/DATA/usr/share/doc/musl/"
printf 'format holy-package-1\nname musl\nversion 1.2.5\nrelease 1\nos linux\narch x86_64\nlibc musl\n' > "$tree/HOLY/meta"
for name in deps provides hooks transform; do : > "$tree/HOLY/$name"; done
printf 'source https://musl.libc.org/releases/musl-1.2.5.tar.gz\nsource-sha256 %s\nldflags "-Wl,-soname,libc.musl-x86_64.so.1"\n' "$digest" > "$tree/HOLY/origin"
sha256sum "$loader" >> "$tree/HOLY/origin"
"$bin" manifest generate "$tree" --output "$out/files"
mv "$out/files" "$tree/HOLY/files"
"$bin" pack "$tree" --output "$out/musl.holy"
"$bin" scan "local:$out/musl.holy"
sha256sum "$out/musl.holy" >> "$out/build.record"
printf 'result built-loader-probed\n' >> "$out/build.record"
