#!/bin/sh
set -eu
umask 022
if [ "$#" -ne 3 ]; then
    printf 'usage: bootstrap-busybox.sh HOLYPKG INPUT-DIRECTORY OUTPUT-DIRECTORY\n' >&2
    exit 2
fi
bin=$(realpath "$1")
inputs=$(realpath "$2")
profile=$(realpath "$(dirname "$0")/../profiles/busybox-bootstrap.config")
case $(uname -m) in
    x86_64) arch=x86_64 ;;
    *) printf 'bootstrap BusyBox currently requires x86_64\n' >&2; exit 6 ;;
esac
for tool in gcc make tar sha256sum awk realpath; do
    command -v "$tool" >/dev/null || { printf 'missing tool: %s\n' "$tool" >&2; exit 6; }
done
musl=a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4
busybox=3311dff32e746499f4df0d5df04d7eb396382d7e108bb9250e7b519b837043a4
printf '%s  %s\n%s  %s\n' "$musl" "$inputs/musl-1.2.5.tar.gz" \
    "$busybox" "$inputs/busybox-1.37.0.tar.bz2" | sha256sum -c -
mkdir -p "$(dirname "$3")"
mkdir "$3"
out=$(realpath "$3")
case "$out" in
    *[!a-zA-Z0-9_./-]*) printf 'build prefix requires an ASCII path without spaces\n' >&2; exit 2 ;;
esac
work=$(mktemp -d "$out/work.XXXXXX")
started=$(date +%s)
cleanup() {
    rc=$?
    trap - EXIT HUP INT TERM
    printf 'exit %s\nelapsed-seconds %s\n' "$rc" "$(($(date +%s) - started))" >> "$out/build.record"
    rm -rf "$work"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
exec > "$out/build.log" 2>&1
unset CFLAGS CPPFLAGS LDFLAGS LDLIBS
printf 'musl-url https://musl.libc.org/releases/musl-1.2.5.tar.gz\nmusl-sha256 %s\nbusybox-url https://busybox.net/downloads/busybox-1.37.0.tar.bz2\nbusybox-sha256 %s\narch %s\n' \
    "$musl" "$busybox" "$arch" > "$out/build.record"
gcc --version >> "$out/build.record"
tar -xzf "$inputs/musl-1.2.5.tar.gz" -C "$work"
tar -xjf "$inputs/busybox-1.37.0.tar.bz2" -C "$work"
(
    cd "$work/musl-1.2.5"
    CC=gcc ./configure --prefix="$work/musl-prefix" --disable-shared
    make -j"${JOBS:-2}"
    make install
)
cc="$work/musl-prefix/bin/musl-gcc"
if gcc -fno-link-libatomic -x c -c /dev/null -o "$work/flag.o" 2>/dev/null; then
    cc="$cc -fno-link-libatomic"
fi
(
    cd "$work/busybox-1.37.0"
    make allnoconfig
    awk 'NR==FNR {split($0,a,"="); setting[a[1]]=$0; next}
         {key=$1=="#" ? $2 : $1; sub(/=.*/,"",key);
          if (key in setting) {print setting[key]; delete setting[key]} else print}
         END {for (key in setting) print setting[key]}' "$profile" .config > .config.next
    mv .config.next .config
    make oldconfig </dev/null
    while IFS= read -r option; do
        grep -Fx "$option" .config >/dev/null || {
            printf 'upstream configuration did not retain %s\n' "$option" >&2
            exit 1
        }
    done < "$profile"
    make -j"${JOBS:-2}" CC="$cc"
    cp .config "$out/busybox.config"
)
binary="$work/busybox-1.37.0/busybox"
"$bin" elf "$binary" > "$out/elf.record"
grep -qx 'runtime nolibc' "$out/elf.record"
grep -qx 'e_type 2' "$out/elf.record"
grep -qx "machine $arch" "$out/elf.record"
"$binary" ash -c 'printf "musl-static-shell\n"' > "$out/shell.record"
grep -qx musl-static-shell "$out/shell.record"
"$binary" --list > "$out/applets"
tree="$work/package"
mkdir -p "$tree/HOLY" "$tree/DATA/usr/bin" "$tree/DATA/usr/share/licenses/busybox" "$tree/DATA/usr/share/licenses/musl"
cp "$binary" "$tree/DATA/usr/bin/busybox"
cp "$work/busybox-1.37.0/LICENSE" "$tree/DATA/usr/share/licenses/busybox/LICENSE"
cp "$work/musl-1.2.5/COPYRIGHT" "$tree/DATA/usr/share/licenses/musl/COPYRIGHT"
cat > "$tree/HOLY/meta" <<EOF
format holy-package-1
name busybox-bootstrap
version 1.37.0
release 1
os linux
arch $arch
libc nolibc
EOF
for name in deps provides hooks transform; do : > "$tree/HOLY/$name"; done
config_hash=$(sha256sum "$out/busybox.config")
config_hash=${config_hash%% *}
printf 'source-url https://busybox.net/downloads/busybox-1.37.0.tar.bz2\nsource-sha256 %s\nlibc-source-sha256 %s\nbuild-config-sha256 %s\n' \
    "$busybox" "$musl" "$config_hash" > "$tree/HOLY/origin"
"$bin" manifest generate "$tree" --output "$work/files"
cp "$work/files" "$tree/HOLY/files"
"$bin" pack "$tree" --output "$out/busybox.holy"
sha256sum "$out/busybox.holy" "$out/busybox.config" "$profile" >> "$out/build.record"
