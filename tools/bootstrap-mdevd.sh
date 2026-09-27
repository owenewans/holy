#!/bin/sh
set -eu
umask 022
test "$#" -eq 3 || { echo 'usage: bootstrap-mdevd.sh HOLYPKG INPUTS OUTPUT' >&2; exit 2; }
bin=$(realpath "$1")
inputs=$(realpath "$2")
test "$(id -u)" != 0 && test "$(uname -m)" = x86_64 || exit 6
case "${ARCH:-x86_64}" in
    x86_64) arch=x86_64 ;;
    i686|x86) arch=x86 ;;
    *) printf 'unsupported mdevd target: %s\n' "$ARCH" >&2; exit 6 ;;
esac
unset ARCH MAKEFLAGS MAKEOVERRIDES MFLAGS
compiler_prefix=${STATIC_PREFIX:-}
if [ -n "$compiler_prefix" ]; then
    compiler_prefix=$(realpath "$compiler_prefix")
    test -x "$compiler_prefix/bin/holy-musl-gcc" && test -f "$compiler_prefix/build.record" || exit 6
    grep -qx "arch $arch" "$compiler_prefix/build.record" && grep -qx 'exit 0' "$compiler_prefix/build.record" || exit 6
elif [ "$arch" != x86_64 ]; then
    echo 'i686 requires STATIC_PREFIX from make static-deps ARCH=i686' >&2
    exit 6
fi
mkdir -p "$(dirname "$3")"
mkdir "$3"
out=$(realpath "$3")
case "$out" in *[!a-zA-Z0-9_./-]*) echo 'unsupported build path' >&2; exit 2;; esac
work=$(mktemp -d "$out/work.XXXXXX")
started=$(date +%s)
cleanup() {
    rc=$?
    trap - EXIT
    printf 'exit %s\nelapsed-seconds %s\n' "$rc" "$(($(date +%s) - started))" >> "$out/build.record"
    rm -rf "$work"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
exec > "$out/build.log" 2>&1
cat > "$out/sources" <<'EOF'
23e242d70492b5381cab2227dd5b5407f748e52fe7a5df919a352c8dae26919d mdevd-0.1.8.2.tar.gz https://codeload.github.com/skarnet/mdevd/tar.gz/refs/tags/v0.1.8.2
efa8b213fe341d57c8b7ad087d928b8d3296643a3a1583bf7e7675766bb68b06 skalibs-2.15.1.0.tar.gz https://codeload.github.com/skarnet/skalibs/tar.gz/refs/tags/v2.15.1.0
EOF
if [ -z "$compiler_prefix" ]; then
    printf '%s\n' 'c5d410d9f82a4f24c549fe5d24f988f85b2679b452413a9f7e5f7b956f2fe7ea x86_64-linux-musl-cross.tgz https://musl.cc/x86_64-linux-musl-cross.tgz' >> "$out/sources"
fi
while read -r hash file url; do
    cp "$inputs/$file" "$work/$file"
    printf '%s  %s\n' "$hash" "$work/$file" | sha256sum -c -
    tar -xf "$work/$file" -C "$work"
done < "$out/sources"
if [ -n "$compiler_prefix" ]; then
    CC="$compiler_prefix/bin/holy-musl-gcc"
    cp "$compiler_prefix/build.record" "$out/compiler.record"
else
    CC="$work/x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc"
fi
export CC
export CFLAGS='-Os -fno-pie'
export LDFLAGS='-static -no-pie'
"$CC" --version > "$out/build.record"
printf 'arch %s\n' "$arch" >> "$out/build.record"
sha256sum "$CC" "$0" >> "$out/build.record"
if [ -n "$compiler_prefix" ]; then sha256sum "$out/compiler.record" >> "$out/build.record"; fi
prefix="$work/skalibs"
(
    cd "$work/skalibs-2.15.1.0"
    ./configure --prefix="$prefix" --disable-shared
    make -j"${JOBS:-2}"
    make install
    cp config.mak "$out/skalibs.config"
)
tree="$work/package"
mkdir -p "$tree/HOLY" "$tree/DATA/usr/share/licenses/mdevd" "$tree/DATA/usr/share/licenses/skalibs" "$tree/DATA/usr/share/doc/mdevd"
(
    cd "$work/mdevd-0.1.8.2"
    ./configure --prefix=/usr --enable-static-libc --disable-shared \
        --with-include="$prefix/include" --with-lib="$prefix/lib" \
        --with-sysdeps="$prefix/lib/skalibs/sysdeps"
    make -j"${JOBS:-2}"
    make DESTDIR="$tree/DATA" install
    cp config.mak "$out/mdevd.config"
    cp COPYING "$tree/DATA/usr/share/licenses/mdevd/COPYING"
    cp doc/*.html "$tree/DATA/usr/share/doc/mdevd/"
)
cp "$work/skalibs-2.15.1.0/COPYING" "$tree/DATA/usr/share/licenses/skalibs/COPYING"
for name in mdevd mdevd-coldplug; do
    "$bin" elf "$tree/DATA/usr/bin/$name" > "$out/$name.elf"
    grep -qx 'runtime nolibc' "$out/$name.elf"
    grep -qx 'e_type 2' "$out/$name.elf"
    grep -qx "machine $arch" "$out/$name.elf"
done
cat > "$tree/HOLY/meta" <<EOF
format holy-package-1
name mdevd
version 0.1.8.2
release 1
os linux
arch $arch
libc nolibc
EOF
for field in deps provides hooks transform; do : > "$tree/HOLY/$field"; done
cp "$out/sources" "$tree/HOLY/origin"
if [ -n "$compiler_prefix" ]; then
    record_hash=$(sha256sum "$out/compiler.record")
    printf 'compiler-record-sha256 %s\n' "${record_hash%% *}" >> "$tree/HOLY/origin"
fi
"$bin" manifest generate "$tree" --output "$work/files"
cp "$work/files" "$tree/HOLY/files"
"$bin" pack "$tree" --output "$out/mdevd.holy"
printf 'missing-man mdevd mdevd-coldplug; upstream HTML included\n' > "$out/docs.record"
sha256sum "$out/mdevd.holy" "$out/skalibs.config" "$out/mdevd.config" >> "$out/build.record"
