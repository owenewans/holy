#!/bin/sh
set -eu
umask 022
if [ "$#" -ne 3 ]; then
    printf 'usage: static-deps.sh INPUT-DIRECTORY OUTPUT-DIRECTORY KERNEL-HEADERS\n' >&2
    exit 2
fi
inputs=$(realpath "$1")
headers=$(realpath "$3")
sources=$(realpath "$(dirname "$0")/../profiles/static-sources")
case "${ARCH:-x86_64}" in
    x86_64) target=x86_64-linux-musl; arch=x86_64; cpu_flags=-m64; link_flags=-Wl,-m,elf_x86_64; openssl_target=linux-x86_64; elf_class=ELF64; machine='Advanced Micro Devices X86-64'; bits=64 ;;
    i686|x86) target=i686-linux-musl; arch=x86; cpu_flags='-m32 -march=i686 -mtune=generic'; link_flags=-Wl,-m,elf_i386; openssl_target=linux-x86; elf_class=ELF32; machine='Intel 80386'; bits=32 ;;
    *) printf 'unsupported static target: %s\n' "$ARCH" >&2; exit 6 ;;
esac
unset ARCH MAKEFLAGS MAKEOVERRIDES MFLAGS
case "$(uname -m)" in
    x86_64|i?86) ;;
    *) printf 'static dependency bootstrap requires an x86 builder\n' >&2; exit 6 ;;
esac
for tool in gcc ar ranlib make cmake autoreconf automake libtoolize perl tar sha256sum pkg-config readelf; do
    command -v "$tool" >/dev/null || { printf 'missing tool: %s\n' "$tool" >&2; exit 6; }
done
for dir in linux asm asm-generic; do
    test -d "$headers/$dir" || { printf 'missing Linux headers: %s\n' "$dir" >&2; exit 6; }
done
mkdir -p "$(dirname "$2")"
mkdir "$2"
out=$(realpath "$2")
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
cp "$sources" "$out/sources"
gcc --version > "$out/build.record"
printf 'arch %s\ntarget %s\ncpu-flags %s\nlink-flags %s\n' "$arch" "$target" "$cpu_flags" "$link_flags" >> "$out/build.record"
sha256sum "$0" "$sources" >> "$out/build.record"
while read -r digest archive url; do
    cp "$inputs/$archive" "$work/$archive"
    printf '%s  %s\n' "$digest" "$work/$archive" | sha256sum -c -
done < "$sources"
while read -r digest archive url; do
    tar -xf "$work/$archive" -C "$work"
done < "$sources"
unset CC CFLAGS CPPFLAGS LDFLAGS LDLIBS
jobs=${JOBS:-2}
(
    cd "$work/musl-1.2.5"
    CC=gcc CFLAGS="$cpu_flags" LDFLAGS="$cpu_flags" AR=ar RANLIB=ranlib \
        ./configure --target="$target" --prefix="$out/toolchain" --syslibdir="$out/toolchain/lib"
    make -j"$jobs"
    make install
)
cp -aL "$headers/linux" "$headers/asm" "$headers/asm-generic" "$out/toolchain/include/"
find "$out/toolchain/include/linux" "$out/toolchain/include/asm" \
    "$out/toolchain/include/asm-generic" -type f -exec sha256sum {} + > "$out/kernel-headers.sha256"
flag=
if gcc -fno-link-libatomic -x c -c /dev/null -o "$work/flag.o" 2>/dev/null; then
    flag=-fno-link-libatomic
fi
mkdir -p "$out/bin" "$out/include" "$out/lib"
printf '#!/bin/sh\nexec "%s/toolchain/bin/musl-gcc" %s %s %s "$@"\n' "$out" "$cpu_flags" "$link_flags" "$flag" > "$out/bin/holy-musl-gcc"
chmod 755 "$out/bin/holy-musl-gcc"
CC="$out/bin/holy-musl-gcc"
CPPFLAGS="-I$out/include"
LDFLAGS="-L$out/lib"
PKG_CONFIG_LIBDIR="$out/lib/pkgconfig"
export CC CPPFLAGS LDFLAGS PKG_CONFIG_LIBDIR
unset PKG_CONFIG_PATH
cat > "$work/target.c" <<'EOF'
#include <stdio.h>
int main(void)
{
    volatile unsigned long long dividend = 0x100000001ULL, divisor = 3;
    printf("pointer-bits %u\n", (unsigned)(sizeof(void *) * 8));
    return dividend / divisor != 1431655765ULL;
}
EOF
"$CC" -static "$work/target.c" -o "$out/target-probe"
LC_ALL=C readelf -h "$out/target-probe" > "$out/target-probe.elf"
grep -q "Class:.*$elf_class" "$out/target-probe.elf" || exit 6
grep -q "Machine:.*$machine" "$out/target-probe.elf" || exit 6
"$out/target-probe" > "$out/target-probe.out" || {
    printf 'builder cannot execute the selected target probe: %s\n' "$target" >&2
    exit 6
}
grep -qx "pointer-bits $bits" "$out/target-probe.out" || exit 6
sha256sum "$out/target-probe" >> "$out/build.record"
build_configure() (
    source=$1
    shift
    cd "$work/$source"
    if [ "$source" = zlib-1.3.2 ]; then
        ./configure --prefix="$out" "$@"
    else
        ./configure --host="$target" --build="$(gcc -dumpmachine)" --prefix="$out" "$@"
    fi
    make -j"$jobs"
    make install
)
build_configure zlib-1.3.2 --static
make -C "$work/lz4-1.10.0/lib" -j"$jobs" BUILD_SHARED=no PREFIX="$out" install
make -C "$work/zstd-1.5.7/lib" -j"$jobs" CC="$CC" PREFIX="$out" libzstd.a-release
make -C "$work/zstd-1.5.7/lib" CC="$CC" PREFIX="$out" install-static install-includes install-pc
make -C "$work/bzip2-1.0.8" -j"$jobs" CC="$CC" libbz2.a
install -m 644 "$work/bzip2-1.0.8/libbz2.a" "$out/lib/"
install -m 644 "$work/bzip2-1.0.8/bzlib.h" "$out/include/"
build_configure xz-5.8.1 --disable-shared --enable-static --disable-nls \
    --disable-xz --disable-xzdec --disable-lzmadec --disable-lzmainfo --disable-scripts
(
    cd "$work/openssl-3.5.8"
    ./Configure "$openssl_target" no-shared no-module no-tests --prefix="$out" --libdir=lib
    make -j"$jobs"
    make install_sw
)
build_configure curl-8.22.0 --disable-shared --enable-static \
    --with-openssl="$out" --with-zlib="$out" --without-libpsl --without-libidn2 \
    --without-librtmp --without-libssh2 --without-brotli --without-zstd --disable-ldap --disable-ldaps
build_configure libarchive-3.8.9 --disable-shared --enable-static --with-bz2lib \
    --with-lzma --with-zstd --without-xml2 --without-expat --without-openssl \
    --without-nettle --without-iconv --disable-acl --disable-xattr --disable-bsdtar \
    --disable-bsdcpio --disable-bsdcat --disable-bsdunzip
for feature in HAVE_LIBBZ2 HAVE_LIBLZMA HAVE_LIBZSTD HAVE_LIBLZ4 HAVE_LIBZ; do
    grep -qx "#define $feature 1" "$work/libarchive-3.8.9/config.h" || {
        printf 'required libarchive codec missing: %s\n' "$feature" >&2
        exit 6
    }
done
for source in argp-standalone-1.5.0 musl-fts-1.2.7 musl-obstack-1.2.3; do
    (cd "$work/$source" && autoreconf -fi)
    build_configure "$source" --disable-shared
done
install -m 644 "$work/argp-standalone-1.5.0/libargp.a" "$out/lib/"
install -m 644 "$work/argp-standalone-1.5.0/argp.h" "$out/include/"
(
    cd "$work/elfutils-0.196"
    ./configure --host="$target" --build="$(gcc -dumpmachine)" --prefix="$out" --disable-debuginfod --disable-libdebuginfod \
        --disable-nls --disable-demangler --without-zstd --without-bzlib --without-lzma
    make -C libelf -j"$jobs" libelf.a
    make -C lib -j"$jobs" libeu.a
    install -m 644 libelf/libelf.a lib/libeu.a "$out/lib/"
    install -m 644 libelf/libelf.h libelf/gelf.h libelf/nlist.h "$out/include/"
)
cmake -S "$work/libsolv-0.7.40" -B "$work/solv-build" \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_PREFIX_PATH="$out" -DCMAKE_INSTALL_PREFIX="$out" \
    -DCMAKE_INSTALL_LIBDIR=lib -DDISABLE_SHARED=ON -DENABLE_STATIC=ON -DMULTI_SEMANTICS=ON \
    -DZLIB_LIBRARY="$out/lib/libz.a" -DZLIB_INCLUDE_DIR="$out/include"
cmake --build "$work/solv-build" -j"$jobs"
cmake --install "$work/solv-build"
sha256sum "$out"/lib/*.a "$out/toolchain/lib/libc.a" >> "$out/build.record"
