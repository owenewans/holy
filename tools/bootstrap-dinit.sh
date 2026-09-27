#!/bin/sh
set -eu
umask 022
test "$#" -eq 3 || { echo 'usage: bootstrap-dinit.sh HOLYPKG INPUTS OUTPUT' >&2; exit 2; }
bin=$(realpath "$1")
inputs=$(realpath "$2")
test "$(id -u)" != 0 && test "$(uname -m)" = x86_64 || exit 6
case "${ARCH:-x86_64}" in
    x86_64) arch=x86_64; target=x86_64-linux-musl; compiler_hash=c5d410d9f82a4f24c549fe5d24f988f85b2679b452413a9f7e5f7b956f2fe7ea ;;
    i686|x86) arch=x86; target=i686-linux-musl; compiler_hash=93bd5504d5d0349258c43d7a668b506acbd627d31c0843a96e4b4c47b27a0180 ;;
    *) printf 'unsupported dinit target: %s\n' "$ARCH" >&2; exit 6 ;;
esac
unset ARCH MAKEFLAGS MAKEOVERRIDES MFLAGS
mkdir -p "$(dirname "$3")"
mkdir "$3"
out=$(realpath "$3")
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
8907d4f668259c4f66d9d2c7cbbb55d455c28dc433596ab29005d589cb572e1e dinit-0.22.1.tar.gz https://github.com/davmac314/dinit/archive/refs/tags/v0.22.1.tar.gz
EOF
printf '%s %s-cross.tgz https://musl.cc/%s-cross.tgz\n' "$compiler_hash" "$target" "$target" >> "$out/sources"
while read -r hash file url; do
    cp "$inputs/$file" "$work/$file"
    printf '%s  %s\n' "$hash" "$work/$file" | sha256sum -c -
    tar -xf "$work/$file" -C "$work"
done < "$out/sources"
cxx="$work/$target-cross/bin/$target-g++"
"$cxx" --version > "$out/build.record"
printf 'arch %s\ntarget %s\n' "$arch" "$target" >> "$out/build.record"
tree="$work/package"
mkdir -p "$tree/HOLY" "$tree/DATA/usr/share/licenses/dinit"
(
    cd "$work/dinit-0.22.1"
    ./configure --platform=Linux --prefix=/usr --sbindir=/usr/bin --disable-capabilities \
        CXX="$cxx" CXX_FOR_BUILD=g++ CXXFLAGS='-Os -fno-pie' \
        LDFLAGS='-static -no-pie' TEST_LDFLAGS='-static -no-pie'
    make -j"${JOBS:-2}"
    make -j"${JOBS:-2}" check
    make DESTDIR="$tree/DATA" install
    cp mconfig "$out/mconfig"
    cp LICENSE "$tree/DATA/usr/share/licenses/dinit/LICENSE"
)
"$bin" elf "$tree/DATA/usr/bin/dinit" > "$out/elf.record"
grep -qx 'runtime nolibc' "$out/elf.record"
grep -qx 'e_type 2' "$out/elf.record"
grep -qx "machine $arch" "$out/elf.record"
"$tree/DATA/usr/bin/dinit" --version > "$out/version.record"
cat > "$tree/HOLY/meta" <<EOF
format holy-package-1
name dinit
version 0.22.1
release 1
os linux
arch $arch
libc nolibc
EOF
for field in deps provides hooks transform; do : > "$tree/HOLY/$field"; done
cp "$out/sources" "$tree/HOLY/origin"
"$bin" manifest generate "$tree" --output "$work/files"
cp "$work/files" "$tree/HOLY/files"
"$bin" pack "$tree" --output "$out/dinit.holy"
sha256sum "$out/dinit.holy" "$out/mconfig" >> "$out/build.record"
