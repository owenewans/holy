#!/bin/sh
set -eu
umask 022
test "$#" -eq 7 || {
    echo 'usage: bootstrap-storage.sh HOLYPKG UTIL-LINUX-GIT DOSFSTOOLS-GIT E2FSPROGS-GIT LIMINE-BINARY-TAR STATIC-PREFIX OUTPUT' >&2
    exit 2
}
bin=$(realpath "$1")
util=$(realpath "$2")
dos=$(realpath "$3")
e2=$(realpath "$4")
limine_archive=$(realpath "$5")
prefix=$(realpath "$6")
test "$(id -u)" != 0 && test "$(uname -m)" = x86_64 || exit 6
test -x "$bin" && test -x "$prefix/bin/holy-musl-gcc" &&
    grep -qx 'arch x86_64' "$prefix/build.record" &&
    grep -qx 'exit 0' "$prefix/build.record" || exit 6
test "$(git -C "$util" rev-parse HEAD)" = d76cbf8f13e65ff657344f7f6a90042cf755ba59
test "$(git -C "$dos" rev-parse HEAD)" = 697f7692c951173c1b732901e13f72bd3182d575
test "$(git -C "$e2" rev-parse HEAD)" = 7ee1d505ef3b37831215f490411f346fe57e9053
printf '%s  %s\n' 9a738586bff5790bd8bfef4a4868a2939cba3f81f22f121306d668c97f1c85d8 \
    "$limine_archive" | sha256sum -c -
for tool in git tar make autoreconf asciidoctor sha256sum; do
    command -v "$tool" >/dev/null || { echo "$tool required" >&2; exit 6; }
done
mkdir -p "$(dirname "$7")"
mkdir "$7"
out=$(realpath "$7")
work="$out/work"
mkdir "$work"
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
printf 'format holy-storage-bootstrap-1\narch x86_64\n' > "$out/build.record"
for name in util-linux dosfstools e2fsprogs; do mkdir "$work/$name"; done
git -C "$util" archive HEAD | tar -xf - -C "$work/util-linux"
git -C "$dos" archive HEAD | tar -xf - -C "$work/dosfstools"
git -C "$e2" archive HEAD | tar -xf - -C "$work/e2fsprogs"
printf 'util-linux-commit %s\ndosfstools-commit %s\ne2fsprogs-commit %s\n' \
    "$(git -C "$util" rev-parse HEAD)" "$(git -C "$dos" rev-parse HEAD)" \
    "$(git -C "$e2" rev-parse HEAD)" >> "$out/build.record"
printf 'limine-binary-sha256 %s\n' \
    9a738586bff5790bd8bfef4a4868a2939cba3f81f22f121306d668c97f1c85d8 >> "$out/build.record"
sha256sum "$prefix/build.record" "$0" >> "$out/build.record"
cc="$prefix/bin/holy-musl-gcc"
(
    cd "$work/util-linux"
    ./autogen.sh
)
mkdir "$work/util-build"
(
    cd "$work/util-build"
    CC="$cc" CFLAGS=-O2 LDFLAGS=-static "$work/util-linux/configure" \
        --prefix=/usr --disable-shared --enable-static --disable-all-programs \
        --enable-libuuid --enable-libblkid --enable-libsmartcols --enable-libfdisk \
        --enable-fdisks=check --enable-static-programs=sfdisk \
        --without-readline --without-ncursesw --without-tinfo --disable-nls
    make -j"${JOBS:-2}" sfdisk.static
)
(
    cd "$work/dosfstools"
    ./autogen.sh
    CC="$cc" CFLAGS=-O2 LDFLAGS=-static ./configure --prefix=/usr
    make -j"${JOBS:-2}"
)
mkdir "$work/e2-build"
(
    cd "$work/e2-build"
    CC="$cc" CFLAGS=-O2 LDFLAGS=-static "$work/e2fsprogs/configure" \
        --prefix=/usr --enable-libuuid --enable-libblkid --disable-nls \
        --disable-fuse2fs --disable-uuidd
    make -j"${JOBS:-2}"
)
tar -xf "$limine_archive" -C "$work"
make -C "$work/limine-binary" CC="$cc" CFLAGS=-O2 LDFLAGS=-static
tree="$work/package"
mkdir -p "$tree/HOLY" "$tree/DATA/usr/bin" "$tree/DATA/usr/share/man/man8" \
    "$tree/DATA/usr/share/man/man1" "$tree/DATA/usr/share/licenses/holy-storage-tools"
cp "$work/util-build/sfdisk.static" "$tree/DATA/usr/bin/sfdisk"
cp "$work/dosfstools/src/mkfs.fat" "$tree/DATA/usr/bin/mkfs.fat"
cp "$work/e2-build/misc/mke2fs" "$tree/DATA/usr/bin/mke2fs"
cp "$work/limine-binary/limine" "$tree/DATA/usr/bin/limine"
for name in sfdisk mkfs.fat mke2fs limine; do
    "$bin" elf "$tree/DATA/usr/bin/$name" > "$out/$name.elf"
    grep -qx 'runtime nolibc' "$out/$name.elf"
    grep -qx 'e_type 2' "$out/$name.elf"
    grep -qx 'machine x86_64' "$out/$name.elf"
done
ln -s ../man-common "$work/util-linux/disk-utils/man-common"
asciidoctor -a release-version=2.42.4 -b manpage \
    -o "$tree/DATA/usr/share/man/man8/sfdisk.8" \
    "$work/util-linux/disk-utils/sfdisk.8.adoc" 2> "$out/sfdisk-man.log"
test ! -s "$out/sfdisk-man.log"
cp "$work/dosfstools/manpages/mkfs.fat.8" "$tree/DATA/usr/share/man/man8/"
cp "$work/e2-build/misc/mke2fs.8" "$tree/DATA/usr/share/man/man8/"
cp "$work/limine-binary/LICENSE" "$tree/DATA/usr/share/licenses/holy-storage-tools/limine-LICENSE"
cp "$work/util-linux/COPYING" "$tree/DATA/usr/share/licenses/holy-storage-tools/util-linux-COPYING"
cp "$work/dosfstools/COPYING" "$tree/DATA/usr/share/licenses/holy-storage-tools/dosfstools-COPYING"
cp "$work/e2fsprogs/NOTICE" "$tree/DATA/usr/share/licenses/holy-storage-tools/e2fsprogs-NOTICE"
cp "$work/e2fsprogs/lib/uuid/COPYING" "$tree/DATA/usr/share/licenses/holy-storage-tools/e2fsprogs-uuid-COPYING"
cat > "$tree/HOLY/meta" <<'EOF'
format holy-package-1
name holy-storage-tools
version 1
release 1
os linux
arch x86_64
libc nolibc
summary "static disk preparation tools for Holy installer"
EOF
for name in deps provides hooks transform; do : > "$tree/HOLY/$name"; done
cp "$out/build.record" "$tree/HOLY/origin"
"$bin" manifest generate "$tree" --output "$work/files"
cp "$work/files" "$tree/HOLY/files"
"$bin" pack "$tree" --output "$out/holy-storage-tools.holy"
"$bin" info "local:$out/holy-storage-tools.holy" > "$out/package.record"
sha256sum "$out/holy-storage-tools.holy" "$tree/DATA/usr/bin/"* >> "$out/build.record"
