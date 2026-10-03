#!/bin/sh
# builds the kernel image an image build boots. the target is a Holy userspace with no
# module loading, so every driver the profile names is built in and the image carries
# only the kernel. a release build is reproducible only from the pinned tarball, the
# recorded config and the recorded compiler, so all three are written to build.record.
set -eu
test "$#" -eq 3 || { echo 'usage: bootstrap-linux.sh INPUTS VERSION OUTPUT' >&2; exit 2; }
test "$(id -u)" != 0 || { echo 'run as an ordinary user' >&2; exit 6; }
inputs=$(realpath "$1")
version=$2
output=$3
case "$version" in ''|*[!a-zA-Z0-9._+-]*) exit 2 ;; esac
case "${ARCH:-x86_64}" in
    x86_64) arch=x86_64; defconfig=x86_64_defconfig; machine=x86-64; bits=64 ;;
    i686|x86) arch=i686; defconfig=i386_defconfig; machine=80386; bits=32 ;;
    *) printf 'unsupported linux target: %s\n' "$ARCH" >&2; exit 6 ;;
esac
unset ARCH MAKEFLAGS MAKEOVERRIDES MFLAGS
project=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
tarball=linux-$version.tar.xz
digest=$(awk -v name="$tarball" '$2 == name { print $1 }' "$project/profiles/linux-sources")
test "${#digest}" -eq 64 || { echo "no pinned digest for $tarball" >&2; exit 6; }
mkdir -p "$(dirname "$output")"
mkdir -m 0700 "$output"
out=$(realpath "$output")
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
{
    printf 'format holy-linux-bootstrap-1\n'
    printf 'arch %s\nversion %s\nlibc nolibc\nconfig %s\n' "$arch" "$version" "$defconfig"
    printf 'source https://cdn.kernel.org/pub/linux/kernel/v7.x/%s\n' "$tarball"
    printf 'source-sha256 %s\n' "$digest"
} > "$out/build.record"
gcc --version >> "$out/build.record"
mkdir "$out/inputs" "$out/work"
cp "$inputs/$tarball" "$out/inputs/"
printf '%s  %s\n' "$digest" "$out/inputs/$tarball" | sha256sum -c -
tar -xf "$out/inputs/$tarball" -C "$out/work"
tree="$out/work/linux-$version"
# a Holy image loads no module at boot, so the profile's drivers are built in rather
# than shipped: one artifact, no modules.dep to agree with, and a kernel that reaches
# its root device before anything has mounted /usr/lib/modules.
fragment() {
    config="$tree/.config"
    while test "$#" -gt 1; do
        scripts/config --file "$config" "$1" "$2"
        shift 2
    done
}
(
    cd "$tree"
    make -s ARCH=x86 "$defconfig"
    fragment -d MODULES -e MODULE_UNLOAD \
        -e BLK_DEV_INITRD -e RD_GZIP -e RD_XZ -e RD_LZ4 -e RD_ZSTD -e RD_BZIP2 \
        -e DEVTMPFS -e DEVTMPFS_MOUNT -e TMPFS -e PROC_FS -e SYSFS \
        -e BLK_DEV_LOOP -e BLK_DEV_RAM -e RAMFS \
        -e ATA -e ATA_PIIX -e SCSI -e BLK_DEV_SD -e BLK_DEV_SR \
        -e VIRTIO -e VIRTIO_PCI -e VIRTIO_BLK -e VIRTIO_NET -e VIRTIO_CONSOLE \
        -e IDE -e ATA_GENERIC \
        -e EXT4_FS -e EXT4_USE_FOR_EXT2 -e JBD2 -e CRC32 -e LIBCRC32C \
        -e CRYPTO -e CRYPTO_CRC32C -e CRYPTO_AES -e CRYPTO_CBC -e CRYPTO_CTR \
        -e XFS_FS -e BTRFS_FS -e F2FS_FS -e MSDOS_FS -e VFAT_FS -e ISO9660_FS \
        -e DUMMY -e ETHERNET -e PACKET -e UNIX -e INET -e NETFILTER \
        -e SERIAL_8250 -e SERIAL_8250_CONSOLE -e SERIAL_CORE -e SERIAL_CORE_CONSOLE \
        -e PCI -e PCI_MSI -e ACPI -e MULTIUSER \
        -e FUTEX -e EPOLL -e SIGNALFD -e EVENTFD -e TIMERFD -e AIO
    make -s ARCH=x86 olddefconfig
    grep -qx '# CONFIG_MODULES is not set' .config
    cp .config "$out/config-$arch"
    make -j"${JOBS:-2}" ARCH=x86 bzImage
)
image="$tree/arch/x86/boot/bzImage"
test -f "$image" || { echo 'kernel build produced no bzImage' >&2; exit 1; }
python3 - "$image" "$arch" <<'PY'
import struct
import sys

with open(sys.argv[1], 'rb') as source:
    header = source.read(0x238)
if len(header) < 0x238 or header[0x202:0x206] != b'HdrS':
    sys.exit('unsupported x86 kernel boot header')
flag = struct.unpack_from('<H', header, 0x236)[0]
actual = 'x86_64' if flag & 1 else 'i686'
if actual != sys.argv[2]:
    sys.exit(f'kernel target {actual} does not match requested {sys.argv[2]}')
PY
cp "$image" "$out/bzImage"
chmod 0644 "$out/bzImage"
cp "$out/config-$arch" "$out/config"
sha256sum "$out/bzImage" "$out/config" "$0" >> "$out/build.record"
printf 'result built-not-booted\n' >> "$out/build.record"
printf '%s\n' "$out/bzImage"