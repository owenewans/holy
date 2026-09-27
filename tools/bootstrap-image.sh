#!/bin/sh
set -eu
test "$#" -eq 10 || {
    echo 'usage: bootstrap-image.sh HOLYPKG STATIC_HOLYPKG STATIC_CC BUSYBOX DINIT MDEVD KERNEL KERNEL_VERSION LIMINE_DIR OUTPUT' >&2
    exit 2
}
if test "${HOLY_IMAGE_NAMESPACE:-}" != 1; then
    test "$(id -u)" != 0 || { echo 'run the builder as an ordinary user' >&2; exit 6; }
    export HOLY_IMAGE_NAMESPACE=1
    exec unshare --map-root-user -- sh "$0" "$@"
fi
test "$(id -u)" = 0 && awk '$1 == 0 && $2 != 0 && $3 == 1 { ok = 1 } END { exit !ok }' /proc/self/uid_map || exit 6
umask 022
PATH=$PATH:/usr/sbin:/sbin
export PATH
bin=$(realpath "$1")
static=$(realpath "$2")
installer=$(realpath "${STATIC_HOLYINSTALL:?STATIC_HOLYINSTALL required}")
cc=$(realpath "$3")
busybox=$(realpath "$4")
dinit=$(realpath "$5")
mdevd=$(realpath "$6")
kernel=$(realpath "$7")
version=$8
limine_dir=$(realpath "$9")
shift 9
case "$version" in ''|*[!a-zA-Z0-9._+-]*) exit 2 ;; esac
test "$(uname -m)" = x86_64 || exit 6
arch=${ARCH:-x86_64}
case "$arch" in
    x86_64) qemu=qemu-system-x86_64; package_arch=x86_64 ;;
    i686) qemu=qemu-system-i386; package_arch=x86 ;;
    *) echo 'ARCH must be i686 or x86_64' >&2; exit 2 ;;
esac
for tool in dracut ldconfig limine sha256sum cpio gzip python3 "$qemu"; do
    command -v "$tool" >/dev/null || { echo "$tool required" >&2; exit 6; }
done
python3 - "$kernel" "$arch" <<'PY'
import struct
import sys

with open(sys.argv[1], 'rb') as source:
    header = source.read(0x238)
if (len(header) < 0x238 or header[0x202:0x206] != b'HdrS' or
        struct.unpack_from('<H', header, 0x206)[0] < 0x20c):
    print('holy-image: unsupported x86 kernel boot header', file=sys.stderr)
    sys.exit(6)
kernel_arch = 'x86_64' if struct.unpack_from('<H', header, 0x236)[0] & 1 else 'i686'
if kernel_arch != sys.argv[2]:
    print(f'holy-image: kernel target {kernel_arch} does not match image {sys.argv[2]}',
          file=sys.stderr)
    sys.exit(6)
PY
project=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
profile=${IMAGE_PROFILE:-dual-libc}
boot_state=${LIBC_BOOT_STATE:-present}
storage=${ROOT_STORAGE:-ram}
network_recovery=${NETWORK_RECOVERY:-off}
case "$network_recovery" in
    off) ;;
    fixture)
        test "$profile" = dual-libc && test "$boot_state" = both && test "$storage" = ram || {
            echo 'network fixture requires dual-libc, both absent and ram root' >&2
            exit 2
        }
        command -v openssl >/dev/null || exit 6
        ;;
    *) echo 'NETWORK_RECOVERY must be off or fixture' >&2; exit 2 ;;
esac
if test "$boot_state" = remove-both && { test "$storage" = ram || test "$profile" != dual-libc || test "$network_recovery" != off; }; then
    echo 'remove-both requires persistent dual-libc root without network fixture' >&2
    exit 2
fi
case "$storage:$profile" in
    ram:*) ;;
    ext4:dual-libc|gpt-ext4:dual-libc)
        for tool in mke2fs qemu-img; do command -v "$tool" >/dev/null || exit 6; done
        if test "$storage" = gpt-ext4; then
            for tool in sfdisk mkfs.fat mcopy mmd; do command -v "$tool" >/dev/null || exit 6; done
        fi
        ;;
    *) echo 'ROOT_STORAGE must be ram, or ext4/gpt-ext4 with dual-libc' >&2; exit 2 ;;
esac
if test "$storage" != gpt-ext4; then command -v xorriso >/dev/null || exit 6; fi
extra_packages=
case "$profile:$boot_state" in
    static-core:present) ;;
    dual-libc:present|dual-libc:glibc|dual-libc:musl|dual-libc:both|dual-libc:remove-both)
        glibc=$(realpath "${GLIBC_PACKAGE:?GLIBC_PACKAGE required}")
        musl=$(realpath "${MUSL_PACKAGE:?MUSL_PACKAGE required}")
        glibc_cc=$(command -v "${GLIBC_CC:-gcc}")
        musl_cc=$(realpath "${MUSL_CC:?MUSL_CC required}")
        test -f "$glibc" && test -f "$musl" && test -x "$musl_cc" || exit 6
        command -v patchelf >/dev/null || exit 6
        extra_packages='glibc musl probe-glibc probe-musl'
        ;;
    *) echo 'unsupported image profile or libc boot state' >&2; exit 2 ;;
esac
mkdir -p "$(dirname "$1")"
mkdir -m 0700 "$1"
out=$(realpath "$1")
work="$out/work"
root="$out/root"
mkdir "$work" "$root" "$out/packages" "$out/inputs" "$out/reports"
started=$(date +%s)
record="$out/build.record"
printf 'format holy-bootstrap-image-1\narch %s\nprofile %s\nlibc-boot-state %s\nkernel-version %s\n' "$arch" "$profile" "$boot_state" "$version" > "$record"
printf 'root-storage %s\n' "$storage" >> "$record"
printf 'network-recovery %s\n' "$network_recovery" >> "$record"
finish() {
    rc=$?
    trap - EXIT
    printf 'exit %s\nelapsed-seconds %s\n' "$rc" "$(($(date +%s) - started))" >> "$record"
    test "$rc" -eq 0 || printf 'result incomplete\n' >> "$record"
    exit "$rc"
}
trap finish EXIT
trap 'exit 1' HUP INT TERM
exec > "$out/build.log" 2>&1
"$bin" elf "$static" > "$out/core.elf"
grep -qx 'runtime nolibc' "$out/core.elf"
grep -qx "machine $package_arch" "$out/core.elf"
"$bin" elf "$installer" > "$out/installer.elf"
grep -qx 'runtime nolibc' "$out/installer.elf"
grep -qx "machine $package_arch" "$out/installer.elf"
"$cc" --version > "$out/compiler.record"
"$cc" -std=c99 -Wall -Wextra -Werror -pedantic -Os -static -fno-pie -no-pie \
    "$project/src/early-init.c" -o "$work/holy-init"
"$bin" elf "$work/holy-init" > "$out/init.elf"
grep -qx 'runtime nolibc' "$out/init.elf"
grep -qx "machine $package_arch" "$out/init.elf"
if "$work/holy-init" > "$work/init.out" 2> "$work/init.err"; then exit 1; else test "$?" -eq 2; fi

tree="$work/tree"
metadata() {
    mkdir -p "$tree/HOLY" "$tree/DATA"
    printf 'format holy-package-1\nname %s\nversion %s\nrelease 1\nos linux\narch %s\nlibc nolibc\n' \
        "$1" "$2" "$3" > "$tree/HOLY/meta"
    for field in deps provides hooks origin transform; do : > "$tree/HOLY/$field"; done
}
pack() {
    "$bin" manifest generate "$tree" --output "$work/files"
    cp "$work/files" "$tree/HOLY/files"
    rm "$work/files"
    "$bin" pack "$tree" --output "$out/packages/$1.holy"
    rm -rf "$tree"
}
for name in busybox dinit mdevd $extra_packages; do
    case "$name" in
        busybox) input=$busybox ;; dinit) input=$dinit ;; mdevd) input=$mdevd ;;
        glibc) input=$glibc ;; musl) input=$musl ;; probe-*) continue ;;
    esac
    cp "$input" "$out/inputs/$name.holy"
    "$bin" info "local:$out/inputs/$name.holy" > "$work/input-info"
    grep -qx "arch $package_arch" "$work/input-info" || exit 6
    parent=$(sha256sum "$out/inputs/$name.holy")
    parent=${parent%% *}
    "$bin" fetch "local:$out/inputs/$name.holy" --extract --output "$tree"
    test ! -s "$tree/HOLY/transform" || exit 6
    if test "$name" = busybox && test -f "$tree/DATA/usr/share/licenses/musl/COPYRIGHT"; then
        mv "$tree/DATA/usr/share/licenses/musl/COPYRIGHT" "$tree/DATA/usr/share/licenses/busybox/musl.COPYRIGHT"
        printf '\nbootstrap-file-mapping usr/share/licenses/musl/COPYRIGHT usr/share/licenses/busybox/musl.COPYRIGHT\n' >> "$tree/HOLY/origin"
    fi
    find "$tree/DATA" -type d -exec chmod 0755 '{}' +
    printf '\nbootstrap-parent-sha256 %s\nbootstrap-ownership 0 0\nbootstrap-directory-mode 0755\n' "$parent" >> "$tree/HOLY/origin"
    pack "$name"
done
if test "$profile" = dual-libc; then
    for abi in glibc musl; do
        case "$abi" in
            glibc)
                compiler=$glibc_cc; needed=libc.so.6
                if test "$arch" = i686; then
                    loader=/usr/lib/holy/i686-linux-gnu/ld-linux.so.2
                    provider=/usr/lib/holy/i686-linux-gnu/libc.so.6
                else
                    loader=/usr/lib/holy/x86_64-linux-gnu/ld-linux-x86-64.so.2
                    provider=/usr/lib/holy/x86_64-linux-gnu/libc.so.6
                fi ;;
            musl)
                compiler=$musl_cc; needed=libc.so
                if test "$arch" = i686; then
                    loader=/usr/lib/holy/i686-linux-musl/ld-musl-i386.so.1
                else
                    loader=/usr/lib/holy/x86_64-linux-musl/ld-musl-x86_64.so.1
                fi
                provider=$loader ;;
        esac
        metadata "probe-$abi" 1 "$package_arch"
        sed "s/libc nolibc/libc $abi/" "$tree/HOLY/meta" > "$work/meta"
        mv "$work/meta" "$tree/HOLY/meta"
        mkdir -p "$tree/DATA/usr/bin"
        probe="$tree/DATA/usr/bin/holy-probe-$abi"
        "$compiler" -std=c99 -Wall -Wextra -Werror -pedantic -O2 -pthread \
            "-DHOLY_LIBC=\"$abi\"" "$project/tests/libc-probe.c" -o "$probe"
        sha256sum "$project/tests/libc-probe.c" "$probe" >> "$tree/HOLY/origin"
        patchelf --set-interpreter "$loader" --replace-needed "$needed" "$provider" "$probe"
        printf 'bootstrap-patchelf interpreter %s\nbootstrap-patchelf needed %s %s\n' "$loader" "$needed" "$provider" >> "$tree/HOLY/origin"
        sha256sum "$probe" >> "$tree/HOLY/origin"
        pack "probe-$abi"
    done
fi
metadata holypkg bootstrap "$package_arch"
mkdir -p "$tree/DATA/usr/bin" "$tree/DATA/usr/share/man/man5" \
    "$tree/DATA/usr/share/man/man7" "$tree/DATA/usr/share/man/man8" "$tree/DATA/usr/share/holy"
cp "$static" "$out/inputs/holypkg"
cp "$out/inputs/holypkg" "$tree/DATA/usr/bin/holypkg"
for section in 5 7 8; do
    for page in "$project/man/"*."$section"; do
        test "${page##*/}" = holyinstall.8 || cp "$page" "$tree/DATA/usr/share/man/man$section/"
    done
done
sha256sum "$out/inputs/holypkg" >> "$tree/HOLY/origin"
pack holypkg
metadata holyinstall bootstrap "$package_arch"
mkdir -p "$tree/DATA/usr/bin" "$tree/DATA/usr/share/man/man8"
cp "$installer" "$out/inputs/holyinstall"
cp "$out/inputs/holyinstall" "$tree/DATA/usr/bin/holyinstall"
cp "$project/man/holyinstall.8" "$tree/DATA/usr/share/man/man8/holyinstall.8"
sha256sum "$out/inputs/holyinstall" "$project/man/holyinstall.8" > "$tree/HOLY/origin"
pack holyinstall
metadata linux "$version" "$package_arch"
mkdir -p "$tree/DATA/boot"
cp "$kernel" "$out/inputs/kernel"
cp "$out/inputs/kernel" "$tree/DATA/boot/vmlinuz"
chmod 0644 "$tree/DATA/boot/vmlinuz"
sha256sum "$out/inputs/kernel" > "$tree/HOLY/origin"
pack linux
metadata limine bootstrap "$package_arch"
mkdir -p "$tree/DATA/usr/share/limine"
set -- limine-bios.sys limine-bios-cd.bin limine-uefi-cd.bin
if test "$arch" = x86_64; then set -- "$@" BOOTX64.EFI; fi
for file do
    cp "$limine_dir/$file" "$tree/DATA/usr/share/limine/$file"
    chmod 0644 "$tree/DATA/usr/share/limine/$file"
    sha256sum "$tree/DATA/usr/share/limine/$file" >> "$tree/HOLY/origin"
done
limine --version >> "$tree/HOLY/origin"
pack limine
metadata boot-fixture 1 noarch
mkdir -p "$tree/DATA/usr/share/holy"
printf 'installed-in-guest\n' > "$tree/DATA/usr/share/holy/fixture-installed"
pack boot-fixture
metadata boot-fixture-root 1 noarch
printf 'require fixture-1 boot-fixture-root package boot-fixture any any any - boot-fixture metadata\n' > "$tree/HOLY/deps"
pack boot-fixture-root
metadata holy-boot bootstrap "$package_arch"
mkdir -p "$tree/DATA/usr/bin" "$tree/DATA/usr/lib/holy" "$tree/DATA/etc/dinit.d" \
    "$tree/DATA/etc/holy" "$tree/DATA/usr/share/holy"
cp "$work/holy-init" "$tree/DATA/usr/bin/holy-init"
cp "$project/profiles/dinit/"* "$tree/DATA/etc/dinit.d/"
cp "$project/tests/boot-probe.sh" "$tree/DATA/usr/lib/holy/boot-probe.sh"
chmod 0644 "$tree/DATA/usr/lib/holy/boot-probe.sh"
cp "$out/packages/boot-fixture.holy" "$tree/DATA/usr/share/holy/fixture.holy"
chmod 0644 "$tree/DATA/usr/share/holy/fixture.holy"
cp "$out/packages/boot-fixture-root.holy" "$tree/DATA/usr/share/holy/fixture-root.holy"
chmod 0644 "$tree/DATA/usr/share/holy/fixture-root.holy"
printf '%s\n' "$version" > "$tree/DATA/etc/holy/kernel-version"
printf '%s\n' "$profile" > "$tree/DATA/etc/holy/image-profile"
case "$storage" in gpt-ext4) printf 'ext4\n' ;; *) printf '%s\n' "$storage" ;; esac > "$tree/DATA/etc/holy/root-storage"
if test "$storage" = gpt-ext4; then printf '/dev/vda2\n' > "$tree/DATA/etc/holy/esp-device"; fi
printf '%s\n' "$boot_state" > "$tree/DATA/etc/holy/libc-boot-state"
printf '%s\n' "$network_recovery" > "$tree/DATA/etc/holy/network-recovery"
if test "$network_recovery" = fixture; then
    mkdir "$out/network"
    printf 'nameserver 10.0.2.3\noptions timeout:2 attempts:2\n' > "$tree/DATA/etc/resolv.conf"
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
        -keyout "$out/network/key.pem" -out "$out/network/ca.pem" \
        -subj '/CN=Holy recovery fixture' \
        -addext 'subjectAltName=DNS:fixture.holy.test,IP:10.0.2.2' \
        > "$work/openssl.out" 2> "$work/openssl.err"
    chmod 0600 "$out/network/key.pem"
    cp "$out/network/ca.pem" "$tree/DATA/etc/holy/recovery-ca.pem"
    sha256sum "$out/network/ca.pem" >> "$record"
fi
if test "$profile" = dual-libc; then
    for name in $extra_packages; do
        hash=$(sha256sum "$out/packages/$name.holy")
        printf '%s\n' "${hash%% *}" > "$tree/DATA/etc/holy/$name.sha256"
    done
fi
printf 'root:x:0:0:root:/root:/bin/sh\n' > "$tree/DATA/etc/passwd"
printf 'root:x:0:\n' > "$tree/DATA/etc/group"
printf 'root:!:0:0:99999:7:::\n' > "$tree/DATA/etc/shadow"
chmod 0600 "$tree/DATA/etc/shadow"
printf 'null 0:0 0600\n.* 0:0 0600\n' > "$tree/DATA/etc/mdev.conf"
for name in bin sbin; do ln -s usr/bin "$tree/DATA/$name"; done
for name in lib lib32 lib64; do ln -s "usr/$name" "$tree/DATA/$name"; done
ln -s bin "$tree/DATA/usr/sbin"
ln -s dinit "$tree/DATA/usr/bin/init"
ln -s busybox "$tree/DATA/usr/bin/sh"
ln -s usr/bin/holy-init "$tree/DATA/init"
sha256sum "$project/src/early-init.c" "$project/tests/boot-probe.sh" \
    "$project/profiles/dinit/"* > "$tree/HOLY/origin"
pack holy-boot
metadata holy-base bootstrap noarch
for name in busybox dinit mdevd holypkg holyinstall linux limine holy-boot $extra_packages; do
    "$bin" info "local:$out/packages/$name.holy" > "$work/package-info"
    actual_name=$(sed -n 's/^name //p' "$work/package-info")
    case "$actual_name" in ''|*[!a-zA-Z0-9._+-]*) echo 'unsupported bootstrap package name' >&2; exit 6 ;; esac
    printf 'require base-%s holy-base package %s any any any - %s metadata\n' "$name" "$actual_name" "$actual_name" >> "$tree/HOLY/deps"
done
pack holy-base
mkdir -p "$root/usr/bin" "$root/usr/lib/holy" "$root/usr/lib32" "$root/usr/lib64" \
    "$root/usr/share/man/man5" "$root/usr/share/man/man7" "$root/usr/share/man/man8" "$root/usr/share/holy" \
    "$root/usr/share/licenses/busybox" "$root/usr/share/licenses/musl" \
    "$root/usr/share/licenses/dinit" "$root/usr/share/licenses/mdevd" \
    "$root/usr/share/licenses/skalibs" "$root/usr/share/doc/mdevd" \
    "$root/usr/include/mdevd" "$root/usr/share/limine" "$root/etc/dinit.d" \
    "$root/etc/holy" "$root/boot" "$root/dev" "$root/proc" "$root/sys" \
    "$root/run" "$root/tmp" "$root/root"
if test "$profile" = dual-libc; then
    if test "$arch" = i686; then
        mkdir -p "$root/usr/lib/holy/i686-linux-gnu" "$root/usr/lib/holy/i686-linux-musl" \
            "$root/usr/share/licenses/glibc-i686" "$root/usr/share/doc/glibc-i686" \
            "$root/usr/share/licenses/musl-i686" "$root/usr/share/doc/musl-i686"
    else
        mkdir -p "$root/usr/lib/holy/x86_64-linux-gnu" "$root/usr/lib/holy/x86_64-linux-musl" \
            "$root/usr/share/licenses/glibc" "$root/usr/share/doc/glibc" "$root/usr/share/doc/musl"
    fi
fi
"$bin" db init --root "$root"
python3 - "$root" "$work/install.conf" <<'PY'
import sys

def quoted(value):
    return '"' + ''.join('\\x%02x' % ord(char) if ord(char) < 32 or ord(char) == 127
                       else '\\' + char if char in ('"', '\\') else char
                       for char in value) + '"'

with open(sys.argv[2], 'w', encoding='utf-8') as output:
    output.write('[install]\nroot ' + quoted(sys.argv[1]) + '\n')
PY
accepted_arch=
for name in holy-base busybox dinit mdevd holypkg holyinstall linux limine holy-boot $extra_packages; do
    package="$out/packages/$name.holy"
    digest=$(sha256sum "$package")
    digest=${digest%% *}
    printf 'package %s %s\n' "$name" "$digest" >> "$record"
    "$bin" cache stage "local:$package" --root "$root"
    printf 'artifact %s\n' "$digest" >> "$work/install.conf"
    if test "$arch" = i686; then
        "$bin" info "local:$package" > "$work/package-info"
        if grep -qx 'arch x86' "$work/package-info"; then accepted_arch="$accepted_arch $digest"; fi
    fi
done
for digest in $accepted_arch; do
    printf 'architecture-placement host x86_64 target x86 artifact %s accepted-unverified\n' "$digest" >> "$record"
    printf 'accept-arch %s\n' "$digest" >> "$work/install.conf"
done
"$installer" --config "$work/install.conf" --plan "$out/install.plan" --holypkg "$bin" > "$out/install.preview"
cat "$out/install.preview"
plan=$(sed -n 's/^set-sha256 \([0-9a-f]*\)$/\1/p' "$out/install.plan")
test "${#plan}" -eq 64
printf 'install-plan %s\n' "$plan" >> "$record"
"$installer" --apply "$out/install.plan" --holypkg "$bin" > "$out/install.apply"
test "$(cat "$root/var/lib/holypkg/generation")" -eq 1
"$bin" db check --all --root "$root" > "$out/root-check.record"
"$bin" docs --root "$root" --output "$root/usr/share/holy/llm.txt"
chmod 0644 "$root/usr/share/holy/llm.txt"
cp "$root/usr/share/holy/llm.txt" "$out/llm.txt"
docs_hash=$(sha256sum "$out/llm.txt")
printf '%s\n' "${docs_hash%% *}" > "$root/etc/holy/docs.sha256"
printf 'documentation-sha256 %s\n' "${docs_hash%% *}" >> "$record"
tail -n 1 "$out/llm.txt" > "$out/docs.record"
if test "$network_recovery" = fixture; then
    for abi in glibc musl; do
        digest=$(cat "$root/etc/holy/$abi.sha256")
        cache="$root/var/cache/holypkg/objects/sha256/$digest.holy"
        test -f "$cache" && cmp "$cache" "$out/packages/$abi.holy"
        cp "$cache" "$out/network/$abi.holy"
        rm "$cache"
        printf 'network-only-artifact %s %s\n' "$abi" "$digest" >> "$record"
    done
fi
for abi in glibc musl; do
    case "$boot_state:$abi" in
        both:*|glibc:glibc|musl:musl)
            case "$abi" in
                glibc)
                    if test "$arch" = i686; then
                        paths='usr/lib/holy/i686-linux-gnu/libc.so.6 usr/lib/holy/i686-linux-gnu/ld-linux.so.2 usr/lib/ld-linux.so.2'
                    else
                        paths='usr/lib/holy/x86_64-linux-gnu/libc.so.6 usr/lib/holy/x86_64-linux-gnu/ld-linux-x86-64.so.2 usr/lib64/ld-linux-x86-64.so.2'
                    fi ;;
                musl)
                    if test "$arch" = i686; then
                        paths='usr/lib/holy/i686-linux-musl/ld-musl-i386.so.1 usr/lib/ld-musl-i386.so.1'
                    else
                        paths='usr/lib/holy/x86_64-linux-musl/ld-musl-x86_64.so.1 usr/lib/ld-musl-x86_64.so.1'
                    fi ;;
            esac
            for path in $paths; do
                rm "$root/$path"
                printf 'omitted-payload %s\n' "$path" >> "$record"
            done
            ;;
    esac
done
sha256sum "$project/tools/bootstrap-image.sh" "$project/profiles/dracut/module-setup.sh" >> "$record"
if test "$storage" = gpt-ext4; then
    truncate -s 1G "$out/disk.raw"
    printf '[disk]\nimage "%s"\nlayout gpt-ext4\n' "$out/disk.raw" > "$work/disk.conf"
    "$installer" disk plan --config "$work/disk.conf" --output "$out/disk.plan"
    cat "$out/disk.plan"
    sha256sum "$out/disk.plan" >> "$record"
fi
cp "$record" "$out/plan"
plan=$(sha256sum "$out/plan")
plan=${plan%% *}
printf '%s\n' "$plan" > "$root/etc/holy/boot-plan"
printf '%s\n' "$plan" > "$out/boot-plan"
root_disk=
root_cmdline=
if test "$storage" != ram; then
    root_disk="$out/root.ext4"
    if test "$storage" = gpt-ext4; then
        truncate -s 765M "$root_disk"
    else
        truncate -s 512M "$root_disk"
    fi
    mke2fs -q -t ext4 -F -d "$root" "$root_disk"
    chmod 0444 "$root_disk"
    sha256sum "$root_disk" >> "$record"
    root_cmdline='holy.root=/dev/vda holy.rootfstype=ext4'
    if test "$storage" = gpt-ext4; then root_cmdline='holy.root=/dev/vda3 holy.rootfstype=ext4 holy.esp=/dev/vda2'; fi
fi
mkdir -p "$work/dracut/modules.d/90holy" "$work/dracut/dracut.conf.d" "$work/empty-conf"
dracut_base=${DRACUT_BASE:-/usr/lib64/dracut}
for file in dracut-functions.sh dracut-logger.sh dracut-install dracut-util dracut-cpio; do
    test ! -e "$dracut_base/$file" || cp "$dracut_base/$file" "$work/dracut/"
done
cp "$project/profiles/dracut/module-setup.sh" "$work/dracut/modules.d/90holy/"
mkdir -p "$root/usr/lib/modules/$version" "$work/dracut-tmp"
HOLY_ROOT="$root" DRACUT_LDCONFIG='ldconfig -X' DRACUT_NO_MKNOD=1 DRACUT_TESTBIN=/usr/bin/busybox dracutbasedir="$work/dracut" dracut --conf /dev/null \
    --sysroot "$root" --tmpdir "$work/dracut-tmp" \
    --confdir "$work/empty-conf" --modules holy --no-kernel --no-hostonly \
    --no-hostonly-cmdline --no-early-microcode --nohardlink --nostrip --gzip \
    "$out/initramfs.img" "$version"
mkdir "$work/audit"
gzip -dc "$out/initramfs.img" > "$work/initramfs.cpio"
(cd "$work/audit" && cpio -id --no-absolute-filenames < "$work/initramfs.cpio")
python3 - "$root" "$work/audit" "$bin" "$profile" "$arch" > "$out/initramfs.audit" <<'PY'
import hashlib, os, pathlib, stat, subprocess, sys
root, unpacked = map(pathlib.Path, sys.argv[1:3])
dynamic = set()
if sys.argv[4] == 'dual-libc':
    if sys.argv[5] == 'i686':
        dynamic.update({'usr/lib/holy/i686-linux-gnu/libc.so.6',
                        'usr/lib/holy/i686-linux-gnu/ld-linux.so.2',
                        'usr/lib/holy/i686-linux-musl/ld-musl-i386.so.1'})
    else:
        dynamic.update({'usr/lib/holy/x86_64-linux-gnu/libc.so.6',
                        'usr/lib/holy/x86_64-linux-gnu/ld-linux-x86-64.so.2',
                        'usr/lib/holy/x86_64-linux-musl/ld-musl-x86_64.so.1'})
    dynamic.update({'usr/bin/holy-probe-glibc', 'usr/bin/holy-probe-musl'})
generated = {'etc/ld.so.cache', 'var/cache/ldconfig/aux-cache',
             'usr/lib/dracut/modules.txt', 'usr/lib/dracut/build-parameter.txt'}
def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1048576), b''):
            h.update(block)
    return h.digest()
for parent, dirs, files in os.walk(unpacked):
    for name in dirs + files:
        path = pathlib.Path(parent) / name
        relative = path.relative_to(unpacked)
        original = root / relative
        actual = path.lstat()
        mode = actual.st_mode
        if stat.S_ISDIR(mode):
            continue
        if relative.as_posix() in generated:
            if not stat.S_ISREG(mode):
                raise SystemExit('invalid generated file: ' + str(relative))
            continue
        before = original.lstat()
        if (mode, actual.st_uid, actual.st_gid) != (before.st_mode, before.st_uid, before.st_gid):
            raise SystemExit('changed mode or owner: ' + str(relative))
        if stat.S_ISLNK(mode):
            if os.readlink(path) != os.readlink(original):
                raise SystemExit('changed link: ' + str(relative))
        elif stat.S_ISREG(mode):
            if digest(path) != digest(original):
                raise SystemExit('changed content: ' + str(relative))
            with path.open('rb') as f:
                elf = f.read(4) == b'\x7fELF'
            if elf:
                facts = subprocess.check_output([sys.argv[3], 'elf', str(path)], text=True)
                if relative.as_posix() in dynamic:
                    print('dynamic-fixture-elf', relative)
                elif 'runtime nolibc' not in facts.splitlines():
                    raise SystemExit('non-static ELF: ' + str(relative))
                else:
                    print('static-elf', relative)
        else:
            raise SystemExit('unexpected object: ' + str(relative))
for parent, dirs, files in os.walk(root):
    for name in dirs + files:
        relative = (pathlib.Path(parent) / name).relative_to(root)
        if not os.path.lexists(unpacked / relative):
            raise SystemExit('missing path: ' + str(relative))
print('result pass')
PY
rm "$work/initramfs.cpio"
mkdir -p "$work/iso/boot/limine" "$work/iso/EFI/BOOT"
cp "$root/boot/vmlinuz" "$work/iso/boot/vmlinuz"
cp "$out/initramfs.img" "$work/iso/boot/initramfs.img"
cp "$root/usr/share/limine/"*.bin "$root/usr/share/limine/limine-bios.sys" "$work/iso/boot/limine/"
if test "$arch" = x86_64; then cp "$root/usr/share/limine/BOOTX64.EFI" "$work/iso/EFI/BOOT/"; fi
cat > "$work/iso/boot/limine/limine.conf" <<EOF
timeout: 0
serial: yes
verbose: yes
/Holy $profile test
    protocol: linux
    kernel_path: boot():/boot/vmlinuz
    module_path: boot():/boot/initramfs.img
    cmdline: console=ttyS0,115200 rdinit=/init holy.test=1 panic=1 $root_cmdline
EOF
boot_media=iso
iso_image="$out/holy-$arch.iso"
if test "$storage" = gpt-ext4; then
    boot_media=disk
    iso_image=
    "$installer" disk apply --plan "$out/disk.plan" --confirm "$out/disk.raw"
    test "$(tail -n 1 "$out/disk.plan.journal")" = committed
    sfdisk --json "$out/disk.raw" > "$out/disk-layout.json"
    python3 - "$out/disk-layout.json" <<'PY'
import json, sys
table = json.load(open(sys.argv[1]))['partitiontable']
assert table['label'] == 'gpt' and table['sectorsize'] == 512
assert [(p['start'], p['size']) for p in table['partitions']] == [
    (2048, 2048), (4096, 524288), (528384, 1566720)]
PY
    mkfs.fat -C -F 32 -s 4 -n HOLYBOOT "$work/esp.fat" 262144
    mmd -i "$work/esp.fat" ::/EFI ::/EFI/BOOT
    if test "$arch" = x86_64; then
        mcopy -i "$work/esp.fat" "$root/usr/share/limine/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
    fi
    mcopy -i "$work/esp.fat" "$root/usr/share/limine/limine-bios.sys" ::/limine-bios.sys
    mcopy -i "$work/esp.fat" "$root/boot/vmlinuz" ::/vmlinuz
    mcopy -i "$work/esp.fat" "$out/initramfs.img" ::/initramfs.img
    sed -e 's@boot():/boot/vmlinuz@boot():/vmlinuz@' \
        -e 's@boot():/boot/initramfs.img@boot():/initramfs.img@' \
        "$work/iso/boot/limine/limine.conf" > "$out/limine.conf"
    mcopy -i "$work/esp.fat" "$out/limine.conf" ::/limine.conf
    for file in vmlinuz initramfs.img limine.conf; do
        mcopy -i "$work/esp.fat" "::/$file" "$work/readback"
        case "$file" in vmlinuz) cmp "$root/boot/vmlinuz" "$work/readback" ;; *) cmp "$out/$file" "$work/readback" ;; esac
        rm "$work/readback"
    done
    "$installer" disk finalize-plan --disk-plan "$out/disk.plan" \
        --esp "$work/esp.fat" --root-image "$root_disk" \
        --output "$out/disk-finalize.plan"
    sha256sum "$out/disk-finalize.plan" >> "$record"
    "$installer" disk finalize-apply --plan "$out/disk-finalize.plan" \
        --confirm "$out/disk.raw"
    test "$(tail -n 1 "$out/disk-finalize.plan.journal")" = committed
    sfdisk --verify "$out/disk.raw"
    chmod 0444 "$out/disk.raw"
    root_disk="$out/disk.raw"
    sha256sum "$out/disk.raw" "$out/disk-layout.json" "$out/limine.conf" >> "$record"
else
    if test "$arch" = i686; then
        xorriso -as mkisofs -R -r -J -b boot/limine/limine-bios-cd.bin \
            -no-emul-boot -boot-load-size 4 -boot-info-table \
            "$work/iso" -o "$iso_image"
    else
        xorriso -as mkisofs -R -r -J -b boot/limine/limine-bios-cd.bin \
            -no-emul-boot -boot-load-size 4 -boot-info-table \
            --efi-boot boot/limine/limine-uefi-cd.bin -efi-boot-part --efi-boot-image \
            --protective-msdos-label "$work/iso" -o "$iso_image"
    fi
    if test "$arch" = x86_64; then
        limine bios-install "$iso_image"
    else
        printf 'bios-el-torito optical-only\n' >> "$record"
    fi
    sha256sum "$iso_image" >> "$record"
fi
sha256sum "$out/initramfs.img" "$root/boot/vmlinuz" >> "$record"
ARCH="$arch" BOOT_MEDIA="$boot_media" ISO="$iso_image" BOOT_PLAN="$plan" REPORT_DIR="$out/reports" \
    IMAGE_PROFILE="$profile" LIBC_BOOT_STATE="$boot_state" \
    NETWORK_RECOVERY="$network_recovery" NETWORK_DIR="$out/network" \
    ROOT_DISK="$root_disk" \
    KERNEL_IMAGE="$root/boot/vmlinuz" KERNEL_VERSION="$version" INITRAMFS="$out/initramfs.img" \
    sh "$project/tests/qemu.sh"
printf 'result boot-tested-%s\n' "$profile" >> "$record"
if test "$storage" = ram; then printf 'not-tested libc-recovery-reboot\n' >> "$record"; fi
if test "$network_recovery" = fixture; then
    printf 'not-tested installer-full-flow public-network-dns graphics\n' >> "$record"
else
    printf 'not-tested installer-full-flow network graphics\n' >> "$record"
fi
