#!/bin/sh
set -eu
test "$#" -ge 10 || {
    echo 'usage: bootstrap-image.sh HOLYPKG STATIC_HOLYPKG STATIC_CC BUSYBOX DINIT MDEVD KERNEL KERNEL_VERSION LIMINE_DIR OUTPUT [--local PACKAGE.holy | --source ALIAS PACKAGE ...]' >&2
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
core_input() {
    case "$1" in
        /*|./*|../*) realpath "$1" ;;
        *:*) printf '%s\n' "$1" ;;
        *) realpath "$1" ;;
    esac
}
busybox=$(core_input "$4")
dinit=$(core_input "$5")
mdevd=$(core_input "$6")
kernel=$(core_input "$7")
version=$8
limine_dir=$(realpath "$9")
shift 9
image_output=$1
shift
case "$version" in ''|*[!a-zA-Z0-9._+-]*) exit 2 ;; esac
test "$(uname -m)" = x86_64 || exit 6
arch=${ARCH:-x86_64}
case "$arch" in
    x86_64) qemu=qemu-system-x86_64; package_arch=x86_64 ;;
    i686) qemu=qemu-system-i386; package_arch=x86 ;;
    *) echo 'ARCH must be i686 or x86_64' >&2; exit 2 ;;
esac
boot_test=${IMAGE_BOOT_TEST:-required}
case "$boot_test" in required|build-only) ;; *) echo 'IMAGE_BOOT_TEST must be required or build-only' >&2; exit 2 ;; esac
if test "$boot_test" = required && ! command -v "$qemu" >/dev/null; then
    boot_test=build-only
    echo "$qemu unavailable; image will remain untested" >&2
fi
for tool in dracut ldconfig limine sha256sum cpio gzip python3; do
    command -v "$tool" >/dev/null || { echo "$tool required" >&2; exit 6; }
done
validate_kernel() {
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
}
project=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
profile=${IMAGE_PROFILE:-dual-libc}
boot_state=${LIBC_BOOT_STATE:-present}
storage=${ROOT_STORAGE:-ram}
network_recovery=${NETWORK_RECOVERY:-off}
install_test=${INSTALL_TEST:-0}
if test "$arch" = i686; then
    install_firmware=${INSTALL_FIRMWARE:-bios}
else
    install_firmware=${INSTALL_FIRMWARE:-both}
fi
case "$install_test:$storage:$profile:$boot_state:$arch" in
    0:*) ;;
    1:ram:static-core:present:x86_64|1:ram:static-core:present:i686) ;;
    *) echo 'INSTALL_TEST=1 requires static-core RAM ISO' >&2; exit 2 ;;
esac
if test "$install_test" = 1; then
    case "$arch:$install_firmware" in
        x86_64:bios|x86_64:both|i686:bios) ;;
        *) echo 'INSTALL_FIRMWARE requires BIOS for i686, BIOS or both for x86_64' >&2; exit 2 ;;
    esac
    doas_package=$(realpath "${DOAS_PACKAGE:?DOAS_PACKAGE required}")
    test -f "$doas_package" || exit 6
fi
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
install_doas=
case "$profile:$boot_state" in
    static-core:present) ;;
    dual-libc:present|dual-libc:glibc|dual-libc:musl|dual-libc:both|dual-libc:remove-both)
        glibc=$(core_input "${GLIBC_PACKAGE:?GLIBC_PACKAGE required}")
        musl=$(core_input "${MUSL_PACKAGE:?MUSL_PACKAGE required}")
        glibc_cc=$(command -v "${GLIBC_CC:-gcc}")
        musl_cc=$(realpath "${MUSL_CC:?MUSL_CC required}")
        test -x "$musl_cc" || exit 6
        command -v patchelf >/dev/null || exit 6
        extra_packages='glibc musl probe-glibc probe-musl'
        ;;
    *) echo 'unsupported image profile or libc boot state' >&2; exit 2 ;;
esac
mkdir -p "$(dirname "$image_output")"
mkdir -m 0700 "$image_output"
out=$(realpath "$image_output")
work="$out/work"
root="$out/root"
mkdir "$work" "$root" "$out/packages" "$out/inputs" "$out/reports"
started=$(date +%s)
record="$out/build.record"
printf 'format holy-bootstrap-image-1\narch %s\nprofile %s\nlibc-boot-state %s\nkernel-version %s\n' "$arch" "$profile" "$boot_state" "$version" > "$record"
printf 'root-storage %s\n' "$storage" >> "$record"
printf 'boot-test %s\n' "$boot_test" >> "$record"
if test -n "${HOLY_IMAGE_CONFIG_SHA256:-}"; then
    case "$HOLY_IMAGE_CONFIG_SHA256" in *[!0-9a-f]*|'') exit 2 ;; esac
    test "${#HOLY_IMAGE_CONFIG_SHA256}" -eq 64 || exit 2
    printf 'image-config-sha256 %s\n' "$HOLY_IMAGE_CONFIG_SHA256" >> "$record"
    test -n "${HOLY_IMAGE_CONFIG_FILE:-}" || exit 6
    cp "$HOLY_IMAGE_CONFIG_FILE" "$out/inputs/image.conf"
    config_copy_hash=$(sha256sum "$out/inputs/image.conf")
    test "${config_copy_hash%% *}" = "$HOLY_IMAGE_CONFIG_SHA256" || {
        echo 'image config changed after validation' >&2
        exit 3
    }
fi
if test -n "${HOLY_IMAGE_ANSWERS:-}"; then
    expected_answers=${HOLY_IMAGE_ANSWERS_SHA256:-}
    case "$expected_answers" in *[!0-9a-f]*|'') exit 2 ;; esac
    test "${#expected_answers}" -eq 64 || exit 2
    cp "$HOLY_IMAGE_ANSWERS" "$out/inputs/resolver-answers"
    answers_hash=$(sha256sum "$out/inputs/resolver-answers")
    test "${answers_hash%% *}" = "$expected_answers" || {
        echo 'resolver answers changed after validation' >&2
        exit 3
    }
    printf 'resolver-answers-sha256 %s\n' "$expected_answers" >> "$record"
fi
printf 'network-recovery %s\n' "$network_recovery" >> "$record"
printf 'install-test %s\n' "$install_test" >> "$record"
if test "$install_test" = 1; then printf 'install-firmware %s\n' "$install_firmware" >> "$record"; fi
finish() {
    rc=$?
    trap - EXIT
    printf 'exit %s\nelapsed-seconds %s\n' "$rc" "$(($(date +%s) - started))" >> "$record"
    if test "$rc" -ne 0 && test "${image_untested:-0}" != 1; then
        printf 'result incomplete\n' >> "$record"
    fi
    exit "$rc"
}
trap finish EXIT
trap 'exit 1' HUP INT TERM
exec > "$out/build.log" 2>&1
(
    set -- "$bin" "$installer" "$cc" dracut ldconfig limine sha256sum cpio gzip python3 unshare
    if test "$profile" = dual-libc; then set -- "$@" "$glibc_cc" "$musl_cc" patchelf; fi
    if test "$storage" != ram; then set -- "$@" mke2fs qemu-img; fi
    if test "$storage" = gpt-ext4; then set -- "$@" sfdisk mkfs.fat mcopy mmd; else set -- "$@" xorriso; fi
    if test "$network_recovery" = fixture; then set -- "$@" openssl; fi
    if test "$boot_test" = required; then set -- "$@" "$qemu"; fi
    python3 "$project/tools/image-host-tools.py" "$out/host-tools.jsonl" "$@"
)
host_tools_hash=$(sha256sum "$out/host-tools.jsonl")
printf 'host-tools-sha256 %s\n' "${host_tools_hash%% *}" >> "$record"
"$bin" db init --root "$root"
if test -n "${HOLY_IMAGE_SOURCE_DIR:-}"; then
    sh "$project/tools/image-source-stage.sh" "$bin" "$root" "$out" "$HOLY_IMAGE_SOURCE_DIR"
fi
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
sh "$project/tools/image-package-stage.sh" "$bin" "$out" "$arch" "$@"
module_probe=off
if test -f "$work/core-kernel.holy"; then
    cp "$work/core-kernel.holy" "$out/inputs/kernel.holy"
    "$bin" info "local:$out/inputs/kernel.holy" > "$work/kernel-info"
    grep -qx 'name linux' "$work/kernel-info" &&
        grep -qx "version $version" "$work/kernel-info" &&
        grep -qx "arch $package_arch" "$work/kernel-info" &&
        grep -qx 'libc nolibc' "$work/kernel-info" || {
            echo 'source kernel package does not match image target/version' >&2
            exit 4
        }
    "$bin" fetch "local:$out/inputs/kernel.holy" --extract \
        --output "$work/kernel-package" > "$work/kernel-extract.record"
    kernel=$(realpath "$work/kernel-package/DATA/boot/vmlinuz")
    case "$kernel" in "$work/kernel-package/DATA/"*) ;; *) exit 4 ;; esac
    module="$work/kernel-package/DATA/usr/lib/modules/$version/kernel/drivers/net/dummy.ko"
    if test -f "$module"; then
        test ! -L "$module" &&
            grep -qx 'kernel/drivers/net/dummy.ko:' \
                "$work/kernel-package/DATA/usr/lib/modules/$version/modules.dep" || exit 4
        module_probe=on
        module_digest=$(sha256sum "$module")
        module_digest=${module_digest%% *}
        "$cc" -std=c99 -Wall -Wextra -Werror -pedantic -Os -static -fno-pie -no-pie \
            "$project/tests/module-probe.c" -o "$work/holy-module-probe"
        "$bin" elf "$work/holy-module-probe" > "$work/module-probe.elf"
        grep -qx 'runtime nolibc' "$work/module-probe.elf"
        grep -qx "machine $package_arch" "$work/module-probe.elf"
        printf 'kernel-module dummy %s\n' "$module_digest" >> "$record"
    fi
fi
test -f "$kernel" || exit 6
validate_kernel
for role in busybox dinit mdevd glibc musl; do
    if test -f "$work/core-$role.holy"; then
        case "$role" in
            busybox) busybox="$work/core-$role.holy" ;;
            dinit) dinit="$work/core-$role.holy" ;;
            mdevd) mdevd="$work/core-$role.holy" ;;
            glibc) glibc="$work/core-$role.holy" ;;
            musl) musl="$work/core-$role.holy" ;;
        esac
    fi
done
test -f "$busybox" && test -f "$dinit" && test -f "$mdevd" || exit 6
if test "$profile" = dual-libc; then
    test -f "$glibc" && test -f "$musl" || exit 6
fi
additional_packages=$(cat "$work/additional-packages")
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
    if test "$name" = busybox && test "$install_test" = 1; then
        for applet in chown login getty su passwd adduser addgroup; do
            "$tree/DATA/usr/bin/busybox" --list | grep -qx "$applet" || {
                echo "BusyBox applet $applet required for install test" >&2
                exit 6
            }
        done
    fi
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
if test "$install_test" = 1; then
    "$bin" info "local:$doas_package" > "$work/doas-info"
    grep -qx 'name doas' "$work/doas-info"
    grep -qx "arch $package_arch" "$work/doas-info"
    grep -qx 'libc nolibc' "$work/doas-info"
    cp "$doas_package" "$out/packages/doas.holy"
    doas_digest=$(sha256sum "$out/packages/doas.holy")
    doas_digest=${doas_digest%% *}
    printf 'guest-package doas %s\n' "$doas_digest" >> "$record"
    install_doas=doas
fi
cp "$kernel" "$out/inputs/kernel"
if test -f "$work/core-kernel.holy"; then
    cp "$work/core-kernel.holy" "$out/packages/linux.holy"
else
    metadata linux "$version" "$package_arch"
    mkdir -p "$tree/DATA/boot"
    cp "$out/inputs/kernel" "$tree/DATA/boot/vmlinuz"
    chmod 0644 "$tree/DATA/boot/vmlinuz"
    sha256sum "$out/inputs/kernel" > "$tree/HOLY/origin"
    pack linux
fi
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
if test "$module_probe" = on; then
    cp "$work/holy-module-probe" "$tree/DATA/usr/bin/holy-module-probe"
    printf '%s\n' "$module_digest" > "$tree/DATA/etc/holy/dummy-module.sha256"
    sha256sum "$project/tests/module-probe.c" "$work/holy-module-probe" \
        >> "$tree/HOLY/origin"
fi
cp "$project/profiles/dinit/"* "$tree/DATA/etc/dinit.d/"
cp "$project/tests/boot-probe.sh" "$tree/DATA/usr/lib/holy/boot-probe.sh"
cp "$project/tests/install-probe.sh" "$tree/DATA/usr/lib/holy/install-probe.sh"
cp "$project/tools/install-source-stage.sh" \
    "$tree/DATA/usr/lib/holy/install-source-stage.sh"
chmod 0644 "$tree/DATA/usr/lib/holy/boot-probe.sh"
chmod 0644 "$tree/DATA/usr/lib/holy/install-probe.sh"
chmod 0644 "$tree/DATA/usr/lib/holy/install-source-stage.sh"
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
        source_id=$(awk -v label="$name" '$1 == label {print $2}' "$work/add-sources")
        if test -n "$source_id"; then
            printf '%s\n' "$source_id" > "$tree/DATA/etc/holy/$name.source-id"
        fi
    done
fi
printf 'root:x:0:0:root:/root:/bin/sh\n' > "$tree/DATA/etc/passwd"
printf 'root:x:0:\n' > "$tree/DATA/etc/group"
printf 'root:!:0:0:99999:7:::\n' > "$tree/DATA/etc/shadow"
chmod 0600 "$tree/DATA/etc/shadow"
if test "$install_test" = 1; then
    printf 'holytest:x:10001:10001:Holy fixture account:/home/holytest:/usr/bin/sh\n' >> "$tree/DATA/etc/passwd"
    printf 'holytest:x:10001:\n' >> "$tree/DATA/etc/group"
    cat >> "$tree/DATA/etc/shadow" <<'EOF'
holytest:$6$holyfixture$dWRvmlTx76Ezgh55faR0FP7brdbDJrBSlGfNEW5bbcQDRvj4uwCOeDgUSHkXHQEedvoyZH55dtVIl9Aie1eMh.:0:0:99999:7:::
EOF
    printf 'permit holytest as root cmd /usr/bin/busybox args id -u\n' > "$tree/DATA/etc/doas.conf"
    chmod 0400 "$tree/DATA/etc/doas.conf"
    printf '%s\n' "$doas_digest" > "$tree/DATA/etc/holy/doas.sha256"
    "$cc" -O2 -std=c99 -Wall -Wextra -Werror -pedantic -static \
        "$project/tests/login-probe.c" -o "$tree/DATA/usr/lib/holy/login-probe"
    "$bin" elf "$tree/DATA/usr/lib/holy/login-probe" > "$out/login-probe.elf"
    grep -qx 'runtime nolibc' "$out/login-probe.elf"
    sha256sum "$project/tests/login-probe.c" "$tree/DATA/usr/lib/holy/login-probe" \
        >> "$tree/HOLY/origin"
fi
printf 'null 0:0 0600\n.* 0:0 0600\n' > "$tree/DATA/etc/mdev.conf"
for name in bin sbin; do ln -s usr/bin "$tree/DATA/$name"; done
for name in lib lib32 lib64; do ln -s "usr/$name" "$tree/DATA/$name"; done
ln -s bin "$tree/DATA/usr/sbin"
ln -s dinit "$tree/DATA/usr/bin/init"
ln -s busybox "$tree/DATA/usr/bin/sh"
ln -s usr/bin/holy-init "$tree/DATA/init"
sha256sum "$project/src/early-init.c" "$project/tests/boot-probe.sh" \
    "$project/tests/install-probe.sh" \
    "$project/tools/install-source-stage.sh" \
    "$project/profiles/dinit/"* > "$tree/HOLY/origin"
pack holy-boot
metadata holy-base bootstrap noarch
: > "$work/package-names"
for name in busybox dinit mdevd holypkg holyinstall linux limine holy-boot $extra_packages $install_doas $additional_packages; do
    "$bin" info "local:$out/packages/$name.holy" > "$work/package-info"
    actual_name=$(sed -n 's/^name //p' "$work/package-info")
    case "$actual_name" in ''|*[!a-zA-Z0-9._+-]*) echo 'unsupported bootstrap package name' >&2; exit 6 ;; esac
    if grep -Fxq -e "$actual_name" "$work/package-names"; then
        echo "duplicate image package name $actual_name" >&2
        exit 4
    fi
    printf '%s\n' "$actual_name" >> "$work/package-names"
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
for name in holy-base busybox dinit mdevd holypkg holyinstall linux limine holy-boot $extra_packages $install_doas $additional_packages; do
    package="$out/packages/$name.holy"
    digest=$(sha256sum "$package")
    digest=${digest%% *}
    printf 'package %s %s\n' "$name" "$digest" >> "$record"
    "$bin" cache stage "local:$package" --root "$root"
    printf 'artifact %s\n' "$digest" >> "$work/install.conf"
    if test -f "$work/add-sources"; then
        source_id=$(awk -v label="$name" '$1 == label {print $2}' "$work/add-sources")
        if test -n "$source_id"; then
            printf 'source %s %s\n' "$digest" "$source_id" >> "$work/install.conf"
        fi
    fi
    if test "$arch" = i686; then
        "$bin" info "local:$package" > "$work/package-info"
        if grep -qx 'arch x86' "$work/package-info"; then accepted_arch="$accepted_arch $digest"; fi
    fi
done
if test "$install_test" = 1; then
    printf 'accept-privileged %s\n' "$doas_digest" >> "$work/install.conf"
fi
for digest in $accepted_arch; do
    printf 'architecture-placement host x86_64 target x86 artifact %s accepted-unverified\n' "$digest" >> "$record"
    printf 'accept-arch %s\n' "$digest" >> "$work/install.conf"
done
"$installer" --config "$work/install.conf" --plan "$out/install.plan" --holypkg "$bin" > "$out/install.preview"
cat "$out/install.preview"
plan=$(sed -n 's/^set-sha256 \([0-9a-f]*\)$/\1/p' "$out/install.plan")
test "${#plan}" -eq 64
printf 'install-plan %s\n' "$plan" >> "$record"
install_plan_file=$(sha256sum "$out/install.plan")
printf 'install-plan-file-sha256 %s\n' "${install_plan_file%% *}" >> "$record"
"$installer" --apply "$out/install.plan" --holypkg "$bin" > "$out/install.apply"
test "$(cat "$root/var/lib/holypkg/generation")" -eq 1
"$bin" db check --all --root "$root" > "$out/root-check.record"
if test "$install_test" = 1; then
    storage_tools=$(realpath "${STORAGE_TOOLS_PACKAGE:?STORAGE_TOOLS_PACKAGE required}")
    "$bin" info "local:$storage_tools" > "$work/storage-info"
    grep -qx 'name holy-storage-tools' "$work/storage-info"
    grep -qx "arch $package_arch" "$work/storage-info"
    grep -qx 'libc nolibc' "$work/storage-info"
    cp "$storage_tools" "$out/inputs/holy-storage-tools.holy"
    storage_parent=$(sha256sum "$out/inputs/holy-storage-tools.holy")
    storage_parent=${storage_parent%% *}
    "$bin" fetch "local:$out/inputs/holy-storage-tools.holy" --extract --output "$tree"
    find "$tree/DATA" -type d -exec chmod 0755 '{}' +
    printf '\nbootstrap-parent-sha256 %s\nbootstrap-ownership 0 0\nbootstrap-directory-mode 0755\n' \
        "$storage_parent" >> "$tree/HOLY/origin"
    pack holy-storage-tools
    mkdir -p "$root/usr/share/man/man1" "$root/usr/share/licenses/holy-storage-tools"
    storage_digest=$(sha256sum "$out/packages/holy-storage-tools.holy")
    storage_digest=${storage_digest%% *}
    printf 'live-only-package holy-storage-tools %s parent %s\n' \
        "$storage_digest" "$storage_parent" >> "$record"
    "$bin" cache stage "local:$out/packages/holy-storage-tools.holy" --root "$root"
    printf '[install]\nroot "%s"\nartifact %s\n' "$root" "$storage_digest" > "$work/storage.conf"
    if test "$arch" = i686; then
        printf 'accept-arch %s\n' "$storage_digest" >> "$work/storage.conf"
    fi
    "$installer" --config "$work/storage.conf" --plan "$out/storage.plan" \
        --holypkg "$bin" > "$out/storage.preview"
    "$installer" --apply "$out/storage.plan" --holypkg "$bin" > "$out/storage.apply"
    "$bin" db check --all --root "$root" > "$out/root-check.record"
fi
"$bin" docs --root "$root" --output "$root/usr/share/holy/llm.txt"
chmod 0644 "$root/usr/share/holy/llm.txt"
cp "$root/usr/share/holy/llm.txt" "$out/llm.txt"
docs_hash=$(sha256sum "$out/llm.txt")
printf '%s\n' "${docs_hash%% *}" > "$root/etc/holy/docs.sha256"
printf 'documentation-sha256 %s\n' "${docs_hash%% *}" >> "$record"
tail -n 1 "$out/llm.txt" > "$out/docs.record"
if test "$install_test" = 1; then
    sed -n 's/^artifact //p' "$work/install.conf" > "$root/usr/share/holy/install-artifacts"
    sed -n 's/^source /source /p' "$work/install.conf" \
        > "$root/usr/share/holy/install-source-bindings"
    if test -f "$out/inputs/sources.conf"; then
        cp "$out/inputs/sources.conf" "$root/usr/share/holy/install-sources.conf"
        cp "$out/inputs/source-aliases" "$root/usr/share/holy/install-source-aliases"
        sha256sum "$root/usr/share/holy/install-sources.conf" \
            "$root/usr/share/holy/install-source-aliases" >> "$record"
    else
        test ! -s "$root/usr/share/holy/install-source-bindings" || exit 6
    fi
    python3 - "$root" "$root/usr/share/holy/install-directories" <<'PY'
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
with open(sys.argv[2], 'w', encoding='utf-8') as output:
    for parent, dirs, files in os.walk(root):
        for name in sorted(dirs):
            path = pathlib.Path(parent) / name
            if path.is_symlink():
                continue
            relative = path.relative_to(root)
            if relative.parts[:3] in (('var', 'lib', 'holypkg'),
                                       ('var', 'cache', 'holypkg')):
                continue
            if any(char.isspace() for char in str(relative)):
                raise SystemExit('unsupported installation directory name')
            mode = stat.S_IMODE(path.stat().st_mode)
            output.write(f'{mode:04o} {relative}\n')
PY
    sha256sum "$root/usr/share/holy/install-artifacts" \
        "$root/usr/share/holy/install-directories" \
        "$root/usr/share/holy/install-source-bindings" >> "$record"
fi
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
(
    cd "$out"
    set -- inputs packages
    if test -d mirrors; then set -- "$@" mirrors; fi
    find "$@" -type f -print0 | sort -z | xargs -0 sha256sum > input-lock.sha256
)
input_lock=$(sha256sum "$out/input-lock.sha256")
printf 'input-lock-sha256 %s\n' "${input_lock%% *}" >> "$record"
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
python3 - "$root" "$work/audit" "$bin" "$profile" "$arch" "$version" > "$out/initramfs.audit" <<'PY'
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
                module = (len(relative.parts) >= 5 and
                          relative.parts[:3] == ('usr', 'lib', 'modules') and
                          relative.parts[3] == sys.argv[6] and relative.suffix == '.ko')
                if module:
                    machine = 'x86' if sys.argv[5] == 'i686' else 'x86_64'
                    if 'e_type 1' not in facts.splitlines() or \
                            'machine ' + machine not in facts.splitlines():
                        raise SystemExit('invalid kernel module: ' + str(relative))
                    print('kernel-module-elf', relative)
                elif relative.as_posix() in dynamic:
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
boot_service=holy.test=1
if test "$install_test" = 1; then boot_service=holy.install-test=1; fi
cat > "$work/iso/boot/limine/limine.conf" <<EOF
timeout: 0
serial: yes
verbose: yes
/Holy $profile test
    protocol: linux
    kernel_path: boot():/boot/vmlinuz
    module_path: boot():/boot/initramfs.img
    cmdline: console=ttyS0,115200 rdinit=/init $boot_service panic=1 $root_cmdline
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
if test "$boot_test" = build-only; then
    printf 'result untested\nnot-tested qemu-boot-contract\n' >> "$record"
    image_untested=1
    exit 6
fi
if test "$install_test" = 1; then
    ARCH="$arch" ISO="$iso_image" BOOT_PLAN="$plan" REPORT_DIR="$out/reports" \
        STATIC_HOLYINSTALL="$installer" INSTALL_FIRMWARE="$install_firmware" \
        python3 "$project/tests/install-vm.py"
else
    ARCH="$arch" BOOT_MEDIA="$boot_media" ISO="$iso_image" BOOT_PLAN="$plan" REPORT_DIR="$out/reports" \
        IMAGE_PROFILE="$profile" LIBC_BOOT_STATE="$boot_state" \
        NETWORK_RECOVERY="$network_recovery" NETWORK_DIR="$out/network" \
        ROOT_DISK="$root_disk" \
        KERNEL_IMAGE="$root/boot/vmlinuz" KERNEL_VERSION="$version" INITRAMFS="$out/initramfs.img" \
        KERNEL_MODULE_PROBE="$module_probe" \
        sh "$project/tests/qemu.sh"
fi
printf 'result boot-tested-%s\n' "$profile" >> "$record"
if test "$storage" = ram; then printf 'not-tested libc-recovery-reboot\n' >> "$record"; fi
if test "$install_test" = 1; then
    printf 'not-tested installer-interactive-menu pam-nss network graphics\n' >> "$record"
elif test "$network_recovery" = fixture; then
    printf 'not-tested installer-full-flow public-network-dns graphics\n' >> "$record"
else
    printf 'not-tested installer-full-flow network graphics\n' >> "$record"
fi
if test "$module_probe" = off; then printf 'not-tested kernel-module-load\n' >> "$record"; fi
