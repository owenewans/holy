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
for tool in dracut ldconfig limine sha256sum cpio gzip python3 qemu-system-x86_64; do
    command -v "$tool" >/dev/null || { echo "$tool required" >&2; exit 6; }
done
project=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
profile=${IMAGE_PROFILE:-dual-libc}
boot_state=${LIBC_BOOT_STATE:-present}
storage=${ROOT_STORAGE:-ram}
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
    dual-libc:present|dual-libc:glibc|dual-libc:musl|dual-libc:both)
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
printf 'format holy-bootstrap-image-1\narch x86_64\nprofile %s\nlibc-boot-state %s\nkernel-version %s\n' "$profile" "$boot_state" "$version" > "$record"
printf 'root-storage %s\n' "$storage" >> "$record"
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
grep -qx 'machine x86_64' "$out/core.elf"
"$cc" --version > "$out/compiler.record"
"$cc" -std=c99 -Wall -Wextra -Werror -pedantic -Os -static -fno-pie -no-pie \
    "$project/src/early-init.c" -o "$work/holy-init"
"$bin" elf "$work/holy-init" > "$out/init.elf"
grep -qx 'runtime nolibc' "$out/init.elf"
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
            glibc) compiler=$glibc_cc; loader=/usr/lib/holy/x86_64-linux-gnu/ld-linux-x86-64.so.2; needed=libc.so.6; provider=/usr/lib/holy/x86_64-linux-gnu/libc.so.6 ;;
            musl) compiler=$musl_cc; loader=/usr/lib/holy/x86_64-linux-musl/ld-musl-x86_64.so.1; needed=libc.so; provider=$loader ;;
        esac
        metadata "probe-$abi" 1 x86_64
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
metadata holypkg bootstrap x86_64
mkdir -p "$tree/DATA/usr/bin" "$tree/DATA/usr/share/man/man5" \
    "$tree/DATA/usr/share/man/man7" "$tree/DATA/usr/share/man/man8" "$tree/DATA/usr/share/holy"
cp "$static" "$out/inputs/holypkg"
cp "$out/inputs/holypkg" "$tree/DATA/usr/bin/holypkg"
for section in 5 7 8; do cp "$project/man/"*."$section" "$tree/DATA/usr/share/man/man$section/"; done
cp "$project/llm.txt" "$tree/DATA/usr/share/holy/llm.txt"
sha256sum "$out/inputs/holypkg" >> "$tree/HOLY/origin"
pack holypkg
metadata linux "$version" x86_64
mkdir -p "$tree/DATA/boot"
cp "$kernel" "$out/inputs/kernel"
cp "$out/inputs/kernel" "$tree/DATA/boot/vmlinuz"
chmod 0644 "$tree/DATA/boot/vmlinuz"
sha256sum "$out/inputs/kernel" > "$tree/HOLY/origin"
pack linux
metadata limine bootstrap x86_64
mkdir -p "$tree/DATA/usr/share/limine"
for file in limine-bios.sys limine-bios-cd.bin limine-uefi-cd.bin BOOTX64.EFI; do
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
metadata holy-boot bootstrap x86_64
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
printf '%s\n' "$boot_state" > "$tree/DATA/etc/holy/libc-boot-state"
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
for name in busybox dinit mdevd holypkg linux limine holy-boot $extra_packages; do
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
    mkdir -p "$root/usr/lib/holy/x86_64-linux-gnu" "$root/usr/lib/holy/x86_64-linux-musl" \
        "$root/usr/share/licenses/glibc" "$root/usr/share/doc/glibc" "$root/usr/share/doc/musl"
fi
"$bin" db init --root "$root"
set --
for name in holy-base busybox dinit mdevd holypkg linux limine holy-boot $extra_packages; do
    package="$out/packages/$name.holy"
    digest=$(sha256sum "$package")
    digest=${digest%% *}
    printf 'package %s %s\n' "$name" "$digest" >> "$record"
    "$bin" cache stage "local:$package" --root "$root"
    set -- "$@" "$digest"
done
"$bin" db plan-set "$@" --root "$root" > "$out/install.plan"
cat "$out/install.plan"
plan=$(sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$out/install.plan")
test "${#plan}" -eq 64
printf 'install-plan %s\n' "$plan" >> "$record"
"$bin" db apply-set "$plan" "$@" --root "$root"
test "$(cat "$root/var/lib/holypkg/generation")" -eq 1
"$bin" db check --all --root "$root" > "$out/root-check.record"
for abi in glibc musl; do
    case "$boot_state:$abi" in
        both:*|glibc:glibc|musl:musl)
            case "$abi" in
                glibc) paths='usr/lib/holy/x86_64-linux-gnu/libc.so.6 usr/lib/holy/x86_64-linux-gnu/ld-linux-x86-64.so.2 usr/lib64/ld-linux-x86-64.so.2' ;;
                musl) paths='usr/lib/holy/x86_64-linux-musl/ld-musl-x86_64.so.1 usr/lib/ld-musl-x86_64.so.1' ;;
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
    cat > "$out/disk.plan" <<'EOF'
label: gpt
unit: sectors
sector-size: 512

start=2048, size=2048, type=21686148-6449-6E6F-744E-656564454649, name="holy-bios"
start=4096, size=262144, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="holy-esp"
start=266240, size=1048576, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="holy-root"
EOF
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
    truncate -s 512M "$root_disk"
    mke2fs -q -t ext4 -F -d "$root" "$root_disk"
    chmod 0444 "$root_disk"
    sha256sum "$root_disk" >> "$record"
    root_cmdline='holy.root=/dev/vda holy.rootfstype=ext4'
    if test "$storage" = gpt-ext4; then root_cmdline='holy.root=/dev/vda3 holy.rootfstype=ext4'; fi
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
python3 - "$root" "$work/audit" "$bin" "$profile" > "$out/initramfs.audit" <<'PY'
import hashlib, os, pathlib, stat, subprocess, sys
root, unpacked = map(pathlib.Path, sys.argv[1:3])
dynamic = {'usr/lib/holy/x86_64-linux-gnu/libc.so.6',
           'usr/lib/holy/x86_64-linux-gnu/ld-linux-x86-64.so.2',
           'usr/lib/holy/x86_64-linux-musl/ld-musl-x86_64.so.1',
           'usr/bin/holy-probe-glibc', 'usr/bin/holy-probe-musl'} if sys.argv[4] == 'dual-libc' else set()
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
cp "$root/usr/share/limine/BOOTX64.EFI" "$work/iso/EFI/BOOT/"
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
iso_image="$out/holy-x86_64.iso"
if test "$storage" = gpt-ext4; then
    boot_media=disk
    iso_image=
    truncate -s 768M "$out/disk.raw"
    sfdisk --no-reread --no-tell-kernel "$out/disk.raw" < "$out/disk.plan"
    sfdisk --json "$out/disk.raw" > "$out/disk-layout.json"
    python3 - "$out/disk-layout.json" <<'PY'
import json, sys
table = json.load(open(sys.argv[1]))['partitiontable']
assert table['label'] == 'gpt' and table['sectorsize'] == 512
assert [(p['start'], p['size'], p['name']) for p in table['partitions']] == [
    (2048, 2048, 'holy-bios'), (4096, 262144, 'holy-esp'), (266240, 1048576, 'holy-root')]
PY
    mkfs.fat -C -F 32 -n HOLYBOOT "$work/esp.fat" 131072
    mmd -i "$work/esp.fat" ::/EFI ::/EFI/BOOT
    mcopy -i "$work/esp.fat" "$root/usr/share/limine/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
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
    dd if="$work/esp.fat" of="$out/disk.raw" bs=1M seek=2 conv=notrunc status=none
    dd if="$root_disk" of="$out/disk.raw" bs=1M seek=130 conv=notrunc status=none
    limine bios-install "$out/disk.raw" 1
    sfdisk --verify "$out/disk.raw"
    chmod 0444 "$out/disk.raw"
    root_disk="$out/disk.raw"
    sha256sum "$out/disk.raw" "$out/disk-layout.json" "$out/limine.conf" >> "$record"
else
    xorriso -as mkisofs -R -r -J -b boot/limine/limine-bios-cd.bin \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    --efi-boot boot/limine/limine-uefi-cd.bin -efi-boot-part --efi-boot-image \
    --protective-msdos-label "$work/iso" -o "$iso_image"
    limine bios-install "$iso_image"
    sha256sum "$iso_image" >> "$record"
fi
sha256sum "$out/initramfs.img" "$root/boot/vmlinuz" >> "$record"
ARCH=x86_64 BOOT_MEDIA="$boot_media" ISO="$iso_image" BOOT_PLAN="$plan" REPORT_DIR="$out/reports" \
    IMAGE_PROFILE="$profile" LIBC_BOOT_STATE="$boot_state" \
    ROOT_DISK="$root_disk" \
    KERNEL_IMAGE="$root/boot/vmlinuz" KERNEL_VERSION="$version" INITRAMFS="$out/initramfs.img" \
    sh "$project/tests/qemu.sh"
printf 'result boot-tested-%s\n' "$profile" >> "$record"
if test "$storage" = ram; then printf 'not-tested libc-recovery-reboot\n' >> "$record"; fi
printf 'not-tested i686 installer network graphics\n' >> "$record"
