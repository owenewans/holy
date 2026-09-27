#!/bin/sh
set -eu
bb=/usr/bin/busybox
pkg=/usr/bin/holypkg
installer=/usr/bin/holyinstall
stage=devices
trap 'echo "HOLY-INSTALL-1 failed $stage"; echo "HOLY-INSTALL-1 result fail"' EXIT

for device in /dev/vda2 /dev/vda3 /dev/sr0; do
    test -b "$device"
done
echo 'HOLY-INSTALL-1 devices target-and-media'

stage=mount
$bb mkdir -p /mnt/holy /mnt/media
$bb mount -t ext4 /dev/vda3 /mnt/holy
$bb mount -t iso9660 -o ro /dev/sr0 /mnt/media
test -s /mnt/media/boot/initramfs.img
echo 'HOLY-INSTALL-1 root mounted'

stage=scaffold
while read -r mode path; do
    test -n "$path"
    $bb mkdir -p "/mnt/holy/$path"
    $bb chmod "$mode" "/mnt/holy/$path"
done < /usr/share/holy/install-directories
$pkg db init --root /mnt/holy > /run/install-db
echo 'HOLY-INSTALL-1 scaffold ready'

stage=packages
printf '[install]\nroot "/mnt/holy"\n' > /run/install.conf
while read -r digest; do
    test "${#digest}" -eq 64
    archive="/var/cache/holypkg/objects/sha256/$digest.holy"
    test -f "$archive"
    $pkg cache stage "local:$archive" --root /mnt/holy > /run/install-cache
    printf 'artifact %s\n' "$digest" >> /run/install.conf
    echo "HOLY-INSTALL-1 staged $digest"
done < /usr/share/holy/install-artifacts
echo 'HOLY-INSTALL-1 resolver start'
$installer --config /run/install.conf --plan /run/install.plan \
    --holypkg "$pkg" > /run/install-preview
$bb grep -q '^plan-set .* read-only$' /run/install-preview
echo 'HOLY-INSTALL-1 plan reviewed'
test "$($bb cat /mnt/holy/var/lib/holypkg/generation)" = 0
$installer --apply /run/install.plan --holypkg "$pkg" > /run/install-apply
test "$($bb cat /mnt/holy/var/lib/holypkg/generation)" = 1
$pkg db check --all --root /mnt/holy > /run/install-check
echo 'HOLY-INSTALL-1 package-set committed'

stage=boot
$bb cp /etc/holy/boot-plan /mnt/holy/etc/holy/boot-plan
$pkg docs --root /mnt/holy --output /mnt/holy/usr/share/holy/llm.txt
docs=$($bb sha256sum /mnt/holy/usr/share/holy/llm.txt)
printf '%s\n' "${docs%% *}" > /mnt/holy/etc/holy/docs.sha256
$bb cp /etc/holy/boot-plan /mnt/holy/etc/holy/installed-from-live
printf '/dev/vda2\n' > /mnt/holy/etc/holy/esp-device
$bb mount -t vfat -o uid=0,gid=0,fmask=0133,dmask=0022 /dev/vda2 /mnt/holy/boot
$bb mkdir -p /mnt/holy/boot/EFI/BOOT
$bb cp /mnt/media/boot/vmlinuz /mnt/holy/boot/vmlinuz
$bb cp /mnt/media/boot/initramfs.img /mnt/holy/boot/initramfs.img
$bb cp /mnt/media/boot/limine/limine-bios.sys /mnt/holy/boot/limine-bios.sys
if test -f /mnt/media/EFI/BOOT/BOOTX64.EFI; then
    $bb cp /mnt/media/EFI/BOOT/BOOTX64.EFI /mnt/holy/boot/EFI/BOOT/BOOTX64.EFI
fi
$bb sed -e 's@boot():/boot/vmlinuz@boot():/vmlinuz@' \
    -e 's@boot():/boot/initramfs.img@boot():/initramfs.img@' \
    -e 's@holy.install-test=1@holy.test=1 holy.root=/dev/vda3 holy.rootfstype=ext4 holy.esp=/dev/vda2@' \
    /mnt/media/boot/limine/limine.conf > /mnt/holy/boot/limine.conf
$bb grep -q 'holy.root=/dev/vda3' /mnt/holy/boot/limine.conf
$pkg db check --all --root /mnt/holy > /run/install-boot-check
echo 'HOLY-INSTALL-1 esp files-and-package-state'
$bb sync
$bb umount /mnt/holy/boot
$bb umount /mnt/media
$bb umount /mnt/holy
echo 'HOLY-INSTALL-1 result pass'
trap - EXIT
while :; do $bb sleep 3600; done
