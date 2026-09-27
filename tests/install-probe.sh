#!/bin/sh
set -eu
bb=/usr/bin/busybox
pkg=/usr/bin/holypkg
installer=/usr/bin/holyinstall
stage=devices
trap 'echo "HOLY-INSTALL-1 failed $stage"; echo "HOLY-INSTALL-1 result fail"' EXIT

for device in /dev/vda /dev/sr0; do
    test -b "$device"
done
echo 'HOLY-INSTALL-1 devices target-and-media'

stage=disk
test ! -e /dev/vda2 && test ! -e /dev/vda3
printf '[disk]\ndevice "/dev/vda"\nlayout gpt-ext4\n' > /run/install-disk.conf
$installer disk plan --config /run/install-disk.conf --output /run/install-disk.plan \
    > /run/install-disk-preview
$installer disk show --plan /run/install-disk.plan > /run/install-disk-show
$bb grep -q '^disk device /dev/vda$' /run/install-disk-show
$bb grep -q '^serial HOLY-INSTALL-VM-1$' /run/install-disk-show
disk_plan=$($bb sha256sum /run/install-disk.plan)
echo "HOLY-INSTALL-1 disk-plan ${disk_plan%% *}"
if $installer disk apply --plan /run/install-disk.plan --confirm /dev/vdb \
    > /run/install-disk-rejected 2>&1; then exit 1; else test "$?" -eq 3; fi
test ! -e /run/install-disk.plan.journal
test ! -e /dev/vda2 && test ! -e /dev/vda3
$installer disk apply --plan /run/install-disk.plan --confirm /dev/vda \
    > /run/install-disk-apply
test "$($bb tail -n 1 /run/install-disk.plan.journal)" = committed
/usr/bin/sfdisk --verify /dev/vda > /run/install-disk-verify
test -b /dev/vda2 && test -b /dev/vda3
echo 'HOLY-INSTALL-1 disk prepared'

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
doas_digest=$($bb cat /etc/holy/doas.sha256)
test "${#doas_digest}" -eq 64
if $installer --config /run/install.conf --plan /run/install-unapproved.plan \
    --holypkg "$pkg" > /run/install-unapproved 2>&1; then
    exit 1
else
    test "$?" -eq 3
fi
test ! -e /run/install-unapproved.plan
$bb grep -q 'decision-required privileged' /run/install-unapproved
printf 'accept-privileged %s\n' "$doas_digest" >> /run/install.conf
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

stage=doas
$pkg db check "$doas_digest" --root /mnt/holy > /run/doas-check
echo 'HOLY-INSTALL-1 doas in-reviewed-set'

stage=account
$bb mkdir -p /mnt/holy/home/holytest
$bb chown 10001:10001 /mnt/holy/home/holytest
$bb chmod 0700 /mnt/holy/home/holytest
$bb cat > /mnt/holy/home/holytest/.profile <<'EOF'
/usr/bin/busybox printf 'HOLY-LOGIN-UID '
/usr/bin/busybox id -u
root_uid=$(/usr/bin/doas /usr/bin/busybox id -u) || exit 1
/usr/bin/busybox printf 'HOLY-DOAS-UID %s\n' "$root_uid"
exit
EOF
$bb chown 10001:10001 /mnt/holy/home/holytest/.profile
$bb chmod 0600 /mnt/holy/home/holytest/.profile
echo 'HOLY-INSTALL-1 account prepared'

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
