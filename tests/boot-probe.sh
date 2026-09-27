#!/bin/sh
set -eu
stage=identity
trap 'echo "HOLY-BOOT-1 failed $stage"; echo "HOLY-BOOT-1 result fail"' EXIT
bb=/usr/bin/busybox
pkg=/usr/bin/holypkg
plan=$($bb cat /etc/holy/boot-plan)
echo "HOLY-BOOT-1 plan $plan"
test "$($bb readlink /proc/1/exe)" = /usr/bin/dinit
echo "HOLY-BOOT-1 pid1-exe $($bb readlink /proc/1/exe)"
echo 'HOLY-BOOT-1 pid1 dinit'
echo "HOLY-BOOT-1 arch $($bb uname -m)"
test "$($bb uname -r)" = "$($bb cat /etc/holy/kernel-version)"
echo "HOLY-BOOT-1 kernel $($bb uname -r)"
test "$($bb ash -c 'printf shell-probe')" = shell-probe
echo 'HOLY-BOOT-1 shell busybox'
stage=static-core
for executable in busybox dinit dinitctl mdevd mdevd-coldplug holypkg holy-init; do
    $pkg elf "/usr/bin/$executable" > /run/core-elf
    $bb grep -qx 'runtime nolibc' /run/core-elf
done
for loader in /lib64/ld-linux-x86-64.so.2 /lib/ld-linux.so.2 /lib/ld-musl-x86_64.so.1 /lib/ld-musl-i386.so.1; do
    test ! -e "$loader"
done
echo 'HOLY-BOOT-1 static-core verified'
stage=devices
/usr/bin/dinitctl --socket-path /run/dinitctl status mdevd > /run/mdevd.status
$bb grep -q 'State: STARTED' /run/mdevd.status
test -c /dev/null
$bb ls -l /dev/null | $bb grep -q '^crw-------'
echo 'HOLY-BOOT-1 device mdevd-coldplug'
stage=packages
$pkg db check --all --root / > /run/package-check
$pkg info local:/usr/share/holy/fixture.holy > /run/package-info
$bb grep -q 'name boot-fixture' /run/package-info
echo 'HOLY-BOOT-1 pkg holypkg'
digest=$($bb sha256sum /usr/share/holy/fixture.holy)
digest=${digest%% *}
$pkg cache stage local:/usr/share/holy/fixture.holy --root / > /run/package-stage
root_digest=$($bb sha256sum /usr/share/holy/fixture-root.holy)
root_digest=${root_digest%% *}
$pkg cache stage local:/usr/share/holy/fixture-root.holy --root / > /run/root-package-stage
$pkg db plan-set "$root_digest" "$digest" --root / > /run/package-plan
hash=$($bb sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' /run/package-plan)
test "${#hash}" -eq 64
$pkg db apply-set "$hash" "$root_digest" "$digest" --root / > /run/package-apply
$pkg db check "$digest" --root / > /run/package-check
test "$($bb cat /usr/share/holy/fixture-installed)" = installed-in-guest
if $pkg db rm "$digest" --root / > /run/provider-remove 2>&1; then exit 1; else test "$?" -eq 3; fi
$pkg db rm "$root_digest" --root / > /run/root-package-remove
$pkg db rm "$digest" --root / > /run/package-remove
test ! -e /usr/share/holy/fixture-installed
echo 'HOLY-BOOT-1 transaction install-check-remove'
echo 'HOLY-BOOT-1 result pass'
trap - EXIT
while :; do $bb sleep 3600; done
