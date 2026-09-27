#!/bin/sh
set -eu
stage=identity
trap 'echo "HOLY-BOOT-1 failed $stage"; echo "HOLY-BOOT-1 result fail"' EXIT
bb=/usr/bin/busybox
pkg=/usr/bin/holypkg
plan=$($bb cat /etc/holy/boot-plan)
profile=$($bb cat /etc/holy/image-profile)
storage=$($bb cat /etc/holy/root-storage)
boot=1
if test "$storage" = ext4; then
    $bb grep -Eq '^[^ ]+ / ext4 ' /proc/mounts
    if test -f /var/lib/holy-boot-test/reboot; then
        test "$($bb cat /var/lib/holy-boot-test/reboot)" = "$plan"
        boot=2
    fi
elif test "$storage" != ram; then
    exit 1
fi
echo "HOLY-BOOT-1 boot $boot"
echo "HOLY-BOOT-1 root $storage"
echo "HOLY-BOOT-1 plan $plan"
echo "HOLY-BOOT-1 profile $profile"
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
if test "$profile" = static-core; then
    for loader in /lib64/ld-linux-x86-64.so.2 /lib/ld-linux.so.2 /lib/ld-musl-x86_64.so.1 /lib/ld-musl-i386.so.1; do
        test ! -e "$loader"
    done
fi
echo 'HOLY-BOOT-1 static-core verified'
stage=devices
/usr/bin/dinitctl --socket-path /run/dinitctl status mdevd > /run/mdevd.status
$bb grep -q 'State: STARTED' /run/mdevd.status
test -c /dev/null
$bb ls -l /dev/null | $bb grep -q '^crw-------'
echo 'HOLY-BOOT-1 device mdevd-coldplug'
if test "$profile" = dual-libc; then
    stage=libc-recovery
    state=$($bb cat /etc/holy/libc-boot-state)
    case "$state" in present|glibc|musl|both) ;; *) exit 1 ;; esac
    if test "$boot" = 2; then state=restored; fi
    for abi in glibc musl; do
        case "$abi" in
            glibc) loader=/usr/lib/holy/x86_64-linux-gnu/ld-linux-x86-64.so.2 ;;
            musl) loader=/usr/lib/holy/x86_64-linux-musl/ld-musl-x86_64.so.1 ;;
        esac
        case "$state:$abi" in
            both:*|glibc:glibc|musl:musl)
                test ! -e "$loader"
                if test "$abi" = glibc; then
                    test ! -e /usr/lib/holy/x86_64-linux-gnu/libc.so.6
                    test ! -L /usr/lib64/ld-linux-x86-64.so.2
                else
                    test ! -L /usr/lib/ld-musl-x86_64.so.1
                fi
                probe=$($bb cat "/etc/holy/probe-$abi.sha256")
                if $pkg db check "$probe" --root / --json > /run/broken-provider; then exit 1; else test "$?" -eq 4; fi
                $bb grep -q '"code":"broken-provider"' /run/broken-provider
                $bb cat /run/broken-provider
                echo "HOLY-BOOT-1 missing-libc $abi"
                ;;
            *) test -f "$loader" ;;
        esac
    done
    echo "HOLY-BOOT-1 libc-initial $state"
    for abi in glibc musl; do
        case "$state:$abi" in
            both:*|glibc:glibc|musl:musl)
                digest=$($bb cat "/etc/holy/$abi.sha256")
                $pkg info "local:/var/cache/holypkg/objects/sha256/$digest.holy" > /run/libc-info
                $bb grep -qx "libc $abi" /run/libc-info
                $pkg db repair-plan "$digest" --root / > /run/libc-plan
                hash=$($bb sed -n 's/^repair-plan .* sha256 \([0-9a-f]*\) missing-only read-only$/\1/p' /run/libc-plan)
                test "${#hash}" -eq 64
                $pkg db repair "$digest" --plan "$hash" --root / > /run/libc-repair
                $bb cat /run/libc-repair
                echo "HOLY-BOOT-1 restored-libc $abi"
                ;;
        esac
    done
    test "$(/usr/bin/holy-probe-glibc)" = glibc-probe
    test "$(/usr/bin/holy-probe-musl)" = musl-probe
    test "$(/lib64/ld-linux-x86-64.so.2 /usr/bin/holy-probe-glibc)" = glibc-probe
    test "$(/lib/ld-musl-x86_64.so.1 /usr/bin/holy-probe-musl)" = musl-probe
    /usr/bin/holy-probe-glibc | /usr/bin/holy-probe-musl glibc-probe > /run/pipe-result
    $bb grep -qx musl-probe /run/pipe-result
    /usr/bin/holy-probe-musl | /usr/bin/holy-probe-glibc musl-probe > /run/pipe-result
    $bb grep -qx glibc-probe /run/pipe-result
    $pkg db check --all --root / > /run/libc-check
    echo 'HOLY-BOOT-1 libc-probes glibc-musl-pipe'
    echo "HOLY-BOOT-1 libc-recovery $state"
fi
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
if test "$storage" = ext4 && test "$boot" = 1; then
    stage=reboot
    $bb mkdir -p /var/lib/holy-boot-test
    printf '%s\n' "$plan" > /var/lib/holy-boot-test/reboot
    $bb sync
    echo 'HOLY-BOOT-1 first-boot pass'
    echo 'HOLY-BOOT-1 reboot requested'
    $bb reboot -f
    while :; do $bb sleep 3600; done
fi
$bb sync
echo 'HOLY-BOOT-1 result pass'
trap - EXIT
while :; do $bb sleep 3600; done
