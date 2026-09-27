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
if test -f /etc/holy/esp-device; then
    stage=esp
    esp=$($bb cat /etc/holy/esp-device)
    $bb grep -F "$esp /boot vfat rw," /proc/mounts
    test -s /boot/vmlinuz
    test -s /boot/initramfs.img
    test -s /boot/limine.conf
    if test "$boot" = 1; then
        test ! -e /boot/holy-reboot-witness
        printf '%s\n' "$plan" > /boot/holy-reboot-witness
    else
        test "$($bb cat /boot/holy-reboot-witness)" = "$plan"
    fi
    echo 'HOLY-BOOT-1 esp mounted-writable'
fi
test "$($bb readlink /proc/1/exe)" = /usr/bin/dinit
echo "HOLY-BOOT-1 pid1-exe $($bb readlink /proc/1/exe)"
echo 'HOLY-BOOT-1 pid1 dinit'
echo "HOLY-BOOT-1 arch $($bb uname -m)"
test "$($bb uname -r)" = "$($bb cat /etc/holy/kernel-version)"
echo "HOLY-BOOT-1 kernel $($bb uname -r)"
test "$($bb ash -c 'printf shell-probe')" = shell-probe
echo 'HOLY-BOOT-1 shell busybox'
stage=static-core
for executable in busybox dinit dinitctl mdevd mdevd-coldplug holypkg holyinstall holy-init; do
    $pkg elf "/usr/bin/$executable" > /run/core-elf
    $bb grep -qx 'runtime nolibc' /run/core-elf
done
if test "$profile" = static-core; then
    for loader in /lib64/ld-linux-x86-64.so.2 /lib/ld-linux.so.2 /lib/ld-musl-x86_64.so.1 /lib/ld-musl-i386.so.1; do
        test ! -e "$loader"
    done
fi
echo 'HOLY-BOOT-1 static-core verified'
stage=installer
if /usr/bin/holyinstall disk > /run/installer-usage 2>&1; then exit 1; else test "$?" -eq 2; fi
$bb grep -q '^usage: holyinstall disk ' /run/installer-usage
echo 'HOLY-BOOT-1 installer static-cli'
stage=devices
/usr/bin/dinitctl --socket-path /run/dinitctl status mdevd > /run/mdevd.status
$bb grep -q 'State: STARTED' /run/mdevd.status
test -c /dev/null
$bb ls -l /dev/null | $bb grep -q '^crw-------'
echo 'HOLY-BOOT-1 device mdevd-coldplug'
if test "$profile" = dual-libc; then
    stage=libc-recovery
    case "$($bb uname -m)" in
        i686)
            glibc_loader=/usr/lib/holy/i686-linux-gnu/ld-linux.so.2
            glibc_runtime=/usr/lib/holy/i686-linux-gnu/libc.so.6
            glibc_public=/lib/ld-linux.so.2
            musl_loader=/usr/lib/holy/i686-linux-musl/ld-musl-i386.so.1
            musl_public=/lib/ld-musl-i386.so.1 ;;
        x86_64)
            glibc_loader=/usr/lib/holy/x86_64-linux-gnu/ld-linux-x86-64.so.2
            glibc_runtime=/usr/lib/holy/x86_64-linux-gnu/libc.so.6
            glibc_public=/lib64/ld-linux-x86-64.so.2
            musl_loader=/usr/lib/holy/x86_64-linux-musl/ld-musl-x86_64.so.1
            musl_public=/lib/ld-musl-x86_64.so.1 ;;
        *) exit 1 ;;
    esac
    state=$($bb cat /etc/holy/libc-boot-state)
    network=$($bb cat /etc/holy/network-recovery)
    case "$network" in off|fixture) ;; *) exit 1 ;; esac
    case "$state" in present|glibc|musl|both|remove-both) ;; *) exit 1 ;; esac
    if test "$boot" = 2; then
        if test "$state" = remove-both; then state=removed-both; else state=restored; fi
    fi
    for abi in glibc musl; do
        case "$abi" in
            glibc) loader=$glibc_loader ;;
            musl) loader=$musl_loader ;;
        esac
        case "$state:$abi" in
            both:*|removed-both:*|glibc:glibc|musl:musl)
                test ! -e "$loader"
                if test "$abi" = glibc; then
                    test ! -e "$glibc_runtime"
                    test ! -L "$glibc_public"
                else
                    test ! -L "$musl_public"
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
    if test "$network" = fixture && test "$state" = both; then
        stage=network-setup
        test -s /etc/holy/recovery-ca.pem
        $bb ip link set eth0 up
        $bb ip addr add 10.0.2.15/24 dev eth0
        $bb ip route add default via 10.0.2.2 dev eth0
        $bb ip addr show eth0 | $bb grep -q 'inet 10.0.2.'
        echo 'HOLY-BOOT-1 network fixture-static-ip'
        $bb nslookup fixture.holy.test > /run/fixture-dns
        $bb grep -q '10.0.2.2' /run/fixture-dns
        echo 'HOLY-BOOT-1 network fixture-dns'
        for abi in glibc musl; do
            digest=$($bb cat "/etc/holy/$abi.sha256")
            test ! -e "/var/cache/holypkg/objects/sha256/$digest.holy"
            $pkg fetch "https://fixture.holy.test:8443/$abi.holy" \
                --sha256 "$digest" --output /var/cache/holypkg/objects/sha256 \
                --ca-file /etc/holy/recovery-ca.pem > /run/network-fetch
            echo "HOLY-BOOT-1 downloaded-libc $abi"
        done
    fi
    for abi in glibc musl; do
        case "$state:$abi" in
            both:*|removed-both:*|glibc:glibc|musl:musl)
                digest=$($bb cat "/etc/holy/$abi.sha256")
                $pkg info "local:/var/cache/holypkg/objects/sha256/$digest.holy" > /run/libc-info
                $bb grep -qx "libc $abi" /run/libc-info
                if test "$state" = removed-both; then
                    $pkg db plan-set "$digest" --root / > /run/libc-plan
                    hash=$($bb sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' /run/libc-plan)
                    test "${#hash}" -eq 64
                    $pkg db apply-set "$hash" "$digest" --root / > /run/libc-repair
                    echo "HOLY-BOOT-1 reinstalled-libc $abi"
                else
                    $pkg db repair-plan "$digest" --root / > /run/libc-plan
                    hash=$($bb sed -n 's/^repair-plan .* sha256 \([0-9a-f]*\) missing-only read-only$/\1/p' /run/libc-plan)
                    test "${#hash}" -eq 64
                    $pkg db repair "$digest" --plan "$hash" --root / > /run/libc-repair
                fi
                $bb cat /run/libc-repair
                echo "HOLY-BOOT-1 restored-libc $abi"
                ;;
        esac
    done
    test "$(/usr/bin/holy-probe-glibc)" = glibc-probe
    test "$(/usr/bin/holy-probe-musl)" = musl-probe
    test "$("$glibc_public" /usr/bin/holy-probe-glibc)" = glibc-probe
    test "$("$musl_public" /usr/bin/holy-probe-musl)" = musl-probe
    /usr/bin/holy-probe-glibc | /usr/bin/holy-probe-musl glibc-probe > /run/pipe-result
    $bb grep -qx musl-probe /run/pipe-result
    /usr/bin/holy-probe-musl | /usr/bin/holy-probe-glibc musl-probe > /run/pipe-result
    $bb grep -qx glibc-probe /run/pipe-result
    $pkg db check --all --root / > /run/libc-check
    echo 'HOLY-BOOT-1 libc-probes glibc-musl-pipe'
    if test "$state" != remove-both; then echo "HOLY-BOOT-1 libc-recovery $state"; fi
fi
stage=documentation
docs=$($bb sha256sum /usr/share/holy/llm.txt)
test "${docs%% *}" = "$($bb cat /etc/holy/docs.sha256)"
$pkg docs --root / --output /run/installed-man.txt
shipped=$($bb sed '$s/generation [0-9][0-9]*/generation current/' /usr/share/holy/llm.txt | $bb sha256sum)
current=$($bb sed '$s/generation [0-9][0-9]*/generation current/' /run/installed-man.txt | $bb sha256sum)
test "$shipped" = "$current"
$bb grep -q '^page .*package "dinit" ' /run/installed-man.txt
$bb grep -q '^page .*package "holypkg" ' /run/installed-man.txt
$bb grep -q '^page .*package "holyinstall" ' /run/installed-man.txt
$bb grep -q '^summary .*missing-man ' /run/installed-man.txt
echo 'HOLY-BOOT-1 docs installed-man-bundle'
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
    if test "$($bb cat /etc/holy/libc-boot-state)" = remove-both; then
        stage=libc-removal
        for abi in glibc musl; do
            digest=$($bb cat "/etc/holy/$abi.sha256")
            probe=$($bb cat "/etc/holy/probe-$abi.sha256")
            if $pkg db rm "$digest" --root / > /run/provider-remove 2>&1; then exit 1; else test "$?" -eq 3; fi
            $pkg db rm "$digest" --accept-broken --root / > /run/provider-remove 2>&1
            if $pkg db check "$probe" --root / --json > /run/broken-provider; then exit 1; else test "$?" -eq 4; fi
            $bb grep -q '"code":"broken-provider"' /run/broken-provider
            echo "HOLY-BOOT-1 removed-libc $abi"
        done
        if $pkg db check --all --root / > /run/libc-check 2>&1; then exit 1; else test "$?" -eq 4; fi
        stage=reboot
    fi
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
