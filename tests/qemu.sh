#!/bin/sh
set -eu

arch=${ARCH:-}
iso=${ISO:-}
plan=${BOOT_PLAN:-}
limit=${QEMU_TIMEOUT:-120}

case "$arch" in
    i686) qemu=qemu-system-i386 ;;
    x86_64) qemu=qemu-system-x86_64 ;;
    *) echo 'holy-qemu: ARCH must be i686 or x86_64' >&2; exit 2 ;;
esac
if ! command -v "$qemu" > /dev/null 2>&1 ||
   ! command -v timeout > /dev/null 2>&1 ||
   ! command -v sha256sum > /dev/null 2>&1; then
    echo 'holy-qemu: QEMU, timeout and sha256sum are required' >&2
    exit 6
fi
if test ! -f "$iso" || test ! -r "$iso"; then
    echo "holy-qemu: missing readable ISO: $iso" >&2
    exit 6
fi
case "$plan" in
    *[!0123456789abcdef]*|'') echo 'holy-qemu: BOOT_PLAN must be SHA-256' >&2; exit 2 ;;
esac
if test "${#plan}" -ne 64; then
    echo 'holy-qemu: BOOT_PLAN must be SHA-256' >&2
    exit 2
fi
case "$limit" in
    *[!0123456789]*|'') echo 'holy-qemu: invalid QEMU_TIMEOUT' >&2; exit 2 ;;
esac
if test "$limit" -lt 1 || test "$limit" -gt 600; then
    echo 'holy-qemu: QEMU_TIMEOUT must be 1..600 seconds' >&2
    exit 2
fi

report_dir=${REPORT_DIR:-${TMPDIR:-/tmp/opencode}}
if test ! -d "$report_dir"; then
    echo "holy-qemu: missing report directory: $report_dir" >&2
    exit 6
fi
run=$(mktemp -d "$report_dir/holy-qemu-$arch-XXXXXX") || exit 1
hash=$(sha256sum "$iso") || exit 1
hash=${hash%% *}
start=$(date +%s)
if timeout --signal=TERM --kill-after=5 "${limit}s" \
    "$qemu" -accel tcg -m 1024 -display none -monitor none -net none \
    -no-reboot -boot d -cdrom "$iso" -serial "file:$run/serial.log" \
    > "$run/qemu.stdout" 2> "$run/qemu.stderr"; then
    code=0
else
    code=$?
fi
end=$(date +%s)
result=fail
if test "$code" -eq 0 && test -f "$run/serial.log" &&
   grep -Fxq "HOLY-BOOT-1 plan $plan" "$run/serial.log" &&
   grep -Fxq 'HOLY-BOOT-1 pid1 dinit' "$run/serial.log" &&
   grep -Fxq 'HOLY-BOOT-1 shell busybox' "$run/serial.log" &&
   grep -Fxq 'HOLY-BOOT-1 pkg holypkg' "$run/serial.log" &&
   grep -Fxq 'HOLY-BOOT-1 result pass' "$run/serial.log"; then
    result=pass
fi
{
    printf 'format holy-qemu-report-1\narch %s\niso %s\niso-sha256 %s\n' "$arch" "$iso" "$hash"
    printf 'plan %s\naccelerator tcg\nfirmware bios\n' "$plan"
    printf 'argv %s\nargv -accel\nargv tcg\nargv -m\nargv 1024\n' "$qemu"
    printf 'argv -display\nargv none\nargv -monitor\nargv none\nargv -net\nargv none\n'
    printf 'argv -no-reboot\nargv -boot\nargv d\nargv -cdrom\nargv %s\n' "$iso"
    printf 'argv -serial\nargv file:%s/serial.log\n' "$run"
    printf 'exit %s\nelapsed-seconds %s\nresult %s\n' \
        "$code" "$((end - start))" "$result"
} > "$run/report"
printf 'holy-qemu: %s report %s\n' "$result" "$run/report"
test "$result" = pass || exit 4
