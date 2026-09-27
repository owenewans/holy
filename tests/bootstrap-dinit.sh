#!/bin/sh
set -eu
test "$#" -eq 3 || exit 2
bin=$(realpath "$1")
for tool in doas chroot timeout mknod; do
    command -v "$tool" >/dev/null || { echo "$tool required" >&2; exit 6; }
done
doas -n true || exit 6
umask 022
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/root"
mkdir -p "$root/usr/bin" "$root/run" "$root/services" "$root/dev" \
    "$root/usr/share/licenses/dinit" "$root/usr/share/licenses/busybox" \
    "$root/usr/share/licenses/musl" "$root/usr/share/man/man5" "$root/usr/share/man/man8"
"$bin" db init --root "$root" > "$tmp/out"
place() {
    "$bin" info "local:$package" > "$tmp/info"
    arch=$(sed -n 's/^arch //p' "$tmp/info")
    set -- "$digest"
    case "$arch:$(uname -m)" in
        x86_64:x86_64|x86:i686) ;;
        *) set -- "$@" --accept-arch "$digest" ;;
    esac
    "$bin" db plan-set "$@" --root "$root" > "$tmp/out"
    plan=$(sed -n 's/.* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
    test "${#plan}" -eq 64
    "$bin" db apply-set "$plan" "$@" --root "$root" > "$tmp/out"
}
for package in "$2" "$3"; do
    "$bin" cache stage "local:$package" --root "$root" > "$tmp/out"
    digest=$(sha256sum "$package")
    digest=${digest%% *}
    place
done
doas -n mknod -m 666 "$root/dev/null" c 1 3
test "$(readlink "$root/usr/bin/reboot")" = shutdown
test "$(readlink "$root/usr/share/man/man8/reboot.8")" = shutdown.8
for name in dinit dinitctl busybox; do
    "$bin" elf "$root/usr/bin/$name" > "$tmp/elf"
    grep -qx 'runtime nolibc' "$tmp/elf"
done
"$bin" elf "$root/usr/bin/dinit" > "$tmp/elf"
if grep -qx 'machine x86' "$tmp/elf"; then
    command -v qemu-i386 >/dev/null || exit 6
    qemu-i386 -cpu pentium2 "$root/usr/bin/dinit" --version > "$tmp/emulator"
    grep -q 'Dinit version' "$tmp/emulator"
fi
cat > "$root/services/probe" <<'EOF'
type = scripted
command = /usr/bin/busybox touch /run/started
stop-command = /usr/bin/busybox touch /run/stopped
EOF
cat > "$root/probe.sh" <<'EOF'
set -eu
test ! -e /lib && test ! -e /lib64 && test ! -e /usr/lib
/usr/bin/dinit --user --services-dir /services --socket-path /run/control probe &
pid=$!
trap 'kill "$pid" 2>/dev/null || :; wait "$pid" || :' EXIT
for i in 1 2 3 4 5 6 7 8 9 10; do
    test ! -e /run/started || break
    /usr/bin/busybox sleep 1
done
test -f /run/started
/usr/bin/dinitctl --socket-path /run/control status probe
/usr/bin/dinitctl --socket-path /run/control shutdown
wait "$pid"
trap - EXIT
test -f /run/stopped
echo 'static dinit service and shutdown passed'
EOF
if ! doas -n timeout -k 2 20 chroot --userspec="$(id -u):$(id -g)" "$root" \
    /usr/bin/busybox ash /probe.sh > "$tmp/service.log" 2>&1; then
    cat "$tmp/service.log" >&2
    exit 1
fi
grep -q 'static dinit service and shutdown passed' "$tmp/service.log"
grep -q 'State: STARTED' "$tmp/service.log"
cat "$tmp/service.log"
"$bin" db check --all --root "$root" > "$tmp/out"
for package in "$2" "$3"; do
    digest=$(sha256sum "$package")
    digest=${digest%% *}
    "$bin" db rm "$digest" --root "$root" > "$tmp/out"
done
test ! -e "$root/usr/bin/dinit"
test ! -L "$root/usr/bin/reboot"
test ! -L "$root/usr/share/man/man8/reboot.8"
printf 'static dinit package install/check/remove passed\n'
sha256sum "$2" "$3"
