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
"$bin" fetch "local:$2" --extract --output "$tmp/dinit" > "$tmp/extract.log"
"$bin" fetch "local:$3" --extract --output "$tmp/busybox" >> "$tmp/extract.log"
root="$tmp/root"
mkdir -p "$root/usr/bin" "$root/run" "$root/services" "$root/dev"
doas -n mknod -m 666 "$root/dev/null" c 1 3
for name in dinit dinitctl; do
    cp "$tmp/dinit/DATA/usr/bin/$name" "$root/usr/bin/$name"
done
cp "$tmp/busybox/DATA/usr/bin/busybox" "$root/usr/bin/busybox"
for name in dinit dinitctl busybox; do
    "$bin" elf "$root/usr/bin/$name" > "$tmp/elf"
    grep -qx 'runtime nolibc' "$tmp/elf"
done
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
sha256sum "$2" "$3"
