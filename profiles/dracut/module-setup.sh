#!/bin/bash
check() { return 0; }
depends() { return 0; }
config() {
    # dracut treats an empty systemd directory as the root directory.
    systemdutildir=/usr/lib/systemd
}
install() {
    test -n "$HOLY_ROOT" && test -x "$HOLY_ROOT/usr/bin/dinit" || return 1
    test -n "$initdir" && test "$initdir" != / || return 1
    rm -rf -- "${initdir:?}/"*
    cp -a "$HOLY_ROOT/." "$initdir/" || return 1
    mkdir -p "$initdir/usr/lib/dracut"
}
