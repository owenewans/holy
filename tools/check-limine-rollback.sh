#!/bin/sh
# checks a limine.conf that is meant to roll a kernel back. two slots, a menu that shows
# both, a digest each path carries, and a default that names the current slot by path
# rather than by position. a config missing any of those offers a choice that cannot be
# taken, so each absence is named here instead of at the machine.
#
# usage: check-limine-rollback.sh CONFIG [CURRENT] [--distinct]
#   CURRENT is a or b, the slot a new boot should land on. --distinct additionally
#   requires the two slots to carry different kernels, which a fresh install cannot
#   satisfy because it has no previous kernel yet and an update can.
set -eu

config=${1:?usage: check-limine-rollback.sh CONFIG [CURRENT] [--distinct]}
current=${2:-}
distinct=${3:-}

test -f "$config" || { printf 'rollback: %s is not a file\n' "$config" >&2; exit 1; }
case $current in
    ''|a|b) ;;
    *) printf 'rollback: CURRENT is a or b, not %s\n' "$current" >&2; exit 2 ;;
esac

fail=0
refuse() { printf 'rollback: %s\n' "$1" >&2; fail=1; }

# a timeout of zero boots without showing the menu, and a menu nobody reaches is not a
# rollback
if grep -qE '^timeout:[[:space:]]*(0|no)[[:space:]]*$' "$config"; then
    refuse 'timeout boots without a menu, so no slot can be chosen'
fi
grep -qE '^hash_mismatch_panic:[[:space:]]*no[[:space:]]*$' "$config" ||
    refuse 'a kernel that fails its digest panics instead of returning to the menu'
if grep -qE '^remember_last_entry:[[:space:]]*yes' "$config"; then
    refuse 'remember_last_entry overrides default_entry on UEFI, so a slot switch is invisible'
fi

entries=$(grep -cE '^/' "$config" || true)
test "${entries:-0}" -ge 2 || refuse "one entry is not a rollback, the config has ${entries:-0}"

# default_entry names a slot path so reordering the entries cannot repoint it at another
# slot. an entry path carries no leading slash: limine reads one as the start of a new
# menu entry, so "/Holy a" as a value names nothing, disables autoboot and leaves every
# boot sitting in the menu waiting for a keypress
default=$(sed -n 's/^default_entry:[[:space:]]*//p' "$config")
case ${default:-} in
    '') refuse 'default_entry is unset, so the first entry boots whatever order the file has' ;;
    /*) refuse "default_entry is $default, a leading slash makes limine read it as a new entry" ;;
    *[!0-9]*) ;;
    *) refuse "default_entry is $default, a position rather than a slot path" ;;
esac
if test -n "$current"; then
    case $default in
        *"$current") ;;
        *) refuse "default_entry is $default, not the current slot $current" ;;
    esac
fi
# the value has to name an entry the file has. an entry heading is the path with a
# leading slash, so the comparison adds the slash the value must not carry itself
if test -n "$default" && ! grep -qxF "/$default" "$config"; then
    refuse "default_entry $default names no entry in the file"
fi

# each slot needs an entry, a kernel, an initramfs and a 128 character digest on both,
# because a digest of another length is a config the loader panics on
for slot in a b; do
    grep -q "^/Holy $slot\$" "$config" || refuse "no entry for slot $slot"
    kernel=$(sed -n "s/^ *kernel_path: .*vmlinuz-$slot#\([0-9a-f]*\).*/\1/p" "$config" | head -1)
    module=$(sed -n "s/^ *module_path: .*initramfs-$slot\.img#\([0-9a-f]*\).*/\1/p" "$config" | head -1)
    test "${#kernel}" = 128 || refuse "slot $slot kernel_path carries a ${#kernel} character digest, not 128"
    test "${#module}" = 128 || refuse "slot $slot module_path carries a ${#module} character digest, not 128"
    eval "kernel_$slot=\$kernel"
done

# two slots carrying the same kernel offer one choice twice. a fresh install is in that
# state because it has no previous kernel, so it is reported rather than refused unless
# the caller asked for a rollback that can actually return somewhere
if test "$kernel_a" = "$kernel_b"; then
    if test "$distinct" = --distinct; then
        refuse 'both slots carry the same kernel, so there is nothing to roll back to'
        identical=1
    else
        identical=1
        printf 'rollback: both slots carry the same kernel, so a rollback is not yet possible\n' >&2
    fi
else
    identical=0
fi

if test "$fail" = 0; then
    printf 'rollback: config ok entries %s default %s slots %s\n' \
           "$entries" "$default" "$(test "$identical" = 1 && echo identical || echo distinct)"
    exit 0
fi
printf 'rollback: config refused\n' >&2
exit 4
