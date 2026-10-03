#!/bin/sh
# writes a limine.conf that can roll a kernel back. the two slots, the menu that shows
# both, the blake2b each path carries and the default_entry that names the current one are
# what makes a bad kernel recoverable, and all five are configuration, not loader code.
#
# usage: limine-rollback.sh CURRENT A_KERNEL A_INITRAMFS B_KERNEL B_INITRAMFS CMDLINE
#   CURRENT is a or b. the four files are hashed here, so a slot whose file is missing
#   or unreadable is refused rather than written as an entry that cannot boot.
set -eu

current=$1
a_kernel=$2
a_initramfs=$3
b_kernel=$4
b_initramfs=$5
cmdline=$6

case $current in
    a|b) ;;
    *) printf 'limine-rollback: CURRENT is a or b, not %s\n' "$current" >&2; exit 2 ;;
esac

command -v b2sum >/dev/null 2>&1 || {
    printf 'limine-rollback: b2sum is required\n' >&2; exit 6; }

# limine reads the digest as 128 lowercase hex characters of blake2b-512 and refuses
# anything else, so a short hash would be a config that panics at boot
hash_of() {
    digest=$(b2sum "$1" | cut -d' ' -f1)
    test "${#digest}" = 128 || {
        printf 'limine-rollback: %s: blake2b digest is %s characters, not 128\n' \
               "$1" "${#digest}" >&2
        exit 1; }
    printf '%s' "$digest"
}

for file in "$a_kernel" "$a_initramfs" "$b_kernel" "$b_initramfs"; do
    test -f "$file" || { printf 'limine-rollback: %s is not a file\n' "$file" >&2; exit 1; }
done

a_kernel_hash=$(hash_of "$a_kernel")
a_initramfs_hash=$(hash_of "$a_initramfs")
b_kernel_hash=$(hash_of "$b_kernel")
b_initramfs_hash=$(hash_of "$b_initramfs")

# a timeout of zero would boot the selected entry without showing the menu, and a menu
# the machine never reaches is not a rollback
cat <<EOF
timeout: 5
serial: yes
verbose: yes
# a kernel that does not match its own digest returns to this menu instead of leaving
# the machine with nothing to choose, which is the moment a rollback is needed
hash_mismatch_panic: no
# the path names the slot rather than its position, so reordering the entries cannot
# repoint the default. remember_last_entry is deliberately absent: on UEFI it would
# override default_entry and make the switch invisible. an entry path carries no leading
# slash: limine reads one as the start of a new menu entry, so a default of /Holy a
# names nothing, disables autoboot and drops every boot into the menu
default_entry: Holy $current
\${holy_cmdline}=$cmdline

/Holy a
    protocol: linux
    comment: slot a ${a_kernel_hash%${a_kernel_hash#????????}}
    kernel_path: boot():/vmlinuz-a#$a_kernel_hash
    module_path: boot():/initramfs-a.img#$a_initramfs_hash
    cmdline: \${holy_cmdline}
/Holy b
    protocol: linux
    comment: slot b ${b_kernel_hash%${b_kernel_hash#????????}}
    kernel_path: boot():/vmlinuz-b#$b_kernel_hash
    module_path: boot():/initramfs-b.img#$b_initramfs_hash
    cmdline: \${holy_cmdline}
EOF
