#!/bin/sh
set -eu
installer=$(realpath "$1")
holypkg=$(realpath "$2")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/root space"
tree="$tmp/tree"
mkdir -p "$root/usr/share" "$tree/HOLY" "$tree/DATA/usr/share"
printf 'format holy-package-1\nname installer-fixture\nversion 1\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' > "$tree/HOLY/meta"
for field in deps provides hooks origin transform; do : > "$tree/HOLY/$field"; done
printf 'installed\n' > "$tree/DATA/usr/share/installer-fixture"
"$holypkg" manifest generate "$tree" --output "$tmp/files" > /dev/null
mv "$tmp/files" "$tree/HOLY/files"
"$holypkg" pack "$tree" --output "$tmp/fixture.holy" > /dev/null
digest=$(sha256sum "$tmp/fixture.holy" | cut -d ' ' -f 1)
"$holypkg" db init --root "$root" > /dev/null
"$holypkg" cache stage "local:$tmp/fixture.holy" --root "$root" > /dev/null
menu_root="$tmp/menu β root"
cp -a "$root" "$menu_root"
if "$installer" --menu --config "$tmp/menu.conf" --plan "$tmp/menu.plan" --holypkg "$holypkg" \
    < /dev/null > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
python3 tests/installer-menu.py "$installer" "$holypkg" "$menu_root" "$digest" \
    "$tmp/menu.conf" "$tmp/menu.plan"
"$holypkg" db check --all --root "$menu_root" > /dev/null
printf '[install]\nroot "%s"\nartifact %s\n' "$root" "$digest" > "$tmp/install.conf"
printf '[install]\nroot "%s"\nroot "%s"\nartifact %s\n' "$root" "$root" "$digest" > "$tmp/duplicate.conf"
if "$installer" --config "$tmp/duplicate.conf" --plan "$tmp/duplicate.plan" --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test ! -e "$tmp/duplicate.plan"
"$installer" --config "$tmp/install.conf" --plan "$tmp/install.plan" --holypkg "$holypkg" > "$tmp/preview"
grep -q '^plan-set .* read-only$' "$tmp/preview"
test ! -e "$root/usr/share/installer-fixture"
test "$(cat "$root/var/lib/holypkg/generation")" -eq 0
grep -qx "artifact $digest" "$tmp/install.plan"
cp "$tmp/install.plan" "$tmp/include.plan"
printf 'include "/etc/shadow"\n' >> "$tmp/include.plan"
if "$installer" --apply "$tmp/include.plan" --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -qx 'holyinstall: plan inputs changed or invalid' "$tmp/err"
test ! -e "$root/usr/share/installer-fixture"
ln -s "$tmp/install.plan" "$tmp/link.plan"
if "$installer" --apply "$tmp/link.plan" --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
mkfifo "$tmp/pipe.plan"
if "$installer" --apply "$tmp/pipe.plan" --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
if "$installer" --config "$tmp/install.conf" --plan "$tmp/install.plan" --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test ! -e "$root/usr/share/installer-fixture"
rm "$tmp/install.conf"
"$installer" --apply "$tmp/install.plan" --holypkg "$holypkg" > "$tmp/out"
grep -qx installed "$root/usr/share/installer-fixture"
"$holypkg" db check --all --root "$root" > /dev/null
if "$installer" --apply "$tmp/install.plan" --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
if grep -qx 'holyinstall: plan inputs changed or invalid' "$tmp/err"; then exit 1; fi
cp "$tmp/install.plan" "$tmp/changed.plan"
sed -i 's/^device [0-9][0-9]*/device invalid/' "$tmp/changed.plan"
if "$installer" --apply "$tmp/changed.plan" --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -qx 'holyinstall: plan inputs changed or invalid' "$tmp/err"
if test "$(uname -m)" = x86_64; then
    arch_tree="$tmp/arch-tree"
    arch_root="$tmp/arch-root"
    mkdir -p "$arch_tree/HOLY" "$arch_tree/DATA/usr/share" "$arch_root/usr/share"
    printf 'format holy-package-1\nname arch-fixture\nversion 1\nrelease 1\nos linux\narch x86\nlibc nolibc\n' > "$arch_tree/HOLY/meta"
    for field in deps provides hooks origin transform; do : > "$arch_tree/HOLY/$field"; done
    printf 'arch-accepted\n' > "$arch_tree/DATA/usr/share/arch-fixture"
    "$holypkg" manifest generate "$arch_tree" --output "$tmp/arch-files" > /dev/null
    mv "$tmp/arch-files" "$arch_tree/HOLY/files"
    "$holypkg" pack "$arch_tree" --output "$tmp/arch-fixture.holy" > /dev/null
    arch_digest=$(sha256sum "$tmp/arch-fixture.holy" | cut -d ' ' -f 1)
    "$holypkg" db init --root "$arch_root" > /dev/null
    "$holypkg" cache stage "local:$tmp/arch-fixture.holy" --root "$arch_root" > /dev/null
    printf '[install]\nroot "%s"\nartifact %s\n' "$arch_root" "$arch_digest" > "$tmp/arch-no-override.conf"
    if "$installer" --config "$tmp/arch-no-override.conf" --plan "$tmp/arch-no-override.plan" --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
    test ! -e "$tmp/arch-no-override.plan"
    printf 'accept-arch %s\n' "$arch_digest" >> "$tmp/arch-no-override.conf"
    "$installer" --config "$tmp/arch-no-override.conf" --plan "$tmp/arch.plan" --holypkg "$holypkg" > "$tmp/out"
    grep -qx 'format holy-install-plan-2' "$tmp/arch.plan"
    grep -qx "accept-arch $arch_digest" "$tmp/arch.plan"
    cp "$tmp/arch.plan" "$tmp/arch-invalid.plan"
    sed -i '/^accept-arch /d' "$tmp/arch-invalid.plan"
    if "$installer" --apply "$tmp/arch-invalid.plan" --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
    "$installer" --apply "$tmp/arch.plan" --holypkg "$holypkg" > "$tmp/out"
    grep -qx arch-accepted "$arch_root/usr/share/arch-fixture"
    "$holypkg" db check --all --root "$arch_root" > /dev/null
fi
printf 'installer plan and apply fixtures passed\n'
