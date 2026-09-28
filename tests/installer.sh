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
printf '[source menu-fixture]\ntype holy-http\nurl https://menu.example/holy/\n' > "$tmp/menu-source.conf"
"$holypkg" source plan --config "$tmp/menu-source.conf" --root "$menu_root" > "$tmp/menu-source.plan"
menu_source_plan=$(sha256sum "$tmp/menu-source.plan" | cut -d ' ' -f 1)
"$holypkg" source apply "$tmp/menu-source.plan" --sha256 "$menu_source_plan" --root "$menu_root" > /dev/null
"$holypkg" source list --root "$menu_root" > "$tmp/menu-source.list"
menu_source_id=$(sed -n 's/^source \([0-9a-f]*\) "menu-fixture" active$/\1/p' "$tmp/menu-source.list")
test "${#menu_source_id}" -eq 64
if "$installer" --menu --config "$tmp/menu.conf" --plan "$tmp/menu.plan" --holypkg "$holypkg" \
    < /dev/null > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 3; fi
python3 tests/installer-menu.py "$installer" "$holypkg" "$menu_root" "$digest" \
    "$tmp/menu.conf" "$tmp/menu.plan" "$menu_source_id"
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
priv_tree="$tmp/priv-tree"
priv_root="$tmp/priv-root"
mkdir -p "$priv_tree/HOLY" "$priv_tree/DATA/usr/bin" "$priv_root/usr/bin"
case "$(uname -m)" in
    x86_64)
        priv_arch=x86_64; priv_bits=64; priv_emulation=elf_x86_64
        printf '.global _start\n_start:\n mov $0, %%edi\n mov $60, %%eax\n syscall\n' > "$tmp/priv.s" ;;
    i686)
        priv_arch=x86; priv_bits=32; priv_emulation=elf_i386
        printf '.global _start\n_start:\n mov $0, %%ebx\n mov $1, %%eax\n int $0x80\n' > "$tmp/priv.s" ;;
    *) echo 'privileged fixture requires x86 or x86_64' >&2; exit 6 ;;
esac
printf 'format holy-package-1\nname privileged-fixture\nversion 1\nrelease 1\nos linux\narch %s\nlibc nolibc\n' "$priv_arch" > "$priv_tree/HOLY/meta"
for field in deps provides hooks origin transform; do : > "$priv_tree/HOLY/$field"; done
as --"$priv_bits" -o "$tmp/priv.o" "$tmp/priv.s"
ld -m "$priv_emulation" -o "$priv_tree/DATA/usr/bin/priv-fixture" "$tmp/priv.o"
chmod 4755 "$priv_tree/DATA/usr/bin/priv-fixture"
"$holypkg" manifest generate "$priv_tree" --output "$tmp/priv-files" > /dev/null
mv "$tmp/priv-files" "$priv_tree/HOLY/files"
"$holypkg" pack "$priv_tree" --output "$tmp/priv-fixture.holy" > /dev/null
priv_digest=$(sha256sum "$tmp/priv-fixture.holy" | cut -d ' ' -f 1)
"$holypkg" db init --root "$priv_root" > /dev/null
"$holypkg" cache stage "local:$tmp/priv-fixture.holy" --root "$priv_root" > /dev/null
printf '[install]\nroot "%s"\nartifact %s\n' "$priv_root" "$priv_digest" > "$tmp/priv.conf"
if "$installer" --config "$tmp/priv.conf" --plan "$tmp/priv-no.plan" --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then
    exit 1
else
    test "$?" -eq 3
fi
test ! -e "$tmp/priv-no.plan"
printf 'accept-privileged %s\n' "$priv_digest" >> "$tmp/priv.conf"
"$installer" --config "$tmp/priv.conf" --plan "$tmp/priv.plan" --holypkg "$holypkg" > "$tmp/out"
grep -qx 'format holy-install-plan-3' "$tmp/priv.plan"
grep -qx "accept-privileged $priv_digest" "$tmp/priv.plan"
cp "$tmp/priv.plan" "$tmp/priv-invalid.plan"
sed -i '/^accept-privileged /d' "$tmp/priv-invalid.plan"
if "$installer" --apply "$tmp/priv-invalid.plan" --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test ! -e "$priv_root/usr/bin/priv-fixture"
"$installer" --apply "$tmp/priv.plan" --holypkg "$holypkg" > "$tmp/out"
test "$(stat -c '%a' "$priv_root/usr/bin/priv-fixture")" = 4755
"$holypkg" db check --all --root "$priv_root" > /dev/null
source_root="$tmp/source-root"
mkdir -p "$source_root/usr/share"
"$holypkg" db init --root "$source_root" > /dev/null
"$holypkg" cache stage "local:$tmp/fixture.holy" --root "$source_root" > /dev/null
printf '[source fixture]\ntype holy-http\nurl https://fixture.example/holy/\n' > "$tmp/source.conf"
"$holypkg" source plan --config "$tmp/source.conf" --root "$source_root" > "$tmp/source-plan"
source_plan=$(sha256sum "$tmp/source-plan" | cut -d ' ' -f 1)
"$holypkg" source apply "$tmp/source-plan" --sha256 "$source_plan" --root "$source_root" > /dev/null
"$holypkg" source list --root "$source_root" > "$tmp/source-list"
source_id=$(sed -n 's/^source \([0-9a-f]*\) "fixture" active$/\1/p' "$tmp/source-list")
test "${#source_id}" -eq 64
printf '[install]\nroot "%s"\nartifact %s\nsource %s %s\n' \
    "$source_root" "$digest" "$digest" "$source_id" > "$tmp/source-install.conf"
cp "$tmp/source-install.conf" "$tmp/source-duplicate.conf"
printf 'source %s %s\n' "$digest" "$source_id" >> "$tmp/source-duplicate.conf"
if "$installer" --config "$tmp/source-duplicate.conf" --plan "$tmp/source-duplicate.plan" \
    --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
test ! -e "$tmp/source-duplicate.plan"
sed "s/$source_id/$(printf '%064d' 0)/" "$tmp/source-install.conf" > "$tmp/source-unknown.conf"
if "$installer" --config "$tmp/source-unknown.conf" --plan "$tmp/source-unknown.plan" \
    --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
test ! -e "$tmp/source-unknown.plan"
"$installer" --config "$tmp/source-install.conf" --plan "$tmp/source-install.plan" \
    --holypkg "$holypkg" > "$tmp/source-preview"
grep -qx 'format holy-install-plan-4' "$tmp/source-install.plan"
grep -qx "source $digest $source_id" "$tmp/source-install.plan"
cp "$tmp/source-install.plan" "$tmp/source-invalid.plan"
sed -i '/^source /d' "$tmp/source-invalid.plan"
if "$installer" --apply "$tmp/source-invalid.plan" --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
test ! -e "$source_root/usr/share/installer-fixture"
"$installer" --apply "$tmp/source-install.plan" --holypkg "$holypkg" > "$tmp/out"
grep -qx "source-id $source_id" "$source_root/var/lib/holypkg/installed/$digest/state"
"$holypkg" db check --all --root "$source_root" > /dev/null
printf 'installer plan and apply fixtures passed\n'
