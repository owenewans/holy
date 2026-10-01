#!/bin/sh
set -eu
installer=$(realpath "$1")
holypkg=$(realpath "$2")
tmp=$(mktemp -d)
#trap 'rm -rf "$tmp"' EXIT HUP INT TERM
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
# the accounts a plan names land in the target root after the packages, and the password
# entry comes from a file the caller supplies rather than from the plan
account_root="$tmp/account-root"
mkdir -p "$account_root/etc"
"$holypkg" db init --root "$account_root" > /dev/null
"$holypkg" cache stage "local:$tmp/fixture.holy" --root "$account_root" > /dev/null
printf 'wheel:x:10:\n' > "$account_root/etc/group"
printf '$6$holysalt$holysignature\n' > "$tmp/password.hash"
chmod 600 "$tmp/password.hash"
printf '[install]\nroot "%s"\naccount anna 1000 1000 /bin/sh wheel\npassword-file "%s"\nartifact %s\n' \
    "$account_root" "$tmp/password.hash" "$digest" > "$tmp/account.conf"
# a malformed account, a name the target cannot hold and a relative password file are
# shape errors the prepare stage refuses before a plan exists
printf '[install]\nroot "%s"\naccount anna 1000 1000 bin/sh -\nartifact %s\n' \
    "$account_root" "$digest" > "$tmp/account-shell.conf"
if "$installer" --config "$tmp/account-shell.conf" --plan "$tmp/account-shell.plan" \
    --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
grep -qx "holyinstall: invalid account at $tmp/account-shell.conf:3" "$tmp/err"
printf '[install]\nroot "%s"\naccount Anna 1000 1000 /bin/sh -\nartifact %s\n' \
    "$account_root" "$digest" > "$tmp/account-name.conf"
if "$installer" --config "$tmp/account-name.conf" --plan "$tmp/account-name.plan" \
    --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
printf '[install]\nroot "%s"\naccount anna 1000 1000 /bin/sh -\npassword-file hash\nartifact %s\n' \
    "$account_root" "$digest" > "$tmp/account-file.conf"
if "$installer" --config "$tmp/account-file.conf" --plan "$tmp/account-file.plan" \
    --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
grep -qx "holyinstall: password-file needs an absolute path at $tmp/account-file.conf:4" "$tmp/err"
printf '[install]\nroot "%s"\naccount anna 1000 1000 /bin/sh -\naccount anna 1001 1001 /bin/sh -\nartifact %s\n' \
    "$account_root" "$digest" > "$tmp/account-double.conf"
if "$installer" --config "$tmp/account-double.conf" --plan "$tmp/account-double.plan" \
    --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
"$installer" --config "$tmp/account.conf" --plan "$tmp/account.plan" --holypkg "$holypkg" > "$tmp/out"
grep -qx 'format holy-install-plan-5' "$tmp/account.plan"
grep -qx 'account anna 1000 1000 /bin/sh wheel' "$tmp/account.plan"
grep -qx "password-file $tmp/password.hash" "$tmp/account.plan"
if grep -q 'holysignature' "$tmp/account.plan"; then exit 1; fi
test ! -e "$account_root/etc/passwd"
"$installer" --apply "$tmp/account.plan" --holypkg "$holypkg" > "$tmp/out"
grep -qx "accounts 1 created in $account_root" "$tmp/out"
grep -qx 'account anna 1000 1000 /bin/sh wheel' "$tmp/out"
grep -qx 'anna:x:1000:1000:Holy user:/root:/bin/sh' "$account_root/etc/passwd"
grep -qx 'anna:x:1000:' "$account_root/etc/group"
grep -qx 'wheel:x:10:anna' "$account_root/etc/group"
grep -qx 'anna:$6$holysalt$holysignature:0:99999:7:::' "$account_root/etc/shadow"
grep -qx 'permit persist anna' "$account_root/etc/doas.conf"
test "$(stat -c '%a' "$account_root/etc/shadow")" = 600
test "$(stat -c '%a' "$account_root/etc/doas.conf")" = 640
test "$(stat -c '%a' "$account_root/etc/passwd")" = 644
"$holypkg" db check --all --root "$account_root" > /dev/null
# a name the target already uses is a decision, not a second install, and the packages
# that landed before it stay
taken_root="$tmp/taken-root"
mkdir -p "$taken_root/etc"
printf 'anna:x:1000:\n' > "$taken_root/etc/group"
"$holypkg" db init --root "$taken_root" > /dev/null
"$holypkg" cache stage "local:$tmp/fixture.holy" --root "$taken_root" > /dev/null
printf '[install]\nroot "%s"\naccount anna 1000 1000 /bin/sh -\nartifact %s\n' \
    "$taken_root" "$digest" > "$tmp/taken.conf"
"$installer" --config "$tmp/taken.conf" --plan "$tmp/taken.plan" --holypkg "$holypkg" > "$tmp/out"
if "$installer" --apply "$tmp/taken.plan" --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
grep -qx 'holyinstall: group anna already exists' "$tmp/err"
test -f "$taken_root/usr/share/installer-fixture"
test ! -e "$taken_root/etc/passwd"
# a group the target does not have is not invented
missing_root="$tmp/missing-root"
mkdir -p "$missing_root/etc"
printf 'wheel:x:10:\n' > "$missing_root/etc/group"
"$holypkg" db init --root "$missing_root" > /dev/null
"$holypkg" cache stage "local:$tmp/fixture.holy" --root "$missing_root" > /dev/null
printf '[install]\nroot "%s"\naccount bea 1001 1001 /bin/sh wheel,absent\nartifact %s\n' \
    "$missing_root" "$digest" > "$tmp/missing.conf"
"$installer" --config "$tmp/missing.conf" --plan "$tmp/missing.plan" --holypkg "$holypkg" > "$tmp/out"
if "$installer" --apply "$tmp/missing.plan" --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
grep -qx 'holyinstall: group absent is not in the target' "$tmp/err"
# the password file holds a shadow entry, not a password
printf 'hunter2\n' > "$tmp/word.hash"
word_root="$tmp/word-root"
mkdir -p "$word_root/etc"
"$holypkg" db init --root "$word_root" > /dev/null
"$holypkg" cache stage "local:$tmp/fixture.holy" --root "$word_root" > /dev/null
printf '[install]\nroot "%s"\naccount cleo 1002 1002 /bin/sh -\npassword-file "%s"\nartifact %s\n' \
    "$word_root" "$tmp/word.hash" "$digest" > "$tmp/word.conf"
"$installer" --config "$tmp/word.conf" --plan "$tmp/word.plan" --holypkg "$holypkg" > "$tmp/out"
if "$installer" --apply "$tmp/word.plan" --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
grep -qx 'holyinstall: password file entry is a lock marker or a hash' "$tmp/err"
test ! -e "$word_root/etc/passwd"
# the locale, the zone and the network profile are planned steps, and apply writes the
# files the packages read rather than owning a manager
network_tree="$tmp/network-tree"
mkdir -p "$network_tree/HOLY" "$network_tree/DATA/usr/lib/holy-units"
printf 'format holy-package-1\nname network-fixture\nversion 1\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' > "$network_tree/HOLY/meta"
for field in deps provides hooks origin transform; do : > "$network_tree/HOLY/$field"; done
printf 'type = process\n' > "$network_tree/DATA/usr/lib/holy-units/network-fixture"
printf 'networked\n' > "$network_tree/DATA/usr/lib/network-fixture"

"$holypkg" manifest generate "$network_tree" --output "$tmp/network-files" > /dev/null
mv "$tmp/network-files" "$network_tree/HOLY/files"
"$holypkg" pack "$network_tree" --output "$tmp/network.holy" > /dev/null
network_digest=$(sha256sum "$tmp/network.holy" | cut -d ' ' -f 1)
identity_root="$tmp/identity-root"
mkdir -p "$identity_root/usr/share/zoneinfo/Europe" "$identity_root/usr/lib" "$identity_root/etc"
printf 'TZif2identity\n' > "$identity_root/usr/share/zoneinfo/Europe/Berlin"
"$holypkg" db init --root "$identity_root" > /dev/null
"$holypkg" cache stage "local:$tmp/fixture.holy" --root "$identity_root" > /dev/null
"$holypkg" cache stage "local:$tmp/network.holy" --root "$identity_root" > /dev/null
printf '[install]\nroot "%s"\nlocale en_US.UTF-8\ntimezone Europe/Berlin\nnetwork-profile connman-iwd\nnetwork-package %s\nartifact %s\nartifact %s\n' \
    "$identity_root" "$network_digest" "$digest" "$network_digest" > "$tmp/identity.conf"
"$installer" --config "$tmp/identity.conf" --plan "$tmp/identity.plan" --holypkg "$holypkg" > "$tmp/out"
grep -qx 'format holy-install-plan-6' "$tmp/identity.plan"
grep -qx 'locale en_US.UTF-8' "$tmp/identity.plan"
grep -qx 'timezone Europe/Berlin' "$tmp/identity.plan"
grep -qx 'network-profile connman-iwd' "$tmp/identity.plan"
grep -qx "network-package $network_digest" "$tmp/identity.plan"
test ! -e "$identity_root/etc/locale.conf"
"$installer" --apply "$tmp/identity.plan" --holypkg "$holypkg" > "$tmp/out"
grep -qx 'locale en_US.UTF-8' "$tmp/out"
grep -qx 'timezone Europe/Berlin' "$tmp/out"
grep -qx "network connman-iwd packages 1 firmware 0" "$tmp/out"
grep -qx 'LANG=en_US.UTF-8' "$identity_root/etc/locale.conf"
grep -qx 'Europe/Berlin' "$identity_root/etc/timezone"
test -L "$identity_root/etc/localtime"
test "$(readlink "$identity_root/etc/localtime")" = /usr/share/zoneinfo/Europe/Berlin
grep -qx 'AutoConnect=true' "$identity_root/etc/connman/connman.conf"
test -d "$identity_root/var/lib/connman"
test -d "$identity_root/var/lib/iwd"
test "$(stat -c '%a' "$identity_root/etc/locale.conf")" = 644
"$holypkg" db check --all --root "$identity_root" > /dev/null
# a zone the target has no data for is not invented
missing_zone="$tmp/missing-zone"
mkdir -p "$missing_zone/usr/share/zoneinfo/Europe" "$missing_zone/etc"
printf 'TZif2identity\n' > "$missing_zone/usr/share/zoneinfo/Europe/Berlin"
"$holypkg" db init --root "$missing_zone" > /dev/null
"$holypkg" cache stage "local:$tmp/fixture.holy" --root "$missing_zone" > /dev/null
printf '[install]\nroot "%s"\ntimezone Africa/Nairobi\nartifact %s\n' \
    "$missing_zone" "$digest" > "$tmp/missing-zone.conf"
"$installer" --config "$tmp/missing-zone.conf" --plan "$tmp/missing-zone.plan" --holypkg "$holypkg" > "$tmp/out"
if "$installer" --apply "$tmp/missing-zone.plan" --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 6; fi
grep -qx 'holyinstall: timezone Africa/Nairobi is not in the target' "$tmp/err"
test ! -e "$missing_zone/etc/localtime"
# a profile needs its artifacts, a zone needs a shape and a locale needs a charset
printf '[install]\nroot "%s"\nnetwork-profile connman-iwd\nartifact %s\n' \
    "$missing_zone" "$digest" > "$tmp/profile-alone.conf"
if "$installer" --config "$tmp/profile-alone.conf" --plan "$tmp/profile-alone.plan" \
    --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
grep -qxF 'holyinstall: [install] network-profile needs network-package lines' "$tmp/err"
printf '[install]\nroot "%s"\nnetwork-profile NetworkManager\nnetwork-package %s\nartifact %s\nartifact %s\n' \
    "$identity_root" "$network_digest" "$digest" "$network_digest" > "$tmp/profile-name.conf"
if "$installer" --config "$tmp/profile-name.conf" --plan "$tmp/profile-name.plan" \
    --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
grep -qx "holyinstall: invalid network-profile at $tmp/profile-name.conf:3" "$tmp/err"
printf '[install]\nroot "%s"\nnetwork-package %s\nartifact %s\n' \
    "$identity_root" "$network_digest" "$digest" > "$tmp/profile-artifact.conf"
if "$installer" --config "$tmp/profile-artifact.conf" --plan "$tmp/profile-artifact.plan" \
    --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
grep -qx "holyinstall: network-package $network_digest is not a selected artifact at $tmp/profile-artifact.conf:3" "$tmp/err"
printf '[install]\nroot "%s"\ntimezone ../escape\nartifact %s\n' \
    "$identity_root" "$digest" > "$tmp/zone-shape.conf"
if "$installer" --config "$tmp/zone-shape.conf" --plan "$tmp/zone-shape.plan" \
    --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
grep -qx "holyinstall: invalid timezone at $tmp/zone-shape.conf:3" "$tmp/err"
printf '[install]\nroot "%s"\nlocale en US\nartifact %s\n' \
    "$identity_root" "$digest" > "$tmp/locale-shape.conf"
if "$installer" --config "$tmp/locale-shape.conf" --plan "$tmp/locale-shape.plan" \
    --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 2; fi
grep -qxF "holyinstall: $tmp/locale-shape.conf:3: locale expects 1 argument(s)" "$tmp/err"
# a profile that lost its packages, or lost its name, is not a shorter plan
sed '/^network-package /d' "$tmp/identity.plan" > "$tmp/identity-short.plan"
if "$installer" --apply "$tmp/identity-short.plan" --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -qx 'holyinstall: plan inputs changed or invalid' "$tmp/err"
sed '/^network-profile /d' "$tmp/identity.plan" > "$tmp/identity-noname.plan"
if "$installer" --apply "$tmp/identity-noname.plan" --holypkg "$holypkg" > "$tmp/out" 2> "$tmp/err"; then exit 1; fi
grep -qx 'holyinstall: plan inputs changed or invalid' "$tmp/err"
printf 'installer plan and apply fixtures passed\n'
