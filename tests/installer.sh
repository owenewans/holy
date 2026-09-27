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
printf 'installer plan and apply fixtures passed\n'
