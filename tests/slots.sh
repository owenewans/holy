#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/root"
tree="$tmp/tree"
mkdir -p "$root/usr/share"
expect() {
    wanted=$1
    shift
    if "$@" > "$tmp/out" 2> "$tmp/err"; then actual=0; else actual=$?; fi
    test "$actual" -eq "$wanted" || { cat "$tmp/out" "$tmp/err"; exit 1; }
}
plan() { sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out"; }
plan_set() {
    expect 0 "$bin" db plan-set "$@" --root "$root"
    approved=$(plan)
    expect 0 "$bin" db apply-set "$approved" "$@" --root "$root"
}

# one package tree per label, with the name, version, architecture and libc the case needs
package() {
    label=$1 name=$2 version=$3 arch=$4 libc=$5
    rm -rf "$tree"
    mkdir -p "$tree/HOLY" "$tree/DATA/usr/share"
    printf 'format holy-package-1\nname %s\nversion %s\nrelease 1\nos linux\narch %s\nlibc %s\n' \
        "$name" "$version" "$arch" "$libc" > "$tree/HOLY/meta"
    for field in deps provides hooks origin transform; do : > "$tree/HOLY/$field"; done
    printf '%s\n' "$label" > "$tree/DATA/usr/share/$label"
    "$bin" manifest generate "$tree" --output "$tmp/files" > "$tmp/out"
    mv "$tmp/files" "$tree/HOLY/files"
    "$bin" pack "$tree" --output "$tmp/$label.holy" > "$tmp/out"
    "$bin" cache stage "local:$tmp/$label.holy" --root "$root" > "$tmp/out"
    sha256sum "$tmp/$label.holy" | cut -d ' ' -f 1
}

"$bin" db init --root "$root" > "$tmp/out"
tool=$(package tool tool 1 noarch nolibc)
tool_next=$(package tool-x86_64 tool 1 x86_64 musl)
library=$(package library library 1 noarch nolibc)

# a root with nothing installed has no slots, and says so in both forms
expect 0 "$bin" db slots --root "$root"
test ! -s "$tmp/out"
expect 0 "$bin" db slots --root "$root" --json
grep -qxF '{"schema":"holy-db-slots-1","slots":[]}' "$tmp/out"

# two names are two slots
plan_set "$tool"
plan_set "$library"
expect 0 "$bin" db slots --root "$root"
grep -qx "slot library linux noarch nolibc source - occupied $library version 1 versions 1" "$tmp/out"
grep -qx "slot tool linux noarch nolibc source - occupied $tool version 1 versions 1" "$tmp/out"
expect 0 "$bin" db slots --root "$root" --json
grep -q -F '"schema":"holy-db-slots-1"' "$tmp/out"
test "$(grep -o -F '"name":"tool"' "$tmp/out" | wc -l)" -eq 1

# the source is part of the slot, so one name from two sources holds two slots
printf '[source alpha]\ntype holy-http\nurl "file://%s/mirror/"\n' "$tmp" > "$tmp/alpha.conf"
"$bin" source plan --config "$tmp/alpha.conf" --root "$root" > "$tmp/alpha.plan" 2> "$tmp/alpha.err"
alpha_plan=$(sha256sum "$tmp/alpha.plan" | cut -d ' ' -f 1)
alpha_source=$(sed -n 's/^add-source \([0-9a-f]*\) "alpha"$/\1/p' "$tmp/alpha.err")
test "${#alpha_source}" -eq 64
"$bin" source apply "$tmp/alpha.plan" --sha256 "$alpha_plan" --root "$root" > "$tmp/out"
expect 0 "$bin" db plan-set "$tool_next" --source "$tool_next=$alpha_source" --root "$root"
approved=$(plan)
expect 0 "$bin" db apply-set "$approved" "$tool_next" --source "$tool_next=$alpha_source" --root "$root"
expect 0 "$bin" db slots --root "$root"
grep -qx "slot tool linux x86_64 musl source $alpha_source occupied $tool_next version 1 versions 1" "$tmp/out"
grep -qx "slot tool linux noarch nolibc source - occupied $tool version 1 versions 1" "$tmp/out"
expect 0 "$bin" db slots --root "$root" --json
test "$(grep -o -F '"name":"tool"' "$tmp/out" | wc -l)" -eq 2
expect 0 "$bin" db check --all --root "$root"

# a replacement moves the slot: the family holds one version and the newest occupant
newer=$(package tool2 tool 2 noarch nolibc)
expect 0 "$bin" db plan-update "$tool" "$newer" --root "$root"
replacement=$(sed -n 's/^plan-update sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
test "${#replacement}" -eq 64
expect 0 "$bin" db apply-update "$replacement" "$tool" "$newer" --root "$root"
expect 0 "$bin" db slots --root "$root"
grep -qx "slot tool linux noarch nolibc source - occupied $newer version 2 versions 1" "$tmp/out"
test ! -d "$root/var/lib/holypkg/installed/$tool"
expect 0 "$bin" db check --all --root "$root"

# the slot a replacement moved keeps its arch and libc, so the report is stable
expect 0 "$bin" db slots --root "$root" --json
grep -q -F "\"occupied\":\"$newer\"" "$tmp/out"
grep -q -F "\"occupied\":\"$tool_next\"" "$tmp/out"

# a named source reports what its bound catalog offers for the slots it occupies, so a
# version family is read against the index the source publishes
repo="$tmp/repo"
mkdir -p "$repo"
offered_version() {
    version=$1
    rm -rf "$tree"
    mkdir -p "$tree/HOLY" "$tree/DATA/usr/share"
    printf 'format holy-package-1\nname offered\nversion %s\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' \
        "$version" > "$tree/HOLY/meta"
    for field in deps provides hooks origin transform; do : > "$tree/HOLY/$field"; done
    printf 'offered %s\n' "$version" > "$tree/DATA/usr/share/offered"
    "$bin" manifest generate "$tree" --output "$tmp/files" > "$tmp/out"
    mv "$tmp/files" "$tree/HOLY/files"
    rm -f "$repo/offered.holy"
    "$bin" pack "$tree" --output "$repo/offered.holy" > "$tmp/out"
    "$bin" repo index "$repo" > "$tmp/out"
    "$bin" repo seal "$repo" > "$tmp/out"
    sed -n 's/^sha256 //p' "$repo/current"
}
catalog_root="$tmp/catalog-root"
mkdir "$catalog_root"
"$bin" db init --root "$catalog_root" > "$tmp/out"
printf '[source offered]\ntype holy-http\nurl "https://fixture.example/holy/"\n' \
    > "$tmp/offered.conf"
"$bin" source plan --config "$tmp/offered.conf" --root "$catalog_root" > "$tmp/offered.plan" 2> "$tmp/offered.err"
offered_plan=$(sha256sum "$tmp/offered.plan" | cut -d ' ' -f 1)
offered_source=$(sed -n 's/^add-source \([0-9a-f]*\) "offered"$/\1/p' "$tmp/offered.err")
test "${#offered_source}" -eq 64
"$bin" source apply "$tmp/offered.plan" --sha256 "$offered_plan" --root "$catalog_root" > "$tmp/out"
offer_index=$(offered_version 1)
test "${#offer_index}" -eq 64
installed_one=$(sha256sum "$repo/offered.holy" | cut -d ' ' -f 1)
printf 'format holy-mirror-1\nurl "https://fixture.example/holy/"\nindex-sha256 %s\nverification digest-pinned-unsigned\nsource-id %s\n' \
    "$offer_index" "$offered_source" > "$repo/mirror-origin"
"$bin" source catalog bind offered "$repo" --root "$catalog_root" > "$tmp/out"
expect 0 "$bin" add offered:offered --root "$catalog_root" --yes > "$tmp/out"
expect 0 "$bin" db slots --root "$catalog_root"
grep -qx "slot offered linux noarch nolibc source $offered_source occupied $installed_one version 1 versions 1" "$tmp/out"
# the catalog offers nothing newer yet, so the report says so rather than guessing
expect 0 "$bin" db slots --root "$catalog_root" --source "$offered_source"
grep -qx "slot offered linux noarch nolibc source $offered_source occupied $installed_one version 1 versions 1 available - version -" "$tmp/out"

# a new generation of the catalog makes a newer member of the family visible
offer_index=$(offered_version 2)
test "${#offer_index}" -eq 64
printf 'format holy-mirror-1\nurl "https://fixture.example/holy/"\nindex-sha256 %s\nverification digest-pinned-unsigned\nsource-id %s\n' \
    "$offer_index" "$offered_source" > "$repo/mirror-origin"
expect 0 "$bin" source catalog bind offered "$repo" --root "$catalog_root" > "$tmp/out"
offered_two=$(sha256sum "$repo/offered.holy" | cut -d ' ' -f 1)
test "$offered_two" != "$installed_one"
expect 0 "$bin" db slots --root "$catalog_root" --source "$offered_source"
grep -qx "slot offered linux noarch nolibc source $offered_source occupied $installed_one version 1 versions 1 available $offered_two version 2" "$tmp/out"
expect 0 "$bin" db slots --root "$catalog_root" --source "$offered_source" --json
grep -q -F "\"available\":\"$offered_two\"" "$tmp/out"
grep -q -F "\"available-version\":\"2\"" "$tmp/out"
# a source that is not asked about adds nothing to the line
expect 0 "$bin" db slots --root "$catalog_root"
if grep -q available "$tmp/out"; then exit 1; fi
# the installed set is untouched by the report
expect 0 "$bin" db check --all --root "$catalog_root"

# a family that writes an epoch orders its own members, and the generic comparator
# refuses such a version, so a slot report has to compare with the family it declares
epoch_version() {
    version=$1
    epoch_family=${2:-pacman}
    rm -rf "$tree"
    mkdir -p "$tree/HOLY" "$tree/DATA/usr/share"
    printf 'format holy-package-1\nname epoched\nversion %s\nrelease 1\nos linux\narch noarch\nlibc nolibc\nx-version-family %s\n' \
        "$version" "$epoch_family" > "$tree/HOLY/meta"
    for field in deps provides hooks origin transform; do : > "$tree/HOLY/$field"; done
    printf 'epoched %s\n' "$version" > "$tree/DATA/usr/share/epoched"
    "$bin" manifest generate "$tree" --output "$tmp/files" > "$tmp/out"
    mv "$tmp/files" "$tree/HOLY/files"
    rm -f "$epoch_repo/epoched.holy"
    "$bin" pack "$tree" --output "$epoch_repo/epoched.holy" > "$tmp/out"
    "$bin" repo index "$epoch_repo" > "$tmp/out"
    "$bin" repo seal "$epoch_repo" > "$tmp/out"
    sed -n 's/^sha256 //p' "$epoch_repo/current"
}
epoch_repo="$tmp/epoch-repo"
mkdir -p "$epoch_repo"
epoch_root="$tmp/epoch-root"
mkdir "$epoch_root"
"$bin" db init --root "$epoch_root" > "$tmp/out"
printf '[source epoched]\ntype holy-http\nurl "https://fixture.example/epoch/"\n' > "$tmp/epoch.conf"
"$bin" source plan --config "$tmp/epoch.conf" --root "$epoch_root" > "$tmp/epoch.plan" 2> "$tmp/epoch.err"
epoch_plan=$(sha256sum "$tmp/epoch.plan" | cut -d ' ' -f 1)
epoch_source=$(sed -n 's/^add-source \([0-9a-f]*\) "epoched"$/\1/p' "$tmp/epoch.err")
test "${#epoch_source}" -eq 64
"$bin" source apply "$tmp/epoch.plan" --sha256 "$epoch_plan" --root "$epoch_root" > "$tmp/out"
epoch_index=$(epoch_version 1:2.0-1)
test "${#epoch_index}" -eq 64
epoch_one=$(sha256sum "$epoch_repo/epoched.holy" | cut -d ' ' -f 1)
printf 'format holy-mirror-1\nurl "https://fixture.example/epoch/"\nindex-sha256 %s\nverification digest-pinned-unsigned\nsource-id %s\n' \
    "$epoch_index" "$epoch_source" > "$epoch_repo/mirror-origin"
"$bin" source catalog bind epoched "$epoch_repo" --root "$epoch_root" > "$tmp/out"
expect 0 "$bin" add epoched:epoched --root "$epoch_root" --yes > "$tmp/out"
# the catalog offers nothing newer yet, and an epoch version does not confuse that
expect 0 "$bin" db slots --root "$epoch_root" --source "$epoch_source"
grep -qx "slot epoched linux noarch nolibc source $epoch_source occupied $epoch_one version 1:2.0-1 versions 1 available - version -" "$tmp/out"
epoch_index=$(epoch_version 1:2.0-3)
test "${#epoch_index}" -eq 64
printf 'format holy-mirror-1\nurl "https://fixture.example/epoch/"\nindex-sha256 %s\nverification digest-pinned-unsigned\nsource-id %s\n' \
    "$epoch_index" "$epoch_source" > "$epoch_repo/mirror-origin"
expect 0 "$bin" source catalog bind epoched "$epoch_repo" --root "$epoch_root" > "$tmp/out"
epoch_two=$(sha256sum "$epoch_repo/epoched.holy" | cut -d ' ' -f 1)
test "$epoch_two" != "$epoch_one"
expect 0 "$bin" db slots --root "$epoch_root" --source "$epoch_source"
grep -qx "slot epoched linux noarch nolibc source $epoch_source occupied $epoch_one version 1:2.0-1 versions 1 available $epoch_two version 1:2.0-3" "$tmp/out"
expect 0 "$bin" db slots --root "$epoch_root" --source "$epoch_source" --json
grep -q -F "\"available-version\":\"1:2.0-3\"" "$tmp/out"
# a catalog offer under another family is a different thing rather than a newer member,
# since the family comes from the installed slot, so an rpm offer names nothing for the
# pacman slot above
epoch_index=$(epoch_version 4 rpm)
test "${#epoch_index}" -eq 64
epoch_four=$(sha256sum "$epoch_repo/epoched.holy" | cut -d ' ' -f 1)
test "$epoch_four" != "$epoch_two"
printf 'format holy-mirror-1\nurl "https://fixture.example/epoch/"\nindex-sha256 %s\nverification digest-pinned-unsigned\nsource-id %s\n' \
    "$epoch_index" "$epoch_source" > "$epoch_repo/mirror-origin"
expect 0 "$bin" source catalog bind epoched "$epoch_repo" --root "$epoch_root" > "$tmp/out"
expect 0 "$bin" db slots --root "$epoch_root" --source "$epoch_source"
grep -qx "slot epoched linux noarch nolibc source $epoch_source occupied $epoch_one version 1:2.0-1 versions 1 available - version -" "$tmp/out"
# a root whose slot declares the rpm family reads the catalog with the rpm comparator
rpm_root="$tmp/epoch-rpm-root"
mkdir "$rpm_root"
"$bin" db init --root "$rpm_root" > "$tmp/out"
"$bin" source plan --config "$tmp/epoch.conf" --root "$rpm_root" > "$tmp/rpm.plan" 2> "$tmp/rpm.err"
rpm_plan=$(sha256sum "$tmp/rpm.plan" | cut -d ' ' -f 1)
rpm_source=$(sed -n 's/^add-source \([0-9a-f]*\) "epoched"$/\1/p' "$tmp/rpm.err")
test "${#rpm_source}" -eq 64
"$bin" source apply "$tmp/rpm.plan" --sha256 "$rpm_plan" --root "$rpm_root" > "$tmp/out"
expect 0 "$bin" source catalog bind epoched "$epoch_repo" --root "$rpm_root" > "$tmp/out"
expect 0 "$bin" add epoched:epoched --root "$rpm_root" --yes > "$tmp/out"
rpm_four=$(sha256sum "$epoch_repo/epoched.holy" | cut -d ' ' -f 1)
expect 0 "$bin" db slots --root "$rpm_root" --source "$rpm_source"
grep -qx "slot epoched linux noarch nolibc source $rpm_source occupied $rpm_four version 4 versions 1 available - version -" "$tmp/out"
epoch_index=$(epoch_version 5 rpm)
test "${#epoch_index}" -eq 64
printf 'format holy-mirror-1\nurl "https://fixture.example/epoch/"\nindex-sha256 %s\nverification digest-pinned-unsigned\nsource-id %s\n' \
    "$epoch_index" "$rpm_source" > "$epoch_repo/mirror-origin"
expect 0 "$bin" source catalog bind epoched "$epoch_repo" --root "$rpm_root" > "$tmp/out"
rpm_five=$(sha256sum "$epoch_repo/epoched.holy" | cut -d ' ' -f 1)
test "$rpm_five" != "$rpm_four"
expect 0 "$bin" db slots --root "$rpm_root" --source "$rpm_source"
grep -qx "slot epoched linux noarch nolibc source $rpm_source occupied $rpm_four version 4 versions 1 available $rpm_five version 5" "$tmp/out"
expect 0 "$bin" db check --all --root "$rpm_root"

# a root with no database is reported as unavailable, the same as db status
if "$bin" db slots --root "$tmp/absent" > "$tmp/out" 2> "$tmp/err"; then exit 1; else test "$?" -eq 1; fi
grep -qx 'holypkg: database status unavailable' "$tmp/err"
printf 'installed slot fixtures passed\n'