#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/root"
tree="$tmp/tree"
mkdir -p "$root/usr/share"
expect() {
    expected=$1
    shift
    if "$@" > "$tmp/out" 2> "$tmp/err"; then actual=0; else actual=$?; fi
    test "$actual" -eq "$expected" || { cat "$tmp/out" "$tmp/err"; exit 1; }
}
package() {
    label=$1 name=$2 path=$3 dependency=$4
    mkdir -p "$tree/$label/HOLY" "$tree/$label/DATA/usr/share"
    printf 'format holy-package-1\nname %s\nversion %s\nrelease 1\nos linux\narch noarch\nlibc nolibc\nsource-name forged\n' "$name" "$label" > "$tree/$label/HOLY/meta"
    for field in deps provides hooks origin transform; do : > "$tree/$label/HOLY/$field"; done
    if test -n "$dependency"; then
        printf 'require dep-1 %s package %s any any any - %s metadata\n' "$name" "$dependency" "$dependency" > "$tree/$label/HOLY/deps"
    fi
    if test "${5:-file}" = link; then
        ln -s app "$tree/$label/DATA/usr/share/$path"
    else
        printf '%s\n' "$label" > "$tree/$label/DATA/usr/share/$path"
    fi
    "$bin" manifest generate "$tree/$label" --output "$tmp/files" > "$tmp/out"
    if test "${6:-}" = config; then
        sed '/^file /s/ none - / config - /' "$tmp/files" > "$tmp/config-files"
        mv "$tmp/config-files" "$tmp/files"
    fi
    mv "$tmp/files" "$tree/$label/HOLY/files"
    "$bin" pack "$tree/$label" --output "$tmp/$label.holy" > "$tmp/out"
    "$bin" cache stage "local:$tmp/$label.holy" --root "$root" > "$tmp/out"
}
hash() { sha256sum "$tmp/$1.holy" | cut -d ' ' -f 1; }
set_hash() { sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out"; }
install() {
    expect 0 "$bin" db plan-set "$@" --root "$root"
    plan=$(set_hash)
    expect 0 "$bin" db apply-set "$plan" "$@" --root "$root"
}
register() {
    expect 0 "$bin" source plan --config "$tmp/config" --root "$root"
    cp "$tmp/out" "$tmp/source-plan"
    digest=$(sha256sum "$tmp/source-plan" | cut -d ' ' -f 1)
    expect 0 "$bin" source apply "$tmp/source-plan" --sha256 "$digest" --root "$root"
}
"$bin" db init --root "$root" > "$tmp/out"
package base1 base payload ''
package base2 base payload ''
package app app app base
package extra extra extra ''
package missing base payload absent
package collision base extra ''
package rename other payload ''
package moved base relocated ''
package linked base payload '' link
old=$(hash base1) new=$(hash base2) app=$(hash app) extra=$(hash extra)
install "$app" "$old"
install "$extra"
expect 0 "$bin" db plan-update "$old" "$new" --root "$root"
cp "$tmp/out" "$tmp/plan"
reserved=$(awk '$1 == "change" && $3 == "replace" {print $2; exit}' "$tmp/plan")
printf 'unowned\n' > "$root/usr/share/.holy-update-$reserved"
expect 4 "$bin" db apply-update "$(sed -n 's/^plan-update sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/plan")" "$old" "$new" --root "$root"
grep -qx unowned "$root/usr/share/.holy-update-$reserved"
test ! -e "$root/var/lib/holypkg/transactions/update"
rm "$root/usr/share/.holy-update-$reserved"
expect 0 "$bin" db plan-update "$old" "$new" --root "$root"
cmp "$tmp/plan" "$tmp/out"
python3 - "$tmp/plan" "$old" "$new" "$app" "$extra" <<'PY'
import hashlib, pathlib, shlex, sys
data = pathlib.Path(sys.argv[1]).read_bytes()
header, record = data.split(b'\n', 1)
assert header.decode().split() == ['plan-update', 'sha256', hashlib.sha256(record).hexdigest(), 'read-only']
rows = [shlex.split(line) for line in record.decode().splitlines()]
old, new, app, extra = sys.argv[2:]
assert ['old', old] in rows and ['new', new] in rows
assert ['source', '-', 'local'] in rows
assert {r[1] for r in rows if r[0] == 'instance'} == {old, app, extra}
assert {r[1] for r in rows if r[0] == 'artifact'} == {new, app, extra}
assert ['edge', app, 'dep-1', new, '-', 'package', 'base'] in rows
assert any(r[0] == 'change' and r[2] == 'replace' for r in rows)
PY
grep -qx base1 "$root/usr/share/payload"
expect 0 "$bin" db check --all --root "$root"
expect 4 "$bin" db plan-update "$old" "$(hash missing)" --root "$root"
test ! -s "$tmp/out"
expect 4 "$bin" db plan-update "$old" "$(hash collision)" --root "$root"
expect 4 "$bin" db plan-update "$old" "$(hash rename)" --root "$root"
expect 3 "$bin" db plan-update "$old" "$old" --root "$root"
expect 6 "$bin" db plan-update "$new" "$old" --root "$root"
expect 2 "$bin" db plan-update invalid "$new" --root "$root"
printf 'user change\n' > "$root/usr/share/payload"
expect 4 "$bin" db plan-update "$old" "$new" --root "$root"
printf 'base1\n' > "$root/usr/share/payload"
printf 'user change\n' > "$root/usr/share/extra"
expect 4 "$bin" db plan-update "$old" "$new" --root "$root"
printf 'extra\n' > "$root/usr/share/extra"
expect 0 "$bin" db reserve "$new" --root "$root"
expect 5 "$bin" db plan-update "$old" "$new" --root "$root"
expect 0 "$bin" db cancel --root "$root"
cache="$root/var/cache/holypkg/objects/sha256"
mv "$cache/$old.holy" "$tmp/old-cache"
expect 6 "$bin" db plan-update "$old" "$new" --root "$root"
mv "$tmp/old-cache" "$cache/$old.holy"
expect 0 "$bin" db plan-update "$old" "$new" --root "$root"
cmp "$tmp/plan" "$tmp/out"
mkdir -p "$tmp/second/usr/share"
cp -a "$root/." "$tmp/second/"
expect 0 "$bin" db plan-update "$old" "$new" --root "$tmp/second"
if cmp -s "$tmp/plan" "$tmp/out"; then exit 1; fi
copy_root="$tmp/second"
update_hash() { sed -n 's/^plan-update sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out"; }
approved=$(sed -n 's/^plan-update sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/plan")
expect 3 "$bin" db apply-update "$approved" "$old" "$new" --root "$copy_root"
replace() {
    expect 0 "$bin" db plan-update "$1" "$2" --root "$copy_root"
    approved=$(update_hash)
    expect 0 "$bin" db apply-update "$approved" "$1" "$2" --root "$copy_root"
    expect 0 "$bin" db status --root "$copy_root"
    expect 0 "$bin" db check --all --root "$copy_root"
    test ! -d "$copy_root/var/lib/holypkg/installed/$1"
    test -d "$copy_root/var/lib/holypkg/installed/$2"
    grep -qx "$approved" "$copy_root/var/lib/holypkg/transactions/$approved/committed"
    grep -qx 'reason dependency' "$copy_root/var/lib/holypkg/installed/$2/state"
    expect 0 "$bin" orphan --root "$copy_root" --json
}
replace "$old" "$new"
grep -qx base2 "$copy_root/usr/share/payload"
grep -q "\"$new\"" "$copy_root/var/lib/holypkg/installed/$app/graph"
if grep -q "\"$old\"" "$copy_root/var/lib/holypkg/installed/$app/graph"; then exit 1; fi
rollback_root="$tmp/rollback-root"
mkdir "$rollback_root"
cp -a "$copy_root/." "$rollback_root/"
expect 0 "$bin" rollback "$approved" --root "$rollback_root"
rollback_plan=$(sed -n 's/^rollback-plan .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
test "${#rollback_plan}" -eq 64
grep -qx "old $new" "$tmp/out"
grep -qx "new $old" "$tmp/out"
transaction_dir="$rollback_root/var/lib/holypkg/transactions/$approved"
cp "$transaction_dir/journal" "$tmp/rollback-journal"
printf 'forged\n' > "$transaction_dir/journal"
expect 2 "$bin" rollback "$approved" --root "$rollback_root"
cp "$tmp/rollback-journal" "$transaction_dir/journal"
cp "$transaction_dir/plan" "$tmp/rollback-source-plan"
printf 'forged\n' > "$transaction_dir/plan"
expect 2 "$bin" rollback "$approved" --root "$rollback_root"
cp "$tmp/rollback-source-plan" "$transaction_dir/plan"
expect 3 "$bin" rollback "$approved" --root "$rollback_root" --apply "$approved"
grep -qx base2 "$rollback_root/usr/share/payload"
expect 0 "$bin" rollback "$approved" --root "$rollback_root" --apply "$rollback_plan"
grep -qx base1 "$rollback_root/usr/share/payload"
expect 0 "$bin" db check --all --root "$rollback_root"
test -d "$rollback_root/var/lib/holypkg/installed/$old"
test ! -d "$rollback_root/var/lib/holypkg/installed/$new"
expect 6 "$bin" rollback "$approved" --root "$rollback_root"
expect 2 "$bin" rollback invalid --root "$rollback_root"
expect 3 "$bin" db rm "$new" --root "$copy_root"
replace "$new" "$(hash moved)"
test ! -e "$copy_root/usr/share/payload"
grep -qx moved "$copy_root/usr/share/relocated"
replace "$(hash moved)" "$(hash linked)"
test ! -e "$copy_root/usr/share/relocated"
test "$(readlink "$copy_root/usr/share/payload")" = app
replace "$(hash linked)" "$old"
grep -qx base1 "$copy_root/usr/share/payload"
expect 0 "$bin" db rm "$extra" --root "$copy_root"
expect 0 "$bin" db check --all --root "$copy_root"
if "$bin" elf "$bin" | grep -q '^interpreter /'; then
    gcc -shared -fPIC -o "$tmp/update-fault.so" "$(dirname "$0")/update-fault.c" -ldl
    fault_client=dynamic
elif test "${HOLY_TEST_STATIC_UPDATE_FAULT:-0}" = 1; then
    fault_client=static
else
    fault_client=skip
    printf 'update fault injection skipped for uninstrumented static client\n'
fi
if test "$fault_client" != skip; then
    for phase in intent-after payload-before payload-after database-before database-after generation-after committed no-space staging-partial; do
        copy_root="$tmp/fault-$phase"
        mkdir "$copy_root"
        cp -a "$root/." "$copy_root/"
        expect 0 "$bin" db plan-update "$old" "$new" --root "$copy_root"
        approved=$(update_hash)
        if test "$fault_client" = dynamic; then
            if env LD_PRELOAD="$tmp/update-fault.so" HOLY_UPDATE_FAULT="$phase" HOLY_UPDATE_NEW="$new" \
                "$bin" db apply-update "$approved" "$old" "$new" --root "$copy_root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else code=$?; fi
        else
            if env HOLY_UPDATE_FAULT="$phase" HOLY_UPDATE_NEW="$new" \
                "$bin" db apply-update "$approved" "$old" "$new" --root "$copy_root" > "$tmp/out" 2> "$tmp/err"; then exit 1; else code=$?; fi
        fi
        if test "$phase" = no-space; then test "$code" -eq 5; else test "$code" -eq 137; fi
        expect 5 "$bin" db status --root "$copy_root"
        expect 5 "$bin" db reserve "$extra" --root "$copy_root"
        for blocked in cancel preflight plan recheck apply; do
            expect 5 "$bin" db "$blocked" --root "$copy_root"
        done
        expect 5 "$bin" db approve "$approved" --root "$copy_root"
        expect 5 "$bin" db check --all --root "$copy_root"
        expect 5 "$bin" db plan-set "$extra" --root "$copy_root"
        if test "$phase" = staging-partial; then
            grep -qx base1 "$copy_root/usr/share/payload"
            expect 5 "$bin" db recover --update --root "$copy_root"
            grep -q 'reserved update object requires inspection' "$tmp/err"
            test "$(find "$copy_root/usr/share" -name '.holy-update-*' | wc -l)" -eq 1
            find "$copy_root/usr/share" -name '.holy-update-*' -type f -delete
        fi
        expect 0 "$bin" db recover --update --root "$copy_root"
        expect 0 "$bin" db status --root "$copy_root"
        expect 0 "$bin" db check --all --root "$copy_root"
        expect 0 "$bin" orphan --root "$copy_root" --json
        grep -qx base2 "$copy_root/usr/share/payload"
        test ! -d "$copy_root/var/lib/holypkg/installed/$old"
        grep -qx "$approved" "$copy_root/var/lib/holypkg/transactions/$approved/committed"
        test "$(find "$copy_root/usr/share" -name '.holy-update-*' | wc -l)" -eq 0
    done
fi
cat > "$tmp/config" <<'EOF'
[source official]
type holy-http
url https://source.example/holy
EOF
register
expect 0 "$bin" source list --root "$root"
source=$(sed -n 's/^source \([0-9a-f]*\) "official" active$/\1/p' "$tmp/out")
package sourced1 sourced sourced ''
package sourced2 sourced sourced ''
first=$(hash sourced1) second=$(hash sourced2)
install "$first" --source "$first=$source"
expect 0 "$bin" db plan-update "$first" "$second" --root "$root"
cp "$tmp/out" "$tmp/sourced-plan"
grep -qx "source $source \"official\"" "$tmp/out"
sed 's/source official/source renamed/' "$tmp/config" > "$tmp/renamed"
mv "$tmp/renamed" "$tmp/config"
register
expect 0 "$bin" db plan-update "$first" "$second" --root "$root"
grep -qx "source $source \"renamed\"" "$tmp/out"
if cmp -s "$tmp/sourced-plan" "$tmp/out"; then exit 1; fi
: > "$tmp/config"
register
expect 6 "$bin" db plan-update "$first" "$second" --root "$root"
expect 0 "$bin" db check --all --root "$root"
cat > "$tmp/config" <<'EOF'
[source renamed]
type holy-http
url https://source.example/holy
EOF
register
expect 0 "$bin" db plan-update "$first" "$second" --root "$root"
approved=$(update_hash)
expect 0 "$bin" db apply-update "$approved" "$first" "$second" --root "$root"
grep -qx "source-id $source" "$root/var/lib/holypkg/installed/$second/state"
grep -qx "source $source \"renamed\"" "$root/var/lib/holypkg/installed/$second/source"
grep -qx 'reason explicit' "$root/var/lib/holypkg/installed/$second/state"
expect 0 "$bin" db check --all --root "$root"
: > "$tmp/config"
register
expect 0 "$bin" db check --all --root "$root"
package config1 settings holy.conf '' file config
package config2 settings holy.conf '' file config
package config3 settings holy.conf '' file config
config_old=$(hash config1) config_new=$(hash config2) config_third=$(hash config3)
install "$config_old"
expect 0 "$bin" db plan-update "$config_old" "$config_new" --root "$root"
grep -q ' config$' "$tmp/out"
printf 'local edit\n' > "$root/usr/share/holy.conf"
expect 4 "$bin" db check "$config_old" --root "$root" --json
grep -q 'changed-config' "$tmp/out"
expect 0 "$bin" db plan-update "$config_old" "$config_new" --root "$root"
grep -q 'usr/share/holy.conf.holy-new' "$tmp/out"
config_plan=$(update_hash)
printf 'changed after preview\n' > "$root/usr/share/holy.conf"
expect 3 "$bin" db apply-update "$config_plan" "$config_old" "$config_new" --root "$root"
test ! -e "$root/usr/share/holy.conf.holy-new"
printf 'local edit\n' > "$root/usr/share/holy.conf"
if test "$fault_client" != skip; then
    config_fault="$tmp/config-fault"
    mkdir "$config_fault"
    cp -a "$root/." "$config_fault/"
    expect 0 "$bin" db plan-update "$config_old" "$config_new" --root "$config_fault"
    fault_plan=$(update_hash)
    if test "$fault_client" = dynamic; then
        if env LD_PRELOAD="$tmp/update-fault.so" HOLY_UPDATE_FAULT=database-before HOLY_UPDATE_NEW="$config_new" \
            "$bin" db apply-update "$fault_plan" "$config_old" "$config_new" --root "$config_fault" > "$tmp/out" 2> "$tmp/err"; then exit 1; else code=$?; fi
    else
        if env HOLY_UPDATE_FAULT=database-before HOLY_UPDATE_NEW="$config_new" \
            "$bin" db apply-update "$fault_plan" "$config_old" "$config_new" --root "$config_fault" > "$tmp/out" 2> "$tmp/err"; then exit 1; else code=$?; fi
    fi
    test "$code" -eq 137
    expect 5 "$bin" db status --root "$config_fault"
    expect 0 "$bin" db recover --update --root "$config_fault"
    grep -qx 'local edit' "$config_fault/usr/share/holy.conf"
    grep -qx config2 "$config_fault/usr/share/holy.conf.holy-new"
    expect 0 "$bin" db check --all --root "$config_fault"
fi
expect 0 "$bin" db apply-update "$config_plan" "$config_old" "$config_new" --root "$root"
grep -qx 'local edit' "$root/usr/share/holy.conf"
grep -qx config2 "$root/usr/share/holy.conf.holy-new"
expect 0 "$bin" db check --all --root "$root"
expect 0 "$bin" db owner usr/share/holy.conf.holy-new --root "$root"
grep -qx "$config_new file usr/share/holy.conf.holy-new" "$tmp/out"
expect 0 "$bin" db plan-update "$config_new" "$config_third" --root "$root"
config_plan=$(update_hash)
expect 0 "$bin" db apply-update "$config_plan" "$config_new" "$config_third" --root "$root"
grep -qx 'local edit' "$root/usr/share/holy.conf"
grep -qx config3 "$root/usr/share/holy.conf.holy-new"
expect 0 "$bin" db check --all --root "$root"
expect 6 "$bin" db repair-plan "$config_third" --root "$root"
test ! -e "$root/var/lib/holypkg/transactions/journal"
expect 0 "$bin" db plan-update "$old" "$new" --root "$root"
base_plan=$(update_hash)
expect 0 "$bin" db apply-update "$base_plan" "$old" "$new" --root "$root"
grep -qx 'local edit' "$root/usr/share/holy.conf"
grep -qx config3 "$root/usr/share/holy.conf.holy-new"
expect 0 "$bin" db check --all --root "$root"
expect 0 "$bin" db rm "$config_third" --root "$root"
grep -qx 'local edit' "$root/usr/share/holy.conf"
test ! -e "$root/usr/share/holy.conf.holy-new"
expect 6 "$bin" db owner usr/share/holy.conf --root "$root"
expect 0 "$bin" db check --all --root "$root"
printf 'update transaction fixtures passed\n'
