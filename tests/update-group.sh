#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
#trap
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
    rm -rf "$tree"
    mkdir -p "$tree/HOLY" "$tree/DATA/usr/share"
    printf 'format holy-package-1\nname %s\nversion %s\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' "$name" "$label" > "$tree/HOLY/meta"
    for field in deps provides hooks origin transform; do : > "$tree/HOLY/$field"; done
    if test -n "$dependency"; then
        printf 'require dep-1 %s package %s any any any - %s metadata\n' "$name" "$dependency" "$dependency" > "$tree/HOLY/deps"
    fi
    printf '%s\n' "$label" > "$tree/DATA/usr/share/$path"
    "$bin" manifest generate "$tree" --output "$tmp/files" > "$tmp/out"
    mv "$tmp/files" "$tree/HOLY/files"
    "$bin" pack "$tree" --output "$tmp/$label.holy" > "$tmp/out"
    "$bin" cache stage "local:$tmp/$label.holy" --root "$root" > "$tmp/out"
}
hash() { sha256sum "$tmp/$1.holy" | cut -d ' ' -f 1; }
set_hash() { sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out"; }
update_hash() { sed -n 's/^plan-update sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out"; }
install() {
    expect 0 "$bin" db plan-set "$@" --root "$root"
    plan=$(set_hash)
    test "${#plan}" -eq 64
    expect 0 "$bin" db apply-set "$plan" "$@" --root "$root"
}
"$bin" db init --root "$root" > "$tmp/out"
package one1 one one ''
package one2 one one ''
package two1 two two ''
package two2 two two ''
package other other other ''
one_old=$(hash one1) one_new=$(hash one2)
two_old=$(hash two1) two_new=$(hash two2)
other=$(hash other)
install "$other"
install "$one_old"
install "$two_old"
# two slots are one plan, one journal and one generation
expect 0 "$bin" db plan-update "$one_old" "$one_new" "$two_old" "$two_new" --root "$root"
grep -qx "format holy-update-plan-2" "$tmp/plan-2" 2>/dev/null && exit 1
cp "$tmp/out" "$tmp/group-plan"
grep -qx "format holy-update-plan-2" "$tmp/group-plan"
grep -qx "replacement 2" "$tmp/group-plan"
grep -qx "pair $one_old $one_new" "$tmp/group-plan"
grep -qx "pair $two_old $two_new" "$tmp/group-plan"
grep -qx "plan-update sha256 $(sed -n 's/^plan-update sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out") read-only" "$tmp/out"
approved=$(update_hash)
test "${#approved}" -eq 64
# the group is one decision, so a wrong hash changes nothing
expect 3 "$bin" db apply-update "$(printf '%064d' 0)" "$one_old" "$one_new" \
    "$two_old" "$two_new" --root "$root"
test -d "$root/var/lib/holypkg/installed/$one_old"
test -d "$root/var/lib/holypkg/installed/$two_old"
expect 2 "$bin" db apply-update "$approved" "$one_old" "$one_new" \
    "$two_old" --root "$root"
# a slot that replaces itself is a decision, and a pair that names something else is
# a shape this command does not take
expect 3 "$bin" db apply-update "$approved" "$one_old" "$one_new" \
    "$two_old" "$two_new" "$other" "$other" --root "$root"
expect 0 "$bin" db apply-update "$approved" "$one_old" "$one_new" \
    "$two_old" "$two_new" --root "$root"
grep -qx "updated $one_old to $one_new generation $(cat "$root/var/lib/holypkg/generation") plan $approved" "$tmp/out"
grep -qx "updated $two_old to $two_new generation $(cat "$root/var/lib/holypkg/generation") plan $approved" "$tmp/out"
grep -qx "updated-group slots 2 generation $(cat "$root/var/lib/holypkg/generation") plan $approved" "$tmp/out"
test ! -d "$root/var/lib/holypkg/installed/$one_old"
test -d "$root/var/lib/holypkg/installed/$one_new"
test -d "$root/var/lib/holypkg/installed/$two_new"
grep -qx one2 "$root/usr/share/one"
grep -qx two2 "$root/usr/share/two"
grep -qx "$approved" "$root/var/lib/holypkg/transactions/$approved/committed"
expect 0 "$bin" db check --all --root "$root"
# the journal names both slots and the decision it was reviewed with
grep -qx "format holy-update-journal-7" "$root/var/lib/holypkg/transactions/$approved/journal"
grep -qx "phase committed" "$root/var/lib/holypkg/transactions/$approved/journal"
grep -qx "replacement 2" "$root/var/lib/holypkg/transactions/$approved/journal"
grep -qx "pair $one_old $one_new" "$root/var/lib/holypkg/transactions/$approved/journal"
grep -qx "pair $two_old $two_new" "$root/var/lib/holypkg/transactions/$approved/journal"
grep -qx "plan $approved" "$root/var/lib/holypkg/transactions/$approved/journal"
# the retained record is one transaction the report states as such
expect 0 "$bin" db transactions --root "$root"
cp "$tmp/out" "$tmp/transactions"
# the record names the generation it planned at, which is the one before the swap
want="transaction $approved kind update generation $(($(cat "$root/var/lib/holypkg/generation") - 1)) replacements 2 pair $one_old $one_new pair $two_old $two_new decisions 0"
if ! grep -qxF "$want" "$tmp/transactions"; then
    printf 'WANT %s\n' "$want" >&2
    grep 'kind update' "$tmp/transactions" >&2
    exit 1
fi
# the reverse of the group restores both slots as one transaction
expect 0 "$bin" rollback "$approved" --root "$root"
reverse=$(sed -n 's/^rollback-plan .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
test "${#reverse}" -eq 64
grep -qx "rollback-pair transaction $approved current $one_new target $one_old" "$tmp/out"
grep -qx "rollback-pair transaction $approved current $two_new target $two_old" "$tmp/out"
expect 0 "$bin" rollback "$approved" --root "$root" --apply "$reverse"
grep -qx "rollback $approved restored 2 artifacts" "$tmp/out"
test -d "$root/var/lib/holypkg/installed/$one_old"
test ! -d "$root/var/lib/holypkg/installed/$one_new"
grep -qx one1 "$root/usr/share/one"
grep -qx two1 "$root/usr/share/two"
expect 0 "$bin" db check --all --root "$root"
# one slot of a group is still an ordinary single-slot plan and journal
expect 0 "$bin" db plan-update "$one_old" "$one_new" --root "$root"
single=$(update_hash)
grep -qx "old $one_old" "$tmp/out"
if grep -qx "replacement 1" "$tmp/out"; then exit 1; fi
expect 0 "$bin" db apply-update "$single" "$one_old" "$one_new" --root "$root"
grep -qx "format holy-update-journal-2" "$root/var/lib/holypkg/transactions/$single/journal"
grep -qx "phase committed" "$root/var/lib/holypkg/transactions/$single/journal"
expect 0 "$bin" db check --all --root "$root"
# a slot that replaces itself is a decision, a pair list that names one artifact twice
# or leaves a pair half-named is a shape this command does not take, and a new artifact
# the root already has is a conflict rather than a slot
expect 3 "$bin" db plan-update "$one_new" "$one_new" "$two_old" "$two_new" --root "$root"
expect 2 "$bin" db plan-update "$one_new" "$two_new" "$two_old" "$two_new" --root "$root"
expect 2 "$bin" db plan-update "$one_new" "$two_new" "$two_old" --root "$root"
expect 2 "$bin" db plan-update "$one_new" "$two_new" "$(printf '%064d' 0)" "$two_new" --root "$root"
expect 4 "$bin" db plan-update "$one_new" "$two_new" --root "$root"
printf 'grouped replacement fixtures passed\n'