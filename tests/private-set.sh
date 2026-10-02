#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/root"
tree="$tmp/tree"
mkdir -p "$root/usr/bin" "$tree"

expect() {
    expected=$1
    shift
    if "$@" > "$tmp/out" 2> "$tmp/err"; then actual=0; else actual=$?; fi
    test "$actual" -eq "$expected" || { cat "$tmp/out" "$tmp/err"; exit 1; }
}

# two packages ship the same program name, each with its own content
program() {
    name=$1 content=$2 dependency=$3
    rm -rf "$tree"
    mkdir -p "$tree/HOLY" "$tree/DATA/usr/bin"
    printf 'format holy-package-1\nname %s\nversion 1\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' "$name" > "$tree/HOLY/meta"
    for field in deps provides hooks origin transform; do : > "$tree/HOLY/$field"; done
    if test -n "$dependency"; then
        printf 'require dep-1 %s package %s any any any - %s metadata\n' "$name" "$dependency" "$dependency" > "$tree/HOLY/deps"
    fi
    printf '%s\n' "$content" > "$tree/DATA/usr/bin/prog"
    "$bin" manifest generate "$tree" --output "$tmp/files" > "$tmp/out"
    mv "$tmp/files" "$tree/HOLY/files"
    "$bin" pack "$tree" --output "$tmp/$name.holy" > "$tmp/out"
    "$bin" cache stage "local:$tmp/$name.holy" --root "$root" > "$tmp/out"
}

hash() { sha256sum "$tmp/$1.holy" | cut -d ' ' -f 1; }
plan_hash() { sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out"; }

"$bin" db init --root "$root" > "$tmp/out"
program first one ''
program second two first
first=$(hash first) second=$(hash second)

# the explicit root requires the other artifact, so the set carries both and they ship
# one program name between them
root_artifact=$second
provider=$first

# one public file, two owners: the plan refuses and names the decision it needs
expect 4 "$bin" db plan-set "$root_artifact" "$provider" --root "$root"
grep -q "claim the same path: usr/bin/prog" "$tmp/err"
grep -q -- "--private $provider=usr/bin/prog or --private $second=usr/bin/prog" "$tmp/err"

# a placement for an artifact that is not in the set is still refused by the collision,
# since it does not move either copy aside
expect 4 "$bin" db plan-set "$root_artifact" "$provider" \
    --private "0000000000000000000000000000000000000000000000000000000000000000=usr/bin/prog" \
    --root "$root"

# the review says which of the two copies moves aside, and the plan names where it lands
expect 0 "$bin" db plan-set "$root_artifact" "$provider" \
    --private "$provider=usr/bin/prog" --root "$root"
grep -qx "private $provider usr/bin/prog -> usr/lib/holy/private/$provider/usr/bin/prog scope artifact-path" "$tmp/out"
chosen=$(plan_hash)

# the plan hash does not carry the decision by itself: an apply without the placement
# re-derives the same collision and refuses, since a placement is a review decision
expect 4 "$bin" db apply-set "$chosen" "$root_artifact" "$provider" --root "$root"
test ! -e "$root/usr/bin/prog"
grep -q "claim the same path: usr/bin/prog" "$tmp/err"

expect 0 "$bin" db apply-set "$chosen" "$root_artifact" "$provider" \
    --private "$provider=usr/bin/prog" --root "$root"

# the explicit root keeps the public path and the dependency's copy moves aside
test "$(cat "$root/usr/bin/prog")" = two
test "$(cat "$root/usr/lib/holy/private/$provider/usr/bin/prog")" = one
test "$(stat -c %a "$root/usr/lib/holy")" = 755

# the installed record names the private path, and the package manifest stays the
# manifest the package shipped
grep -q "usr/lib/holy/private/$provider/usr/bin/prog" \
    "$root/var/lib/holypkg/installed/$provider/files"
grep -q '"usr/bin/prog"' "$root/var/lib/holypkg/installed/$provider/package-files"
grep -q "holy-private-transform-1" "$root/var/lib/holypkg/installed/$provider/config-state"

# both packages check clean against what is installed
expect 0 "$bin" check --root "$root"

# the explicit root still requires the provider, so removing it needs the broken-edge
# decision rather than a plain removal
expect 3 "$bin" db rm "$provider" --root "$root"
test -e "$root/usr/lib/holy/private/$provider/usr/bin/prog"
expect 0 "$bin" db rm "$provider" --accept-broken --root "$root"
# the private tree belongs to the artifact that shipped the file, so removing that
# artifact takes its file and leaves the public path alone. the directories stay, the
# way a removal keeps every shared directory a manifest declared
test ! -e "$root/usr/lib/holy/private/$provider/usr/bin/prog"
test "$(cat "$root/usr/bin/prog")" = two
# the accepted removal leaves the consumer in place with a broken edge, which check
# reports rather than hides
expect 4 "$bin" check --root "$root"
grep -q "broken-provider consumer=$root_artifact" "$tmp/out" "$tmp/err"

echo "private placement set fixtures passed"