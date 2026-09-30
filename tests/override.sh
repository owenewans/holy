#!/bin/sh
set -eu

bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/root"
tree="$tmp/tree"
store="$root/etc/holy/overrides"
mkdir -p "$root/etc"
expect() {
    wanted=$1
    shift
    rc=0
    "$@" > "$tmp/out" 2> "$tmp/err" || rc=$?
    test "$rc" -eq "$wanted" || { cat "$tmp/out" "$tmp/err"; exit 1; }
}
printf 'packaged line\n' > "$tmp/foo.conf"
printf 'second packaged line\n' > "$tmp/bar.conf"
tree_digest() {
    sha256sum "$1" | cut -d ' ' -f 1
}
expect 0 "$bin" db init --root "$root"
rm -rf "$tree"
mkdir -p "$tree/HOLY" "$tree/DATA/etc"
printf 'format holy-package-1\nname override-fixture\nversion 1\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' > "$tree/HOLY/meta"
for field in deps provides hooks origin transform; do : > "$tree/HOLY/$field"; done
cp "$tmp/foo.conf" "$tree/DATA/etc/foo.conf"
cp "$tmp/bar.conf" "$tree/DATA/etc/bar.conf"
expect 0 "$bin" manifest generate "$tree" --output "$tmp/files"
mv "$tmp/files" "$tree/HOLY/files"
expect 0 "$bin" pack "$tree" --output "$tmp/override-fixture.holy"
expect 0 "$bin" cache stage "local:$tmp/override-fixture.holy" --root "$root"
artifact=$(tree_digest "$tmp/override-fixture.holy")
plan=$("$bin" db plan-set "$artifact" --root "$root" | sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p')
expect 0 "$bin" db apply-set "$plan" "$artifact" --root "$root"
foo=$(tree_digest "$root/etc/foo.conf")
bar=$(tree_digest "$root/etc/bar.conf")
other=$(printf '%064d' 1)
# a store with no records is an empty report, and needs no database
expect 0 "$bin" override list --root "$root"
grep -qx 'override-summary records 0 applied 0 pending 0 not-installed 0 review 0 invalid 0 read-only' "$tmp/out"
mkdir -p "$store"
printf 'the replacement line\n' > "$tmp/body"
body=$(tree_digest "$tmp/body")
# an override whose result is what the file already holds is applied
cat > "$store/a-applied.override" <<EOF
format holy-override-1
scope artifact
digest $artifact
path /etc/foo.conf
sha256 $other
patch $body
result $foo
EOF
cat "$tmp/body" >> "$store/a-applied.override"
# a record whose source is what the file holds is pending: the patch is not applied
cat > "$store/b-pending.override" <<EOF
format holy-override-1
scope version
name override-fixture
version 1
path /etc/bar.conf
sha256 $bar
patch $body
result $other
EOF
cat "$tmp/body" >> "$store/b-pending.override"
# a scope that names another artifact does not cover this one
cat > "$store/c-scope.override" <<EOF
format holy-override-1
scope artifact
digest $other
path /etc/foo.conf
sha256 $foo
patch $body
result $foo
EOF
cat "$tmp/body" >> "$store/c-scope.override"
# a file that is neither the recorded source nor its result needs a review
cat > "$store/d-drift.override" <<EOF
format holy-override-1
scope package
package override-fixture
path /etc/foo.conf
sha256 $other
patch $body
result $other
EOF
cat "$tmp/body" >> "$store/d-drift.override"
# a path no installed artifact owns is not a match
cat > "$store/e-absent.override" <<EOF
format holy-override-1
scope artifact
digest $artifact
path /etc/absent.conf
sha256 $other
patch $body
result $other
EOF
cat "$tmp/body" >> "$store/e-absent.override"
# a record whose body is not the recorded patch is invalid
cat > "$store/f-invalid.override" <<EOF
format holy-override-1
scope artifact
digest $artifact
path /etc/foo.conf
sha256 $other
patch $other
result $foo
EOF
cat "$tmp/body" >> "$store/f-invalid.override"
# a file that is not a record at all is invalid too
printf 'not an override record\n' > "$store/g-plain.override"
expect 2 "$bin" override list --root "$root"
grep -qx "override a-applied.override state applied scope artifact $artifact path /etc/foo.conf arch any libc any" "$tmp/out"
grep -qx "override b-pending.override state pending scope version override-fixture@1 path /etc/bar.conf arch any libc any" "$tmp/out"
grep -qx 'override-detail c-scope.override scope or conditions name another artifact' "$tmp/out"
grep -qx "override-owner c-scope.override $artifact override-fixture 1 noarch" "$tmp/out"
grep -qx 'override-detail d-drift.override the file is neither the recorded source nor its result' "$tmp/out"
grep -qx 'override-detail e-absent.override no installed artifact owns this path' "$tmp/out"
grep -qx 'override-detail f-invalid.override override patch body does not match its digest' "$tmp/out"
grep -qx 'override-detail g-plain.override unsupported override format' "$tmp/out"
grep -qx "override-summary records 7 applied 1 pending 1 not-installed 1 review 2 invalid 2 read-only" "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 17
# the machine-readable report carries the same facts under a stable schema
expect 2 "$bin" override list --root "$root" --json
grep -qx "{\"schema\":\"holy-override-report-1\",\"type\":\"override\",\"name\":\"a-applied.override\",\"scope\":\"artifact\",\"subject\":\"$artifact\",\"path\":\"/etc/foo.conf\",\"arch\":\"any\",\"libc\":\"any\",\"source_sha256\":\"$other\",\"result_sha256\":\"$foo\",\"owner\":\"$artifact\",\"owner_name\":\"override-fixture\",\"owner_version\":\"1\",\"state\":\"applied\"}" "$tmp/out"
grep -qx '{"schema":"holy-override-report-1","type":"summary","records":7,"applied":1,"pending":1,"not-installed":1,"review":2,"invalid":2}' "$tmp/out"
# a store entry that is not a readable regular file is invalid, and named
rm "$store/f-invalid.override"
ln -s "$tmp/foo.conf" "$store/f-invalid.override"
expect 2 "$bin" override list --root "$root"
grep -qx 'override-detail f-invalid.override override file is not a readable regular file' "$tmp/out"
rm "$store/f-invalid.override" "$store/g-plain.override"
# a record that needs review is status 3, the decision the record cannot make
expect 3 "$bin" override list --root "$root"
grep -qx "override-summary records 5 applied 1 pending 1 not-installed 1 review 2 invalid 0 read-only" "$tmp/out"
rm "$store/c-scope.override" "$store/d-drift.override"
# a record whose file cannot be read through the root is a review, not a guess
rm "$root/etc/foo.conf"
mkdir "$root/etc/foo.conf"
expect 3 "$bin" override list --root "$root"
grep -qx 'override-detail a-applied.override the file is not readable through the root' "$tmp/out"
rmdir "$root/etc/foo.conf"
cp "$tmp/foo.conf" "$root/etc/foo.conf"
rm "$store/e-absent.override"
expect 0 "$bin" override list --root "$root"
grep -qx "override-summary records 2 applied 1 pending 1 not-installed 0 review 0 invalid 0 read-only" "$tmp/out"
# a root without a database cannot answer which artifact owns a path
mkdir "$tmp/empty"
expect 6 "$bin" override list --root "$tmp/empty"
grep -qx 'holypkg: installed set unavailable' "$tmp/err"
expect 2 "$bin" override list
expect 2 "$bin" override show --root "$root"
expect 2 "$bin" override list --root "$root" --json --json
printf 'override report fixtures passed\n'
