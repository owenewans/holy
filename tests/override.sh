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
    test "$rc" -eq "$wanted" || {
        echo "status $rc wanted $wanted: $*" >&2
        cat "$tmp/out" "$tmp/err" >&2
        exit 1
    }
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
grep -qx 'override-summary records 0 applied 0 pending 0 not-installed 0 review 0 invalid 0 whole-file 0 diff 0 read-only' "$tmp/out"
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
grep -qx "override-owner c-scope.override $artifact override-fixture 1 noarch source -" "$tmp/out"
grep -qx 'override-detail d-drift.override the file is neither the recorded source nor its result' "$tmp/out"
grep -qx 'override-detail e-absent.override no installed artifact owns this path' "$tmp/out"
grep -qx 'override-detail f-invalid.override override patch body does not match its digest' "$tmp/out"
grep -qx 'override-detail g-plain.override unsupported override format' "$tmp/out"
grep -qx "override-form a-applied.override diff" "$tmp/out"
grep -qx 'override-form b-pending.override diff' "$tmp/out"
grep -qx 'override-form c-scope.override diff' "$tmp/out"
grep -qx 'override-form d-drift.override diff' "$tmp/out"
grep -qx 'override-form e-absent.override diff' "$tmp/out"
grep -qx "override-summary records 7 applied 1 pending 1 not-installed 1 review 2 invalid 2 whole-file 0 diff 5 read-only" "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 22
# the machine-readable report carries the same facts under a stable schema
expect 2 "$bin" override list --root "$root" --json
grep -qx "{\"schema\":\"holy-override-report-1\",\"type\":\"override\",\"name\":\"a-applied.override\",\"scope\":\"artifact\",\"subject\":\"$artifact\",\"path\":\"/etc/foo.conf\",\"arch\":\"any\",\"libc\":\"any\",\"source_sha256\":\"$other\",\"result_sha256\":\"$foo\",\"owner\":\"$artifact\",\"owner_name\":\"override-fixture\",\"owner_version\":\"1\",\"state\":\"applied\",\"form\":\"diff\"}" "$tmp/out"
grep -qx '{"schema":"holy-override-report-1","type":"summary","records":7,"applied":1,"pending":1,"not-installed":1,"review":2,"invalid":2,"whole-file":0,"diff":5}' "$tmp/out"
# a store entry that is not a readable regular file is invalid, and named
rm "$store/f-invalid.override"
ln -s "$tmp/foo.conf" "$store/f-invalid.override"
expect 2 "$bin" override list --root "$root"
grep -qx 'override-detail f-invalid.override override file is not a readable regular file' "$tmp/out"
rm "$store/f-invalid.override" "$store/g-plain.override"
# a record that needs review is status 3, the decision the record cannot make
expect 3 "$bin" override list --root "$root"
grep -qx "override-summary records 5 applied 1 pending 1 not-installed 1 review 2 invalid 0 whole-file 0 diff 5 read-only" "$tmp/out"
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
grep -qx "override-summary records 2 applied 1 pending 1 not-installed 0 review 0 invalid 0 whole-file 0 diff 2 read-only" "$tmp/out"
# a set states the records it would write over and binds them into its plan, so a
# store that changed between the plan and the apply moves the plan hash
# a record the store keeps for a file no installed artifact owns yet
printf 'extra packaged line\n' > "$tmp/extra.conf"
extra=$(tree_digest "$tmp/extra.conf")
cp "$tmp/extra.conf" "$tmp/extra-body"
cat > "$store/i-extra.override" <<EOF
format holy-override-1
scope artifact
digest $artifact
path /etc/extra.conf
sha256 $other
patch $extra
result $extra
EOF
cat "$tmp/extra-body" >> "$store/i-extra.override"
rm -rf "$tree"
mkdir -p "$tree/HOLY" "$tree/DATA/etc"
printf 'format holy-package-1\nname override-fixture-two\nversion 1\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' > "$tree/HOLY/meta"
for field in deps provides hooks origin transform; do : > "$tree/HOLY/$field"; done
cp "$tmp/extra.conf" "$tree/DATA/etc/extra.conf"
expect 0 "$bin" manifest generate "$tree" --output "$tmp/files2"
mv "$tmp/files2" "$tree/HOLY/files"
expect 0 "$bin" pack "$tree" --output "$tmp/override-fixture-two.holy"
expect 0 "$bin" cache stage "local:$tmp/override-fixture-two.holy" --root "$root"
second=$(tree_digest "$tmp/override-fixture-two.holy")
expect 0 "$bin" db plan-set "$second" --root "$root"
grep -qx "override i-extra.override path /etc/extra.conf file absent patch $extra" "$tmp/out"
test "$(grep -c '^override ' "$tmp/out")" -eq 1
set_plan=$(sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
test -n "$set_plan"
# the same selection without the store is a different plan, since the records are inputs
mv "$store" "$tmp/store-away"
expect 0 "$bin" db plan-set "$second" --root "$root"
bare_plan=$(sed -n 's/^plan-set .* sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
test "$bare_plan" != "$set_plan"
test "$(grep -c '^override ' "$tmp/out")" -eq 0
mv "$tmp/store-away" "$store"
# a store that gained a record the plan did not see is a decision, not a silent change
cat > "$store/h-added.override" <<EOF
format holy-override-1
scope artifact
digest $artifact
path /etc/extra.conf
sha256 $other
patch $extra
result $extra
EOF
cat "$tmp/extra-body" >> "$store/h-added.override"
expect 3 "$bin" db apply-set "$set_plan" "$second" --root "$root"
test ! -e "$root/etc/extra.conf"
rm "$store/h-added.override"
expect 0 "$bin" db apply-set "$set_plan" "$second" --root "$root"
grep -qx 'extra packaged line' "$root/etc/extra.conf"
# a new artifact writing a file a record covered leaves that record naming another
# artifact, which is the review the record cannot decide for itself
expect 3 "$bin" override list --root "$root"
grep -qx "override i-extra.override state review scope artifact $artifact path /etc/extra.conf arch any libc any" "$tmp/out"
grep -qx "override-owner i-extra.override $second override-fixture-two 1 noarch source -" "$tmp/out"
grep -qx 'override-detail i-extra.override scope or conditions name another artifact' "$tmp/out"
grep -qx "override-summary records 3 applied 1 pending 1 not-installed 0 review 1 invalid 0 whole-file 1 diff 2 read-only" "$tmp/out"
# the plan for one whole-file record says what applying it would write, and refuses
# every record that is not one this manager applies or no longer applies in place
printf 'the patched configuration line\n' > "$tmp/patched"
patched=$(tree_digest "$tmp/patched")
cat > "$store/whole.override" <<EOF
format holy-override-1
scope artifact
digest $artifact
path /etc/foo.conf
sha256 $foo
patch $patched
result $patched
EOF
cat "$tmp/patched" >> "$store/whole.override"
expect 0 "$bin" override plan whole.override --root "$root"
grep -qx "override-plan whole.override path /etc/foo.conf owner $artifact override-fixture 1 source $foo result $patched patch $patched form whole-file" "$tmp/out"
plan=$(sed -n 's/^override-plan-sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
test "${#plan}" -eq 64
expect 0 "$bin" override plan whole.override --root "$root"
test "$(sed -n 's/^override-plan-sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")" = "$plan"
expect 0 "$bin" override plan whole.override --root "$root" --json
grep -qx "{\"schema\":\"holy-override-plan-1\",\"type\":\"plan\",\"name\":\"whole.override\",\"path\":\"/etc/foo.conf\",\"owner\":\"$artifact\",\"owner_name\":\"override-fixture\",\"owner_version\":\"1\",\"source_sha256\":\"$foo\",\"result_sha256\":\"$patched\",\"patch_sha256\":\"$patched\",\"form\":\"whole-file\",\"generation\":$(cat "$root/var/lib/holypkg/generation"),\"sha256\":\"$plan\"}" "$tmp/out"
# a diff record is a decision this manager does not take
expect 3 "$bin" override plan a-applied.override --root "$root"
grep -q 'is a diff record' "$tmp/err"
expect 3 "$bin" override plan b-pending.override --root "$root"
# a record scoped to a version the owner does not have is a review for the report and a
# refusal for the plan, while one scoped to the package reaches the version it omits
cat > "$store/other-version.override" <<EOF
format holy-override-1
scope version
name override-fixture
version 9
path /etc/foo.conf
sha256 $foo
patch $patched
result $patched
EOF
cat "$tmp/patched" >> "$store/other-version.override"
expect 3 "$bin" override plan other-version.override --root "$root"
grep -qx 'holypkg: override other-version.override is scoped to version override-fixture@9; the artifact owning /etc/foo.conf is override-fixture 1 source -' "$tmp/err"
cat > "$store/package-scope.override" <<EOF
format holy-override-1
scope package
package override-fixture
path /etc/foo.conf
sha256 $foo
patch $patched
result $patched
EOF
cat "$tmp/patched" >> "$store/package-scope.override"
expect 0 "$bin" override plan package-scope.override --root "$root"
grep -qx "override-plan package-scope.override path /etc/foo.conf owner $artifact override-fixture 1 source $foo result $patched patch $patched form whole-file" "$tmp/out"
expect 3 "$bin" override apply other-version.override --sha256 "$(printf '%064d' 0)" --root "$root"
grep -qx 'holypkg: override other-version.override is scoped to version override-fixture@9; the artifact owning /etc/foo.conf is override-fixture 1 source -' "$tmp/err"
rm "$store/other-version.override" "$store/package-scope.override"
# a file that is not what the record applies to is a decision, not a plan
cat > "$store/elsewhere.override" <<EOF
format holy-override-1
scope artifact
digest $artifact
path /etc/foo.conf
sha256 $other
patch $patched
result $patched
EOF
cat "$tmp/patched" >> "$store/elsewhere.override"
expect 3 "$bin" override plan elsewhere.override --root "$root"
grep -qx 'holypkg: override elsewhere.override does not apply to the file in place' "$tmp/err"
# a record whose result is already in place has nothing to write
cat > "$store/applied.override" <<EOF
format holy-override-1
scope artifact
digest $artifact
path /etc/foo.conf
sha256 $other
patch $foo
result $foo
EOF
cat "$tmp/foo.conf" >> "$store/applied.override"
expect 3 "$bin" override plan applied.override --root "$root"
grep -qx 'holypkg: override applied.override is already applied' "$tmp/err"
rm "$store/applied.override"
# a payload that drifted is not a plan, and a file no artifact owns has none either
printf 'patched by hand\n' > "$root/etc/foo.conf"
expect 3 "$bin" override plan whole.override --root "$root"
grep -qx 'holypkg: the installed payload file /etc/foo.conf drifted' "$tmp/err"
cp "$tmp/foo.conf" "$root/etc/foo.conf"
sed 's|^path /etc/foo.conf$|path /etc/absent.conf|' "$store/whole.override" \
    > "$store/unowned.override"
expect 3 "$bin" override plan unowned.override --root "$root"
grep -qx 'holypkg: no installed artifact owns /etc/absent.conf' "$tmp/err"
rm "$store/unowned.override"
expect 2 "$bin" override plan ../escape.override --root "$root"
expect 2 "$bin" override plan short --root "$root"
expect 2 "$bin" override plan missing.override --root "$root"
grep -qx 'holypkg: override missing.override is not a readable record' "$tmp/err"
# a store entry that is not a readable record has no plan, and a name that is not a
# record name is a usage error
ln -s "$tmp/foo.conf" "$store/unreadable.override"
expect 2 "$bin" override plan unreadable.override --root "$root"
grep -qx 'holypkg: override unreadable.override is not a readable record' "$tmp/err"
rm "$store/unreadable.override" "$store/elsewhere.override"
# applying the prepared plan writes the body over the file and nothing else: the path
# keeps its name and its mode, the owner is unchanged, and a second apply is the work
# already done
expect 0 "$bin" override plan whole.override --root "$root"
apply_hash=$(sed -n 's/^override-plan-sha256 \([0-9a-f]*\) read-only$/\1/p' "$tmp/out")
expect 3 "$bin" override apply whole.override --sha256 "$(printf '%064d' 0)" --root "$root"
grep -qx 'holypkg: the prepared plan changed before the apply' "$tmp/err"
grep -qx 'packaged line' "$root/etc/foo.conf"
expect 0 "$bin" override apply whole.override --sha256 "$apply_hash" --root "$root"
grep -qx "override-applied whole.override path /etc/foo.conf result $patched owner $artifact generation $(cat "$root/var/lib/holypkg/generation")" "$tmp/out"
grep -qx 'the patched configuration line' "$root/etc/foo.conf"
test "$(stat -c %a "$root/etc/foo.conf")" = "$(stat -c %a "$root/etc/bar.conf")"
test -z "$(find "$root/etc" -name '.holy-tmp-*' -print)"
# the record now reads as applied, and the plan refuses it as a decision. a-applied
# covered the same file with another result, so it needs a review instead.
expect 3 "$bin" override list --root "$root"
grep -qx "override whole.override state applied scope artifact $artifact path /etc/foo.conf arch any libc any" "$tmp/out"
grep -qx "override-owner whole.override $artifact override-fixture 1 noarch source -" "$tmp/out"
grep -qx 'override-detail a-applied.override the file is neither the recorded source nor its result' "$tmp/out"
expect 3 "$bin" override plan whole.override --root "$root"
grep -qx 'holypkg: the installed payload file /etc/foo.conf drifted' "$tmp/err"
# the applied file is payload drift the installed check reports, and the record is the
# reason the plan can no longer write it
expect 4 "$bin" db check --all --root "$root"
grep -qx 'holypkg: changed-file etc/foo.conf' "$tmp/err"
expect 2 "$bin" override apply whole.override --sha256 not-a-digest --root "$root"
rm "$store/whole.override"
# a repair brings the packaged bytes back, so a path an override record covered is
# stated in the plan and the statement moves the plan hash
cp "$tmp/foo.conf" "$root/etc/foo.conf"
rm "$root/etc/foo.conf"
expect 0 "$bin" db repair-plan "$artifact" --root "$root"
grep -qx 'repair-override a-applied.override path /etc/foo.conf state packaged-bytes-restored' "$tmp/out"
test "$(grep -c '^repair-override ' "$tmp/out")" -eq 1
plain_repair=$(sed -n 's/^repair-plan .* sha256 \([0-9a-f]*\) missing-only read-only$/\1/p' "$tmp/out")
test "${#plain_repair}" -eq 64
cat > "$store/repaired.override" <<EOF
format holy-override-1
scope artifact
digest $artifact
path /etc/foo.conf
sha256 $other
patch $foo
result $patched
EOF
cat "$tmp/foo.conf" >> "$store/repaired.override"
expect 0 "$bin" db repair-plan "$artifact" --root "$root"
grep -qx 'repair-override repaired.override path /etc/foo.conf state packaged-bytes-restored' "$tmp/out"
repair=$(sed -n 's/^repair-plan .* sha256 \([0-9a-f]*\) missing-only read-only$/\1/p' "$tmp/out")
test "$repair" != "$plain_repair"
expect 0 "$bin" db repair "$artifact" --plan "$repair" --root "$root"
grep -qx 'packaged line' "$root/etc/foo.conf"
expect 0 "$bin" db check --all --root "$root"
# the file carries the packaged bytes again: the record that patched those bytes reads
# applied, and the record written against other bytes reads review and says why
expect 3 "$bin" override list --root "$root"
grep -qx "override a-applied.override state applied scope artifact $artifact path /etc/foo.conf arch any libc any" "$tmp/out"
grep -qx "override repaired.override state review scope artifact $artifact path /etc/foo.conf arch any libc any" "$tmp/out"
grep -qx 'override-detail repaired.override the file is neither the recorded source nor its result' "$tmp/out"
rm "$store/repaired.override"
# a root without a database cannot answer which artifact owns a path
mkdir "$tmp/empty"
expect 6 "$bin" override list --root "$tmp/empty"
grep -qx 'holypkg: installed set unavailable' "$tmp/err"
expect 2 "$bin" override list
expect 2 "$bin" override show --root "$root"
expect 2 "$bin" override plan whole.override
expect 2 "$bin" override list --root "$root" --json --json
printf 'override report fixtures passed\n'
