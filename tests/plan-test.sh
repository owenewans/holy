#!/bin/sh
set -eu

bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/root"
repo="$tmp/repo"
mkdir -p "$root/usr/share" "$repo"
expect() {
    wanted=$1
    shift
    rc=0
    "$@" > "$tmp/out" 2> "$tmp/err" || rc=$?
    test "$rc" -eq "$wanted" || { cat "$tmp/out" "$tmp/err"; exit 1; }
}
package() {
    version=$1
    tree="$tmp/tree-$version"
    mkdir -p "$tree/HOLY" "$tree/DATA/usr/share"
    printf 'format holy-package-1\nname update-fixture\nversion %s\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' "$version" > "$tree/HOLY/meta"
    printf 'x-version-family pacman\n' >> "$tree/HOLY/meta"
    for field in deps provides hooks origin transform; do : > "$tree/HOLY/$field"; done
    printf 'version %s\n' "$version" > "$tree/DATA/usr/share/update-fixture"
    expect 0 "$bin" manifest generate "$tree" --output "$tmp/files-$version"
    mv "$tmp/files-$version" "$tree/HOLY/files"
    expect 0 "$bin" pack "$tree" --output "$repo/update-$version.holy"
}
seal() {
    expect 0 "$bin" repo index "$repo"
    expect 0 "$bin" repo seal "$repo"
    index=$(sed -n 's/^sha256 //p' "$repo/current")
    printf 'format holy-mirror-1\nurl "https://repo.example/holy/"\nindex-sha256 %s\nverification digest-pinned-unsigned\nsource-id %s\n' "$index" "$source_id" > "$repo/mirror-origin"
}
register() {
    printf '[source %s]\ntype holy-http\nurl "%s"\n' "$1" "$2" > "$tmp/source.conf"
    expect 0 "$bin" source plan --config "$tmp/source.conf" --root "$root"
    cp "$tmp/out" "$tmp/source.plan"
    registered=$(sha256sum "$tmp/source.plan" | cut -d ' ' -f 1)
    expect 0 "$bin" source apply "$tmp/source.plan" --sha256 "$registered" --root "$root"
}
expect 0 "$bin" db init --root "$root"
register fixture https://repo.example/holy/
expect 0 "$bin" source list --root "$root"
source_id=$(awk '$1 == "source" && $4 == "active" {print $2}' "$tmp/out")
test "${#source_id}" -eq 64
package 1
old=$(sha256sum "$repo/update-1.holy" | cut -d ' ' -f 1)
seal
expect 0 "$bin" source catalog bind fixture "$repo" --root "$root"
expect 0 "$bin" add fixture:update-fixture --root "$root" --yes
package 2
next=$(sha256sum "$repo/update-2.holy" | cut -d ' ' -f 1)
seal
expect 0 "$bin" source catalog bind fixture "$repo" --root "$root"
expect 0 "$bin" up fixture:update-fixture --prepare --output "$tmp/plan" --root "$root"
plan=$(sha256sum "$tmp/plan" | cut -d ' ' -f 1)
grep -qx "prepared $plan $tmp/plan old $old new $next index $index" "$tmp/out"
# a prepared plan is the fixed set a test verifies: every input is present and bound.
expect 0 "$bin" test "$tmp/plan" --root "$root"
grep -qx "test-plan $plan mode root" "$tmp/out"
grep -qx "test-input source $source_id alias \"fixture\"" "$tmp/out"
grep -qx "test-input catalog \"$repo\" index $index" "$tmp/out"
grep -qx "test-input old $old new $next state-plan $(sed -n 's/^state-plan //p' "$tmp/plan")" "$tmp/out"
grep -qx "test-check plan-document pass" "$tmp/out"
grep -qx "test-check source-binding pass" "$tmp/out"
grep -qx "test-check catalog-generation pass" "$tmp/out"
grep -qx "test-check old-archive pass" "$tmp/out"
grep -qx "test-check slot-candidate pass" "$tmp/out"
grep -qx "test-check new-archive pass" "$tmp/out"
grep -qx "test-check installed-slot pass" "$tmp/out"
grep -qx "test-check installed-payload pass" "$tmp/out"
grep -qx "test-check runtime-probes skip detail explicit-probe-request" "$tmp/out"
grep -qx "test-image rootfs generation $(cat "$root/var/lib/holypkg/generation") digest $(sed -n 's/^test-image rootfs generation [0-9]* digest //p' "$tmp/out")" "$tmp/out"
grep -qx "test-unexecuted runtime-probes reason explicit-probe-request" "$tmp/out"
grep -qx "test-report pass 8 fail 0 skip 1 unknown 0 coverage plan-inputs" "$tmp/out"
test "$(wc -l < "$tmp/out")" -eq 16
# the reviewed plan digest is the review gate, and the same plan reports the same binding.
expect 0 "$bin" test "$tmp/plan" --sha256 "$plan" --root "$root"
cp "$tmp/out" "$tmp/first"
expect 0 "$bin" test "$tmp/plan" --sha256 "$plan" --root "$root"
cmp "$tmp/first" "$tmp/out"
expect 3 "$bin" test "$tmp/plan" --sha256 "$(printf '%064d' 0)" --root "$root"
grep -qx 'holypkg: plan digest differs from the approved one' "$tmp/err"
test ! -s "$tmp/out"
expect 2 "$bin" test
expect 2 "$bin" test "$tmp/plan" --shell --root "$root"
expect 2 "$bin" test "$tmp/plan" --mode host --root "$root"
expect 2 "$bin" test "$tmp/plan" --sha256 --root "$root"
printf 'format holy-up-plan-1\nsource-id %s\n' "$source_id" > "$tmp/malformed.plan"
expect 2 "$bin" test "$tmp/malformed.plan" --root "$root"
grep -qx 'holypkg: malformed update plan' "$tmp/err"
expect 6 "$bin" test "$tmp/absent.plan" --root "$root"
grep -qx 'holypkg: update plan unavailable' "$tmp/err"
# an edited body no longer carries the state-plan digest, so the plan is malformed.
{ cat "$tmp/plan"; printf 'edited\n'; } > "$tmp/edited.plan"
expect 2 "$bin" test "$tmp/edited.plan" --root "$root"
# the machine-readable report carries the same facts under a stable schema.
expect 0 "$bin" test "$tmp/plan" --root "$root" --json
grep -qx "{\"schema\":\"holy-test-report-1\",\"type\":\"plan\",\"plan\":\"$plan\",\"mode\":\"root\",\"source\":\"$source_id\",\"alias\":\"fixture\",\"catalog\":\"$repo\",\"index\":\"$index\",\"old\":\"$old\",\"new\":\"$next\",\"state-plan\":\"$(sed -n 's/^state-plan //p' "$tmp/plan")\",\"coverage\":\"plan-inputs\"}" "$tmp/out"
grep -qx "{\"schema\":\"holy-test-report-1\",\"type\":\"check\",\"check\":\"old-archive\",\"result\":\"pass\"}" "$tmp/out"
grep -q '"type":"image","mode":"root","generation":' "$tmp/out"
grep -qx "{\"schema\":\"holy-test-report-1\",\"type\":\"unexecuted\",\"check\":\"runtime-probes\",\"reason\":\"explicit-probe-request\"}" "$tmp/out"
grep -qx '{"schema":"holy-test-report-1","type":"summary","pass":8,"fail":0,"skip":1,"unknown":0,"coverage":"plan-inputs"}' "$tmp/out"
# a VM trial owns its own image and needs a runner this command does not have.
expect 6 "$bin" test "$tmp/plan" --mode vm --root "$root"
grep -qx "test-image vm none reason no-vm-runner" "$tmp/out"
grep -qx "test-check vm-trial unknown detail no-vm-runner" "$tmp/out"
grep -qx "test-unexecuted vm-trial reason no-vm-runner" "$tmp/out"
grep -qx "test-report pass 8 fail 0 skip 1 unknown 1 coverage plan-inputs" "$tmp/out"
# each bound input has one honest outcome when it is not what the plan recorded.
cp -a "$root" "$tmp/root-new-gone"
rm "$tmp/root-new-gone/var/cache/holypkg/objects/sha256/$next.holy"
expect 4 "$bin" test "$tmp/plan" --root "$tmp/root-new-gone"
grep -qx "test-check new-archive fail detail archive-unavailable" "$tmp/out"
grep -qx "test-report pass 7 fail 1 skip 1 unknown 0 coverage plan-inputs" "$tmp/out"
cp -a "$root" "$tmp/root-old-gone"
rm "$tmp/root-old-gone/var/cache/holypkg/objects/sha256/$old.holy"
expect 4 "$bin" test "$tmp/plan" --root "$tmp/root-old-gone"
grep -qx "test-check old-archive fail detail old-archive-unavailable" "$tmp/out"
grep -qx "test-check slot-candidate skip detail no-old-identity" "$tmp/out"
cp -a "$root" "$tmp/root-drift"
printf 'drift\n' > "$tmp/root-drift/usr/share/update-fixture"
expect 4 "$bin" test "$tmp/plan" --root "$tmp/root-drift"
grep -qx "test-check installed-slot pass" "$tmp/out"
grep -qx "test-check installed-payload fail detail changed-payload" "$tmp/out"
cp -a "$root" "$tmp/root-removed"
expect 0 "$bin" db rm "$old" --root "$tmp/root-removed"
expect 4 "$bin" test "$tmp/plan" --root "$tmp/root-removed"
grep -qx "test-check installed-slot fail detail old-artifact-not-installed" "$tmp/out"
grep -qx "test-check installed-payload skip detail no-installed-slot" "$tmp/out"
# a source registry that names another source-id or loses the alias no longer binds
# the plan, which is a fact about the registry rather than a guess.
cp -a "$root" "$tmp/root-binding"
# a source id is the digest of its definition, so a self-consistent record for another
# definition binds another id
other_id=$(printf 'type "holy-http"\nurl "https://repo.example/other/"\n' | sha256sum | cut -d ' ' -f 1)
sed -e "s/^source $source_id /source $other_id /" \
    -e 's|https://repo.example/holy/|https://repo.example/other/|' \
    "$root/var/lib/holypkg/sources" > "$tmp/root-binding/var/lib/holypkg/sources"
expect 4 "$bin" test "$tmp/plan" --root "$tmp/root-binding"
grep -qx "test-check source-binding fail detail source-id-changed" "$tmp/out"
cp -a "$root" "$tmp/root-alias"
sed 's/ "fixture" / "renamed" /' \
    "$root/var/lib/holypkg/sources" > "$tmp/root-alias/var/lib/holypkg/sources"
expect 4 "$bin" test "$tmp/plan" --root "$tmp/root-alias"
grep -qx "test-check source-binding fail detail no-active-source" "$tmp/out"
grep -qx 'holypkg: active source unavailable: "fixture"' "$tmp/err"
# a catalog that now serves another generation is not the generation the plan fixed.
cp -a "$root" "$tmp/root-generation"
package 3
seal
expect 4 "$bin" test "$tmp/plan" --root "$tmp/root-generation"
grep -qx "test-check source-binding pass" "$tmp/out"
grep -qx "test-check catalog-generation fail detail catalog-generation-changed" "$tmp/out"
printf 'plan test fixtures passed\n'
