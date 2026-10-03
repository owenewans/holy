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
    version=$1 comparator=${2:-pacman} unit=${3:-} name=${4:-update-fixture}
    tree="$tmp/tree-$version"
    mkdir -p "$tree/HOLY" "$tree/DATA/usr/share"
    printf 'format holy-package-1\nname %s\nversion %s\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' "$name" "$version" > "$tree/HOLY/meta"
    if test "$comparator" != unknown; then
        printf 'x-version-family %s\n' "$comparator" >> "$tree/HOLY/meta"
    fi
    for field in deps provides hooks origin transform; do : > "$tree/HOLY/$field"; done
    if test "$version" = 2; then
        printf 'record payload normalized before pack\n' > "$tree/HOLY/transform"
    fi
    printf 'version %s\n' "$version" > "$tree/DATA/usr/share/$name"
    if test "$unit" = unit; then
        mkdir -p "$tree/DATA/etc/dinit.d"
        printf 'type = process\ncommand = /usr/bin/%s\n' "$name" > "$tree/DATA/etc/dinit.d/$name"
    fi
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
expect 0 "$bin" db init --root "$root"
printf '[source fixture]\ntype holy-http\nurl "https://repo.example/holy/"\n' > "$tmp/source.conf"
expect 0 "$bin" source plan --config "$tmp/source.conf" --root "$root"
cp "$tmp/out" "$tmp/source.plan"
source_plan=$(sha256sum "$tmp/source.plan" | cut -d ' ' -f 1)
expect 0 "$bin" source apply "$tmp/source.plan" --sha256 "$source_plan" --root "$root"
expect 0 "$bin" source list --root "$root"
source_id=$(awk '$1 == "source" && $4 == "active" {print $2}' "$tmp/out")
test "${#source_id}" -eq 64
package 1
old=$(sha256sum "$repo/update-1.holy" | cut -d ' ' -f 1)
seal
expect 0 "$bin" source catalog bind fixture "$repo" --root "$root"
expect 0 "$bin" add fixture:update-fixture --root "$root" --yes
grep -qx 'version 1' "$root/usr/share/update-fixture"
expect 0 "$bin" up fixture:update-fixture --prepare --output "$tmp/no-update" --root "$root"
grep -q '^up-to-date ' "$tmp/out"
test ! -e "$tmp/no-update"
package 2
next=$(sha256sum "$repo/update-2.holy" | cut -d ' ' -f 1)
cp -a "$tmp/tree-2" "$tmp/unrelated-tree"
sed -i 's/^name update-fixture$/name unrelated-fixture/' "$tmp/unrelated-tree/HOLY/meta"
mv "$tmp/unrelated-tree/DATA/usr/share/update-fixture" \
    "$tmp/unrelated-tree/DATA/usr/share/unrelated-fixture"
expect 0 "$bin" manifest generate "$tmp/unrelated-tree" --output "$tmp/unrelated-files"
mv "$tmp/unrelated-files" "$tmp/unrelated-tree/HOLY/files"
expect 0 "$bin" pack "$tmp/unrelated-tree" --output "$repo/unrelated.holy"
unrelated=$(sha256sum "$repo/unrelated.holy" | cut -d ' ' -f 1)
seal
expect 6 "$bin" up fixture:update-fixture --prepare --output "$tmp/stale-binding" --root "$root"
test ! -e "$tmp/stale-binding"
expect 0 "$bin" source catalog bind fixture "$repo" --root "$root"
cp "$repo/unrelated.holy" "$tmp/unrelated.original"
printf corrupt >> "$repo/unrelated.holy"
expect 6 "$bin" source catalog bind fixture "$repo" --root "$root"
cp "$repo/index.$index" "$tmp/saved-index"
printf corrupt >> "$repo/index.$index"
expect 6 "$bin" up fixture:update-fixture --prepare --output "$tmp/bad-index.plan" --root "$root"
test ! -e "$tmp/bad-index.plan"
cp "$tmp/saved-index" "$repo/index.$index"
expect 0 "$bin" up fixture:update-fixture --prepare --output "$tmp/up.plan" --root "$root"
test ! -e "$root/var/cache/holypkg/objects/sha256/$unrelated"
plan=$(sha256sum "$tmp/up.plan" | cut -d ' ' -f 1)
grep -qx "prepared $plan $tmp/up.plan old $old new $next index $index" "$tmp/out"
cp "$repo/update-1.holy" "$tmp/old-source-artifact"
printf corrupt >> "$repo/update-1.holy"
expect 0 "$bin" up fixture:update-fixture --prepare --output "$tmp/old-source-damaged.plan" --root "$root"
cmp "$tmp/up.plan" "$tmp/old-source-damaged.plan"
cp "$tmp/old-source-artifact" "$repo/update-1.holy"
grep -qx "source-id $source_id" "$tmp/up.plan"
grep -qx "index $index" "$tmp/up.plan"
grep -qx "old $old" "$tmp/up.plan"
grep -qx "new $next" "$tmp/up.plan"
# --all reaches the same slot from the installed set and prepares the same plan, so the
# one-slot reference is not a second path through the code
expect 0 "$bin" up --all --prepare --output "$tmp/all.plan" --root "$root"
cmp "$tmp/up.plan" "$tmp/all.plan"
grep -qx "prepared $plan $tmp/all.plan old $old new $next index $index" "$tmp/out"
# naming a reference as well is two ways to say one thing, and the narrower list would be
# dropped without a word
expect 2 "$bin" up --all fixture:update-fixture --prepare --output "$tmp/both.plan" --root "$root"
test ! -e "$tmp/both.plan"
# a slot the arch excludes is not a reference, so the run has nothing to do
expect 2 "$bin" up --all --arch x86 --prepare --output "$tmp/arch.plan" --root "$root"
test ! -e "$tmp/arch.plan"
grep -qx 'version 1' "$root/usr/share/update-fixture"
package 9
unlisted=$(sha256sum "$repo/update-9.holy" | cut -d ' ' -f 1)
expect 0 "$bin" cache stage "local:$repo/update-9.holy" --root "$root"
expect 0 "$bin" db plan-update "$old" "$unlisted" --root "$root"
sed '1d' "$tmp/out" > "$tmp/unlisted.body"
unlisted_inner=$(sha256sum "$tmp/unlisted.body" | cut -d ' ' -f 1)
python3 - "$tmp/up.plan" "$tmp/unlisted.body" "$next" "$unlisted" "$unlisted_inner" "$tmp/unlisted.plan" <<'PY'
from pathlib import Path
import sys
plan, body, old, new, inner, output = sys.argv[1:]
header = Path(plan).read_bytes().split(b'[update]\n', 1)[0]
header = header.replace(f'new {old}\n'.encode(), f'new {new}\n'.encode())
header = header.replace(next(line for line in header.splitlines(keepends=True)
                             if line.startswith(b'state-plan ')),
                        f'state-plan {inner}\n'.encode())
Path(output).write_bytes(header + Path(body).read_bytes())
PY
unlisted_plan=$(sha256sum "$tmp/unlisted.plan" | cut -d ' ' -f 1)
expect 3 "$bin" apply "$tmp/unlisted.plan" --sha256 "$unlisted_plan" --root "$root"
grep -q 'prepared artifact absent from source slot' "$tmp/err"
grep -qx 'version 1' "$root/usr/share/update-fixture"
rm "$repo/update-9.holy"
expect 3 "$bin" apply "$tmp/up.plan" --sha256 "$(printf '%064d' 0)" --root "$root"
cp "$repo/current" "$tmp/current"
cp "$repo/mirror-origin" "$tmp/origin"
printf 'sha256 %064d\n' 0 > "$repo/current"
expect 6 "$bin" apply "$tmp/up.plan" --sha256 "$plan" --root "$root"
cp "$tmp/current" "$repo/current"
cp "$tmp/origin" "$repo/mirror-origin"
printf '[source renamed]\ntype holy-http\nurl "https://repo.example/holy/"\n' > "$tmp/source.conf"
expect 0 "$bin" source plan --config "$tmp/source.conf" --root "$root"
cp "$tmp/out" "$tmp/source.plan"
source_plan=$(sha256sum "$tmp/source.plan" | cut -d ' ' -f 1)
expect 0 "$bin" source apply "$tmp/source.plan" --sha256 "$source_plan" --root "$root"
expect 6 "$bin" apply "$tmp/up.plan" --sha256 "$plan" --root "$root"
printf '[source fixture]\ntype holy-http\nurl "https://repo.example/holy/"\n' > "$tmp/source.conf"
expect 0 "$bin" source plan --config "$tmp/source.conf" --root "$root"
cp "$tmp/out" "$tmp/source.plan"
source_plan=$(sha256sum "$tmp/source.plan" | cut -d ' ' -f 1)
expect 0 "$bin" source apply "$tmp/source.plan" --sha256 "$source_plan" --root "$root"
expect 3 "$bin" apply "$tmp/up.plan" --sha256 "$plan" --root "$root"
# a rehearsal applies the approved plan to a copy of the root, so the review can be
# exercised without the running root changing
expect 0 "$bin" apply "$tmp/up.plan" --sha256 "$plan" --root "$root" --work "$tmp/trial"
grep -qx 'version 1' "$root/usr/share/update-fixture"
grep -q "^apply-trial-root $tmp/trial/trial-root slots 1 " "$tmp/out"
grep -qx 'version 2' "$tmp/trial/trial-root/usr/share/update-fixture"
# a work directory inside the root would be a copy reading its own output
expect 2 "$bin" apply "$tmp/up.plan" --sha256 "$plan" --root "$root" --work "$root/trial"
expect 2 "$bin" apply "$tmp/up.plan" --sha256 "$plan" --root "$root" --work relative
expect 0 "$bin" up fixture:update-fixture --prepare --output "$tmp/fresh.plan" --root "$root"
fresh=$(sha256sum "$tmp/fresh.plan" | cut -d ' ' -f 1)
expect 0 "$bin" apply "$tmp/fresh.plan" --sha256 "$fresh" --root "$root"
grep -qx 'version 2' "$root/usr/share/update-fixture"
grep -qx "source-id $source_id" "$root/var/lib/holypkg/installed/$next/state"
expect 0 "$bin" db check --all --root "$root"
expect 0 "$bin" up fixture:update-fixture --prepare --output "$tmp/no-newer" --root "$root"
test ! -e "$tmp/no-newer"
# nothing newer anywhere is the same answer for every installed slot at once
expect 0 "$bin" up --all --prepare --output "$tmp/no-newer-all" --root "$root"
grep -q "^up-to-date $source_id $next$" "$tmp/out"
test ! -e "$tmp/no-newer-all"
expect 0 "$bin" up fixture:update-fixture --prepare --choose "$old" --output "$tmp/downgrade.plan" --root "$root"
downgrade=$(sha256sum "$tmp/downgrade.plan" | cut -d ' ' -f 1)
expect 0 "$bin" apply "$tmp/downgrade.plan" --sha256 "$downgrade" --root "$root"
grep -qx 'version 1' "$root/usr/share/update-fixture"
expect 0 "$bin" db check --all --root "$root"
cp "$tmp/unrelated.original" "$repo/unrelated.holy"
package 3 unknown
third=$(sha256sum "$repo/update-3.holy" | cut -d ' ' -f 1)
seal
expect 0 "$bin" source catalog bind fixture "$repo" --root "$root"
expect 3 "$bin" up fixture:update-fixture --prepare --output "$tmp/unknown.plan" --root "$root"
grep -q 'decision-required update candidate' "$tmp/err"
test ! -e "$tmp/unknown.plan"
expect 0 "$bin" up fixture:update-fixture --prepare --choose "$third" \
    --output "$tmp/chosen.plan" --root "$root"
chosen=$(sha256sum "$tmp/chosen.plan" | cut -d ' ' -f 1)
sed "s/^new $third/new $(printf '%064d' 0)/" "$tmp/chosen.plan" > "$tmp/forged.plan"
forged=$(sha256sum "$tmp/forged.plan" | cut -d ' ' -f 1)
expect 2 "$bin" apply "$tmp/forged.plan" --sha256 "$forged" --root "$root"
grep -qx 'version 1' "$root/usr/share/update-fixture"
expect 0 "$bin" apply "$tmp/chosen.plan" --sha256 "$chosen" --root "$root"
grep -qx 'version 3' "$root/usr/share/update-fixture"
expect 0 "$bin" db check --all --root "$root"
rm "$repo/update-1.holy" "$repo/update-2.holy" "$repo/update-3.holy"
package 4 holy
fourth=$(sha256sum "$repo/update-4.holy" | cut -d ' ' -f 1)
seal
expect 0 "$bin" source catalog bind fixture "$repo" --root "$root"
expect 0 "$bin" up fixture:update-fixture --prepare --choose "$fourth" \
    --output "$tmp/native-switch.plan" --root "$root"
switch=$(sha256sum "$tmp/native-switch.plan" | cut -d ' ' -f 1)
expect 0 "$bin" apply "$tmp/native-switch.plan" --sha256 "$switch" --root "$root"
package 5 holy
fifth=$(sha256sum "$repo/update-5.holy" | cut -d ' ' -f 1)
seal
expect 0 "$bin" source catalog bind fixture "$repo" --root "$root"
expect 0 "$bin" up fixture:update-fixture --prepare --output "$tmp/native.plan" --root "$root"
grep -qx "new $fifth" "$tmp/native.plan"
native=$(sha256sum "$tmp/native.plan" | cut -d ' ' -f 1)
expect 0 "$bin" apply "$tmp/native.plan" --sha256 "$native" --root "$root"
grep -qx 'version 5' "$root/usr/share/update-fixture"
expect 0 "$bin" db check --all --root "$root"
cp -a "$tmp/tree-5" "$tmp/tree-5-r2"
sed -i 's/^release 1$/release 2/' "$tmp/tree-5-r2/HOLY/meta"
expect 0 "$bin" pack "$tmp/tree-5-r2" --output "$repo/update-5-r2.holy"
revision=$(sha256sum "$repo/update-5-r2.holy" | cut -d ' ' -f 1)
seal
expect 0 "$bin" source catalog bind fixture "$repo" --root "$root"
expect 0 "$bin" up fixture:update-fixture --prepare --output "$tmp/native-revision.plan" --root "$root"
grep -qx "new $revision" "$tmp/native-revision.plan"
revised=$(sha256sum "$tmp/native-revision.plan" | cut -d ' ' -f 1)
expect 0 "$bin" apply "$tmp/native-revision.plan" --sha256 "$revised" --root "$root"
grep -qx 'version 5' "$root/usr/share/update-fixture"
expect 0 "$bin" db check --all --root "$root"
package 6 holy
seal
expect 0 "$bin" source catalog bind fixture "$repo" --root "$root"
expect 2 "$bin" up fixture:update-fixture --prepare --output "$tmp/invalid.plan" --yes --root "$root"
test ! -e "$tmp/invalid.plan"
expect 0 "$bin" up fixture:update-fixture --prepare --root "$root"
temporary=$(awk '$1 == "prepared" {print $3}' "$tmp/out")
test -f "$temporary"
test "$(stat -c '%a' "$temporary")" = 600
rm "$temporary"
rmdir "$(dirname "$temporary")"
expect 0 "$bin" up fixture:update-fixture --yes --root "$root"
applied_temp=$(awk '$1 == "prepared" {print $3}' "$tmp/out")
test ! -e "$applied_temp"
test ! -d "$(dirname "$applied_temp")"
grep -qx 'version 6' "$root/usr/share/update-fixture"
expect 0 "$bin" db check --all --root "$root"
package 7 holy
seal
expect 0 "$bin" source catalog bind fixture "$repo" --root "$root"
expect 3 "$bin" up fixture:update-fixture --noninteractive --output "$tmp/review.plan" --root "$root"
grep -q 'decision-required plan=' "$tmp/err"
expect 3 "$bin" up fixture:update-fixture --output "$tmp/implicit.plan" --root "$root"
cmp "$tmp/review.plan" "$tmp/implicit.plan"
grep -qx 'version 6' "$root/usr/share/update-fixture"
review=$(sha256sum "$tmp/review.plan" | cut -d ' ' -f 1)
expect 0 "$bin" apply "$tmp/review.plan" --sha256 "$review" --root "$root"
grep -qx 'version 7' "$root/usr/share/update-fixture"
expect 0 "$bin" db check --all --root "$root"
for family in apk xbps; do
    root="$tmp/$family-root"
    repo="$tmp/$family-repo"
    mkdir -p "$root/usr/share" "$repo"
    expect 0 "$bin" db init --root "$root"
    expect 0 "$bin" source plan --config "$tmp/source.conf" --root "$root"
    cp "$tmp/out" "$tmp/$family-source.plan"
    source_plan=$(sha256sum "$tmp/$family-source.plan" | cut -d ' ' -f 1)
    expect 0 "$bin" source apply "$tmp/$family-source.plan" --sha256 "$source_plan" --root "$root"
    expect 0 "$bin" source list --root "$root"
    source_id=$(awk '$1 == "source" && $4 == "active" {print $2}' "$tmp/out")
    if test "$family" = apk; then
        package 1.0-r0 apk
    else
        package 1.0 xbps
    fi
    seal
    expect 0 "$bin" source catalog bind fixture "$repo" --root "$root"
    expect 0 "$bin" add fixture:update-fixture --root "$root" --yes
    if test "$family" = apk; then
        package 1.0-r1 apk
        revision=$(sha256sum "$repo/update-1.0-r1.holy" | cut -d ' ' -f 1)
    else
        cp -a "$tmp/tree-1.0" "$tmp/tree-1.0-r2"
        sed -i 's/^release 1$/release 2/' "$tmp/tree-1.0-r2/HOLY/meta"
        expect 0 "$bin" pack "$tmp/tree-1.0-r2" --output "$repo/update-1.0-r2.holy"
        revision=$(sha256sum "$repo/update-1.0-r2.holy" | cut -d ' ' -f 1)
    fi
    seal
    expect 0 "$bin" source catalog bind fixture "$repo" --root "$root"
    expect 0 "$bin" up fixture:update-fixture --prepare --output "$tmp/$family-revision.plan" --root "$root"
    grep -qx "new $revision" "$tmp/$family-revision.plan"
    prepared=$(sha256sum "$tmp/$family-revision.plan" | cut -d ' ' -f 1)
    expect 0 "$bin" apply "$tmp/$family-revision.plan" --sha256 "$prepared" --root "$root"
    package 1.1 "$family"
    newest=$(sha256sum "$repo/update-1.1.holy" | cut -d ' ' -f 1)
    seal
    expect 0 "$bin" source catalog bind fixture "$repo" --root "$root"
    expect 0 "$bin" up fixture:update-fixture --prepare --output "$tmp/$family-version.plan" --root "$root"
    grep -qx "new $newest" "$tmp/$family-version.plan"
    prepared=$(sha256sum "$tmp/$family-version.plan" | cut -d ' ' -f 1)
    expect 0 "$bin" apply "$tmp/$family-version.plan" --sha256 "$prepared" --root "$root"
    grep -qx 'version 1.1' "$root/usr/share/update-fixture"
    expect 0 "$bin" db check --all --root "$root"
done
# a replacement that ships a unit needs the same consent a set does, and the prepared
# plan carries it so the apply needs no flag of its own
package 3 pacman unit
third=$(sha256sum "$repo/update-3.holy" | cut -d ' ' -f 1)
seal
expect 0 "$bin" source catalog bind fixture "$repo" --root "$root"
expect 3 "$bin" up fixture:update-fixture --prepare --choose "$third" --output "$tmp/unit.plan" --root "$root"
test ! -e "$tmp/unit.plan"
expect 0 "$bin" up fixture:update-fixture --prepare --choose "$third" \
    --accept-service update-fixture --output "$tmp/unit.plan" --root "$root"
grep -qx 'service update-fixture' "$tmp/unit.plan"
grep -qx 'service etc/dinit.d/update-fixture' "$tmp/unit.plan"
grep -qxF '[services]' "$tmp/unit.plan"
prepared=$(sha256sum "$tmp/unit.plan" | cut -d ' ' -f 1)
expect 3 "$bin" apply "$tmp/unit.plan" --sha256 "$(printf '%064d' 0)" --root "$root"
expect 0 "$bin" apply "$tmp/unit.plan" --sha256 "$prepared" --root "$root"
test -f "$root/etc/dinit.d/update-fixture"
grep -qx 'version 3' "$root/usr/share/update-fixture"
expect 0 "$bin" db check --all --root "$root"
# a group prepares several slots as one reviewed plan, and applying it needs no flag of
# its own because the document states every decision the transaction had
package 11 holy '' other
other_old=$(sha256sum "$repo/update-11.holy" | cut -d ' ' -f 1)
seal
expect 0 "$bin" source catalog bind fixture "$repo" --root "$root"
expect 0 "$bin" add fixture:other --root "$root" --yes
grep -qx 'version 11' "$root/usr/share/other"
package 8 holy
newer=$(sha256sum "$repo/update-8.holy" | cut -d ' ' -f 1)
package 12 holy '' other
other_new=$(sha256sum "$repo/update-12.holy" | cut -d ' ' -f 1)
seal
expect 0 "$bin" source catalog bind fixture "$repo" --root "$root"
index=$(awk '$1 == "sha256" {print $2}' "$repo/current")
expect 0 "$bin" up fixture:update-fixture fixture:other --prepare \
    --choose "fixture:update-fixture=$newer" --output "$tmp/group.plan" --root "$root"
group=$(sha256sum "$tmp/group.plan" | cut -d ' ' -f 1)
grep -qx "prepared-slot 0 source-id $source_id old $third new $newer index $index signature unsigned" "$tmp/out"
grep -qx "prepared-slot 1 source-id $source_id old $other_old new $other_new index $index signature unsigned" "$tmp/out"
grep -qx "prepared $group $tmp/group.plan slots 2" "$tmp/out"
grep -qx 'slot 0' "$tmp/group.plan"
grep -qx 'slot 1' "$tmp/group.plan"
grep -qx 'signature unsigned' "$tmp/group.plan"
grep -qx 'replacement 2' "$tmp/group.plan"
grep -qx 'format holy-update-plan-2' "$tmp/group.plan"
grep -qxF '[update]' "$tmp/group.plan"
# --all reaches the same two slots, and a --choose naming one of them settles that slot
# while the other keeps the version its family orders
expect 0 "$bin" up --all --prepare --choose "fixture:update-fixture=$newer" \
    --output "$tmp/family-all.plan" --root "$root"
# --all has no caller order, so its slots come in the walk's order and the documents are
# the same set rather than the same bytes
grep -qx 'replacement 2' "$tmp/family-all.plan"
for pair in "$third $newer" "$other_old $other_new"; do
    grep -qx "old ${pair% *}" "$tmp/family-all.plan"
    grep -qx "new ${pair#* }" "$tmp/family-all.plan"
done
grep -qx "prepared $(sha256sum "$tmp/family-all.plan" | cut -d ' ' -f 1) $tmp/family-all.plan slots 2" "$tmp/out"
# a path a plan already occupies is refused rather than overwritten, and the refusal says
# which of the two it is instead of leaving status 1 to be guessed at
expect 1 "$bin" up --all --prepare --choose "fixture:update-fixture=$newer" \
    --output "$tmp/family-all.plan" --root "$root"
grep -qx 'holypkg: plan: File exists' "$tmp/err"
expect 1 "$bin" up --all --prepare --choose "fixture:update-fixture=$newer" \
    --output "$tmp/no-such-dir/plan" --root "$root"
grep -qx 'holypkg: plan directory: No such file or directory' "$tmp/err"
expect 3 "$bin" apply "$tmp/group.plan" --sha256 "$(printf '%064d' 0)" --root "$root"
grep -qx 'version 3' "$root/usr/share/update-fixture"
expect 0 "$bin" apply "$tmp/group.plan" --sha256 "$group" --root "$root"
grep -qx "updated-group slots 2 generation $(cat "$root/var/lib/holypkg/generation") plan $(sed -n 's/^state-plan //p' "$tmp/group.plan")" "$tmp/out"
grep -qx 'version 8' "$root/usr/share/update-fixture"
grep -qx 'version 12' "$root/usr/share/other"
expect 0 "$bin" db check --all --root "$root"
# --all over two installed slots of one source prepares them as one plan and applies it
# as one transaction, without the caller naming either slot
variant() {
    from=$1 to=$2 version=$3
    rm -rf "$tmp/tree-$to-$version"
    cp -a "$tmp/tree-$version" "$tmp/tree-$to-$version"
    sed -i "s/^name $from\$/name $to/" "$tmp/tree-$to-$version/HOLY/meta"
    mv "$tmp/tree-$to-$version/DATA/usr/share/$from" \
       "$tmp/tree-$to-$version/DATA/usr/share/$to"
    expect 0 "$bin" manifest generate "$tmp/tree-$to-$version" \
        --output "$tmp/$to-$version-files"
    mv "$tmp/$to-$version-files" "$tmp/tree-$to-$version/HOLY/files"
    expect 0 "$bin" pack "$tmp/tree-$to-$version" --output "$repo/$to-$version.holy"
}
group_root="$tmp/group-root"
group_repo="$tmp/group-repo"
mkdir -p "$group_root/usr/share" "$group_repo"
root="$group_root"; repo="$group_repo"
expect 0 "$bin" db init --root "$root"
expect 0 "$bin" source plan --config "$tmp/source.conf" --root "$root"
cp "$tmp/out" "$tmp/group-source.plan"
group_source_plan=$(sha256sum "$tmp/group-source.plan" | cut -d ' ' -f 1)
expect 0 "$bin" source apply "$tmp/group-source.plan" --sha256 "$group_source_plan" --root "$root"
expect 0 "$bin" source list --root "$root"
group_source=$(awk '$1 == "source" && $4 == "active" {print $2}' "$tmp/out")
# the shared helper appends to a tree it does not clear, so the two versions this block
# reuses are removed first
rm -rf "$tmp/tree-1" "$tmp/tree-2"
package 1 pacman '' alpha
variant alpha beta 1
seal
expect 0 "$bin" source catalog bind fixture "$repo" --root "$root"
expect 0 "$bin" add fixture:alpha --root "$root" --yes
expect 0 "$bin" add fixture:beta --root "$root" --yes
grep -qx 'version 1' "$root/usr/share/alpha"
grep -qx 'version 1' "$root/usr/share/beta"
package 2 pacman '' alpha
variant alpha beta 2
seal
expect 0 "$bin" source catalog bind fixture "$repo" --root "$root"
expect 0 "$bin" up --all --prepare --output "$tmp/group-all.plan" --root "$root"
group_all=$(sha256sum "$tmp/group-all.plan" | cut -d ' ' -f 1)
grep -qx "prepared $group_all $tmp/group-all.plan slots 2" "$tmp/out"
grep -qx 'slot 0' "$tmp/group-all.plan"
grep -qx 'slot 1' "$tmp/group-all.plan"
grep -qx 'replacement 2' "$tmp/group-all.plan"
grep -qx "source-id $group_source" "$tmp/group-all.plan"
# one --yes applies the group, and both payloads moved under one generation
expect 0 "$bin" up --all --yes --root "$root"
grep -qx 'version 2' "$root/usr/share/alpha"
grep -qx 'version 2' "$root/usr/share/beta"
expect 0 "$bin" db check --all --root "$root"
# a second run has nothing newer anywhere, so no plan is written
expect 0 "$bin" up --all --prepare --output "$tmp/group-none.plan" --root "$root"
test ! -e "$tmp/group-none.plan"
grep -c '^up-to-date ' "$tmp/out"
test "$(grep -c '^up-to-date ' "$tmp/out")" -eq 2
# a reference the installed set does not hold, and one it holds under another arch, name
# what is missing instead of leaving the status to be read
expect 6 "$bin" up fixture:absent --prepare --output "$tmp/absent.plan" --root "$root"
grep -qx 'holypkg: installed source slot unavailable for absent' "$tmp/err"
test ! -e "$tmp/absent.plan"
# the same reference under an architecture or libc it is not installed for says which
# narrowing excluded it, since the bare refusal reads as a name that is not installed
expect 6 "$bin" up fixture:alpha --arch aarch64 --prepare --output "$tmp/arch.plan" \
    --root "$root"
grep -qx 'holypkg: installed source slot unavailable for alpha (architecture aarch64)' \
    "$tmp/err"
test ! -e "$tmp/arch.plan"
expect 6 "$bin" up fixture:alpha --libc glibc --prepare --output "$tmp/libc.plan" \
    --root "$root"
grep -qx 'holypkg: installed source slot unavailable for alpha (libc glibc)' "$tmp/err"
expect 6 "$bin" up fixture:alpha --arch aarch64 --libc glibc --prepare \
    --output "$tmp/both.plan" --root "$root"
grep -qx 'holypkg: installed source slot unavailable for alpha (architecture aarch64, libc glibc)' \
    "$tmp/err"
# a catalog that cannot be opened says which path and why, since --catalog names it
expect 6 "$bin" up fixture:alpha --catalog "$tmp/absent-catalog" --prepare \
    --output "$tmp/catalog.plan" --root "$root"
grep -qx "holypkg: catalog $tmp/absent-catalog unavailable for source fixture: No such file or directory" \
    "$tmp/err"
test ! -e "$tmp/catalog.plan"
printf 'source update preparation and apply fixtures passed\n'
