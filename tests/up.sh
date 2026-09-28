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
    version=$1 comparator=${2:-pacman}
    tree="$tmp/tree-$version"
    mkdir -p "$tree/HOLY" "$tree/DATA/usr/share"
    printf 'format holy-package-1\nname update-fixture\nversion %s\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' "$version" > "$tree/HOLY/meta"
    if test "$comparator" != unknown; then
        printf 'x-version-family %s\n' "$comparator" >> "$tree/HOLY/meta"
    fi
    for field in deps provides hooks origin transform; do : > "$tree/HOLY/$field"; done
    if test "$version" = 2; then
        printf 'record payload normalized before pack\n' > "$tree/HOLY/transform"
    fi
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
expect 0 "$bin" up fixture:update-fixture --prepare --output "$tmp/fresh.plan" --root "$root"
fresh=$(sha256sum "$tmp/fresh.plan" | cut -d ' ' -f 1)
expect 0 "$bin" apply "$tmp/fresh.plan" --sha256 "$fresh" --root "$root"
grep -qx 'version 2' "$root/usr/share/update-fixture"
grep -qx "source-id $source_id" "$root/var/lib/holypkg/installed/$next/state"
expect 0 "$bin" db check --all --root "$root"
expect 0 "$bin" up fixture:update-fixture --prepare --output "$tmp/no-newer" --root "$root"
test ! -e "$tmp/no-newer"
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
printf 'source update preparation and apply fixtures passed\n'
