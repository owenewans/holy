#!/bin/sh
set -eu
bin=$(realpath "$1")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
printf '#!/bin/sh\nexec "$@"\n' > "$tmp/busybox"
chmod 0755 "$tmp/busybox"
mkdir -p "$tmp/tree/HOLY" "$tmp/tree/DATA" "$tmp/repo" "$tmp/id-root" \
    "$tmp/live/var/cache/holypkg/image-mirrors" "$tmp/target" "$tmp/inputs"
printf 'format holy-package-1\nname sourced\nversion 1\nrelease 1\nos linux\narch noarch\nlibc nolibc\n' \
    > "$tmp/tree/HOLY/meta"
for member in files deps provides hooks origin transform; do
    : > "$tmp/tree/HOLY/$member"
done
tar -cf "$tmp/package.tar" -C "$tmp/tree" HOLY DATA
lz4 -q "$tmp/package.tar" "$tmp/repo/sourced.holy"
"$bin" repo index "$tmp/repo" > "$tmp/result"
"$bin" repo seal "$tmp/repo" > "$tmp/result"
printf '[source fixture]\ntype holy-http\nurl "https://fixture.example/holy/"\n' \
    > "$tmp/inputs/install-sources.conf"
printf 'fixture\n' > "$tmp/inputs/install-source-aliases"
"$bin" db init --root "$tmp/id-root" > "$tmp/result"
"$bin" source plan --config "$tmp/inputs/install-sources.conf" \
    --root "$tmp/id-root" > "$tmp/id.plan"
plan=$(sha256sum "$tmp/id.plan")
"$bin" source apply "$tmp/id.plan" --sha256 "${plan%% *}" \
    --root "$tmp/id-root" > "$tmp/result"
"$bin" source list --root "$tmp/id-root" > "$tmp/id.list"
source_id=$(sed -n 's/^source \([0-9a-f]*\) "fixture" active$/\1/p' "$tmp/id.list")
test "${#source_id}" -eq 64
index=$(sed -n 's/^sha256 //p' "$tmp/repo/current")
printf 'format holy-mirror-1\nurl "https://fixture.example/holy/"\nindex-sha256 %s\nverification digest-pinned-unsigned\nsource-id %s\n' \
    "$index" "$source_id" > "$tmp/repo/mirror-origin"
cp -R "$tmp/repo" "$tmp/live/var/cache/holypkg/image-mirrors/fixture"
digest=$(sha256sum "$tmp/repo/sourced.holy")
digest=${digest%% *}
printf 'source %s %s\n' "$digest" "$source_id" \
    > "$tmp/inputs/install-source-bindings"
"$bin" db init --root "$tmp/target" > "$tmp/result"
sh tools/install-source-stage.sh "$bin" "$tmp/inputs" "$tmp/live" \
    "$tmp/target" "$tmp/bindings" "$tmp/busybox"
test "$(cat "$tmp/bindings")" = "source $digest $source_id"
cmp "$tmp/inputs/install-sources.conf" "$tmp/target/etc/holy.conf"
"$bin" cache stage "local:$tmp/repo/sourced.holy" --root "$tmp/target" > "$tmp/result"
printf '[install]\nroot "%s"\nartifact %s\n' "$tmp/target" "$digest" \
    > "$tmp/install.conf"
cat "$tmp/bindings" >> "$tmp/install.conf"
./holyinstall --config "$tmp/install.conf" --plan "$tmp/install.plan" \
    --holypkg "$bin" > "$tmp/result"
./holyinstall --apply "$tmp/install.plan" --holypkg "$bin" > "$tmp/result"
"$bin" db check --all --root "$tmp/target" > "$tmp/result"
grep -q "^source $source_id " \
    "$tmp/target/var/lib/holypkg/installed/$digest/source"
mv "$tmp/target" "$tmp/relocated"
mkdir "$tmp/fetched"
"$bin" fetch fixture:sourced --root "$tmp/relocated" \
    --output "$tmp/fetched" > "$tmp/result"
test -f "$tmp/fetched/$digest.holy"
mkdir "$tmp/local-root" "$tmp/local-inputs"
"$bin" db init --root "$tmp/local-root" > "$tmp/result"
: > "$tmp/local-inputs/install-source-bindings"
sh tools/install-source-stage.sh "$bin" "$tmp/local-inputs" "$tmp/live" \
    "$tmp/local-root" "$tmp/local-bindings" "$tmp/busybox"
test ! -s "$tmp/local-bindings"
mkdir "$tmp/bad-root"
"$bin" db init --root "$tmp/bad-root" > "$tmp/result"
printf 'source %s %064d\n' "$digest" 0 \
    > "$tmp/inputs/install-source-bindings"
if sh tools/install-source-stage.sh "$bin" "$tmp/inputs" "$tmp/live" \
    "$tmp/bad-root" "$tmp/bad-bindings" "$tmp/busybox" \
    > "$tmp/result" 2> "$tmp/error"; then
    exit 1
else
    test "$?" -eq 3
fi
printf 'install source staging passed\n'
