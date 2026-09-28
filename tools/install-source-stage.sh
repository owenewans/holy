#!/bin/sh
set -eu
test "$#" -eq 6 || exit 2
bin=$1
inputs=$2
live=$3
target=$4
output=$5
bb=$6
test -d "$target/var/lib/holypkg" && test -d "$inputs" || exit 6
: > "$output"
if test ! -f "$inputs/install-sources.conf"; then
    test ! -s "$inputs/install-source-bindings" || exit 6
    exit 0
fi
test -f "$inputs/install-source-aliases" && \
    test -f "$inputs/install-source-bindings" || exit 6
"$bb" mkdir -p "$target/etc"
"$bb" cp "$inputs/install-sources.conf" "$target/etc/holy.conf"
"$bin" source plan --config "$target/etc/holy.conf" --root "$target" \
    > "$output.plan"
plan=$("$bb" sha256sum "$output.plan")
"$bin" source apply "$output.plan" --sha256 "${plan%% *}" \
    --root "$target" > "$output.apply"
while IFS= read -r alias; do
    case "$alias" in ''|*[!a-zA-Z0-9_-]*) exit 2 ;; esac
    if test -d "$live/var/cache/holypkg/image-mirrors/$alias"; then
        "$bb" mkdir -p "$target/var/cache/holypkg/image-mirrors"
        "$bb" cp -R "$live/var/cache/holypkg/image-mirrors/$alias" \
            "$target/var/cache/holypkg/image-mirrors/$alias"
        "$bin" source catalog bind "$alias" \
            "$target/var/cache/holypkg/image-mirrors/$alias" \
            --root "$target" > "$output.bind"
    fi
done < "$inputs/install-source-aliases"
"$bin" source list --root "$target" > "$output.registry"
while read -r kind digest source_id; do
    test "$kind" = source && test "${#digest}" -eq 64 && \
        test "${#source_id}" -eq 64 || exit 2
    case "$digest$source_id" in *[!0-9a-f]*) exit 2 ;; esac
    "$bb" grep -q "^source $source_id " "$output.registry" || exit 3
    printf 'source %s %s\n' "$digest" "$source_id" >> "$output"
done < "$inputs/install-source-bindings"
