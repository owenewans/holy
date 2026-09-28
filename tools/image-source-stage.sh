#!/bin/sh
set -eu
test "$#" -eq 4 || exit 2
bin=$1
root=$2
out=$3
inputs=$4
record="$out/build.record"
work="$out/work"
test -f "$inputs/sources.conf" && test -f "$inputs/aliases" || exit 6
cp "$inputs/sources.conf" "$out/inputs/sources.conf"
cp "$inputs/aliases" "$out/inputs/source-aliases"
sha256sum "$out/inputs/sources.conf" "$out/inputs/source-aliases" >> "$record"
"$bin" source plan --config "$out/inputs/sources.conf" --root "$root" > "$out/source.plan"
source_plan=$(sha256sum "$out/source.plan")
source_plan=${source_plan%% *}
printf 'source-plan %s\n' "$source_plan" >> "$record"
"$bin" source apply "$out/source.plan" --sha256 "$source_plan" --root "$root"
"$bin" source list --root "$root" > "$work/source-list"
mkdir "$out/mirrors"
while IFS= read -r alias; do
    case "$alias" in ''|*[!a-zA-Z0-9_-]*) exit 2 ;; esac
    index=$(cat "$inputs/$alias.index")
    case "$index" in *[!0-9a-f]*|'') exit 2 ;; esac
    test "${#index}" -eq 64 || exit 2
    commit=
    if test -f "$inputs/$alias.commit"; then
        commit=$(cat "$inputs/$alias.commit")
        case "$commit" in *[!0-9a-f]*|'') exit 2 ;; esac
        case "${#commit}" in 40|64) ;; *) exit 2 ;; esac
    fi
    source_id=$(awk -v name="\"$alias\"" \
        '$1 == "source" && $3 == name && $4 == "active" {print $2}' "$work/source-list")
    test "${#source_id}" -eq 64 || exit 6
    if test -f "$inputs/$alias.mirror"; then
        mirror=$(cat "$inputs/$alias.mirror")
        test "$(cat "$mirror/current")" = "sha256 $index" || exit 4
        cp -R "$mirror" "$out/mirrors/$alias"
        test "$(cat "$out/mirrors/$alias/current")" = "sha256 $index" || exit 4
        printf 'source-mirror %s imported\n' "$alias" >> "$record"
    else
        set -- "$bin" sync "$alias" --root "$root" --sha256 "$index" \
            --output "$out/mirrors/$alias"
        if test -n "$commit"; then set -- "$@" --commit "$commit"; fi
        if test -f "$inputs/$alias.ca"; then
            ca_file=$(cat "$inputs/$alias.ca")
            sha256sum "$ca_file" >> "$record"
            set -- "$@" --ca-file "$ca_file"
        fi
        "$@"
        printf 'source-mirror %s downloaded\n' "$alias" >> "$record"
    fi
    if test -f "$inputs/$alias.embed"; then
        test "$(cat "$inputs/$alias.embed")" = yes || exit 2
        mkdir -p "$root/var/cache/holypkg/image-mirrors"
        cp -R "$out/mirrors/$alias" "$root/var/cache/holypkg/image-mirrors/$alias"
        "$bin" source catalog bind "$alias" \
            "$root/var/cache/holypkg/image-mirrors/$alias" --root "$root"
        printf 'source-embedded %s full-catalog\n' "$alias" >> "$record"
    fi
    printf 'source %s %s index %s\n' "$alias" "$source_id" "$index" >> "$record"
    if test -n "$commit"; then printf 'source-commit %s %s\n' "$alias" "$commit" >> "$record"; fi
done < "$out/inputs/source-aliases"
