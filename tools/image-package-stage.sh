#!/bin/sh
set -eu
test "$#" -ge 3 || exit 2
bin=$(realpath "$1")
out=$(realpath "$2")
arch=$3
shift 3
work="$out/work"
record="$out/build.record"
test -d "$work" && test -d "$out/packages" && test -d "$out/inputs" || exit 6
case "$arch" in x86_64|i686) ;; *) exit 2 ;; esac
additional_index=0
: > "$work/additional-packages"
: > "$work/source-artifacts"
: > "$work/requested-sources"
scan_kind=
scan_alias=
for token do
    case "$scan_kind" in
        local) scan_kind= ;;
        alias) scan_alias=$token; scan_kind=package ;;
        package)
            printf '%s %s\n' "$scan_alias" "$token" >> "$work/requested-sources"
            scan_kind= ;;
        *)
            case "$token" in
                --local) scan_kind=local ;;
                --source) scan_kind=alias ;;
                *) exit 2 ;;
            esac ;;
    esac
done
test -z "$scan_kind" || exit 2
add_image_package() {
    input=$1
    selected_source=${2:-}
    additional_index=$((additional_index + 1))
    label=$(printf 'add-%04d' "$additional_index")
    cp "$input" "$out/inputs/$label.holy"
    "$bin" info "local:$out/inputs/$label.holy" > "$work/input-info"
    target_arch=$(sed -n 's/^arch //p' "$work/input-info")
    case "$arch:$target_arch" in
        x86_64:x86_64|x86_64:x86|x86_64:noarch|i686:x86|i686:noarch) ;;
        *) echo "additional package $label has incompatible arch $target_arch" >&2; exit 6 ;;
    esac
    cp "$out/inputs/$label.holy" "$out/packages/$label.holy"
    input_hash=$(sha256sum "$out/inputs/$label.holy")
    input_hash=${input_hash%% *}
    printf 'additional-input %s %s\n' "$label" "$input_hash" >> "$record"
    printf ' %s' "$label" >> "$work/additional-packages"
    if test -n "$selected_source"; then
        printf '%s %s\n' "$label" "$selected_source" >> "$work/add-sources"
    fi
}
prepare_resolver() {
    resolver_root="$work/resolver-root"
    if test -d "$resolver_root"; then return; fi
    test -f "$out/inputs/sources.conf" || exit 6
    mkdir "$resolver_root"
    "$bin" db init --root "$resolver_root" > "$work/resolver-init.record"
    "$bin" source plan --config "$out/inputs/sources.conf" --root "$resolver_root" \
        > "$work/resolver-source.plan"
    resolver_plan=$(sha256sum "$work/resolver-source.plan")
    "$bin" source apply "$work/resolver-source.plan" --sha256 "${resolver_plan%% *}" \
        --root "$resolver_root" > "$work/resolver-source.record"
    while IFS= read -r resolver_alias; do
        "$bin" source catalog bind "$resolver_alias" "$out/mirrors/$resolver_alias" \
            --root "$resolver_root" > "$work/resolver-bind-$resolver_alias.record"
    done < "$out/inputs/source-aliases"
}
while test "$#" -gt 0; do
    case "$1" in
        --local)
            test "$#" -ge 2 || exit 2
            add_image_package "$2"
            shift 2 ;;
        --source)
            test "$#" -ge 3 && test -f "$work/source-list" || exit 2
            alias=$2
            package_name=$3
            shift 3
            case "$alias" in ''|*[!a-zA-Z0-9_-]*) exit 2 ;; esac
            case "$package_name" in ''|*[!a-zA-Z0-9._+-]*) exit 2 ;; esac
            source_id=$(awk -v name="\"$alias\"" \
                '$1 == "source" && $3 == name && $4 == "active" {print $2}' "$work/source-list")
            test "${#source_id}" -eq 64 || exit 6
            prepare_resolver
            (
                set -- "$bin" add "$alias:$package_name" --root "$resolver_root" \
                    --prepare --noninteractive
                while read -r candidate_alias candidate_name; do
                    if test "$candidate_alias" != "$alias"; then
                        set -- "$@" --candidate "$candidate_alias:$candidate_name"
                    fi
                done < "$work/requested-sources"
                "$@"
            ) > "$work/solve-$alias-$package_name.record"
            awk '$1 == "selected" {print $2}' \
                "$work/solve-$alias-$package_name.record" > "$work/selected"
            test -s "$work/selected" || exit 6
            while IFS= read -r digest; do
                test "${#digest}" -eq 64 || exit 6
                selected_source=$(awk -v hash="$digest" \
                    '$1 == "binding" && $2 == hash && $3 == "source" {print $4}' \
                    "$work/solve-$alias-$package_name.record")
                test "${#selected_source}" -eq 64 || exit 6
                selected_alias=$(awk -v id="$selected_source" \
                    '$1 == "source" && $2 == id && $4 == "active" {gsub(/"/, "", $3); print $3}' \
                    "$work/source-list")
                test -n "$selected_alias" || exit 6
                existing=$(awk -v hash="$digest" '$1 == hash {print $2}' "$work/source-artifacts")
                if test -n "$existing"; then
                    test "$existing" = "$selected_source" || {
                        echo "artifact $digest selected from multiple sources" >&2
                        exit 4
                    }
                    continue
                fi
                mkdir "$work/fetch-$digest"
                "$bin" repo fetch "$out/mirrors/$selected_alias" "$digest" \
                    --output "$work/fetch-$digest" > "$work/fetch-$digest.record"
                input="$work/fetch-$digest/$digest.holy"
                test "$(cat "$work/fetch-$digest.record")" = "$input" || exit 6
                test -f "$input" || exit 6
                add_image_package "$input" "$selected_source"
                printf '%s %s\n' "$digest" "$selected_source" >> "$work/source-artifacts"
            done < "$work/selected" ;;
        *) exit 2 ;;
    esac
done
printf '\n' >> "$work/additional-packages"
