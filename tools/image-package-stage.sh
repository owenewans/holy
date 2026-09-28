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
: > "$work/core-roots"
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
        core_role) scan_kind=alias ;;
        *)
            case "$token" in
                --local) scan_kind=local ;;
                --source) scan_kind=alias ;;
                --core) scan_kind=core_role ;;
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
        --source|--core)
            kind=$1
            if test "$kind" = --core; then
                test "$#" -ge 4 || exit 2
                role=$2
                case "$role" in busybox|dinit|mdevd|glibc|musl) ;; *) exit 2 ;; esac
                shift
            fi
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
            accepted_arch=
            while :; do
                if (
                    set -- "$bin" add "$alias:$package_name" --root "$resolver_root" \
                        --prepare --noninteractive
                    if test -f "$out/inputs/resolver-answers"; then
                        set -- "$@" --answers "$out/inputs/resolver-answers"
                    fi
                    while read -r candidate_alias candidate_name; do
                        if test "$candidate_alias" != "$alias"; then
                            set -- "$@" --candidate "$candidate_alias:$candidate_name"
                        fi
                    done < "$work/requested-sources"
                    for accepted in $accepted_arch; do
                        set -- "$@" --accept-arch "$accepted"
                    done
                    "$@"
                ) > "$work/solve-$alias-$package_name.record" \
                    2> "$work/solve-$alias-$package_name.error"; then
                    break
                else
                    rc=$?
                fi
                if test "$rc" -ne 3; then
                    cat "$work/solve-$alias-$package_name.error" >&2
                    exit "$rc"
                fi
                awk '$1 == "holypkg:" && $2 == "decision-required" &&
                     $3 == "architecture" {
                         hash = ""; target = ""
                         for (i = 4; i <= NF; ++i) {
                             if ($i ~ /^artifact=/) hash = substr($i, 10)
                             if ($i ~ /^target=/) target = $i
                         }
                         if (target == "target=x86;") print hash
                     }' "$work/solve-$alias-$package_name.error" \
                    > "$work/arch-decisions"
                new_decision=0
                while IFS= read -r accepted; do
                    test "${#accepted}" -eq 64 || exit 6
                    case "$accepted" in *[!0-9a-f]*) exit 6 ;; esac
                    case " $accepted_arch " in *" $accepted "*) continue ;; esac
                    "$bin" info "local:$resolver_root/var/cache/holypkg/objects/sha256/$accepted.holy" \
                        > "$work/arch-info"
                    grep -qx 'arch x86' "$work/arch-info" || exit 4
                    accepted_arch="$accepted_arch $accepted"
                    new_decision=1
                    printf 'resolver-architecture image %s artifact %s accepted\n' \
                        "$arch" "$accepted" >> "$record"
                done < "$work/arch-decisions"
                if test "$new_decision" -eq 0; then
                    cat "$work/solve-$alias-$package_name.error" >&2
                    exit 3
                fi
            done
            if test "$kind" = --core; then
                root_digest=$(awk '$1 == "plan-set" && $4 == "root" {print $5}' \
                    "$work/solve-$alias-$package_name.record")
                test "${#root_digest}" -eq 64 || exit 6
                printf '%s %s %s\n' "$role" "$root_digest" "$source_id" >> "$work/core-roots"
            fi
            awk '$1 == "selected" {print $2}' \
                "$work/solve-$alias-$package_name.record" > "$work/selected"
            test -s "$work/selected" || exit 6
            while IFS= read -r digest; do
                test "${#digest}" -eq 64 || exit 6
                selected_source=$(awk -v hash="$digest" \
                    '$1 == "binding" && $2 == hash && $3 == "source" {print $4}' \
                    "$work/solve-$alias-$package_name.record")
                test "${#selected_source}" -eq 64 || exit 6
                existing=$(awk -v hash="$digest" '$1 == hash {print $2}' "$work/source-artifacts")
                if test -n "$existing"; then
                    test "$existing" = "$selected_source" || {
                        echo "artifact $digest selected from multiple sources" >&2
                        exit 4
                    }
                    continue
                fi
                printf '%s %s\n' "$digest" "$selected_source" >> "$work/source-artifacts"
            done < "$work/selected" ;;
        *) exit 2 ;;
    esac
done
while read -r digest selected_source; do
    selected_alias=$(awk -v id="$selected_source" \
        '$1 == "source" && $2 == id && $4 == "active" {gsub(/"/, "", $3); print $3}' \
        "$work/source-list")
    test -n "$selected_alias" || exit 6
    mkdir "$work/fetch-$digest"
    "$bin" repo fetch "$out/mirrors/$selected_alias" "$digest" \
        --output "$work/fetch-$digest" > "$work/fetch-$digest.record"
    input="$work/fetch-$digest/$digest.holy"
    test "$(cat "$work/fetch-$digest.record")" = "$input" && test -f "$input" || exit 6
    roles=$(awk -v hash="$digest" '$2 == hash {print $1}' "$work/core-roots")
    if test -n "$roles"; then
        test "$(printf '%s\n' "$roles" | wc -l)" -eq 1 || {
            echo "artifact $digest selected for multiple core roles" >&2
            exit 4
        }
        role=$roles
        root_source=$(awk -v hash="$digest" '$2 == hash {print $3}' "$work/core-roots")
        test "$root_source" = "$selected_source" || exit 4
        cp "$input" "$work/core-$role.holy"
        printf '%s %s\n' "$role" "$selected_source" >> "$work/add-sources"
        printf 'core-input %s %s %s\n' "$role" "$digest" "$selected_source" >> "$record"
    else
        add_image_package "$input" "$selected_source"
    fi
done < "$work/source-artifacts"
printf '\n' >> "$work/additional-packages"
