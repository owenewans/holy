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
            "$bin" repo solve "$out/mirrors/$alias" "$package_name" \
                > "$work/solve-$alias-$package_name.record"
            sed -n 's/^selected \([0-9a-f]*\)$/\1/p' \
                "$work/solve-$alias-$package_name.record" > "$work/selected"
            test -s "$work/selected" || exit 6
            while IFS= read -r digest; do
                test "${#digest}" -eq 64 || exit 6
                existing=$(awk -v hash="$digest" '$1 == hash {print $2}' "$work/source-artifacts")
                if test -n "$existing"; then
                    test "$existing" = "$source_id" || {
                        echo "artifact $digest selected from multiple sources" >&2
                        exit 4
                    }
                    continue
                fi
                mkdir "$work/fetch-$digest"
                "$bin" repo fetch "$out/mirrors/$alias" "$digest" \
                    --output "$work/fetch-$digest" > "$work/fetch-$digest.record"
                input="$work/fetch-$digest/$digest.holy"
                test "$(cat "$work/fetch-$digest.record")" = "$input" || exit 6
                test -f "$input" || exit 6
                add_image_package "$input" "$source_id"
                printf '%s %s\n' "$digest" "$source_id" >> "$work/source-artifacts"
            done < "$work/selected" ;;
        *) exit 2 ;;
    esac
done
printf '\n' >> "$work/additional-packages"
