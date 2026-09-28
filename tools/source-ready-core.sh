#!/bin/sh
set -eu

if test "${1:-}" = --pack; then
    test "$#" -eq 6 || exit 2
    bin=$2
    input=$3
    output=$4
    tree=$5
    role=$6
    test "$(id -u)" = 0 &&
        awk '$1 == 0 && $2 != 0 && $3 == 1 { ok = 1 } END { exit !ok }' \
            /proc/self/uid_map || exit 6
    "$bin" fetch "local:$input" --extract --output "$tree" > /dev/null
    test ! -s "$tree/HOLY/transform" || {
        echo "source-ready: $role already has local transforms" >&2
        exit 4
    }
    chown -hR 0:0 "$tree/DATA"
    parent=$(sha256sum "$input")
    printf 'source-ready-parent-sha256 %s\nsource-ready-ownership 0 0\n' \
        "${parent%% *}" >> "$tree/HOLY/origin"
    "$bin" manifest generate "$tree" --output "$tree.files" > /dev/null
    mv "$tree.files" "$tree/HOLY/files"
    "$bin" pack "$tree" --output "$output" > /dev/null
    exit 0
fi

test "$#" -eq 9 || {
    echo 'usage: source-ready-core.sh HOLYPKG OUTPUT ALIAS URL BUSYBOX DINIT MDEVD GLIBC MUSL' >&2
    exit 2
}
bin=$(realpath "$1")
out=$2
alias=$3
url=$4
case "$alias" in ''|*[!a-zA-Z0-9_-]*) exit 2 ;; esac
case "$url" in https://*|http://*) ;; *) exit 2 ;; esac
authority=${url#*://}
authority=${authority%%/*}
case "$authority" in ''|*@*|*' '*|*'	'*) exit 2 ;; esac
test "$(id -u)" != 0 || { echo 'source-ready: run as an ordinary user' >&2; exit 6; }
for tool in unshare chown sha256sum awk python3; do
    command -v "$tool" >/dev/null || { echo "source-ready: $tool required" >&2; exit 6; }
done
python3 - "$url" "$out" <<'PY'
import sys

if any(ord(char) < 32 or char in '"\\' for value in sys.argv[1:] for char in value):
    sys.exit('source-ready: URL and output path cannot contain quotes, backslashes or controls')
PY
mkdir "$out"
out=$(realpath "$out")
mkdir "$out/inputs" "$out/repo" "$out/work" "$out/identity"
printf 'format holy-source-ready-core-1\nsource-alias %s\n' "$alias" > "$out/build.record"
script=$(realpath "$0")
shift 4
for role in busybox dinit mdevd glibc musl; do
    input=$(realpath "$1")
    shift
    cp "$input" "$out/inputs/$role.holy"
    input="$out/inputs/$role.holy"
    "$bin" info "local:$input" > "$out/work/$role.info"
    name=$(sed -n 's/^name //p' "$out/work/$role.info")
    arch=$(sed -n 's/^arch //p' "$out/work/$role.info")
    libc=$(sed -n 's/^libc //p' "$out/work/$role.info")
    case "$name:$arch" in
        *:x86|*:x86_64) ;;
        *) echo "source-ready: $role requires an x86 ELF package" >&2; exit 4 ;;
    esac
    case "$role:$libc" in
        busybox:nolibc|dinit:nolibc|mdevd:nolibc|glibc:glibc|musl:musl) ;;
        *) echo "source-ready: $role has unexpected libc $libc" >&2; exit 4 ;;
    esac
    if test -n "${target_arch:-}"; then
        test "$target_arch" = "$arch" || {
            echo "source-ready: $role has target $arch, expected $target_arch" >&2
            exit 4
        }
    else
        target_arch=$arch
    fi
    case "$name" in ''|*[!a-zA-Z0-9._+-]*) exit 4 ;; esac
    printf '%s %s\n' "$role" "$name" >> "$out/work/names"
    unshare --map-root-user -- sh "$script" --pack "$bin" "$input" \
        "$out/repo/$role.holy" "$out/work/tree-$role" "$role"
    "$bin" verify "local:$out/repo/$role.holy" > "$out/work/$role.verify"
    parent=$(sha256sum "$input")
    artifact=$(sha256sum "$out/repo/$role.holy")
    printf 'core %s %s %s\n' "$role" "${parent%% *}" "${artifact%% *}" \
        >> "$out/build.record"
done

"$bin" repo index "$out/repo" > "$out/work/index.record"
"$bin" repo seal "$out/repo" > "$out/work/seal.record"
index=$(sed -n 's/^sha256 //p' "$out/repo/current")
test "${#index}" -eq 64 || exit 6
printf '[source %s]\ntype holy-http\nurl "%s"\n' "$alias" "$url" \
    > "$out/work/source.conf"
"$bin" db init --root "$out/identity" > "$out/work/db.record"
"$bin" source plan --config "$out/work/source.conf" --root "$out/identity" \
    > "$out/work/source.plan"
plan=$(sha256sum "$out/work/source.plan")
"$bin" source apply "$out/work/source.plan" --sha256 "${plan%% *}" \
    --root "$out/identity" > "$out/work/source.record"
"$bin" source list --root "$out/identity" > "$out/work/sources"
source_id=$(awk -v name="\"$alias\"" \
    '$1 == "source" && $3 == name && $4 == "active" {print $2}' \
    "$out/work/sources")
test "${#source_id}" -eq 64 || exit 6
printf 'format holy-mirror-1\nurl "%s"\nindex-sha256 %s\nverification digest-pinned-unsigned\nsource-id %s\n' \
    "$url" "$index" "$source_id" > "$out/repo/mirror-origin"
printf '[source %s]\ntype holy-http\nurl "%s"\nindex-sha256 %s\nmirror "%s"\nembed-mirror yes\n' \
    "$alias" "$url" "$index" "$out/repo" > "$out/core-source.conf"
printf '\n[packages]\n' >> "$out/core-source.conf"
while read -r role name; do
    printf '%s %s:%s\n' "$role" "$alias" "$name" >> "$out/core-source.conf"
done < "$out/work/names"
printf 'arch %s\nsource-id %s\nindex %s\nresult sealed-unsigned\n' \
    "$target_arch" "$source_id" "$index" >> "$out/build.record"
printf '%s\n' "$out/core-source.conf"
