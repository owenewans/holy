#!/bin/sh
set -eu
test "$#" -ge 2 || { echo 'usage: fetch-sources.sh DIRECTORY MANIFEST [NAME ...]' >&2; exit 2; }
out=$1
manifest=$2
shift 2
test -f "$manifest" || { echo "missing manifest: $manifest" >&2; exit 6; }
command -v curl >/dev/null && command -v sha256sum >/dev/null || exit 6
awk '
    NF != 3 || $1 !~ /^[0-9a-f]+$/ || length($1) != 64 ||
    $2 !~ /^[A-Za-z0-9][A-Za-z0-9._+-]*$/ || $3 !~ /^https:\/\// || seen[$2]++ {
        print "invalid source manifest at line " NR > "/dev/stderr"; bad=1
    }
    END { exit bad }
' "$manifest" || exit 2
if test "$#" -gt 0; then
    for name do
        case "$name" in ''|*[!a-zA-Z0-9._+-]*) echo "invalid source name: $name" >&2; exit 2 ;; esac
        awk -v name="$name" '$2 == name { found=1 } END { exit !found }' "$manifest" || {
            echo "source absent from manifest: $name" >&2; exit 2;
        }
    done
fi
mkdir -p "$out"
out=$(realpath "$out")
while read -r hash name url; do
    if test "$#" -gt 0; then
        selected=0
        for wanted do test "$name" != "$wanted" || selected=1; done
        test "$selected" = 1 || continue
    fi
    target=$out/$name
    if test -e "$target"; then
        printf '%s  %s\n' "$hash" "$target" | sha256sum -c - >/dev/null || {
            echo "existing source has wrong digest: $target" >&2; exit 4;
        }
        echo "verified $name"
        continue
    fi
    temp=$(mktemp "$out/.fetch.XXXXXX")
    trap 'rm -f "$temp"' EXIT
    trap 'exit 1' HUP INT TERM
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --retry 3 --connect-timeout 20 --output "$temp" "$url" || exit 6
    printf '%s  %s\n' "$hash" "$temp" | sha256sum -c - >/dev/null || {
        echo "downloaded source has wrong digest: $name" >&2; exit 4;
    }
    chmod 0644 "$temp"
    if ! ln "$temp" "$target" 2>/dev/null; then
        printf '%s  %s\n' "$hash" "$target" | sha256sum -c - >/dev/null || exit 4
    fi
    rm -f "$temp"
    trap - EXIT HUP INT TERM
    printf '%s  %s\n' "$hash" "$target" | sha256sum -c - >/dev/null
    echo "fetched $name"
done < "$manifest"
